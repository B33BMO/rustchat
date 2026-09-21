//! rustchat-relay — a deliberately ignorant, multi-room broadcast hub.
//!
//! The relay holds open WebSockets and copies sealed envelopes between the
//! ones sharing a room. It is configured with a single *relay access* auth
//! key, which decides who may connect at all, and with no room keys
//! whatsoever. Rooms are named by a one-way id derived from a room key, so a
//! client can conjure a room simply by joining it, and the relay can group
//! sockets correctly while being structurally unable to read a single message.
//!
//! So the interesting properties here are not cryptographic, they are about
//! not falling over: size caps, rate limits, connection caps, room caps,
//! handshake timeouts, and evicting rooms nobody is using. Anyone with the
//! access key can open rooms, and the access key is meant to be handed around,
//! so the relay assumes its own users may misbehave.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustchat_core::{
    ClientMsg, MAX_ENVELOPE_BYTES, PROTOCOL_VERSION, RelayMsg, SealedEnvelope, parse_hex32,
    verify_proof,
};
use tokio::sync::{Mutex, broadcast};

/// A client gets this long to answer the challenge before being dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Sustained send rate per connection, messages per second.
const RATE_PER_SEC: f64 = 5.0;
/// How many messages a connection may burst above the sustained rate.
const RATE_BURST: f64 = 10.0;
/// Buffered broadcast messages before a slow client is considered hopeless.
const BROADCAST_CAPACITY: usize = 256;
/// How long an empty room keeps its replay buffer before being forgotten.
/// Long enough to survive a reconnect or a quick restart, short enough that
/// abandoned rooms don't accumulate.
const EMPTY_ROOM_TTL: Duration = Duration::from_secs(600);
/// How often to sweep for abandoned rooms.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Ceiling on bytes of replay buffer per room. Bounds memory against a room
/// that sends nothing but maximum-size envelopes.
const HISTORY_BYTES_PER_ROOM: usize = 256 * 1024;

type RoomId = [u8; 32];

#[derive(Parser, Debug)]
#[command(
    name = "rustchat-relay",
    version,
    about = "Multi-room, zero-knowledge relay for rustchat. Never sees plaintext."
)]
struct Args {
    /// Address to bind. Keep this on loopback and put a tunnel or reverse
    /// proxy in front of it; the relay speaks plain HTTP by design.
    #[arg(long, env = "RUSTCHAT_BIND", default_value = "127.0.0.1:7777")]
    bind: SocketAddr,

    /// Relay access auth key, 64 hex characters, from `rustchat relaykey`.
    ///
    /// This gates who may connect. It is *not* a room key and carries no
    /// ability to read any room.
    #[arg(long, env = "RUSTCHAT_AUTH_KEY")]
    auth_key: String,

    /// Sealed envelopes retained per room, for replay to clients that join
    /// late. Memory only — a restart forgets everything. 0 disables replay.
    #[arg(long, env = "RUSTCHAT_HISTORY", default_value_t = 200)]
    history: usize,

    /// Maximum simultaneous connections across all rooms.
    #[arg(long, env = "RUSTCHAT_MAX_CONNS", default_value_t = 200)]
    max_conns: usize,

    /// Maximum rooms held at once, including empty ones awaiting eviction.
    #[arg(long, env = "RUSTCHAT_MAX_ROOMS", default_value_t = 64)]
    max_rooms: usize,
}

/// What travels on a room's broadcast channel.
///
/// Occupancy rides the same channel as chat so the two stay ordered, but it is
/// a distinct variant rather than a magic envelope: any room member can send
/// arbitrary envelope bytes, so a sentinel encoded *inside* an envelope would
/// let one client forge occupancy updates for everyone else.
#[derive(Clone, Debug)]
enum Broadcast {
    Envelope(SealedEnvelope),
    Occupancy,
}

/// A replay buffer, bounded by both message count and total bytes.
#[derive(Default)]
struct History {
    envelopes: VecDeque<SealedEnvelope>,
    bytes: usize,
}

impl History {
    fn push(&mut self, env: SealedEnvelope, max_len: usize) {
        if max_len == 0 {
            return;
        }
        self.bytes += envelope_bytes(&env);
        self.envelopes.push_back(env);
        while self.envelopes.len() > max_len || self.bytes > HISTORY_BYTES_PER_ROOM {
            match self.envelopes.pop_front() {
                Some(old) => self.bytes = self.bytes.saturating_sub(envelope_bytes(&old)),
                None => break,
            }
        }
    }

    fn snapshot(&self) -> Vec<SealedEnvelope> {
        self.envelopes.iter().cloned().collect()
    }
}

fn envelope_bytes(env: &SealedEnvelope) -> usize {
    env.n.len() + env.c.len()
}

/// One room. The relay knows its id, how many sockets are in it, and a pile of
/// bytes it cannot read.
struct Room {
    tx: broadcast::Sender<Broadcast>,
    history: Mutex<History>,
    occupants: AtomicUsize,
    /// When this room last had a connection, for evicting abandoned rooms.
    idle_since: Mutex<Instant>,
}

impl Room {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            tx,
            history: Mutex::new(History::default()),
            occupants: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
        }
    }

    fn occupants(&self) -> usize {
        self.occupants.load(Ordering::Relaxed)
    }
}

struct AppState {
    /// The relay access auth key. The only secret the relay holds, and it
    /// grants no ability to read anything.
    auth_key: [u8; 32],
    history_limit: usize,
    max_conns: usize,
    max_rooms: usize,
    rooms: Mutex<HashMap<RoomId, Arc<Room>>>,
    /// Connections across all rooms, for the global cap.
    connections: AtomicUsize,
}

impl AppState {
    fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// Returns the room, creating it if this is the first person in.
    ///
    /// Creation is the normal case, not an exception: a room exists precisely
    /// because somebody joined it.
    async fn room(&self, id: RoomId) -> Result<Arc<Room>, &'static str> {
        let mut rooms = self.rooms.lock().await;
        if let Some(room) = rooms.get(&id) {
            return Ok(room.clone());
        }
        if rooms.len() >= self.max_rooms {
            // Reclaim rooms nobody is in before refusing. An abandoned room
            // holding a replay buffer must never block a live one.
            rooms.retain(|_, room| room.occupants() > 0);
            if rooms.len() >= self.max_rooms {
                return Err("this relay is holding too many rooms");
            }
        }
        let room = Arc::new(Room::new());
        rooms.insert(id, room.clone());
        Ok(room)
    }

    /// Drops empty rooms that have been idle past [`EMPTY_ROOM_TTL`].
    async fn sweep(&self) {
        let now = Instant::now();
        let mut rooms = self.rooms.lock().await;
        let mut stale = Vec::new();
        for (id, room) in rooms.iter() {
            if room.occupants() == 0 {
                let idle_since = *room.idle_since.lock().await;
                if now.duration_since(idle_since) > EMPTY_ROOM_TTL {
                    stale.push(*id);
                }
            }
        }
        for id in stale {
            rooms.remove(&id);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let auth_key = parse_hex32(&args.auth_key).context("--auth-key")?;

    let state = Arc::new(AppState {
        auth_key,
        history_limit: args.history,
        max_conns: args.max_conns,
        max_rooms: args.max_rooms,
        rooms: Mutex::new(HashMap::new()),
        connections: AtomicUsize::new(0),
    });

    // Reclaim abandoned rooms in the background, so memory does not grow with
    // every room anyone ever opened.
    let sweeper = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            sweeper.sweep().await;
        }
    });

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;
    // The bound address rather than the requested one, so `--bind 127.0.0.1:0`
    // reports the port the OS actually handed out.
    let bound = listener.local_addr().context("reading the bound address")?;
    eprintln!(
        "rustchat-relay v{} listening on {bound} (protocol v{PROTOCOL_VERSION}, \
         history {}/room, max conns {}, max rooms {})",
        env!("CARGO_PKG_VERSION"),
        args.history,
        args.max_conns,
        args.max_rooms
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("shutting down");
}

/// Reports liveness and coarse load. Deliberately says nothing about who is
/// connected or which rooms exist, because the relay cannot identify either.
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rooms = state.rooms.lock().await.len();
    axum::Json(serde_json::json!({
        "ok": true,
        "protocol": PROTOCOL_VERSION,
        "connections": state.connections(),
        "rooms": rooms,
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    if state.connections() >= state.max_conns {
        return (StatusCode::SERVICE_UNAVAILABLE, "relay is full").into_response();
    }
    ws.max_message_size(MAX_ENVELOPE_BYTES * 2)
        .on_upgrade(move |socket| async move {
            if let Err(err) = serve_socket(socket, state).await {
                // Routine: clients vanish, and peers without the access key
                // get hung up on. Worth a line, not worth alarm.
                eprintln!("connection ended: {err:#}");
            }
        })
}

/// The outcome of a handshake: which room the client may join.
struct Admitted {
    room_id: RoomId,
}

/// Runs one client connection: challenge, verify, join a room, then pump.
async fn serve_socket(socket: WebSocket, state: Arc<AppState>) -> Result<()> {
    let (mut sink, mut stream) = socket.split();

    // --- Handshake --------------------------------------------------------
    // Fresh per connection, so a captured proof cannot be replayed.
    let mut challenge = [0u8; 32];
    rand::fill(&mut challenge);
    send(
        &mut sink,
        &RelayMsg::Challenge {
            v: PROTOCOL_VERSION,
            nonce: b64(&challenge),
        },
    )
    .await?;

    let admitted = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut stream, &state, &challenge),
    )
    .await
    .unwrap_or(None);

    let Some(admitted) = admitted else {
        let _ = send(
            &mut sink,
            &RelayMsg::Error {
                reason: "authentication failed".into(),
            },
        )
        .await;
        let _ = sink.close().await;
        anyhow::bail!("rejected an unauthenticated client");
    };

    // --- Join the room ----------------------------------------------------
    let room = match state.room(admitted.room_id).await {
        Ok(room) => room,
        Err(reason) => {
            let _ = send(
                &mut sink,
                &RelayMsg::Error {
                    reason: reason.to_string(),
                },
            )
            .await;
            let _ = sink.close().await;
            anyhow::bail!("{reason}");
        }
    };

    // Counted only after authenticating, so unauthenticated probes cannot
    // consume the connection budget. The guard decrements and re-announces on
    // every exit path, including the `?` returns below.
    let _guard = OccupantGuard::new(state.clone(), room.clone());
    let mut rx = room.tx.subscribe();
    let occupants = room.occupants();

    send(&mut sink, &RelayMsg::Welcome { occupants }).await?;

    if state.history_limit > 0 {
        let envs = room.history.lock().await.snapshot();
        if !envs.is_empty() {
            send(&mut sink, &RelayMsg::History { envs }).await?;
        }
    }
    let _ = room.tx.send(Broadcast::Occupancy);

    // --- Pump -------------------------------------------------------------
    let mut bucket = TokenBucket::new(RATE_BURST, RATE_PER_SEC);
    loop {
        tokio::select! {
            // Outbound: anything published to this room.
            received = rx.recv() => {
                match received {
                    Ok(Broadcast::Envelope(env)) => {
                        send(&mut sink, &RelayMsg::Msg { env }).await?;
                    }
                    Ok(Broadcast::Occupancy) => {
                        send(&mut sink, &RelayMsg::Occupants { occupants: room.occupants() }).await?;
                    }
                    // The client fell far enough behind that we dropped
                    // messages for it. Rejoining is the honest fix, so tell
                    // it plainly instead of silently showing a gapped room.
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        send(&mut sink, &RelayMsg::Error {
                            reason: format!("fell behind by {n} messages; reconnect"),
                        }).await?;
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            // Inbound: what this client wants to say.
            frame = stream.next() => {
                let Some(frame) = frame else { break };
                match frame? {
                    Message::Text(text) => {
                        let Ok(msg) = serde_json::from_str::<ClientMsg>(&text) else {
                            continue; // Unparseable: ignore, don't disconnect.
                        };
                        match msg {
                            ClientMsg::Send { env } => {
                                if !bucket.take() {
                                    send(&mut sink, &RelayMsg::Error {
                                        reason: "slow down".into(),
                                    }).await?;
                                    continue;
                                }
                                if envelope_bytes(&env) > MAX_ENVELOPE_BYTES {
                                    continue;
                                }
                                room.history.lock().await.push(env.clone(), state.history_limit);
                                // Every client renders on receive, including
                                // the sender, so the whole room agrees on
                                // ordering without any sequence numbers.
                                let _ = room.tx.send(Broadcast::Envelope(env));
                            }
                            ClientMsg::Ping => send(&mut sink, &RelayMsg::Pong).await?,
                            ClientMsg::Auth { .. } => {} // Already past that.
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Reads the client's `Auth` and decides whether to admit it.
///
/// Returns `None` for every kind of failure, so a caller cannot accidentally
/// distinguish "wrong access key" from "malformed room id" and neither can a
/// client.
async fn handshake<S>(stream: &mut S, state: &AppState, challenge: &[u8]) -> Option<Admitted>
where
    S: futures_util::Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    while let Some(frame) = stream.next().await {
        let text = match frame.ok()? {
            Message::Text(t) => t,
            Message::Close(_) => return None,
            // Ignore pings and stray binary while we wait for the answer.
            _ => continue,
        };
        let ClientMsg::Auth { v, proof, room } = serde_json::from_str::<ClientMsg>(&text).ok()?
        else {
            return None;
        };
        if v != PROTOCOL_VERSION {
            return None;
        }
        let proof = unb64(&proof).ok()?;
        if !verify_proof(&state.auth_key, challenge, &proof) {
            return None;
        }
        let room_id = parse_hex32(&room).ok()?;
        return Some(Admitted { room_id });
    }
    None
}

/// Keeps occupancy honest across every way a connection can end, including
/// `?` returns and cancellation inside `select!`, and tells the rest of the
/// room on the way out.
struct OccupantGuard {
    state: Arc<AppState>,
    room: Arc<Room>,
}

impl OccupantGuard {
    fn new(state: Arc<AppState>, room: Arc<Room>) -> Self {
        state.connections.fetch_add(1, Ordering::Relaxed);
        room.occupants.fetch_add(1, Ordering::Relaxed);
        Self { state, room }
    }
}

impl Drop for OccupantGuard {
    fn drop(&mut self) {
        self.state.connections.fetch_sub(1, Ordering::Relaxed);
        let left = self.room.occupants.fetch_sub(1, Ordering::Relaxed);
        let _ = self.room.tx.send(Broadcast::Occupancy);
        // Start the eviction clock once the last person leaves. `fetch_sub`
        // returns the value *before* the decrement, so 1 means now empty.
        if left == 1
            && let Ok(mut idle) = self.room.idle_since.try_lock()
        {
            *idle = Instant::now();
        }
    }
}

/// A simple token bucket: `burst` tokens, refilled at `per_sec`.
struct TokenBucket {
    tokens: f64,
    burst: f64,
    per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(burst: f64, per_sec: f64) -> Self {
        Self {
            tokens: burst,
            burst,
            per_sec,
            last: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.per_sec)
            .min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn send<S>(sink: &mut S, msg: &RelayMsg) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
{
    let text = serde_json::to_string(msg)?;
    sink.send(Message::Text(text.into())).await?;
    Ok(())
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(n: &str, c: &str) -> SealedEnvelope {
        SealedEnvelope {
            n: n.into(),
            c: c.into(),
        }
    }

    #[test]
    fn bucket_allows_a_burst_then_throttles() {
        let mut b = TokenBucket::new(3.0, 1.0);
        assert!(b.take());
        assert!(b.take());
        assert!(b.take());
        assert!(!b.take(), "burst should be exhausted");
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = TokenBucket::new(1.0, 1000.0);
        assert!(b.take());
        assert!(!b.take());
        std::thread::sleep(Duration::from_millis(20));
        assert!(b.take(), "should have refilled");
    }

    #[test]
    fn bucket_does_not_overfill() {
        // A modest refill rate, so the microseconds between the takes below
        // add a negligible fraction of a token. With a very high rate the
        // bucket legitimately refills mid-test and this proves nothing.
        let mut b = TokenBucket::new(2.0, 10.0);
        // Idle long enough that an uncapped bucket would hold ~12 tokens.
        std::thread::sleep(Duration::from_millis(1000));
        assert!(b.take());
        assert!(b.take());
        assert!(!b.take(), "idling must not bank more than the burst size");
    }

    #[test]
    fn history_is_capped_by_count() {
        let mut h = History::default();
        for i in 0..10 {
            h.push(env("n", &i.to_string()), 3);
        }
        assert_eq!(h.envelopes.len(), 3);
        assert_eq!(
            h.envelopes.front().unwrap().c,
            "7",
            "oldest should be dropped"
        );
    }

    #[test]
    fn history_is_capped_by_bytes() {
        let mut h = History::default();
        let big = "x".repeat(64 * 1024);
        for _ in 0..20 {
            h.push(env("n", &big), 1000);
        }
        assert!(
            h.bytes <= HISTORY_BYTES_PER_ROOM,
            "byte budget exceeded: {}",
            h.bytes
        );
        assert!(h.envelopes.len() < 20, "should have evicted some");
    }

    #[test]
    fn history_of_zero_retains_nothing() {
        let mut h = History::default();
        h.push(env("n", "c"), 0);
        assert!(h.envelopes.is_empty());
        assert_eq!(h.bytes, 0);
    }

    #[test]
    fn byte_accounting_stays_consistent() {
        let mut h = History::default();
        for i in 0..50 {
            h.push(env("nonce", &"y".repeat(i * 100)), 5);
        }
        let actual: usize = h.envelopes.iter().map(envelope_bytes).sum();
        assert_eq!(h.bytes, actual, "tracked bytes drifted from reality");
    }

    #[tokio::test]
    async fn rooms_are_created_on_demand_and_reused() {
        let state = test_state(4);
        let a = state.room([1u8; 32]).await.unwrap();
        let b = state.room([1u8; 32]).await.unwrap();
        let c = state.room([2u8; 32]).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b), "the same id must give the same room");
        assert!(!Arc::ptr_eq(&a, &c), "different ids are different rooms");
        assert_eq!(state.rooms.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn empty_rooms_are_reclaimed_before_refusing_a_new_one() {
        let state = test_state(2);
        let _a = state.room([1u8; 32]).await.unwrap();
        let _b = state.room([2u8; 32]).await.unwrap();
        // Both are empty, so making a third should reclaim rather than fail.
        assert!(state.room([3u8; 32]).await.is_ok());
        assert_eq!(state.rooms.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn occupied_rooms_are_never_reclaimed() {
        let state = test_state(1);
        let occupied = state.room([1u8; 32]).await.unwrap();
        occupied.occupants.fetch_add(1, Ordering::Relaxed);
        assert!(
            state.room([2u8; 32]).await.is_err(),
            "must refuse rather than evict a room with people in it"
        );
        assert!(state.rooms.lock().await.contains_key(&[1u8; 32]));
    }

    #[tokio::test]
    async fn the_sweeper_only_takes_stale_empty_rooms() {
        let state = test_state(8);
        let fresh = state.room([1u8; 32]).await.unwrap();
        let stale = state.room([2u8; 32]).await.unwrap();
        let busy = state.room([3u8; 32]).await.unwrap();
        busy.occupants.fetch_add(1, Ordering::Relaxed);
        *stale.idle_since.lock().await = Instant::now() - EMPTY_ROOM_TTL - Duration::from_secs(1);
        *busy.idle_since.lock().await = Instant::now() - EMPTY_ROOM_TTL - Duration::from_secs(1);
        drop((fresh, stale, busy));

        state.sweep().await;
        let rooms = state.rooms.lock().await;
        assert!(rooms.contains_key(&[1u8; 32]), "recently idle room kept");
        assert!(!rooms.contains_key(&[2u8; 32]), "stale empty room swept");
        assert!(rooms.contains_key(&[3u8; 32]), "occupied room kept");
    }

    #[test]
    fn base64_roundtrips() {
        assert_eq!(unb64(&b64(b"hello")).unwrap(), b"hello");
    }

    fn test_state(max_rooms: usize) -> Arc<AppState> {
        Arc::new(AppState {
            auth_key: [0u8; 32],
            history_limit: 10,
            max_conns: 100,
            max_rooms,
            rooms: Mutex::new(HashMap::new()),
            connections: AtomicUsize::new(0),
        })
    }
}
