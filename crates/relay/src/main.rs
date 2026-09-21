//! rustchat-relay — a deliberately ignorant broadcast hub.
//!
//! The relay's whole job is to hold open a set of WebSockets and copy sealed
//! envelopes between them. It is configured with the room key's *auth subkey*
//! and nothing else, which lets it turn away clients that can't prove they
//! know the room key while leaving it structurally unable to read a single
//! message: the message subkey is a sibling derivation it never receives.
//!
//! So the interesting properties here are not cryptographic, they are about
//! not falling over — size caps, rate limits, connection caps, handshake
//! timeouts. Anyone with the room key can talk, and the room key is meant to
//! be passed around, so the relay assumes its own members may misbehave.

use std::collections::VecDeque;
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
    ClientMsg, MAX_ENVELOPE_BYTES, PROTOCOL_VERSION, RelayMsg, SealedEnvelope, parse_auth_hex,
    verify_proof,
};
use tokio::sync::broadcast;

/// A client gets this long to answer the challenge before being dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Sustained send rate per connection, messages per second.
const RATE_PER_SEC: f64 = 5.0;
/// How many messages a connection may burst above the sustained rate.
const RATE_BURST: f64 = 10.0;
/// Buffered broadcast messages before a slow client is considered hopeless.
const BROADCAST_CAPACITY: usize = 256;

#[derive(Parser, Debug)]
#[command(
    name = "rustchat-relay",
    version,
    about = "Zero-knowledge relay for rustchat. Never sees plaintext."
)]
struct Args {
    /// Address to bind. Keep this on loopback and put a tunnel or reverse
    /// proxy in front of it; the relay speaks plain HTTP by design.
    #[arg(long, env = "RUSTCHAT_BIND", default_value = "127.0.0.1:7777")]
    bind: SocketAddr,

    /// Room auth key, 64 hex characters. Generate with `rustchat keygen`.
    ///
    /// This is *not* the room key and cannot be turned back into it.
    #[arg(long, env = "RUSTCHAT_AUTH_KEY")]
    auth_key: String,

    /// Sealed envelopes to retain for replay to clients that join late.
    /// Memory only — a restart forgets everything. 0 disables replay.
    #[arg(long, env = "RUSTCHAT_HISTORY", default_value_t = 200)]
    history: usize,

    /// Maximum simultaneous connections.
    #[arg(long, env = "RUSTCHAT_MAX_CONNS", default_value_t = 200)]
    max_conns: usize,
}

/// What travels on the room's broadcast channel.
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

struct AppState {
    auth_key: [u8; 32],
    history_limit: usize,
    max_conns: usize,
    /// Sealed envelopes only. The relay cannot read these and never tries.
    history: tokio::sync::Mutex<VecDeque<SealedEnvelope>>,
    tx: broadcast::Sender<Broadcast>,
    occupants: AtomicUsize,
}

impl AppState {
    fn occupants(&self) -> usize {
        self.occupants.load(Ordering::Relaxed)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let auth_key = parse_auth_hex(&args.auth_key).context("--auth-key")?;
    let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);

    let state = Arc::new(AppState {
        auth_key,
        history_limit: args.history,
        max_conns: args.max_conns,
        history: tokio::sync::Mutex::new(VecDeque::new()),
        tx,
        occupants: AtomicUsize::new(0),
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
        "rustchat-relay v{} listening on {bound} (protocol v{PROTOCOL_VERSION}, history {}, max conns {})",
        env!("CARGO_PKG_VERSION"),
        args.history,
        args.max_conns
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

/// Reports liveness and occupancy. Deliberately says nothing about who is
/// connected, because the relay does not know.
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "ok": true,
        "protocol": PROTOCOL_VERSION,
        "occupants": state.occupants(),
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    if state.occupants() >= state.max_conns {
        return (StatusCode::SERVICE_UNAVAILABLE, "room is full").into_response();
    }
    ws.max_message_size(MAX_ENVELOPE_BYTES * 2)
        .on_upgrade(move |socket| async move {
            if let Err(err) = serve_socket(socket, state).await {
                // Routine: clients vanish, and unauthenticated peers get
                // hung up on. Worth a line, not worth alarm.
                eprintln!("connection ended: {err:#}");
            }
        })
}

/// Runs one client connection: challenge, verify, then pump until it leaves.
async fn serve_socket(socket: WebSocket, state: Arc<AppState>) -> Result<()> {
    let (mut sink, mut stream) = socket.split();

    // --- Handshake ------------------------------------------------------
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

    let authed = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        while let Some(frame) = stream.next().await {
            let text = match frame? {
                Message::Text(t) => t,
                Message::Close(_) => return Ok(false),
                // Ignore pings and stray binary while we wait for the answer.
                _ => continue,
            };
            let Ok(ClientMsg::Auth { v, proof }) = serde_json::from_str::<ClientMsg>(&text) else {
                return Ok(false);
            };
            if v != PROTOCOL_VERSION {
                return Ok(false);
            }
            let Ok(proof) = unb64(&proof) else {
                return Ok(false);
            };
            return Ok::<bool, anyhow::Error>(verify_proof(&state.auth_key, &challenge, &proof));
        }
        Ok(false)
    })
    .await
    .unwrap_or(Ok(false))?;

    if !authed {
        let _ = send(
            &mut sink,
            &RelayMsg::Error {
                reason: "authentication failed".into(),
            },
        )
        .await;
        let _ = sink.close().await;
        anyhow::bail!("rejected an unauthenticated client");
    }

    // --- Admission ------------------------------------------------------
    // Counted only after authenticating, so unauthenticated probes cannot
    // consume the connection budget. The guard decrements and re-announces on
    // every exit path, including the `?` returns below.
    let _guard = OccupantGuard::new(state.clone());
    let mut rx = state.tx.subscribe();
    let occupants = state.occupants();

    send(&mut sink, &RelayMsg::Welcome { occupants }).await?;

    if state.history_limit > 0 {
        let envs: Vec<SealedEnvelope> = state.history.lock().await.iter().cloned().collect();
        if !envs.is_empty() {
            send(&mut sink, &RelayMsg::History { envs }).await?;
        }
    }
    let _ = state.tx.send(Broadcast::Occupancy);

    // --- Pump -----------------------------------------------------------
    let mut bucket = TokenBucket::new(RATE_BURST, RATE_PER_SEC);
    loop {
        tokio::select! {
            // Outbound: anything published to the room.
            received = rx.recv() => {
                match received {
                    Ok(Broadcast::Envelope(env)) => {
                        send(&mut sink, &RelayMsg::Msg { env }).await?;
                    }
                    Ok(Broadcast::Occupancy) => {
                        send(&mut sink, &RelayMsg::Occupants { occupants: state.occupants() }).await?;
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
                                if env.n.len() + env.c.len() > MAX_ENVELOPE_BYTES {
                                    continue;
                                }
                                if state.history_limit > 0 {
                                    let mut history = state.history.lock().await;
                                    history.push_back(env.clone());
                                    while history.len() > state.history_limit {
                                        history.pop_front();
                                    }
                                }
                                // Every client renders on receive, including
                                // the sender, so the whole room agrees on
                                // ordering without any sequence numbers.
                                let _ = state.tx.send(Broadcast::Envelope(env));
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

/// Keeps the occupant count honest across every way a connection can end,
/// including `?` returns and cancellation inside `select!`, and tells the rest
/// of the room on the way out.
struct OccupantGuard {
    state: Arc<AppState>,
}

impl OccupantGuard {
    fn new(state: Arc<AppState>) -> Self {
        state.occupants.fetch_add(1, Ordering::Relaxed);
        Self { state }
    }
}

impl Drop for OccupantGuard {
    fn drop(&mut self) {
        self.state.occupants.fetch_sub(1, Ordering::Relaxed);
        let _ = self.state.tx.send(Broadcast::Occupancy);
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
        let mut b = TokenBucket::new(2.0, 1_000_000.0);
        std::thread::sleep(Duration::from_millis(10));
        assert!(b.take());
        assert!(b.take());
        assert!(!b.take(), "tokens must cap at the burst size");
    }

    #[test]
    fn base64_roundtrips() {
        assert_eq!(unb64(&b64(b"hello")).unwrap(), b"hello");
    }
}
