//! End-to-end tests against the real relay binary.
//!
//! These drive the actual process over a real socket rather than calling into
//! its internals, because the properties worth testing here — that a wrong key
//! gets you nowhere, that the relay cannot read what it forwards — are
//! properties of the deployed thing.

use std::process::Stdio;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rustchat_core::{
    AccessKey, ClientMsg, PROTOCOL_VERSION, Payload, RelayMsg, RoomKey, SealedEnvelope,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_tungstenite::tungstenite::Message;

const TIMEOUT: Duration = Duration::from_secs(10);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// A running relay, killed when dropped.
struct Relay {
    child: tokio::process::Child,
    url: String,
    addr: String,
}

impl Relay {
    /// How many connections the relay currently believes it has.
    async fn connections(&self) -> usize {
        let body = reqwest_get(&format!("http://{}/health", self.addr)).await;
        let value: serde_json::Value = serde_json::from_str(&body).expect("health json");
        value["connections"].as_u64().expect("connections") as usize
    }

    /// Polls until the connection count reaches `want`, or gives up.
    async fn wait_for_connections(&self, want: usize, within: Duration) -> usize {
        let deadline = std::time::Instant::now() + within;
        let mut seen = self.connections().await;
        while std::time::Instant::now() < deadline && seen != want {
            tokio::time::sleep(Duration::from_millis(200)).await;
            seen = self.connections().await;
        }
        seen
    }
}

/// A one-line HTTP GET, to avoid pulling an HTTP client in just for /health.
async fn reqwest_get(url: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (host, path) = url.trim_start_matches("http://").split_once('/').unwrap();
    let mut stream = tokio::net::TcpStream::connect(host).await.expect("connect");
    let request = format!("GET /{path} HTTP/1.0\r\nHost: {host}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("read health response");
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or(response)
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Starts a relay on an OS-assigned port and waits until it is listening.
async fn start_relay(auth_hex: &str, history: usize) -> Relay {
    start_relay_with(auth_hex, history, 90).await
}

/// As [`start_relay`], with an explicit idle timeout in seconds.
async fn start_relay_with(auth_hex: &str, history: usize, idle_secs: u64) -> Relay {
    spawn_relay(auth_hex, history, idle_secs, &[]).await
}

async fn spawn_relay(auth_hex: &str, history: usize, idle_secs: u64, extra: &[&str]) -> Relay {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rustchat-relay"))
        .args([
            "--bind",
            "127.0.0.1:0",
            "--auth-key",
            auth_hex,
            "--history",
            &history.to_string(),
            "--idle-timeout",
            &idle_secs.to_string(),
        ])
        .args(extra)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawning the relay binary");

    let stderr = child.stderr.take().expect("relay stderr");
    let mut lines = BufReader::new(stderr).lines();
    let addr = tokio::time::timeout(TIMEOUT, async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(rest) = line.split("listening on ").nth(1) {
                return rest
                    .split_whitespace()
                    .next()
                    .expect("an address in the startup line")
                    .to_string();
            }
        }
        panic!("relay exited before it started listening");
    })
    .await
    .expect("relay took too long to start");

    Relay {
        child,
        url: format!("ws://{addr}/ws"),
        addr,
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn next_msg(socket: &mut Socket) -> Option<RelayMsg> {
    tokio::time::timeout(TIMEOUT, async {
        while let Some(frame) = socket.next().await {
            match frame.ok()? {
                Message::Text(text) => {
                    if let Ok(msg) = serde_json::from_str::<RelayMsg>(&text) {
                        return Some(msg);
                    }
                }
                Message::Close(_) => return None,
                _ => continue,
            }
        }
        None
    })
    .await
    .expect("timed out waiting for the relay")
}

async fn send(socket: &mut Socket, msg: &ClientMsg) {
    socket
        .send(Message::text(serde_json::to_string(msg).unwrap()))
        .await
        .expect("sending to the relay");
}

/// Connects, proves relay access, and joins the room named by `room`.
async fn join(url: &str, access: &AccessKey, room: &RoomKey) -> Socket {
    let (mut socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("connecting to the relay");
    let Some(RelayMsg::Challenge { v, nonce }) = next_msg(&mut socket).await else {
        panic!("expected a challenge");
    };
    assert_eq!(v, PROTOCOL_VERSION);
    send(
        &mut socket,
        &ClientMsg::Auth {
            v: PROTOCOL_VERSION,
            proof: b64(&access.prove(&unb64(&nonce))),
            room: room.room_id_hex(),
        },
    )
    .await;
    match next_msg(&mut socket).await {
        Some(RelayMsg::Welcome { .. }) => socket,
        other => panic!("expected a welcome, got {other:?}"),
    }
}

/// Seals a chat message the way the client does.
fn sealed(key: &RoomKey, user: &str, body: &str) -> SealedEnvelope {
    let payload = Payload::Msg {
        user: user.to_string(),
        body: body.to_string(),
        ts: 1_700_000_000_000,
    };
    let json = serde_json::to_vec(&payload).unwrap();
    let (nonce, ciphertext) = rustchat_core::seal(&key.derive().msg, &json).unwrap();
    SealedEnvelope {
        n: b64(&nonce),
        c: b64(&ciphertext),
    }
}

fn open_envelope(key: &RoomKey, env: &SealedEnvelope) -> Payload {
    let plaintext =
        rustchat_core::open(&key.derive().msg, &unb64(&env.n), &unb64(&env.c)).expect("opening");
    serde_json::from_slice(&plaintext).expect("parsing the payload")
}

#[tokio::test]
async fn two_members_can_talk_to_each_other() {
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;

    let mut alice = join(&relay.url, &access, &key).await;
    let mut bob = join(&relay.url, &access, &key).await;

    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&key, "alice", "hello bob"),
        },
    )
    .await;

    // Bob may see an occupancy update first; the message is what matters.
    let payload = loop {
        match next_msg(&mut bob).await {
            Some(RelayMsg::Msg { env }) => break open_envelope(&key, &env),
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected a message, got {other:?}"),
        }
    };
    match payload {
        Payload::Msg { user, body, .. } => {
            assert_eq!(user, "alice");
            assert_eq!(body, "hello bob");
        }
        other => panic!("expected a chat message, got {other:?}"),
    }
}

#[tokio::test]
async fn the_sender_sees_its_own_message() {
    // Every client renders on receive, so the whole room shares one ordering.
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;
    let mut alice = join(&relay.url, &access, &key).await;

    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&key, "alice", "echo?"),
        },
    )
    .await;

    loop {
        match next_msg(&mut alice).await {
            Some(RelayMsg::Msg { env }) => {
                assert!(matches!(
                    open_envelope(&key, &env),
                    Payload::Msg { ref body, .. } if body == "echo?"
                ));
                break;
            }
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected an echo, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_late_joiner_gets_the_backlog() {
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;

    let mut alice = join(&relay.url, &access, &key).await;
    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&key, "alice", "said before you arrived"),
        },
    )
    .await;
    // Let the relay commit it to the ring buffer before the next client joins.
    let _ = next_msg(&mut alice).await;

    let mut bob = join(&relay.url, &access, &key).await;
    let envs = loop {
        match next_msg(&mut bob).await {
            Some(RelayMsg::History { envs }) => break envs,
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected history, got {other:?}"),
        }
    };
    assert_eq!(envs.len(), 1);
    assert!(matches!(
        open_envelope(&key, &envs[0]),
        Payload::Msg { ref body, .. } if body == "said before you arrived"
    ));
}

#[tokio::test]
async fn history_can_be_switched_off() {
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay(&access.auth_hex(), 0).await;

    let mut alice = join(&relay.url, &access, &key).await;
    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&key, "alice", "ephemeral"),
        },
    )
    .await;
    let _ = next_msg(&mut alice).await;

    let mut bob = join(&relay.url, &access, &key).await;
    send(&mut bob, &ClientMsg::Ping).await;
    loop {
        match next_msg(&mut bob).await {
            Some(RelayMsg::Pong) => break,
            Some(RelayMsg::Occupants { .. }) => continue,
            Some(RelayMsg::History { .. }) => panic!("history was disabled but replayed anyway"),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_wrong_access_key_is_turned_away() {
    let real = AccessKey::generate();
    let impostor = AccessKey::generate();
    let relay = start_relay(&real.auth_hex(), 200).await;

    let (mut socket, _) = tokio_tungstenite::connect_async(&relay.url)
        .await
        .expect("connecting");
    let Some(RelayMsg::Challenge { nonce, .. }) = next_msg(&mut socket).await else {
        panic!("expected a challenge");
    };
    send(
        &mut socket,
        &ClientMsg::Auth {
            v: PROTOCOL_VERSION,
            proof: b64(&impostor.prove(&unb64(&nonce))),
            room: RoomKey::generate().room_id_hex(),
        },
    )
    .await;

    match next_msg(&mut socket).await {
        Some(RelayMsg::Error { reason }) => assert!(reason.contains("authentication")),
        other => panic!("an impostor should be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_mismatched_protocol_version_is_turned_away() {
    let access = AccessKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;

    let (mut socket, _) = tokio_tungstenite::connect_async(&relay.url)
        .await
        .expect("connecting");
    let Some(RelayMsg::Challenge { nonce, .. }) = next_msg(&mut socket).await else {
        panic!("expected a challenge");
    };
    send(
        &mut socket,
        &ClientMsg::Auth {
            v: PROTOCOL_VERSION + 99,
            proof: b64(&access.prove(&unb64(&nonce))),
            room: RoomKey::generate().room_id_hex(),
        },
    )
    .await;

    match next_msg(&mut socket).await {
        Some(RelayMsg::Error { .. }) | None => {}
        other => panic!("a version mismatch should be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn messages_cannot_be_sent_before_authenticating() {
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;

    let (mut socket, _) = tokio_tungstenite::connect_async(&relay.url)
        .await
        .expect("connecting");
    let _ = next_msg(&mut socket).await; // the challenge

    // Skip the handshake and try to talk anyway.
    send(
        &mut socket,
        &ClientMsg::Send {
            env: sealed(&key, "sneaky", "am i in?"),
        },
    )
    .await;

    match next_msg(&mut socket).await {
        Some(RelayMsg::Error { .. }) | None => {}
        other => panic!("unauthenticated sends must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn the_relay_never_sees_plaintext() {
    // The relay is configured with the auth subkey only. This asserts the
    // structural property that makes that safe: what it forwards is opaque
    // without the message subkey, which it is never given.
    let key = RoomKey::generate();
    let keys = key.derive();
    let env = sealed(&key, "alice", "the eagle has landed");

    let ciphertext = unb64(&env.c);
    assert!(
        !String::from_utf8_lossy(&ciphertext).contains("eagle"),
        "the body should not be readable in the envelope"
    );
    assert!(
        !String::from_utf8_lossy(&ciphertext).contains("alice"),
        "the username should not be readable in the envelope either"
    );
    // Everything the relay holds, used against the payload, gets nowhere: it
    // has the room id and an access auth key, and neither opens anything.
    assert!(
        rustchat_core::open(&keys.room_id, &unb64(&env.n), &ciphertext).is_err(),
        "the room id must not open a message"
    );
    assert!(
        rustchat_core::open(&AccessKey::generate().auth(), &unb64(&env.n), &ciphertext).is_err(),
        "an access auth key must not open a message"
    );
}

#[tokio::test]
async fn occupancy_is_reported_as_people_come_and_go() {
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;

    let mut alice = join(&relay.url, &access, &key).await;
    let bob = join(&relay.url, &access, &key).await;

    // Alice should be told the room grew to two.
    let count = loop {
        match next_msg(&mut alice).await {
            Some(RelayMsg::Occupants { occupants }) if occupants == 2 => break occupants,
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected an occupancy update, got {other:?}"),
        }
    };
    assert_eq!(count, 2);

    drop(bob);
    let count = loop {
        match next_msg(&mut alice).await {
            Some(RelayMsg::Occupants { occupants }) if occupants == 1 => break occupants,
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected an occupancy update, got {other:?}"),
        }
    };
    assert_eq!(count, 1, "leaving should be reflected in the count");
}

// --- multi-room behaviour --------------------------------------------------

#[tokio::test]
async fn a_room_can_be_created_just_by_joining_it() {
    // The whole point of protocol v2: the relay is configured with no room
    // keys, so a brand-new room key works immediately with no server change.
    let access = AccessKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;

    let brand_new = RoomKey::generate();
    let mut alice = join(&relay.url, &access, &brand_new).await;
    let mut bob = join(&relay.url, &access, &brand_new).await;

    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&brand_new, "alice", "fresh room"),
        },
    )
    .await;

    loop {
        match next_msg(&mut bob).await {
            Some(RelayMsg::Msg { env }) => {
                assert!(matches!(
                    open_envelope(&brand_new, &env),
                    Payload::Msg { ref body, .. } if body == "fresh room"
                ));
                break;
            }
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected a message in the new room, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn rooms_do_not_leak_into_each_other() {
    let access = AccessKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;
    let room_a = RoomKey::generate();
    let room_b = RoomKey::generate();

    let mut alice = join(&relay.url, &access, &room_a).await;
    let mut bob = join(&relay.url, &access, &room_b).await;

    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&room_a, "alice", "only for room a"),
        },
    )
    .await;
    // Alice must see her own message, so the relay has certainly processed it.
    loop {
        match next_msg(&mut alice).await {
            Some(RelayMsg::Msg { .. }) => break,
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected an echo, got {other:?}"),
        }
    }

    // Bob is in another room. A round-trip ping proves the relay is still
    // talking to him, and that nothing from room A arrived in the meantime.
    send(&mut bob, &ClientMsg::Ping).await;
    loop {
        match next_msg(&mut bob).await {
            Some(RelayMsg::Pong) => break,
            Some(RelayMsg::Occupants { .. }) => continue,
            Some(RelayMsg::Msg { .. }) => panic!("a message crossed between rooms"),
            Some(RelayMsg::History { .. }) => panic!("another room's history leaked"),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn occupancy_is_counted_per_room() {
    let access = AccessKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;
    let room_a = RoomKey::generate();
    let room_b = RoomKey::generate();

    let mut alice = join(&relay.url, &access, &room_a).await;
    // Two people join a different room; alice's count must stay at 1.
    let _b1 = join(&relay.url, &access, &room_b).await;
    let _b2 = join(&relay.url, &access, &room_b).await;

    send(&mut alice, &ClientMsg::Ping).await;
    loop {
        match next_msg(&mut alice).await {
            Some(RelayMsg::Pong) => break,
            Some(RelayMsg::Occupants { occupants }) => {
                assert_eq!(occupants, 1, "another room's occupants were counted");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn history_is_per_room() {
    let access = AccessKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;
    let room_a = RoomKey::generate();
    let room_b = RoomKey::generate();

    let mut alice = join(&relay.url, &access, &room_a).await;
    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&room_a, "alice", "room a backlog"),
        },
    )
    .await;
    let _ = next_msg(&mut alice).await;

    // A newcomer to room B must get room B's (empty) history, not room A's.
    let mut bob = join(&relay.url, &access, &room_b).await;
    send(&mut bob, &ClientMsg::Ping).await;
    loop {
        match next_msg(&mut bob).await {
            Some(RelayMsg::Pong) => break,
            Some(RelayMsg::Occupants { .. }) => continue,
            Some(RelayMsg::History { .. }) => panic!("room A's history reached room B"),
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_malformed_room_id_is_refused() {
    let access = AccessKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;

    let (mut socket, _) = tokio_tungstenite::connect_async(&relay.url)
        .await
        .expect("connecting");
    let Some(RelayMsg::Challenge { nonce, .. }) = next_msg(&mut socket).await else {
        panic!("expected a challenge");
    };
    send(
        &mut socket,
        &ClientMsg::Auth {
            v: PROTOCOL_VERSION,
            proof: b64(&access.prove(&unb64(&nonce))),
            room: "not-a-room-id".into(),
        },
    )
    .await;

    match next_msg(&mut socket).await {
        Some(RelayMsg::Error { .. }) | None => {}
        other => panic!("a malformed room id must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn the_relay_cannot_tell_which_room_key_produced_an_id() {
    // The relay sees room ids. This asserts the one-way property that makes
    // handing them over safe.
    let key = RoomKey::generate();
    let id = key.room_id_hex();
    assert_ne!(id, hex(key.as_bytes()), "the id must not be the key itself");
    assert_ne!(
        id,
        hex(&key.derive().msg),
        "the id must not be the message key"
    );
    assert_ne!(
        id,
        RoomKey::generate().room_id_hex(),
        "different keys must give different ids"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- noticing clients that vanished ----------------------------------------

#[tokio::test]
async fn a_client_that_vanishes_stops_being_counted() {
    // A peer that goes away without closing — a sleeping laptop, a dropped
    // tunnel — leaves a socket that still looks open from the relay's side.
    // Silence is the only evidence, so the relay has to act on it or the
    // room's headcount stays wrong forever.
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay_with(&access.auth_hex(), 200, 2).await;

    let ghost = join(&relay.url, &access, &key).await;
    assert_eq!(
        relay.wait_for_connections(1, Duration::from_secs(5)).await,
        1
    );

    // Keep the socket open at the OS level but never poll it again: no reads,
    // no writes, not even the automatic Pong. Exactly what a vanished peer
    // looks like from here.
    std::mem::forget(ghost);

    let after = relay.wait_for_connections(0, Duration::from_secs(20)).await;
    assert_eq!(after, 0, "a silent connection should have been dropped");
}

#[tokio::test]
async fn a_client_that_keeps_talking_is_left_alone() {
    // The other half of the contract: the idle timeout must not cut off
    // someone who is simply not typing.
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay_with(&access.auth_hex(), 200, 3).await;

    let mut alice = join(&relay.url, &access, &key).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(7);
    while std::time::Instant::now() < deadline {
        send(&mut alice, &ClientMsg::Ping).await;
        // Draining replies is what a real client does, and is also what
        // sends the automatic Pong for the relay's own heartbeat.
        let _ = tokio::time::timeout(Duration::from_millis(400), next_msg(&mut alice)).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    assert_eq!(
        relay.connections().await,
        1,
        "a client that keeps answering must not be dropped"
    );
}

#[tokio::test]
async fn a_vanished_client_frees_its_room() {
    // The room should be reclaimable afterwards, not pinned open by a ghost.
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay_with(&access.auth_hex(), 200, 2).await;

    let ghost = join(&relay.url, &access, &key).await;
    std::mem::forget(ghost);
    assert_eq!(
        relay.wait_for_connections(0, Duration::from_secs(20)).await,
        0
    );

    // A fresh client can still use the same room, and finds itself alone.
    let mut alice = join(&relay.url, &access, &key).await;
    send(&mut alice, &ClientMsg::Ping).await;
    loop {
        match next_msg(&mut alice).await {
            Some(RelayMsg::Pong) => break,
            Some(RelayMsg::Occupants { occupants }) => {
                assert_eq!(occupants, 1, "the ghost should not still be counted");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// Waits for the backlog a join replays, skipping occupancy chatter.
async fn history_of(socket: &mut Socket) -> Vec<SealedEnvelope> {
    loop {
        match next_msg(socket).await {
            Some(RelayMsg::History { envs }) => return envs,
            Some(RelayMsg::Occupants { .. }) => continue,
            other => panic!("expected history, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn history_survives_a_restart_with_a_data_dir() {
    // The case this exists for: say something, everyone leaves, the relay
    // restarts, and a different device joins later and still sees it.
    let dir = std::env::temp_dir().join(format!(
        "rustchat-e2e-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    let dir_arg = dir.to_str().unwrap().to_string();
    let access = AccessKey::generate();
    let key = RoomKey::generate();

    let relay = spawn_relay(&access.auth_hex(), 200, 90, &["--data-dir", &dir_arg]).await;
    let mut laptop = join(&relay.url, &access, &key).await;
    for body in ["first", "second"] {
        send(
            &mut laptop,
            &ClientMsg::Send {
                env: sealed(&key, "bmo", body),
            },
        )
        .await;
    }
    // Wait for both echoes, so both are committed before the relay goes.
    let mut echoed = 0;
    while echoed < 2 {
        if let Some(RelayMsg::Msg { .. }) = next_msg(&mut laptop).await {
            echoed += 1;
        }
    }
    drop(laptop);
    drop(relay);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let relay = spawn_relay(&access.auth_hex(), 200, 90, &["--data-dir", &dir_arg]).await;
    let mut phone = join(&relay.url, &access, &key).await;
    let bodies: Vec<String> = history_of(&mut phone)
        .await
        .iter()
        .map(|env| match open_envelope(&key, env) {
            Payload::Msg { body, .. } => body,
            other => panic!("expected chat, got {other:?}"),
        })
        .collect();
    assert_eq!(bodies, ["first", "second"]);

    // And the files hold nothing readable.
    for entry in std::fs::read_dir(&dir).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(!text.contains("first") && !text.contains("bmo"), "{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn without_a_data_dir_a_restart_forgets() {
    let access = AccessKey::generate();
    let key = RoomKey::generate();
    let relay = start_relay(&access.auth_hex(), 200).await;
    let mut alice = join(&relay.url, &access, &key).await;
    send(
        &mut alice,
        &ClientMsg::Send {
            env: sealed(&key, "alice", "ephemeral"),
        },
    )
    .await;
    let _ = next_msg(&mut alice).await;
    drop(alice);
    drop(relay);

    let relay = start_relay(&access.auth_hex(), 200).await;
    let mut bob = join(&relay.url, &access, &key).await;
    // No history frame at all: the next thing is occupancy.
    assert!(matches!(
        next_msg(&mut bob).await,
        Some(RelayMsg::Occupants { .. })
    ));
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
