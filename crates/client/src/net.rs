//! The client's connection to a relay.
//!
//! This module knows how to seal, open and shuttle payloads, and nothing about
//! how any of it looks. It owns the reconnect loop, so the UI never has to
//! think about the socket being down: it just keeps receiving [`NetEvent`]s.

use std::time::Duration;

use anyhow::{Result, bail};
use futures_util::{SinkExt, StreamExt};
use rustchat_core::{
    AccessKey, ClientMsg, PROTOCOL_VERSION, Payload, RelayMsg, RoomKeys, SealedEnvelope, open, seal,
};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Longest gap between reconnect attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How often to nudge the relay so idle connections aren't reaped.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Something happened on the wire that the UI should show.
#[derive(Debug)]
pub enum NetEvent {
    /// Attempting to reach the relay.
    Connecting,
    /// Handshake succeeded. The UI answers this by sending a join payload,
    /// which is what makes reconnects re-announce you automatically.
    Connected {
        occupants: usize,
    },
    /// Replayed backlog, oldest first.
    History(Vec<Payload>),
    /// A payload that opened cleanly.
    Payload(Payload),
    Occupants(usize),
    /// An informational line for the transcript.
    Notice(String),
    /// Connection lost; a retry is already scheduled.
    Disconnected(String),
    /// Unrecoverable. No further events will arrive.
    Fatal(String),
}

/// Something the UI wants done on the wire.
#[derive(Debug)]
pub enum NetCmd {
    Send(Payload),
    Shutdown,
}

/// How a single connection ended.
enum Outcome {
    /// The UI asked to quit.
    Quit,
    /// The connection dropped; reconnect.
    Dropped(String),
    /// Retrying cannot help — the room key is wrong, or the two ends disagree
    /// about the protocol. Reconnecting on a loop would just reissue the same
    /// rejection every few seconds and bury the reason in the transcript.
    Hopeless(String),
}

/// Everything needed to reach a room: which relay, how to get in, and which
/// room to join once inside.
pub struct Connection {
    pub relay_url: String,
    pub access: AccessKey,
    pub room: RoomKeys,
}

impl std::fmt::Debug for Connection {
    /// Redacted: this holds the relay access key and the room's message key,
    /// and connections end up in error messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("relay_url", &self.relay_url)
            .field("access", &"<redacted>")
            .field("room_id", &hex_prefix(&self.room.room_id))
            .finish()
    }
}

/// First four bytes of a room id, enough to tell two rooms apart in a log
/// without writing out an identifier that follows a room around.
fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Starts the connection task. Returns a command sink and an event source.
pub fn spawn(conn: Connection) -> (mpsc::Sender<NetCmd>, mpsc::Receiver<NetEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (ev_tx, ev_rx) = mpsc::channel(256);
    tokio::spawn(async move {
        run(conn, cmd_rx, ev_tx).await;
    });
    (cmd_tx, ev_rx)
}

async fn run(conn: Connection, mut cmd_rx: mpsc::Receiver<NetCmd>, ev_tx: mpsc::Sender<NetEvent>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let _ = ev_tx.send(NetEvent::Connecting).await;
        match session(&conn, &mut cmd_rx, &ev_tx).await {
            Ok(Outcome::Quit) => return,
            Ok(Outcome::Hopeless(why)) => {
                let _ = ev_tx.send(NetEvent::Fatal(why)).await;
                return;
            }
            Ok(Outcome::Dropped(why)) => {
                let _ = ev_tx.send(NetEvent::Disconnected(why)).await;
            }
            Err(err) => {
                let _ = ev_tx.send(NetEvent::Disconnected(format!("{err:#}"))).await;
            }
        }

        // Wait out the backoff, but stay responsive to a quit while we do.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                cmd = cmd_rx.recv() => match cmd {
                    // Messages typed while offline are dropped rather than
                    // queued: silently delivering them minutes later, out of
                    // context, is worse than never sending them.
                    Some(NetCmd::Send(_)) => continue,
                    Some(NetCmd::Shutdown) | None => return,
                },
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Runs one connection from handshake to close.
async fn session(
    conn: &Connection,
    cmd_rx: &mut mpsc::Receiver<NetCmd>,
    ev_tx: &mpsc::Sender<NetEvent>,
) -> Result<Outcome> {
    let (stream, _) = tokio_tungstenite::connect_async(&conn.relay_url).await?;
    let (mut sink, mut source) = stream.split();

    // --- Handshake: prove we know the room key ---------------------------
    let first = next_relay_msg(&mut source)
        .await?
        .ok_or_else(|| anyhow::anyhow!("relay closed before challenging us"))?;
    let RelayMsg::Challenge { v, nonce } = first else {
        bail!("relay did not open with a challenge");
    };
    if v != PROTOCOL_VERSION {
        return Ok(Outcome::Hopeless(format!(
            "the relay speaks protocol v{v}, this client speaks v{PROTOCOL_VERSION} — \
             update whichever is older"
        )));
    }
    let challenge = unb64(&nonce)?;
    // The proof covers relay access; the room id says which room to join. The
    // room id is a one-way derivation, so naming it here tells the relay where
    // to route us without telling it anything about what we will say.
    send(
        &mut sink,
        &ClientMsg::Auth {
            v: PROTOCOL_VERSION,
            proof: b64(&conn.access.prove(&challenge)),
            room: to_hex(&conn.room.room_id),
        },
    )
    .await?;

    let welcome = next_relay_msg(&mut source)
        .await?
        .ok_or_else(|| anyhow::anyhow!("relay closed during the handshake"))?;
    let occupants = match welcome {
        RelayMsg::Welcome { occupants } => occupants,
        // Auth now covers relay access only, so a rejection means the access
        // key is wrong — never the room key, which the relay cannot check.
        RelayMsg::Error { reason } => {
            return Ok(Outcome::Hopeless(format!(
                "the relay turned us away ({reason}) — the relay access key is probably wrong"
            )));
        }
        other => bail!("unexpected reply to our handshake: {other:?}"),
    };
    let _ = ev_tx.send(NetEvent::Connected { occupants }).await;

    // --- Pump -------------------------------------------------------------
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await; // The first tick fires immediately; skip it.

    loop {
        tokio::select! {
            incoming = next_relay_msg(&mut source) => {
                let Some(msg) = incoming? else {
                    return Ok(Outcome::Dropped("relay closed the connection".into()));
                };
                match msg {
                    RelayMsg::Msg { env } => {
                        if let Some(p) = open_envelope(&conn.room, &env) {
                            let _ = ev_tx.send(NetEvent::Payload(p)).await;
                        }
                    }
                    RelayMsg::History { envs } => {
                        let payloads: Vec<Payload> = envs
                            .iter()
                            .filter_map(|env| open_envelope(&conn.room, env))
                            .collect();
                        if !payloads.is_empty() {
                            let _ = ev_tx.send(NetEvent::History(payloads)).await;
                        }
                    }
                    RelayMsg::Occupants { occupants } => {
                        let _ = ev_tx.send(NetEvent::Occupants(occupants)).await;
                    }
                    RelayMsg::Error { reason } => {
                        return Ok(Outcome::Dropped(reason));
                    }
                    RelayMsg::Pong => {}
                    RelayMsg::Challenge { .. } | RelayMsg::Welcome { .. } => {
                        let _ = ev_tx
                            .send(NetEvent::Notice("relay repeated its handshake".into()))
                            .await;
                    }
                }
            }

            cmd = cmd_rx.recv() => match cmd {
                Some(NetCmd::Send(payload)) => {
                    let json = serde_json::to_vec(&payload)?;
                    let (nonce, ciphertext) = seal(&conn.room.msg, &json)?;
                    send(&mut sink, &ClientMsg::Send {
                        env: SealedEnvelope { n: b64(&nonce), c: b64(&ciphertext) },
                    }).await?;
                }
                Some(NetCmd::Shutdown) | None => {
                    let _ = sink.close().await;
                    return Ok(Outcome::Quit);
                }
            },

            _ = keepalive.tick() => {
                send(&mut sink, &ClientMsg::Ping).await?;
            }
        }
    }
}

/// Opens one envelope, or returns `None` if it wasn't meant for this key.
///
/// A relay's history can legitimately contain messages from a *previous* room
/// key — someone rotated it, the relay kept its buffer — so a failure here is
/// mundane and gets skipped quietly rather than reported as an error.
fn open_envelope(room: &RoomKeys, env: &SealedEnvelope) -> Option<Payload> {
    let nonce = unb64(&env.n).ok()?;
    let ciphertext = unb64(&env.c).ok()?;
    let plaintext = open(&room.msg, &nonce, &ciphertext).ok()?;
    serde_json::from_slice(&plaintext).ok()
}

fn to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads the next relay message, skipping frames that aren't protocol JSON.
async fn next_relay_msg<S>(source: &mut S) -> Result<Option<RelayMsg>>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(frame) = source.next().await {
        match frame? {
            Message::Text(text) => match serde_json::from_str::<RelayMsg>(&text) {
                Ok(msg) => return Ok(Some(msg)),
                Err(_) => continue,
            },
            Message::Close(_) => return Ok(None),
            _ => continue,
        }
    }
    Ok(None)
}

async fn send<S>(sink: &mut S, msg: &ClientMsg) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::error::Error + Send + Sync + 'static,
{
    sink.send(Message::text(serde_json::to_string(msg)?))
        .await?;
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
    use rustchat_core::RoomKey;

    #[test]
    fn envelopes_roundtrip_through_the_wire_format() {
        let keys = RoomKey::generate().derive();
        let payload = Payload::Msg {
            user: "bmo".into(),
            body: "hello".into(),
            ts: 99,
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let (nonce, ct) = seal(&keys.msg, &json).unwrap();
        let env = SealedEnvelope {
            n: b64(&nonce),
            c: b64(&ct),
        };
        let back = open_envelope(&keys, &env).unwrap();
        assert_eq!(back.user(), "bmo");
        assert_eq!(back.ts(), 99);
    }

    #[test]
    fn envelopes_from_another_room_are_skipped() {
        let mine = RoomKey::generate().derive();
        let theirs = RoomKey::generate().derive();
        let json = serde_json::to_vec(&Payload::Join {
            user: "x".into(),
            ts: 0,
        })
        .unwrap();
        let (nonce, ct) = seal(&theirs.msg, &json).unwrap();
        let env = SealedEnvelope {
            n: b64(&nonce),
            c: b64(&ct),
        };
        assert!(open_envelope(&mine, &env).is_none());
    }

    #[test]
    fn connection_debug_never_leaks_key_material() {
        let access = rustchat_core::AccessKey::generate();
        let room = RoomKey::generate();
        let conn = Connection {
            relay_url: "wss://relay.example/ws".into(),
            access: rustchat_core::AccessKey::from_bytes(*access.as_bytes()),
            room: room.derive(),
        };
        let shown = format!("{conn:?}");
        assert!(shown.contains("<redacted>"));
        assert!(shown.contains("relay.example"), "the URL is not secret");
        assert!(
            !shown.contains(&to_hex(&room.derive().msg)),
            "the message key leaked into Debug output"
        );
        assert!(
            !shown.contains(&to_hex(&room.derive().room_id)),
            "the full room id should be abbreviated, not printed whole"
        );
    }

    #[test]
    fn malformed_envelopes_are_skipped() {
        let keys = RoomKey::generate().derive();
        assert!(
            open_envelope(
                &keys,
                &SealedEnvelope {
                    n: "!!!not base64".into(),
                    c: "!!!".into(),
                }
            )
            .is_none()
        );
    }
}
