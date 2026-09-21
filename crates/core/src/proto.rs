//! Wire protocol.
//!
//! Two layers sit on one WebSocket. The **outer** layer ([`ClientMsg`] /
//! [`RelayMsg`]) is plaintext JSON the relay reads and acts on: a
//! challenge/response handshake naming a room, then sealed envelopes it
//! shuttles between everyone in that room. The **inner** layer ([`Payload`])
//! is JSON sealed under the room key's message subkey, which the relay has no
//! way to read.
//!
//! Everything a human would care about — who is speaking, what they said, when
//! they joined — lives in the inner layer. The relay's view of a room is a room
//! id, a count of sockets and a pile of opaque bytes. It is configured with no
//! room keys at all, which is what lets one relay carry any number of rooms.

use serde::{Deserialize, Serialize};

/// A sealed payload as it crosses the wire. Base64 so it survives JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// Per-message nonce, base64.
    pub n: String,
    /// Ciphertext including the Poly1305 tag, base64.
    pub c: String,
}

/// Client to relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Answers [`RelayMsg::Challenge`] and names the room to join.
    ///
    /// `proof` is base64 of `BLAKE3(access_auth_key, challenge)`, proving the
    /// client may use this relay at all. `room` is the hex room id — a one-way
    /// derivation of the room key, so naming a room here reveals nothing about
    /// its contents. Rooms spring into existence on first join.
    Auth { v: u16, proof: String, room: String },
    /// Publishes a sealed payload to the room.
    Send { env: SealedEnvelope },
    /// Keepalive.
    Ping,
}

/// Relay to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum RelayMsg {
    /// Opens the handshake with a fresh random nonce, base64.
    Challenge { v: u16, nonce: String },
    /// Handshake accepted and the room joined. `occupants` counts sockets in
    /// *this room*, including this one.
    Welcome { occupants: usize },
    /// Recent traffic, oldest first, replayed on join.
    History { envs: Vec<SealedEnvelope> },
    /// A sealed payload from some member of the room.
    Msg { env: SealedEnvelope },
    /// This room's socket count changed. Carries no identity — the relay
    /// doesn't know any.
    Occupants { occupants: usize },
    /// Terminal error; the relay closes the socket after sending this.
    Error { reason: String },
    /// Keepalive response.
    Pong,
}

/// The inner, sealed payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// Someone said something.
    Msg {
        user: String,
        body: String,
        /// Sender's clock, Unix milliseconds. Advisory: it is attacker-chosen
        /// in the sense that any room member can lie about it, so it is used
        /// for display only and never for ordering or expiry.
        ts: i64,
    },
    /// Announced by a client just after a successful handshake.
    Join { user: String, ts: i64 },
    /// Announced by a client on a clean exit.
    Leave { user: String, ts: i64 },
}

impl Payload {
    /// The username attached to this payload, as claimed by its sender.
    pub fn user(&self) -> &str {
        match self {
            Payload::Msg { user, .. }
            | Payload::Join { user, .. }
            | Payload::Leave { user, .. } => user,
        }
    }

    pub fn ts(&self) -> i64 {
        match self {
            Payload::Msg { ts, .. } | Payload::Join { ts, .. } | Payload::Leave { ts, .. } => *ts,
        }
    }
}

/// Current wall clock in Unix milliseconds, or 0 if the clock is before the
/// epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Caps a username to something a terminal can render and a human can read.
///
/// Usernames are chosen client-side and never verified by anyone — the room
/// key is the only real credential, so two people can pick the same name.
/// Sanitising here keeps a hostile name from corrupting the display of every
/// other client in the room.
pub fn sanitize_username(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{200b}' && !is_bidi_control(*c))
        .take(24)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "anon".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Strips a message body of anything that would break the TUI.
pub fn sanitize_body(raw: &str) -> String {
    raw.chars()
        .filter(|c| (!c.is_control() || *c == '\n') && !is_bidi_control(*c))
        .take(crate::MAX_BODY_BYTES)
        .collect()
}

/// Unicode bidirectional overrides, which can visually reorder a line and make
/// a message read as something other than what it says.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_messages_roundtrip() {
        let msg = ClientMsg::Auth {
            v: crate::PROTOCOL_VERSION,
            proof: "abc".into(),
            room: "ff00".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"auth\""));
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(&json).unwrap(),
            ClientMsg::Auth { .. }
        ));
    }

    #[test]
    fn payloads_roundtrip() {
        let p = Payload::Msg {
            user: "bmo".into(),
            body: "hi".into(),
            ts: 42,
        };
        let back: Payload = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back.user(), "bmo");
        assert_eq!(back.ts(), 42);
    }

    #[test]
    fn usernames_are_capped_and_stripped() {
        assert_eq!(sanitize_username("  bmo\n "), "bmo");
        assert_eq!(sanitize_username(""), "anon");
        assert_eq!(sanitize_username("   "), "anon");
        assert_eq!(sanitize_username(&"x".repeat(100)).len(), 24);
        assert_eq!(sanitize_username("a\u{202e}b"), "ab");
    }

    #[test]
    fn bodies_keep_newlines_but_drop_escapes() {
        assert_eq!(sanitize_body("a\nb"), "a\nb");
        assert_eq!(sanitize_body("a\u{1b}[31mb"), "a[31mb");
        assert_eq!(sanitize_body("a\u{2066}b"), "ab");
    }
}
