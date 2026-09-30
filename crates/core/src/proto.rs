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

/// Exactly how many bytes `payload` will occupy on the wire once sealed and
/// encoded, as the relay measures it against
/// [`MAX_ENVELOPE_BYTES`](crate::MAX_ENVELOPE_BYTES).
///
/// Worth checking before sending: the relay drops an over-size envelope
/// without a word, and JSON escaping means a body within
/// [`MAX_BODY_BYTES`](crate::MAX_BODY_BYTES) can still seal too large — every
/// quote, backslash or newline costs two bytes.
pub fn envelope_size(sealed: &impl Serialize) -> usize {
    let json = serde_json::to_vec(sealed)
        .map(|v| v.len())
        .unwrap_or(usize::MAX / 2);
    let b64 = |n: usize| n.div_ceil(3) * 4;
    b64(crate::crypto::NONCE_BYTES) + b64(json + crate::crypto::TAG_BYTES)
}

/// Whether `payload` will fit through the relay once signed.
pub fn fits(payload: &Payload) -> bool {
    signed_size(payload) <= crate::MAX_ENVELOPE_BYTES
}

/// [`envelope_size`] of `payload` with a signature attached — the size that
/// actually goes out. Signatures are fixed-size, so a placeholder of the right
/// length measures exactly.
pub fn signed_size(payload: &Payload) -> usize {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    envelope_size(&crate::Signed {
        payload: payload.clone(),
        sig: Some(crate::identity::Sig {
            pk: b64.encode([0u8; crate::identity::PUBLIC_BYTES]),
            s: b64.encode([0u8; crate::identity::SIGNATURE_BYTES]),
        }),
    })
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

/// Strips a message body of anything that would break the TUI, and caps it at
/// [`MAX_BODY_BYTES`](crate::MAX_BODY_BYTES) on a character boundary.
///
/// The cap is in bytes because the relay's envelope cap is: a body capped in
/// characters could be four times the size in emoji, seal to more than the
/// relay accepts, and be dropped without anyone being told.
pub fn sanitize_body(raw: &str) -> String {
    let mut out = String::new();
    for c in raw
        .chars()
        .filter(|c| (!c.is_control() || *c == '\n') && !is_bidi_control(*c))
    {
        if out.len() + c.len_utf8() > crate::MAX_BODY_BYTES {
            break;
        }
        out.push(c);
    }
    out
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
    fn bodies_are_capped_in_bytes_not_characters() {
        let emoji = "🦀".repeat(crate::MAX_BODY_BYTES);
        let body = sanitize_body(&emoji);
        assert!(body.len() <= crate::MAX_BODY_BYTES, "{} bytes", body.len());
        assert_eq!(
            body.len(),
            crate::MAX_BODY_BYTES,
            "4-byte chars fill it exactly"
        );
        assert!(body.chars().all(|c| c == '🦀'), "never cut mid-character");
    }

    fn sealed_size(payload: &Payload) -> usize {
        use base64::Engine;
        let json = serde_json::to_vec(payload).unwrap();
        let (nonce, ct) = crate::seal(&[0u8; 32], &json).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        b64.encode(nonce).len() + b64.encode(ct).len()
    }

    #[test]
    fn envelope_size_is_exact() {
        for body in ["", "hi", "a\"b\\c\nd", &"🦀".repeat(300), &"x".repeat(4096)] {
            let p = Payload::Msg {
                user: "bmo".into(),
                body: body.into(),
                ts: 1_790_000_000_000,
            };
            assert_eq!(envelope_size(&p), sealed_size(&p), "body {body:?}");
        }
    }

    #[test]
    fn signed_size_is_exact() {
        let id = crate::Identity::generate();
        let payload = Payload::Msg {
            user: "bmo".into(),
            body: "a \"quoted\" line".into(),
            ts: 7,
        };
        let signed = crate::Signed {
            sig: Some(id.sign(&[1; 32], &payload)),
            payload: payload.clone(),
        };
        assert_eq!(signed_size(&payload), envelope_size(&signed));
    }

    #[test]
    fn a_full_plain_body_fits_but_a_full_escaped_one_does_not() {
        let plain = Payload::Msg {
            user: "x".repeat(24),
            body: sanitize_body(&"x".repeat(crate::MAX_BODY_BYTES)),
            ts: i64::MAX,
        };
        assert!(fits(&plain), "{} bytes", signed_size(&plain));
        // Quotes are the worst case: one byte of body, two of JSON. This is
        // what `fits` exists to catch, since the relay would drop it silently.
        let escaped = Payload::Msg {
            user: "x".into(),
            body: sanitize_body(&"\"".repeat(crate::MAX_BODY_BYTES)),
            ts: 0,
        };
        assert!(!fits(&escaped));
    }

    #[test]
    fn bodies_keep_newlines_but_drop_escapes() {
        assert_eq!(sanitize_body("a\nb"), "a\nb");
        assert_eq!(sanitize_body("a\u{1b}[31mb"), "a[31mb");
        assert_eq!(sanitize_body("a\u{2066}b"), "ab");
    }
}
