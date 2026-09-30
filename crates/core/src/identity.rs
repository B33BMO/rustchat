//! Per-device signing identities.
//!
//! The room key gets you in the door but says nothing about who is speaking:
//! anyone in the room can put any name on a message. So each device also holds
//! an Ed25519 key and signs what it sends. Nobody vouches for these keys —
//! there's still no server-side identity — but a key, once seen for a name,
//! lets every later message under that name be checked against it. That's
//! trust on first use, like SSH host keys: it can't stop an impostor who got
//! there first, but it does make a *change* visible, which is the attack that
//! matters inside a room of people who already know each other.
//!
//! A signature travels as an optional extra field beside the payload
//! ([`Signed`]). Older clients ignore fields they don't know, so they keep
//! reading signed messages, and newer ones see unsigned messages as just that.

use base64::Engine;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::proto::Payload;

/// Domain separation for what gets signed, so a signature made here can't be
/// passed off as one made for any other purpose.
const CONTEXT: &[u8] = b"rustchat v2 signed payload\0";

/// Human-facing prefix on an encoded identity.
const IDENTITY_PREFIX: &str = "rcid1";

/// Bytes of a public key, and of a signature.
pub const PUBLIC_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;

/// This device's signing key.
pub struct Identity(SigningKey);

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        let identity = Self::from_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);
        identity
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The secret seed, for sealing into the vault. Handle with care.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `rcid1-…`, for carrying an identity somewhere without a vault — a
    /// bot's environment, say — so it keeps one key across runs. Secret.
    pub fn encode(&self) -> String {
        let mut seed = self.to_bytes();
        let out = crate::key::encode_with(IDENTITY_PREFIX, &seed);
        zeroize::Zeroize::zeroize(&mut seed);
        out
    }

    pub fn decode(s: &str) -> anyhow::Result<Self> {
        use anyhow::Context;
        let mut seed =
            crate::key::decode_with(IDENTITY_PREFIX, s).context("not a rustchat identity")?;
        let identity = Self::from_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);
        Ok(identity)
    }

    pub fn public(&self) -> [u8; PUBLIC_BYTES] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs `payload` for the room with this id.
    pub fn sign(&self, room_id: &[u8; 32], payload: &Payload) -> Sig {
        let signature = self.0.sign(&signing_bytes(room_id, payload));
        Sig {
            pk: b64(&self.public()),
            s: b64(&signature.to_bytes()),
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", fingerprint(&self.public()))
    }
}

/// A signature and the key that made it, as carried beside a payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sig {
    /// Public key, base64.
    pub pk: String,
    /// Signature, base64.
    pub s: String,
}

/// What's actually sealed: a payload and, from clients that sign, a signature.
///
/// Flattened so the payload's own fields stay at the top level — which is
/// what lets an older client, reading this as a plain [`Payload`], simply
/// skip the extra `sig` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    #[serde(flatten)]
    pub payload: Payload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Sig>,
}

/// Who, cryptographically, sent a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    /// No signature: an older client, or someone declining to sign.
    Unsigned,
    /// Signed by this key, and the signature checks out.
    Valid([u8; PUBLIC_BYTES]),
    /// A signature that doesn't verify. Either tampering, or someone pasting
    /// another person's key onto a message they wrote.
    Invalid,
}

impl Signed {
    /// Checks the signature against `room_id`, the room this arrived in.
    pub fn verify(&self, room_id: &[u8; 32]) -> Signer {
        let Some(sig) = &self.sig else {
            return Signer::Unsigned;
        };
        let check = || -> Option<[u8; PUBLIC_BYTES]> {
            let pk: [u8; PUBLIC_BYTES] = unb64(&sig.pk)?.try_into().ok()?;
            let s: [u8; SIGNATURE_BYTES] = unb64(&sig.s)?.try_into().ok()?;
            let key = VerifyingKey::from_bytes(&pk).ok()?;
            // Strict: rejects the malleable and small-order edge cases that
            // plain verification lets through.
            key.verify_strict(
                &signing_bytes(room_id, &self.payload),
                &Signature::from_bytes(&s),
            )
            .ok()?;
            Some(pk)
        };
        match check() {
            Some(pk) => Signer::Valid(pk),
            None => Signer::Invalid,
        }
    }
}

/// The exact bytes a signature covers.
///
/// Built by hand rather than by re-serialising JSON, so that verifying never
/// depends on two machines producing byte-identical JSON. Every field is
/// length-prefixed, so no two different payloads encode alike, and the room id
/// is included so a message signed in one room can't be replayed into another.
fn signing_bytes(room_id: &[u8; 32], payload: &Payload) -> Vec<u8> {
    let (kind, user, body, ts) = match payload {
        Payload::Msg { user, body, ts } => (0u8, user, body.as_str(), ts),
        Payload::Join { user, ts } => (1, user, "", ts),
        Payload::Leave { user, ts } => (2, user, "", ts),
    };
    let mut out = Vec::with_capacity(CONTEXT.len() + 32 + 1 + 8 + user.len() + body.len() + 8);
    out.extend_from_slice(CONTEXT);
    out.extend_from_slice(room_id);
    out.push(kind);
    for field in [user.as_bytes(), body.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&ts.to_le_bytes());
    out
}

/// A short, readable form of a public key for people to compare, e.g.
/// `3f7a 91c2 0b4d e6f8`. Hashed rather than truncated, so it depends on the
/// whole key.
pub fn fingerprint(pk: &[u8; PUBLIC_BYTES]) -> String {
    let hash = blake3::derive_key("rustchat v2 key fingerprint", pk);
    hash[..8]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `typed` names the key `pk`: its fingerprint, or enough of the start
/// of it to be unambiguous, ignoring spaces and case.
pub fn fingerprint_matches(pk: &[u8; PUBLIC_BYTES], typed: &str) -> bool {
    let want: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    // Four hex digits is too few to mean anything; demand at least eight.
    want.len() >= 8 && fingerprint(pk).replace(' ', "").starts_with(&want)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: [u8; 32] = [9; 32];

    fn msg(user: &str, body: &str) -> Payload {
        Payload::Msg {
            user: user.into(),
            body: body.into(),
            ts: 1_790_000_000_000,
        }
    }

    fn signed(id: &Identity, payload: Payload) -> Signed {
        Signed {
            sig: Some(id.sign(&ROOM, &payload)),
            payload,
        }
    }

    #[test]
    fn a_signature_verifies_to_its_key() {
        let id = Identity::generate();
        let s = signed(&id, msg("bmo", "hi"));
        assert_eq!(s.verify(&ROOM), Signer::Valid(id.public()));
    }

    #[test]
    fn any_change_breaks_it() {
        let id = Identity::generate();
        let original = signed(&id, msg("bmo", "pay sam $10"));

        let mut edited = original.clone();
        edited.payload = msg("bmo", "pay sam $1000");
        assert_eq!(edited.verify(&ROOM), Signer::Invalid, "body");

        let mut renamed = original.clone();
        renamed.payload = msg("sam", "pay sam $10");
        assert_eq!(renamed.verify(&ROOM), Signer::Invalid, "name");

        let mut redated = original.clone();
        redated.payload = Payload::Msg {
            user: "bmo".into(),
            body: "pay sam $10".into(),
            ts: 1,
        };
        assert_eq!(redated.verify(&ROOM), Signer::Invalid, "timestamp");
    }

    #[test]
    fn a_signature_is_bound_to_its_room() {
        let id = Identity::generate();
        let s = signed(&id, msg("bmo", "hi"));
        assert_eq!(s.verify(&[8; 32]), Signer::Invalid);
    }

    #[test]
    fn a_borrowed_public_key_does_not_help_a_forger() {
        // Claiming someone else's key on a message you signed yourself.
        let victim = Identity::generate();
        let forger = Identity::generate();
        let mut s = signed(&forger, msg("victim", "i quit"));
        s.sig.as_mut().unwrap().pk = b64(&victim.public());
        assert_eq!(s.verify(&ROOM), Signer::Invalid);
    }

    #[test]
    fn kinds_are_not_interchangeable() {
        let id = Identity::generate();
        let join = Payload::Join {
            user: "bmo".into(),
            ts: 5,
        };
        let leave = Payload::Leave {
            user: "bmo".into(),
            ts: 5,
        };
        let s = Signed {
            sig: Some(id.sign(&ROOM, &join)),
            payload: leave,
        };
        assert_eq!(s.verify(&ROOM), Signer::Invalid);
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Without length prefixes, ("ab", "c") and ("a", "bc") would sign
        // the same bytes.
        assert_ne!(
            signing_bytes(&ROOM, &msg("ab", "c")),
            signing_bytes(&ROOM, &msg("a", "bc"))
        );
    }

    #[test]
    fn garbage_signatures_are_invalid_not_panics() {
        let mut s = signed(&Identity::generate(), msg("bmo", "hi"));
        for (pk, sig) in [("", ""), ("!!!", "???"), ("AAAA", "AAAA")] {
            s.sig = Some(Sig {
                pk: pk.into(),
                s: sig.into(),
            });
            assert_eq!(s.verify(&ROOM), Signer::Invalid);
        }
    }

    #[test]
    fn unsigned_is_its_own_answer() {
        let s = Signed {
            payload: msg("bmo", "hi"),
            sig: None,
        };
        assert_eq!(s.verify(&ROOM), Signer::Unsigned);
    }

    #[test]
    fn identities_survive_the_vault_roundtrip() {
        let id = Identity::generate();
        let back = Identity::from_bytes(&id.to_bytes());
        assert_eq!(back.public(), id.public());
    }

    #[test]
    fn identities_encode_and_decode() {
        let id = Identity::generate();
        let text = id.encode();
        assert!(text.starts_with("rcid1-"), "{text}");
        assert_eq!(Identity::decode(&text).unwrap().public(), id.public());
        assert!(Identity::decode(&crate::RoomKey::generate().encode()).is_err());
    }

    #[test]
    fn older_clients_still_read_signed_messages() {
        // The compatibility promise: a signed payload parses as a plain one.
        let s = signed(&Identity::generate(), msg("bmo", "hi"));
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"sig\""));
        let old: Payload = serde_json::from_str(&json).unwrap();
        assert_eq!(old, msg("bmo", "hi"));
    }

    #[test]
    fn newer_clients_read_unsigned_messages() {
        let json = serde_json::to_string(&msg("bmo", "hi")).unwrap();
        let s: Signed = serde_json::from_str(&json).unwrap();
        assert_eq!(s.sig, None);
        assert_eq!(s.payload, msg("bmo", "hi"));
    }

    #[test]
    fn fingerprints_are_short_stable_and_matchable() {
        let id = Identity::generate();
        let fp = fingerprint(&id.public());
        assert_eq!(fp.len(), 19, "{fp}");
        assert_eq!(fp, fingerprint(&id.public()));
        assert!(fingerprint_matches(&id.public(), &fp));
        assert!(fingerprint_matches(&id.public(), &fp[..9].to_uppercase()));
        assert!(
            !fingerprint_matches(&id.public(), &fp[..4]),
            "too short to trust"
        );
        assert!(!fingerprint_matches(&Identity::generate().public(), &fp));
    }
}
