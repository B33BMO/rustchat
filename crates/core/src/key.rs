//! Secrets and the subkeys derived from them.
//!
//! Three distinct secrets, with deliberately separate jobs:
//!
//! * [`AccessKey`] — one per relay. Decides who may open a socket at all. The
//!   relay holds only its one-way [`AccessKey::auth`] derivation, so it can
//!   turn away strangers without learning the access key itself.
//! * [`RoomKey`] — one per room, end-to-end. Yields [`RoomKeys::msg`] for
//!   encryption and [`RoomKeys::room_id`] for routing. The relay only ever
//!   learns the room id.
//! * A local passphrase, which never leaves the machine (see
//!   [`crate::vault`]).
//!
//! The room id is what lets one relay carry any number of rooms without being
//! configured for any of them. It is derived one-way, so the relay can group
//! clients by room while being unable to work back to the key that would let
//! it read them.

use anyhow::{Context, Result, bail};
use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Human-facing prefix on an encoded room key.
const ROOM_PREFIX: &str = "rc1";
/// Human-facing prefix on an encoded relay access key.
const ACCESS_PREFIX: &str = "rca1";

/// blake3 KDF contexts. These strings are part of the protocol: changing one
/// changes every derived key, so they are versioned alongside
/// [`crate::PROTOCOL_VERSION`].
const CTX_ACCESS_AUTH: &str = "rustchat v2 relay-access-auth";
const CTX_MSG: &str = "rustchat v2 message";
const CTX_ROOM_ID: &str = "rustchat v2 room-id";
const CTX_PASSPHRASE_SALT: &str = "rustchat v2 key-from-passphrase salt";

/// Argon2id cost for stretching a passphrase into a key. Deliberately heavy:
/// a passphrase-derived key is attackable offline by anyone who captures
/// ciphertext, unlike the vault which needs local disk access first.
const M_COST: u32 = 256 * 1024; // 256 MiB
const T_COST: u32 = 4;
const P_COST: u32 = 1;

/// Stretches a passphrase into 32 bytes with a fixed, domain-separated salt.
///
/// The salt has to be fixed: everyone typing the same phrase must arrive at
/// the same key. That makes the phrase's own entropy the only defence, which
/// is why generated keys are the default everywhere and this is opt-in.
fn stretch(passphrase: &str, domain: &str) -> Result<[u8; 32]> {
    let salt = blake3::derive_key(CTX_PASSPHRASE_SALT, domain.as_bytes());
    let params = argon2::Params::new(M_COST, T_COST, P_COST, Some(32))
        .map_err(|e| anyhow::anyhow!("bad argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt[..16], &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 failed: {e}"))?;
    Ok(out)
}

/// Encodes 32 bytes as `<prefix>-XXXXXXXX-...`, grouped for reading aloud.
fn encode_with(prefix: &str, bytes: &[u8; 32]) -> String {
    let body = BASE32_NOPAD.encode(bytes);
    let mut out = String::with_capacity(prefix.len() + body.len() + 8);
    out.push_str(prefix);
    for (i, ch) in body.chars().enumerate() {
        if i % 8 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Parses [`encode_with`] output, tolerating case, dashes and whitespace.
fn decode_with(prefix: &str, s: &str) -> Result<[u8; 32]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .collect();
    let lower = cleaned.to_lowercase();
    let body = lower
        .strip_prefix(prefix)
        .with_context(|| format!("expected it to start with `{prefix}`"))?;
    let raw = BASE32_NOPAD
        .decode(body.to_uppercase().as_bytes())
        .context("malformed key (bad base32)")?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("key is the wrong length"))
}

/// True when `s` looks like it was meant to be an encoded key with `prefix`.
fn looks_like(prefix: &str, s: &str) -> bool {
    s.trim()
        .trim_start_matches(['-', '_'])
        .to_lowercase()
        .starts_with(prefix)
}

/// A relay access key: the credential for opening a socket to a relay.
///
/// Separate from any room key on purpose. It stops a relay from being an open
/// service for the internet, while saying nothing about which rooms exist on
/// it or what is in them.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccessKey([u8; 32]);

impl AccessKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        Ok(Self(stretch(passphrase, "relay-access")?))
    }

    pub fn encode(&self) -> String {
        encode_with(ACCESS_PREFIX, &self.0)
    }

    pub fn decode(s: &str) -> Result<Self> {
        Ok(Self(
            decode_with(ACCESS_PREFIX, s).context("not a relay access key")?,
        ))
    }

    /// Accepts an encoded access key, or failing that a passphrase.
    pub fn parse_or_derive(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("no relay access key given");
        }
        if looks_like(ACCESS_PREFIX, trimmed) {
            return Self::decode(trimmed);
        }
        Self::from_passphrase(trimmed)
    }

    /// What the relay is configured with. One-way, so a compromised relay
    /// cannot recover the access key or impersonate its holders elsewhere.
    pub fn auth(&self) -> [u8; 32] {
        blake3::derive_key(CTX_ACCESS_AUTH, &self.0)
    }

    /// Answers a relay challenge: `BLAKE3(auth, nonce)`.
    pub fn prove(&self, challenge: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.auth(), challenge).as_bytes()
    }

    /// Hex form of [`Self::auth`], as the relay's config takes it.
    pub fn auth_hex(&self) -> String {
        to_hex(&self.auth())
    }
}

impl std::fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessKey(<redacted>)")
    }
}

/// A 32-byte room key. The only thing protecting a room's contents.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RoomKey([u8; 32]);

impl RoomKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        Ok(Self(stretch(passphrase, "room")?))
    }

    pub fn encode(&self) -> String {
        encode_with(ROOM_PREFIX, &self.0)
    }

    pub fn decode(s: &str) -> Result<Self> {
        Ok(Self(decode_with(ROOM_PREFIX, s).context("not a room key")?))
    }

    /// Accepts an encoded room key, or failing that a passphrase.
    ///
    /// A string that *looks* encoded but fails to decode is an error rather
    /// than a passphrase: quietly treating a mistyped key as a passphrase
    /// would drop you into a different, empty room with no hint as to why
    /// nobody is talking.
    pub fn parse_or_derive(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("no room key given");
        }
        if looks_like(ROOM_PREFIX, trimmed) {
            return Self::decode(trimmed);
        }
        Self::from_passphrase(trimmed)
    }

    /// Derives the subkeys used on the wire.
    pub fn derive(&self) -> RoomKeys {
        RoomKeys {
            msg: blake3::derive_key(CTX_MSG, &self.0),
            room_id: blake3::derive_key(CTX_ROOM_ID, &self.0),
        }
    }

    /// The room's routing id, hex encoded — what the relay sees.
    pub fn room_id_hex(&self) -> String {
        to_hex(&self.derive().room_id)
    }
}

impl std::fmt::Debug for RoomKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomKey(<redacted>)")
    }
}

/// Subkeys derived from a [`RoomKey`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RoomKeys {
    /// Seals and opens message payloads. Clients only; never transmitted.
    pub msg: [u8; 32],
    /// Groups clients into a room. Sent to the relay in the clear, which is
    /// safe because it is a one-way derivation: it identifies a room without
    /// enabling anyone to read it.
    pub room_id: [u8; 32],
}

/// Verifies a client's challenge response against a relay's auth key.
///
/// The relay's only crypto. Constant-time, so a client cannot learn the
/// expected proof a byte at a time by measuring how fast it is rejected.
pub fn verify_proof(auth_key: &[u8; 32], challenge: &[u8], proof: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let Ok(proof) = <[u8; 32]>::try_from(proof) else {
        return false;
    };
    let expected = blake3::keyed_hash(auth_key, challenge);
    expected.as_bytes().ct_eq(&proof).into()
}

fn to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses a 32-byte hex value, such as a relay's configured auth key.
pub fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        bail!("expected 64 hex characters, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).context("not valid hex")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_keys_roundtrip() {
        let k = RoomKey::generate();
        assert_eq!(
            RoomKey::decode(&k.encode()).unwrap().as_bytes(),
            k.as_bytes()
        );
    }

    #[test]
    fn access_keys_roundtrip() {
        let k = AccessKey::generate();
        assert_eq!(
            AccessKey::decode(&k.encode()).unwrap().as_bytes(),
            k.as_bytes()
        );
    }

    #[test]
    fn the_two_key_kinds_are_not_interchangeable() {
        // Pasting one where the other is wanted must fail loudly rather than
        // silently producing a key that authenticates nothing.
        let room = RoomKey::generate();
        let access = AccessKey::generate();
        assert!(AccessKey::decode(&room.encode()).is_err());
        assert!(RoomKey::decode(&access.encode()).is_err());
    }

    #[test]
    fn decoding_tolerates_sloppy_input() {
        let k = RoomKey::generate();
        let mangled = format!("  {}  ", k.encode().to_lowercase().replace('-', " "));
        assert_eq!(RoomKey::decode(&mangled).unwrap().as_bytes(), k.as_bytes());
    }

    #[test]
    fn mistyped_key_errors_instead_of_becoming_a_passphrase() {
        let mut encoded = RoomKey::generate().encode();
        encoded.pop();
        assert!(RoomKey::parse_or_derive(&encoded).is_err());
    }

    #[test]
    fn room_subkeys_are_distinct_and_stable() {
        let k = RoomKey::from_bytes([7u8; 32]);
        let a = k.derive();
        let b = k.derive();
        assert_eq!(a.msg, b.msg);
        assert_eq!(a.room_id, b.room_id);
        assert_ne!(a.msg, a.room_id, "the room id must not be the message key");
        assert_ne!(
            a.room_id,
            *k.as_bytes(),
            "the room id must not leak the room key"
        );
    }

    #[test]
    fn the_room_id_does_not_reveal_the_message_key() {
        // The relay is told the room id. If that let it reconstruct the
        // message key, the whole design would be pointless.
        let k = RoomKey::generate();
        let keys = k.derive();
        assert_ne!(keys.room_id, keys.msg);
        assert_ne!(blake3::derive_key(CTX_MSG, &keys.room_id), keys.msg);
    }

    #[test]
    fn different_rooms_get_different_ids() {
        assert_ne!(
            RoomKey::generate().room_id_hex(),
            RoomKey::generate().room_id_hex()
        );
    }

    #[test]
    fn access_auth_does_not_reveal_the_access_key() {
        let k = AccessKey::generate();
        assert_ne!(k.auth(), *k.as_bytes());
    }

    #[test]
    fn proofs_are_challenge_bound() {
        let k = AccessKey::generate();
        assert_ne!(k.prove(b"nonce-a"), k.prove(b"nonce-b"));
    }

    #[test]
    fn verifies_only_the_right_proof() {
        let k = AccessKey::generate();
        let auth = k.auth();
        let challenge = b"a challenge";
        assert!(verify_proof(&auth, challenge, &k.prove(challenge)));
        assert!(!verify_proof(&auth, b"other", &k.prove(challenge)));
        assert!(!verify_proof(&[0u8; 32], challenge, &k.prove(challenge)));
        assert!(!verify_proof(&auth, challenge, b"too short"));
    }

    #[test]
    fn hex_roundtrips() {
        let k = AccessKey::generate();
        assert_eq!(parse_hex32(&k.auth_hex()).unwrap(), k.auth());
        assert!(parse_hex32("nope").is_err());
        assert!(parse_hex32(&"z".repeat(64)).is_err());
    }
}
