//! The room key: parsing, formatting, and subkey derivation.

use anyhow::{Context, Result, bail};
use data_encoding::BASE32_NOPAD;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Human-facing prefix on an encoded room key.
const PREFIX: &str = "rc1";

/// blake3 KDF contexts. These strings are part of the protocol: changing one
/// changes every derived key, so they are versioned alongside
/// [`crate::PROTOCOL_VERSION`].
const CTX_AUTH: &str = "rustchat v1 relay-auth";
const CTX_MSG: &str = "rustchat v1 message";
const CTX_ROOM_SALT: &str = "rustchat v1 room-key-from-passphrase salt";

/// Argon2id cost for stretching a *room* passphrase. Deliberately heavier than
/// the vault's cost: a room passphrase is attackable offline by anyone who can
/// capture ciphertext off the relay, whereas the vault needs local disk access.
const ROOM_M_COST: u32 = 256 * 1024; // 256 MiB
const ROOM_T_COST: u32 = 4;
const ROOM_P_COST: u32 = 1;

/// A 32-byte room key. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RoomKey([u8; 32]);

impl RoomKey {
    /// Generates a fresh room key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        Self(bytes)
    }

    /// Wraps raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Stretches a human-chosen passphrase into a room key with Argon2id.
    ///
    /// The salt is a fixed, domain-separated constant — it has to be, since
    /// every member must land on the same key from the same phrase. That makes
    /// the passphrase's own entropy the only thing standing between an
    /// eavesdropper and the room, which is why [`Self::generate`] is the
    /// default and this is opt-in.
    pub fn from_passphrase(passphrase: &str) -> Result<Self> {
        let salt = blake3::derive_key(CTX_ROOM_SALT, b"rustchat");
        let params = argon2::Params::new(ROOM_M_COST, ROOM_T_COST, ROOM_P_COST, Some(32))
            .map_err(|e| anyhow::anyhow!("bad argon2 params: {e}"))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), &salt[..16], &mut out)
            .map_err(|e| anyhow::anyhow!("argon2 failed: {e}"))?;
        Ok(Self(out))
    }

    /// Encodes as `rc1-XXXXXXXX-...`, grouped for reading aloud.
    pub fn encode(&self) -> String {
        let body = BASE32_NOPAD.encode(&self.0);
        let mut out = String::with_capacity(PREFIX.len() + body.len() + 8);
        out.push_str(PREFIX);
        for (i, ch) in body.chars().enumerate() {
            if i % 8 == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        out
    }

    /// Parses [`Self::encode`] output, tolerating case, dashes and whitespace.
    pub fn decode(s: &str) -> Result<Self> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .collect();
        let body = cleaned
            .strip_prefix(PREFIX)
            .or_else(|| cleaned.strip_prefix(&PREFIX.to_uppercase()))
            .context("not a room key: expected it to start with `rc1`")?;
        let raw = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .context("room key is malformed (bad base32)")?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("room key is the wrong length"))?;
        Ok(Self(bytes))
    }

    /// Accepts either an encoded room key or, failing that, a passphrase.
    ///
    /// A string that *looks* like an encoded key but fails to decode is an
    /// error rather than a passphrase — silently treating a mistyped key as a
    /// passphrase would drop you into a different, empty room with no hint as
    /// to why nobody is talking.
    pub fn parse_or_derive(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("no room key given");
        }
        let looks_encoded = trimmed
            .trim_start_matches(['-', '_'])
            .to_lowercase()
            .starts_with(PREFIX);
        if looks_encoded {
            return Self::decode(trimmed);
        }
        Self::from_passphrase(trimmed)
    }

    /// Derives the subkeys actually used on the wire.
    pub fn derive(&self) -> Keys {
        Keys {
            auth: blake3::derive_key(CTX_AUTH, &self.0),
            msg: blake3::derive_key(CTX_MSG, &self.0),
        }
    }
}

impl std::fmt::Debug for RoomKey {
    /// Never prints key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomKey(<redacted>)")
    }
}

/// Subkeys derived from a [`RoomKey`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    /// Proves room membership to the relay. Safe to hand the relay: it is a
    /// one-way derivation, so it cannot be walked back to the room key or
    /// forward to [`Keys::msg`].
    pub auth: [u8; 32],
    /// Seals and opens message payloads. Clients only.
    pub msg: [u8; 32],
}

impl Keys {
    /// Answers a relay challenge: `BLAKE3(auth_key, nonce)`.
    pub fn prove(&self, challenge: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.auth, challenge).as_bytes()
    }

    /// Hex-encodes the auth key, the form the relay is configured with.
    pub fn auth_hex(&self) -> String {
        self.auth.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Verifies a client's challenge response against an auth key.
///
/// This is the relay's half of the handshake, and the only crypto it performs.
/// The comparison is constant-time so that a client cannot learn the expected
/// proof one byte at a time by measuring how fast it is rejected.
pub fn verify_proof(auth_key: &[u8; 32], challenge: &[u8], proof: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let Ok(proof) = <[u8; 32]>::try_from(proof) else {
        return false;
    };
    let expected = blake3::keyed_hash(auth_key, challenge);
    expected.as_bytes().ct_eq(&proof).into()
}

/// Parses the hex auth key from a relay's config.
pub fn parse_auth_hex(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        bail!("auth key must be 64 hex characters, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).context("auth key is not valid hex")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_encoding() {
        let k = RoomKey::generate();
        let decoded = RoomKey::decode(&k.encode()).unwrap();
        assert_eq!(k.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn decoding_tolerates_sloppy_input() {
        let k = RoomKey::generate();
        let encoded = k.encode();
        let mangled = format!("  {}  ", encoded.to_lowercase().replace('-', " "));
        assert_eq!(RoomKey::decode(&mangled).unwrap().as_bytes(), k.as_bytes());
    }

    #[test]
    fn mistyped_key_errors_instead_of_becoming_a_passphrase() {
        let mut encoded = RoomKey::generate().encode();
        encoded.pop();
        assert!(RoomKey::parse_or_derive(&encoded).is_err());
    }

    #[test]
    fn subkeys_are_distinct_and_stable() {
        let k = RoomKey::from_bytes([7u8; 32]);
        let a = k.derive();
        let b = k.derive();
        assert_eq!(a.auth, b.auth);
        assert_eq!(a.msg, b.msg);
        assert_ne!(a.auth, a.msg, "auth and msg subkeys must not collide");
        assert_ne!(
            a.auth,
            *k.as_bytes(),
            "auth subkey must not leak the room key"
        );
    }

    #[test]
    fn proofs_are_challenge_bound() {
        let keys = RoomKey::from_bytes([1u8; 32]).derive();
        assert_ne!(keys.prove(b"nonce-a"), keys.prove(b"nonce-b"));
    }

    #[test]
    fn verifies_only_the_right_proof() {
        let keys = RoomKey::generate().derive();
        let challenge = b"a challenge";
        assert!(verify_proof(&keys.auth, challenge, &keys.prove(challenge)));
        assert!(!verify_proof(
            &keys.auth,
            b"other challenge",
            &keys.prove(challenge)
        ));
        assert!(!verify_proof(&[0u8; 32], challenge, &keys.prove(challenge)));
        assert!(!verify_proof(&keys.auth, challenge, b"too short"));
    }

    #[test]
    fn auth_hex_roundtrips() {
        let keys = RoomKey::generate().derive();
        assert_eq!(parse_auth_hex(&keys.auth_hex()).unwrap(), keys.auth);
    }
}
