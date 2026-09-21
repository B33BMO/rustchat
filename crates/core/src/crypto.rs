//! Authenticated encryption for message payloads.
//!
//! XChaCha20-Poly1305 with a fresh random 192-bit nonce per message. The nonce
//! is wide enough that random generation collides with negligible probability,
//! so clients need no shared counter state — which matters here, because
//! everyone in the room encrypts under the same key with no coordination.

use anyhow::{Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Bound into every payload as associated data, so a ciphertext from a future
/// protocol version can't be replayed into this one.
const AAD: &[u8] = b"rustchat-v1-payload";

/// Nonce width for XChaCha20-Poly1305, in bytes.
pub const NONCE_BYTES: usize = 24;

/// Encrypts `plaintext` under `msg_key`, returning `(nonce, ciphertext)`.
pub fn seal(msg_key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; NONCE_BYTES], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(msg_key.into());
    let mut nonce = [0u8; NONCE_BYTES];
    rand::fill(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok((nonce, ciphertext))
}

/// Decrypts a `(nonce, ciphertext)` pair under `msg_key`.
///
/// A failure here is expected and routine, not exceptional: it is what you get
/// when a message was sealed under a different room key. Callers should skip
/// the message rather than tear down the connection.
pub fn open(msg_key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_BYTES {
        bail!("nonce must be {NONCE_BYTES} bytes, got {}", nonce.len());
    }
    let nonce: &XNonce = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce is not {NONCE_BYTES} bytes"))?;
    let cipher = XChaCha20Poly1305::new(msg_key.into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("could not decrypt (wrong room key, or tampered message)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let key = [3u8; 32];
        let (nonce, ct) = seal(&key, b"hello room").unwrap();
        assert_eq!(open(&key, &nonce, &ct).unwrap(), b"hello room");
    }

    #[test]
    fn rejects_the_wrong_key() {
        let (nonce, ct) = seal(&[1u8; 32], b"secret").unwrap();
        assert!(open(&[2u8; 32], &nonce, &ct).is_err());
    }

    #[test]
    fn rejects_tampering() {
        let key = [4u8; 32];
        let (nonce, mut ct) = seal(&key, b"transfer $10").unwrap();
        ct[0] ^= 0x01;
        assert!(open(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn nonces_do_not_repeat() {
        let key = [5u8; 32];
        let a = seal(&key, b"x").unwrap().0;
        let b = seal(&key, b"x").unwrap().0;
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_a_short_nonce() {
        assert!(open(&[0u8; 32], &[0u8; 8], b"whatever").is_err());
    }
}
