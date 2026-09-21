//! The on-disk vault: a room key and your scrollback, sealed under a local
//! passphrase.
//!
//! This is the only thing rustchat ever writes to disk, and it is opaque
//! without your passphrase. The passphrase is yours alone and is never sent
//! anywhere — it is not the room key and does not need to match anybody
//! else's. Losing it costs you the stored copy of the room key and your local
//! history; it does not lock you out of the room, since you can always paste
//! the room key again.

use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const MAGIC: &[u8; 6] = b"RCVLT1";
const FORMAT_VERSION: u8 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const HEADER_BYTES: usize = 6 + 1 + 4 + 4 + 4 + SALT_BYTES + NONCE_BYTES;
const AAD: &[u8] = b"rustchat-vault-v1";

/// Argon2id cost for the vault. Tuned for a roughly quarter-second unlock on a
/// normal laptop: high enough to make guessing expensive, low enough that
/// typing your passphrase doesn't feel like a penalty.
const M_COST: u32 = 64 * 1024; // 64 MiB
const T_COST: u32 = 3;
const P_COST: u32 = 1;

/// How many of your own messages to keep. Old ones fall off the front.
pub const HISTORY_LIMIT: usize = 500;

/// One remembered line of chat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLine {
    pub user: String,
    pub body: String,
    pub ts: i64,
}

/// Vault contents, as they exist decrypted in memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    /// Base64 of the 32-byte room key.
    #[serde(default)]
    pub room_key_b64: String,
    #[serde(default)]
    pub relay_url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub history: Vec<StoredLine>,
}

impl VaultData {
    /// Appends a line, evicting the oldest once past [`HISTORY_LIMIT`].
    pub fn push_line(&mut self, line: StoredLine) {
        self.history.push(line);
        if self.history.len() > HISTORY_LIMIT {
            let excess = self.history.len() - HISTORY_LIMIT;
            self.history.drain(..excess);
        }
    }
}

/// Stretches a passphrase into a sealing key using the given salt and costs.
fn derive_sealing_key(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32]> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("bad argon2 params: {e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 failed: {e}"))?;
    Ok(out)
}

/// Serialises and seals `data` under `passphrase`, producing vault file bytes.
pub fn seal_vault(passphrase: &str, data: &VaultData) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    let mut salt = [0u8; SALT_BYTES];
    rand::fill(&mut salt);
    let mut nonce = [0u8; NONCE_BYTES];
    rand::fill(&mut nonce);

    let mut sealing_key = derive_sealing_key(passphrase, &salt, M_COST, T_COST, P_COST)?;
    let cipher = XChaCha20Poly1305::new((&sealing_key).into());
    let mut plaintext = serde_json::to_vec(data).context("serialising vault")?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            AeadPayload {
                msg: &plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| anyhow::anyhow!("sealing vault failed"));
    plaintext.zeroize();
    sealing_key.zeroize();
    let ciphertext = ciphertext?;

    let mut out = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&M_COST.to_le_bytes());
    out.extend_from_slice(&T_COST.to_le_bytes());
    out.extend_from_slice(&P_COST.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens vault file bytes with `passphrase`.
///
/// Costs are read from the file's own header rather than the constants above,
/// so a vault written by an older build still opens after they are retuned.
pub fn open_vault(passphrase: &str, bytes: &[u8]) -> Result<VaultData> {
    if bytes.len() < HEADER_BYTES {
        bail!("vault file is truncated");
    }
    if &bytes[..6] != MAGIC {
        bail!("not a rustchat vault file");
    }
    if bytes[6] != FORMAT_VERSION {
        bail!("vault format v{} is not supported by this build", bytes[6]);
    }
    let u32_at = |off: usize| {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let m_cost = u32_at(7);
    let t_cost = u32_at(11);
    let p_cost = u32_at(15);
    // A hostile vault file could otherwise name a multi-gigabyte memory cost
    // and turn unlocking into an OOM.
    if m_cost > 1024 * 1024 || t_cost > 32 || p_cost > 16 {
        bail!("vault header declares implausible argon2 costs; refusing to open it");
    }
    let salt = &bytes[19..19 + SALT_BYTES];
    let nonce = &bytes[19 + SALT_BYTES..HEADER_BYTES];
    let ciphertext = &bytes[HEADER_BYTES..];

    let mut sealing_key = derive_sealing_key(passphrase, salt, m_cost, t_cost, p_cost)?;
    let cipher = XChaCha20Poly1305::new((&sealing_key).into());
    let nonce: &XNonce = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("vault nonce is malformed"))?;
    let plaintext = cipher.decrypt(
        nonce,
        AeadPayload {
            msg: ciphertext,
            aad: AAD,
        },
    );
    sealing_key.zeroize();
    let mut plaintext = plaintext.map_err(|_| anyhow::anyhow!("wrong passphrase"))?;
    let data = serde_json::from_slice(&plaintext).context("vault contents are corrupt");
    plaintext.zeroize();
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultData {
        VaultData {
            room_key_b64: "aaaa".into(),
            relay_url: "wss://relay.example/ws".into(),
            username: "bmo".into(),
            history: vec![StoredLine {
                user: "bmo".into(),
                body: "hello".into(),
                ts: 1,
            }],
        }
    }

    #[test]
    fn roundtrips() {
        let sealed = seal_vault("correct horse", &sample()).unwrap();
        let opened = open_vault("correct horse", &sealed).unwrap();
        assert_eq!(opened.username, "bmo");
        assert_eq!(opened.history.len(), 1);
    }

    #[test]
    fn rejects_the_wrong_passphrase() {
        let sealed = seal_vault("right", &sample()).unwrap();
        let err = open_vault("wrong", &sealed).unwrap_err().to_string();
        assert!(err.contains("wrong passphrase"), "got: {err}");
    }

    #[test]
    fn rejects_an_empty_passphrase() {
        assert!(seal_vault("", &sample()).is_err());
    }

    #[test]
    fn plaintext_does_not_appear_in_the_file() {
        let sealed = seal_vault("pw", &sample()).unwrap();
        assert!(
            !sealed.windows(3).any(|w| w == b"bmo"),
            "username leaked into the vault file in the clear"
        );
    }

    #[test]
    fn detects_tampering() {
        let mut sealed = seal_vault("pw", &sample()).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open_vault("pw", &sealed).is_err());
    }

    #[test]
    fn rejects_junk_and_truncation() {
        assert!(open_vault("pw", b"nope").is_err());
        assert!(open_vault("pw", &[0u8; 128]).is_err());
    }

    #[test]
    fn refuses_absurd_costs() {
        let mut sealed = seal_vault("pw", &sample()).unwrap();
        sealed[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = open_vault("pw", &sealed).unwrap_err().to_string();
        assert!(err.contains("implausible"), "got: {err}");
    }

    #[test]
    fn history_is_capped() {
        let mut data = VaultData::default();
        for i in 0..(HISTORY_LIMIT + 50) {
            data.push_line(StoredLine {
                user: "u".into(),
                body: format!("{i}"),
                ts: i as i64,
            });
        }
        assert_eq!(data.history.len(), HISTORY_LIMIT);
        assert_eq!(data.history[0].body, "50", "oldest lines should be evicted");
    }
}
