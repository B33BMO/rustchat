//! Invites: everything a newcomer needs, in one paste.
//!
//! Joining otherwise means typing three separate things — a relay address, a
//! relay access key and a room key — which is three chances to get it wrong.
//! An invite bundles them into a single token.
//!
//! An invite is a **secret**. It contains the room key, so anyone holding it
//! can read the room, and the access key, so they can reach the relay. It
//! deserves the same care as the room key itself.

use anyhow::{Context, Result, bail};
use data_encoding::BASE32_NOPAD;
use zeroize::Zeroize;

use crate::key::{AccessKey, RoomKey};

const PREFIX: &str = "rcinv1";
const FORMAT_VERSION: u8 = 1;
/// Longer than any sane relay URL, short enough to bound a hostile invite.
const MAX_URL_BYTES: usize = 200;

/// A decoded invite.
pub struct Invite {
    pub relay_url: String,
    pub access_key: AccessKey,
    /// Absent for an invite to the relay but not to any particular room.
    pub room_key: Option<RoomKey>,
}

impl Invite {
    /// Packs the invite into a single case-insensitive token.
    pub fn encode(&self) -> String {
        let url = self.relay_url.as_bytes();
        let mut payload = Vec::with_capacity(2 + 32 + 32 + 1 + url.len());
        payload.push(FORMAT_VERSION);
        payload.push(u8::from(self.room_key.is_some()));
        payload.extend_from_slice(self.access_key.as_bytes());
        if let Some(room) = &self.room_key {
            payload.extend_from_slice(room.as_bytes());
        }
        payload.push(url.len() as u8);
        payload.extend_from_slice(url);

        let token = format!("{PREFIX}-{}", BASE32_NOPAD.encode(&payload));
        payload.zeroize();
        token
    }

    /// Unpacks [`Self::encode`] output, tolerating case and whitespace.
    pub fn decode(s: &str) -> Result<Self> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let body = cleaned
            .to_lowercase()
            .strip_prefix(PREFIX)
            .map(|rest| rest.trim_start_matches('-').to_string())
            .context("not an invite: expected it to start with `rcinv1`")?;
        let mut payload = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .context("invite is malformed (bad base32)")?;

        let result = Self::from_payload(&payload);
        payload.zeroize();
        result
    }

    fn from_payload(payload: &[u8]) -> Result<Self> {
        // Every length is checked before use: an invite arrives from outside
        // and a truncated one must be an error, never a panic.
        if payload.len() < 2 + 32 + 1 {
            bail!("invite is truncated");
        }
        if payload[0] != FORMAT_VERSION {
            bail!(
                "invite format v{} is not supported by this build",
                payload[0]
            );
        }
        let has_room = payload[1] == 1;
        let mut at = 2;

        let access = <[u8; 32]>::try_from(&payload[at..at + 32])
            .map_err(|_| anyhow::anyhow!("invite is truncated"))?;
        at += 32;

        let room = if has_room {
            if payload.len() < at + 32 + 1 {
                bail!("invite is truncated");
            }
            let bytes = <[u8; 32]>::try_from(&payload[at..at + 32])
                .map_err(|_| anyhow::anyhow!("invite is truncated"))?;
            at += 32;
            Some(RoomKey::from_bytes(bytes))
        } else {
            None
        };

        if payload.len() <= at {
            bail!("invite is truncated");
        }
        let url_len = payload[at] as usize;
        at += 1;
        if url_len == 0 {
            bail!("invite carries no relay address");
        }
        if url_len > MAX_URL_BYTES || payload.len() < at + url_len {
            bail!("invite is malformed (bad relay address length)");
        }
        let relay_url = std::str::from_utf8(&payload[at..at + url_len])
            .context("invite's relay address is not valid UTF-8")?
            .to_string();

        Ok(Self {
            relay_url,
            access_key: AccessKey::from_bytes(access),
            room_key: room,
        })
    }
}

impl std::fmt::Debug for Invite {
    /// Redacted: an invite carries both keys, and these end up in error
    /// messages and logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("relay_url", &self.relay_url)
            .field("access_key", &"<redacted>")
            .field("room_key", &self.room_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// True when `s` looks like it was meant to be an invite.
pub fn looks_like_invite(s: &str) -> bool {
    s.trim().to_lowercase().starts_with(PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(room: bool) -> Invite {
        Invite {
            relay_url: "wss://relay.example.com/ws".into(),
            access_key: AccessKey::generate(),
            room_key: room.then(RoomKey::generate),
        }
    }

    #[test]
    fn roundtrips_with_a_room() {
        let invite = sample(true);
        let token = invite.encode();
        let back = Invite::decode(&token).unwrap();
        assert_eq!(back.relay_url, invite.relay_url);
        assert_eq!(back.access_key.as_bytes(), invite.access_key.as_bytes());
        assert_eq!(
            back.room_key.unwrap().as_bytes(),
            invite.room_key.unwrap().as_bytes()
        );
    }

    #[test]
    fn roundtrips_without_a_room() {
        let invite = sample(false);
        let back = Invite::decode(&invite.encode()).unwrap();
        assert!(back.room_key.is_none());
        assert_eq!(back.relay_url, invite.relay_url);
    }

    #[test]
    fn tolerates_case_and_whitespace() {
        let invite = sample(true);
        let token = invite.encode();
        let mangled = format!("  {}\n", token.to_uppercase());
        let back = Invite::decode(&mangled).unwrap();
        assert_eq!(back.access_key.as_bytes(), invite.access_key.as_bytes());
    }

    #[test]
    fn is_recognisable() {
        assert!(looks_like_invite(&sample(true).encode()));
        assert!(looks_like_invite("  RCINV1-ABC"));
        assert!(!looks_like_invite("rc1-AAAA"));
        assert!(!looks_like_invite("rca1-AAAA"));
    }

    #[test]
    fn rejects_junk_and_truncation() {
        assert!(Invite::decode("hello").is_err());
        assert!(Invite::decode("rcinv1-!!!!").is_err());
        assert!(Invite::decode("rcinv1-").is_err());
        let token = sample(true).encode();
        for cut in [10, 20, 40, token.len() - 4] {
            assert!(
                Invite::decode(&token[..cut]).is_err(),
                "a truncated invite must not decode (cut at {cut})"
            );
        }
    }

    #[test]
    fn rejects_a_hostile_url_length() {
        let mut payload = vec![FORMAT_VERSION, 0];
        payload.extend_from_slice(&[9u8; 32]);
        payload.push(255); // claims a 255-byte URL that isn't there
        payload.extend_from_slice(b"short");
        assert!(Invite::from_payload(&payload).is_err());
    }

    #[test]
    fn rejects_a_future_format() {
        let mut payload = vec![99, 0];
        payload.extend_from_slice(&[1u8; 32]);
        payload.push(1);
        payload.push(b'x');
        let err = Invite::from_payload(&payload).unwrap_err().to_string();
        assert!(err.contains("not supported"), "got: {err}");
    }

    #[test]
    fn debug_output_never_leaks_key_material() {
        let invite = sample(true);
        let shown = format!("{invite:?}");
        let secret = BASE32_NOPAD.encode(invite.access_key.as_bytes());
        assert!(
            !shown.contains(&secret),
            "access key leaked into Debug output"
        );
        assert!(shown.contains("<redacted>"));
        assert!(shown.contains("relay.example.com"), "the URL is not secret");
    }

    #[test]
    fn stays_a_reasonable_length_to_paste() {
        let token = sample(true).encode();
        assert!(
            token.len() < 200,
            "an invite should be pasteable, got {} chars",
            token.len()
        );
    }
}
