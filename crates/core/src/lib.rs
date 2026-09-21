//! Shared crypto and wire protocol for rustchat.
//!
//! There are exactly two secrets in this system:
//!
//! * The **room key** — 32 bytes, shared by everyone in the room. It is the
//!   only thing you hand out to let someone in. Everything readable is
//!   encrypted under a subkey of it.
//! * A **local passphrase** — personal, never transmitted. It only ever seals
//!   the on-disk [`vault`], which is where a client stashes the room key so you
//!   don't have to paste it on every launch.
//!
//! The relay is deliberately given *neither*. It only learns the room key's
//! [`Keys::auth`] subkey, which is enough to turn away clients that can't prove
//! they know the room key, and useless for reading any message. See [`proto`].

pub mod crypto;
pub mod key;
pub mod proto;
pub mod vault;

pub use crypto::{open, seal};
pub use key::{Keys, RoomKey, parse_auth_hex, verify_proof};
pub use proto::{ClientMsg, Payload, RelayMsg, SealedEnvelope};

/// Wire-format version. Bumped on any breaking change to [`proto`] or the
/// derivation in [`key`]; the relay refuses anything it doesn't recognise.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest sealed envelope the relay will accept or forward, in bytes.
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024;

/// Largest message body a client will send, in bytes (UTF-8).
pub const MAX_BODY_BYTES: usize = 4 * 1024;
