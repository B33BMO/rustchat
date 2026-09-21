//! Shared crypto and wire protocol for rustchat.
//!
//! There are three secrets in this system, with deliberately separate jobs:
//!
//! * A **relay access key** ([`AccessKey`]) — one per relay. It decides who
//!   may open a socket, and nothing else. The relay is configured with its
//!   one-way derivation, so it can turn away strangers without holding the key.
//! * A **room key** ([`RoomKey`]) — one per room, shared with everyone you
//!   want in it. It yields the AEAD key that makes messages readable, and a
//!   one-way **room id** that the relay uses purely to group sockets together.
//! * A **local passphrase** — personal, never transmitted. It only seals the
//!   on-disk [`vault`], so a long key need not be pasted on every launch.
//!
//! One relay therefore carries any number of rooms while being configured for
//! none of them: it sees room ids and ciphertext, and holds no room key. See
//! [`proto`] for the wire format and [`Invite`] for handing all of this to
//! somebody in one paste.

pub mod crypto;
pub mod invite;
pub mod key;
pub mod proto;
pub mod vault;

pub use crypto::{open, seal};
pub use invite::Invite;
pub use key::{AccessKey, RoomKey, RoomKeys, parse_hex32, verify_proof};
pub use proto::{ClientMsg, Payload, RelayMsg, SealedEnvelope};

/// Wire-format version. Bumped on any breaking change to [`proto`] or the
/// derivation in [`key`]; the relay refuses anything it doesn't recognise.
pub const PROTOCOL_VERSION: u16 = 2;

/// Largest sealed envelope the relay will accept or forward, in bytes.
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024;

/// Largest message body a client will send, in bytes (UTF-8).
pub const MAX_BODY_BYTES: usize = 4 * 1024;
