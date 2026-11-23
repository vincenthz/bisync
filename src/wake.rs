//! What a running session waits on.
//!
//! A `watch` session has two things to listen to — the peer, and the local
//! filesystem — and blocking on either one means going deaf to the other.
//! Alternating short timeouts would work and would keep the process awake
//! twenty times a second for no reason, so instead both producers push into one
//! channel and the driver blocks on that. The reader thread in
//! [`crate::transport`] and the debouncer thread in [`crate::watch`] are the two
//! producers; this enum is what they have in common.

use crate::proto::Msg;

pub enum Wake {
    /// A message from the peer.
    Msg(Msg),
    /// The peer closed the link cleanly.
    Closed,
    /// The link is unusable; no more messages will arrive.
    Failed(String),
    /// These paths changed locally. A single empty string means the whole tree
    /// needs re-examining — a dropped event, or the periodic full rescan.
    Local(Vec<String>),
}
