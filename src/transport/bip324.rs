//! BIP324 covert transport — the intended production [`Transport`] (DESIGN §9). **Not yet
//! implemented**; this marks the seam so it can be filled without disturbing anything above.
//!
//! Plan (see `docs/BIP324-PATCH-NOTES.md`):
//! - The sustained interactive channel rides **decoy packets** on an established BIP324 v2
//!   session between two `bitcoind` peers — AEAD-encrypted, so a passive observer can't tell a
//!   decoy from a real message (only size/count/timing show). Each decoy is already
//!   message-framed, satisfying the [`Transport`] framing contract directly.
//! - Rendezvous / membership signaling (garbage surface) and the v2 handshake sit **below**
//!   this type; a `Bip324Transport` is constructed only after the peer session is authenticated.
//! - The orchestrator drives Core over a **local control API** (RPC + an async inbound path;
//!   patch-notes §5/§6) to emit decoys (send) and route received ones (recv). That control
//!   plane never touches the wire, so it has no bearing on detectability.
//!
//! When built, `connect` will take the peer/session handle and control endpoint; `send`/`recv`
//! will marshal frames to/from decoy packets.

use super::Transport;
use crate::{Error, Result};

/// Placeholder for the BIP324 covert transport. Fields (Core control handle, session id, framing
/// state) are TBD; see module docs.
pub struct Bip324Transport {
    _private: (),
}

impl Bip324Transport {
    /// Establish the covert channel over an existing BIP324 session. Unimplemented — returns a
    /// [`Error::Todo`] so callers degrade gracefully rather than panic.
    pub fn connect() -> Result<Self> {
        Err(Error::Todo(
            "BIP324 transport: wire to Core decoy send/recv via the local control API \
             (see docs/BIP324-PATCH-NOTES.md)",
        ))
    }
}

impl Transport for Bip324Transport {
    fn send(&mut self, _frame: &[u8]) -> Result<()> {
        Err(Error::Todo("BIP324 transport: marshal frame into a decoy packet"))
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        Err(Error::Todo("BIP324 transport: route decoy packet into a frame"))
    }
}
