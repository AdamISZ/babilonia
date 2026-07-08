//! Abstract peer-to-peer channel — the seam for how Alice and Bob talk during the interactive
//! OP_RAND setup.
//!
//! The whole commit-blind-reveal exchange — TX templates, `H_k`/`T`/`X` + `π_a`, `K_b` + `π_r`,
//! MuSig2 nonce-commitment rounds and partial signatures — is a turn-based conversation over an
//! **ordered, reliable, framed, already-authenticated** bidirectional message channel between
//! the two peers. Nothing above this trait cares *how* those frames travel.
//!
//! The intended production transport is the **BIP324 covert channel** (decoy packets carrying
//! the round-trips; see `docs/BIP324-PATCH-NOTES.md` and [`bip324`]). But that is one choice.
//! This trait is deliberately minimal so anyone can drop in a different medium — plain TCP, an
//! overlay/onion route, a relay like Nostr, files exchanged out-of-band, or the in-memory
//! [`memory::channel_pair`] used by tests — without touching the protocol logic.
//!
//! ## Contract for implementors
//! - **Framing preserved.** Each [`Transport::recv`] returns exactly one frame that some
//!   [`Transport::send`] passed — no splitting or coalescing. (Stream transports like TCP must
//!   add their own length-delimiting; `bitcoind`'s decoy packets are already message-framed.)
//! - **Ordered & reliable.** Frames arrive in send order, exactly once, or `recv` errors.
//! - **Two parties.** A channel connects exactly Alice↔Bob; peer identity/auth and rendezvous
//!   live *below* this trait (e.g. the BIP324 handshake, garbage membership signaling) and are
//!   assumed established before a `Transport` exists.
//! - **Payload-opaque.** Frames are bytes; the protocol layer owns (de)serialization, so no
//!   serialization format is imposed on alternative transports.
//!
//! The interface is synchronous and blocking, which fits a turn-based protocol; an async
//! variant can be added later if a transport needs it.

#[cfg(feature = "node")]
pub mod bip324;
pub mod memory;

use crate::Result;

/// An ordered, reliable, framed, authenticated bidirectional channel to the peer.
///
/// Object-safe: hold one as `Box<dyn Transport>` to stay agnostic to the medium.
pub trait Transport: Send {
    /// Send one framed message to the peer.
    fn send(&mut self, frame: &[u8]) -> Result<()>;

    /// Block until the next framed message arrives from the peer, returning it whole.
    fn recv(&mut self) -> Result<Vec<u8>>;

    /// Non-blocking receive: the next frame if one is already available, else `None`. Lets a caller
    /// poll a transport while also watching other inputs (the node core's peer workers use this to
    /// select between incoming frames and local instructions).
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>>;

    /// Flush any buffered outbound data. Default: no-op (unbuffered transports).
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A `&mut` to any transport is itself a transport (delegation). This lets a bet **session** borrow
/// a peer worker's owned transport for the duration of a protocol run without moving it out.
impl<T: Transport + ?Sized> Transport for &mut T {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        (**self).send(frame)
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        (**self).recv()
    }
    fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        (**self).try_recv()
    }
    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
}
