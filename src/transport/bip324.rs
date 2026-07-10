//! BIP324 covert transport — the intended production [`Transport`], riding **decoy
//! packets** on an established BIP324 v2 session between two `bitcoind` peers.
//!
//! A frame `send` becomes one `senddecoy` RPC → an AEAD-encrypted decoy packet on the wire; the
//! peer's patched Core captures it and surfaces it via `getdecoys`, which `recv` drains. To a
//! passive observer a decoy is indistinguishable from a real message (only size/count/timing
//! leak); the RPC control plane never touches the wire.
//!
//! The framing contract holds directly: each decoy carries exactly one frame, delivered in order
//! over the reliable v2 connection. Rendezvous, the v2 handshake, and peer auth sit **below** this
//! type — a `Bip324Transport` is constructed only once the two nodes are peered over v2 and their
//! node ids are known. Requires the `node` feature (drives Core over RPC).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bitcoincore_rpc::{Client, RpcApi};

use super::Transport;
use crate::{Error, Result};

/// Magic prefix stamped on every babilonia frame *inside* its decoy payload, so a receiver can tell
/// our traffic apart from the generic BIP324 decoy packets any v2 node may emit (that indistinction
/// is what let a random signet peer hijack the accepter's peer slot). It rides inside the
/// AEAD-encrypted decoy content, so it's invisible on the wire — no covertness cost. The trailing
/// byte is a version. NOTE: this only marks a frame as *babilonia*; it does not authenticate *which*
/// counterparty sent it — per-session rendezvous (a shared token) is the follow-on for that.
pub const DECOY_MAGIC: &[u8] = b"babilon\x01";

/// A [`Transport`] that tunnels frames as BIP324 decoy packets to one peer, driven over a local
/// (patched) `bitcoind`'s `senddecoy`/`getdecoys` RPCs.
pub struct Bip324Transport {
    /// RPC handle to the local node whose peer we're talking to.
    client: Client,
    /// The counterparty's node id on this node (from `getpeerinfo`).
    peer_id: i64,
    /// Received frames buffered from `getdecoys` (which drains in batches) but not yet `recv`'d.
    inbox: VecDeque<Vec<u8>>,
    /// How often `recv` polls `getdecoys` while waiting.
    poll_interval: Duration,
    /// How long `recv` waits for a frame before erroring.
    recv_timeout: Duration,
}

impl Bip324Transport {
    /// Construct a transport to `peer_id` over `client`'s node. The BIP324 v2 session must already
    /// be established (both nodes peered, `-v2transport=1`).
    pub fn new(client: Client, peer_id: i64) -> Self {
        Self {
            client,
            peer_id,
            inbox: VecDeque::new(),
            poll_interval: Duration::from_millis(50),
            recv_timeout: Duration::from_secs(30),
        }
    }

    /// Override how long `recv` blocks waiting for a frame (default 30s).
    pub fn with_recv_timeout(mut self, timeout: Duration) -> Self {
        self.recv_timeout = timeout;
        self
    }

    /// Pre-seed the inbox with frames already pulled from `getdecoys` during peer identification.
    /// `getdecoys` drains, so a caller that read decoys to discover *which* peer is running the
    /// protocol (the accepter side) must hand those frames here, or the first message is lost.
    pub fn seeded(mut self, frames: Vec<Vec<u8>>) -> Self {
        self.inbox.extend(frames);
        self
    }

    /// Pull any decoys received from the peer into the inbox — keeping only *our* frames (those
    /// carrying [`DECOY_MAGIC`]) and dropping generic BIP324 decoys the peer may also emit.
    fn drain_decoys(&mut self) -> Result<()> {
        let r: serde_json::Value = self.client.call("getdecoys", &[self.peer_id.into()])?;
        if let Some(arr) = r.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    let bytes = hex::decode(s).map_err(|_| Error::Transport("bad decoy hex"))?;
                    if let Some(frame) = bytes.strip_prefix(DECOY_MAGIC) {
                        self.inbox.push_back(frame.to_vec());
                    }
                }
            }
        }
        Ok(())
    }
}

impl Transport for Bip324Transport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        let payload = [DECOY_MAGIC, frame].concat(); // mark it as ours
        let queued: serde_json::Value = self
            .client
            .call("senddecoy", &[self.peer_id.into(), hex::encode(&payload).into()])?;
        if queued.as_bool() == Some(true) {
            Ok(())
        } else {
            Err(Error::Transport("senddecoy: peer not connected"))
        }
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        let deadline = Instant::now() + self.recv_timeout;
        loop {
            if let Some(frame) = self.inbox.pop_front() {
                return Ok(frame);
            }
            self.drain_decoys()?;
            if self.inbox.is_empty() {
                if Instant::now() > deadline {
                    return Err(Error::Transport("recv timed out waiting for decoy"));
                }
                std::thread::sleep(self.poll_interval);
            }
        }
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        if let Some(frame) = self.inbox.pop_front() {
            return Ok(Some(frame));
        }
        self.drain_decoys()?;
        Ok(self.inbox.pop_front())
    }
}
