//! In-memory [`Transport`] pair — a real, working channel for driving the protocol in tests
//! (and a reference for what a transport must do). No network, no framing to get wrong: it's
//! two `mpsc` queues wired crosswise, so it trivially preserves frame boundaries and order.

use std::sync::mpsc::{channel, Receiver, Sender};

use super::Transport;
use crate::{Error, Result};

/// One end of an in-memory duplex channel.
pub struct DuplexChannel {
    outbound: Sender<Vec<u8>>,
    inbound: Receiver<Vec<u8>>,
}

/// Create a connected Alice/Bob pair. Each end's `send` is the other's `recv`.
pub fn channel_pair() -> (DuplexChannel, DuplexChannel) {
    let (a_out, b_in) = channel();
    let (b_out, a_in) = channel();
    (
        DuplexChannel { outbound: a_out, inbound: a_in },
        DuplexChannel { outbound: b_out, inbound: b_in },
    )
}

impl Transport for DuplexChannel {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.outbound
            .send(frame.to_vec())
            .map_err(|_| Error::Transport("peer channel closed"))
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        self.inbound
            .recv()
            .map_err(|_| Error::Transport("peer channel closed"))
    }

    fn try_recv(&mut self) -> Result<Option<Vec<u8>>> {
        use std::sync::mpsc::TryRecvError;
        match self.inbound.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Error::Transport("peer channel closed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A framed request/response round-trip over the trait object — proving object safety and
    /// that whole frames survive intact and in order.
    #[test]
    fn boxed_transport_round_trip() {
        let (alice, bob) = channel_pair();
        let mut alice: Box<dyn Transport> = Box::new(alice);
        let mut bob: Box<dyn Transport> = Box::new(bob);

        alice.send(b"pi_a: H1,H2,T,X").unwrap();
        assert_eq!(bob.recv().unwrap(), b"pi_a: H1,H2,T,X");

        bob.send(b"pi_r: K_b").unwrap();
        alice.send(b"nonce commitment").unwrap();
        assert_eq!(alice.recv().unwrap(), b"pi_r: K_b");
        assert_eq!(bob.recv().unwrap(), b"nonce commitment");
    }

    /// Dropping one end surfaces as a transport error on the other, not a panic.
    #[test]
    fn dropped_peer_errors() {
        let (alice, bob) = channel_pair();
        let mut alice = alice;
        drop(bob);
        assert!(alice.recv().is_err());
    }
}
