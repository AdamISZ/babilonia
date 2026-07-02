//! Typed wire messages for the commit-blind setup (hash-free, Bob-commits-first), plus a compact
//! self-describing codec. These are the frames over a [`crate::transport::Transport`]
//! (PROTOCOL.md §2–§3). Only public data — group points and opaque proof bytes.
//!
//! This module covers the **commit** flights (`Open`, `Accept`). The pre-signing/funding flight
//! (`Arm` + partials + input sigs, PROTOCOL.md §3.3) is a later addition.
//!
//! Encoding: points 33-byte compressed SEC1, integers little-endian, variable bytes `u32`-LE
//! length-prefixed, each message a 1-byte tag; a bounds-checked reader rejects short/trailing.

use musig2::secp::Point;

use crate::{Error, Result};

const TAG_OPEN: u8 = 1;
const TAG_ACCEPT: u8 = 2;

/// Flight 1 — Alice → Bob. Alice's opening: game parameters + her thimbles. `pi_a` carries the
/// Schnorr PoKs that `H_1,H_2` are well-formed (opaque for now; AssumeValid).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    pub alice_stake: u64,
    pub delta: u64,
    pub reveal_window: u16,
    pub refund_locktime: u32,
    /// `P_a` (Alice's public identity/funding key).
    pub p_a: Point,
    /// Thimbles `H_1, H_2 = h_1·G, h_2·G`.
    pub h1: Point,
    pub h2: Point,
    /// Well-formedness proofs for `H_1,H_2` (opaque).
    pub pi_a: Vec<u8>,
}

/// Flight 2 — Bob → Alice. Bob's commitment: his **public funding key** `P_b` (so Alice can form
/// `Q = MuSig2(P_a,P_b)`) and his **claim key** `K = W_b + H_y` (hides `y` and the hidden claim
/// key `W_b`). `pi_r` proves `K` is well-formed for exactly one thimble.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accept {
    pub bob_stake: u64,
    /// `P_b` — Bob's public funding key (enters `Q`; distinct from the hidden claim key `W_b`).
    pub p_b: Point,
    /// `K = W_b + H_y` — Bob's pot-claim key.
    pub k: Point,
    /// `π_r` (opaque): CDS 1-of-2 OR that `K − H_y = w_b·G` for one `y`.
    pub pi_r: Vec<u8>,
}

// --- codec ---

fn put_point(out: &mut Vec<u8>, p: &Point) {
    out.extend_from_slice(&p.serialize());
}

fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Decode("length overflow"))?;
        if end > self.buf.len() {
            return Err(Error::Decode("frame too short"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn tag(&mut self, expected: u8) -> Result<()> {
        if self.take(1)?[0] != expected {
            return Err(Error::Decode("unexpected message tag"));
        }
        Ok(())
    }
    fn point(&mut self) -> Result<Point> {
        Point::from_slice(self.take(33)?).map_err(|_| Error::Decode("invalid point"))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn lp(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Decode("trailing bytes"))
        }
    }
}

impl Open {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_OPEN];
        out.extend_from_slice(&self.alice_stake.to_le_bytes());
        out.extend_from_slice(&self.delta.to_le_bytes());
        out.extend_from_slice(&self.reveal_window.to_le_bytes());
        out.extend_from_slice(&self.refund_locktime.to_le_bytes());
        for p in [&self.p_a, &self.h1, &self.h2] {
            put_point(&mut out, p);
        }
        put_lp(&mut out, &self.pi_a);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_OPEN)?;
        let m = Open {
            alice_stake: r.u64()?,
            delta: r.u64()?,
            reveal_window: r.u16()?,
            refund_locktime: r.u32()?,
            p_a: r.point()?,
            h1: r.point()?,
            h2: r.point()?,
            pi_a: r.lp()?,
        };
        r.finish()?;
        Ok(m)
    }
}

impl Accept {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_ACCEPT];
        out.extend_from_slice(&self.bob_stake.to_le_bytes());
        put_point(&mut out, &self.p_b);
        put_point(&mut out, &self.k);
        put_lp(&mut out, &self.pi_r);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_ACCEPT)?;
        let m = Accept {
            bob_stake: r.u64()?,
            p_b: r.point()?,
            k: r.point()?,
            pi_r: r.lp()?,
        };
        r.finish()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    fn some_point() -> Point {
        let secp = secp256k1::Secp256k1::new();
        Keypair::new(&secp).pk.into()
    }

    #[test]
    fn messages_round_trip() {
        let open = Open {
            alice_stake: 100_000,
            delta: 10_000,
            reveal_window: 6,
            refund_locktime: 200,
            p_a: some_point(),
            h1: some_point(),
            h2: some_point(),
            pi_a: vec![1, 2, 3],
        };
        assert_eq!(Open::decode(&open.encode()).unwrap(), open);

        let accept = Accept { bob_stake: 100_000, p_b: some_point(), k: some_point(), pi_r: vec![] };
        assert_eq!(Accept::decode(&accept.encode()).unwrap(), accept);
    }

    #[test]
    fn decode_rejects_wrong_tag_and_junk() {
        let accept = Accept { bob_stake: 1, p_b: some_point(), k: some_point(), pi_r: vec![] };
        assert!(Open::decode(&accept.encode()).is_err());
        let mut bad = accept.encode();
        bad.push(0xff);
        assert!(Accept::decode(&bad).is_err());
        assert!(Accept::decode(&accept.encode()[..10]).is_err());
    }
}
