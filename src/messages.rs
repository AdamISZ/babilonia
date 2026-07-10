//! Typed wire messages for the **v5** setup flow (`adaptor_construction_spec_v5.tex`, P1–P6), plus
//! a compact self-describing codec. These are the frames over a [`crate::transport::Transport`].
//! Only public data — group points/scalars, MuSig2 nonces/partials, and opaque proof bytes.
//!
//! Four flights (game parameters are agreed out-of-band as [`crate::setup::GameParams`]). Nonces
//! follow key exchange, since a MuSig2 session needs both keys to form the aggregate:
//! ```text
//! 1. AliceOpen   A→B : P_a, thimbles A_1,A_2 (+ PoKs)                                        (P2)
//! 2. BobCommit   B→A : P_b, K=W_b+A_y (+ π_r), refund & settlement nonces                    (P3)
//! 3. AliceReveal A→B : refund & settlement nonces, ctxt=a_c+H(d), D=d·G, π_a (Σ-part),
//!                      refund & settlement partials                                          (P4)
//! 4. BobAuth     B→A : refund & settlement partials (authorises the D-adaptor pre-sig)       (P5)
//! ```
//!
//! Encoding: points 33B SEC1, scalars/partials 32B, MuSig2 pub-nonces 66B, variable bytes `u32`-LE
//! length-prefixed, each message a 1-byte tag; a bounds-checked reader rejects short/trailing.

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Txid};
use musig2::secp::{MaybeScalar, Point, Scalar};
use musig2::{BinaryEncoding, PartialSignature, PubNonce};

use crate::{Error, Result};

const TAG_ALICE_OPEN: u8 = 1;
const TAG_BOB_COMMIT: u8 = 2;
const TAG_ALICE_REVEAL: u8 = 3;
const TAG_BOB_AUTH: u8 = 4;
const TAG_FUND_OPEN: u8 = 5;
const TAG_FUND_REPLY: u8 = 6;
const TAG_FUND_FINAL: u8 = 7;

// --- joint PSBT funding sub-protocol (before the setup driver; v5 §P1) ---

/// Funding flight 1 — Dealer → Player. The dealer (Alice, the *parker*) contributes her **whole**
/// input (`amount = F_A`, no funding change) and gives her **payout** address `alice_payout` — where
/// her parked surplus `c_A` / refund `F_A` return (the settlement's & refund's Alice-side output). See
/// COVERT-TX-PLAN §8.
#[derive(Clone, Debug)]
pub struct FundOpen {
    pub p_a: Point,
    pub input: OutPoint,
    pub amount: u64,
    pub alice_payout: String,
}

/// Funding flight 2 — Player → Dealer. The player (Bob) contributes his input, takes his funding
/// **change** `c_B` (`change`), gives his **payout** address `bob_payout` (the refund's `b→Bob`
/// output), and the wallet-signed PSBT (his own input signed).
#[derive(Clone, Debug)]
pub struct FundReply {
    pub p_b: Point,
    pub input: OutPoint,
    pub amount: u64,
    pub change: String,
    pub bob_payout: String,
    pub psbt: String,
}

/// Funding flight 3 — Dealer → Player. The dealer's wallet-signed PSBT, so the player can combine +
/// finalize the same `TX1`.
#[derive(Clone, Debug)]
pub struct FundFinal {
    pub psbt: String,
}

/// Flight 1 (P2) — Alice → Bob. Her funding key `P_a` and thimbles `A_1,A_2 = a_1·G, a_2·G` with
/// PoKs.
#[derive(Clone, Debug)]
pub struct AliceOpen {
    pub p_a: Point,
    pub a1: Point,
    pub a2: Point,
    pub thimble_poks: Vec<u8>,
}

/// Flight 2 (P3) — Bob → Alice. His funding key `P_b` (so Alice can form `Q`), claim key
/// `K = W_b + A_y` (`W_b` = Bob's fresh *hidden* claim key, `≠ P_b`) with `π_r`, and his public
/// nonces for the refund and settlement MuSig2 sessions.
#[derive(Clone, Debug)]
pub struct BobCommit {
    pub p_b: Point,
    pub k: Point,
    pub pi_r: Vec<u8>,
    pub refund_nonce: PubNonce,
    pub settle_nonce: PubNonce,
}

/// Flight 3 (P4) — Alice → Bob. Her session nonces, the encrypted outcome `ctxt = a_c + H(d)`, the
/// settlement adaptor point `D = d·G`, `π_a` (Σ-part; the hash conjunct is stubbed), and her
/// partials for the settlement (adaptor on `D`) and the refund.
#[derive(Clone, Debug)]
pub struct AliceReveal {
    pub refund_nonce: PubNonce,
    pub settle_nonce: PubNonce,
    pub ctxt: Scalar,
    pub d_point: Point,
    pub pi_a: Vec<u8>,
    pub refund_partial: PartialSignature,
    pub settle_partial: PartialSignature,
}

/// Flight 4 (P5) — Bob → Alice. His refund and settlement partials, completing both sessions.
#[derive(Clone, Debug)]
pub struct BobAuth {
    pub refund_partial: PartialSignature,
    pub settle_partial: PartialSignature,
}

// --- codec ---

fn put_point(out: &mut Vec<u8>, p: &Point) {
    out.extend_from_slice(&p.serialize());
}
fn put_scalar(out: &mut Vec<u8>, s: &Scalar) {
    out.extend_from_slice(&s.serialize());
}
fn put_partial(out: &mut Vec<u8>, s: &PartialSignature) {
    out.extend_from_slice(&s.serialize());
}
fn put_nonce(out: &mut Vec<u8>, n: &PubNonce) {
    out.extend_from_slice(&n.to_bytes());
}
fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
fn put_outpoint(out: &mut Vec<u8>, o: &OutPoint) {
    out.extend_from_slice(&o.txid.to_byte_array());
    out.extend_from_slice(&o.vout.to_le_bytes());
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
    fn scalar(&mut self) -> Result<Scalar> {
        Scalar::from_slice(self.take(32)?).map_err(|_| Error::Decode("invalid scalar"))
    }
    fn partial(&mut self) -> Result<PartialSignature> {
        MaybeScalar::from_slice(self.take(32)?).map_err(|_| Error::Decode("invalid partial"))
    }
    fn nonce(&mut self) -> Result<PubNonce> {
        PubNonce::from_bytes(self.take(66)?).map_err(|_| Error::Decode("invalid pubnonce"))
    }
    fn lp(&mut self) -> Result<Vec<u8>> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.lp()?).map_err(|_| Error::Decode("invalid utf-8"))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn outpoint(&mut self) -> Result<OutPoint> {
        let txid = Txid::from_byte_array(self.take(32)?.try_into().unwrap());
        let vout = u32::from_le_bytes(self.take(4)?.try_into().unwrap());
        Ok(OutPoint { txid, vout })
    }
    fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Decode("trailing bytes"))
        }
    }
}

impl AliceOpen {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_ALICE_OPEN];
        for p in [&self.p_a, &self.a1, &self.a2] {
            put_point(&mut out, p);
        }
        put_lp(&mut out, &self.thimble_poks);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_ALICE_OPEN)?;
        let m = AliceOpen {
            p_a: r.point()?,
            a1: r.point()?,
            a2: r.point()?,
            thimble_poks: r.lp()?,
        };
        r.finish()?;
        Ok(m)
    }
}

impl BobCommit {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_BOB_COMMIT];
        put_point(&mut out, &self.p_b);
        put_point(&mut out, &self.k);
        put_lp(&mut out, &self.pi_r);
        put_nonce(&mut out, &self.refund_nonce);
        put_nonce(&mut out, &self.settle_nonce);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_BOB_COMMIT)?;
        let m = BobCommit {
            p_b: r.point()?,
            k: r.point()?,
            pi_r: r.lp()?,
            refund_nonce: r.nonce()?,
            settle_nonce: r.nonce()?,
        };
        r.finish()?;
        Ok(m)
    }
}

impl AliceReveal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_ALICE_REVEAL];
        put_nonce(&mut out, &self.refund_nonce);
        put_nonce(&mut out, &self.settle_nonce);
        put_scalar(&mut out, &self.ctxt);
        put_point(&mut out, &self.d_point);
        put_lp(&mut out, &self.pi_a);
        put_partial(&mut out, &self.refund_partial);
        put_partial(&mut out, &self.settle_partial);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_ALICE_REVEAL)?;
        let m = AliceReveal {
            refund_nonce: r.nonce()?,
            settle_nonce: r.nonce()?,
            ctxt: r.scalar()?,
            d_point: r.point()?,
            pi_a: r.lp()?,
            refund_partial: r.partial()?,
            settle_partial: r.partial()?,
        };
        r.finish()?;
        Ok(m)
    }
}

impl BobAuth {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_BOB_AUTH];
        put_partial(&mut out, &self.refund_partial);
        put_partial(&mut out, &self.settle_partial);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_BOB_AUTH)?;
        let m = BobAuth { refund_partial: r.partial()?, settle_partial: r.partial()? };
        r.finish()?;
        Ok(m)
    }
}

impl FundOpen {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_FUND_OPEN];
        put_point(&mut out, &self.p_a);
        put_outpoint(&mut out, &self.input);
        out.extend_from_slice(&self.amount.to_le_bytes());
        put_lp(&mut out, self.alice_payout.as_bytes());
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_FUND_OPEN)?;
        let m = FundOpen { p_a: r.point()?, input: r.outpoint()?, amount: r.u64()?, alice_payout: r.string()? };
        r.finish()?;
        Ok(m)
    }
}

impl FundReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_FUND_REPLY];
        put_point(&mut out, &self.p_b);
        put_outpoint(&mut out, &self.input);
        out.extend_from_slice(&self.amount.to_le_bytes());
        put_lp(&mut out, self.change.as_bytes());
        put_lp(&mut out, self.bob_payout.as_bytes());
        put_lp(&mut out, self.psbt.as_bytes());
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_FUND_REPLY)?;
        let m = FundReply {
            p_b: r.point()?,
            input: r.outpoint()?,
            amount: r.u64()?,
            change: r.string()?,
            bob_payout: r.string()?,
            psbt: r.string()?,
        };
        r.finish()?;
        Ok(m)
    }
}

impl FundFinal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TAG_FUND_FINAL];
        put_lp(&mut out, self.psbt.as_bytes());
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        r.tag(TAG_FUND_FINAL)?;
        let m = FundFinal { psbt: r.string()? };
        r.finish()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use crate::musig::KeyAgg;

    fn some_point() -> Point {
        let secp = secp256k1::Secp256k1::new();
        Keypair::new(&secp).pk.into()
    }
    fn some_nonce() -> PubNonce {
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let keyagg = KeyAgg::new([a.pk, b.pk]).unwrap();
        let (_r, n) = keyagg.first_round(0, a.sk, [7u8; 32]).unwrap();
        n
    }
    fn some_scalar() -> Scalar {
        let secp = secp256k1::Secp256k1::new();
        Scalar::from(Keypair::new(&secp).sk)
    }

    #[test]
    fn flights_round_trip() {
        let open = AliceOpen { p_a: some_point(), a1: some_point(), a2: some_point(), thimble_poks: vec![1, 2, 3] };
        assert_eq!(AliceOpen::decode(&open.encode()).unwrap().thimble_poks, open.thimble_poks);
        assert_eq!(AliceOpen::decode(&open.encode()).unwrap().a1, open.a1);

        let commit = BobCommit {
            p_b: some_point(),
            k: some_point(),
            pi_r: vec![9],
            refund_nonce: some_nonce(),
            settle_nonce: some_nonce(),
        };
        assert_eq!(BobCommit::decode(&commit.encode()).unwrap().k, commit.k);

        let reveal = AliceReveal {
            refund_nonce: some_nonce(),
            settle_nonce: some_nonce(),
            ctxt: some_scalar(),
            d_point: some_point(),
            pi_a: vec![4, 5],
            refund_partial: MaybeScalar::from(some_scalar()),
            settle_partial: MaybeScalar::from(some_scalar()),
        };
        let dec = AliceReveal::decode(&reveal.encode()).unwrap();
        assert_eq!(dec.ctxt, reveal.ctxt);
        assert_eq!(dec.settle_partial, reveal.settle_partial);

        let auth = BobAuth {
            refund_partial: MaybeScalar::from(some_scalar()),
            settle_partial: MaybeScalar::from(some_scalar()),
        };
        assert_eq!(BobAuth::decode(&auth.encode()).unwrap().settle_partial, auth.settle_partial);
    }

    #[test]
    fn decode_rejects_wrong_tag_and_junk() {
        let auth = BobAuth {
            refund_partial: MaybeScalar::from(some_scalar()),
            settle_partial: MaybeScalar::from(some_scalar()),
        };
        assert!(AliceOpen::decode(&auth.encode()).is_err());
        let mut bad = auth.encode();
        bad.push(0xff);
        assert!(BobAuth::decode(&bad).is_err());
    }
}
