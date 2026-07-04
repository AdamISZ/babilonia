//! MuSig2 (BIP327) with Schnorr adaptors — the one primitive every on-chain step uses.
//!
//! Thin wrapper over the `musig2` crate. The rest of Babilonia speaks in domain terms
//! (aggregate key, adaptor pre-signature, adapt, extract) rather than raw round state. Two
//! parties only (`P_a` = index 0, `P_b` = index 1).
//!
//! **Nonce hygiene is load-bearing** (DESIGN §10 open #2): every tx is a *distinct* session
//! (RefundTx, SettleTx) and MUST use an independent `nonce_seed`, or the shared key leaks. The
//! two-round exchange is BIP327's commitment discipline.
//!
//! Adaptor flow (v5 §P5/P6): both parties `sign_adaptor` against the settlement adaptor point
//! `D = d·G`; the aggregate is an [`AdaptorSignature`] that is *not yet* a valid BIP340 sig. Alice
//! (who knows `d`) calls [`adapt`] to finish it — and publishing the finished sig lets Bob
//! [`extract`] `d` back out. That `d` decrypts the outcome (`a_c = ctxt − H(d)`); that is the reveal.

use musig2::secp::{MaybeScalar, Point, Scalar};
use musig2::{
    AdaptorSignature, FirstRound, KeyAggContext, LiftedSignature, PartialSignature, PubNonce,
    SecNonceSpices, SecondRound,
};
use secp256k1::{PublicKey, SecretKey};

use crate::{Error, Result};

fn musig_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Musig(e.to_string())
}

/// The aggregate key `P_agg` over `[P_a, P_b]` (BIP327 KeyAgg). Order is fixed by the caller
/// and shared by both parties; index 0 = Alice, 1 = Bob.
#[derive(Clone, Debug)]
pub struct KeyAgg {
    ctx: KeyAggContext,
}

impl KeyAgg {
    /// Aggregate the two identity keys (untweaked). `pubkeys` order must match on both sides.
    pub fn new(pubkeys: [PublicKey; 2]) -> Result<Self> {
        let ctx = KeyAggContext::new(pubkeys).map_err(musig_err)?;
        Ok(KeyAgg { ctx })
    }

    /// Aggregate + apply the BIP341 **key-path-only** taproot tweak (empty merkle root), so the
    /// aggregate *is* a P2TR output key and signing produces valid key-path spends. This is the
    /// form `Q_fund`/`Q'` use (no script leaves). Matches `bitcoin`'s `tap_tweak(secp, None)`.
    pub fn new_taproot(pubkeys: [PublicKey; 2]) -> Result<Self> {
        let ctx = KeyAggContext::new(pubkeys)
            .map_err(musig_err)?
            .with_unspendable_taproot_tweak()
            .map_err(musig_err)?;
        Ok(KeyAgg { ctx })
    }

    /// The aggregate key as a `secp` point (for BIP340 verification of a completed signature).
    pub fn agg_point(&self) -> Point {
        self.ctx.aggregated_pubkey()
    }

    /// The aggregate public key as a 32-byte x-only encoding (feeds the taproot output key).
    pub fn agg_xonly(&self) -> [u8; 32] {
        let pk: Point = self.ctx.aggregated_pubkey();
        // x-only serialization is the last 32 bytes of the 33-byte compressed form.
        let comp = pk.serialize();
        let mut x = [0u8; 32];
        x.copy_from_slice(&comp[1..33]);
        x
    }

    /// Begin a signing session for `signer_index` (0=Alice, 1=Bob). `nonce_seed` MUST be fresh
    /// per session. Returns our public nonce to hand to the peer.
    pub fn first_round(
        &self,
        signer_index: usize,
        seckey: SecretKey,
        nonce_seed: [u8; 32],
    ) -> Result<(Round1, PubNonce)> {
        let round = FirstRound::new(
            self.ctx.clone(),
            nonce_seed,
            signer_index,
            SecNonceSpices::new().with_seckey(Scalar::from(seckey)),
        )
        .map_err(musig_err)?;
        let our_nonce = round.our_public_nonce();
        Ok((Round1 { round }, our_nonce))
    }
}

/// First round: nonce is out; waiting to learn the peer's nonce so we can produce our adaptor
/// partial signature.
pub struct Round1 {
    round: FirstRound,
}

impl Round1 {
    /// Receive the peer's nonce and emit our **adaptor** partial signature over `msg`, offset by
    /// `adaptor_point` (`T` on ChallengeTx, `K_b` on SettleBobWins).
    pub fn sign_adaptor(
        self,
        peer_index: usize,
        peer_nonce: PubNonce,
        seckey: SecretKey,
        adaptor_point: Point,
        msg: [u8; 32],
    ) -> Result<(Round2, PartialSignature)> {
        let mut round = self.round;
        round.receive_nonce(peer_index, peer_nonce).map_err(musig_err)?;
        let second = round
            .finalize_adaptor(Scalar::from(seckey), adaptor_point, msg)
            .map_err(musig_err)?;
        let ours: PartialSignature = second.our_signature();
        Ok((Round2 { round: second }, ours))
    }

    /// Plain (non-adaptor) partial signature over `msg` — the cooperative close and
    /// `SettleAliceWins` (no secret-gating; a relative timelock gates the latter at the tx layer).
    pub fn sign(
        self,
        peer_index: usize,
        peer_nonce: PubNonce,
        seckey: SecretKey,
        msg: [u8; 32],
    ) -> Result<(Round2, PartialSignature)> {
        let mut round = self.round;
        round.receive_nonce(peer_index, peer_nonce).map_err(musig_err)?;
        let second = round.finalize(Scalar::from(seckey), msg).map_err(musig_err)?;
        let ours: PartialSignature = second.our_signature();
        Ok((Round2 { round: second }, ours))
    }
}

/// Second round: our partial is out; waiting for the peer's to aggregate into the adaptor sig.
pub struct Round2 {
    round: SecondRound<[u8; 32]>,
}

impl Round2 {
    /// Register the peer's partial signature (verified internally against the adaptor point).
    pub fn receive(&mut self, peer_index: usize, peer_partial: PartialSignature) -> Result<()> {
        self.round
            .receive_signature(peer_index, peer_partial)
            .map_err(musig_err)
    }

    /// Aggregate into the [`AdaptorSignature`] — a pre-signature completable only with
    /// `dlog(adaptor_point)`. Use after [`Round1::sign_adaptor`].
    pub fn finalize(self) -> Result<AdaptorSignature> {
        self.round.finalize_adaptor::<AdaptorSignature>().map_err(musig_err)
    }

    /// Aggregate into a finished BIP340 signature. Use after [`Round1::sign`] (plain sessions).
    pub fn finalize_plain(self) -> Result<LiftedSignature> {
        self.round.finalize::<LiftedSignature>().map_err(musig_err)
    }
}

/// Complete an adaptor pre-signature into a valid BIP340 signature using the adaptor secret
/// (`t` on ChallengeTx; `dlog(K_b)` on SettleBobWins). Returns `None` if the secret is zero.
pub fn adapt(pre: &AdaptorSignature, secret: &Scalar) -> Option<LiftedSignature> {
    pre.adapt::<LiftedSignature>(*secret)
}

/// Recover the adaptor secret from a completed signature (Bob extracts `t` from the broadcast
/// ChallengeTx; §4). Inverse of [`adapt`]. `None` if `final_sig` is unrelated to `pre`.
pub fn extract(pre: &AdaptorSignature, final_sig: &LiftedSignature) -> Option<MaybeScalar> {
    pre.reveal_secret::<MaybeScalar>(final_sig)
}

/// The 64-byte BIP340 encoding (`xonly(R) || s`) of a completed signature — the witness element
/// for a taproot key-path spend under `SIGHASH_DEFAULT`.
pub fn signature_bytes(final_sig: &LiftedSignature) -> [u8; 64] {
    final_sig.compact().serialize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    }

    /// Two-party MuSig2 adaptor round-trip: aggregate → both sign against `T=t·G` → aggregate
    /// to an adaptor pre-sig → `adapt(t)` yields a valid BIP340 sig for `P_agg` → `extract`
    /// recovers `t`. This is the reveal, end to end.
    #[test]
    fn adaptor_roundtrip_two_party() {
        use crate::keys::Keypair;
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let (sk_a, pk_a) = (a.sk, a.pk);
        let (sk_b, pk_b) = (b.sk, b.pk);

        let keyagg = KeyAgg::new([pk_a, pk_b]).unwrap();
        let msg = [0x42u8; 32];

        // Adaptor secret t and its point T = t·G.
        let t = Scalar::from(Keypair::new(&secp).sk);
        let big_t: Point = t.base_point_mul();

        // Round 1: each party emits a nonce.
        let (r1_a, pn_a) = keyagg.first_round(0, sk_a, seed()).unwrap();
        let (r1_b, pn_b) = keyagg.first_round(1, sk_b, seed()).unwrap();

        // Round 1 → 2: exchange nonces, each emits an adaptor partial.
        let (mut r2_a, ps_a) = r1_a.sign_adaptor(1, pn_b, sk_a, big_t, msg).unwrap();
        let (mut r2_b, ps_b) = r1_b.sign_adaptor(0, pn_a, sk_b, big_t, msg).unwrap();

        // Exchange partials; both can aggregate to the same adaptor pre-signature.
        r2_a.receive(1, ps_b).unwrap();
        r2_b.receive(0, ps_a).unwrap();
        let adaptor_sig = r2_a.finalize().unwrap();
        assert_eq!(adaptor_sig, r2_b.finalize().unwrap(), "both derive same pre-sig");

        // The pre-signature is NOT yet a valid BIP340 sig; completing it needs t.
        let final_sig = adapt(&adaptor_sig, &t).expect("adapt with t");

        // The completed signature verifies for the aggregate key.
        let agg: Point = keyagg.ctx.aggregated_pubkey();
        musig2::verify_single(agg, final_sig, msg).expect("valid BIP340 sig for P_agg");

        // And the counterparty recovers t from the broadcast signature — the reveal.
        let recovered = extract(&adaptor_sig, &final_sig).expect("extract secret");
        assert_eq!(recovered, MaybeScalar::from(t), "recovered adaptor secret == t");
    }
}
