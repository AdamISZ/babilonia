//! The transaction graph (JOIN-CONSTRUCTION §5a). Every spend is a taproot **key-path** spend;
//! there are no script leaves in the δ-split model. This is the byte boundary: the `musig2`/
//! `secp` aggregate key (secp256k1 0.31) becomes a `bitcoin` (secp256k1 0.29) P2TR output.
//!
//! Pre-signing chain (setup ordering — the build backbone):
//! ```text
//! fix TX1 inputs+outputs ─► Q_fund outpoint known
//!   └─ ChallengeTx pinned (spends Q_fund → Q')  ─► Q' outpoint known
//!        └─ SettleBobWins / SettleAliceWins pre-signable
//!   └─ RefundTx pre-signable
//! INVARIANT: no funds enter Q_fund until RefundTx is fully pre-signed (recovery guaranteed).
//! ```

use bitcoin::absolute::LockTime;
use bitcoin::key::TweakedPublicKey;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};
use bitcoin::hashes::Hash;

use crate::musig::KeyAgg;
use crate::{Error, Result};

/// A taproot key-path output keyed by `MuSig2(P_a,P_b)` with the BIP341 key-path tweak applied.
/// Bundles the (tweaked) aggregate for signing with the `bitcoin` P2TR script it funds.
pub struct TaprootKey {
    pub keyagg: KeyAgg,
    pub output_key: XOnlyPublicKey,
    pub spk: ScriptBuf,
}

impl TaprootKey {
    /// Aggregate `[P_a, P_b]` with the key-path taproot tweak and derive the P2TR output.
    pub fn new(p_a: secp256k1::PublicKey, p_b: secp256k1::PublicKey) -> Result<Self> {
        let keyagg = KeyAgg::new_taproot([p_a, p_b])?;
        let output_key = XOnlyPublicKey::from_slice(&keyagg.agg_xonly())
            .map_err(|_| Error::Protocol("aggregate key is not a valid x-only point"))?;
        // We performed the BIP341 tweak inside the MuSig context, so this key is already the
        // taproot output key — assert-tweaked is correct here.
        let tweaked = TweakedPublicKey::dangerous_assume_tweaked(output_key);
        let spk = ScriptBuf::new_p2tr_tweaked(tweaked);
        Ok(TaprootKey { keyagg, output_key, spk })
    }

    /// A funding `TxOut` paying `value` into this key-path output.
    pub fn txout(&self, value: Amount) -> TxOut {
        TxOut { value, script_pubkey: self.spk.clone() }
    }
}

/// A single-input spend skeleton (unsigned; witness filled after signing).
fn spend(prevout: OutPoint, sequence: Sequence, outputs: Vec<TxOut>, lock_time: LockTime) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

/// RefundTx: `Q_fund → {alice, bob}`, `nLockTime T2`. The no-reveal fallback (mutual refund).
pub fn build_refund(
    q_fund: OutPoint,
    alice: TxOut,
    bob: TxOut,
    refund_locktime: LockTime,
) -> Transaction {
    // nLockTime is enforced only if at least one input sequence is non-final.
    spend(q_fund, Sequence::ENABLE_LOCKTIME_NO_RBF, vec![alice, bob], refund_locktime)
}

/// ChallengeTx: `Q_fund → Q'`, the reveal carrier. Alice signs the sole input with the adaptor
/// on `T`; broadcasting leaks `t`. Output is the pot `Q'` (value = pot − fee).
pub fn build_challenge(
    q_fund: OutPoint,
    q_fund_value: Amount,
    q_prime: &TaprootKey,
    fee: Amount,
) -> Result<Transaction> {
    let out_value = q_fund_value
        .checked_sub(fee)
        .ok_or(Error::Protocol("fee exceeds pot"))?;
    Ok(spend(
        q_fund,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        vec![q_prime.txout(out_value)],
        LockTime::ZERO,
    ))
}

/// A fixed-output settlement spending `Q'`. `SettleBobWins` (no timelock) and `SettleAliceWins`
/// (relative timelock `N` from `Q'`) share this shape — the outputs encode the δ-split, so the
/// spender cannot grab more than their share.
pub fn build_settlement(
    q_prime: OutPoint,
    winner: TxOut,
    loser: TxOut,
    relative_timelock: Option<u16>,
) -> Transaction {
    let sequence = match relative_timelock {
        // BIP68 relative lock, block-based — enforced on a key-path spend, no opcode.
        Some(n) => Sequence::from_height(n),
        None => Sequence::ENABLE_RBF_NO_LOCKTIME,
    };
    spend(q_prime, sequence, vec![winner, loser], LockTime::ZERO)
}

/// The taproot key-path signature hash (BIP341, `SIGHASH_DEFAULT`) for `input_index`, given all
/// prevouts. This 32-byte digest is the message fed to the MuSig2 signing session.
pub fn key_spend_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(input_index, &Prevouts::All(prevouts), TapSighashType::Default)
        .map_err(|_| Error::Protocol("taproot key-spend sighash failed"))?;
    Ok(sighash.to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use crate::musig::{adapt, extract};
    use musig2::secp::Scalar;
    use rand::RngCore;

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    }

    /// End-to-end taproot integration: ChallengeTx key-path-spends `Q_fund` with a tweaked
    /// 2-party MuSig2 **adaptor** signature over `bitcoin`'s real BIP341 sighash. Verifying the
    /// completed signature against the P2TR output key (over that sighash) is the consensus
    /// check bitcoind performs — so this proves ChallengeTx is a valid spend, offline. It also
    /// exercises the reveal: `extract` recovers `t` from the completed signature.
    #[test]
    fn challenge_tx_valid_keypath_spend() {
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);

        let q_fund = TaprootKey::new(a.pk, b.pk).unwrap();
        let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();

        // A (pretend) confirmed funding output.
        let pot = Amount::from_sat(200_000);
        let q_fund_txout = q_fund.txout(pot);
        let q_fund_outpoint = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x11; 32]),
            vout: 0,
        };

        // Build ChallengeTx and its key-path sighash.
        let tx = build_challenge(q_fund_outpoint, pot, &q_prime, Amount::from_sat(300)).unwrap();
        let sighash = key_spend_sighash(&tx, 0, &[q_fund_txout]).unwrap();

        // The reveal: adaptor secret h_c (Alice's chosen thimble scalar), adaptor point H_c.
        let h_c = Scalar::from(Keypair::new(&secp).sk);
        let h_c_point = h_c.base_point_mul();

        // Two-party adaptor signing over the tweaked Q_fund key.
        let (r1a, pna) = q_fund.keyagg.first_round(0, a.sk, seed()).unwrap();
        let (r1b, pnb) = q_fund.keyagg.first_round(1, b.sk, seed()).unwrap();
        let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, h_c_point, sighash).unwrap();
        let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, h_c_point, sighash).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        let pre = r2a.finalize().unwrap();

        // Alice completes with h_c; the signature must verify for the P2TR output key over the
        // exact sighash — i.e. bitcoind would accept this key-path spend.
        let final_sig = adapt(&pre, &h_c).unwrap();
        musig2::verify_single(q_fund.keyagg.agg_point(), final_sig, sighash)
            .expect("completed adaptor sig is a valid taproot key-path signature");

        // Cross-check the byte boundary: the key the signature verifies under equals the bitcoin
        // P2TR output key embedded in Q_fund's scriptPubKey.
        let mut agg_x = [0u8; 32];
        agg_x.copy_from_slice(&q_fund.keyagg.agg_xonly());
        assert_eq!(agg_x, q_fund.output_key.serialize(), "musig agg == bitcoin output key");

        // The reveal: Bob recovers h_c from the broadcast signature.
        assert_eq!(extract(&pre, &final_sig).unwrap().unwrap(), h_c);
    }

    // --- Settlement signing paths (offline; verify against Q''s output key over its sighash) ---

    use crate::reveal::{claim_secret, compute_k};
    use bitcoin::hashes::Hash;

    fn q_prime_setup(
        a: &Keypair,
        b: &Keypair,
    ) -> (TaprootKey, OutPoint, Amount, [u8; 32], Transaction) {
        // A pretend Q' (ChallengeTx output) and a settlement spending it into a δ-split.
        let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();
        let value = Amount::from_sat(100_000);
        let outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([0x22; 32]), vout: 0 };
        // Outputs (winner/loser) — scripts are immaterial to sig validity here; reuse Q''s spk.
        let winner = TxOut { value: Amount::from_sat(60_000), script_pubkey: q_prime.spk.clone() };
        let loser = TxOut { value: Amount::from_sat(39_000), script_pubkey: q_prime.spk.clone() };
        let tx = build_settlement(outpoint, winner, loser, None);
        let sighash = key_spend_sighash(&tx, 0, &[q_prime.txout(value)]).unwrap();
        (q_prime, outpoint, value, sighash, tx)
    }

    /// SettleBobWins: adaptor-locked on `K = W_b + H_y`; only a winner (who knows
    /// `dlog(K) = w_b + h_y`) completes it.
    #[test]
    fn settle_bob_wins_adaptor_on_k() {
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp); // Bob's funding key (in Q)
        let (q_prime, _, _, sighash, _) = q_prime_setup(&a, &b);

        // Bob's hidden claim key W_b (distinct from the funding key b) and the revealed win
        // scalar h_win (= h_c). K = W_b + H_win, dlog(K) = w_b + h_win.
        let w_b = Scalar::from(Keypair::new(&secp).sk);
        let h_win = Scalar::from(Keypair::new(&secp).sk);
        let k = compute_k(&w_b.base_point_mul(), &h_win.base_point_mul()).unwrap();
        let claim = claim_secret(&w_b, &h_win).unwrap(); // dlog(K)

        // Both parties adaptor-sign SettleBobWins against K.
        let (r1a, pna) = q_prime.keyagg.first_round(0, a.sk, seed()).unwrap();
        let (r1b, pnb) = q_prime.keyagg.first_round(1, b.sk, seed()).unwrap();
        let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, k, sighash).unwrap();
        let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, k, sighash).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        let pre = r2a.finalize().unwrap();

        // Bob completes with dlog(K) → valid key-path signature for Q'.
        let final_sig = adapt(&pre, &claim).unwrap();
        musig2::verify_single(q_prime.keyagg.agg_point(), final_sig, sighash)
            .expect("winner's completed SettleBobWins is valid");

        // A non-winner (wrong secret) cannot produce a valid signature.
        let wrong = Scalar::from(Keypair::new(&secp).sk);
        let bad = adapt(&pre, &wrong).unwrap();
        assert!(musig2::verify_single(q_prime.keyagg.agg_point(), bad, sighash).is_err());
    }

    /// Cooperative close: a plain 2-party MuSig2 key-path spend with the split outputs.
    #[test]
    fn cooperative_close_plain() {
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let (q_prime, _, _, sighash, _) = q_prime_setup(&a, &b);

        let (r1a, pna) = q_prime.keyagg.first_round(0, a.sk, seed()).unwrap();
        let (r1b, pnb) = q_prime.keyagg.first_round(1, b.sk, seed()).unwrap();
        let (mut r2a, psa) = r1a.sign(1, pnb, a.sk, sighash).unwrap();
        let (mut r2b, psb) = r1b.sign(0, pna, b.sk, sighash).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        let final_sig = r2a.finalize_plain().unwrap();

        musig2::verify_single(q_prime.keyagg.agg_point(), final_sig, sighash)
            .expect("cooperative close is a valid key-path signature");
    }

    /// SettleAliceWins: plain, pre-signed by both; the relative timelock lives in `nSequence`
    /// (consensus-enforced, tested on regtest) and does not affect signature validity.
    #[test]
    fn settle_alice_wins_plain_timelocked() {
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();
        let value = Amount::from_sat(100_000);
        let outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([0x33; 32]), vout: 0 };
        let winner = TxOut { value: Amount::from_sat(60_000), script_pubkey: q_prime.spk.clone() };
        let loser = TxOut { value: Amount::from_sat(39_000), script_pubkey: q_prime.spk.clone() };
        let tx = build_settlement(outpoint, winner, loser, Some(3)); // nSequence relative = 3
        assert_eq!(tx.input[0].sequence, Sequence::from_height(3));
        let sighash = key_spend_sighash(&tx, 0, &[q_prime.txout(value)]).unwrap();

        let (r1a, pna) = q_prime.keyagg.first_round(0, a.sk, seed()).unwrap();
        let (r1b, pnb) = q_prime.keyagg.first_round(1, b.sk, seed()).unwrap();
        let (mut r2a, psa) = r1a.sign(1, pnb, a.sk, sighash).unwrap();
        let (mut r2b, psb) = r1b.sign(0, pna, b.sk, sighash).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        let final_sig = r2a.finalize_plain().unwrap();

        musig2::verify_single(q_prime.keyagg.agg_point(), final_sig, sighash)
            .expect("SettleAliceWins is a valid key-path signature");
    }
}
