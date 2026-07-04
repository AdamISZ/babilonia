//! The transaction graph (adaptor spec **v5**). One jointly-funded output; the settlement is a
//! MuSig2 adaptor signature whose own witness `d` is the released decryption key.
//!
//! ```text
//! TX1 ─► U1 (pot, MuSig2(P_a,P_b) key-path) ─┬─ RefundTx  (spends U1; nLockTime t_r)   [fallback]
//!                                            └─ SettleTx  (spends U1; adaptor on D=d·G,
//!                                                          completing it POSTS d)  ─► ClaimOutput
//!   ClaimOutput = P2TR(NUMS internal) with two leaves:
//!     bob_wins     : <K> OP_CHECKSIG                     (winner knows dlog K = w_b + a_c)
//!     alice_timeout: <t_1> OP_CSV OP_DROP <P_a> OP_CHECKSIG   (Alice reclaims after t_1)
//! ```
//!
//! **Interlock** (v5 §P6): Alice cannot spend `U1` (get the pot) without completing the settlement
//! adaptor, which posts `d`; Bob then decrypts `a_c = ctxt − H(d)` and, if he won, claims `K`.
//! `d` is a fresh dealer-owned scalar (outcome-independent). `t_r > t_1`. Byte boundary:
//! `musig2`/`secp` (secp256k1 0.31) aggregate → `bitcoin` (0.29) P2TR.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};

use musig2::secp::Point;

use crate::musig::KeyAgg;
use crate::{Error, Result};

/// A taproot key-path output keyed by `MuSig2(P_a,P_b)` with the BIP341 key-path tweak applied —
/// the pot `U1`.
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
        let tweaked = TweakedPublicKey::dangerous_assume_tweaked(output_key);
        let spk = ScriptBuf::new_p2tr_tweaked(tweaked);
        Ok(TaprootKey { keyagg, output_key, spk })
    }

    /// A funding `TxOut` paying `value` into this key-path output.
    pub fn txout(&self, value: Amount) -> TxOut {
        TxOut { value, script_pubkey: self.spk.clone() }
    }
}

/// BIP341's "nothing-up-my-sleeve" x-only point — the unspendable internal key for the claim
/// output, so the pot can only move through the two named leaves.
const NUMS_INTERNAL: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn nums_internal() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&NUMS_INTERNAL).expect("valid BIP341 NUMS point")
}

/// An unsigned N-input spend (witnesses filled after signing).
fn spend_inputs(inputs: &[(OutPoint, Sequence)], outputs: Vec<TxOut>, lock_time: LockTime) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time,
        input: inputs
            .iter()
            .map(|&(previous_output, sequence)| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    }
}

/// RefundTx: spends `U1` back to the original stakes, `nLockTime t_r`. The no-reveal fallback; a
/// plain 2-party MuSig2 key-path spend.
pub fn build_refund(u1: OutPoint, alice: TxOut, bob: TxOut, refund_locktime: LockTime) -> Transaction {
    spend_inputs(&[(u1, Sequence::ENABLE_LOCKTIME_NO_RBF)], vec![alice, bob], refund_locktime)
}

/// SettleTx: spends `U1` via a MuSig2 **adaptor signature locked to `D = d·G`** — completing it
/// (and hence getting paid) posts `d` on-chain, the decryption key. `outputs` carry the settlement
/// (typically the claim output).
pub fn build_settlement(u1: OutPoint, outputs: Vec<TxOut>) -> Transaction {
    spend_inputs(&[(u1, Sequence::ENABLE_RBF_NO_LOCKTIME)], outputs, LockTime::ZERO)
}

/// The pot payout output: P2TR with an unspendable NUMS internal key and two leaves — Bob-wins
/// (`<K> OP_CHECKSIG`, spendable only by the winner who knows `dlog K = w_b + a_c`) and
/// Alice-timeout (`<t_1> OP_CSV OP_DROP <P_a> OP_CHECKSIG`).
pub struct ClaimOutput {
    pub spk: ScriptBuf,
    pub spend_info: TaprootSpendInfo,
    pub bob_leaf: ScriptBuf,
    pub alice_leaf: ScriptBuf,
}

impl ClaimOutput {
    /// Build the claim output for pot-claim key `K`, Alice's fallback key, and relative timelock
    /// `alice_timeout` (blocks, BIP68).
    pub fn new(k: Point, alice_key: XOnlyPublicKey, alice_timeout: u16) -> Result<Self> {
        let k_xonly = XOnlyPublicKey::from_slice(&k.serialize()[1..33])
            .map_err(|_| Error::Protocol("claim key K is not a valid x-only point"))?;
        let bob_leaf = Builder::new()
            .push_x_only_key(&k_xonly)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let alice_leaf = Builder::new()
            .push_int(alice_timeout as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&alice_key)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let spend_info = TaprootBuilder::new()
            .add_leaf(1, bob_leaf.clone())
            .and_then(|b| b.add_leaf(1, alice_leaf.clone()))
            .map_err(|_| Error::Protocol("taproot builder: add leaf"))?
            .finalize(&secp, nums_internal())
            .map_err(|_| Error::Protocol("taproot builder: finalize"))?;
        let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
        Ok(ClaimOutput { spk, spend_info, bob_leaf, alice_leaf })
    }

    /// A `TxOut` paying `value` into the claim output.
    pub fn txout(&self, value: Amount) -> TxOut {
        TxOut { value, script_pubkey: self.spk.clone() }
    }

    /// The BIP341 control block proving `leaf` is committed in this output's script tree (goes in
    /// the witness of a script-path spend).
    pub fn control_block(&self, leaf: &ScriptBuf) -> Result<ControlBlock> {
        self.spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .ok_or(Error::Protocol("no control block for leaf"))
    }
}

/// A single-input spend of a claim output via one of its leaves. Bob passes `Sequence::default()`
/// (final); Alice passes `Sequence::from_height(t_1)` to satisfy the `OP_CSV` on her leaf.
pub fn build_claim_spend(claim: OutPoint, sequence: Sequence, outputs: Vec<TxOut>) -> Transaction {
    spend_inputs(&[(claim, sequence)], outputs, LockTime::ZERO)
}

/// The taproot **key-path** signature hash (BIP341, `SIGHASH_DEFAULT`) for `input_index`, given
/// all prevouts. Used for the MuSig2 spends of `U1`.
pub fn key_spend_sighash(tx: &Transaction, input_index: usize, prevouts: &[TxOut]) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(input_index, &Prevouts::All(prevouts), TapSighashType::Default)
        .map_err(|_| Error::Protocol("taproot key-spend sighash failed"))?;
    Ok(sighash.to_byte_array())
}

/// The taproot **script-path** signature hash for a tapscript `leaf`. Used for the claim output's
/// Bob-wins / Alice-timeout leaf spends.
pub fn script_spend_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf: &ScriptBuf,
) -> Result<[u8; 32]> {
    let mut cache = SighashCache::new(tx);
    let leaf_hash = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    let sighash = cache
        .taproot_script_spend_signature_hash(input_index, &Prevouts::All(prevouts), leaf_hash, TapSighashType::Default)
        .map_err(|_| Error::Protocol("taproot script-spend sighash failed"))?;
    Ok(sighash.to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use crate::musig::{adapt, extract};
    use crate::reveal::{claim_secret, compute_k};
    use musig2::secp::Scalar;
    use rand::RngCore;

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    }

    fn outpoint(tag: u8) -> OutPoint {
        OutPoint { txid: bitcoin::Txid::from_byte_array([tag; 32]), vout: 0 }
    }

    /// A plain 2-party MuSig2 key-path signature over `msg`, verified against the aggregate.
    fn plain_sig(key: &TaprootKey, a: &Keypair, b: &Keypair, msg: [u8; 32]) -> musig2::LiftedSignature {
        let (r1a, pna) = key.keyagg.first_round(0, a.sk, seed()).unwrap();
        let (r1b, pnb) = key.keyagg.first_round(1, b.sk, seed()).unwrap();
        let (mut r2a, psa) = r1a.sign(1, pnb, a.sk, msg).unwrap();
        let (mut r2b, psb) = r1b.sign(0, pna, b.sk, msg).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        r2a.finalize_plain().unwrap()
    }

    /// RefundTx spends U1 with a valid plain key-path signature.
    #[test]
    fn refund_one_input_plain() {
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let u1 = TaprootKey::new(a.pk, b.pk).unwrap();
        let v1 = Amount::from_sat(200_000);
        let prevouts = [u1.txout(v1)];

        let alice = TxOut { value: Amount::from_sat(100_000), script_pubkey: u1.spk.clone() };
        let bob = TxOut { value: Amount::from_sat(99_000), script_pubkey: u1.spk.clone() };
        let tx = build_refund(outpoint(0x11), alice, bob, LockTime::from_height(200).unwrap());

        let sighash = key_spend_sighash(&tx, 0, &prevouts).unwrap();
        let sig = plain_sig(&u1, &a, &b, sighash);
        musig2::verify_single(u1.keyagg.agg_point(), sig, sighash).expect("refund signs valid");
    }

    /// SettleTx spends U1 with a MuSig2 **adaptor** signature locked to `D = d·G`; completing it
    /// reveals `d` (the decryption key), and the output is the winner's claim output.
    #[test]
    fn settlement_u1_adaptor_on_d_reveals_d() {
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let u1 = TaprootKey::new(a.pk, b.pk).unwrap();
        let v1 = Amount::from_sat(200_000);
        let prevouts = [u1.txout(v1)];

        // Bob's claim key + a winning thimble scalar a_c; K = W_b + A_c.
        let w_b = Scalar::from(Keypair::new(&secp).sk);
        let a_c = Scalar::from(Keypair::new(&secp).sk);
        let k = compute_k(&w_b.base_point_mul(), &a_c.base_point_mul()).unwrap();
        let a_xonly = XOnlyPublicKey::from_slice(&a.pk.serialize()[1..33]).unwrap();
        let claim = ClaimOutput::new(k, a_xonly, 6).unwrap();
        let tx = build_settlement(outpoint(0x21), vec![claim.txout(Amount::from_sat(198_000))]);

        // Adaptor on D = d·G; completing it must reveal d.
        let d = Scalar::from(Keypair::new(&secp).sk);
        let sh = key_spend_sighash(&tx, 0, &prevouts).unwrap();
        let (r1a, pna) = u1.keyagg.first_round(0, a.sk, seed()).unwrap();
        let (r1b, pnb) = u1.keyagg.first_round(1, b.sk, seed()).unwrap();
        let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, d.base_point_mul(), sh).unwrap();
        let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, d.base_point_mul(), sh).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        let pre = r2a.finalize().unwrap();
        let sig = adapt(&pre, &d).unwrap();
        musig2::verify_single(u1.keyagg.agg_point(), sig, sh).expect("settlement adaptor completion valid");
        assert_eq!(extract(&pre, &sig).unwrap().unwrap(), d, "settlement reveals d");
    }

    /// The winner (who knows `dlog K = w_b + a_c`) can produce a valid BIP340 signature under the
    /// Bob-wins leaf key `K`.
    #[test]
    fn claim_bob_wins_leaf_signs() {
        use bitcoin::secp256k1::{Keypair as BKeypair, Message, Secp256k1, SecretKey};
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let w_b = Scalar::from(b.sk); // reuse b as the hidden claim key for the test
        let a_c = Scalar::from(Keypair::new(&secp).sk);
        let k = compute_k(&w_b.base_point_mul(), &a_c.base_point_mul()).unwrap();
        let claim_sk = claim_secret(&w_b, &a_c).unwrap(); // dlog K = w_b + a_c

        let a_xonly = XOnlyPublicKey::from_slice(&a.pk.serialize()[1..33]).unwrap();
        let claim = ClaimOutput::new(k, a_xonly, 6).unwrap();
        let claim_prevout = claim.txout(Amount::from_sat(150_000));

        let tx = build_claim_spend(
            outpoint(0x31),
            Sequence::default(),
            vec![TxOut { value: Amount::from_sat(149_000), script_pubkey: claim.spk.clone() }],
        );
        let sighash = script_spend_sighash(&tx, 0, &[claim_prevout], &claim.bob_leaf).unwrap();

        let bsecp = Secp256k1::new();
        let kp = BKeypair::from_secret_key(&bsecp, &SecretKey::from_slice(&claim_sk.serialize()).unwrap());
        let sig = bsecp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &kp);
        let k_xonly = XOnlyPublicKey::from_slice(&k.serialize()[1..33]).unwrap();
        bsecp
            .verify_schnorr(&sig, &Message::from_digest(sighash), &k_xonly)
            .expect("winner's bob-leaf signature is a valid BIP340 sig under K");
        assert!(claim.control_block(&claim.bob_leaf).is_ok());
    }

    /// Alice's timeout leaf: the spend must carry the relative-timelock sequence, and she signs a
    /// valid BIP340 sig under P_a.
    #[test]
    fn claim_alice_timeout_leaf_signs() {
        use bitcoin::secp256k1::{Keypair as BKeypair, Message, Secp256k1, SecretKey};
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let k = compute_k(
            &Scalar::from(b.sk).base_point_mul(),
            &Scalar::from(Keypair::new(&secp).sk).base_point_mul(),
        )
        .unwrap();
        let a_xonly = XOnlyPublicKey::from_slice(&a.pk.serialize()[1..33]).unwrap();
        let claim = ClaimOutput::new(k, a_xonly, 6).unwrap();
        let claim_prevout = claim.txout(Amount::from_sat(150_000));

        let tx = build_claim_spend(
            outpoint(0x41),
            Sequence::from_height(6),
            vec![TxOut { value: Amount::from_sat(149_000), script_pubkey: claim.spk.clone() }],
        );
        assert_eq!(tx.input[0].sequence, Sequence::from_height(6), "CSV-satisfying sequence");
        let sighash = script_spend_sighash(&tx, 0, &[claim_prevout], &claim.alice_leaf).unwrap();

        let bsecp = Secp256k1::new();
        let kp = BKeypair::from_secret_key(&bsecp, &SecretKey::from_slice(&Scalar::from(a.sk).serialize()).unwrap());
        let sig = bsecp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &kp);
        bsecp
            .verify_schnorr(&sig, &Message::from_digest(sighash), &a_xonly)
            .expect("Alice's timeout-leaf signature is valid under P_a");
        assert!(claim.control_block(&claim.alice_leaf).is_ok());
    }
}
