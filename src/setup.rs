//! The v5 setup driver (`adaptor_construction_spec_v5.tex`, P1–P6): a four-flight interactive
//! exchange over a [`Transport`] that pre-signs the tx graph (the refund, and the settlement
//! adaptor pre-signature locked to `D`) and commits the encrypted outcome `ctxt = a_c + H(d)`.
//!
//! `π_a` is produced/verified through the narrow [`crate::pi_a`] interface (`prove`/`verify`): the
//! Σ-part is always proved, and with the `pi_a` feature the real `ctxt = a_c + H(d)` hash conjunct
//! is too. `π_r` and the thimble PoKs are real. Two MuSig2 sessions run over the
//! flights: the **refund** (plain) and the **settlement** (adaptor on `D`), both single-input.
//!
//! On success each side holds the same pre-signed settlement (Alice can `adapt` it with `d` and
//! broadcast → reveals `d`; Bob then `extract`s `d` and decrypts `a_c`) and the same refund.

use std::str::FromStr;

use bitcoin::{absolute::LockTime, Address, Amount, OutPoint, ScriptBuf, Transaction, TxOut, XOnlyPublicKey};
use musig2::secp::{Point, Scalar};
use musig2::{AdaptorSignature, LiftedSignature};
use serde::{Deserialize, Serialize};

use crate::keys::Keypair;
use crate::messages::{AliceOpen, AliceReveal, BobAuth, BobCommit};
use crate::musig::KeyAgg;
use crate::pi_a;
use crate::reveal::compute_k;
use crate::sigma;
use crate::txgraph::{build_refund, build_settlement, key_spend_sighash, shuffle_seeded, ClaimOutput, TaprootKey};
use crate::transport::Transport;
use crate::{Error, Result};

/// Parameters both parties agree on before the driver runs (funding + payout shape).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GameParams {
    /// The confirmed pot outpoint `U1` and its value.
    pub u1_outpoint: OutPoint,
    pub u1_value: Amount,
    pub alice_stake: Amount,
    pub bob_stake: Amount,
    /// Flat per-tx fee (settlement / refund).
    pub fee: Amount,
    /// Refund absolute lock height `t_r`.
    pub refund_locktime: u32,
    /// Claim-output Alice-timeout relative lock `t_1` (blocks).
    pub alice_timeout: u16,
    /// Which π_a construction to use (both parties must agree). See [`pi_a::Scheme`].
    pub pi_a_scheme: pi_a::Scheme,
    /// Alice's payout address (parked `c_A` in the settlement, `F_A` in the refund). Filled by
    /// `fund_pot` from the funding flights; empty until then. See COVERT-TX-PLAN §8.
    pub alice_payout: String,
    /// Bob's payout address (the refund's `b→Bob` output). Filled by `fund_pot`.
    pub bob_payout: String,
}

/// Alice's private inputs.
#[derive(Clone, Serialize, Deserialize)]
pub struct AliceSecrets {
    pub identity: Keypair,
    /// Thimble secret scalars `a_1, a_2` (thimbles `A_i = a_i·G`).
    pub thimbles: [Scalar; 2],
    /// Alice's secret choice `c ∈ {0,1}`.
    pub choice: usize,
    /// Fresh dealer decryption secret `d` (the settlement adaptor witness).
    pub d: Scalar,
}

/// Bob's private inputs.
#[derive(Clone, Serialize, Deserialize)]
pub struct BobSecrets {
    pub funding: Keypair,
    /// Bob's hidden claim key `W_b` (≠ funding key).
    pub claim: Keypair,
    /// Bob's secret guess `y ∈ {0,1}`.
    pub guess: usize,
}

/// The pre-signed artifacts both parties end with (they agree on all of these).
pub struct SetupResult {
    pub keyagg: KeyAgg,
    pub settle_tx: Transaction,
    pub settle_sighash: [u8; 32],
    /// Settlement adaptor pre-signature locked to `D`; Alice completes it with `d`.
    pub settle_pre: AdaptorSignature,
    pub refund_tx: Transaction,
    pub refund_sighash: [u8; 32],
    pub refund_sig: LiftedSignature,
    pub ctxt: Scalar,
    /// `D = d·G`.
    pub d_point: Point,
    /// `K = W_b + A_y`.
    pub k: Point,
    pub thimbles: [Point; 2],
    /// Alice's funding key `P_a` (both know it; needed to rebuild the claim output).
    pub p_a: Point,
}

fn ctx_keys(p_a: &Point, p_b: &Point) -> Vec<u8> {
    let mut v = p_a.serialize().to_vec();
    v.extend_from_slice(&p_b.serialize());
    v
}

fn x_only(p: &secp256k1::PublicKey) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&p.serialize()[1..33]).map_err(|_| Error::Protocol("bad x-only key"))
}

/// The scriptPubKey of a payout address string. The `scriptPubKey` is network-independent, so we
/// `assume_checked` rather than thread the network through the setup driver.
fn payout_spk(addr: &str) -> Result<ScriptBuf> {
    Ok(Address::from_str(addr).map_err(|_| Error::Protocol("bad payout address"))?.assume_checked().script_pubkey())
}

/// A per-tx shuffle seed for a co-signed tx: `SHA256(domain ‖ shared)` where `shared` is the
/// ECDH secret both parties (and *only* they) share. Distinct `domain` per tx ⇒ independent orders.
fn order_seed(domain: &[u8], shared: &[u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let mut eng = sha256::Hash::engine();
    eng.input(domain);
    eng.input(shared);
    sha256::Hash::from_engine(eng).to_byte_array()
}

/// Build the (identical, on both sides) settlement + refund txs and their key-spend sighashes for
/// the pot `u1` given the claim key `k`. Both are the payment-manifold 2-out shape (Alice-parks,
/// COVERT-TX-PLAN §8.2): the settlement pays `{O_K = S, c_A_out → alice_payout}`, the refund
/// `{F_A_out → alice_payout, b → bob_payout}`. Output order is shuffled from the shared secret
/// `shared` (§9) so it looks random on-chain while both parties derive the same bytes.
fn tx_graph(
    u1: &TaprootKey,
    p_a: &secp256k1::PublicKey,
    k: &Point,
    params: &GameParams,
    shared: &[u8; 32],
) -> Result<(Transaction, [u8; 32], ClaimOutput, Transaction, [u8; 32])> {
    let prevout = u1.txout(params.u1_value);
    let claim = ClaimOutput::new(*k, x_only(p_a)?, params.alice_timeout)?;
    let s = params.alice_stake + params.bob_stake; // at-risk pot; O_K carries exactly this
    let c_a_out = params
        .u1_value
        .checked_sub(s)
        .and_then(|v| v.checked_sub(params.fee))
        .ok_or(Error::Protocol("settlement: c_A_out underflow"))?;
    let alice_spk = payout_spk(&params.alice_payout)?;
    let mut settle_outs = vec![claim.txout(s), TxOut { value: c_a_out, script_pubkey: alice_spk.clone() }];
    shuffle_seeded(&mut settle_outs, &order_seed(b"babilonia/settle-order", shared));
    let settle_tx = build_settlement(params.u1_outpoint, settle_outs);
    let settle_sighash = key_spend_sighash(&settle_tx, 0, &[prevout.clone()])?;

    let refund_locktime = LockTime::from_height(params.refund_locktime)
        .map_err(|_| Error::Protocol("bad refund locktime"))?;
    let f_a_out = params
        .u1_value
        .checked_sub(params.bob_stake)
        .and_then(|v| v.checked_sub(params.fee))
        .ok_or(Error::Protocol("refund: F_A_out underflow"))?;
    let mut refund_outs = vec![
        TxOut { value: f_a_out, script_pubkey: alice_spk },
        TxOut { value: params.bob_stake, script_pubkey: payout_spk(&params.bob_payout)? },
    ];
    shuffle_seeded(&mut refund_outs, &order_seed(b"babilonia/refund-order", shared));
    let refund_tx = build_refund(params.u1_outpoint, refund_outs, refund_locktime);
    let refund_sighash = key_spend_sighash(&refund_tx, 0, &[prevout])?;
    Ok((settle_tx, settle_sighash, claim, refund_tx, refund_sighash))
}

/// The ECDH shared secret between the two funding keys — `x_a·P_b = x_b·P_a`, known only to the two
/// parties. Seeds the co-signed txs' output shuffle (both derive it, observers can't).
fn shared_secret(sk: &secp256k1::SecretKey, other_pk: &secp256k1::PublicKey) -> [u8; 32] {
    secp256k1::ecdh::SharedSecret::new(other_pk, sk).secret_bytes()
}

/// Run Alice's side (signer index 0).
pub fn run_alice<T: Transport>(ch: &mut T, params: &GameParams, s: &AliceSecrets) -> Result<SetupResult> {
    let p_a: Point = s.identity.pk.into();
    let thimbles = s.thimbles.map(|a| a.base_point_mul());
    let [a1, a2] = thimbles;

    // Self-protection: equal thimbles make Bob always win (a_c is the same for either choice), so
    // Alice must never commit them. Bob rejects this too (run_bob), but Alice is the party harmed,
    // so she is the one with the real incentive to check — and does so for every π_a scheme here.
    if a1 == a2 {
        return Err(Error::Protocol("degenerate thimbles: A_1 == A_2"));
    }

    // Flight 1 (P2): thimbles + PoKs.
    ch.send(
        &AliceOpen {
            p_a,
            a1,
            a2,
            thimble_poks: sigma::prove_thimble_poks(&s.thimbles, &p_a.serialize()),
        }
        .encode(),
    )?;

    // Flight 2 (P3): Bob's key, K, π_r, nonces.
    let commit = BobCommit::decode(&ch.recv()?)?;
    let ctx = ctx_keys(&p_a, &commit.p_b);
    if !sigma::verify_pi_r(&commit.k, &thimbles, &ctx, &commit.pi_r) {
        return Err(Error::ProofInvalid("pi_r"));
    }
    let p_b_pub: secp256k1::PublicKey = commit.p_b.into();
    let u1 = TaprootKey::new(s.identity.pk, p_b_pub)?;
    let shared = shared_secret(&s.identity.sk, &p_b_pub);
    let (settle_tx, settle_sighash, _claim, refund_tx, refund_sighash) =
        tx_graph(&u1, &s.identity.pk, &commit.k, params, &shared)?;

    // Alice's MuSig2 sessions (distinct fresh seeds — nonce hygiene).
    let (r1_refund, refund_nonce) = u1.keyagg.first_round(0, s.identity.sk, fresh_seed())?;
    let (r1_settle, settle_nonce) = u1.keyagg.first_round(0, s.identity.sk, fresh_seed())?;
    let d_point = s.d.base_point_mul();
    let (mut r2_refund, refund_partial) = r1_refund.sign(1, commit.refund_nonce, s.identity.sk, refund_sighash)?;
    let (mut r2_settle, settle_partial) =
        r1_settle.sign_adaptor(1, commit.settle_nonce, s.identity.sk, d_point, settle_sighash)?;

    // The encrypted outcome + π_a. `pad` is the single H definition (shared with reveal); `pi_a`
    // proves `ctxt = a_c + H(d) ∧ a_c·G ∈ {A_i} ∧ D = d·G` (hash conjunct real with the `pi_a`
    // feature, Σ-part otherwise).
    let a_c = s.thimbles[s.choice];
    let ctxt = (a_c + pi_a::pad(params.pi_a_scheme, &s.d)).unwrap();
    let statement = pi_a::Statement { ctxt, d_point, thimbles, ctx: ctx.clone() };
    let witness = pi_a::Witness { t: s.d, choice: s.choice, a_c };
    let pi_a = pi_a::prove(params.pi_a_scheme, &statement, &witness)?.to_bytes();

    // Flight 3 (P4).
    ch.send(
        &AliceReveal { refund_nonce, settle_nonce, ctxt, d_point, pi_a, refund_partial, settle_partial }.encode(),
    )?;

    // Flight 4 (P5): Bob's partials complete both sessions.
    let auth = BobAuth::decode(&ch.recv()?)?;
    r2_refund.receive(1, auth.refund_partial)?;
    r2_settle.receive(1, auth.settle_partial)?;
    let refund_sig = r2_refund.finalize_plain()?;
    let settle_pre = r2_settle.finalize()?;

    Ok(SetupResult {
        keyagg: u1.keyagg,
        settle_tx,
        settle_sighash,
        settle_pre,
        refund_tx,
        refund_sighash,
        refund_sig,
        ctxt,
        d_point,
        k: commit.k,
        thimbles,
        p_a,
    })
}

/// Run Bob's side (signer index 1).
pub fn run_bob<T: Transport>(ch: &mut T, params: &GameParams, s: &BobSecrets) -> Result<SetupResult> {
    if s.guess >= 2 {
        return Err(Error::Protocol("guess out of range"));
    }
    // Flight 1 (P2): Alice's thimbles + PoKs.
    let open = AliceOpen::decode(&ch.recv()?)?;
    if open.a1 == open.a2 {
        return Err(Error::Protocol("degenerate thimbles: A_1 == A_2"));
    }
    let thimbles = [open.a1, open.a2];
    if !sigma::verify_thimble_poks(&thimbles, &open.p_a.serialize(), &open.thimble_poks) {
        return Err(Error::ProofInvalid("thimble PoKs"));
    }

    let p_b: Point = s.funding.pk.into();
    let w_b: Point = s.claim.pk.into();
    let k = compute_k(&w_b, &thimbles[s.guess])?; // K = W_b + A_y
    let ctx = ctx_keys(&open.p_a, &p_b);
    let w_b_scalar: Scalar = s.claim.sk.into();
    let pi_r = sigma::prove_pi_r(&w_b_scalar, s.guess, &k, &thimbles, &ctx)?;

    let p_a_pub: secp256k1::PublicKey = open.p_a.into();
    let u1 = TaprootKey::new(p_a_pub, s.funding.pk)?;
    let shared = shared_secret(&s.funding.sk, &p_a_pub);
    let (settle_tx, settle_sighash, _claim, refund_tx, refund_sighash) =
        tx_graph(&u1, &p_a_pub, &k, params, &shared)?;

    // Bob's sessions + nonces.
    let (r1_refund, refund_nonce) = u1.keyagg.first_round(1, s.funding.sk, fresh_seed())?;
    let (r1_settle, settle_nonce) = u1.keyagg.first_round(1, s.funding.sk, fresh_seed())?;

    // Flight 2 (P3).
    ch.send(&BobCommit { p_b, k, pi_r, refund_nonce, settle_nonce }.encode())?;

    // Flight 3 (P4): Alice's nonces, ctxt, D, π_a, partials.
    let reveal = AliceReveal::decode(&ch.recv()?)?;
    let statement = pi_a::Statement {
        ctxt: reveal.ctxt,
        d_point: reveal.d_point,
        thimbles,
        ctx: ctx.clone(),
    };
    if !pi_a::verify(params.pi_a_scheme, &statement, &pi_a::Proof::from_bytes(&reveal.pi_a))? {
        return Err(Error::ProofInvalid("pi_a"));
    }
    let (mut r2_refund, refund_partial) = r1_refund.sign(0, reveal.refund_nonce, s.funding.sk, refund_sighash)?;
    let (mut r2_settle, settle_partial) =
        r1_settle.sign_adaptor(0, reveal.settle_nonce, s.funding.sk, reveal.d_point, settle_sighash)?;

    // Flight 4 (P5).
    ch.send(&BobAuth { refund_partial, settle_partial }.encode())?;

    r2_refund.receive(0, reveal.refund_partial)?;
    r2_settle.receive(0, reveal.settle_partial)?;
    let refund_sig = r2_refund.finalize_plain()?;
    let settle_pre = r2_settle.finalize()?;

    Ok(SetupResult {
        keyagg: u1.keyagg,
        settle_tx,
        settle_sighash,
        settle_pre,
        refund_tx,
        refund_sighash,
        refund_sig,
        ctxt: reveal.ctxt,
        d_point: reveal.d_point,
        k,
        thimbles,
        p_a: open.p_a,
    })
}

fn fresh_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut s = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::musig::{adapt, extract};
    use crate::reveal::{claim_secret, recover_a_c, won};
    use crate::transport::memory::channel_pair;

    fn scalar() -> Scalar {
        let secp = secp256k1::Secp256k1::new();
        Scalar::from(Keypair::new(&secp).sk)
    }

    /// The full v5 setup runs over the transport (π_a Σ-part real, hash conjunct stubbed): both
    /// sides agree on the pre-signed settlement + refund, Alice completes the settlement with `d`,
    /// and Bob recovers `a_c` and his claim key `K`.
    #[test]
    fn v5_setup_flow_over_transport() {
        let secp = secp256k1::Secp256k1::new();
        let c = 1usize;
        let alice = AliceSecrets {
            identity: Keypair::new(&secp),
            thimbles: [scalar(), scalar()],
            choice: c,
            d: scalar(),
        };
        let bob = BobSecrets {
            funding: Keypair::new(&secp),
            claim: Keypair::new(&secp),
            guess: c, // a winning guess
        };
        let payout = || {
            let xo = XOnlyPublicKey::from_slice(&Keypair::new(&secp).pk.serialize()[1..33]).unwrap();
            let bsecp = bitcoin::secp256k1::Secp256k1::new();
            bitcoin::Address::p2tr(&bsecp, xo, None, bitcoin::Network::Regtest).to_string()
        };
        let params = GameParams {
            u1_outpoint: OutPoint { txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), vout: 0 },
            u1_value: Amount::from_sat(600_000),
            alice_stake: Amount::from_sat(250_000),
            bob_stake: Amount::from_sat(248_000),
            fee: Amount::from_sat(2_000),
            refund_locktime: 200,
            alice_timeout: 6,
            pi_a_scheme: pi_a::Scheme::Squaring,
            alice_payout: payout(),
            bob_payout: payout(),
        };
        // Snapshots for the post-run check.
        let d = alice.d;
        let a_c = alice.thimbles[c];
        let w_b = Scalar::from(bob.claim.sk);

        let (mut alice_ch, mut bob_ch) = channel_pair();
        let params_b = params.clone();
        let bob_handle = std::thread::spawn(move || run_bob(&mut bob_ch, &params_b, &bob));
        let a = run_alice(&mut alice_ch, &params, &alice).unwrap();
        let b = bob_handle.join().unwrap().unwrap();

        // Both sides agree on the shared artifacts.
        assert_eq!(a.settle_sighash, b.settle_sighash);
        assert_eq!(a.ctxt, b.ctxt);
        assert_eq!(a.d_point, b.d_point);
        assert_eq!(a.k, b.k);

        // Alice completes the settlement with d → a valid BIP340 sig for Q; Bob extracts d from it
        // (using his own pre-sig), decrypts a_c, and confirms his win + claim key.
        let final_sig = adapt(&a.settle_pre, &d).expect("adapt with d");
        musig2::verify_single(a.keyagg.agg_point(), final_sig, a.settle_sighash)
            .expect("completed settlement is a valid key-path signature");
        let d_bob = extract(&b.settle_pre, &final_sig).unwrap().unwrap();
        assert_eq!(d_bob, d, "Bob extracts d");
        let a_c_bob = recover_a_c(pi_a::Scheme::Squaring, &b.ctxt, &d_bob).unwrap();
        assert_eq!(a_c_bob, a_c, "Bob decrypts a_c");
        assert!(won(&a_c_bob, &b.thimbles[c]));
        assert_eq!(claim_secret(&w_b, &a_c_bob).unwrap().base_point_mul(), b.k, "K spendable");

        // The refund is a valid signature too.
        musig2::verify_single(a.keyagg.agg_point(), a.refund_sig, a.refund_sighash).expect("refund valid");
    }
}
