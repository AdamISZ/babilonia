#![cfg(feature = "node")] // drives a local bitcoind over RPC; needs the `node` feature
//! End-to-end regtest tests for the **v5** transaction graph. One jointly-funded output `U1`; the
//! settlement spends it with a MuSig2 **adaptor signature locked to `D = d·G`** whose completion
//! posts `d` on-chain. Bob extracts `d`, decrypts `a_c = ctxt − H(d)`, and — if he won — spends the
//! claim output via a **key-path** spend under `K` (its internal key). Also the fallbacks: refund
//! (`nLockTime t_r`) and Alice's timeout leaf. The hash conjunct binding `ctxt` to `a_c` is the ZKP
//! layer; here `ctxt` is honest
//! and we validate the on-chain graph + reveal against a real `bitcoind`.
//!
//! Requires `bitcoind` on PATH. Ignored by default. Run:
//!   cargo test --test regtest_e2e -- --ignored --test-threads=1 --nocapture

use babilonia::keys::Keypair;
use babilonia::musig::{adapt, extract, signature_bytes};
use babilonia::node::Node;
use babilonia::reveal::{claim_secret, compute_k, recover_a_c, won};
use babilonia::pi_a::{pad, Scheme};
use babilonia::txgraph::{
    build_claim_spend, build_refund, build_settlement, key_spend_sighash, script_spend_sighash,
    ClaimOutput, TaprootKey,
};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair as BKeypair, Message, SecretKey};
use bitcoin::{absolute::LockTime, Address, Amount, Network, OutPoint, Sequence, TxOut, Witness};
use bitcoincore_rpc::RpcApi;
use musig2::secp::Scalar;
use rand::RngCore;

fn seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// A plain 2-party MuSig2 key-path signature's 64 bytes, for a taproot key-spend witness.
fn plain_witness(key: &TaprootKey, a: &Keypair, b: &Keypair, msg: [u8; 32]) -> Vec<u8> {
    let (r1a, pna) = key.keyagg.first_round(0, a.sk, seed()).unwrap();
    let (r1b, pnb) = key.keyagg.first_round(1, b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign(1, pnb, a.sk, msg).unwrap();
    let (mut r2b, psb) = r1b.sign(0, pna, b.sk, msg).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    signature_bytes(&r2a.finalize_plain().unwrap()).to_vec()
}

fn addr(key: &TaprootKey) -> Address {
    Address::from_script(&key.spk, Network::Regtest).unwrap()
}

struct Funded {
    node: Node,
    secp: secp256k1::Secp256k1<secp256k1::All>,
    a: Keypair,
    b: Keypair,
    u1: TaprootKey,
    u1_out: OutPoint,
    v1: Amount,
}

fn fund_u1() -> Funded {
    let node = Node::regtest().expect("start bitcoind regtest");
    let secp = secp256k1::Secp256k1::new();
    let a = Keypair::new(&secp);
    let b = Keypair::new(&secp); // Bob's funding key (in Q)
    let u1 = TaprootKey::new(a.pk, b.pk).unwrap();
    let v1 = Amount::from_sat(500_000);
    let u1_out = node.fund_address(&addr(&u1), v1).unwrap();
    Funded { node, secp, a, b, u1, u1_out, v1 }
}

/// A completed 2-party MuSig2 adaptor signature on `D`, plus the pre-signature (so the caller can
/// `extract` the witness). Alice adapts with `d`.
fn adaptor_settle(
    f: &Funded,
    sh: [u8; 32],
    d: &Scalar,
) -> (musig2::LiftedSignature, musig2::AdaptorSignature) {
    let (r1a, pna) = f.u1.keyagg.first_round(0, f.a.sk, seed()).unwrap();
    let (r1b, pnb) = f.u1.keyagg.first_round(1, f.b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, f.a.sk, d.base_point_mul(), sh).unwrap();
    let (mut r2b, psb) = r1b.sign_adaptor(0, pna, f.b.sk, d.base_point_mul(), sh).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    let pre = r2a.finalize().unwrap();
    (adapt(&pre, d).unwrap(), pre)
}

/// Capstone: the settlement confirms (adaptor on `D`, posting `d`); Bob extracts `d`, decrypts
/// `a_c`, and spends the claim output via a **key-path** spend under `K` — the full Bob-wins
/// settlement on real `bitcoind`.
#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn settle_then_bob_claims_on_regtest() {
    let f = fund_u1();
    let prevouts = [f.u1.txout(f.v1)];

    // Alice's winning thimble scalar a_c, hidden claim key W_b; K = W_b + A_c.
    let a_c = Scalar::from(Keypair::new(&f.secp).sk);
    let w_b = Scalar::from(Keypair::new(&f.secp).sk);
    let k = compute_k(&w_b.base_point_mul(), &a_c.base_point_mul()).unwrap();
    let claim_sk = claim_secret(&w_b, &a_c).unwrap();
    let a_xonly = bitcoin::XOnlyPublicKey::from_slice(&f.a.pk.serialize()[1..33]).unwrap();
    let claim = ClaimOutput::new(k, a_xonly, 6).unwrap();

    // Alice's fresh dealer secret d and the ciphertext (sent to Bob off-chain in P4).
    let d = Scalar::from(Keypair::new(&f.secp).sk);
    let ctxt = (a_c + pad(Scheme::Squaring, &d)).unwrap();

    let fee = Amount::from_sat(2_000);
    let pot = f.v1 - fee;
    let mut settle = build_settlement(f.u1_out, vec![claim.txout(pot)]);
    let sh = key_spend_sighash(&settle, 0, &prevouts).unwrap();
    let (sig, pre) = adaptor_settle(&f, sh, &d);
    settle.input[0].witness = Witness::from_slice(&[signature_bytes(&sig).as_slice()]);

    let settle_txid = f.node.broadcast(&settle).expect("bitcoind accepts SettleTx (adaptor on D)");
    f.node.mine(1).unwrap();
    println!("[settle] confirmed {settle_txid} — d posted on-chain");

    // Bob: extract d from the published signature, decrypt a_c, confirm the win.
    let d_bob = extract(&pre, &sig).unwrap().unwrap();
    assert_eq!(d_bob, d, "Bob extracts d from the settlement");
    let a_c_bob = recover_a_c(Scheme::Squaring, &ctxt, &d_bob).unwrap();
    assert_eq!(a_c_bob, a_c, "Bob decrypts a_c = ctxt − H(d)");
    assert!(won(&a_c_bob, &a_c.base_point_mul()));

    // Bob claims the pot via a KEY-PATH spend under K (internal key) — no script revealed.
    let claim_out = OutPoint { txid: settle_txid, vout: 0 };
    let dest = f.node.new_address().unwrap();
    let mut claim_tx = build_claim_spend(
        claim_out,
        Sequence::default(),
        vec![TxOut { value: pot - fee, script_pubkey: dest.script_pubkey() }],
    );
    let csh = key_spend_sighash(&claim_tx, 0, &[claim.txout(pot)]).unwrap();
    let bsecp = bitcoin::secp256k1::Secp256k1::new();
    let kp = BKeypair::from_secret_key(&bsecp, &SecretKey::from_slice(&claim_sk.serialize()).unwrap());
    let tweaked = kp.tap_tweak(&bsecp, claim.spend_info.merkle_root());
    let key_sig = bsecp.sign_schnorr_no_aux_rand(&Message::from_digest(csh), &tweaked.to_keypair()).serialize();
    claim_tx.input[0].witness = Witness::from_slice(&[key_sig.as_slice()]);

    let claim_txid = f.node.broadcast(&claim_tx).expect("bitcoind accepts Bob's key-path claim under K");
    f.node.mine(1).unwrap();
    assert!(f.node.utxo_confirmations(&OutPoint { txid: claim_txid, vout: 0 }).unwrap().is_some());
    println!("[claim]  Bob decrypted a_c and spent the pot via K (key path) ✓  ({claim_txid})");
}

/// Alice's timeout leaf: rejected before the relative timelock, accepted after.
#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn alice_timeout_claim_on_regtest() {
    let f = fund_u1();
    let prevouts = [f.u1.txout(f.v1)];
    let timeout: u16 = 5;

    // A claim output whose K nobody spends (Bob "lost"); Alice reclaims after `timeout`.
    let k = compute_k(
        &Scalar::from(Keypair::new(&f.secp).sk).base_point_mul(),
        &Scalar::from(Keypair::new(&f.secp).sk).base_point_mul(),
    )
    .unwrap();
    let a_xonly = bitcoin::XOnlyPublicKey::from_slice(&f.a.pk.serialize()[1..33]).unwrap();
    let claim = ClaimOutput::new(k, a_xonly, timeout).unwrap();

    let fee = Amount::from_sat(2_000);
    let pot = f.v1 - fee;
    let d = Scalar::from(Keypair::new(&f.secp).sk);
    let mut settle = build_settlement(f.u1_out, vec![claim.txout(pot)]);
    let sh = key_spend_sighash(&settle, 0, &prevouts).unwrap();
    let (sig, _pre) = adaptor_settle(&f, sh, &d);
    settle.input[0].witness = Witness::from_slice(&[signature_bytes(&sig).as_slice()]);
    let settle_txid = f.node.broadcast(&settle).expect("settlement confirms");
    f.node.mine(1).unwrap();

    let claim_out = OutPoint { txid: settle_txid, vout: 0 };
    let dest = f.node.new_address().unwrap();
    let build_alice_spend = || {
        let mut t = build_claim_spend(
            claim_out,
            Sequence::from_height(timeout),
            vec![TxOut { value: pot - fee, script_pubkey: dest.script_pubkey() }],
        );
        let sh = script_spend_sighash(&t, 0, &[claim.txout(pot)], &claim.alice_leaf).unwrap();
        let bsecp = bitcoin::secp256k1::Secp256k1::new();
        let kp = BKeypair::from_secret_key(&bsecp, &SecretKey::from_slice(&Scalar::from(f.a.sk).serialize()).unwrap());
        let sig = bsecp.sign_schnorr_no_aux_rand(&Message::from_digest(sh), &kp).serialize();
        let cb = claim.control_block(&claim.alice_leaf).unwrap();
        t.input[0].witness =
            Witness::from_slice(&[sig.as_slice(), claim.alice_leaf.as_bytes(), &cb.serialize()]);
        t
    };

    assert!(f.node.broadcast(&build_alice_spend()).is_err(), "timeout leaf rejected before t_1");
    f.node.mine(timeout as u64).unwrap();
    let txid = f.node.broadcast(&build_alice_spend()).expect("timeout leaf accepted after t_1");
    f.node.mine(1).unwrap();
    assert!(f.node.utxo_confirmations(&OutPoint { txid, vout: 0 }).unwrap().is_some());
    println!("[timeout] Alice reclaimed via the timeout leaf after t_1 ✓");
}

/// RefundTx spends U1 back to the stakes once `nLockTime t_r` matures.
#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn refund_after_locktime_on_regtest() {
    let f = fund_u1();
    let prevouts = [f.u1.txout(f.v1)];

    let height = f.node.client.get_block_count().unwrap() as u32;
    let t_r = height + 5;
    let fee = Amount::from_sat(2_000);
    let alice = TxOut { value: f.v1 - fee, script_pubkey: f.node.new_address().unwrap().script_pubkey() };
    let bob = TxOut { value: Amount::from_sat(1_000), script_pubkey: f.node.new_address().unwrap().script_pubkey() };

    let build_refund_tx = || {
        let mut t = build_refund(f.u1_out, alice.clone(), bob.clone(), LockTime::from_height(t_r).unwrap());
        let sh = key_spend_sighash(&t, 0, &prevouts).unwrap();
        t.input[0].witness = Witness::from_slice(&[plain_witness(&f.u1, &f.a, &f.b, sh).as_slice()]);
        t
    };

    assert!(f.node.broadcast(&build_refund_tx()).is_err(), "refund rejected before t_r");
    f.node.mine(6).unwrap();
    let txid = f.node.broadcast(&build_refund_tx()).expect("refund accepted at t_r");
    f.node.mine(1).unwrap();
    assert!(f.node.utxo_confirmations(&OutPoint { txid, vout: 0 }).unwrap().is_some());
    println!("[refund] stakes refunded after t_r ✓");
}
