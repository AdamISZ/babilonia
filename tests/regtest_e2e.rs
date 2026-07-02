//! End-to-end regtest baseline: fund `Q_fund`, build + sign ChallengeTx (MuSig2 adaptor →
//! adapt), assemble the taproot key-path witness, broadcast to a real `bitcoind`, mine, and
//! assert `Q'` is a confirmed UTXO. This is the consensus/relay proof the offline unit tests
//! can't give, and it exercises witness assembly.
//!
//! Requires `bitcoind` (v31) on PATH. Ignored by default so `cargo test` stays hermetic. Run:
//!   cargo test --test regtest_e2e -- --ignored --nocapture

use babilonia::keys::Keypair;
use babilonia::musig::{adapt, extract, signature_bytes};
use babilonia::regtest::RegtestNode;
use babilonia::reveal::{
    bob_claim_secret, bob_derive_win_scalar, compute_k_b, open_chosen_thimble,
};
use babilonia::thimbles::Thimbles;
use babilonia::txgraph::{build_challenge, build_settlement, key_spend_sighash, TaprootKey};
use bitcoin::{Address, Amount, Network, OutPoint, TxOut, Witness};
use bitcoincore_rpc::RpcApi;
use musig2::secp::{Point, Scalar};
use musig2::CompactSignature;
use rand::RngCore;

fn seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// Everything the settlement tests need after the game has reached the pot `Q'` on-chain.
struct AtPot {
    node: RegtestNode,
    secp: secp256k1::Secp256k1<secp256k1::All>,
    a: Keypair,
    b: Keypair,
    q_prime: TaprootKey,
    q_prime_outpoint: OutPoint,
    q_prime_value: Amount,
}

/// Fund `Q_fund`, broadcast+confirm ChallengeTx (the reveal), and return the live `Q'` UTXO.
fn play_to_pot() -> AtPot {
    let node = RegtestNode::start().expect("start bitcoind regtest");
    let secp = secp256k1::Secp256k1::new();
    let a = Keypair::new(&secp);
    let b = Keypair::new(&secp);

    let q_fund = TaprootKey::new(a.pk, b.pk).unwrap();
    let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();

    let pot = Amount::from_sat(500_000);
    let q_fund_addr = Address::from_script(&q_fund.spk, Network::Regtest).unwrap();
    let q_fund_outpoint = node.fund_address(&q_fund_addr, pot).unwrap();

    let challenge_fee = Amount::from_sat(1_000);
    let mut tx = build_challenge(q_fund_outpoint, pot, &q_prime, challenge_fee).unwrap();
    let sighash = key_spend_sighash(&tx, 0, &[q_fund.txout(pot)]).unwrap();

    let t = Scalar::from(Keypair::new(&secp).sk);
    let big_t = t.base_point_mul();
    let (r1a, pna) = q_fund.keyagg.first_round(0, a.sk, seed()).unwrap();
    let (r1b, pnb) = q_fund.keyagg.first_round(1, b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, big_t, sighash).unwrap();
    let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, big_t, sighash).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    let pre = r2a.finalize().unwrap();
    let final_sig = adapt(&pre, &t).unwrap();
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&final_sig).as_slice()]);

    let challenge_txid = node.broadcast(&tx).expect("ChallengeTx accepted");
    node.mine(1).unwrap();

    AtPot {
        node,
        secp,
        a,
        b,
        q_prime,
        q_prime_outpoint: OutPoint { txid: challenge_txid, vout: 0 },
        q_prime_value: pot - challenge_fee,
    }
}

#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn challenge_tx_confirms_on_regtest() {
    let node = RegtestNode::start().expect("start bitcoind regtest");

    let secp = secp256k1::Secp256k1::new();
    let a = Keypair::new(&secp);
    let b = Keypair::new(&secp);

    // Q_fund and Q' are both MuSig2(P_a,P_b) taproot key-path outputs.
    let q_fund = TaprootKey::new(a.pk, b.pk).unwrap();
    let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();

    // Fund Q_fund from the node wallet (single-funder stand-in for the real 2-input co-spend).
    let pot = Amount::from_sat(500_000);
    let q_fund_addr = Address::from_script(&q_fund.spk, Network::Regtest).expect("p2tr address");
    let q_fund_outpoint = node.fund_address(&q_fund_addr, pot).expect("fund Q_fund");

    // Build ChallengeTx: Q_fund -> Q' (value = pot - fee).
    let fee = Amount::from_sat(1_000);
    let mut tx = build_challenge(q_fund_outpoint, pot, &q_prime, fee).unwrap();
    let prevout = q_fund.txout(pot);
    let sighash = key_spend_sighash(&tx, 0, &[prevout]).unwrap();

    // Two-party MuSig2 adaptor signature over the real sighash, offset by T = t*G.
    let t = Scalar::from(Keypair::new(&secp).sk);
    let big_t = t.base_point_mul();
    let (r1a, pna) = q_fund.keyagg.first_round(0, a.sk, seed()).unwrap();
    let (r1b, pnb) = q_fund.keyagg.first_round(1, b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, big_t, sighash).unwrap();
    let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, big_t, sighash).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    let pre = r2a.finalize().unwrap();

    // Alice completes with t; assemble the key-path witness (single 64-byte element).
    let final_sig = adapt(&pre, &t).unwrap();
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&final_sig).as_slice()]);

    // Broadcast + confirm.
    let txid = node.broadcast(&tx).expect("bitcoind accepts ChallengeTx");
    node.mine(1).unwrap();

    // Q' (ChallengeTx output 0) is a confirmed UTXO of the expected value.
    let q_prime_outpoint = bitcoin::OutPoint { txid, vout: 0 };
    let confs = node
        .utxo_confirmations(&q_prime_outpoint)
        .unwrap()
        .expect("Q' is unspent/confirmed");
    assert!(confs >= 1, "Q' confirmed, got {confs} confirmations");

    // The broadcast also revealed t (the reveal): Bob can extract it from the on-chain sig.
    assert_eq!(extract(&pre, &final_sig).unwrap().unwrap(), t);
}

#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn settle_bob_wins_confirms_on_regtest() {
    let g = play_to_pot();

    // Bob's winning key material: t_b, his identity x_b, and the revealed win scalar h (=h_{i*}).
    let t_b = Scalar::from(Keypair::new(&g.secp).sk);
    let x_b = Scalar::from(g.b.sk);
    let h_win = Scalar::from(Keypair::new(&g.secp).sk);
    let p_b: Point = g.b.pk.into();
    let k_b = compute_k_b(&t_b, &p_b, &h_win.base_point_mul()).unwrap();
    let claim = bob_claim_secret(&t_b, &x_b, &h_win).unwrap(); // dlog(K_b), Bob only knows on winning

    // Split outputs: Bob (winner) d_B+δ, Alice (loser) d_A−δ; fee = value − 498_000 = 1_000.
    let bob_addr = g.node.new_address().unwrap();
    let alice_addr = g.node.new_address().unwrap();
    let winner = TxOut { value: Amount::from_sat(300_000), script_pubkey: bob_addr.script_pubkey() };
    let loser = TxOut { value: Amount::from_sat(198_000), script_pubkey: alice_addr.script_pubkey() };
    let mut tx = build_settlement(g.q_prime_outpoint, winner, loser, None);
    let sighash = key_spend_sighash(&tx, 0, &[g.q_prime.txout(g.q_prime_value)]).unwrap();

    // Both adaptor-sign on K_b; Bob completes with dlog(K_b).
    let (r1a, pna) = g.q_prime.keyagg.first_round(0, g.a.sk, seed()).unwrap();
    let (r1b, pnb) = g.q_prime.keyagg.first_round(1, g.b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, g.a.sk, k_b, sighash).unwrap();
    let (mut r2b, psb) = r1b.sign_adaptor(0, pna, g.b.sk, k_b, sighash).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    let pre = r2a.finalize().unwrap();
    let final_sig = adapt(&pre, &claim).unwrap();
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&final_sig).as_slice()]);

    let txid = g.node.broadcast(&tx).expect("bitcoind accepts SettleBobWins");
    g.node.mine(1).unwrap();

    assert!(
        g.node.utxo_confirmations(&OutPoint { txid, vout: 0 }).unwrap().unwrap_or(0) >= 1,
        "settlement output confirmed"
    );
    assert!(
        g.node.utxo_confirmations(&g.q_prime_outpoint).unwrap().is_none(),
        "Q' was consumed by SettleBobWins"
    );
}

#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn settle_alice_wins_relative_timelock_on_regtest() {
    let g = play_to_pot(); // Q' now has 1 confirmation

    let alice_addr = g.node.new_address().unwrap();
    let bob_addr = g.node.new_address().unwrap();
    let winner = TxOut { value: Amount::from_sat(300_000), script_pubkey: alice_addr.script_pubkey() };
    let loser = TxOut { value: Amount::from_sat(198_000), script_pubkey: bob_addr.script_pubkey() };
    let n = 3u16;
    let mut tx = build_settlement(g.q_prime_outpoint, winner, loser, Some(n));
    let sighash = key_spend_sighash(&tx, 0, &[g.q_prime.txout(g.q_prime_value)]).unwrap();

    // Plain 2-party pre-signed keypath spend (Bob can't retract → no veto).
    let (r1a, pna) = g.q_prime.keyagg.first_round(0, g.a.sk, seed()).unwrap();
    let (r1b, pnb) = g.q_prime.keyagg.first_round(1, g.b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign(1, pnb, g.a.sk, sighash).unwrap();
    let (mut r2b, psb) = r1b.sign(0, pna, g.b.sk, sighash).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    let final_sig = r2a.finalize_plain().unwrap();
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&final_sig).as_slice()]);

    // Q' has 1 confirmation < N=3 ⇒ BIP68 relative timelock not yet mature ⇒ rejected.
    assert!(
        g.node.broadcast(&tx).is_err(),
        "SettleAliceWins must be rejected before the relative timelock matures"
    );

    // Advance so Q' has >= 3 confirmations, then it is accepted.
    g.node.mine(2).unwrap();
    let txid = g.node.broadcast(&tx).expect("SettleAliceWins accepted after N blocks");
    g.node.mine(1).unwrap();
    assert!(
        g.node.utxo_confirmations(&OutPoint { txid, vout: 0 }).unwrap().unwrap_or(0) >= 1,
        "settlement output confirmed"
    );
}

/// Capstone: the whole cryptographic game, end to end on a real node, with a *real* `h_{i*}`
/// derived through the reveal — not a synthetic scalar. Alice commits thimbles and chooses `i*`;
/// Bob guesses `j* = i*` (a win); funding + ChallengeTx put `Q'` on-chain and leak `t`; Bob
/// recovers `t` **from the on-chain witness**, opens `A_{i*}`, confirms the win, computes
/// `dlog(K_b)`, and claims via SettleBobWins. Proofs are AssumeValid; everything else is real.
#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn full_game_bob_wins_capstone() {
    let node = RegtestNode::start().expect("start bitcoind regtest");
    let secp = secp256k1::Secp256k1::new();
    let a = Keypair::new(&secp); // Alice, P_a
    let b = Keypair::new(&secp); // Bob, P_b
    let p_a: Point = a.pk.into();
    let p_b: Point = b.pk.into();

    // --- Alice's commitments (π_a AssumeValid): two thimbles, secret choice i*, blinding t. ---
    let a1 = Scalar::from(Keypair::new(&secp).sk);
    let a2 = Scalar::from(Keypair::new(&secp).sk);
    let i_star = 1usize;
    let thimbles = Thimbles::new(a1, a2, i_star);
    let chosen = thimbles.chosen();
    let t = Scalar::from(Keypair::new(&secp).sk);
    let big_t = t.base_point_mul();
    let x = t * (p_a + chosen.a_point).not_inf().unwrap(); // X = t·(P_a + A_{i*})

    // --- Bob guesses j* = i* (a win) and builds his pot key K_b from H_{j*} (π_r AssumeValid). ---
    let j_star = i_star;
    let h_guessed = thimbles.thimbles[j_star].h_point; // H_{j*} = H_{i*}
    let t_b = Scalar::from(Keypair::new(&secp).sk);
    let x_b = Scalar::from(b.sk);
    let k_b = compute_k_b(&t_b, &p_b, &h_guessed).unwrap();

    // --- Funding + Q'. ---
    let q_fund = TaprootKey::new(a.pk, b.pk).unwrap();
    let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();
    let pot = Amount::from_sat(500_000);
    let q_fund_addr = Address::from_script(&q_fund.spk, Network::Regtest).unwrap();
    let q_fund_outpoint = node.fund_address(&q_fund_addr, pot).unwrap();
    println!("[setup]  Alice i*={i_star}, Bob j*={j_star} (a winning guess); pot {} sat", pot.to_sat());
    println!("[fund]   Q_fund funded at {q_fund_outpoint}");

    // --- ChallengeTx (the reveal): both adaptor-sign on T; both derive the same pre-signature. ---
    let challenge_fee = Amount::from_sat(1_000);
    let mut challenge = build_challenge(q_fund_outpoint, pot, &q_prime, challenge_fee).unwrap();
    let ch_sighash = key_spend_sighash(&challenge, 0, &[q_fund.txout(pot)]).unwrap();
    let (r1a, pna) = q_fund.keyagg.first_round(0, a.sk, seed()).unwrap();
    let (r1b, pnb) = q_fund.keyagg.first_round(1, b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, big_t, ch_sighash).unwrap();
    let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, big_t, ch_sighash).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    let pre_alice = r2a.finalize().unwrap();
    let pre_bob = r2b.finalize().unwrap(); // Bob keeps his copy of the adaptor pre-sig
    assert_eq!(pre_alice, pre_bob);

    // Alice completes with t and broadcasts.
    let final_sig = adapt(&pre_alice, &t).unwrap();
    challenge.input[0].witness = Witness::from_slice(&[signature_bytes(&final_sig).as_slice()]);
    let challenge_txid = node.broadcast(&challenge).expect("ChallengeTx accepted");
    node.mine(1).unwrap();
    println!("[reveal] ChallengeTx confirmed: {challenge_txid} — t is now leaked on-chain");

    // --- Bob recovers t FROM the on-chain tx (he only needs his setup pre-signature). ---
    let onchain = node.client.get_raw_transaction(&challenge_txid, None).unwrap();
    let witness_sig = onchain.input[0].witness.to_vec();
    let sig_bytes: [u8; 64] = witness_sig[0].as_slice().try_into().expect("64-byte keypath sig");
    let lifted = CompactSignature::from_bytes(&sig_bytes).unwrap().lift_nonce().unwrap();
    let t_recovered: Scalar = extract(&pre_bob, &lifted).unwrap().unwrap();
    assert_eq!(t_recovered, t, "Bob recovers t from the broadcast ChallengeTx");
    println!("[reveal] Bob recovered t from the on-chain witness (matches Alice's t) ✓");

    // --- Bob opens A_{i*}, confirms the win, and computes his claim secret dlog(K_b). ---
    let a_opened = open_chosen_thimble(&t_recovered, &x, &p_a).unwrap();
    assert_eq!(a_opened, chosen.a_point);
    let h_win = bob_derive_win_scalar(&a_opened, &h_guessed).expect("Bob won (j* == i*)");
    // Had Bob guessed the other thimble, he'd derive nothing (a loss):
    let other = 1 - i_star;
    assert!(bob_derive_win_scalar(&a_opened, &thimbles.thimbles[other].h_point).is_none());
    let claim = bob_claim_secret(&t_b, &x_b, &h_win).unwrap();
    assert_eq!(claim.base_point_mul(), k_b, "claim secret is exactly dlog(K_b)");
    println!("[win]    Bob opened A_i*, confirmed the win, and computed dlog(K_b) ✓");

    // --- SettleBobWins: both adaptor-sign on K_b; Bob completes with dlog(K_b) and claims. ---
    let q_prime_outpoint = OutPoint { txid: challenge_txid, vout: 0 };
    let q_prime_value = pot - challenge_fee;
    let bob_addr = node.new_address().unwrap();
    let alice_addr = node.new_address().unwrap();
    let winner = TxOut { value: Amount::from_sat(300_000), script_pubkey: bob_addr.script_pubkey() };
    let loser = TxOut { value: Amount::from_sat(198_000), script_pubkey: alice_addr.script_pubkey() };
    let mut settle = build_settlement(q_prime_outpoint, winner, loser, None);
    let st_sighash = key_spend_sighash(&settle, 0, &[q_prime.txout(q_prime_value)]).unwrap();
    let (s1a, spna) = q_prime.keyagg.first_round(0, a.sk, seed()).unwrap();
    let (s1b, spnb) = q_prime.keyagg.first_round(1, b.sk, seed()).unwrap();
    let (mut s2a, spsa) = s1a.sign_adaptor(1, spnb, a.sk, k_b, st_sighash).unwrap();
    let (mut s2b, spsb) = s1b.sign_adaptor(0, spna, b.sk, k_b, st_sighash).unwrap();
    s2a.receive(1, spsb).unwrap();
    s2b.receive(0, spsa).unwrap();
    let settle_pre = s2b.finalize().unwrap();
    let settle_final = adapt(&settle_pre, &claim).unwrap();
    settle.input[0].witness = Witness::from_slice(&[signature_bytes(&settle_final).as_slice()]);

    let settle_txid = node.broadcast(&settle).expect("SettleBobWins accepted");
    node.mine(1).unwrap();
    let confs = node.utxo_confirmations(&OutPoint { txid: settle_txid, vout: 0 }).unwrap().unwrap_or(0);
    assert!(confs >= 1, "Bob's winnings confirmed");
    assert!(
        node.utxo_confirmations(&q_prime_outpoint).unwrap().is_none(),
        "Q' consumed by SettleBobWins"
    );
    println!("[settle] SettleBobWins confirmed: {settle_txid} ({confs} conf) — Bob 300000, Alice 198000; Q' spent ✓");
    println!("[done]   full game settled on-chain");
}
