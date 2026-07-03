#![cfg(feature = "node")] // drives a local bitcoind over RPC; needs the `node` feature
//! End-to-end regtest tests (hash-free design). Fund `Q_fund`, reveal via ChallengeTx's adaptor
//! (secret = the chosen thimble scalar `h_c`), settle `Q'`, all validated by a real `bitcoind`.
//!
//! Requires `bitcoind` (v31) on PATH. Ignored by default so `cargo test` stays hermetic. Run:
//!   cargo test --test regtest_e2e -- --ignored --nocapture

use babilonia::keys::Keypair;
use babilonia::musig::{adapt, signature_bytes, svalue_presig, svalue_reveal, KeyAgg};
use babilonia::regtest::RegtestNode;
use babilonia::reveal::{claim_secret, compute_k, won};
use babilonia::txgraph::{build_challenge, build_settlement, key_spend_sighash, TaprootKey};
use bitcoin::{Address, Amount, Network, OutPoint, TxOut, Witness};
use bitcoincore_rpc::RpcApi;
use musig2::secp::{Point, Scalar};
use musig2::{CompactSignature, LiftedSignature};
use rand::RngCore;

fn seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// ChallengeTx signing under the **s-value adaptor**: a plain 2-party MuSig2 aggregate — neither
/// party references the adaptor point, so **Bob's partial is blind to `H_c`**. Only Alice
/// aggregates the full signature; she binds the adaptor secret afterwards via `svalue_presig`.
fn plain_challenge_sig(
    keyagg: &KeyAgg,
    alice_sk: secp256k1::SecretKey,
    bob_sk: secp256k1::SecretKey,
    msg: [u8; 32],
) -> LiftedSignature {
    let (r1a, pna) = keyagg.first_round(0, alice_sk, seed()).unwrap();
    let (r1b, pnb) = keyagg.first_round(1, bob_sk, seed()).unwrap();
    let (mut r2a, _psa) = r1a.sign(1, pnb, alice_sk, msg).unwrap();
    let (_r2b, psb) = r1b.sign(0, pna, bob_sk, msg).unwrap(); // Bob: plain partial, no H_c
    r2a.receive(1, psb).unwrap();
    r2a.finalize_plain().unwrap()
}

/// State after the game has reached the pot `Q'` on-chain (via a generic reveal, not tied to a
/// specific thimble — the settlement tests exercise the `Q'`-spend paths in isolation).
struct AtPot {
    node: RegtestNode,
    secp: secp256k1::Secp256k1<secp256k1::All>,
    a: Keypair,
    b: Keypair,
    q_prime: TaprootKey,
    q_prime_outpoint: OutPoint,
    q_prime_value: Amount,
}

/// Fund `Q_fund`, broadcast+confirm ChallengeTx (adaptor on some `H_c`), return the live `Q'`.
fn play_to_pot() -> AtPot {
    let node = RegtestNode::start().expect("start bitcoind regtest");
    let secp = secp256k1::Secp256k1::new();
    let a = Keypair::new(&secp);
    let b = Keypair::new(&secp); // Bob's funding key (in Q)

    let q_fund = TaprootKey::new(a.pk, b.pk).unwrap();
    let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();

    let pot = Amount::from_sat(500_000);
    let q_fund_addr = Address::from_script(&q_fund.spk, Network::Regtest).unwrap();
    let q_fund_outpoint = node.fund_address(&q_fund_addr, pot).unwrap();

    let challenge_fee = Amount::from_sat(1_000);
    let mut tx = build_challenge(q_fund_outpoint, pot, &q_prime, challenge_fee).unwrap();
    let sighash = key_spend_sighash(&tx, 0, &[q_fund.txout(pot)]).unwrap();

    // s-value reveal: Bob signs blind; Alice binds the secret h_c after aggregating.
    let full = plain_challenge_sig(&q_fund.keyagg, a.sk, b.sk, sighash);
    let h_c = Scalar::from(Keypair::new(&secp).sk);
    let _pre_s = svalue_presig(&full, &h_c); // Alice's pre-sig for Bob (reveal not checked here)
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&full).as_slice()]);

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

    let q_fund = TaprootKey::new(a.pk, b.pk).unwrap();
    let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();

    let pot = Amount::from_sat(500_000);
    let q_fund_addr = Address::from_script(&q_fund.spk, Network::Regtest).expect("p2tr address");
    let q_fund_outpoint = node.fund_address(&q_fund_addr, pot).expect("fund Q_fund");

    let fee = Amount::from_sat(1_000);
    let mut tx = build_challenge(q_fund_outpoint, pot, &q_prime, fee).unwrap();
    let sighash = key_spend_sighash(&tx, 0, &[q_fund.txout(pot)]).unwrap();

    // s-value adaptor: Bob signs blind (plain), Alice binds h_c afterwards.
    let full = plain_challenge_sig(&q_fund.keyagg, a.sk, b.sk, sighash);
    let h_c = Scalar::from(Keypair::new(&secp).sk);
    let pre_s = svalue_presig(&full, &h_c); // Alice → Bob
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&full).as_slice()]);

    let txid = node.broadcast(&tx).expect("bitcoind accepts ChallengeTx");
    node.mine(1).unwrap();

    let confs = node
        .utxo_confirmations(&OutPoint { txid, vout: 0 })
        .unwrap()
        .expect("Q' is unspent/confirmed");
    assert!(confs >= 1, "Q' confirmed, got {confs} confirmations");
    // Reveal: Bob recovers h_c from the broadcast signature + his pre-sig scalar.
    assert_eq!(svalue_reveal(pre_s, &full).unwrap(), h_c, "s-value reveal recovers h_c");
}

#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn settle_bob_wins_confirms_on_regtest() {
    let g = play_to_pot();

    // Bob's hidden claim key W_b (distinct from his funding key g.b) and the revealed win scalar
    // h_win (= h_c). K = W_b + H_win, dlog(K) = w_b + h_win.
    let w_b = Scalar::from(Keypair::new(&g.secp).sk);
    let h_win = Scalar::from(Keypair::new(&g.secp).sk);
    let k = compute_k(&w_b.base_point_mul(), &h_win.base_point_mul()).unwrap();
    let claim = claim_secret(&w_b, &h_win).unwrap();

    let bob_addr = g.node.new_address().unwrap();
    let alice_addr = g.node.new_address().unwrap();
    let winner = TxOut { value: Amount::from_sat(300_000), script_pubkey: bob_addr.script_pubkey() };
    let loser = TxOut { value: Amount::from_sat(198_000), script_pubkey: alice_addr.script_pubkey() };
    let mut tx = build_settlement(g.q_prime_outpoint, winner, loser, None);
    let sighash = key_spend_sighash(&tx, 0, &[g.q_prime.txout(g.q_prime_value)]).unwrap();

    // Both adaptor-sign on K; Bob completes with dlog(K).
    let (r1a, pna) = g.q_prime.keyagg.first_round(0, g.a.sk, seed()).unwrap();
    let (r1b, pnb) = g.q_prime.keyagg.first_round(1, g.b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, g.a.sk, k, sighash).unwrap();
    let (mut r2b, psb) = r1b.sign_adaptor(0, pna, g.b.sk, k, sighash).unwrap();
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

    let (r1a, pna) = g.q_prime.keyagg.first_round(0, g.a.sk, seed()).unwrap();
    let (r1b, pnb) = g.q_prime.keyagg.first_round(1, g.b.sk, seed()).unwrap();
    let (mut r2a, psa) = r1a.sign(1, pnb, g.a.sk, sighash).unwrap();
    let (mut r2b, psb) = r1b.sign(0, pna, g.b.sk, sighash).unwrap();
    r2a.receive(1, psb).unwrap();
    r2b.receive(0, psa).unwrap();
    let final_sig = r2a.finalize_plain().unwrap();
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&final_sig).as_slice()]);

    assert!(
        g.node.broadcast(&tx).is_err(),
        "SettleAliceWins must be rejected before the relative timelock matures"
    );
    g.node.mine(2).unwrap();
    let txid = g.node.broadcast(&tx).expect("SettleAliceWins accepted after N blocks");
    g.node.mine(1).unwrap();
    assert!(
        g.node.utxo_confirmations(&OutPoint { txid, vout: 0 }).unwrap().unwrap_or(0) >= 1,
        "settlement output confirmed"
    );
}

/// Capstone: the whole hash-free game end to end on a real node. Alice commits thimbles and
/// chooses `c`; Bob guesses `y = c` (a win) and commits `K = W_b + H_y`; ChallengeTx's adaptor
/// (secret = the chosen thimble scalar `h_c`) reveals on broadcast; Bob recovers `h_c` **from the
/// on-chain witness**, confirms `H_c = H_y`, computes `dlog(K) = w_b + h_c`, and claims via
/// SettleBobWins. Proofs AssumeValid; everything else real.
#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn full_game_bob_wins_capstone() {
    let node = RegtestNode::start().expect("start bitcoind regtest");
    let secp = secp256k1::Secp256k1::new();
    let a = Keypair::new(&secp); // Alice P_a
    let b = Keypair::new(&secp); // Bob funding key P_b (in Q)
    let w = Keypair::new(&secp); // Bob hidden claim key W_b (in K)

    // Alice's thimbles + choice c; the chosen thimble scalar h_c IS the reveal secret.
    let c = 1usize;
    let thimbles = [
        Scalar::from(Keypair::new(&secp).sk),
        Scalar::from(Keypair::new(&secp).sk),
    ];
    let h_c = thimbles[c];

    // Bob guesses y = c (a win) and forms K = W_b + H_y.
    let y = c;
    let h_guessed = thimbles[y].base_point_mul(); // H_y = H_c
    let w_b: Scalar = w.sk.into();
    let w_b_point: Point = w.pk.into();
    let k = compute_k(&w_b_point, &h_guessed).unwrap();

    // Funding + Q'.
    let q_fund = TaprootKey::new(a.pk, b.pk).unwrap();
    let q_prime = TaprootKey::new(a.pk, b.pk).unwrap();
    let pot = Amount::from_sat(500_000);
    let q_fund_addr = Address::from_script(&q_fund.spk, Network::Regtest).unwrap();
    let q_fund_outpoint = node.fund_address(&q_fund_addr, pot).unwrap();
    println!("[setup]  Alice c={c}, Bob y={y} (a winning guess); pot {} sat", pot.to_sat());
    println!("[fund]   Q_fund funded at {q_fund_outpoint}");

    // ChallengeTx via the s-value adaptor: Bob signs his partial PLAIN (blind to H_c); Alice
    // aggregates the full signature and only then binds the reveal secret h_c (= chosen thimble
    // scalar). This is the Bob-commits-first ordering in the crypto.
    let challenge_fee = Amount::from_sat(1_000);
    let mut challenge = build_challenge(q_fund_outpoint, pot, &q_prime, challenge_fee).unwrap();
    let ch_sighash = key_spend_sighash(&challenge, 0, &[q_fund.txout(pot)]).unwrap();
    let full = plain_challenge_sig(&q_fund.keyagg, a.sk, b.sk, ch_sighash);
    let pre_s = svalue_presig(&full, &h_c); // Alice → Bob (Bob never saw H_c to sign)
    challenge.input[0].witness = Witness::from_slice(&[signature_bytes(&full).as_slice()]);
    let challenge_txid = node.broadcast(&challenge).expect("ChallengeTx accepted");
    node.mine(1).unwrap();
    println!("[reveal] ChallengeTx confirmed: {challenge_txid} — Bob signed blind; h_c now on-chain");

    // Bob recovers h_c FROM the on-chain tx (needs only Alice's pre-sig scalar).
    let onchain = node.client.get_raw_transaction(&challenge_txid, None).unwrap();
    let witness_sig = onchain.input[0].witness.to_vec();
    let sig_bytes: [u8; 64] = witness_sig[0].as_slice().try_into().expect("64-byte keypath sig");
    let lifted = CompactSignature::from_bytes(&sig_bytes).unwrap().lift_nonce().unwrap();
    let h_recovered: Scalar = svalue_reveal(pre_s, &lifted).unwrap();
    assert_eq!(h_recovered, h_c, "Bob recovers h_c from the broadcast ChallengeTx");
    println!("[reveal] Bob recovered h_c from the on-chain witness ✓");

    // Bob confirms the win and computes his claim secret dlog(K) = w_b + h_c.
    assert!(won(&h_recovered, &h_guessed), "Bob won (y == c)");
    let other = 1 - c;
    assert!(!won(&h_recovered, &thimbles[other].base_point_mul()), "the other thimble loses");
    let claim = claim_secret(&w_b, &h_recovered).unwrap();
    assert_eq!(claim.base_point_mul(), k, "claim secret is exactly dlog(K)");
    println!("[win]    Bob confirmed the win and computed dlog(K) ✓");

    // SettleBobWins: both adaptor-sign on K; Bob completes with dlog(K).
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
    let (mut s2a, spsa) = s1a.sign_adaptor(1, spnb, a.sk, k, st_sighash).unwrap();
    let (mut s2b, spsb) = s1b.sign_adaptor(0, spna, b.sk, k, st_sighash).unwrap();
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
