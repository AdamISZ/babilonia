#![cfg(feature = "node")]
//! A full **v5 game** end to end on regtest: the business `game` module (`play_dealer`/
//! `play_player`) drives the node-layer `bet` (which builds/broadcasts the transactions), with
//! **simplified funding** (the orchestrator funds the pot). `π_a` runs Σ-part-only (hash conjunct
//! stubbed). The setup exchange rides an in-memory transport (BIP324 is validated separately).
//!
//! Requires `bitcoind`. Ignored by default. Run:
//!   cargo test --test game -- --ignored --test-threads=1 --nocapture

use babilonia::bet::{Bet, BetRole};
use babilonia::game::{play_dealer, play_player, Outcome};
use babilonia::keys::Keypair;
use babilonia::node::Node;
use babilonia::setup::{AliceSecrets, BobSecrets, GameParams};
use babilonia::transport::memory::channel_pair;
use bitcoin::{Amount, Network, OutPoint};
use bitcoincore_rpc::RpcApi;
use musig2::secp::Scalar;

fn scalar(secp: &secp256k1::Secp256k1<secp256k1::All>) -> Scalar {
    Scalar::from(Keypair::new(secp).sk)
}

/// Player wins (`y = c`): fund → setup (4 flights) → dealer settles (posts `d`) → player decrypts
/// `a_c` and claims via `K`; both sides converge on `PlayerWins`.
#[test]
#[ignore = "requires bitcoind; run with --ignored"]
fn full_game_player_wins_on_regtest() {
    let node = Node::regtest().expect("regtest node");
    let secp = secp256k1::Secp256k1::new();

    let c = 1usize;
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [scalar(&secp), scalar(&secp)],
        choice: c,
        d: scalar(&secp),
    };
    let bob = BobSecrets {
        funding: Keypair::new(&secp),
        claim: Keypair::new(&secp),
        guess: c, // a winning guess
    };

    // Joint PSBT funding: each party has its own funded wallet; U1 is funded collaboratively in
    // fund_pot (both contribute an input, each signs only its own).
    let (alice_stake, bob_stake) = (Amount::from_sat(250_000), Amount::from_sat(250_000));
    let alice_wallet = node.create_funded_wallet("alice", Amount::from_sat(100_000_000)).unwrap();
    let bob_wallet = node.create_funded_wallet("bob", Amount::from_sat(100_000_000)).unwrap();
    node.spawn_miner(std::time::Duration::from_millis(400)).unwrap(); // steady confirmations

    let height = node.client.get_block_count().unwrap() as u32;
    let params = GameParams {
        u1_outpoint: OutPoint::null(), // filled in by fund_pot
        u1_value: Amount::ZERO,        // filled in by fund_pot
        alice_stake,
        bob_stake,
        fee: Amount::from_sat(2_000),
        refund_locktime: height + 100,
        alice_timeout: 6,
        pi_a_scheme: babilonia::pi_a::Scheme::Squaring,
        alice_payout: String::new(), // filled by fund_pot
        bob_payout: String::new(),
    };

    let (dealer_ch, player_ch) = channel_pair();
    let mut dealer = Bet::new(
        node.rpc_wallet(alice_wallet),
        node.rpc_chain().unwrap(),
        Network::Regtest,
        dealer_ch,
        params.clone(),
        BetRole::Dealer(alice),
    );
    let mut player = Bet::new(
        node.rpc_wallet(bob_wallet),
        node.rpc_chain().unwrap(),
        Network::Regtest,
        player_ch,
        params.clone(),
        BetRole::Player(bob),
    );

    // Bob plays on another thread; both talk only through their transport + the shared chain.
    let player_handle = std::thread::spawn(move || play_player(&mut player));
    let dealer_outcome = play_dealer(&mut dealer).expect("dealer plays");
    let player_outcome = player_handle.join().unwrap().expect("player plays");

    assert_eq!(player_outcome, Outcome::PlayerWins, "player observed a win and claimed");
    assert_eq!(dealer_outcome, Outcome::PlayerWins, "dealer saw the pot claimed");
    println!("[ok]   full v5 game: player won and claimed the pot on-chain ✓");
}

/// Dealer wins (`y ≠ c`) via the **cooperative overlay** (COVERT-TX-PLAN §10): the player sees `d`
/// off-chain, realises he lost, and co-signs a single key-path `U1 → Alice` spend. The bet resolves
/// in one tx — the settlement is *never* broadcast and there is no `t_1` wait.
#[test]
#[ignore = "requires bitcoind; run with --ignored"]
fn full_game_dealer_wins_cooperatively_on_regtest() {
    let node = Node::regtest().expect("regtest node");
    let secp = secp256k1::Secp256k1::new();

    let c = 1usize;
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [scalar(&secp), scalar(&secp)],
        choice: c,
        d: scalar(&secp),
    };
    let bob = BobSecrets {
        funding: Keypair::new(&secp),
        claim: Keypair::new(&secp),
        guess: 1 - c, // a losing guess ⇒ dealer wins
    };

    let (alice_stake, bob_stake) = (Amount::from_sat(250_000), Amount::from_sat(250_000));
    let alice_wallet = node.create_funded_wallet("alice_d", Amount::from_sat(100_000_000)).unwrap();
    let bob_wallet = node.create_funded_wallet("bob_d", Amount::from_sat(100_000_000)).unwrap();
    node.spawn_miner(std::time::Duration::from_millis(400)).unwrap();

    let height = node.client.get_block_count().unwrap() as u32;
    let params = GameParams {
        u1_outpoint: OutPoint::null(),
        u1_value: Amount::ZERO,
        alice_stake,
        bob_stake,
        fee: Amount::from_sat(2_000),
        refund_locktime: height + 100,
        alice_timeout: 6,
        pi_a_scheme: babilonia::pi_a::Scheme::Squaring,
        alice_payout: String::new(),
        bob_payout: String::new(),
    };

    let (dealer_ch, player_ch) = channel_pair();
    let mut dealer = Bet::new(
        node.rpc_wallet(alice_wallet),
        node.rpc_chain().unwrap(),
        Network::Regtest,
        dealer_ch,
        params.clone(),
        BetRole::Dealer(alice),
    );
    let mut player = Bet::new(
        node.rpc_wallet(bob_wallet),
        node.rpc_chain().unwrap(),
        Network::Regtest,
        player_ch,
        params.clone(),
        BetRole::Player(bob),
    );

    let player_handle = std::thread::spawn(move || play_player(&mut player));
    let dealer_outcome = play_dealer(&mut dealer).expect("dealer plays");
    let player_outcome = player_handle.join().unwrap().expect("player plays");

    assert_eq!(player_outcome, Outcome::DealerWins, "player conceded a loss");
    assert_eq!(dealer_outcome, Outcome::DealerWins, "dealer resolved cooperatively");

    // Proof it was the cooperative path (not the enforced fallback): `DealerWins` is only returned
    // cooperatively after the U1→Alice tx confirms, and the settlement is never broadcast — so if it
    // isn't on-chain, the enforced settle+reclaim path definitively did not run.
    let chain = node.rpc_chain().unwrap();
    let settle_txid = dealer.settlement_txid().expect("setup complete");
    assert!(chain.get_transaction(settle_txid).unwrap().is_none(), "settlement must never hit the chain");
    println!("[ok]   full v5 game: dealer won cooperatively in one tx — no settlement, no timeout ✓");
}
