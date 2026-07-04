//! A single-process **regtest game runner**: spins up a throwaway `bitcoind`, funds the pot
//! (simplified funding), and plays a full v5 game between a Dealer and a Player over an in-memory
//! transport, printing each step. `π_a` runs its Σ-part only (hash conjunct stubbed).
//!
//! ```text
//! cargo run --bin regtest-game            # player wins (y = c) and claims the pot
//! cargo run --bin regtest-game -- --lose  # player loses; dealer reclaims after the timeout
//! ```
//! (Set `BABILONIA_BITCOIND` to a bitcoind path, e.g. the patched build.)

use babilonia::bet::{Bet, BetRole};
use babilonia::game::{play_dealer, play_player, Outcome};
use babilonia::keys::Keypair;
use babilonia::node::Node;
use babilonia::setup::{AliceSecrets, BobSecrets, GameParams};
use babilonia::transport::memory::channel_pair;
use bitcoin::{Amount, Network, OutPoint};
use bitcoincore_rpc::RpcApi;
use musig2::secp::Scalar;
use std::time::Duration;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let lose = std::env::args().any(|a| a == "--lose");
    let secp = secp256k1::Secp256k1::new();
    let scalar = || Scalar::from(Keypair::new(&secp).sk);

    println!("── Babilonia regtest game ──────────────────────────────");
    print!("spinning up bitcoind (regtest)… ");
    let node = Node::regtest()?;
    println!("up (network={:?})", node.network());

    let c = 1usize;
    let y = if lose { 0 } else { 1 }; // player wins iff y == c
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [scalar(), scalar()],
        choice: c,
        d: scalar(),
    };
    let bob = BobSecrets { funding: Keypair::new(&secp), claim: Keypair::new(&secp), guess: y };
    println!(
        "dealer chooses c={c}; player guesses y={y}  →  expecting {}",
        if y == c { "PLAYER wins" } else { "DEALER wins" }
    );

    // Joint PSBT funding: each party gets its own funded wallet; U1 is funded collaboratively
    // during the game (fund_pot), not by the orchestrator.
    let (alice_stake, bob_stake) = (Amount::from_sat(250_000), Amount::from_sat(250_000));
    let alice_wallet = node.create_funded_wallet("alice", Amount::from_sat(100_000_000))?;
    let bob_wallet = node.create_funded_wallet("bob", Amount::from_sat(100_000_000))?;
    println!("funded two wallets (alice, bob); U1 will be jointly funded during play");

    // Steady block production so broadcasts confirm; the game just waits for confirmations.
    node.spawn_miner(Duration::from_millis(400))?;

    let height = node.client.get_block_count()? as u32;
    let params = GameParams {
        u1_outpoint: OutPoint::null(), // filled in by fund_pot (joint PSBT)
        u1_value: Amount::ZERO,        // filled in by fund_pot
        alice_stake,
        bob_stake,
        fee: Amount::from_sat(2_000),
        refund_locktime: height + 100,
        alice_timeout: 6,
    };

    let (dch, pch) = channel_pair();
    let mut dealer = Bet::new(alice_wallet, Network::Regtest, dch, params.clone(), BetRole::Dealer(alice))
        .with_progress(|m| println!("  [dealer] {m}"));
    let mut player = Bet::new(bob_wallet, Network::Regtest, pch, params.clone(), BetRole::Player(bob))
        .with_progress(|m| println!("  [player] {m}"));

    println!("── playing ─────────────────────────────────────────────");
    let ph = std::thread::spawn(move || play_player(&mut player));
    let dealer_outcome = play_dealer(&mut dealer)?;
    let player_outcome = ph.join().unwrap()?;

    println!("── result ──────────────────────────────────────────────");
    println!("dealer sees: {dealer_outcome:?}");
    println!("player sees: {player_outcome:?}");
    if dealer_outcome != player_outcome {
        return Err("dealer and player disagree on the outcome".into());
    }
    match player_outcome {
        Outcome::PlayerWins => println!("🎉 PLAYER won and claimed the pot."),
        Outcome::DealerWins => println!("🏦 DEALER kept the pot (player lost; reclaimed after timeout)."),
    }
    Ok(())
}
