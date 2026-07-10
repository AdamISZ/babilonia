#![cfg(all(feature = "node", feature = "basic-wallet"))]
//! Crash **recovery** end to end: a player runs funding + setup, then "crashes" before observing —
//! the dealer settles (posting `d`) — and we recover the player purely from its on-disk record,
//! extracting `d` and claiming the win with no live peer. This is the payoff of the persistence work.
//!
//! Requires `bitcoind`. Ignored by default. Run:
//!   cargo test --features basic-wallet --test recover -- --ignored --test-threads=1 --nocapture

use std::time::Duration;

use babilonia::bet::{Bet, BetRole};
use babilonia::game::BetChain;
use babilonia::keys::Keypair;
use babilonia::node::Node;
use babilonia::persist::{BetRecord, Phase};
use babilonia::setup::{AliceSecrets, BobSecrets, GameParams};
use babilonia::transport::memory::channel_pair;
use basic_wallet::BasicWallet;
use bitcoin::{Amount, Network, OutPoint};
use bitcoincore_rpc::RpcApi;
use musig2::secp::Scalar;

fn scalar(secp: &secp256k1::Secp256k1<secp256k1::All>) -> Scalar {
    Scalar::from(Keypair::new(secp).sk)
}

#[test]
#[ignore = "requires bitcoind; run with --ignored"]
fn player_recovers_a_win_after_crash() {
    let node = Node::regtest().expect("regtest node");
    let dir = |w: &str| std::env::temp_dir().join(format!("rec-{w}-{}", std::process::id()));
    for w in ["alice", "bob", "state-d", "state-p", "recov"] {
        let _ = std::fs::remove_dir_all(dir(w));
    }
    let mk = |w: &str| BasicWallet::create_new_at(&dir(w), Network::Regtest, node.rpc_url(), node.cookie()).unwrap().0;
    let (alice_w, bob_w) = (mk("alice"), mk("bob"));

    let send = |a: &bitcoin::Address, s: u64| {
        node.client.send_to_address(a, Amount::from_sat(s), None, None, None, None, None, None).unwrap();
    };
    send(&alice_w.receive_address(), 100_000_000);
    send(&bob_w.receive_address(), 100_000_000);
    let mineaddr = node.new_address().unwrap();
    node.client.generate_to_address(1, &mineaddr).unwrap();
    alice_w.sync().unwrap();
    bob_w.sync().unwrap();
    node.spawn_miner(Duration::from_millis(400)).unwrap();

    let secp = secp256k1::Secp256k1::new();
    let c = 1usize;
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [scalar(&secp), scalar(&secp)],
        choice: c,
        d: scalar(&secp),
    };
    let bob = BobSecrets { funding: Keypair::new(&secp), claim: Keypair::new(&secp), guess: c }; // wins

    let height = node.client.get_block_count().unwrap() as u32;
    let params = GameParams {
        u1_outpoint: OutPoint::null(),
        u1_value: Amount::ZERO,
        alice_stake: Amount::from_sat(250_000),
        bob_stake: Amount::from_sat(250_000),
        fee: Amount::from_sat(2_000),
        refund_locktime: height + 100,
        alice_timeout: 6,
        pi_a_scheme: babilonia::pi_a::Scheme::Squaring,
    };

    let (dealer_ch, player_ch) = channel_pair();
    let mut dealer = Bet::new(Box::new(alice_w), node.rpc_chain().unwrap(), Network::Regtest, dealer_ch, params.clone(), BetRole::Dealer(alice))
        .with_state_dir(dir("state-d"));
    let mut player = Bet::new(Box::new(bob_w), node.rpc_chain().unwrap(), Network::Regtest, player_ch, params.clone(), BetRole::Player(bob))
        .with_state_dir(dir("state-p"));

    // Player runs funding + setup, then STOPS before observing — the crash.
    let ph = std::thread::spawn(move || -> Result<(), babilonia::Error> {
        player.fund_pot()?;
        player.setup()?;
        player.broadcast_funding()?;
        Ok(())
    });
    // Dealer settles (posts d on-chain), so the player *could* have claimed — but it crashed.
    dealer.fund_pot().unwrap();
    dealer.setup().unwrap();
    dealer.broadcast_funding().unwrap();
    dealer.settle().unwrap();
    ph.join().unwrap().expect("player ran through funding");

    // Recover the player from disk alone — no peer, no in-memory state.
    let rec_path = std::fs::read_dir(dir("state-p"))
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .expect("player record on disk")
        .path();
    let rec = BetRecord::load(&rec_path).expect("load player record");
    assert_eq!(rec.phase, Phase::FundingBroadcast, "player crashed right after funding");
    let settle_txid = rec.setup.as_ref().unwrap().settle_tx.compute_txid();

    let recov_wallet = mk("recov");
    let chain = node.rpc_chain().unwrap();
    let msg = babilonia::recover::recover(&rec, &*chain, &recov_wallet).expect("recovery claims the win");
    println!("recovery: {msg}");

    // The claim landed: the settlement's claim output is now spent.
    node.client.generate_to_address(1, &mineaddr).unwrap();
    let claim_out = OutPoint { txid: settle_txid, vout: 0 };
    assert!(!chain.utxo_unspent(claim_out).unwrap(), "claim output spent by the recovered claim");
    println!("[ok] player recovered a win from its record alone — extracted d and claimed ✓");
}
