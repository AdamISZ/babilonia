#![cfg(all(feature = "node", feature = "basic-wallet"))]
//! A full bet on regtest with the **reference BDK wallet** (`basic-wallet`) as the [`Wallet`] backend
//! — the rewire proof. This exercises the joint-funding PSBT path through BDK: each side builds the
//! same 2-input tx (its own UTXO + the counterparty's as a *foreign* UTXO), signs only its own
//! input, and the two partials are combined and finalised into `TX1`.
//!
//! Requires `bitcoind`. Ignored by default. Run:
//!   cargo test --features basic-wallet --test bet_basic_wallet -- --ignored --test-threads=1 --nocapture

use std::time::Duration;

use babilonia::bet::{Bet, BetRole};
use babilonia::game::{play_dealer, play_player, Outcome};
use babilonia::keys::Keypair;
use babilonia::node::Node;
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
fn full_bet_with_basic_wallet_player_wins() {
    let node = Node::regtest().expect("regtest node");

    // Two independent BasicWallets on this node, funded from the node's coinbase wallet.
    let dir = |who: &str| std::env::temp_dir().join(format!("bw-{who}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(dir("alice"));
    let _ = std::fs::remove_dir_all(dir("bob"));
    let (alice_w, _) =
        BasicWallet::create_new_at(&dir("alice"), Network::Regtest, node.rpc_url(), node.cookie()).unwrap();
    let (bob_w, _) =
        BasicWallet::create_new_at(&dir("bob"), Network::Regtest, node.rpc_url(), node.cookie()).unwrap();

    let send = |addr: &bitcoin::Address, sats: u64| {
        node.client
            .send_to_address(addr, Amount::from_sat(sats), None, None, None, None, None, None)
            .unwrap();
    };
    send(&alice_w.receive_address(), 100_000_000);
    send(&bob_w.receive_address(), 100_000_000);
    let mineaddr = node.new_address().unwrap();
    node.client.generate_to_address(1, &mineaddr).unwrap();
    alice_w.sync().unwrap();
    bob_w.sync().unwrap();
    assert_eq!(alice_w.balance().to_sat(), 100_000_000, "alice funded");
    assert_eq!(bob_w.balance().to_sat(), 100_000_000, "bob funded");

    node.spawn_miner(Duration::from_millis(400)).unwrap(); // steady confirmations for the bet

    let secp = secp256k1::Secp256k1::new();
    let c = 1usize;
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [scalar(&secp), scalar(&secp)],
        choice: c,
        d: scalar(&secp),
    };
    let bob = BobSecrets { funding: Keypair::new(&secp), claim: Keypair::new(&secp), guess: c };

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
    let mut dealer = Bet::new(
        Box::new(alice_w),
        node.rpc_chain().unwrap(),
        Network::Regtest,
        dealer_ch,
        params.clone(),
        BetRole::Dealer(alice),
    );
    let mut player = Bet::new(
        Box::new(bob_w),
        node.rpc_chain().unwrap(),
        Network::Regtest,
        player_ch,
        params.clone(),
        BetRole::Player(bob),
    );

    let player_handle = std::thread::spawn(move || play_player(&mut player));
    let dealer_res = play_dealer(&mut dealer);
    let player_res = player_handle.join().unwrap();
    println!("dealer result: {dealer_res:?}");
    println!("player result: {player_res:?}");

    assert_eq!(player_res.unwrap(), Outcome::PlayerWins);
    assert_eq!(dealer_res.unwrap(), Outcome::PlayerWins);
    println!("[ok] full bet with basic-wallet (BDK) — joint PSBT funding worked; player won ✓");
}
