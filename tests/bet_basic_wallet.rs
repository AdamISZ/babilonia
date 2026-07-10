#![cfg(all(feature = "node", feature = "basic-wallet"))]
//! A full bet on regtest with the **reference BDK wallet** (`basic-wallet`) as the [`Wallet`] backend
//! — the rewire proof. This exercises the joint-funding PSBT path through BDK: each side builds the
//! same 2-input tx (its own UTXO + the counterparty's as a *foreign* UTXO), signs only its own
//! input, and the two partials are combined and finalised into `TX1`.
//!
//! Requires `bitcoind`. Ignored by default. Run:
//!   cargo test --features basic-wallet --test bet_basic_wallet -- --ignored --test-threads=1 --nocapture

use std::str::FromStr;
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
        alice_payout: String::new(), // filled by fund_pot
        bob_payout: String::new(),
    };

    let refund_dir = std::env::temp_dir().join(format!("bw-refund-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&refund_dir);

    let (dealer_ch, player_ch) = channel_pair();
    let mut dealer = Bet::new(
        Box::new(alice_w),
        node.rpc_chain().unwrap(),
        Network::Regtest,
        dealer_ch,
        params.clone(),
        BetRole::Dealer(alice),
    )
    .with_state_dir(refund_dir.clone());
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

    // On disk: the human-readable broadcastable refund + the full crash-recovery record.
    let dir: Vec<_> = std::fs::read_dir(&refund_dir).expect("state dir").filter_map(|e| e.ok()).collect();
    let refund_txt = dir.iter().find(|e| e.file_name().to_string_lossy().starts_with("refund-")).expect("refund-*.txt");
    let json = dir.iter().find(|e| e.file_name().to_string_lossy().ends_with(".json")).expect("<id>.json record");

    let content = std::fs::read_to_string(refund_txt.path()).unwrap();
    let hex = content.lines().find_map(|l| l.strip_prefix("refund_tx: ")).expect("refund_tx line").trim();
    let refund: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(hex).expect("valid refund tx");
    assert_eq!(refund.input.len(), 1, "refund spends the single U1 output");
    assert!(!refund.input[0].witness.is_empty(), "refund is fully signed (witnessed)");
    assert_eq!(refund.output.len(), 2, "refund returns stakes to both funders");

    // The record round-trips through disk and carries the state to rebuild that refund after a crash.
    let rec = babilonia::persist::BetRecord::load(&json.path()).expect("load record");
    assert_eq!(rec.phase, babilonia::persist::Phase::Done, "dealer bet persisted through to Done");
    assert!(rec.funding_tx.is_some(), "funding tx persisted");
    let setup = rec.setup.expect("setup persisted in record");
    assert_eq!(setup.refund_tx.compute_txid(), refund.compute_txid(), "record's refund matches the broadcastable one");

    // Covert shapes (COVERT-TX-PLAN §8): funding is a 2-out payjoin, and the settlement is a 2-out
    // payment — `O_K = S` (the at-risk pot) + Alice's parked change `c_A_out → alice_payout`.
    let funding = rec.funding_tx.as_ref().expect("funding tx");
    assert_eq!(funding.output.len(), 2, "funding is a 2-out payjoin (U1 + Bob's change)");
    let s = params.alice_stake + params.bob_stake; // O_K carries exactly S
    assert_eq!(setup.settle_tx.output.len(), 2, "settlement is a 2-out payment (O_K + parked c_A)");
    let o_k = setup.settle_tx.output.iter().filter(|o| o.value == s).count();
    assert_eq!(o_k, 1, "settlement's O_K output pays exactly S = a + b");
    let alice_spk = bitcoin::Address::from_str(&rec.params.alice_payout)
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let c_a = setup.settle_tx.output.iter().find(|o| o.script_pubkey == alice_spk).expect("c_A output → alice_payout");
    assert!(c_a.value > Amount::ZERO, "Alice's parked change returns to her payout address");

    // The settlement's outputs are order-randomized (§9): O_K sits at whichever vout the shuffle put it.
    let o_k_vout = setup.settle_tx.output.iter().position(|o| o.value == s).unwrap() as u32;

    // Phase 1b: the enforced Alice-win reclaim was pre-signed at setup, persisted, 2-out, and spends O_K.
    let reclaim = setup.reclaim_tx.as_ref().expect("dealer pre-signed reclaim persisted");
    assert_eq!(reclaim.output.len(), 2, "reclaim is a 2-out payment");
    assert!(!reclaim.input[0].witness.is_empty(), "reclaim is fully witnessed (script-path)");
    assert_eq!(
        reclaim.input[0].previous_output,
        OutPoint { txid: setup.settle_tx.compute_txid(), vout: o_k_vout },
        "reclaim spends O_K (located by scriptPubKey, any vout)"
    );
    let _ = std::fs::remove_dir_all(&refund_dir);

    println!("[ok] full bet with basic-wallet (BDK) — joint funding + broadcastable refund + round-tripped recovery record ✓");
}
