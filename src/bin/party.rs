//! **Two-window game runner.** Each process runs ONE party against its OWN `bitcoind`, and the two
//! nodes carry the game's setup messages over the real **BIP324 covert channel** (decoy packets).
//! Requires the PATCHED bitcoind (senddecoy/getdecoys) — set `BABILONIA_BITCOIND`.
//!
//! Window 1 — the dealer (also the sole block producer):
//! ```text
//! BABILONIA_BITCOIND=/path/to/patched/bitcoind cargo run --bin party -- --role dealer
//! ```
//! It prints its P2P address; copy that into window 2.
//!
//! Window 2 — the player:
//! ```text
//! BABILONIA_BITCOIND=/path/to/patched/bitcoind cargo run --bin party -- --role player --connect <addr> [--guess 0|1]
//! ```
//! The dealer chooses `c = 1`; the player wins iff `--guess 1` (the default).

use std::error::Error;
use std::str::FromStr;
use std::time::{Duration, Instant};

use babilonia::bet::{Bet, BetRole};
use babilonia::game::{play_dealer, play_player};
use babilonia::keys::Keypair;
use babilonia::node::Node;
use babilonia::setup::{AliceSecrets, BobSecrets, GameParams};
use babilonia::transport::bip324::Bip324Transport;
use babilonia::transport::Transport;
use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoincore_rpc::RpcApi;
use musig2::secp::Scalar;
use secp256k1::Secp256k1;

const STAKE_SAT: u64 = 250_000;
const FEE_SAT: u64 = 2_000;
// A fixed absolute refund height, agreed out-of-band, so both sign the identical refund tx.
const REFUND_LOCKTIME: u32 = 50_000;
const ALICE_TIMEOUT: u16 = 6;

fn params() -> GameParams {
    GameParams {
        u1_outpoint: OutPoint::null(), // filled in by fund_pot (joint PSBT)
        u1_value: Amount::ZERO,
        alice_stake: Amount::from_sat(STAKE_SAT),
        bob_stake: Amount::from_sat(STAKE_SAT),
        fee: Amount::from_sat(FEE_SAT),
        refund_locktime: REFUND_LOCKTIME,
        alice_timeout: ALICE_TIMEOUT,
        pi_a_scheme: babilonia::pi_a::Scheme::Squaring,
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone());
    let role = flag("--role").ok_or("need --role dealer|player")?;
    match role.as_str() {
        "dealer" => run_dealer(Node::regtest()?),
        "player" => {
            let connect = flag("--connect").ok_or("player needs --connect <dealer P2P addr>")?;
            let guess: usize = flag("--guess").and_then(|s| s.parse().ok()).unwrap_or(1);
            // The second node spawns UNFUNDED so it syncs to the dealer's chain instead of forking.
            run_player(Node::regtest_unfunded()?, connect, guess)
        }
        other => Err(format!("unknown role {other:?} (want dealer|player)").into()),
    }
}

fn run_dealer(node: Node) -> Result<(), Box<dyn Error>> {
    println!("── Babilonia — DEALER ──────────────────────────────────");
    println!("[dealer] node up. P2P address: {}", node.p2p_addr());
    println!("[dealer] in another window run:");
    println!("           cargo run --bin party -- --role player --connect {}", node.p2p_addr());
    println!("[dealer] waiting for the player to connect over BIP324 v2…");
    if !node.wait_for_v2_peers(1, Duration::from_secs(300))? {
        return Err("player did not connect within 5 min".into());
    }
    let peer_id = node.only_peer_id()?;
    println!("[dealer] player connected (peer id {peer_id}); covert channel up ✓");

    // The dealer is the sole miner — steady block production for the shared chain.
    node.spawn_miner(Duration::from_millis(500))?;

    let mut transport = Bip324Transport::new(node.new_rpc_client()?, peer_id);

    // Pre-fund the player's wallet (it spawned unfunded): receive its address, send it coins.
    let player_addr = String::from_utf8(transport.recv()?)?;
    println!("[dealer] funding the player's wallet at {}", player_addr.trim());
    let addr = Address::from_str(player_addr.trim())?
        .require_network(Network::Regtest)
        .map_err(|_| "player address network mismatch")?;
    let txid = node.client.send_to_address(&addr, Amount::from_sat(STAKE_SAT * 8), None, None, None, None, None, None)?;
    // Wait for it to confirm — this matures the player's output AND our own change (which we just
    // created by spending our only mature coinbase), so our fund_pot can select an input.
    println!("[dealer] funding tx {txid}; waiting for confirmation…");
    wait_tx_confirmed(&node, txid)?;
    transport.send(b"funded")?;

    // Dealer secrets — chooses c = 1.
    let secp = Secp256k1::new();
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [Scalar::from(Keypair::new(&secp).sk), Scalar::from(Keypair::new(&secp).sk)],
        choice: 1,
        d: Scalar::from(Keypair::new(&secp).sk),
    };
    let mut dealer = Bet::new(node.rpc_wallet(node.wallet_client()?), node.rpc_chain()?, Network::Regtest, transport, params(), BetRole::Dealer(alice))
        .with_progress(|m| println!("  [dealer] {m}"));

    println!("── playing over BIP324 ─────────────────────────────────");
    let outcome = play_dealer(&mut dealer)?;
    println!("── result ──────────────────────────────────────────────");
    println!("[dealer] RESULT: {outcome:?}");
    Ok(())
}

fn run_player(node: Node, connect: String, guess: usize) -> Result<(), Box<dyn Error>> {
    println!("── Babilonia — PLAYER ──────────────────────────────────");
    println!("[player] connecting to dealer at {connect}…");
    node.connect_to_addr(&connect)?;
    if !node.wait_for_v2_peers(1, Duration::from_secs(120))? {
        return Err("could not peer with the dealer".into());
    }
    let peer_id = node.only_peer_id()?;
    println!("[player] peered with the dealer (peer id {peer_id}); covert channel up ✓");

    let mut transport = Bip324Transport::new(node.new_rpc_client()?, peer_id);

    // Ask the dealer to fund our wallet; wait for the coins to sync + confirm.
    let addr = node.new_address()?;
    println!("[player] requesting wallet funding at {addr}");
    transport.send(addr.to_string().as_bytes())?;
    let _ack = transport.recv()?;
    println!("[player] waiting for funding to confirm…");
    wait_for_utxo(&node, Amount::from_sat(STAKE_SAT))?;
    println!("[player] wallet funded ✓");

    let secp = Secp256k1::new();
    let bob = BobSecrets { funding: Keypair::new(&secp), claim: Keypair::new(&secp), guess };
    let mut player = Bet::new(node.rpc_wallet(node.wallet_client()?), node.rpc_chain()?, Network::Regtest, transport, params(), BetRole::Player(bob))
        .with_progress(|m| println!("  [player] {m}"));

    println!("── playing over BIP324 (guess y={guess}) ────────────────");
    let outcome = play_player(&mut player)?;
    println!("── result ──────────────────────────────────────────────");
    println!("[player] RESULT: {outcome:?}");
    Ok(())
}

/// Wait until `txid` has at least one confirmation on this node.
fn wait_tx_confirmed(node: &Node, txid: bitcoin::Txid) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(info) = node.client.get_raw_transaction_info(&txid, None) {
            if info.confirmations.unwrap_or(0) >= 1 {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            return Err("dealer funding did not confirm".into());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Wait until the wallet has a confirmed UTXO of at least `need` (the dealer's funding, synced in).
fn wait_for_utxo(node: &Node, need: Amount) -> Result<(), Box<dyn Error>> {
    let client = node.wallet_client()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let utxos = client.list_unspent(Some(1), None, None, None, None)?;
        if utxos.iter().any(|u| u.amount >= need) {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err("funding did not arrive within 2 min".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
