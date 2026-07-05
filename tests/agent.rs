#![cfg(feature = "node")]
//! Headless node-core test: two [`NodeCore`]s, connected by an in-memory transport and backed by a
//! shared regtest `bitcoind`, play a full bet driven **only** through the `Command`/`Event` API — no
//! UI, no direct protocol calls. Proves the actor core orchestrates funding → setup → settle → claim
//! and that both sides converge on the same outcome.
//!
//! Requires `bitcoind`. Ignored by default:
//!   cargo test --test agent -- --ignored --test-threads=1 --nocapture

use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use babilonia::agent::{Command, Config, Event, NodeCore};
use babilonia::node::Node;
use babilonia::transport::memory::channel_pair;
use bitcoin::{Amount, Network};

/// Drain `events`, forwarding each to `label` output, until an `Outcome` arrives or we time out.
fn wait_outcome(label: &str, events: &Receiver<Event>, deadline: Instant) -> Option<String> {
    while Instant::now() < deadline {
        match events.recv_timeout(Duration::from_millis(500)) {
            Ok(Event::Outcome { msg }) => {
                println!("[{label}] OUTCOME: {msg}");
                return Some(msg);
            }
            Ok(Event::Progress { msg }) => println!("[{label}] {msg}"),
            Ok(Event::Info { msg }) => println!("[{label}] info: {msg}"),
            Ok(Event::Error { msg }) => println!("[{label}] ERROR: {msg}"),
            Ok(other) => println!("[{label}] {other:?}"),
            Err(_) => {}
        }
    }
    None
}

#[test]
#[ignore = "requires bitcoind; run with --ignored"]
fn two_cores_play_a_bet_over_commands() {
    let node = Node::regtest().expect("regtest node");
    node.create_funded_wallet("alice", Amount::from_sat(100_000_000)).unwrap();
    node.create_funded_wallet("bob", Amount::from_sat(100_000_000)).unwrap();
    node.spawn_miner(Duration::from_millis(400)).unwrap(); // steady confirmations

    // The two cores share one node (distinct wallets); their peer channel is in-memory.
    let (end_a, end_b) = channel_pair();
    let cfg = |auto| Config { network: Network::Regtest, auto_accept: auto, ..Config::default() };

    let backend_a = Arc::new(node.agent_backend("alice"));
    let (core_a, cmd_a, evt_a) = NodeCore::new(backend_a, cfg(false));
    let core_a = core_a.with_seeded_peer("bob", Box::new(end_a));

    let backend_b = Arc::new(node.agent_backend("bob"));
    let (core_b, _cmd_b, evt_b) = NodeCore::new(backend_b, cfg(true)); // acceptor auto-accepts
    let core_b = core_b.with_seeded_peer("alice", Box::new(end_b));

    let ha = std::thread::spawn(move || core_a.run());
    let hb = std::thread::spawn(move || core_b.run());

    // Alice (proposer/dealer) initiates the bet; Bob (auto-accept/player) picks it up.
    cmd_a.send(Command::Propose).unwrap();

    let deadline = Instant::now() + Duration::from_secs(90);
    let out_a = wait_outcome("alice", &evt_a, deadline);
    let out_b = wait_outcome("bob", &evt_b, deadline);

    // Shut the cores down.
    let _ = cmd_a.send(Command::Quit);
    let _ = _cmd_b.send(Command::Quit);
    let _ = ha.join();
    let _ = hb.join();

    let (out_a, out_b) = (out_a.expect("alice reached an outcome"), out_b.expect("bob reached an outcome"));
    assert_eq!(out_a, out_b, "dealer and player agree on the outcome");
    println!("[ok] two cores played a bet over the Command/Event API → {out_a}");
}
