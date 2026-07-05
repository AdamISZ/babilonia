//! `babilonia-node` — an interactive Babilonia node: a bitcoin node (for the wallet + the BIP324
//! covert transport) driven by the CLI REPL over the node core. Two of these connect by network
//! address and bet.
//!
//! ```text
//! # terminal 1 — the funded, mining node:
//! BABILONIA_BITCOIND=/path/to/patched/bitcoind babilonia-node
//! # it prints its P2P address; fund the other node with `send <addr> <sats>`.
//!
//! # terminal 2 — a joining node (syncs to the first; auto-accepts):
//! BABILONIA_BITCOIND=… babilonia-node --join --auto-accept
//! # then in terminal 2:  connect <addr-from-terminal-1>
//! ```
//! Regtest only for now (signet is a later stage). The `node` feature is required.

use std::sync::Arc;
use std::time::Duration;

use babilonia::agent::{Config, NodeCore, Ui};
use babilonia::node::Node;
use babilonia::repl::Repl;
use bitcoin::Network;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let has = |f: &str| args.iter().any(|a| a == f);

    if has("--signet") {
        return Err("signet support is a later stage; use regtest for now".into());
    }
    let join = has("--join");
    let auto_accept = has("--auto-accept");

    // Spawn the local (patched) bitcoind. The mining/funded node is the default; a `--join` node
    // spawns unfunded and syncs to the peer's chain (so two regtest nodes share one chain).
    eprintln!("spinning up bitcoind (regtest{})…", if join { ", join" } else { ", funded+miner" });
    let node = if join { Node::regtest_unfunded()? } else { Node::regtest()? };
    if !join {
        node.spawn_miner(Duration::from_millis(500))?; // steady confirmations for bets
    }

    // Config: load from `--config <path>` (or ~/.babilonia/config.txt), then apply CLI overrides.
    let config_path = flag_value(&args, "--config").map(std::path::PathBuf::from).unwrap_or_else(default_config_path);
    let mut config = Config::load(&config_path);
    config.network = Network::Regtest;
    if auto_accept {
        config.auto_accept = true;
    }

    println!("── babilonia-node up ───────────────────────────────────");
    println!("network:  regtest");
    println!("P2P addr: {}   (give this to the peer's `connect`)", node.p2p_addr());
    println!("role:     {}", if join { "joining (unfunded, syncs)" } else { "funded + mining" });
    println!("config:   {} (stake {}% · auto_accept {})", config_path.display(), config.stake_percent, config.auto_accept);
    println!("────────────────────────────────────────────────────────");

    let backend = Arc::new(node.agent_backend("bab"));
    let (core, cmd_tx, evt_rx) = NodeCore::new(backend, config);
    let core = core.with_config_path(config_path);

    // Core loop on its own thread; the REPL owns this thread until the user quits.
    let core_handle = std::thread::spawn(move || core.run());

    let mut ui = Repl::new();
    ui.run(cmd_tx, evt_rx);

    let _ = core_handle.join();
    // `node` (owning the bitcoind child) drops here → the node shuts down.
    Ok(())
}

/// Value following `flag` in `args` (e.g. `--config <path>`), if present.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

/// `$HOME/.babilonia/config.txt` (falls back to the current dir if `$HOME` is unset).
fn default_config_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&home).join(".babilonia").join("config.txt")
}
