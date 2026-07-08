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
//! **Signet:** `--signet` (needs `--features basic-wallet`) attaches to your already-running
//! (patched) signet `bitcoind` and drives the BDK `basic-wallet` — fund it from a faucet. Regtest is
//! the default and self-contained. The `node` feature is required.
//!
//! ```text
//! # a signet node (patched Core, running + synced), then:
//! babilonia-node --signet --rpc-url http://127.0.0.1:38332 --cookie ~/.bitcoin/signet/.cookie
//! # `receive` → fund that address from a signet faucet → `balance` → `propose`.
//! ```

use std::path::PathBuf;
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
        #[cfg(feature = "basic-wallet")]
        {
            return run_signet(&args);
        }
        #[cfg(not(feature = "basic-wallet"))]
        {
            return Err("signet needs the BDK wallet — rebuild with `--features basic-wallet`".into());
        }
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

/// `$HOME/.babilonia` (falls back to the current dir if `$HOME` is unset).
fn babilonia_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".babilonia")
}

/// `$HOME/.babilonia/config.txt`.
fn default_config_path() -> PathBuf {
    babilonia_dir().join("config.txt")
}

/// Bitcoin Core's default data dir for this platform (used only for the signet cookie default).
#[cfg(feature = "basic-wallet")]
fn default_bitcoin_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(home).join("Library").join("Application Support").join("Bitcoin")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from(home).join(".bitcoin")
    }
}

/// Signet: **attach** to an already-running (patched) signet `bitcoind` and drive the BDK
/// `basic-wallet` (keys in the app; the node is only a chain source + BIP324 transport).
#[cfg(feature = "basic-wallet")]
fn run_signet(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use babilonia::agent::BasicWalletBackend;

    let has = |f: &str| args.iter().any(|a| a == f);
    let rpc_url = flag_value(args, "--rpc-url").unwrap_or_else(|| "http://127.0.0.1:38332".into());
    let cookie = flag_value(args, "--cookie")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_bitcoin_dir().join("signet").join(".cookie"));
    let p2p_port: u16 = flag_value(args, "--p2p-port").and_then(|s| s.parse().ok()).unwrap_or(38333);
    let wallet_dir =
        flag_value(args, "--wallet-dir").map(PathBuf::from).unwrap_or_else(|| babilonia_dir().join("signet-wallet"));

    // Attach to the running node — fail fast if unreachable. No node wallet: keys live in the BDK wallet.
    let node = Node::attach(&rpc_url, cookie.clone(), Network::Signet, p2p_port)?;

    let config_path = flag_value(args, "--config").map(PathBuf::from).unwrap_or_else(default_config_path);
    let mut config = Config::load(&config_path);
    config.network = Network::Signet;
    if has("--auto-accept") {
        config.auto_accept = true;
    }

    println!("── babilonia-node up (signet) ──────────────────────────");
    println!("node:     {rpc_url}   (attached — not managed by babilonia)");
    println!("wallet:   basic-wallet (BDK) · state {}", wallet_dir.display());
    println!("P2P addr: {}   (give this to the peer's `connect`)", node.p2p_addr());
    println!("funding:  run `receive`, send signet coins to it from a faucet, then `balance`");
    println!("config:   {} (stake {}% · auto_accept {})", config_path.display(), config.stake_percent, config.auto_accept);
    println!("────────────────────────────────────────────────────────");

    let backend = Arc::new(BasicWalletBackend::new(rpc_url, cookie, Network::Signet, wallet_dir));
    let (core, cmd_tx, evt_rx) = NodeCore::new(backend, config);
    let core = core.with_config_path(config_path);

    let core_handle = std::thread::spawn(move || core.run());
    let mut ui = Repl::new();
    ui.run(cmd_tx, evt_rx);
    let _ = core_handle.join();
    Ok(())
}
