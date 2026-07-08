//! `basic-bitcoin-wallet` — a tiny CLI over [`basic_wallet::BasicWallet`]. Connects to a running
//! bitcoind; supports regtest / signet / mainnet.
//!
//! Usage:
//!   basic-bitcoin-wallet [--network regtest|signet|bitcoin] [--datadir <dir>]
//!       --rpc-url <url> (--cookie <path> | --rpc-user <u> --rpc-pass <p>)
//!       <new | receive | balance | utxos | send <addr> <sats> | send-single <addr> <sats>>

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use basic_wallet::BasicWallet;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client};
use bitcoin::{Amount, Network};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (flags, pos) = parse(&args);

    let network = match flags.get("network") {
        Some(s) => Network::from_str(s).map_err(|_| anyhow!("bad --network '{s}'"))?,
        None => Network::Regtest,
    };
    let datadir = flags.get("datadir").map(PathBuf::from).unwrap_or_else(default_datadir);
    let rpc_url = flags.get("rpc-url").context("--rpc-url <url> is required")?;
    let auth = if let Some(cookie) = flags.get("cookie") {
        Auth::CookieFile(PathBuf::from(cookie))
    } else if let (Some(u), Some(p)) = (flags.get("rpc-user"), flags.get("rpc-pass")) {
        Auth::UserPass(u.clone(), p.clone())
    } else {
        bail!("need --cookie <path> or --rpc-user <u> --rpc-pass <p>");
    };
    let client = Client::new(rpc_url, auth).context("connecting to bitcoind")?;

    let cmd = pos.first().map(String::as_str).unwrap_or("");
    match cmd {
        "new" => {
            let (w, m) = BasicWallet::create_new(&datadir, network, client)?;
            println!("mnemonic: {m}");
            println!("network:  {network}");
            println!("address:  {}", w.receive_address());
        }
        "receive" => {
            let w = BasicWallet::load(&datadir, network, client)?;
            println!("{}", w.receive_address());
        }
        "balance" => {
            let w = BasicWallet::load(&datadir, network, client)?;
            println!("{} sat", w.balance().to_sat());
        }
        "utxos" => {
            let w = BasicWallet::load(&datadir, network, client)?;
            for (op, v) in w.list_utxos() {
                println!("{op}  {} sat", v.to_sat());
            }
        }
        "send" | "send-single" => {
            let addr = pos.get(1).context("usage: send <address> <sats>")?;
            let sats: u64 = pos.get(2).context("usage: send <address> <sats>")?.parse()?;
            let w = BasicWallet::load(&datadir, network, client)?;
            let amount = Amount::from_sat(sats);
            let txid = if cmd == "send" {
                w.send(addr, amount)?
            } else {
                w.send_single_utxo(addr, amount)?
            };
            println!("broadcast {txid}");
        }
        _ => bail!("commands: new | receive | balance | utxos | send <addr> <sats> | send-single <addr> <sats>"),
    }
    Ok(())
}

/// Split argv into `--flag value` pairs and positionals (every flag takes a value here).
fn parse(args: &[String]) -> (HashMap<String, String>, Vec<String>) {
    let (mut flags, mut pos) = (HashMap::new(), Vec::new());
    let mut i = 1;
    while i < args.len() {
        if let Some(name) = args[i].strip_prefix("--") {
            flags.insert(name.to_string(), args.get(i + 1).cloned().unwrap_or_default());
            i += 2;
        } else {
            pos.push(args[i].clone());
            i += 1;
        }
    }
    (flags, pos)
}

fn default_datadir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".basic-wallet")
}
