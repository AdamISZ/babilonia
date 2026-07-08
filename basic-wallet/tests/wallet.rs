//! Wallet-functionality tests for `basic-wallet`, exercised against a throwaway regtest `bitcoind`.
//! (No babilonia dependency — this crate is standalone.)
//!
//! Requires a `bitcoind` (via `$BABILONIA_BITCOIND` or on `PATH`). Ignored by default:
//!   cargo test -p basic-wallet -- --ignored --test-threads=1 --nocapture

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use basic_wallet::BasicWallet;
use bdk_bitcoind_rpc::bitcoincore_rpc::json::AddressType;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{Address, Amount, Network};

static SEQ: AtomicU32 = AtomicU32::new(0);

/// A throwaway regtest `bitcoind` we own — killed and cleaned up on drop.
struct Regtest {
    child: Child,
    datadir: PathBuf,
    port: u16,
}

impl Regtest {
    fn start() -> Self {
        let bin = std::env::var("BABILONIA_BITCOIND").unwrap_or_else(|_| "bitcoind".into());
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let datadir = std::env::temp_dir().join(format!("bw-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&datadir).unwrap();
        let port = free_port();
        let child = Command::new(&bin)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={port}"))
            .arg("-txindex=1") // create_psbt fetches counterparty prevtxs by txid
            .arg("-fallbackfee=0.0002")
            .arg("-server=1")
            .arg("-daemon=0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn bitcoind");

        let node = Regtest { child, datadir, port };
        // Wait for RPC readiness.
        for _ in 0..80 {
            if let Ok(c) = node.try_client("") {
                if c.get_blockchain_info().is_ok() {
                    return node;
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("bitcoind did not become ready");
    }

    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
    fn cookie(&self) -> PathBuf {
        self.datadir.join("regtest").join(".cookie")
    }
    fn try_client(&self, path: &str) -> Result<Client, bdk_bitcoind_rpc::bitcoincore_rpc::Error> {
        Client::new(&format!("{}{path}", self.rpc_url()), Auth::CookieFile(self.cookie()))
    }
    fn client(&self) -> Client {
        self.try_client("").unwrap()
    }
    fn miner(&self) -> Client {
        self.try_client("/wallet/miner").unwrap()
    }

    /// Create the coinbase wallet and mine it to maturity; returns a spendable miner address.
    fn init_funds(&self) -> Address {
        self.client().create_wallet("miner", None, None, None, None).unwrap();
        let addr = self.miner().get_new_address(None, None).unwrap().assume_checked();
        self.client().generate_to_address(101, &addr).unwrap();
        addr
    }

    /// Fund `wallet` with `sats` from the miner wallet, mine it in, and sync.
    fn fund(&self, wallet: &BasicWallet, sats: u64, mine_to: &Address) {
        self.miner()
            .send_to_address(&wallet.receive_address(), Amount::from_sat(sats), None, None, None, None, None, None)
            .unwrap();
        self.client().generate_to_address(1, mine_to).unwrap();
        wallet.sync().unwrap();
    }

    fn new_wallet(&self, who: &str) -> BasicWallet {
        let dir = self.datadir.join(format!("wallet-{who}"));
        let _ = std::fs::remove_dir_all(&dir);
        BasicWallet::create_new_at(&dir, Network::Regtest, &self.rpc_url(), &self.cookie()).unwrap().0
    }
}

impl Drop for Regtest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
#[ignore = "requires bitcoind; run with --ignored"]
fn wallet_basics() {
    let node = Regtest::start();
    let mine_to = node.init_funds();
    let w = node.new_wallet("alice");

    assert_eq!(w.balance().to_sat(), 0, "fresh wallet is empty");
    node.fund(&w, 100_000_000, &mine_to);
    assert_eq!(w.balance().to_sat(), 100_000_000, "funded 1 BTC");
    assert_eq!(w.list_utxos().len(), 1, "one UTXO");

    // A normal send (change back to the wallet).
    let dest = node.miner().get_new_address(None, None).unwrap().assume_checked();
    w.send(&dest.to_string(), Amount::from_sat(30_000_000)).unwrap();
    node.client().generate_to_address(1, &mine_to).unwrap();
    w.sync().unwrap();
    let after_send = w.balance().to_sat();
    assert!(after_send < 70_000_000 && after_send > 69_900_000, "≈70M − fee, got {after_send}");

    // A single-UTXO-enforced send.
    w.send_single_utxo(&dest.to_string(), Amount::from_sat(20_000_000)).unwrap();
    node.client().generate_to_address(1, &mine_to).unwrap();
    w.sync().unwrap();
    let after_single = w.balance().to_sat();
    assert!(after_single < after_send - 20_000_000, "single-utxo send reduced balance");
    println!("[ok] wallet basics: new / fund / balance / utxos / send / send-single ✓");
}

#[test]
#[ignore = "requires bitcoind; run with --ignored"]
fn joint_cosign() {
    // The mechanism babilonia's funding relies on: one wallet builds a 2-input tx (its own UTXO +
    // the other's as a *foreign* UTXO), each signs its own input, then it's finalised & broadcast.
    let node = Regtest::start();
    let mine_to = node.init_funds();
    let a = node.new_wallet("a");
    let b = node.new_wallet("b");
    node.fund(&a, 100_000_000, &mine_to);
    node.fund(&b, 100_000_000, &mine_to);

    let a_in = a.list_utxos()[0].0;
    let b_in = b.list_utxos()[0].0;
    let pot = node.miner().get_new_address(None, Some(AddressType::Bech32m)).unwrap().assume_checked();
    let change_a = a.change_address().to_string();
    let change_b = b.change_address().to_string();

    // inputs 200_000_000; outputs: pot 50M + two 74_999_500 changes ⇒ 1000-sat fee.
    let outputs = [
        (pot.to_string(), Amount::from_sat(50_000_000)),
        (change_a, Amount::from_sat(74_999_500)),
        (change_b, Amount::from_sat(74_999_500)),
    ];

    // Wallet `b` builds & self-signs; wallet `a` signs its own (foreign-to-b) input; `a` finalises.
    let mut psbt = b.create_psbt(&[a_in, b_in], &outputs).expect("build joint psbt");
    b.sign_psbt(&mut psbt).expect("b signs its input");
    a.sign_psbt(&mut psbt).expect("a signs its input");
    let tx = a.combine_finalize(psbt, &[]).expect("finalize");

    let txid = a.broadcast(&tx).expect("broadcast joint tx");
    node.client().generate_to_address(1, &mine_to).unwrap();
    let conf = node.client().get_raw_transaction_info(&txid, None).unwrap().confirmations.unwrap_or(0);
    assert!(conf >= 1, "joint tx confirmed ({conf} conf)");
    assert!(tx.input.len() == 2 && tx.output.len() == 3, "2-in / 3-out joint tx");
    println!("[ok] joint co-sign: foreign-UTXO build + cross-sign + finalize + broadcast ✓");
}
