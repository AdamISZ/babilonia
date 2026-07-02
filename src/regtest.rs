//! Regtest harness: spawn a throwaway `bitcoind` (v31) on a temp datadir, drive it over RPC,
//! and tear it down on `Drop`. Hermetic — no external node required — so the e2e in
//! `tests/regtest_e2e.rs` is a reusable baseline. Proofs run `AssumeValid`; this layer proves
//! the tx graph is actually relay/consensus-accepted, and exercises witness assembly.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::{Error, Result};

static INSTANCE: AtomicU32 = AtomicU32::new(0);

/// A self-managed regtest `bitcoind` with a loaded wallet. Killed and cleaned up on drop.
pub struct RegtestNode {
    child: Child,
    datadir: PathBuf,
    /// Wallet-scoped RPC client (also serves non-wallet calls).
    pub client: Client,
}

/// Grab an ephemeral free TCP port by binding to :0 and releasing it.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

impl RegtestNode {
    /// Spawn `bitcoind -regtest`, wait for RPC, create + load a wallet, and mine to maturity so
    /// the wallet has spendable coins.
    pub fn start() -> Result<Self> {
        let n = INSTANCE.fetch_add(1, Ordering::SeqCst);
        let datadir = std::env::temp_dir().join(format!("babilonia-regtest-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&datadir)?;

        let rpc_port = free_port()?;
        let p2p_port = free_port()?;
        let child = Command::new("bitcoind")
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={}", rpc_port))
            .arg(format!("-port={}", p2p_port))
            .arg("-server=1")
            .arg("-listen=0")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0002")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?; // io::Error (e.g. bitcoind not on PATH) surfaces via Error::Io

        let cookie = datadir.join("regtest").join(".cookie");
        let url = format!("http://127.0.0.1:{rpc_port}");

        // Wait for the cookie file and a responsive RPC.
        let deadline = Instant::now() + Duration::from_secs(20);
        let node = loop {
            if cookie.exists() {
                if let Ok(c) = Client::new(&url, Auth::CookieFile(cookie.clone())) {
                    if c.get_blockchain_info().is_ok() {
                        break c;
                    }
                }
            }
            if Instant::now() > deadline {
                return Err(Error::Protocol("bitcoind did not become ready within 20s"));
            }
            sleep(Duration::from_millis(150));
        };

        node.create_wallet("bab", None, None, None, None)?;
        let client = Client::new(&format!("{url}/wallet/bab"), Auth::CookieFile(cookie))?;

        let node = RegtestNode { child, datadir, client };
        node.fund_wallet()?;
        Ok(node)
    }

    /// Mine 101 blocks to a wallet address so the first coinbase matures (spendable balance).
    fn fund_wallet(&self) -> Result<()> {
        let addr = self.new_address()?;
        self.client.generate_to_address(101, &addr)?;
        Ok(())
    }

    /// A fresh wallet address (network-checked for regtest).
    pub fn new_address(&self) -> Result<Address> {
        let addr = self
            .client
            .get_new_address(None, None)?
            .require_network(Network::Regtest)
            .map_err(|_| Error::Protocol("address network mismatch"))?;
        Ok(addr)
    }

    /// Mine `n` blocks to a throwaway wallet address (advances height for timelocks).
    pub fn mine(&self, n: u64) -> Result<()> {
        let addr = self.new_address()?;
        self.client.generate_to_address(n, &addr)?;
        Ok(())
    }

    /// Pay `amount` to `address` from the wallet, mine it in, and return the funding outpoint.
    pub fn fund_address(&self, address: &Address, amount: Amount) -> Result<OutPoint> {
        let txid = self
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)?;
        self.mine(1)?;
        let tx = self.client.get_raw_transaction(&txid, None)?;
        let spk = address.script_pubkey();
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == spk)
            .ok_or(Error::Protocol("funded output not found in tx"))? as u32;
        Ok(OutPoint { txid, vout })
    }

    /// Broadcast a fully-signed transaction to the node's mempool.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        Ok(self.client.send_raw_transaction(tx)?)
    }

    /// Confirmations for an unspent output (`None` if spent/unknown). Excludes the mempool.
    pub fn utxo_confirmations(&self, outpoint: &OutPoint) -> Result<Option<u32>> {
        let res = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))?;
        Ok(res.map(|r| r.confirmations))
    }
}

impl Drop for RegtestNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}
