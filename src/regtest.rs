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
/// P2P listening and BIP324 v2 transport are enabled, so two nodes can peer over v2.
pub struct RegtestNode {
    child: Child,
    datadir: PathBuf,
    /// P2P listen port (for peering two nodes).
    p2p_port: u16,
    /// Wallet-scoped RPC client (also serves non-wallet calls).
    pub client: Client,
}

/// Grab an ephemeral free TCP port by binding to :0 and releasing it.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

impl RegtestNode {
    /// Spawn `bitcoind -regtest` (the binary named by `$BABILONIA_BITCOIND`, else `bitcoind`),
    /// wait for RPC, create + load a wallet, and mine to maturity.
    pub fn start() -> Result<Self> {
        let bin = std::env::var("BABILONIA_BITCOIND").unwrap_or_else(|_| "bitcoind".into());
        Self::start_with_binary(&bin)
    }

    /// Like [`start`](Self::start) but with an explicit `bitcoind` path (e.g. a patched build).
    pub fn start_with_binary(bitcoind: &str) -> Result<Self> {
        let n = INSTANCE.fetch_add(1, Ordering::SeqCst);
        let datadir = std::env::temp_dir().join(format!("babilonia-regtest-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&datadir)?;

        let rpc_port = free_port()?;
        let p2p_port = free_port()?;
        let child = Command::new(bitcoind)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={}", rpc_port))
            .arg(format!("-port={}", p2p_port))
            .arg("-server=1")
            .arg("-listen=1")
            .arg("-v2transport=1") // BIP324
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

        let node = RegtestNode { child, datadir, p2p_port, client };
        node.fund_wallet()?;
        Ok(node)
    }

    /// This node's P2P address (`127.0.0.1:<port>`).
    pub fn p2p_addr(&self) -> String {
        format!("127.0.0.1:{}", self.p2p_port)
    }

    /// Add `other` as a persistent peer; Core establishes (and re-establishes) the connection.
    pub fn connect_to(&self, other: &RegtestNode) -> Result<()> {
        let _: serde_json::Value = self
            .client
            .call("addnode", &[other.p2p_addr().into(), "add".into()])?;
        Ok(())
    }

    /// Raw `getpeerinfo` peer array.
    pub fn peers(&self) -> Result<Vec<serde_json::Value>> {
        let v: serde_json::Value = self.client.call("getpeerinfo", &[])?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }

    /// Count of peers currently on a BIP324 **v2** transport.
    pub fn v2_peer_count(&self) -> Result<usize> {
        Ok(self
            .peers()?
            .iter()
            .filter(|p| {
                p.get("transport_protocol_type").and_then(|t| t.as_str()) == Some("v2")
            })
            .count())
    }

    /// The node id of the single connected peer (regtest two-node setups have exactly one).
    pub fn only_peer_id(&self) -> Result<i64> {
        let ids: Vec<i64> = self
            .peers()?
            .iter()
            .filter_map(|p| p.get("id").and_then(|v| v.as_i64()))
            .collect();
        match ids.as_slice() {
            [id] => Ok(*id),
            _ => Err(Error::Protocol("expected exactly one peer")),
        }
    }

    /// Send a BIP324 decoy packet carrying `payload` to peer `peer_id` (patched-node RPC).
    pub fn send_decoy(&self, peer_id: i64, payload: &[u8]) -> Result<bool> {
        let r: serde_json::Value = self
            .client
            .call("senddecoy", &[peer_id.into(), hex::encode(payload).into()])?;
        Ok(r.as_bool().unwrap_or(false))
    }

    /// Drain the decoy payloads received from peer `peer_id` (patched-node RPC).
    pub fn get_decoys(&self, peer_id: i64) -> Result<Vec<Vec<u8>>> {
        let r: serde_json::Value = self.client.call("getdecoys", &[peer_id.into()])?;
        let mut out = Vec::new();
        if let Some(arr) = r.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    out.push(hex::decode(s).map_err(|_| Error::Protocol("bad decoy hex"))?);
                }
            }
        }
        Ok(out)
    }

    /// Poll until at least `min` peers are connected over v2, or time out.
    pub fn wait_for_v2_peers(&self, min: usize, timeout: Duration) -> Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.v2_peer_count()? >= min {
                return Ok(true);
            }
            if Instant::now() > deadline {
                return Ok(false);
            }
            sleep(Duration::from_millis(200));
        }
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
