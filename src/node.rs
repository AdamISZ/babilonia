//! A `Node`: a party's local Bitcoin stack — the bitcoind RPC (wallet + network), the network
//! type, the p2p address, peering, and the BIP324 covert transport to a peer. It is the
//! infrastructure the **node layer** builds bet transactions on; the `game` layer (business logic)
//! only ever talks to a `Node`, never to bitcoin transactions directly.
//!
//! Two flavours: [`Node::regtest`] spawns a throwaway `bitcoind` it owns (killed on `Drop`) — the
//! hermetic baseline for tests — and [`Node::connect`] attaches to an already-running node (real
//! deployments, the two-window runner). Requires the `node` feature.

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

/// A party's local Bitcoin node — RPC/wallet access, network type, p2p address, and the BIP324
/// covert transport to a peer. Owns its `bitcoind` process only when it spawned one.
pub struct Node {
    /// Bitcoin network (Regtest for the current runner; parametrised for later).
    network: Network,
    /// P2P listen port (for peering two nodes).
    p2p_port: u16,
    /// Base RPC URL and cookie path (to mint fresh clients via `new_rpc_client`).
    rpc_url: String,
    cookie: PathBuf,
    /// The loaded wallet name (for minting per-thread wallet clients).
    wallet: String,
    /// A spawned `bitcoind` we own (killed on `Drop`); `None` when attached to an existing node.
    child: Option<Child>,
    datadir: Option<PathBuf>,
    /// Wallet-scoped RPC client (also serves non-wallet calls).
    pub client: Client,
}

/// Grab an ephemeral free TCP port by binding to :0 and releasing it.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

impl Node {
    /// Spawn `bitcoind -regtest` (the binary named by `$BABILONIA_BITCOIND`, else `bitcoind`),
    /// wait for RPC, create + load a wallet, and mine to maturity. The spawned node is owned and
    /// killed on `Drop`.
    pub fn regtest() -> Result<Self> {
        let bin = std::env::var("BABILONIA_BITCOIND").unwrap_or_else(|_| "bitcoind".into());
        Self::regtest_with_binary(&bin)
    }

    /// Attach to an already-running node (not owned; not killed on drop). `base_url` is the RPC
    /// base (no `/wallet/...`); `wallet` is loaded/scoped for wallet calls; `p2p_port` is the
    /// node's advertised P2P port (for peering).
    pub fn connect(base_url: &str, cookie: PathBuf, network: Network, p2p_port: u16, wallet: &str) -> Result<Self> {
        let client = Client::new(&format!("{base_url}/wallet/{wallet}"), Auth::CookieFile(cookie.clone()))?;
        client.get_blockchain_info()?; // fail fast if unreachable
        Ok(Node {
            network,
            p2p_port,
            rpc_url: base_url.to_string(),
            cookie,
            wallet: wallet.to_string(),
            child: None,
            datadir: None,
            client,
        })
    }

    /// Attach to a running node **with no wallet scope** — for callers that bring their own wallet
    /// (e.g. the BDK `basic-wallet`, which only needs the node as a chain source + transport).
    /// Health-checks on the base RPC endpoint.
    pub fn attach(base_url: &str, cookie: PathBuf, network: Network, p2p_port: u16) -> Result<Self> {
        let client = Client::new(base_url, Auth::CookieFile(cookie.clone()))?;
        client.get_blockchain_info()?; // fail fast if unreachable
        Ok(Node {
            network,
            p2p_port,
            rpc_url: base_url.to_string(),
            cookie,
            wallet: String::new(),
            child: None,
            datadir: None,
            client,
        })
    }

    /// A fresh **wallet-scoped** RPC client — hand one to each concurrent party so they don't share
    /// a single `Client` across threads.
    pub fn wallet_client(&self) -> Result<Client> {
        self.named_wallet_client(&self.wallet)
    }

    fn named_wallet_client(&self, name: &str) -> Result<Client> {
        Ok(Client::new(
            &format!("{}/wallet/{}", self.rpc_url, name),
            Auth::CookieFile(self.cookie.clone()),
        )?)
    }

    /// Create a fresh wallet on this node, fund it with `amount` from the primary wallet (mined in),
    /// and return its client. Used to give each party its own wallet for joint PSBT funding.
    pub fn create_funded_wallet(&self, name: &str, amount: Amount) -> Result<Client> {
        self.client.create_wallet(name, None, None, None, None)?;
        let wc = self.named_wallet_client(name)?;
        let addr = wc
            .get_new_address(None, None)?
            .require_network(self.network)
            .map_err(|_| Error::Protocol("address network mismatch"))?;
        self.client
            .send_to_address(&addr, amount, None, None, None, None, None, None)?;
        self.mine(1)?;
        Ok(wc)
    }

    /// A boxed default [`Wallet`](crate::wallet::Wallet) over `wallet_client` (wallet-scoped RPC).
    pub fn rpc_wallet(&self, wallet_client: Client) -> Box<dyn crate::wallet::Wallet> {
        Box::new(crate::wallet::RpcWallet::new(wallet_client, self.network))
    }

    /// A boxed default [`Chain`](crate::chain::Chain) over a fresh non-wallet RPC client to this node.
    pub fn rpc_chain(&self) -> Result<Box<dyn crate::chain::Chain>> {
        Ok(Box::new(crate::chain::RpcChain::new(self.new_rpc_client()?)))
    }

    /// The base RPC URL of this node (no wallet path) — for building external clients (e.g. a
    /// `basic_wallet::BasicWallet`).
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// The cookie file path for this node's RPC auth.
    pub fn cookie(&self) -> &std::path::Path {
        &self.cookie
    }

    /// An [`RpcBackend`](crate::agent::RpcBackend) for the node core, scoped to `wallet_name`. Holds
    /// only connection details, so it outlives individual clients and is `Send + Sync`.
    pub fn agent_backend(&self, wallet_name: &str) -> crate::agent::RpcBackend {
        crate::agent::RpcBackend::new(self.rpc_url.clone(), self.cookie.clone(), self.network, wallet_name.to_string())
    }

    /// Like [`regtest`](Self::regtest) but with an explicit `bitcoind` path (e.g. a patched build).
    pub fn regtest_with_binary(bitcoind: &str) -> Result<Self> {
        Self::spawn(bitcoind, true)
    }

    /// Spawn a node WITHOUT mining any initial blocks — for the *second* node in a two-node setup:
    /// it must sync to the miner's chain rather than fork with its own coinbase. Honors
    /// `$BABILONIA_BITCOIND`.
    pub fn regtest_unfunded() -> Result<Self> {
        let bin = std::env::var("BABILONIA_BITCOIND").unwrap_or_else(|_| "bitcoind".into());
        Self::spawn(&bin, false)
    }

    fn spawn(bitcoind: &str, fund: bool) -> Result<Self> {
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
        let client = Client::new(&format!("{url}/wallet/bab"), Auth::CookieFile(cookie.clone()))?;

        let node = Node {
            network: Network::Regtest,
            p2p_port,
            rpc_url: url,
            cookie,
            wallet: "bab".to_string(),
            child: Some(child),
            datadir: Some(datadir),
            client,
        };
        if fund {
            node.fund_wallet()?;
        }
        Ok(node)
    }

    /// This node's Bitcoin network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Build a fresh (non-wallet) RPC client to this node — e.g. to hand to a `Bip324Transport`,
    /// which owns its client. The decoy RPCs are non-wallet, so no wallet scope is needed.
    pub fn new_rpc_client(&self) -> Result<Client> {
        Ok(Client::new(&self.rpc_url, Auth::CookieFile(self.cookie.clone()))?)
    }

    /// This node's P2P address (`127.0.0.1:<port>`).
    pub fn p2p_addr(&self) -> String {
        format!("127.0.0.1:{}", self.p2p_port)
    }

    /// Add a peer by P2P address (`host:port`) persistently; Core establishes (and re-establishes)
    /// the connection.
    pub fn connect_to_addr(&self, addr: &str) -> Result<()> {
        let _: serde_json::Value = self.client.call("addnode", &[addr.into(), "add".into()])?;
        Ok(())
    }

    /// Add `other` as a persistent peer.
    pub fn connect_to(&self, other: &Node) -> Result<()> {
        self.connect_to_addr(&other.p2p_addr())
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

    /// A fresh wallet address (checked against this node's network).
    pub fn new_address(&self) -> Result<Address> {
        let addr = self
            .client
            .get_new_address(None, None)?
            .require_network(self.network)
            .map_err(|_| Error::Protocol("address network mismatch"))?;
        Ok(addr)
    }

    /// Mine `n` blocks to a throwaway wallet address (advances height for timelocks).
    pub fn mine(&self, n: u64) -> Result<()> {
        let addr = self.new_address()?;
        self.client.generate_to_address(n, &addr)?;
        Ok(())
    }

    /// Spawn a detached thread that mines one block every `interval` — steady block production so
    /// broadcast transactions confirm (parties just wait for confirmations). Exits when the node
    /// goes away. In a two-node setup, run this on exactly one node to avoid chain forks.
    pub fn spawn_miner(&self, interval: Duration) -> Result<()> {
        let client = self.wallet_client()?;
        let network = self.network;
        std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            let addr = match client.get_new_address(None, None).map(|a| a.require_network(network)) {
                Ok(Ok(a)) => a,
                _ => break, // node/RPC gone
            };
            if client.generate_to_address(1, &addr).is_err() {
                break;
            }
        });
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

impl Drop for Node {
    fn drop(&mut self) {
        // Only tear down a node we spawned; a connected node is left running.
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(datadir) = self.datadir.as_ref() {
            let _ = std::fs::remove_dir_all(datadir);
        }
    }
}
