//! An elementary BDK-based Bitcoin wallet: a BIP39 seed, BIP86 taproot descriptors, synced from a
//! bitcoind over RPC. Standalone (the `basic-bitcoin-wallet` binary) and coupling-free — it has no
//! babilonia dependency; babilonia adapts these methods to its own `Wallet` trait on its side.
//!
//! Deliberately minimal — no wallet-file persistence. State is just the mnemonic + a birthday
//! height in `<datadir>/<network>/wallet.state`, and every run re-syncs from the birthday. Fine for
//! regtest/signet; a mainnet wallet with an old birthday would do a long initial scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bdk_bitcoind_rpc::Emitter;
use bdk_wallet::{KeychainKind, SignOptions, TxOrdering, Wallet};
use bitcoin::bip32::Xpriv;
use bitcoin::psbt::Input as PsbtInput;
use bitcoin::{Address, Amount, Network, OutPoint, Psbt, Transaction, Txid, Weight};
use bip39::Mnemonic;

/// Addresses revealed on each keychain before a scan (a generous gap limit).
const GAP: u32 = 50;
/// Rough fee buffer used only for the single-UTXO coverage check.
const FEE_BUFFER: Amount = Amount::from_sat(1_000);

/// A minimal BDK wallet over a bitcoind RPC connection. Interior-mutable (a `Mutex`) so the
/// `&self` [`babilonia::wallet::Wallet`] methods can drive BDK's `&mut` API and the type stays `Send`.
/// Cheaply `Clone` (state shared via `Arc`) so a caller can cache one warm wallet and hand out clones
/// that all share the synced chain state — avoiding a full rescan-from-birthday on every use.
#[derive(Clone)]
pub struct BasicWallet {
    wallet: Arc<Mutex<Wallet>>,
    rpc: Arc<Client>,
    network: Network,
    birthday: u32,
}

impl BasicWallet {
    /// Generate a fresh 12-word wallet, record it, and sync.
    pub fn create_new(datadir: &Path, network: Network, rpc: Client) -> Result<(Self, Mnemonic)> {
        let path = state_path(datadir, network);
        if path.exists() {
            return Err(anyhow!("a wallet already exists at {}", path.display()));
        }
        let mnemonic = Mnemonic::generate(12).map_err(|e| anyhow!("mnemonic generation: {e}"))?;
        let birthday = rpc.get_block_count()? as u32; // only funds after this height matter
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, format!("{mnemonic}\n{birthday}\n"))?;
        let w = Self::build(&mnemonic, network, rpc, birthday)?;
        Ok((w, mnemonic))
    }

    /// Convenience: connect to a bitcoind by RPC URL + cookie file, then create a new wallet.
    pub fn create_new_at(datadir: &Path, network: Network, rpc_url: &str, cookie: &Path) -> Result<(Self, Mnemonic)> {
        let client = Client::new(rpc_url, Auth::CookieFile(cookie.to_path_buf()))?;
        Self::create_new(datadir, network, client)
    }

    /// Convenience: connect to a bitcoind by RPC URL + cookie file, then load an existing wallet.
    pub fn load_at(datadir: &Path, network: Network, rpc_url: &str, cookie: &Path) -> Result<Self> {
        let client = Client::new(rpc_url, Auth::CookieFile(cookie.to_path_buf()))?;
        Self::load(datadir, network, client)
    }

    /// Open the wallet at `datadir` for `network` — loading it if it exists, else creating a fresh
    /// one. (Used when a caller mints a wallet on demand and doesn't care which.)
    pub fn open_at(datadir: &Path, network: Network, rpc_url: &str, cookie: &Path) -> Result<Self> {
        if state_path(datadir, network).exists() {
            Self::load_at(datadir, network, rpc_url, cookie)
        } else {
            Ok(Self::create_new_at(datadir, network, rpc_url, cookie)?.0)
        }
    }

    /// Load an existing wallet from its state file and sync.
    pub fn load(datadir: &Path, network: Network, rpc: Client) -> Result<Self> {
        let path = state_path(datadir, network);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("no wallet at {} — run `new` first", path.display()))?;
        let mut lines = content.lines();
        let mnemonic = Mnemonic::from_str(lines.next().unwrap_or("").trim())
            .map_err(|e| anyhow!("corrupt wallet state (mnemonic): {e}"))?;
        let birthday = lines.next().unwrap_or("0").trim().parse().unwrap_or(0);
        Self::build(&mnemonic, network, rpc, birthday)
    }

    fn build(mnemonic: &Mnemonic, network: Network, rpc: Client, birthday: u32) -> Result<Self> {
        let (ext, int) = descriptors(mnemonic, network)?;
        let mut wallet = Wallet::create(ext, int)
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| anyhow!("wallet create: {e}"))?;
        let _ = wallet.reveal_addresses_to(KeychainKind::External, GAP);
        let _ = wallet.reveal_addresses_to(KeychainKind::Internal, GAP);
        let w = Self { wallet: Arc::new(Mutex::new(wallet)), rpc: Arc::new(rpc), network, birthday };
        w.sync()?;
        Ok(w)
    }

    /// Pull blocks (from the birthday) and mempool from bitcoind into the wallet.
    pub fn sync(&self) -> Result<()> {
        let mut wallet = self.wallet.lock().unwrap();
        let cp = wallet.latest_checkpoint();
        let start = cp.height().max(self.birthday);
        let mut emitter = Emitter::new(&*self.rpc, cp, start);
        while let Some(ev) = emitter.next_block()? {
            let h = ev.block_height();
            wallet.apply_block_connected_to(&ev.block, h, ev.connected_to())?;
        }
        let mempool = emitter.mempool()?;
        wallet.apply_unconfirmed_txs(mempool);
        Ok(())
    }

    /// Total balance (all confirmed + trusted-unconfirmed).
    pub fn balance(&self) -> Amount {
        self.wallet.lock().unwrap().balance().total()
    }

    /// The next unused external address (rotates as earlier ones are funded).
    pub fn receive_address(&self) -> Address {
        self.wallet.lock().unwrap().next_unused_address(KeychainKind::External).address
    }

    /// The next unused internal (change) address.
    pub fn change_address(&self) -> Address {
        self.wallet.lock().unwrap().next_unused_address(KeychainKind::Internal).address
    }

    /// Confirmed/known UTXOs as `(outpoint, value)`.
    pub fn list_utxos(&self) -> Vec<(OutPoint, Amount)> {
        self.wallet
            .lock()
            .unwrap()
            .list_unspent()
            .map(|u| (u.outpoint, u.txout.value))
            .collect()
    }

    /// Send `amount` to `addr` (normal coin selection), broadcasting via bitcoind.
    pub fn send(&self, addr: &str, amount: Amount) -> Result<Txid> {
        let script = self.parse_addr(addr)?.script_pubkey();
        let tx = {
            let mut wallet = self.wallet.lock().unwrap();
            let mut b = wallet.build_tx();
            b.add_recipient(script, amount);
            let mut psbt = b.finish()?;
            wallet.sign(&mut psbt, SignOptions::default())?;
            psbt.extract_tx()?
        };
        Ok(self.rpc.send_raw_transaction(&tx)?)
    }

    /// Send `amount` to `addr` using **exactly one** input UTXO (the single-UTXO-enforced spend).
    pub fn send_single_utxo(&self, addr: &str, amount: Amount) -> Result<Txid> {
        let script = self.parse_addr(addr)?.script_pubkey();
        let tx = {
            let mut wallet = self.wallet.lock().unwrap();
            let need = amount + FEE_BUFFER;
            let outpoint = wallet
                .list_unspent()
                .find(|u| u.txout.value >= need)
                .map(|u| u.outpoint)
                .ok_or_else(|| anyhow!("no single UTXO covers {amount} + fee"))?;
            let mut b = wallet.build_tx();
            b.manually_selected_only();
            b.add_utxo(outpoint)?;
            b.add_recipient(script, amount);
            let mut psbt = b.finish()?;
            wallet.sign(&mut psbt, SignOptions::default())?;
            psbt.extract_tx()?
        };
        Ok(self.rpc.send_raw_transaction(&tx)?)
    }

    /// Build an **unsigned** PSBT spending exactly `inputs` to `outputs` — for a *joint* funding
    /// transaction where some inputs belong to the counterparty. Inputs this wallet owns are added
    /// directly; the rest are added as `add_foreign_utxo` (their prevout fetched from bitcoind). The
    /// fee is pinned to `sum(inputs) − sum(outputs)` so BDK injects no change of its own, and the
    /// input/output order is preserved so both parties build the identical transaction.
    pub fn create_psbt(&self, inputs: &[OutPoint], outputs: &[(String, Amount)]) -> Result<Psbt> {
        let mut wallet = self.wallet.lock().unwrap();
        let owned: HashMap<OutPoint, Amount> =
            wallet.list_unspent().map(|u| (u.outpoint, u.txout.value)).collect();
        let mut in_sum = Amount::ZERO;
        let mut b = wallet.build_tx();
        b.manually_selected_only().ordering(TxOrdering::Untouched);
        for &op in inputs {
            if let Some(v) = owned.get(&op) {
                b.add_utxo(op)?;
                in_sum += *v;
            } else {
                let prevtx = self.fetch_prevtx(op.txid)?;
                let txout = prevtx
                    .output
                    .get(op.vout as usize)
                    .cloned()
                    .ok_or_else(|| anyhow!("prevout {op} not found"))?;
                in_sum += txout.value;
                // BDK wants the full prevtx (non_witness_utxo) as well as the witness_utxo.
                let psbt_in = PsbtInput {
                    witness_utxo: Some(txout),
                    non_witness_utxo: Some(prevtx),
                    ..Default::default()
                };
                // A taproot key-path spend: empty scriptSig + a ~64-byte Schnorr signature witness.
                b.add_foreign_utxo(op, psbt_in, Weight::from_wu(66))?;
            }
        }
        let mut out_sum = Amount::ZERO;
        for (addr, amt) in outputs {
            let script = Address::from_str(addr)?.require_network(self.network)?.script_pubkey();
            b.add_recipient(script, *amt);
            out_sum += *amt;
        }
        let fee = in_sum.checked_sub(out_sum).ok_or_else(|| anyhow!("outputs exceed inputs"))?;
        b.fee_absolute(fee);
        Ok(b.finish()?)
    }

    /// Fetch a full transaction from bitcoind (for a counterparty's input in a joint PSBT). Needs
    /// `-txindex` on the node.
    fn fetch_prevtx(&self, txid: Txid) -> Result<Transaction> {
        Ok(self.rpc.get_raw_transaction(&txid, None)?)
    }

    /// Sign this wallet's own inputs of `psbt` in place.
    pub fn sign_psbt(&self, psbt: &mut Psbt) -> Result<()> {
        self.wallet.lock().unwrap().sign(psbt, SignOptions::default())?;
        Ok(())
    }

    /// Combine PSBTs, finalise, and extract a broadcastable transaction.
    pub fn combine_finalize(&self, mut psbt: Psbt, others: &[Psbt]) -> Result<Transaction> {
        for o in others {
            psbt.combine(o.clone())?;
        }
        let opts = SignOptions { try_finalize: true, ..Default::default() };
        self.wallet.lock().unwrap().finalize_psbt(&mut psbt, opts)?;
        Ok(psbt.extract_tx()?)
    }

    /// Broadcast a signed transaction via bitcoind.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        Ok(self.rpc.send_raw_transaction(tx)?)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    fn parse_addr(&self, s: &str) -> Result<Address> {
        Ok(Address::from_str(s)?.require_network(self.network)?)
    }
}

fn descriptors(mnemonic: &Mnemonic, network: Network) -> Result<(String, String)> {
    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed).map_err(|e| anyhow!("xprv: {e}"))?;
    let coin = if network == Network::Bitcoin { 0 } else { 1 };
    let ext = format!("tr({xprv}/86'/{coin}'/0'/0/*)");
    let int = format!("tr({xprv}/86'/{coin}'/0'/1/*)");
    Ok((ext, int))
}

fn state_path(datadir: &Path, network: Network) -> PathBuf {
    datadir.join(network.to_string()).join("wallet.state")
}
