//! The **`Chain`** trait — the block/transaction *view* the bet layer needs (broadcast,
//! confirmations, tx lookup, outpoint spent-ness), kept separate from the [`Wallet`](crate::wallet)
//! (which owns keys/UTXOs). The default [`RpcChain`] drives a `bitcoind` over RPC; an
//! Electrum/Esplora backend (e.g. via `bdk_chain`'s `ChainOracle`) could be an alternative impl.
//!
//! The trait exposes *primitives*; the bet layer composes waiting/timeout policy (poll-until-N-confs
//! etc.) on top, so different backends don't each re-implement it.

use bitcoin::{OutPoint, Transaction, Txid};

use crate::Result;

/// The chain-view operations the bet layer depends on. `Send` for the same reason as [`Wallet`].
pub trait Chain: Send {
    /// Broadcast a fully-signed transaction; returns its txid. Should tolerate a tx already in the
    /// mempool/chain.
    fn broadcast(&self, tx: &Transaction) -> Result<Txid>;
    /// Confirmations of `txid`: `Some(0)` = seen but unconfirmed (mempool), `Some(n)` confirmed,
    /// `None` = not seen / unknown.
    fn confirmations(&self, txid: Txid) -> Result<Option<u32>>;
    /// Fetch a transaction by txid from mempool or chain (`None` if not found).
    fn get_transaction(&self, txid: Txid) -> Result<Option<Transaction>>;
    /// Whether `outpoint` is currently an unspent output (false if spent or unknown).
    fn utxo_unspent(&self, outpoint: OutPoint) -> Result<bool>;
    /// A human-readable decode of `tx` for progress logs. Default: the txid; the RPC impl overrides
    /// with the full `decoderawtransaction` JSON.
    fn decode_tx(&self, tx: &Transaction) -> String {
        format!("txid={}", tx.compute_txid())
    }
}

#[cfg(feature = "node")]
pub use rpc::RpcChain;

#[cfg(feature = "node")]
mod rpc {
    use bitcoin::{OutPoint, Transaction, Txid};
    use bitcoincore_rpc::{Client, RpcApi};

    use super::Chain;
    use crate::Result;

    /// The default [`Chain`]: a `bitcoind` driven over RPC. Any client works (its queries are
    /// non-wallet); the runners hand it a non-wallet client.
    pub struct RpcChain {
        client: Client,
    }

    impl RpcChain {
        pub fn new(client: Client) -> Self {
            RpcChain { client }
        }
    }

    impl Chain for RpcChain {
        fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
            Ok(self.client.send_raw_transaction(tx)?)
        }

        fn confirmations(&self, txid: Txid) -> Result<Option<u32>> {
            // `get_raw_transaction_info` errors when the tx is not yet seen — treat as "unknown"
            // (keep waiting), matching the previous inline behaviour.
            match self.client.get_raw_transaction_info(&txid, None) {
                Ok(info) => Ok(Some(info.confirmations.unwrap_or(0))),
                Err(_) => Ok(None),
            }
        }

        fn get_transaction(&self, txid: Txid) -> Result<Option<Transaction>> {
            Ok(self.client.get_raw_transaction(&txid, None).ok())
        }

        fn utxo_unspent(&self, outpoint: OutPoint) -> Result<bool> {
            Ok(self
                .client
                .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))?
                .is_some())
        }

        fn decode_tx(&self, tx: &Transaction) -> String {
            let raw = hex::encode(bitcoin::consensus::serialize(tx));
            match self.client.call::<serde_json::Value>("decoderawtransaction", &[raw.into()]) {
                Ok(v) => format!(
                    "(decoderawtransaction):\n{}",
                    serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())
                ),
                Err(e) => format!("<decoderawtransaction failed: {e}>"),
            }
        }
    }
}
