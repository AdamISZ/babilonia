//! The **`Wallet`** trait — the bitcoin-wallet operations the bet layer needs: receiving/change
//! addresses, UTXO selection, and PSBT funding (build / sign / finalise). One of the three
//! swappable components (with [`Transport`](crate::transport::Transport) and the future `Ui`); the
//! default [`RpcWallet`] drives a `bitcoind` wallet over RPC.
//!
//! Scope: **funding and receiving only** — contributing a stake input + change to the shared PSBT,
//! signing this wallet's own inputs, and producing payout addresses. It is *never* used for the
//! protocol's taproot spends (claim/settle), which sign with protocol keys, not wallet keys.
//!
//! PSBTs cross this boundary (and the wire) as **base64 strings** — the form both `bitcoind` RPC and
//! the funding messages already use. (`bitcoin::Psbt` would be the cleaner type for a later pass.)

use bitcoin::{Address, Amount, OutPoint, Transaction, Txid};

use crate::Result;

/// The wallet operations the bet layer depends on. Implementors must be `Send` (the node core may
/// drive them from a worker thread).
pub trait Wallet: Send {
    /// Total spendable balance.
    fn balance(&self) -> Result<Amount>;
    /// A fresh receiving address (for payouts / external funding).
    fn receive_address(&self) -> Result<Address>;
    /// An internal change address.
    fn change_address(&self) -> Result<Address>;
    /// Select one confirmed UTXO worth at least `need`; returns its outpoint and value.
    fn select_input(&self, need: Amount) -> Result<(OutPoint, Amount)>;
    /// Build an **unsigned** PSBT spending `inputs` to `outputs` (address string → amount). base64.
    fn create_psbt(&self, inputs: &[OutPoint], outputs: &[(String, Amount)]) -> Result<String>;
    /// Send `amount` to `address` as a plain payment (funds a peer, external transfer, etc.).
    fn send_to(&self, address: &str, amount: Amount) -> Result<Txid>;
    /// Sign this wallet's own inputs of a base64 PSBT; returns the updated base64 PSBT.
    fn sign_psbt(&self, psbt: &str) -> Result<String>;
    /// Combine partially-signed base64 PSBTs and finalise into a network-ready transaction.
    fn combine_finalize(&self, psbts: &[&str]) -> Result<Transaction>;
}

#[cfg(feature = "node")]
pub use rpc::RpcWallet;

#[cfg(feature = "node")]
mod rpc {
    use std::str::FromStr;

    use bitcoin::{Address, Amount, Network, OutPoint, Transaction, Txid};
    use bitcoincore_rpc::{Client, RpcApi};

    use super::Wallet;
    use crate::{Error, Result};

    /// The default [`Wallet`]: a `bitcoind` wallet driven over RPC. A wallet-scoped client (it also
    /// serves the non-wallet PSBT RPCs `createpsbt`/`combinepsbt`/`finalizepsbt`).
    pub struct RpcWallet {
        client: Client,
        network: Network,
    }

    impl RpcWallet {
        pub fn new(client: Client, network: Network) -> Self {
            RpcWallet { client, network }
        }
    }

    fn checked(addr: &str, network: Network) -> Result<Address> {
        Address::from_str(addr)
            .map_err(|_| Error::Protocol("bad wallet address"))?
            .require_network(network)
            .map_err(|_| Error::Protocol("wallet address network mismatch"))
    }

    impl Wallet for RpcWallet {
        fn balance(&self) -> Result<Amount> {
            Ok(self.client.get_balance(None, None)?)
        }

        fn receive_address(&self) -> Result<Address> {
            self.client
                .get_new_address(None, None)?
                .require_network(self.network)
                .map_err(|_| Error::Protocol("address network mismatch"))
        }

        fn change_address(&self) -> Result<Address> {
            checked(&self.client.call::<String>("getrawchangeaddress", &[])?, self.network)
        }

        fn select_input(&self, need: Amount) -> Result<(OutPoint, Amount)> {
            let utxos = self.client.list_unspent(Some(1), None, None, None, None)?;
            let u = utxos
                .into_iter()
                .find(|u| u.amount >= need)
                .ok_or(Error::Protocol("no wallet UTXO covers the stake"))?;
            Ok((OutPoint { txid: u.txid, vout: u.vout }, u.amount))
        }

        fn create_psbt(&self, inputs: &[OutPoint], outputs: &[(String, Amount)]) -> Result<String> {
            let ins: Vec<_> = inputs
                .iter()
                .map(|o| serde_json::json!({"txid": o.txid.to_string(), "vout": o.vout}))
                .collect();
            // createpsbt takes outputs as an array of single-key {address: btc} objects.
            let outs: Vec<serde_json::Value> = outputs
                .iter()
                .map(|(a, amt)| {
                    let mut m = serde_json::Map::new();
                    m.insert(a.clone(), serde_json::json!(amt.to_btc()));
                    serde_json::Value::Object(m)
                })
                .collect();
            Ok(self
                .client
                .call::<String>("createpsbt", &[serde_json::json!(ins), serde_json::json!(outs)])?)
        }

        fn send_to(&self, address: &str, amount: Amount) -> Result<Txid> {
            let addr = checked(address, self.network)?;
            Ok(self.client.send_to_address(&addr, amount, None, None, None, None, None, None)?)
        }

        fn sign_psbt(&self, psbt: &str) -> Result<String> {
            Ok(self.client.wallet_process_psbt(psbt, Some(true), None, None)?.psbt)
        }

        fn combine_finalize(&self, psbts: &[&str]) -> Result<Transaction> {
            let combined = self.client.call::<String>("combinepsbt", &[serde_json::json!(psbts)])?;
            let hex = self
                .client
                .finalize_psbt(&combined, Some(true))?
                .hex
                .ok_or(Error::Protocol("PSBT did not finalise"))?;
            bitcoin::consensus::deserialize(&hex).map_err(|_| Error::Protocol("bad finalised tx"))
        }
    }
}
