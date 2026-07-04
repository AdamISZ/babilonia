//! The node layer — **translates game verbs into Bitcoin transactions**. A [`Bet`] implements
//! [`crate::game::BetChain`] against a `bitcoind` (via an RPC [`Client`]) and a [`Transport`] to
//! the counterparty. This is the only place in the game path that builds/broadcasts transactions.
//!
//! v5 pipeline: `fund_pot` (step 2: pre-funded pot; PSBT joint funding is a later step) → `setup`
//! (the 4-flight driver) → dealer `settle` (adapt with `d`, broadcast — posts `d`) → `observe`
//! (player extracts `d` from the on-chain settlement and decrypts `a_c`; dealer watches for a claim
//! vs the timeout) → `claim`/`dealer_take_on_loss`. `π_a` runs Σ-part-only (hash conjunct stubbed).

use std::time::{Duration, Instant};

use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair as BKeypair, Message, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, Sequence, Transaction, TxOut, Txid, Witness, XOnlyPublicKey};
use bitcoincore_rpc::{Client, RpcApi};
use musig2::secp::{Point, Scalar};
use musig2::CompactSignature;

use crate::game::{BetChain, Outcome};
use crate::messages::{FundFinal, FundOpen, FundReply};
use crate::musig::{adapt, extract, signature_bytes};
use crate::reveal::{claim_secret, recover_a_c, won};
use crate::setup::{run_alice, run_bob, AliceSecrets, BobSecrets, GameParams, SetupResult};
use crate::transport::Transport;
use crate::txgraph::{build_claim_spend, key_spend_sighash, script_spend_sighash, ClaimOutput, TaprootKey};
use crate::{Error, Result};

/// Total funding-transaction fee (split evenly between the two contributors).
const FUND_FEE: Amount = Amount::from_sat(1_000);

/// The party's role and its private inputs.
pub enum BetRole {
    Dealer(AliceSecrets),
    Player(BobSecrets),
}

/// A bet played by one party: its RPC client (on-chain), its transport (to the peer), the agreed
/// parameters, and accumulated state.
pub struct Bet<T: Transport> {
    client: Client,
    network: Network,
    transport: T,
    params: GameParams,
    role: BetRole,
    setup: Option<SetupResult>,
    recovered_a_c: Option<Scalar>,
    funding_tx: Option<Transaction>,
    progress: Option<Box<dyn Fn(&str) + Send>>,
}

impl<T: Transport> Bet<T> {
    /// Construct a bet for `role` over `client`/`transport`. The pot `params.u1_outpoint` is assumed
    /// already funded (step 2's simplified funding); joint PSBT funding lands in `fund_pot` later.
    pub fn new(client: Client, network: Network, transport: T, params: GameParams, role: BetRole) -> Self {
        Bet {
            client,
            network,
            transport,
            params,
            role,
            setup: None,
            recovered_a_c: None,
            funding_tx: None,
            progress: None,
        }
    }

    /// Attach a progress sink — called with a human-readable line at each step (the runner prints
    /// it). Keeps I/O out of the library.
    pub fn with_progress(mut self, sink: impl Fn(&str) + Send + 'static) -> Self {
        self.progress = Some(Box::new(sink));
        self
    }

    fn log(&self, msg: &str) {
        if let Some(sink) = &self.progress {
            sink(msg);
        }
    }

    fn state(&self) -> Result<&SetupResult> {
        self.setup.as_ref().ok_or(Error::Protocol("setup not complete"))
    }

    fn new_address(&self) -> Result<Address> {
        self.client
            .get_new_address(None, None)?
            .require_network(self.network)
            .map_err(|_| Error::Protocol("address network mismatch"))
    }

    /// Wait until `txid` has at least `min_conf` confirmations (blocks come from a background miner,
    /// not from us — so this works whether one node or two peered nodes back the chain).
    fn wait_confirmed(&self, txid: Txid, min_conf: u32) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(info) = self.client.get_raw_transaction_info(&txid, None) {
                if info.confirmations.unwrap_or(0) >= min_conf {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                return Err(Error::Protocol("transaction did not reach the required confirmations"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The full `decoderawtransaction` JSON decode of a signed transaction, for the progress log.
    fn decode_tx(&self, tx: &Transaction, label: &str) -> String {
        let raw = hex::encode(bitcoin::consensus::serialize(tx));
        match self.client.call::<serde_json::Value>("decoderawtransaction", &[raw.into()]) {
            Ok(v) => format!("{label} (decoderawtransaction):\n{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string())),
            Err(e) => format!("{label}: <decoderawtransaction failed: {e}>"),
        }
    }

    fn poll_tx(&self, txid: Txid, timeout: Duration) -> Result<Transaction> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(tx) = self.client.get_raw_transaction(&txid, None) {
                return Ok(tx);
            }
            if Instant::now() > deadline {
                return Err(Error::Protocol("timed out waiting for a transaction"));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    // --- joint PSBT funding helpers ---

    /// Pick one confirmed wallet UTXO covering `need`.
    fn select_input(&self, need: Amount) -> Result<(OutPoint, Amount)> {
        let utxos = self.client.list_unspent(Some(1), None, None, None, None)?;
        let u = utxos
            .into_iter()
            .find(|u| u.amount >= need)
            .ok_or(Error::Protocol("no wallet UTXO covers the stake"))?;
        Ok((OutPoint { txid: u.txid, vout: u.vout }, u.amount))
    }

    fn change_addr(&self) -> Result<String> {
        Ok(self.client.call::<String>("getrawchangeaddress", &[])?)
    }

    /// The pot key `U1 = P2TR(MuSig2(P_a,P_b))` and its address string.
    fn u1_taproot(&self, p_a: &secp256k1::PublicKey, p_b: &secp256k1::PublicKey) -> Result<(TaprootKey, String)> {
        let u1 = TaprootKey::new(*p_a, *p_b)?;
        let addr = bitcoin::Address::from_script(&u1.spk, self.network)
            .map_err(|_| Error::Protocol("bad U1 address"))?;
        Ok((u1, addr.to_string()))
    }

    /// Build the shared unsigned funding PSBT (both sides build it identically): inputs in order
    /// `[dealer, player]`, outputs `[U1:pot, dealer_change, player_change]`.
    fn build_funding_psbt(
        &self,
        inputs: [OutPoint; 2],
        u1_addr: &str,
        pot: Amount,
        changes: [(String, Amount); 2],
    ) -> Result<String> {
        let ins: Vec<_> = inputs
            .iter()
            .map(|o| serde_json::json!({"txid": o.txid.to_string(), "vout": o.vout}))
            .collect();
        let [(d_addr, d_amt), (p_addr, p_amt)] = changes;
        let outs = serde_json::json!([
            {u1_addr: pot.to_btc()},
            {d_addr: d_amt.to_btc()},
            {p_addr: p_amt.to_btc()},
        ]);
        Ok(self.client.call::<String>("createpsbt", &[serde_json::json!(ins), outs])?)
    }

    /// Sign our own inputs of a PSBT.
    fn wallet_sign(&self, psbt: &str) -> Result<String> {
        Ok(self.client.wallet_process_psbt(psbt, Some(true), None, None)?.psbt)
    }

    /// Combine the two partially-signed PSBTs and finalise into the raw `TX1`.
    fn combine_finalize(&self, a: &str, b: &str) -> Result<Transaction> {
        let combined = self.client.call::<String>("combinepsbt", &[serde_json::json!([a, b])])?;
        let hex = self
            .client
            .finalize_psbt(&combined, Some(true))?
            .hex
            .ok_or(Error::Protocol("funding PSBT did not finalise"))?;
        bitcoin::consensus::deserialize(&hex).map_err(|_| Error::Protocol("bad finalised TX1"))
    }

    /// Locate the `U1` output in `TX1` (by scriptPubKey).
    fn locate_u1(tx: &Transaction, u1: &TaprootKey) -> Result<(OutPoint, Amount)> {
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == u1.spk)
            .ok_or(Error::Protocol("U1 output not found in TX1"))?;
        Ok((OutPoint { txid: tx.compute_txid(), vout: vout as u32 }, tx.output[vout].value))
    }

    /// The claim output for this bet (rebuilt from `K`, `P_a`, `t_1` — both parties know these).
    fn claim_output(&self) -> Result<ClaimOutput> {
        let s = self.state()?;
        ClaimOutput::new(s.k, x_only(&s.p_a)?, self.params.alice_timeout)
    }

    fn settle_txid(&self) -> Result<Txid> {
        Ok(self.state()?.settle_tx.compute_txid())
    }

    /// Value carried by the settlement output (= claim-output prevout).
    fn pot(&self) -> Result<Amount> {
        self.params
            .u1_value
            .checked_sub(self.params.fee)
            .ok_or(Error::Protocol("fee exceeds pot"))
    }

    // --- role-specific observation ---

    /// Player: wait for the settlement on-chain, extract `d`, decrypt `a_c`, and decide the outcome.
    fn player_observe(&mut self, guess: usize) -> Result<Outcome> {
        let (settle_pre, ctxt, thimbles) = {
            let s = self.state()?;
            (s.settle_pre.clone(), s.ctxt, s.thimbles)
        };
        self.log("waiting for the dealer's settlement on-chain…");
        let tx = self.poll_tx(self.settle_txid()?, Duration::from_secs(30))?;
        let sig_bytes = tx.input[0].witness.iter().next().ok_or(Error::Protocol("no settlement witness"))?;
        let compact = CompactSignature::from_bytes(sig_bytes).map_err(|_| Error::Protocol("bad settlement sig"))?;
        let final_sig = compact.lift_nonce().map_err(|_| Error::Protocol("cannot lift settlement sig"))?;
        let d = extract(&settle_pre, &final_sig)
            .and_then(|m| m.into_option())
            .ok_or(Error::Protocol("could not extract d from settlement"))?;
        let a_c = recover_a_c(&ctxt, &d)?;
        self.recovered_a_c = Some(a_c);
        let outcome = if won(&a_c, &thimbles[guess]) { Outcome::PlayerWins } else { Outcome::DealerWins };
        self.log(&format!("extracted d, decrypted a_c → {outcome:?}"));
        Ok(outcome)
    }

    /// Dealer: after settling, watch the claim output — spent (player claimed) ⇒ PlayerWins; still
    /// unspent past the window ⇒ DealerWins.
    fn dealer_observe(&self) -> Result<Outcome> {
        self.log("watching the claim output — did the player claim?");
        let claim = OutPoint { txid: self.settle_txid()?, vout: 0 };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let unspent = self.client.get_tx_out(&claim.txid, claim.vout, Some(false))?;
            if unspent.is_none() {
                return Ok(Outcome::PlayerWins); // claim output was spent by the player
            }
            if Instant::now() > deadline {
                return Ok(Outcome::DealerWins);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Build the unsigned claim-output spend paying the pot (minus fee) to a fresh wallet address.
    fn build_claim_spend_tx(&self, sequence: Sequence) -> Result<(Transaction, Amount, ClaimOutput)> {
        let claim = self.claim_output()?;
        let pot = self.pot()?;
        let claim_out = OutPoint { txid: self.settle_txid()?, vout: 0 };
        let dest = self.new_address()?;
        let out_value = pot.checked_sub(self.params.fee).ok_or(Error::Protocol("fee exceeds claim"))?;
        let tx = build_claim_spend(
            claim_out,
            sequence,
            vec![TxOut { value: out_value, script_pubkey: dest.script_pubkey() }],
        );
        Ok((tx, pot, claim))
    }

    /// Broadcast a fully-witnessed claim spend, wait for confirmation, and log it.
    fn submit_claim(&self, tx: &Transaction, label: &str, via: &str) -> Result<()> {
        self.log(&self.decode_tx(tx, label));
        let txid = self.client.send_raw_transaction(tx)?;
        self.wait_confirmed(txid, 1)?;
        self.log(&format!("spent the pot via the {via} — broadcast {txid}"));
        Ok(())
    }
}

impl<T: Transport> BetChain for Bet<T> {
    fn fund_pot(&mut self) -> Result<()> {
        let (alice_stake, bob_stake) = (self.params.alice_stake, self.params.bob_stake);
        let pot = alice_stake + bob_stake;
        let half_fee = Amount::from_sat(FUND_FEE.to_sat() / 2);

        // Extract our funding pubkey (drop the `self.role` borrow before the &mut coordination).
        enum Side {
            Dealer,
            Player,
        }
        let (side, my_key) = match &self.role {
            BetRole::Dealer(a) => (Side::Dealer, a.identity.pk),
            BetRole::Player(b) => (Side::Player, b.funding.pk),
        };
        let change_of = |amount: Amount, stake: Amount| -> Result<Amount> {
            amount
                .checked_sub(stake)
                .and_then(|a| a.checked_sub(half_fee))
                .ok_or(Error::Protocol("funding input too small for stake"))
        };

        let (u1, tx) = match side {
            Side::Dealer => {
                let (input, amount) = self.select_input(alice_stake + half_fee)?;
                let change = self.change_addr()?;
                self.transport.send(
                    &FundOpen { p_a: my_key.into(), input, amount: amount.to_sat(), change: change.clone() }.encode(),
                )?;
                let reply = FundReply::decode(&self.transport.recv()?)?;
                let p_b: secp256k1::PublicKey = reply.p_b.into();
                let (u1, u1_addr) = self.u1_taproot(&my_key, &p_b)?;
                let changes = [
                    (change, change_of(amount, alice_stake)?),
                    (reply.change, change_of(Amount::from_sat(reply.amount), bob_stake)?),
                ];
                let psbt = self.build_funding_psbt([input, reply.input], &u1_addr, pot, changes)?;
                let mine = self.wallet_sign(&psbt)?;
                self.transport.send(&FundFinal { psbt: mine.clone() }.encode())?;
                (u1, self.combine_finalize(&mine, &reply.psbt)?)
            }
            Side::Player => {
                let open = FundOpen::decode(&self.transport.recv()?)?;
                let p_a: secp256k1::PublicKey = open.p_a.into();
                let (u1, u1_addr) = self.u1_taproot(&p_a, &my_key)?;
                let (input, amount) = self.select_input(bob_stake + half_fee)?;
                let change = self.change_addr()?;
                let changes = [
                    (open.change, change_of(Amount::from_sat(open.amount), alice_stake)?),
                    (change.clone(), change_of(amount, bob_stake)?),
                ];
                let psbt = self.build_funding_psbt([open.input, input], &u1_addr, pot, changes)?;
                let mine = self.wallet_sign(&psbt)?;
                self.transport.send(
                    &FundReply { p_b: my_key.into(), input, amount: amount.to_sat(), change, psbt: mine.clone() }.encode(),
                )?;
                let fin = FundFinal::decode(&self.transport.recv()?)?;
                (u1, self.combine_finalize(&mine, &fin.psbt)?)
            }
        };

        let (u1_out, u1_value) = Self::locate_u1(&tx, &u1)?;
        self.params.u1_outpoint = u1_out;
        self.params.u1_value = u1_value;
        self.log(&format!("joint PSBT funding built — U1 = {u1_out} ({} sat); TX1 held (not broadcast)", u1_value.to_sat()));
        self.log(&self.decode_tx(&tx, "TX1 (joint funding, both inputs signed)"));
        self.funding_tx = Some(tx);
        Ok(())
    }

    fn broadcast_funding(&mut self) -> Result<()> {
        let tx = self.funding_tx.clone().ok_or(Error::Protocol("no funding tx to broadcast"))?;
        let txid = tx.compute_txid();
        let _ = self.client.send_raw_transaction(&tx); // ignore "already in mempool/chain"
        // Wait for TX1 itself to confirm — NOT for U1 to be unspent, since the dealer's settlement
        // may spend U1 before the other party's check runs.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(info) = self.client.get_raw_transaction_info(&txid, None) {
                if info.confirmations.unwrap_or(0) >= 1 {
                    break;
                }
            }
            if Instant::now() > deadline {
                return Err(Error::Protocol("funding did not confirm"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.log(&format!("funding TX1 broadcast + confirmed ({txid})"));
        Ok(())
    }

    fn setup(&mut self) -> Result<()> {
        self.log("running the 4-flight setup (thimbles, K+π_r, ctxt/D/π_a, dual pre-sign)…");
        let result = match &self.role {
            BetRole::Dealer(s) => run_alice(&mut self.transport, &self.params, s)?,
            BetRole::Player(s) => run_bob(&mut self.transport, &self.params, s)?,
        };
        self.setup = Some(result);
        self.log("setup complete — refund and settlement adaptor pre-signed");
        Ok(())
    }

    fn settle(&mut self) -> Result<()> {
        let d = match &self.role {
            BetRole::Dealer(a) => a.d,
            BetRole::Player(_) => return Err(Error::Protocol("only the dealer settles")),
        };
        let s = self.state()?;
        let sig = adapt(&s.settle_pre, &d).ok_or(Error::Protocol("settlement adapt failed"))?;
        let mut tx = s.settle_tx.clone();
        tx.input[0].witness = Witness::from_slice(&[signature_bytes(&sig).as_slice()]);
        self.log(&self.decode_tx(&tx, "settlement (MuSig2 adaptor completed with d)"));
        let txid = self.client.send_raw_transaction(&tx)?;
        self.wait_confirmed(txid, 1)?;
        self.log(&format!("settled — adapted with d and broadcast {txid} (d now on-chain)"));
        Ok(())
    }

    fn observe_outcome(&mut self) -> Result<Outcome> {
        match &self.role {
            BetRole::Dealer(_) => self.dealer_observe(),
            BetRole::Player(p) => {
                let guess = p.guess;
                self.player_observe(guess)
            }
        }
    }

    fn claim_win(&mut self) -> Result<()> {
        let (w_b, a_c) = match &self.role {
            BetRole::Player(p) => (
                Scalar::from(p.claim.sk),
                self.recovered_a_c.ok_or(Error::Protocol("outcome not observed"))?,
            ),
            BetRole::Dealer(_) => return Err(Error::Protocol("only the player claims a win")),
        };
        let claim_sk = claim_secret(&w_b, &a_c)?; // dlog K = w_b + a_c
        let (mut tx, pot, claim) = self.build_claim_spend_tx(Sequence::default())?;
        // Key-path spend of the claim output (internal key K) — no script revealed, indistinguishable
        // from an ordinary taproot payment.
        let sighash = key_spend_sighash(&tx, 0, &[claim.txout(pot)])?;
        let bsecp = bitcoin::secp256k1::Secp256k1::new();
        let sk = SecretKey::from_slice(&claim_sk.serialize()).map_err(|_| Error::Protocol("bad claim key"))?;
        let tweaked = BKeypair::from_secret_key(&bsecp, &sk).tap_tweak(&bsecp, claim.spend_info.merkle_root());
        let sig = bsecp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &tweaked.to_keypair()).serialize();
        tx.input[0].witness = Witness::from_slice(&[sig.as_slice()]);
        self.submit_claim(&tx, "claim (Bob wins — key-path spend of K)", "<K> key path")
    }

    fn dealer_take_on_loss(&mut self) -> Result<()> {
        let sk_a = match &self.role {
            BetRole::Dealer(a) => Scalar::from(a.identity.sk),
            BetRole::Player(_) => return Err(Error::Protocol("only the dealer reclaims")),
        };
        // Wait for the relative timelock to mature: the claim output (created by the settlement)
        // needs `alice_timeout` confirmations before its CSV leaf is spendable.
        self.wait_confirmed(self.settle_txid()?, self.params.alice_timeout as u32)?;
        let (mut tx, pot, claim) = self.build_claim_spend_tx(Sequence::from_height(self.params.alice_timeout))?;
        // Script-path spend of Alice's timeout leaf — the only script that ever hits the chain.
        let sighash = script_spend_sighash(&tx, 0, &[claim.txout(pot)], &claim.alice_leaf)?;
        let bsecp = bitcoin::secp256k1::Secp256k1::new();
        let sk = SecretKey::from_slice(&sk_a.serialize()).map_err(|_| Error::Protocol("bad key"))?;
        let sig = bsecp
            .sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &BKeypair::from_secret_key(&bsecp, &sk))
            .serialize();
        let cb = claim.control_block(&claim.alice_leaf)?;
        tx.input[0].witness = Witness::from_slice(&[sig.as_slice(), claim.alice_leaf.as_bytes(), &cb.serialize()]);
        self.submit_claim(&tx, "claim (Alice timeout — script-path spend)", "Alice-timeout leaf")
    }
}

fn x_only(p: &Point) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&p.serialize()[1..33]).map_err(|_| Error::Protocol("bad x-only key"))
}
