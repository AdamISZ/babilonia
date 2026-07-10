//! The node layer — **translates game verbs into Bitcoin transactions**. A [`Bet`] implements
//! [`crate::game::BetChain`] over three swappable traits — a [`Wallet`] (funding), a [`Chain`]
//! (broadcast/confirmations), and a [`Transport`] to the counterparty — with **no direct RPC**. This
//! is the only place in the game path that builds/broadcasts transactions.
//!
//! v5 pipeline: `fund_pot` (joint PSBT) → `setup` (the 4-flight driver) → `broadcast_funding` →
//! dealer `settle` (adapt with `d`, broadcast — posts `d`) → `observe` (player extracts `d` and
//! decrypts `a_c`; dealer watches the claim output) → `claim`/`dealer_take_on_loss`.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair as BKeypair, Message, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, Sequence, Transaction, TxOut, Txid, Witness, XOnlyPublicKey};
use musig2::secp::{Point, Scalar};
use musig2::CompactSignature;

use crate::chain::Chain;
use crate::game::{BetChain, Outcome};
use crate::messages::{FundFinal, FundOpen, FundReply};
use crate::musig::{adapt, extract, signature_bytes};
use crate::reveal::{claim_secret, recover_a_c, won};
use crate::setup::{run_alice, run_bob, AliceSecrets, BobSecrets, GameParams, SetupResult};
use crate::transport::Transport;
use crate::persist::{new_id, BetRecord, Phase, SetupData};
use crate::txgraph::{
    build_claim_spend, key_spend_sighash, random_seed, script_spend_sighash, shuffle_seeded, split_payment, ClaimOutput,
    TaprootKey,
};
use crate::wallet::Wallet;
use crate::{Error, Result};

// Fee model: every tx (funding, settlement, claim, refund) pays the flat `params.fee`. The funding
// fee is split evenly between the two contributors. TODO: a fee-rate (sat/vB) applied per tx by its
// vsize, so the larger funding tx pays proportionally more — the right model for real networks.

/// The party's role and its private inputs.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum BetRole {
    Dealer(AliceSecrets),
    Player(BobSecrets),
}

/// A bet played by one party over a [`Wallet`], a [`Chain`], and a [`Transport`] to the peer, plus
/// the agreed parameters and accumulated state.
pub struct Bet<T: Transport> {
    wallet: Box<dyn Wallet>,
    chain: Box<dyn Chain>,
    network: Network,
    transport: T,
    params: GameParams,
    role: BetRole,
    setup: Option<SetupResult>,
    recovered_a_c: Option<Scalar>,
    funding_tx: Option<Transaction>,
    /// Dealer only: the pre-signed 2-out CSV-leaf reclaim of `O_K`, built at setup and persisted.
    reclaim_tx: Option<Transaction>,
    progress: Option<Box<dyn Fn(&str) + Send>>,
    /// Unique id for this bet's on-disk record.
    bet_id: String,
    /// Where the crash-recovery record + refund are persisted (recovery for either party).
    state_dir: Option<PathBuf>,
}

impl<T: Transport> Bet<T> {
    /// Funding amounts (Alice-parks, COVERT-TX-PLAN §8.2): `U1 = F_A + b − fee` (Alice bears the
    /// funding fee), Bob's change `c_B = F_B − b`.
    fn funding_amounts(f_a: Amount, f_b: Amount, b: Amount, fee: Amount) -> Result<(Amount, Amount)> {
        let u1_value = f_a
            .checked_add(b)
            .and_then(|v| v.checked_sub(fee))
            .ok_or(Error::Protocol("funding amount underflow"))?;
        let c_b = f_b.checked_sub(b).ok_or(Error::Protocol("player input below stake"))?;
        Ok((u1_value, c_b))
    }

    /// Guard the parked surplus before broadcasting: `c_A = U1 − S ≥ 5·fee`, and the settlement's two
    /// outputs must differ (`c_A_out = c_A − fee ≠ S`). Protects covertness and dust.
    fn check_park(u1_value: Amount, a: Amount, b: Amount, fee: Amount) -> Result<()> {
        let s = a + b;
        let c_a = u1_value.checked_sub(s).ok_or(Error::Protocol("pot below stake — dealer input too small"))?;
        if c_a < Amount::from_sat(5 * fee.to_sat()) {
            return Err(Error::Protocol("parked surplus below 5·fee floor — dealer input too small"));
        }
        if c_a.checked_sub(fee) == Some(s) {
            return Err(Error::Protocol("settlement would have two equal outputs (c_A_out == S)"));
        }
        Ok(())
    }

    /// Construct a bet for `role` over `wallet`/`chain`/`transport`.
    pub fn new(
        wallet: Box<dyn Wallet>,
        chain: Box<dyn Chain>,
        network: Network,
        transport: T,
        params: GameParams,
        role: BetRole,
    ) -> Self {
        Bet {
            wallet,
            chain,
            network,
            transport,
            params,
            role,
            setup: None,
            recovered_a_c: None,
            funding_tx: None,
            reclaim_tx: None,
            progress: None,
            bet_id: new_id(),
            state_dir: None,
        }
    }

    /// Attach a progress sink — called with a human-readable line at each step (the runner prints
    /// it). Keeps I/O out of the library.
    pub fn with_progress(mut self, sink: impl Fn(&str) + Send + 'static) -> Self {
        self.progress = Some(Box::new(sink));
        self
    }

    /// Directory in which the fully-signed refund is written before funding is broadcast, so an abort
    /// after funding confirms is still recoverable. Unset ⇒ not persisted (ephemeral use / tests);
    /// the node app always sets it.
    pub fn with_state_dir(mut self, dir: PathBuf) -> Self {
        self.state_dir = Some(dir);
        self
    }

    fn log(&self, msg: &str) {
        if let Some(sink) = &self.progress {
            sink(msg);
        }
    }

    /// Persist the fully-signed refund transaction to disk **before** funding is broadcast, so the pot
    /// locked in U1 is always recoverable — even if this process dies — by broadcasting the saved tx
    /// once the chain passes `refund_locktime`. A refund path that only lives in memory is no safety
    /// net at all. This runs inside [`setup`], which is a hard gate before `broadcast_funding`: if it
    /// fails, funding is never broadcast, so the stakes stay in the wallets.
    fn persist_refund(&self) -> Result<()> {
        let Some(dir) = &self.state_dir else {
            self.log("WARNING: no state dir — refund NOT persisted; an abort after funding would strand the pot");
            return Ok(());
        };
        let s = self.state()?;
        let mut refund = s.refund_tx.clone();
        refund.input[0].witness = Witness::from_slice(&[signature_bytes(&s.refund_sig).as_slice()]);
        let raw = hex::encode(bitcoin::consensus::serialize(&refund));
        let lock = self.params.refund_locktime;
        let record = format!(
            "# babilonia refund — reclaims the jointly-funded pot (U1) back to the funders.\n\
             # Recover by broadcasting refund_tx once the chain passes block {lock}:\n\
             #   bitcoin-cli sendrawtransaction <refund_tx>\n\
             u1: {}\n\
             locktime: {lock}\n\
             refund_tx: {raw}\n",
            self.params.u1_outpoint,
        );
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("refund-{}.txt", self.params.u1_outpoint.txid));
        std::fs::write(&path, record)?;
        self.log(&format!("refund persisted → {} (broadcast after block {lock} to reclaim)", path.display()));
        Ok(())
    }

    /// Snapshot the full bet state to disk at a phase transition, so either party can complete or
    /// recover *any* step after a crash. No-op without a state dir. Written atomically.
    fn persist(&self, phase: Phase) -> Result<()> {
        let Some(dir) = &self.state_dir else {
            return Ok(());
        };
        let setup = self.setup.as_ref().map(|s| SetupData {
            settle_tx: s.settle_tx.clone(),
            settle_pre: s.settle_pre.clone(),
            refund_tx: s.refund_tx.clone(),
            refund_sig: s.refund_sig.clone(),
            ctxt: s.ctxt,
            d_point: s.d_point,
            k: s.k,
            thimbles: s.thimbles,
            p_a: s.p_a,
            reclaim_tx: self.reclaim_tx.clone(),
        });
        let record = BetRecord {
            id: self.bet_id.clone(),
            phase,
            role: self.role.clone(),
            params: self.params.clone(),
            funding_tx: self.funding_tx.clone(),
            setup,
            recovered_a_c: self.recovered_a_c,
        };
        record.save(dir)?;
        self.log(&format!("bet {} state persisted (phase {phase:?})", &self.bet_id[..8.min(self.bet_id.len())]));
        Ok(())
    }

    fn state(&self) -> Result<&SetupResult> {
        self.setup.as_ref().ok_or(Error::Protocol("setup not complete"))
    }

    /// A wall-clock budget for one on-chain step (a tx appearing, or gaining one confirmation).
    /// Regtest has a fast background miner (sub-second blocks); real networks take block-time, so this
    /// must be generous or a legitimately-confirming tx is abandoned — the signet "did not reach the
    /// required confirmations" bug, where a 60s deadline fired before a ~minute-plus block.
    fn step_budget(&self) -> Duration {
        match self.network {
            Network::Regtest => Duration::from_secs(60),
            _ => Duration::from_secs(30 * 60), // ~3 signet/mainnet blocks of slack per step
        }
    }

    /// Wait until `txid` has at least `min_conf` confirmations. Blocks come from the network (or a
    /// background miner on regtest), not from us; this polls the [`Chain`] view.
    fn wait_confirmed(&self, txid: Txid, min_conf: u32) -> Result<()> {
        let deadline = Instant::now() + self.step_budget() * min_conf.max(1);
        loop {
            if let Some(c) = self.chain.confirmations(txid)? {
                if c >= min_conf {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                return Err(Error::Protocol("transaction did not reach the required confirmations"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// A labelled decode of a signed transaction for the progress log (via the [`Chain`]).
    fn decode_tx(&self, tx: &Transaction, label: &str) -> String {
        format!("{label} {}", self.chain.decode_tx(tx))
    }

    fn poll_tx(&self, txid: Txid, timeout: Duration) -> Result<Transaction> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(tx) = self.chain.get_transaction(txid)? {
                return Ok(tx);
            }
            if Instant::now() > deadline {
                return Err(Error::Protocol("timed out waiting for a transaction"));
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    // --- joint PSBT funding helpers ---

    /// The pot key `U1 = P2TR(MuSig2(P_a,P_b))` and its address string.
    fn u1_taproot(&self, p_a: &secp256k1::PublicKey, p_b: &secp256k1::PublicKey) -> Result<(TaprootKey, String)> {
        let u1 = TaprootKey::new(*p_a, *p_b)?;
        let addr = bitcoin::Address::from_script(&u1.spk, self.network)
            .map_err(|_| Error::Protocol("bad U1 address"))?;
        Ok((u1, addr.to_string()))
    }

    /// Build the **2-in / 2-out** funding PSBT (Alice-parks, COVERT-TX-PLAN §8): inputs `[F_A, F_B]`,
    /// outputs `[U1(value), Bob's change]`. Alice's whole input folds into `U1` (no Alice change) —
    /// the payjoin shape. The layout is protocol logic; the PSBT goes through the [`Wallet`].
    fn build_funding_psbt(
        &self,
        inputs: [OutPoint; 2],
        u1_addr: &str,
        u1_value: Amount,
        bob_change: (&str, Amount),
    ) -> Result<String> {
        // Player-built (single builder) → fresh random order for both inputs and outputs, so neither
        // "dealer input first" nor "U1 first" is a fixed tell (COVERT-TX-PLAN §9). The dealer verifies
        // order-independently, and `locate_u1` finds U1 by scriptPubKey. The wallets preserve order
        // (RPC createpsbt array order; BDK `TxOrdering::Untouched`).
        let mut inputs = inputs.to_vec();
        shuffle_seeded(&mut inputs, &random_seed());
        let mut outputs = vec![(u1_addr.to_string(), u1_value), (bob_change.0.to_string(), bob_change.1)];
        shuffle_seeded(&mut outputs, &random_seed());
        self.wallet.create_psbt(&inputs, &outputs)
    }

    /// The dealer verifies the player-built funding tx before co-signing: it must spend exactly the
    /// two agreed inputs and pay exactly `U1` (value `F_A + b − fee`) + Bob's change — nothing more, so
    /// the player cannot redirect or over-fee Alice's parked input. Order-independent.
    fn verify_funding_psbt(
        &self,
        psbt_b64: &str,
        inputs: [OutPoint; 2],
        u1: &TaprootKey,
        u1_value: Amount,
        bob_change: (&str, Amount),
    ) -> Result<()> {
        let psbt = bitcoin::Psbt::from_str(psbt_b64).map_err(|_| Error::Decode("funding psbt"))?;
        let tx = &psbt.unsigned_tx;

        let mut got_in: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        let mut want_in = inputs.to_vec();
        got_in.sort();
        want_in.sort();
        if got_in != want_in {
            return Err(Error::Protocol("funding tx spends unexpected inputs"));
        }

        let spk_of = |addr: &str| -> Result<Vec<u8>> {
            Ok(Address::from_str(addr)
                .map_err(|_| Error::Decode("change address"))?
                .require_network(self.network)
                .map_err(|_| Error::Decode("change address network"))?
                .script_pubkey()
                .to_bytes())
        };
        let mut want_out = vec![
            (u1.spk.to_bytes(), u1_value.to_sat()),
            (spk_of(bob_change.0)?, bob_change.1.to_sat()),
        ];
        let mut got_out: Vec<(Vec<u8>, u64)> =
            tx.output.iter().map(|o| (o.script_pubkey.to_bytes(), o.value.to_sat())).collect();
        want_out.sort();
        got_out.sort();
        if got_out != want_out {
            return Err(Error::Protocol("funding tx has unexpected outputs"));
        }
        Ok(())
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

    /// Locate `O_K` in the (output-shuffled) settlement tx by its scriptPubKey — it may sit at any
    /// vout now that the settlement outputs are randomized (COVERT-TX-PLAN §9).
    fn o_k_outpoint(&self) -> Result<OutPoint> {
        let claim_spk = self.claim_output()?.spk;
        let settle_tx = &self.state()?.settle_tx;
        let vout = settle_tx
            .output
            .iter()
            .position(|o| o.script_pubkey == claim_spk)
            .ok_or(Error::Protocol("O_K not found in settlement outputs"))?;
        Ok(OutPoint { txid: settle_tx.compute_txid(), vout: vout as u32 })
    }

    /// Value carried by the settlement's claim output `O_K` — the at-risk pot `S = a + b` (Alice's
    /// parked `c_A` returns as the settlement's *other* output, not through `O_K`).
    fn pot(&self) -> Result<Amount> {
        Ok(self.params.alice_stake + self.params.bob_stake)
    }

    // --- role-specific observation ---

    /// Player: wait for the settlement on-chain, extract `d`, decrypt `a_c`, and decide the outcome.
    fn player_observe(&mut self, guess: usize) -> Result<Outcome> {
        let (settle_pre, ctxt, thimbles) = {
            let s = self.state()?;
            (s.settle_pre.clone(), s.ctxt, s.thimbles)
        };
        self.log("waiting for the dealer's settlement on-chain…");
        let tx = self.poll_tx(self.settle_txid()?, self.step_budget())?;
        let sig_bytes = tx.input[0].witness.iter().next().ok_or(Error::Protocol("no settlement witness"))?;
        let compact = CompactSignature::from_bytes(sig_bytes).map_err(|_| Error::Protocol("bad settlement sig"))?;
        let final_sig = compact.lift_nonce().map_err(|_| Error::Protocol("cannot lift settlement sig"))?;
        let d = extract(&settle_pre, &final_sig)
            .and_then(|m| m.into_option())
            .ok_or(Error::Protocol("could not extract d from settlement"))?;
        let a_c = recover_a_c(self.params.pi_a_scheme, &ctxt, &d)?;
        self.recovered_a_c = Some(a_c);
        self.persist(Phase::Observed)?;
        let outcome = if won(&a_c, &thimbles[guess]) { Outcome::PlayerWins } else { Outcome::DealerWins };
        self.log(&format!("extracted d, decrypted a_c → {outcome:?}"));
        Ok(outcome)
    }

    /// Dealer: after settling, watch the claim output — spent (player claimed) ⇒ PlayerWins; still
    /// unspent past the window ⇒ DealerWins.
    fn dealer_observe(&self) -> Result<Outcome> {
        self.log("watching the claim output — did the player claim?");
        let claim = self.o_k_outpoint()?;
        // Give the player's claim time to land *and confirm* on a real network (the dealer only sees
        // confirmed spends here); too short would wrongly declare DealerWins on a legitimate claim.
        let deadline = Instant::now() + self.step_budget() * 2;
        loop {
            if !self.chain.utxo_unspent(claim)? {
                return Ok(Outcome::PlayerWins); // claim output was spent by the player
            }
            if Instant::now() > deadline {
                return Ok(Outcome::DealerWins);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Build the unsigned claim-output spend of `O_K` as a payment-like **2-out** tx (pay + change to
    /// two fresh wallet addresses, summing `S − fee`; COVERT-TX-PLAN §8.2).
    fn build_claim_spend_tx(&self, sequence: Sequence) -> Result<(Transaction, Amount, ClaimOutput)> {
        let claim = self.claim_output()?;
        let pot = self.pot()?; // O_K value = S
        let claim_out = self.o_k_outpoint()?;
        let out_value = pot.checked_sub(self.params.fee).ok_or(Error::Protocol("fee exceeds claim"))?;
        let (pay, change) = split_payment(out_value)?;
        let pay_addr = self.wallet.receive_address()?;
        let change_addr = self.wallet.change_address()?;
        // Single-builder tx → a fresh random output order (COVERT-TX-PLAN §9).
        let mut outs = vec![
            TxOut { value: pay, script_pubkey: pay_addr.script_pubkey() },
            TxOut { value: change, script_pubkey: change_addr.script_pubkey() },
        ];
        shuffle_seeded(&mut outs, &random_seed());
        let tx = build_claim_spend(claim_out, sequence, outs);
        Ok((tx, pot, claim))
    }

    /// Dealer: build the fully-witnessed **2-out** CSV-leaf reclaim of `O_K` (enforced Alice-win). A
    /// script-path spend of Alice's timeout leaf, sequence `t_1` — valid only after the relative
    /// timelock, so it can be pre-signed at setup. Payment-shaped (pay + change to two Alice addrs).
    fn build_reclaim_tx(&self) -> Result<Transaction> {
        let sk_a = match &self.role {
            BetRole::Dealer(a) => Scalar::from(a.identity.sk),
            BetRole::Player(_) => return Err(Error::Protocol("only the dealer reclaims")),
        };
        let (mut tx, pot, claim) = self.build_claim_spend_tx(Sequence::from_height(self.params.alice_timeout))?;
        let sighash = script_spend_sighash(&tx, 0, &[claim.txout(pot)], &claim.alice_leaf)?;
        let bsecp = bitcoin::secp256k1::Secp256k1::new();
        let sk = SecretKey::from_slice(&sk_a.serialize()).map_err(|_| Error::Protocol("bad key"))?;
        let sig = bsecp
            .sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &BKeypair::from_secret_key(&bsecp, &sk))
            .serialize();
        let cb = claim.control_block(&claim.alice_leaf)?;
        tx.input[0].witness = Witness::from_slice(&[sig.as_slice(), claim.alice_leaf.as_bytes(), &cb.serialize()]);
        Ok(tx)
    }

    /// Broadcast a fully-witnessed claim spend, wait for confirmation, and log it.
    fn submit_claim(&self, tx: &Transaction, label: &str, via: &str) -> Result<()> {
        self.log(&self.decode_tx(tx, label));
        let txid = self.chain.broadcast(tx)?;
        self.wait_confirmed(txid, 1)?;
        self.log(&format!("spent the pot via the {via} — broadcast {txid}"));
        Ok(())
    }
}

impl<T: Transport> BetChain for Bet<T> {
    fn fund_pot(&mut self) -> Result<()> {
        let (a, b, fee) = (self.params.alice_stake, self.params.bob_stake, self.params.fee);
        // Alice brings a whole input F_A ≥ a + 6·fee so the parked c_A clears the 5·fee floor.
        let alice_need = a + Amount::from_sat(6 * fee.to_sat());

        enum Side {
            Dealer,
            Player,
        }
        let (side, my_key) = match &self.role {
            BetRole::Dealer(s) => (Side::Dealer, s.identity.pk),
            BetRole::Player(s) => (Side::Player, s.funding.pk),
        };

        // **Player builds** the 2-in/2-out payjoin funding; the **dealer verifies + co-signs**. Alice
        // parks (whole input into U1, no funding change); Bob takes his change. See COVERT-TX-PLAN §8.
        let (u1, tx) = match side {
            Side::Dealer => {
                let (input, f_a) = self.wallet.select_input(alice_need)?; // F_A (whole; parked = F_A − a − fee)
                let alice_payout = self.wallet.receive_address()?.to_string();
                self.transport.send(
                    &FundOpen { p_a: my_key.into(), input, amount: f_a.to_sat(), alice_payout: alice_payout.clone() }.encode(),
                )?;
                let reply = FundReply::decode(&self.transport.recv()?)?;
                let p_b: secp256k1::PublicKey = reply.p_b.into();
                let (u1, _u1_addr) = self.u1_taproot(&my_key, &p_b)?;
                let (u1_value, c_b) = Self::funding_amounts(f_a, Amount::from_sat(reply.amount), b, fee)?;
                Self::check_park(u1_value, a, b, fee)?;
                self.verify_funding_psbt(&reply.psbt, [input, reply.input], &u1, u1_value, (&reply.change, c_b))?;
                let both = self.wallet.sign_psbt(&reply.psbt)?; // add our input's signature
                self.transport.send(&FundFinal { psbt: both.clone() }.encode())?;
                self.params.alice_payout = alice_payout;
                self.params.bob_payout = reply.bob_payout;
                (u1, self.wallet.combine_finalize(&[&both])?)
            }
            Side::Player => {
                let open = FundOpen::decode(&self.transport.recv()?)?;
                let p_a: secp256k1::PublicKey = open.p_a.into();
                let (u1, u1_addr) = self.u1_taproot(&p_a, &my_key)?;
                let (input, f_b) = self.wallet.select_input(b + fee)?; // F_B ≥ b + fee ⇒ non-dust change
                let change = self.wallet.change_address()?.to_string();
                let bob_payout = self.wallet.receive_address()?.to_string();
                let (u1_value, c_b) = Self::funding_amounts(Amount::from_sat(open.amount), f_b, b, fee)?;
                Self::check_park(u1_value, a, b, fee)?;
                let psbt = self.build_funding_psbt([open.input, input], &u1_addr, u1_value, (&change, c_b))?;
                let mine = self.wallet.sign_psbt(&psbt)?;
                self.transport.send(
                    &FundReply { p_b: my_key.into(), input, amount: f_b.to_sat(), change, bob_payout: bob_payout.clone(), psbt: mine }.encode(),
                )?;
                let fin = FundFinal::decode(&self.transport.recv()?)?;
                self.params.alice_payout = open.alice_payout;
                self.params.bob_payout = bob_payout;
                (u1, self.wallet.combine_finalize(&[&fin.psbt])?)
            }
        };

        let (u1_out, u1_value) = Self::locate_u1(&tx, &u1)?;
        self.params.u1_outpoint = u1_out;
        self.params.u1_value = u1_value;
        self.log(&format!("funding built (Alice-parks payjoin) — U1 = {u1_out} ({} sat); TX1 held", u1_value.to_sat()));
        self.log(&self.decode_tx(&tx, "TX1 (2-in/2-out funding)"));
        self.funding_tx = Some(tx);
        self.persist(Phase::Funded)?;
        Ok(())
    }

    fn broadcast_funding(&mut self) -> Result<()> {
        let tx = self.funding_tx.clone().ok_or(Error::Protocol("no funding tx to broadcast"))?;
        let txid = tx.compute_txid();
        let _ = self.chain.broadcast(&tx); // ignore "already in mempool/chain"
        // Wait for TX1 itself to confirm — NOT for U1 to be unspent, since the dealer's settlement
        // may spend U1 before the other party's check runs.
        self.wait_confirmed(txid, 1)?;
        self.log(&format!("funding TX1 broadcast + confirmed ({txid})"));
        self.persist(Phase::FundingBroadcast)?;
        Ok(())
    }

    fn setup(&mut self) -> Result<()> {
        self.log("running the 4-flight setup (thimbles, K+π_r, ctxt/D/π_a, dual pre-sign)…");
        let result = match &self.role {
            BetRole::Dealer(s) => run_alice(&mut self.transport, &self.params, s)?,
            BetRole::Player(s) => run_bob(&mut self.transport, &self.params, s)?,
        };
        self.setup = Some(result);
        // Dealer: pre-build the enforced Alice-win reclaim now (valid only after t_1), so it's on disk
        // before any funding is broadcast and recovery needs no live signing. See COVERT-TX-PLAN §8.
        if matches!(self.role, BetRole::Dealer(_)) {
            self.reclaim_tx = Some(self.build_reclaim_tx()?);
        }
        self.log("setup complete — refund and settlement adaptor pre-signed");
        self.persist_refund()?; // safety net on disk BEFORE any funding is broadcast
        self.persist(Phase::SetupDone)?;
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
        let txid = self.chain.broadcast(&tx)?;
        self.wait_confirmed(txid, 1)?;
        self.log(&format!("settled — adapted with d and broadcast {txid} (d now on-chain)"));
        self.persist(Phase::Settled)?;
        Ok(())
    }

    fn observe_outcome(&mut self) -> Result<Outcome> {
        match &self.role {
            BetRole::Dealer(_) => {
                let outcome = self.dealer_observe()?;
                self.persist(Phase::Done)?; // dealer's terminal step (the player's Done is in claim_win)
                Ok(outcome)
            }
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
        self.submit_claim(&tx, "claim (Bob wins — key-path spend of K)", "<K> key path")?;
        self.persist(Phase::Done)?;
        Ok(())
    }

    fn dealer_take_on_loss(&mut self) -> Result<()> {
        // Wait for the relative timelock to mature: the claim output (created by the settlement)
        // needs `alice_timeout` confirmations before its CSV leaf is spendable — then broadcast the
        // reclaim pre-signed at setup.
        self.wait_confirmed(self.settle_txid()?, self.params.alice_timeout as u32)?;
        let tx = self.reclaim_tx.clone().ok_or(Error::Protocol("reclaim tx not pre-built at setup"))?;
        self.submit_claim(&tx, "claim (Alice timeout — pre-signed script-path spend)", "Alice-timeout leaf")
    }
}

fn x_only(p: &Point) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&p.serialize()[1..33]).map_err(|_| Error::Protocol("bad x-only key"))
}
