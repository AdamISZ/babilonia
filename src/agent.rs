//! The **node core** — a headless, UI-agnostic orchestrator. It owns config, a [`Backend`] (which
//! mints [`Wallet`]/[`Chain`]/[`Transport`] instances), and per-peer workers, and drives bets via
//! the existing `game`/`bet`/`setup` layers. It is a **single-owner actor loop**: all mutable state
//! lives in one loop fed by a single input channel; blocking I/O (stdin via the UI, each peer's
//! transport, each bet session) runs on edge threads that only *send messages* to that channel. No
//! shared mutexes, no async runtime — and the loop reads like sequential code.
//!
//! Boundaries (the three swappable components): the UI drives it through [`Command`] in / [`Event`]
//! out (mirroring Tauri's IPC); `Backend` abstracts the bitcoin node; `Transport` the peer channel.
//!
//! Stage 2 scope: one peer, one bet at a time. The proposer is the **dealer** (picks `c`); the
//! acceptor is the **player** (guesses `y`).

use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bitcoin::{Amount, Network, OutPoint};
use musig2::secp::Scalar;

use crate::bet::{Bet, BetRole};
use crate::chain::Chain;
use crate::game::{play_dealer, play_player};
use crate::keys::Keypair;
use crate::pi_a;
use crate::setup::{AliceSecrets, BobSecrets, GameParams};
use crate::transport::Transport;
use crate::wallet::Wallet;
use crate::Result;

/// Blocks between an absolute refund locktime and "now" when a bet is proposed.
const REFUND_LOCKTIME_OFFSET: u32 = 100;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Node configuration. The sizing/accept *knobs* live here; the *policies* that consume them
/// ([`ProposalPolicy`], [`AcceptPolicy`]) are separate swappable objects.
#[derive(Clone, Debug)]
pub struct Config {
    pub network: Network,
    /// Percent of a chosen UTXO to stake (consumed by the proposal policy).
    pub stake_percent: u8,
    /// Accept incoming proposals without asking the user (subject to `auto_accept_cap_sats`).
    pub auto_accept: bool,
    /// When auto-accepting, only do so for stakes ≤ this (0 = no cap).
    pub auto_accept_cap_sats: u64,
    pub fee_sats: u64,
    pub alice_timeout: u16,
    pub pi_a_scheme: pi_a::Scheme,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            network: Network::Regtest,
            stake_percent: 50,
            auto_accept: false,
            auto_accept_cap_sats: 0,
            fee_sats: 2_000,
            alice_timeout: 6,
            pi_a_scheme: pi_a::Scheme::Squaring,
        }
    }
}

impl Config {
    /// Load config from a `key = value` text file, falling back to defaults for anything absent or
    /// unparseable (a missing file is fine).
    pub fn load(path: &std::path::Path) -> Config {
        let mut c = Config::default();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    let _ = c.apply(k.trim(), v.trim());
                }
            }
        }
        c
    }

    /// Persist config to `path` (creating parent dirs).
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, self.to_text())
    }

    fn to_text(&self) -> String {
        format!(
            "network = {}\nstake_percent = {}\nauto_accept = {}\nauto_accept_cap_sats = {}\nfee_sats = {}\nalice_timeout = {}\npi_a_scheme = {}\n",
            self.network,
            self.stake_percent,
            self.auto_accept,
            self.auto_accept_cap_sats,
            self.fee_sats,
            self.alice_timeout,
            if self.pi_a_scheme == pi_a::Scheme::Poseidon { "poseidon" } else { "squaring" },
        )
    }

    /// Apply one `key`/`value` setting (used by both the file loader and the `set` command).
    pub fn apply(&mut self, key: &str, value: &str) -> std::result::Result<(), String> {
        let bad = || format!("bad value for {key}: '{value}'");
        match key {
            "network" => self.network = value.parse().map_err(|_| bad())?,
            "stake_percent" => self.stake_percent = value.parse().map_err(|_| bad())?,
            "auto_accept" => self.auto_accept = value.parse().map_err(|_| bad())?,
            "auto_accept_cap_sats" => self.auto_accept_cap_sats = value.parse().map_err(|_| bad())?,
            "fee_sats" => self.fee_sats = value.parse().map_err(|_| bad())?,
            "alice_timeout" => self.alice_timeout = value.parse().map_err(|_| bad())?,
            "pi_a_scheme" => {
                self.pi_a_scheme = match value {
                    "squaring" => pi_a::Scheme::Squaring,
                    "poseidon" => pi_a::Scheme::Poseidon,
                    _ => return Err(bad()),
                }
            }
            _ => return Err(format!("unknown config key '{key}'")),
        }
        Ok(())
    }
}

/// **Proposal-sizing policy** — a business-logic seam. Given the wallet's spendable UTXO values and
/// the current config, choose a stake to propose (`None` = decline). The default is [`PercentOfLargest`];
/// a game-theoretic sizer can replace it without touching the core.
pub trait ProposalPolicy: Send {
    fn stake_sats(&self, utxo_values: &[Amount], config: &Config) -> Option<u64>;
}

/// Default proposal policy: stake `config.stake_percent`% of the largest spendable UTXO.
pub struct PercentOfLargest;
impl ProposalPolicy for PercentOfLargest {
    fn stake_sats(&self, utxo_values: &[Amount], config: &Config) -> Option<u64> {
        let largest = utxo_values.iter().max()?.to_sat();
        let stake = largest.saturating_mul(config.stake_percent as u64) / 100;
        (stake > 0).then_some(stake)
    }
}

/// What to do with an incoming proposal.
pub enum AcceptDecision {
    Accept,
    Reject,
    /// Surface it to the user and wait for an `accept`/`reject` command.
    Ask,
}

/// **Accept policy** — a business-logic seam. Decide what to do with an incoming proposal of
/// `stake_sats`. The default is [`ConfigAccept`] (auto-accept within the cap, else ask).
pub trait AcceptPolicy: Send + Sync {
    fn decide(&self, stake_sats: u64, config: &Config) -> AcceptDecision;
}

/// Default accept policy: auto-accept iff `auto_accept` and the stake is within the cap; else ask.
pub struct ConfigAccept;
impl AcceptPolicy for ConfigAccept {
    fn decide(&self, stake_sats: u64, config: &Config) -> AcceptDecision {
        if config.auto_accept && (config.auto_accept_cap_sats == 0 || stake_sats <= config.auto_accept_cap_sats) {
            AcceptDecision::Accept
        } else {
            AcceptDecision::Ask
        }
    }
}

// ---------------------------------------------------------------------------
// UI boundary: Command in, Event out
// ---------------------------------------------------------------------------

/// An identifier for a proposed/active bet.
pub type BetId = u64;

/// A command from the UI to the core.
#[derive(Clone, Debug)]
pub enum Command {
    /// Peer with a bitcoin node at `addr` (the transport backend establishes BIP324).
    Connect { addr: String },
    /// Propose a bet to the connected peer (size per config).
    Propose,
    /// Accept a pending incoming proposal.
    Accept(BetId),
    /// Reject a pending incoming proposal.
    Reject(BetId),
    /// Ask for a fresh receiving address.
    Receive,
    /// Ask for the wallet balance.
    Balance,
    /// Send `sats` to `address` from the wallet (a plain payment — funds a peer, etc.).
    Send { address: String, sats: u64 },
    /// Set a config value (`key`, `value`).
    Set { key: String, value: String },
    /// Show the current config.
    ShowConfig,
    /// Shut the node down.
    Quit,
}

/// An event from the core to the UI.
#[derive(Clone, Debug)]
pub enum Event {
    Connected { peer: String },
    /// An incoming proposal awaiting `Accept`/`Reject` (only in manual-accept mode).
    Proposed { id: BetId, from: String, stake_sats: u64 },
    Progress { msg: String },
    Outcome { msg: String },
    Address { address: String },
    Balance { sats: u64 },
    Config { text: String },
    Info { msg: String },
    Error { msg: String },
}

/// The **UI boundary** — the third swappable component (with `Backend`/`Transport`). An
/// implementation drives the interaction: it turns user input into [`Command`]s (sent on
/// `commands`) and renders [`Event`]s (from `events`), returning when the session ends. The default
/// is [`crate::repl::Repl`]; a GUI (e.g. Tauri) is another impl over the same two channels.
pub trait Ui {
    fn run(&mut self, commands: Sender<Command>, events: Receiver<Event>);
}

// ---------------------------------------------------------------------------
// Backend: mints Wallet / Chain / Transport (the "local bitcoin node" role)
// ---------------------------------------------------------------------------

/// Abstracts the local bitcoin node: it produces fresh [`Wallet`]/[`Chain`] handles (a bet session
/// gets its own) and connects a [`Transport`] to a peer address. `Send + Sync` so it can be shared
/// (`Arc`) across the core loop and its worker threads.
pub trait Backend: Send + Sync {
    fn network(&self) -> Network;
    fn wallet(&self) -> Result<Box<dyn Wallet>>;
    fn chain(&self) -> Result<Box<dyn Chain>>;
    /// Initiate a connection to `addr` — a dial only (`addnode`). Registration of the resulting peer
    /// happens asynchronously via [`accept`](Backend::accept), so only the *initiator* dials; the
    /// other side auto-accepts. Default: no-op (seeded-peer / test backends need no dialing).
    fn dial(&self, _addr: &str) -> Result<()> {
        Ok(())
    }
    /// Identify the counterparty peer and return a transport to it (with its address). The core polls
    /// this while it holds no registered peer. `expected` disambiguates on a busy node with many v2
    /// peers (e.g. a signet/mainnet node): `Some(addr)` — *we* dialed that address, so match the peer
    /// with it (dialer side); `None` — match the peer that is actually exchanging **decoys**, i.e. the
    /// one running our protocol (a normal network peer never sends decoys) (accepter side). Default:
    /// `None` (backends with no peer discovery, e.g. the in-memory test transport).
    fn accept(&self, _expected: Option<&str>) -> Result<Option<(Box<dyn Transport>, String)>> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Peer handshake envelope (control messages before the bet flights)
// ---------------------------------------------------------------------------

/// Terms of a proposed bet — sent by the proposer; both sides build the identical [`GameParams`].
#[derive(Clone, Copy, Debug)]
struct ProposeTerms {
    stake_sats: u64,
    fee_sats: u64,
    refund_locktime: u32,
    alice_timeout: u16,
    scheme: u8, // 0 = Squaring, 1 = Poseidon
}

impl ProposeTerms {
    fn encode(&self) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&self.stake_sats.to_le_bytes());
        v.extend_from_slice(&self.fee_sats.to_le_bytes());
        v.extend_from_slice(&self.refund_locktime.to_le_bytes());
        v.extend_from_slice(&self.alice_timeout.to_le_bytes());
        v.push(self.scheme);
        v
    }
    fn decode(b: &[u8]) -> Option<ProposeTerms> {
        if b.len() != 24 || b[0] != 1 {
            return None;
        }
        Some(ProposeTerms {
            stake_sats: u64::from_le_bytes(b[1..9].try_into().ok()?),
            fee_sats: u64::from_le_bytes(b[9..17].try_into().ok()?),
            refund_locktime: u32::from_le_bytes(b[17..21].try_into().ok()?),
            alice_timeout: u16::from_le_bytes(b[21..23].try_into().ok()?),
            scheme: b[23],
        })
    }
    fn scheme(&self) -> pi_a::Scheme {
        if self.scheme == 1 {
            pi_a::Scheme::Poseidon
        } else {
            pi_a::Scheme::Squaring
        }
    }
    fn game_params(&self, network: Network) -> GameParams {
        let _ = network;
        GameParams {
            u1_outpoint: OutPoint::null(),
            u1_value: Amount::ZERO,
            alice_stake: Amount::from_sat(self.stake_sats),
            bob_stake: Amount::from_sat(self.stake_sats),
            fee: Amount::from_sat(self.fee_sats),
            refund_locktime: self.refund_locktime,
            alice_timeout: self.alice_timeout,
            pi_a_scheme: self.scheme(),
        }
    }
}

/// Presence marker a dialer sends once on connect so the accepter can identify which of its v2 peers
/// is running our protocol (a decoy = our protocol; normal peers send none). `ProposeTerms::decode`
/// rejects it (tag ≠ 1), so a worker that receives it ignores it.
const MSG_HELLO: &[u8] = &[0u8];
const MSG_ACCEPT: &[u8] = &[2u8];
const MSG_REJECT: &[u8] = &[3u8];

// ---------------------------------------------------------------------------
// Internal channels
// ---------------------------------------------------------------------------

/// The single input to the core loop.
enum Input {
    Command(Command),
    Worker(WorkerEvent),
    /// Periodic tick that drives auto-accept polling of the backend for an inbound peer.
    Tick,
}

/// A message from a peer worker to the core.
enum WorkerEvent {
    Proposed { stake_sats: u64 },
    Progress(String),
    Outcome(String),
    Info(String),
    Error(String),
}

/// An instruction from the core to a peer worker.
enum Instr {
    Propose(ProposeTerms),
    Accept,
    Reject,
    /// Push an updated config (so the worker's accept policy sees `set` changes).
    Config(Config),
    Quit,
}

/// The core's handle to a connected peer's worker.
struct PeerHandle {
    addr: String,
    instr: Sender<Instr>,
}

// ---------------------------------------------------------------------------
// NodeCore
// ---------------------------------------------------------------------------

/// The headless node core. Construct with [`NodeCore::new`], optionally seed a peer, then
/// [`run`](NodeCore::run) it (blocking) on a thread of your choice.
pub struct NodeCore {
    backend: Arc<dyn Backend>,
    config: Config,
    proposal_policy: Box<dyn ProposalPolicy>,
    accept_policy: Arc<dyn AcceptPolicy>,
    config_path: Option<std::path::PathBuf>,
    events: Sender<Event>,
    input_tx: Sender<Input>,
    input_rx: Receiver<Input>,
    peer: Option<PeerHandle>,
    /// The address we dialed via [`Command::Connect`], if any. On a busy node it tells `accept` to
    /// register the peer at *this* address (dialer side); `None` means match by decoy traffic.
    dialed: Option<String>,
    pending: Option<(BetId, u64)>, // (id, stake) awaiting manual Accept/Reject
    next_bet_id: BetId,
}

impl NodeCore {
    /// Build a core over `backend`/`config` with the default policies. Returns the core, a
    /// [`Command`] sender (UI → core), and an [`Event`] receiver (core → UI) — the swappable UI
    /// boundary. Override the policies with [`with_proposal_policy`](Self::with_proposal_policy) /
    /// [`with_accept_policy`](Self::with_accept_policy), and enable persistence with
    /// [`with_config_path`](Self::with_config_path).
    pub fn new(backend: Arc<dyn Backend>, config: Config) -> (Self, Sender<Command>, Receiver<Event>) {
        let (input_tx, input_rx) = channel::<Input>();
        let (evt_tx, evt_rx) = channel::<Event>();
        let (cmd_tx, cmd_rx) = channel::<Command>();
        // Bridge external Commands onto the single input channel.
        {
            let it = input_tx.clone();
            thread::spawn(move || {
                while let Ok(c) = cmd_rx.recv() {
                    if it.send(Input::Command(c)).is_err() {
                        break;
                    }
                }
            });
        }
        // Auto-accept poller: ticks the core once a second so it can pick up an inbound peer.
        {
            let it = input_tx.clone();
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(1));
                if it.send(Input::Tick).is_err() {
                    break;
                }
            });
        }
        let core = NodeCore {
            backend,
            config,
            proposal_policy: Box::new(PercentOfLargest),
            accept_policy: Arc::new(ConfigAccept),
            config_path: None,
            events: evt_tx,
            input_tx,
            input_rx,
            peer: None,
            dialed: None,
            pending: None,
            next_bet_id: 1,
        };
        (core, cmd_tx, evt_rx)
    }

    /// Swap the proposal-sizing policy.
    pub fn with_proposal_policy(mut self, policy: Box<dyn ProposalPolicy>) -> Self {
        self.proposal_policy = policy;
        self
    }

    /// Swap the accept policy.
    pub fn with_accept_policy(mut self, policy: Arc<dyn AcceptPolicy>) -> Self {
        self.accept_policy = policy;
        self
    }

    /// Persist config to `path` on every `set` (and expect it was loaded from there at startup).
    pub fn with_config_path(mut self, path: std::path::PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Seed an already-established peer transport (used by tests / when a connection is made out of
    /// band). The real path is the [`Command::Connect`] handler.
    pub fn with_seeded_peer(mut self, addr: impl Into<String>, transport: Box<dyn Transport>) -> Self {
        self.spawn_peer(addr.into(), transport, false); // pre-established channel: no discovery hello
        self
    }

    fn emit(&self, ev: Event) {
        let _ = self.events.send(ev);
    }

    /// Run the actor loop until `Quit` or all senders drop.
    pub fn run(mut self) {
        while let Ok(input) = self.input_rx.recv() {
            match input {
                Input::Command(cmd) => {
                    if !self.handle_command(cmd) {
                        break;
                    }
                }
                Input::Worker(ev) => self.handle_worker(ev),
                Input::Tick => self.poll_accept(),
            }
        }
        if let Some(p) = &self.peer {
            let _ = p.instr.send(Instr::Quit);
        }
    }

    /// Returns `false` on `Quit`.
    fn handle_command(&mut self, cmd: Command) -> bool {
        match cmd {
            Command::Connect { addr } => match self.backend.dial(&addr) {
                Ok(()) => {
                    self.emit(Event::Info {
                        msg: format!("dialing {addr}… (registers automatically once connected)"),
                    });
                    self.dialed = Some(addr);
                }
                Err(e) => self.emit(Event::Error { msg: format!("dial: {e}") }),
            },
            Command::Propose => self.propose(),
            Command::Accept(id) => self.decide(id, true),
            Command::Reject(id) => self.decide(id, false),
            Command::Receive => match self.backend.wallet().and_then(|w| w.receive_address()) {
                Ok(a) => self.emit(Event::Address { address: a.to_string() }),
                Err(e) => self.emit(Event::Error { msg: format!("receive: {e}") }),
            },
            Command::Balance => match self.backend.wallet().and_then(|w| w.balance()) {
                Ok(b) => self.emit(Event::Balance { sats: b.to_sat() }),
                Err(e) => self.emit(Event::Error { msg: format!("balance: {e}") }),
            },
            Command::Send { address, sats } => {
                match self.backend.wallet().and_then(|w| w.send_to(&address, Amount::from_sat(sats))) {
                    Ok(txid) => self.emit(Event::Info { msg: format!("sent {sats} sats → {address} ({txid})") }),
                    Err(e) => self.emit(Event::Error { msg: format!("send: {e}") }),
                }
            }
            Command::Set { key, value } => self.set_config(&key, &value),
            Command::ShowConfig => self.emit(Event::Config { text: format!("{:#?}", self.config) }),
            Command::Quit => return false,
        }
        true
    }

    fn handle_worker(&mut self, ev: WorkerEvent) {
        match ev {
            WorkerEvent::Proposed { stake_sats } => {
                let id = self.next_bet_id;
                self.next_bet_id += 1;
                self.pending = Some((id, stake_sats));
                let from = self.peer.as_ref().map(|p| p.addr.clone()).unwrap_or_default();
                self.emit(Event::Proposed { id, from, stake_sats });
            }
            WorkerEvent::Progress(msg) => self.emit(Event::Progress { msg }),
            WorkerEvent::Outcome(msg) => {
                self.pending = None;
                self.emit(Event::Outcome { msg });
            }
            WorkerEvent::Info(msg) => self.emit(Event::Info { msg }),
            WorkerEvent::Error(msg) => self.emit(Event::Error { msg }),
        }
    }

    fn propose(&mut self) {
        if self.peer.is_none() {
            return self.emit(Event::Error { msg: "no peer connected".into() });
        }
        // Size the stake via the (swappable) proposal policy over the wallet's UTXOs.
        let utxos = match self.backend.wallet().and_then(|w| w.utxo_values()) {
            Ok(u) => u,
            Err(e) => return self.emit(Event::Error { msg: format!("utxos: {e}") }),
        };
        let stake = match self.proposal_policy.stake_sats(&utxos, &self.config) {
            Some(s) => s,
            None => return self.emit(Event::Error { msg: "proposal policy declined (no suitable UTXO)".into() }),
        };
        let height = match self.backend.chain().and_then(|c| c.block_height()) {
            Ok(h) => h,
            Err(e) => return self.emit(Event::Error { msg: format!("height: {e}") }),
        };
        let terms = ProposeTerms {
            stake_sats: stake,
            fee_sats: self.config.fee_sats,
            refund_locktime: height + REFUND_LOCKTIME_OFFSET,
            alice_timeout: self.config.alice_timeout,
            scheme: if self.config.pi_a_scheme == pi_a::Scheme::Poseidon { 1 } else { 0 },
        };
        let _ = self.peer.as_ref().unwrap().instr.send(Instr::Propose(terms));
        self.emit(Event::Info { msg: format!("proposed a bet of {stake} sats") });
    }

    fn decide(&mut self, id: BetId, accept: bool) {
        match (&self.pending, &self.peer) {
            (Some((pid, _)), Some(peer)) if *pid == id => {
                let _ = peer.instr.send(if accept { Instr::Accept } else { Instr::Reject });
                if !accept {
                    self.pending = None;
                }
            }
            _ => self.emit(Event::Error { msg: format!("no pending bet {id}") }),
        }
    }

    fn set_config(&mut self, key: &str, value: &str) {
        if let Err(msg) = self.config.apply(key, value) {
            return self.emit(Event::Error { msg });
        }
        // Persist (if a path is set) and push the new config to the peer worker so its accept policy
        // sees the change.
        if let Some(path) = &self.config_path {
            if let Err(e) = self.config.save(path) {
                self.emit(Event::Error { msg: format!("save config: {e}") });
            }
        }
        if let Some(peer) = &self.peer {
            let _ = peer.instr.send(Instr::Config(self.config.clone()));
        }
        self.emit(Event::Info { msg: format!("{key} = {value}") });
    }

    /// Auto-accept: while we hold no peer, register the first established v2 peer the backend
    /// reports (an inbound connection, or the outbound one our own `dial` just opened).
    fn poll_accept(&mut self) {
        if self.peer.is_some() {
            return;
        }
        if let Ok(Some((transport, addr))) = self.backend.accept(self.dialed.as_deref()) {
            // Dialer (we have a `dialed` addr) announces itself; the accepter identified us by decoy.
            let send_hello = self.dialed.is_some();
            self.spawn_peer(addr.clone(), transport, send_hello);
            self.emit(Event::Connected { peer: addr });
        }
    }

    fn spawn_peer(&mut self, addr: String, transport: Box<dyn Transport>, send_hello: bool) {
        let (instr_tx, instr_rx) = channel::<Instr>();
        let to_core = self.input_tx.clone();
        let backend = self.backend.clone();
        let config = self.config.clone();
        let accept = self.accept_policy.clone();
        thread::spawn(move || peer_worker(transport, instr_rx, to_core, backend, config, accept, send_hello));
        self.peer = Some(PeerHandle { addr, instr: instr_tx });
    }
}

// ---------------------------------------------------------------------------
// Peer worker — owns one transport; idles polling for incoming proposals and
// local instructions, and runs a bet session (dealer or player) end to end.
// ---------------------------------------------------------------------------

fn peer_worker(
    mut transport: Box<dyn Transport>,
    instr_rx: Receiver<Instr>,
    to_core: Sender<Input>,
    backend: Arc<dyn Backend>,
    mut config: Config,
    accept: Arc<dyn AcceptPolicy>,
    send_hello: bool,
) {
    // Dialer only: announce presence with a hello decoy so the accepter can pick us out among its v2
    // peers (it can't match us by address — we're inbound to it). The accepter stays silent: *we*
    // already know it (the peer at the address we dialed), so it needs no hello — and a reply hello
    // could collide with a protocol `recv()` (e.g. the proposer awaiting ACCEPT).
    if send_hello {
        let _ = transport.send(MSG_HELLO);
    }
    let mut pending_terms: Option<ProposeTerms> = None;
    loop {
        // 1. Incoming control frame?
        match transport.try_recv() {
            Ok(Some(frame)) => {
                if let Some(terms) = ProposeTerms::decode(&frame) {
                    match accept.decide(terms.stake_sats, &config) {
                        AcceptDecision::Accept => {
                            let _ = to_core.send(Input::Worker(WorkerEvent::Info(format!(
                                "accepting bet of {} sats",
                                terms.stake_sats
                            ))));
                            if transport.send(MSG_ACCEPT).is_ok() {
                                run_player(&mut *transport, &backend, &config, terms, &to_core);
                            }
                        }
                        AcceptDecision::Reject => {
                            let _ = transport.send(MSG_REJECT);
                        }
                        AcceptDecision::Ask => {
                            let _ = to_core.send(Input::Worker(WorkerEvent::Proposed { stake_sats: terms.stake_sats }));
                            pending_terms = Some(terms);
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(_) => break, // peer gone
        }
        // 2. Local instruction?
        match instr_rx.try_recv() {
            Ok(Instr::Propose(terms)) => run_proposer(&mut *transport, &backend, &config, terms, &to_core),
            Ok(Instr::Accept) => {
                if let Some(terms) = pending_terms.take() {
                    if transport.send(MSG_ACCEPT).is_ok() {
                        run_player(&mut *transport, &backend, &config, terms, &to_core);
                    }
                }
            }
            Ok(Instr::Reject) => {
                let _ = transport.send(MSG_REJECT);
                pending_terms = None;
            }
            Ok(Instr::Config(c)) => config = c,
            Ok(Instr::Quit) => break,
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => break,
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Proposer side: send terms, await Accept/Reject, then play as **dealer**.
fn run_proposer(
    transport: &mut dyn Transport,
    backend: &Arc<dyn Backend>,
    config: &Config,
    terms: ProposeTerms,
    to_core: &Sender<Input>,
) {
    if transport.send(&terms.encode()).is_err() {
        return err(to_core, "propose: send failed");
    }
    match transport.recv() {
        Ok(resp) if resp == MSG_ACCEPT => run_dealer(transport, backend, config, terms, to_core),
        Ok(resp) if resp == MSG_REJECT => {
            let _ = to_core.send(Input::Worker(WorkerEvent::Info("peer rejected the bet".into())));
        }
        Ok(_) => err(to_core, "propose: unexpected reply"),
        Err(e) => err(to_core, &format!("propose: {e}")),
    }
}

fn run_dealer(
    transport: &mut dyn Transport,
    backend: &Arc<dyn Backend>,
    config: &Config,
    terms: ProposeTerms,
    to_core: &Sender<Input>,
) {
    let secp = secp256k1::Secp256k1::new();
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [scalar(&secp), scalar(&secp)],
        choice: rand_bit(),
        d: scalar(&secp),
    };
    play(transport, backend, config, terms, BetRole::Dealer(alice), to_core, true);
}

fn run_player(
    transport: &mut dyn Transport,
    backend: &Arc<dyn Backend>,
    config: &Config,
    terms: ProposeTerms,
    to_core: &Sender<Input>,
) {
    let secp = secp256k1::Secp256k1::new();
    let bob = BobSecrets { funding: Keypair::new(&secp), claim: Keypair::new(&secp), guess: rand_bit() };
    play(transport, backend, config, terms, BetRole::Player(bob), to_core, false);
}

#[allow(clippy::too_many_arguments)]
fn play(
    transport: &mut dyn Transport,
    backend: &Arc<dyn Backend>,
    config: &Config,
    terms: ProposeTerms,
    role: BetRole,
    to_core: &Sender<Input>,
    is_dealer: bool,
) {
    let (wallet, chain) = match (backend.wallet(), backend.chain()) {
        (Ok(w), Ok(c)) => (w, c),
        _ => return err(to_core, "bet: could not open wallet/chain"),
    };
    let params = terms.game_params(config.network);
    let progress = {
        let tc = to_core.clone();
        move |m: &str| {
            let _ = tc.send(Input::Worker(WorkerEvent::Progress(m.to_string())));
        }
    };
    let mut bet = Bet::new(wallet, chain, config.network, transport, params, role).with_progress(progress);
    let result = if is_dealer { play_dealer(&mut bet) } else { play_player(&mut bet) };
    match result {
        Ok(outcome) => {
            let _ = to_core.send(Input::Worker(WorkerEvent::Outcome(format!("{outcome:?}"))));
        }
        Err(e) => err(to_core, &format!("bet failed: {e}")),
    }
}

fn err(to_core: &Sender<Input>, msg: &str) {
    let _ = to_core.send(Input::Worker(WorkerEvent::Error(msg.to_string())));
}

fn scalar(secp: &secp256k1::Secp256k1<secp256k1::All>) -> Scalar {
    Scalar::from(Keypair::new(secp).sk)
}

fn rand_bit() -> usize {
    usize::from(rand::random::<bool>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrips_through_file() {
        let dir = std::env::temp_dir().join(format!("babtest-cfg-{}", std::process::id()));
        let path = dir.join("config.txt");
        let _ = std::fs::remove_dir_all(&dir);

        let mut c = Config::default();
        c.apply("stake_percent", "7").unwrap();
        c.apply("auto_accept", "true").unwrap();
        c.apply("auto_accept_cap_sats", "999").unwrap();
        c.apply("pi_a_scheme", "poseidon").unwrap();
        c.save(&path).unwrap();

        let loaded = Config::load(&path);
        assert_eq!(loaded.stake_percent, 7);
        assert!(loaded.auto_accept);
        assert_eq!(loaded.auto_accept_cap_sats, 999);
        assert_eq!(loaded.pi_a_scheme, pi_a::Scheme::Poseidon);

        assert!(c.apply("nope", "x").is_err());
        assert!(c.apply("stake_percent", "notnum").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_policy_sizes_percent_of_largest() {
        let mut cfg = Config::default();
        cfg.stake_percent = 10;
        let utxos = [Amount::from_sat(1_000), Amount::from_sat(5_000), Amount::from_sat(200)];
        assert_eq!(PercentOfLargest.stake_sats(&utxos, &cfg), Some(500)); // 10% of 5000
        assert_eq!(PercentOfLargest.stake_sats(&[], &cfg), None);
    }

    #[test]
    fn accept_policy_respects_auto_and_cap() {
        let mut cfg = Config::default();
        cfg.auto_accept = false;
        assert!(matches!(ConfigAccept.decide(100, &cfg), AcceptDecision::Ask));
        cfg.auto_accept = true;
        cfg.auto_accept_cap_sats = 0; // no cap
        assert!(matches!(ConfigAccept.decide(1_000_000, &cfg), AcceptDecision::Accept));
        cfg.auto_accept_cap_sats = 500;
        assert!(matches!(ConfigAccept.decide(400, &cfg), AcceptDecision::Accept));
        assert!(matches!(ConfigAccept.decide(600, &cfg), AcceptDecision::Ask));
    }
}

// ---------------------------------------------------------------------------
// Default RPC backend (requires the `node` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "node")]
pub use rpc_backend::RpcBackend;
#[cfg(feature = "basic-wallet")]
pub use rpc_backend::BasicWalletBackend;

#[cfg(feature = "node")]
mod rpc_backend {
    use std::path::PathBuf;

    use bitcoin::Network;
    use bitcoincore_rpc::{Auth, Client, RpcApi};

    use super::Backend;
    use crate::chain::RpcChain;
    use crate::transport::bip324::{Bip324Transport, DECOY_MAGIC};
    use crate::transport::Transport;
    use crate::wallet::RpcWallet;
    use crate::Result;

    /// The default [`Backend`]: mints RPC wallet/chain clients and BIP324 transports against a local
    /// (patched) `bitcoind`. Holds only connection details (Send + Sync), not the node itself, so it
    /// can be shared across the core loop and workers.
    pub struct RpcBackend {
        rpc_url: String,
        cookie: PathBuf,
        network: Network,
        wallet_name: String,
    }

    impl RpcBackend {
        pub fn new(rpc_url: String, cookie: PathBuf, network: Network, wallet_name: String) -> Self {
            RpcBackend { rpc_url, cookie, network, wallet_name }
        }

        fn client(&self, path: &str) -> Result<Client> {
            Ok(Client::new(&format!("{}{path}", self.rpc_url), Auth::CookieFile(self.cookie.clone()))?)
        }
    }

    impl Backend for RpcBackend {
        fn network(&self) -> Network {
            self.network
        }

        fn wallet(&self) -> Result<Box<dyn crate::wallet::Wallet>> {
            Ok(Box::new(RpcWallet::new(self.client(&format!("/wallet/{}", self.wallet_name))?, self.network)))
        }

        fn chain(&self) -> Result<Box<dyn crate::chain::Chain>> {
            Ok(Box::new(RpcChain::new(self.client("")?)))
        }

        fn dial(&self, addr: &str) -> Result<()> {
            let c = self.client("")?;
            // "add" registers a persistent peer. If it's already added (a re-`connect`, or the node
            // dialed it during normal peering), that's success — the peer is there — not a failure;
            // the caller must still proceed as the dialer (set `dialed`, send the hello).
            match c.call::<serde_json::Value>("addnode", &[addr.into(), "add".into()]) {
                Ok(_) => Ok(()),
                Err(e) if e.to_string().contains("already added") => Ok(()),
                Err(e) => Err(e.into()),
            }
        }

        fn accept(&self, expected: Option<&str>) -> Result<Option<(Box<dyn Transport>, String)>> {
            let c = self.client("")?;
            let peers: serde_json::Value = c.call("getpeerinfo", &[])?;
            let v2_peers = peers
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p.get("transport_protocol_type").and_then(|t| t.as_str()) == Some("v2"));

            for p in v2_peers {
                let Some(id) = p.get("id").and_then(|v| v.as_i64()) else { continue };
                let addr = p.get("addr").and_then(|a| a.as_str()).unwrap_or("peer").to_string();
                match expected {
                    // Dialer: register the peer at the address we dialed (there may be many others).
                    Some(want) => {
                        if addr_matches(&addr, want) {
                            return Ok(Some((Box::new(Bip324Transport::new(self.client("")?, id)), addr)));
                        }
                    }
                    // Accepter: register the peer that is actually sending us decoys — our protocol's
                    // hello. A normal network peer never does. `getdecoys` drains, so hand the drained
                    // frames to the transport so nothing sent before registration is lost.
                    None => {
                        let seed = drain_decoys(&c, id);
                        if !seed.is_empty() {
                            let t = Bip324Transport::new(self.client("")?, id).seeded(seed);
                            return Ok(Some((Box::new(t), addr)));
                        }
                    }
                }
            }
            Ok(None)
        }
    }

    /// Does a `getpeerinfo` peer address match the address we dialed? Exact, or same host (a dialed
    /// `ip:port` shows back verbatim for an outbound peer; be lenient on port formatting).
    fn addr_matches(peer_addr: &str, want: &str) -> bool {
        fn host(a: &str) -> &str {
            a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a)
        }
        peer_addr == want || host(peer_addr) == host(want)
    }

    /// Drain `getdecoys` for one peer into decoded frames — tolerant: a peer with no decoy session
    /// (a normal network peer) yields an empty vec rather than erroring, so we can probe every peer.
    fn drain_decoys(c: &Client, id: i64) -> Vec<Vec<u8>> {
        let Ok(r) = c.call::<serde_json::Value>("getdecoys", &[id.into()]) else {
            return Vec::new();
        };
        r.as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
            .filter_map(|s| hex::decode(s).ok())
            // Only *babilonia* frames (magic prefix) identify a peer as ours; a generic BIP324 decoy
            // from a random v2 peer must not register it (the signet peer-hijack bug).
            .filter_map(|bytes| bytes.strip_prefix(DECOY_MAGIC).map(|f| f.to_vec()))
            .collect()
    }

    /// A [`Backend`] whose wallet is the standalone **`basic-wallet`** (BDK): keys live in the app and
    /// `bitcoind` is only a chain source + BIP324 transport. Chain/dial/accept reuse [`RpcBackend`] —
    /// only `wallet()` differs. This is the wallet for signet/mainnet, where the node's own wallet is
    /// not the funder (funds arrive from a faucet / elsewhere to the BDK wallet's own addresses).
    #[cfg(feature = "basic-wallet")]
    pub struct BasicWalletBackend {
        inner: RpcBackend,
        datadir: PathBuf,
    }

    #[cfg(feature = "basic-wallet")]
    impl BasicWalletBackend {
        /// `datadir` holds the BDK wallet state (mnemonic + birthday); created on first use.
        pub fn new(rpc_url: String, cookie: PathBuf, network: Network, datadir: PathBuf) -> Self {
            BasicWalletBackend { inner: RpcBackend::new(rpc_url, cookie, network, String::new()), datadir }
        }
    }

    #[cfg(feature = "basic-wallet")]
    impl Backend for BasicWalletBackend {
        fn network(&self) -> Network {
            self.inner.network
        }

        fn wallet(&self) -> Result<Box<dyn crate::wallet::Wallet>> {
            let w = basic_wallet::BasicWallet::open_at(
                &self.datadir,
                self.inner.network,
                &self.inner.rpc_url,
                &self.inner.cookie,
            )
            .map_err(|e| crate::Error::Wallet(format!("{e:#}")))?;
            Ok(Box::new(w))
        }

        fn chain(&self) -> Result<Box<dyn crate::chain::Chain>> {
            self.inner.chain()
        }

        fn dial(&self, addr: &str) -> Result<()> {
            self.inner.dial(addr)
        }

        fn accept(&self, expected: Option<&str>) -> Result<Option<(Box<dyn Transport>, String)>> {
            self.inner.accept(expected)
        }
    }
}
