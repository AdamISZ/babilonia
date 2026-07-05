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

/// Node configuration. Stage 2 carries the sizing/accept knobs as plain fields; Stage 4 adds the
/// proposal/accept *policies* and persistence.
#[derive(Clone, Debug)]
pub struct Config {
    pub network: Network,
    /// Percent of a chosen UTXO to stake (Stage 4 policy; Stage 2 uses `default_stake_sats`).
    pub stake_percent: u8,
    /// Accept incoming proposals without asking the user.
    pub auto_accept: bool,
    /// Fixed stake used by `propose` until the Stage 4 sizing policy lands.
    pub default_stake_sats: u64,
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
            default_stake_sats: 250_000,
            fee_sats: 2_000,
            alice_timeout: 6,
            pi_a_scheme: pi_a::Scheme::Squaring,
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
    /// Establish a peer channel to `addr`.
    fn connect(&self, addr: &str) -> Result<Box<dyn Transport>>;
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

const MSG_ACCEPT: &[u8] = &[2u8];
const MSG_REJECT: &[u8] = &[3u8];

// ---------------------------------------------------------------------------
// Internal channels
// ---------------------------------------------------------------------------

/// The single input to the core loop.
enum Input {
    Command(Command),
    Worker(WorkerEvent),
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
    events: Sender<Event>,
    input_tx: Sender<Input>,
    input_rx: Receiver<Input>,
    peer: Option<PeerHandle>,
    pending: Option<(BetId, u64)>, // (id, stake) awaiting manual Accept/Reject
    next_bet_id: BetId,
}

impl NodeCore {
    /// Build a core over `backend`/`config`. Returns the core, a [`Command`] sender (UI → core), and
    /// an [`Event`] receiver (core → UI) — the swappable UI boundary.
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
        let core = NodeCore {
            backend,
            config,
            events: evt_tx,
            input_tx,
            input_rx,
            peer: None,
            pending: None,
            next_bet_id: 1,
        };
        (core, cmd_tx, evt_rx)
    }

    /// Seed an already-established peer transport (used by tests / when a connection is made out of
    /// band). The real path is the [`Command::Connect`] handler.
    pub fn with_seeded_peer(mut self, addr: impl Into<String>, transport: Box<dyn Transport>) -> Self {
        self.spawn_peer(addr.into(), transport);
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
            }
        }
        if let Some(p) = &self.peer {
            let _ = p.instr.send(Instr::Quit);
        }
    }

    /// Returns `false` on `Quit`.
    fn handle_command(&mut self, cmd: Command) -> bool {
        match cmd {
            Command::Connect { addr } => match self.backend.connect(&addr) {
                Ok(t) => {
                    self.spawn_peer(addr.clone(), t);
                    self.emit(Event::Connected { peer: addr });
                }
                Err(e) => self.emit(Event::Error { msg: format!("connect: {e}") }),
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
        let peer = match &self.peer {
            Some(p) => p,
            None => return self.emit(Event::Error { msg: "no peer connected".into() }),
        };
        let height = match self.backend.chain().and_then(|c| c.block_height()) {
            Ok(h) => h,
            Err(e) => return self.emit(Event::Error { msg: format!("height: {e}") }),
        };
        let terms = ProposeTerms {
            stake_sats: self.config.default_stake_sats,
            fee_sats: self.config.fee_sats,
            refund_locktime: height + REFUND_LOCKTIME_OFFSET,
            alice_timeout: self.config.alice_timeout,
            scheme: if self.config.pi_a_scheme == pi_a::Scheme::Poseidon { 1 } else { 0 },
        };
        let _ = peer.instr.send(Instr::Propose(terms));
        self.emit(Event::Info { msg: format!("proposed a bet of {} sats", terms.stake_sats) });
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
        let ok = match key {
            "auto_accept" => value.parse::<bool>().map(|v| self.config.auto_accept = v).is_ok(),
            "stake_percent" => value.parse::<u8>().map(|v| self.config.stake_percent = v).is_ok(),
            "stake_sats" => value.parse::<u64>().map(|v| self.config.default_stake_sats = v).is_ok(),
            _ => return self.emit(Event::Error { msg: format!("unknown config key '{key}'") }),
        };
        if ok {
            self.emit(Event::Info { msg: format!("{key} = {value}") });
        } else {
            self.emit(Event::Error { msg: format!("bad value for {key}: '{value}'") });
        }
    }

    fn spawn_peer(&mut self, addr: String, transport: Box<dyn Transport>) {
        let (instr_tx, instr_rx) = channel::<Instr>();
        let to_core = self.input_tx.clone();
        let backend = self.backend.clone();
        let config = self.config.clone();
        thread::spawn(move || peer_worker(transport, instr_rx, to_core, backend, config));
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
    config: Config,
) {
    let mut pending_terms: Option<ProposeTerms> = None;
    loop {
        // 1. Incoming control frame?
        match transport.try_recv() {
            Ok(Some(frame)) => {
                if let Some(terms) = ProposeTerms::decode(&frame) {
                    if config.auto_accept {
                        let _ = to_core.send(Input::Worker(WorkerEvent::Info(format!(
                            "auto-accepting bet of {} sats",
                            terms.stake_sats
                        ))));
                        if transport.send(MSG_ACCEPT).is_ok() {
                            run_player(&mut *transport, &backend, &config, terms, &to_core);
                        }
                    } else {
                        let _ = to_core.send(Input::Worker(WorkerEvent::Proposed { stake_sats: terms.stake_sats }));
                        pending_terms = Some(terms);
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

// ---------------------------------------------------------------------------
// Default RPC backend (requires the `node` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "node")]
pub use rpc_backend::RpcBackend;

#[cfg(feature = "node")]
mod rpc_backend {
    use std::path::PathBuf;
    use std::time::Duration;

    use bitcoin::Network;
    use bitcoincore_rpc::{Auth, Client, RpcApi};

    use super::Backend;
    use crate::chain::RpcChain;
    use crate::transport::bip324::Bip324Transport;
    use crate::transport::Transport;
    use crate::wallet::RpcWallet;
    use crate::{Error, Result};

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

        fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
            let c = self.client("")?;
            // Reuse an already-established v2 peer if present (e.g. the *inbound* side of a
            // connection the peer initiated) — so both parties register a worker over the one
            // connection. Otherwise initiate outbound via `addnode` and wait.
            if let Some(id) = first_v2_peer(&c)? {
                return Ok(Box::new(Bip324Transport::new(self.client("")?, id)));
            }
            let _: serde_json::Value = c.call("addnode", &[addr.into(), "add".into()])?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(id) = first_v2_peer(&c)? {
                    return Ok(Box::new(Bip324Transport::new(self.client("")?, id)));
                }
                if std::time::Instant::now() > deadline {
                    return Err(Error::Protocol("peer did not connect over v2 within 30s"));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    /// The node id of the first peer on a BIP324 v2 transport, if any.
    fn first_v2_peer(c: &Client) -> Result<Option<i64>> {
        let peers: serde_json::Value = c.call("getpeerinfo", &[])?;
        Ok(peers.as_array().and_then(|arr| {
            arr.iter()
                .filter(|p| p.get("transport_protocol_type").and_then(|t| t.as_str()) == Some("v2"))
                .filter_map(|p| p.get("id").and_then(|v| v.as_i64()))
                .next()
        }))
    }
}
