//! Babilonia — L2 core for the OP_RAND-emulation "lottery-as-mix".
//!
//! Geometry: **join** (adaptor spec **v5**, `docs/adaptor_construction_spec_v5.tex`). One
//! jointly-funded output; the settlement's *own* adaptor witness `d` is the released decryption
//! key (v4 used a second output for this; v5 folds it into the settlement, and an even earlier
//! single-adaptor design had no atomic-and-hiding message order — see v5 §1):
//!
//! ```text
//! TX1 ─► U1 (pot, MuSig2(P_a,P_b)) ─┬─ RefundTx  (spends U1; nLockTime t_r)   [fallback]
//!                                   └─ SettleTx  (spends U1; adaptor on D=d·G → POSTS d)
//!        ─► ClaimOutput = P2TR(internal K): Bob-wins = key-path spend of K; one leaf <t_1> CSV <P_a>
//! ```
//!
//! **Interlock:** Alice cannot spend `U1` (get the pot) without completing the settlement adaptor,
//! which posts the fresh, outcome-independent dealer secret `d`. Bob then decrypts
//! `a_c = ctxt − H(d)` (`ctxt = a_c + H(d)`, RO hash — a linear pad would leak `c`), and if he won
//! (`a_c·G = A_y`) claims `K = W_b + A_y` with `w_b + a_c` (`W_b` = Bob's hidden claim key, ≠ his
//! funding key). Roles: **Alice = chooser** (`c`), **Bob = guesser** (`y`); Bob wins iff `y = c`.
//!
//! Status: **v5 rework in progress.** Done + regtest-validated: the tx graph (`txgraph`), the
//! encrypted-outcome reveal (`reveal`), and the `π_a` **Σ-part** / `π_r` / thimble PoKs (`sigma`).
//! Pending: the `π_a` **hash circuit** (`sigma::prove_recovery_circuit`, backend TBD) and the v5
//! **message flow** (`setup`/`messages` still run the pre-v5 handshake). L1 BIP324 covert transport
//! is wired (`transport::bip324`, `node` feature). The `proofs` module's `AssumeValid` is vestigial.

/// The game — business logic only (roles, outcome, the bet sequence); no bitcoin.
pub mod game;
/// π_a — the encrypted-outcome well-formedness proof, behind a narrow mechanism-agnostic interface.
/// The interface is always compiled; the `pi_a` feature swaps in the real Bulletproofs+Poseidon
/// hash-circuit implementation (else Σ-part + SHA-256 pad).
pub mod pi_a;
/// The node layer — translates game verbs into bitcoin transactions, over the [`wallet::Wallet`],
/// [`chain::Chain`] and [`transport::Transport`] traits (no direct RPC).
pub mod bet;
/// The `Chain` trait (block/tx view) + the default `RpcChain`. One of the swappable components.
pub mod chain;
pub mod keys;
pub mod messages;
pub mod musig;
pub mod params;
pub mod proofs;
pub mod protocol;
pub mod setup;
/// The `Wallet` trait (funding/addresses/PSBT) + the default `RpcWallet`. Swappable component.
pub mod wallet;
/// A party's local Bitcoin node — RPC/wallet, network, p2p, and the BIP324 transport (requires
/// the `node` feature). The infra the node layer builds bet transactions on.
#[cfg(feature = "node")]
pub mod node;
pub mod reveal;
pub mod sigma;
pub mod transport;
pub mod txgraph;

/// Which side of the table a party sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Chooser: fixes `i*`, owns the reveal, wins on timeout.
    Alice,
    /// Guesser: fixes `j*`, wins immediately on a correct guess.
    Bob,
}

/// The realized coin outcome, known only after the reveal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `j* == i*` — Bob guessed right.
    BobWins,
    /// `j* != i*` — Alice keeps the swing.
    AliceWins,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("secp256k1: {0}")]
    Secp(#[from] secp256k1::Error),
    #[error("musig2: {0}")]
    Musig(String),
    #[cfg(feature = "node")]
    #[error("bitcoin rpc: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport: {0}")]
    Transport(&'static str),
    #[error("decode: {0}")]
    Decode(&'static str),
    #[error("proof {0} failed verification")]
    ProofInvalid(&'static str),
    #[error("protocol misuse: {0}")]
    Protocol(&'static str),
    #[error("not yet implemented: {0}")]
    Todo(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
