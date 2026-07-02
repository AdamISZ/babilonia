//! Babilonia — L2 core for the OP_RAND-emulation "lottery-as-mix".
//!
//! Geometry: **join** (single funding tx). Settlement follows the δ-split, fully-keypath
//! model of `JOIN-CONSTRUCTION.md` §5a:
//!
//! ```text
//! TX1 ─► Q_fund = MuSig2(P_a,P_b) ─┬─ RefundTx   (nLockTime T2)          [no-reveal fallback]
//!                                  └─ ChallengeTx (Alice adaptor, leaks t) ─► Q'
//! Q' = MuSig2(P_a,P_b) keypath, spent by exactly one of:
//!   (1) cooperative close   — fresh MuSig2 split, both sign live         [normal, fully clean]
//!   (2) SettleBobWins       — pre-signed, Alice partial adaptor-locked on K_b (Bob completes
//!                             iff he won), fixed split {d_B+δ, d_A−δ}
//!   (3) SettleAliceWins     — pre-signed by both, nSequence=N from Q', fixed split {d_A+δ, d_B−δ}
//! ```
//!
//! Roles: **Alice = Challenger/chooser**, **Bob = Accepter/guesser**. Bob wins iff `j* = i*`.
//!
//! Status: scaffold. Crypto (MuSig2/adaptor), tx construction, and the sigma proofs are
//! typed interfaces with stubbed bodies; the setup/settlement state machine and the reveal
//! algebra are the spine to fill in. Proofs are assume-valid until the plumbing is proven on
//! regtest (see `proofs`).

pub mod keys;
pub mod messages;
pub mod musig;
pub mod params;
pub mod proofs;
pub mod protocol;
pub mod setup;
pub mod regtest;
pub mod reveal;
pub mod thimbles;
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
