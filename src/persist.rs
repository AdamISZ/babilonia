//! Crash-recoverable **bet records**: the full in-memory bet state serialized to disk (JSON),
//! rewritten atomically at each phase transition, so either party can complete or recover *any* step
//! after a crash — broadcast the refund, (re)settle, observe+claim, or reclaim the timeout leaf.
//!
//! The `KeyAgg` and `ClaimOutput` are *not* stored: they're derived on recovery from `p_a`/`p_b`/`k`
//! and `alice_timeout`. Nothing in recovery needs the aggregate signing context — all the signatures
//! that context produced (`settle_pre`, `refund_sig`) are already captured here.
//!
//! **Secrets are stored in clear** (seed/keys/`d`). Encryption at rest is a deliberate follow-on.

use std::path::Path;

use bitcoin::Transaction;
use musig2::secp::{Point, Scalar};
use musig2::{AdaptorSignature, LiftedSignature};
use serde::{Deserialize, Serialize};

use crate::bet::BetRole;
use crate::setup::GameParams;
use crate::{Error, Result};

/// How far the bet has progressed — tells a recovering party what remains to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Funding tx built + `U1` located; nothing pre-signed yet. Abort is safe — funding isn't broadcast.
    Funded,
    /// Setup done: refund + settlement pre-signed. The refund is now the safety net.
    SetupDone,
    /// Funding broadcast and confirmed; `U1` is live on-chain.
    FundingBroadcast,
    /// Dealer settled (posted `d`) — or the player observed the settlement on-chain.
    Settled,
    /// Player extracted `d`, recovered `a_c`, decided the outcome.
    Observed,
    /// Terminal: resolved (claimed / reclaimed / refunded).
    Done,
}

/// The persistable setup artifacts (a `SetupResult` minus the derived `KeyAgg`).
#[derive(Clone, Serialize, Deserialize)]
pub struct SetupData {
    pub settle_tx: Transaction,
    pub settle_pre: AdaptorSignature,
    pub refund_tx: Transaction,
    pub refund_sig: LiftedSignature,
    pub ctxt: Scalar,
    pub d_point: Point,
    pub k: Point,
    pub thimbles: [Point; 2],
    pub p_a: Point,
    /// Dealer only: the pre-signed 2-out CSV-leaf reclaim of `O_K` (enforced Alice-win). Valid only
    /// after the relative timelock `t_1`; built + witnessed at setup so recovery just broadcasts it.
    /// `None` for the player. See COVERT-TX-PLAN §8.
    #[serde(default)]
    pub reclaim_tx: Option<Transaction>,
}

/// The full recoverable state of one party's bet.
#[derive(Clone, Serialize, Deserialize)]
pub struct BetRecord {
    /// Unique id (also the filename stem).
    pub id: String,
    pub phase: Phase,
    /// Our role + private inputs (Alice/Bob secrets).
    pub role: BetRole,
    pub params: GameParams,
    pub funding_tx: Option<Transaction>,
    pub setup: Option<SetupData>,
    pub recovered_a_c: Option<Scalar>,
}

impl BetRecord {
    /// Atomically write to `<dir>/<id>.json` (write-temp + rename, so a crash mid-write can't corrupt
    /// an existing record).
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let json =
            serde_json::to_string_pretty(self).map_err(|_| Error::Protocol("serialize bet record"))?;
        let path = dir.join(format!("{}.json", self.id));
        let tmp = dir.join(format!("{}.json.tmp", self.id));
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Load a record from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|_| Error::Decode("bet record json"))
    }
}

/// A fresh, unique bet id (random 128-bit, hex).
pub fn new_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}
