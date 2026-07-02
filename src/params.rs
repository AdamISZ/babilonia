//! Game parameters — the content of Alice's opening proposal to Bob.
//!
//! v1 defaults (JOIN-CONSTRUCTION §5a): equal stakes, deterministic split = own stake back,
//! a single wager `delta`. Amount/fee shaping for payment-mimicry is deliberately out of scope
//! for the first cut.

use bitcoin::Amount;

/// Everything Alice fixes in her over-the-wire proposal. `delta`-independence of fairness is
/// why Alice may set these unilaterally (Bob consents by accepting).
#[derive(Clone, Copy, Debug)]
pub struct Params {
    /// Each party's stake `S` (equal ⇒ fair p=½ matching-pennies coin).
    pub stake: Amount,
    /// The wager `δ`: swing moved from loser to winner on top of the deterministic split.
    pub delta: Amount,
    /// Bob's guaranteed claim window: `N` blocks, **relative to `Q'`** (BIP68).
    pub reveal_window: u16,
    /// Abort deadline `T2` for the reveal: absolute height on `RefundTx`.
    pub refund_locktime: bitcoin::absolute::LockTime,
    /// Which chain we're on (regtest for the harness).
    pub network: bitcoin::Network,
}

impl Params {
    /// Deterministic share returned to each party before the swing (`d = v = stake`).
    pub fn deterministic_share(&self) -> Amount {
        self.stake
    }

    /// Winner's take: `d + δ`.
    pub fn winner_amount(&self) -> Amount {
        self.stake + self.delta
    }

    /// Loser's take: `d − δ`. Panics if `δ > stake` (an invalid proposal).
    pub fn loser_amount(&self) -> Amount {
        self.stake
            .checked_sub(self.delta)
            .expect("delta must not exceed stake")
    }

    /// Total pot held by `Q_fund` (pre-fee).
    pub fn pot(&self) -> Amount {
        self.stake * 2
    }

    /// Cheap sanity check for a received proposal.
    pub fn is_wellformed(&self) -> bool {
        self.delta <= self.stake && self.reveal_window >= 1
    }
}
