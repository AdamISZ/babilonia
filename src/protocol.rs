//! The setup + settlement state machine. Phases are types so an out-of-order step (e.g. funding
//! before RefundTx is pre-signed) is a compile error, not a footgun.
//!
//! Setup runs over L1 while both parties cooperate; the invariant is that money only enters
//! `Q_fund` once every recovery/settlement spend is pre-signed.

use crate::params::Params;
use crate::proofs::Verifier;
use crate::{Outcome, Result, Role};

/// Phase 0 — proposal exchanged, proofs verified, keys aggregated. Nothing on-chain.
pub struct Negotiated {
    pub role: Role,
    pub params: Params,
}

/// Phase 1 — TX1 is fixed (inputs+outputs), so every downstream outpoint is known and the
/// pre-signing chain can run. Still nothing broadcast.
pub struct Pinned {
    pub role: Role,
    pub params: Params,
}

/// Phase 2 — RefundTx + ChallengeTx + both settlements pre-signed and verified. Safe to fund.
pub struct Armed {
    pub role: Role,
    pub params: Params,
}

/// Phase 3 — TX1 broadcast/confirmed; the game is live.
pub struct Live {
    pub role: Role,
    pub params: Params,
}

impl Negotiated {
    /// Alice assembles her proposal; Bob validates it and both `π_a`/`π_r` before proceeding.
    pub fn begin<V: Verifier>(
        role: Role,
        params: Params,
        _verifier: &V,
    ) -> Result<Self> {
        if !params.is_wellformed() {
            return Err(crate::Error::Protocol("malformed proposal params"));
        }
        Ok(Negotiated { role, params })
    }

    /// Fix TX1 → derive `Q_fund`/`Q'`/settlement outpoints.
    pub fn pin(self) -> Result<Pinned> {
        todo!("fix TX1, derive Q_fund and the pre-signing chain of outpoints")
    }
}

impl Pinned {
    /// Exchange + verify all pre-signatures. Enforces the fund-only-after-refund invariant.
    pub fn arm(self) -> Result<Armed> {
        todo!("pre-sign RefundTx, ChallengeTx, SettleBobWins, SettleAliceWins; verify")
    }
}

impl Armed {
    /// Broadcast TX1 and wait for confirmation.
    pub fn fund(self) -> Result<Live> {
        todo!("broadcast TX1, await confirmation")
    }
}

impl Live {
    /// Alice's outcome-blind reveal: broadcast ChallengeTx, publishing `t`.
    pub fn reveal(&self) -> Result<()> {
        if self.role != Role::Alice {
            return Err(crate::Error::Protocol("only Alice reveals"));
        }
        todo!("complete ChallengeTx adaptor, broadcast, create Q'")
    }

    /// Settle `Q'` once the outcome is known: try the cooperative close, else the appropriate
    /// unilateral fallback.
    pub fn settle(&self, _outcome: Outcome) -> Result<()> {
        todo!("cooperative close if both online, else SettleBobWins / SettleAliceWins")
    }
}
