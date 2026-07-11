//! The game — **business logic only**. Roles, the outcome, and the *sequence* of a bet, expressed
//! against an abstract [`BetChain`] whose verbs the node layer (`bet`) implements as real Bitcoin
//! transactions. Nothing here touches a transaction, a signature, or a sighash: swap in a mock
//! `BetChain` and this same flow runs with no bitcoind.
//!
//! The v5 game: Alice is the **Dealer** (picks `c`, deals the encrypted outcome, must settle to be
//! paid); Bob is the **Player** (picks `y`, wins iff `y = c`). The dealer settling posts `d`, which
//! lets the player decrypt the outcome and — if he won — claim the pot; otherwise the dealer
//! reclaims after the timeout.

use crate::Result;

/// Which side of the table a party sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Alice — deals the encrypted outcome and settles to be paid.
    Dealer,
    /// Bob — guesses, and claims iff he won.
    Player,
}

/// The realised result of the bet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Bob guessed right (`y = c`).
    PlayerWins,
    /// Bob guessed wrong.
    DealerWins,
}

/// The Bitcoin-facing verbs a game step needs. The **only** seam between business logic and
/// transactions — implemented by the node layer (`crate::bet`). Each verb performs one on-chain /
/// interactive action; the game logic never sees a transaction.
pub trait BetChain {
    /// Establish the jointly-funded pot `U1` (both stakes). Interactive.
    fn fund_pot(&mut self) -> Result<()>;
    /// Run the interactive setup: pre-sign the refund and the settlement adaptor, commit the
    /// encrypted outcome. Interactive.
    fn setup(&mut self) -> Result<()>;
    /// **Sign** the funding transaction (the signatures are deliberately deferred to here), broadcast
    /// it, and wait for `U1` to confirm. Runs only **after** the refund is pre-signed, so the first
    /// broadcastable funding tx to exist anywhere is created with its refund already in hand — no funds
    /// can be locked into `U1` without a refund. Interactive (a two-message signing exchange).
    fn broadcast_funding(&mut self) -> Result<()>;
    /// Try to resolve the bet cooperatively before touching the chain (COVERT-TX-PLAN §10). The
    /// dealer reveals the outcome off-chain; if the **player lost**, he co-signs a single key-path
    /// `U1 → Alice` spend and both sides finish immediately — no settlement, no `t_1`. Returns
    /// `Some(outcome)` when it resolved this way, or `None` to fall back to the enforced path (the
    /// player won, declined, or is offline). Interactive.
    fn try_cooperative_resolve(&mut self) -> Result<Option<Outcome>>;
    /// **Dealer**: reveal + settle — complete the settlement adaptor (posts `d`) and broadcast it,
    /// so the dealer is paid and the outcome becomes recoverable.
    fn settle(&mut self) -> Result<()>;
    /// Observe the realised [`Outcome`] from the chain (the dealer watches for a claim vs timeout;
    /// the player recovers the reveal and checks his guess).
    fn observe_outcome(&mut self) -> Result<Outcome>;
    /// **Player**: claim the pot with the winning key `K`.
    fn claim_win(&mut self) -> Result<()>;
    /// **Dealer**: take the pot after the timeout when the player lost (didn't claim).
    fn dealer_take_on_loss(&mut self) -> Result<()>;
}

/// The dealer's game: fund → setup → settle (get paid, reveal) → observe → reclaim if the player
/// lost. Returns the realised outcome.
pub fn play_dealer<C: BetChain>(chain: &mut C) -> Result<Outcome> {
    chain.fund_pot()?;
    chain.setup()?;
    chain.broadcast_funding()?;
    // Fast path: if the player concedes a loss, the bet resolves in one cooperative tx.
    if let Some(outcome) = chain.try_cooperative_resolve()? {
        return Ok(outcome);
    }
    chain.settle()?;
    let outcome = chain.observe_outcome()?;
    if matches!(outcome, Outcome::DealerWins) {
        chain.dealer_take_on_loss()?;
    }
    Ok(outcome)
}

/// The player's game: fund → setup → wait for the dealer's settlement → recover the outcome → claim
/// if he won. Returns the realised outcome.
pub fn play_player<C: BetChain>(chain: &mut C) -> Result<Outcome> {
    chain.fund_pot()?;
    chain.setup()?;
    chain.broadcast_funding()?;
    // Fast path: if I lost, I concede here and we finish without any on-chain resolution.
    if let Some(outcome) = chain.try_cooperative_resolve()? {
        return Ok(outcome);
    }
    let outcome = chain.observe_outcome()?;
    if matches!(outcome, Outcome::PlayerWins) {
        chain.claim_win()?;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock backend proving the business flow runs with no Bitcoin at all: it records the verb
    /// sequence and returns a fixed outcome.
    #[derive(Default)]
    struct Mock {
        steps: Vec<&'static str>,
        outcome: Option<Outcome>,
        /// If set, `try_cooperative_resolve` resolves the bet here (the cooperative fast path).
        coop_resolves: Option<Outcome>,
    }
    impl BetChain for Mock {
        fn fund_pot(&mut self) -> Result<()> { self.steps.push("fund"); Ok(()) }
        fn setup(&mut self) -> Result<()> { self.steps.push("setup"); Ok(()) }
        fn broadcast_funding(&mut self) -> Result<()> { self.steps.push("broadcast"); Ok(()) }
        fn try_cooperative_resolve(&mut self) -> Result<Option<Outcome>> { self.steps.push("coop"); Ok(self.coop_resolves) }
        fn settle(&mut self) -> Result<()> { self.steps.push("settle"); Ok(()) }
        fn observe_outcome(&mut self) -> Result<Outcome> { self.steps.push("observe"); Ok(self.outcome.unwrap()) }
        fn claim_win(&mut self) -> Result<()> { self.steps.push("claim"); Ok(()) }
        fn dealer_take_on_loss(&mut self) -> Result<()> { self.steps.push("take"); Ok(()) }
    }

    #[test]
    fn dealer_and_player_sequences() {
        // Player wins: cooperative path declines (None) → observe + claim.
        let mut p = Mock { outcome: Some(Outcome::PlayerWins), ..Default::default() };
        assert_eq!(play_player(&mut p).unwrap(), Outcome::PlayerWins);
        assert_eq!(p.steps, ["fund", "setup", "broadcast", "coop", "observe", "claim"]);

        let mut d = Mock { outcome: Some(Outcome::PlayerWins), ..Default::default() };
        assert_eq!(play_dealer(&mut d).unwrap(), Outcome::PlayerWins);
        assert_eq!(d.steps, ["fund", "setup", "broadcast", "coop", "settle", "observe"]);

        // Dealer wins, enforced fallback (coop returns None): dealer reclaims, player does not claim.
        let mut d = Mock { outcome: Some(Outcome::DealerWins), ..Default::default() };
        assert_eq!(play_dealer(&mut d).unwrap(), Outcome::DealerWins);
        assert_eq!(d.steps, ["fund", "setup", "broadcast", "coop", "settle", "observe", "take"]);

        let mut p = Mock { outcome: Some(Outcome::DealerWins), ..Default::default() };
        assert_eq!(play_player(&mut p).unwrap(), Outcome::DealerWins);
        assert_eq!(p.steps, ["fund", "setup", "broadcast", "coop", "observe"]);
    }

    #[test]
    fn cooperative_resolution_short_circuits() {
        // When the overlay resolves (player conceded a loss), both sides stop right after `coop` —
        // no settle / observe / claim / take.
        let mut d = Mock { coop_resolves: Some(Outcome::DealerWins), ..Default::default() };
        assert_eq!(play_dealer(&mut d).unwrap(), Outcome::DealerWins);
        assert_eq!(d.steps, ["fund", "setup", "broadcast", "coop"]);

        let mut p = Mock { coop_resolves: Some(Outcome::DealerWins), ..Default::default() };
        assert_eq!(play_player(&mut p).unwrap(), Outcome::DealerWins);
        assert_eq!(p.steps, ["fund", "setup", "broadcast", "coop"]);
    }
}
