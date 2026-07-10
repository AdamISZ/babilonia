//! Crash recovery — drive the remaining on-chain actions from a persisted [`BetRecord`], with **no
//! live peer**. Every action mirrors the in-memory [`bet`](crate::bet) path (settle / observe+claim /
//! timeout-reclaim / refund), but reads its inputs from the record instead of `self`, so a party that
//! restarted after a crash can still do whatever it needs to.

use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair as BKeypair, Message, SecretKey};
use bitcoin::{Amount, OutPoint, Sequence, TxOut, Witness, XOnlyPublicKey};
use musig2::secp::{Point, Scalar};
use musig2::CompactSignature;

use crate::bet::BetRole;
use crate::chain::Chain;
use crate::musig::{adapt, extract, signature_bytes};
use crate::persist::{BetRecord, Phase, SetupData};
use crate::reveal::{claim_secret, recover_a_c, won};
use crate::txgraph::{build_claim_spend, key_spend_sighash, split_payment, ClaimOutput};
use crate::wallet::Wallet;
use crate::{Error, Result};

/// A human-readable assessment of what a record needs, checked against the chain.
pub struct Assessment {
    pub id: String,
    pub phase: Phase,
    pub role: &'static str,
    /// What the situation is / what `recover` would do.
    pub summary: String,
    /// Whether [`recover`] can act on it *right now*.
    pub actionable: bool,
}

fn role_str(role: &BetRole) -> &'static str {
    match role {
        BetRole::Dealer(_) => "dealer",
        BetRole::Player(_) => "player",
    }
}

fn x_only(p: &Point) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&p.serialize()[1..33]).map_err(|_| Error::Protocol("bad x-only key"))
}

/// Value of the settlement's claim output `O_K` — the at-risk pot `S = a + b` (Alice's parked `c_A`
/// returns as the settlement's other output, not through `O_K`).
fn pot(rec: &BetRecord) -> Result<Amount> {
    Ok(rec.params.alice_stake + rec.params.bob_stake)
}

/// Inspect a record against the chain and summarize the recovery situation.
pub fn assess(rec: &BetRecord, chain: &dyn Chain) -> Result<Assessment> {
    let role = role_str(&rec.role);
    let mk = |summary: String, actionable: bool| Assessment {
        id: rec.id.clone(),
        phase: rec.phase,
        role,
        summary,
        actionable,
    };
    if rec.phase == Phase::Done {
        return Ok(mk("resolved — nothing to do".into(), false));
    }
    let Some(setup) = &rec.setup else {
        // Only Funded: funding was never broadcast (setup incomplete), so no funds are committed.
        return Ok(mk("setup incomplete; no funds committed on-chain".into(), false));
    };
    let u1_live = chain.utxo_unspent(rec.params.u1_outpoint)?;
    let settle_txid = setup.settle_tx.compute_txid();
    let height = chain.block_height()?;

    if u1_live {
        // Pot still in U1 — not yet settled or refunded.
        return Ok(match &rec.role {
            BetRole::Dealer(_) => mk("U1 unspent — re-broadcast the settlement (posts d)".into(), true),
            BetRole::Player(_) => {
                let refund_hint = if height >= rec.params.refund_locktime {
                    " (or `recover <id> refund` to reclaim now)"
                } else {
                    ""
                };
                mk(format!("waiting for the dealer to settle{refund_hint}"), false)
            }
        });
    }

    // U1 is spent. Settled (by the settlement) or refunded elsewhere?
    if chain.get_transaction(settle_txid)?.is_none() {
        return Ok(mk("U1 already spent (refunded / by another path) — nothing to do".into(), false));
    }
    let claim_out = OutPoint { txid: settle_txid, vout: 0 };
    if !chain.utxo_unspent(claim_out)? {
        return Ok(mk("settlement claimed already — resolved".into(), false));
    }
    match &rec.role {
        BetRole::Player(_) => Ok(mk("settlement on-chain — extract d and claim if you won".into(), true)),
        BetRole::Dealer(_) => {
            let confs = chain.confirmations(settle_txid)?.unwrap_or(0);
            if confs >= rec.params.alice_timeout as u32 {
                Ok(mk("player never claimed — reclaim via the timeout leaf".into(), true))
            } else {
                Ok(mk(
                    format!("waiting for the player to claim, or the {}-conf timeout ({confs} so far)", rec.params.alice_timeout),
                    false,
                ))
            }
        }
    }
}

/// Execute the forward recovery action for a record (settle / observe+claim / reclaim), returning a
/// human summary. Use [`broadcast_refund`] for the abort path instead.
pub fn recover(rec: &BetRecord, chain: &dyn Chain, wallet: &dyn Wallet) -> Result<String> {
    let setup = rec.setup.as_ref().ok_or(Error::Protocol("no setup in record — nothing to recover"))?;
    let u1_live = chain.utxo_unspent(rec.params.u1_outpoint)?;
    if u1_live {
        return match &rec.role {
            BetRole::Dealer(_) => settle_action(rec, setup, chain),
            BetRole::Player(_) => Err(Error::Protocol("only the dealer can settle; wait, or `refund` after the locktime")),
        };
    }
    let settle_txid = setup.settle_tx.compute_txid();
    if chain.get_transaction(settle_txid)?.is_none() {
        return Err(Error::Protocol("U1 already spent by another path (refunded?) — nothing to recover"));
    }
    match &rec.role {
        BetRole::Player(_) => observe_and_claim(rec, setup, chain, wallet),
        BetRole::Dealer(_) => reclaim_action(rec, setup, chain),
    }
}

/// Broadcast the fully-signed refund (the abort/reclaim path) — returns the pot to both funders. The
/// chain must have passed `refund_locktime`, and U1 must still be unspent.
pub fn broadcast_refund(rec: &BetRecord, chain: &dyn Chain) -> Result<String> {
    let setup = rec.setup.as_ref().ok_or(Error::Protocol("no setup — no refund exists"))?;
    let height = chain.block_height()?;
    if height < rec.params.refund_locktime {
        return Err(Error::Protocol("refund not spendable yet (before its locktime)"));
    }
    let mut refund = setup.refund_tx.clone();
    refund.input[0].witness = Witness::from_slice(&[signature_bytes(&setup.refund_sig).as_slice()]);
    let txid = chain.broadcast(&refund)?;
    Ok(format!("broadcast the refund {txid} — pot returned to both funders"))
}

// --- individual actions (mirror the Bet's private methods, driven from the record) ---

fn settle_action(rec: &BetRecord, setup: &SetupData, chain: &dyn Chain) -> Result<String> {
    let d = match &rec.role {
        BetRole::Dealer(a) => a.d,
        BetRole::Player(_) => return Err(Error::Protocol("only the dealer settles")),
    };
    let sig = adapt(&setup.settle_pre, &d).ok_or(Error::Protocol("settlement adapt failed"))?;
    let mut tx = setup.settle_tx.clone();
    tx.input[0].witness = Witness::from_slice(&[signature_bytes(&sig).as_slice()]);
    let txid = chain.broadcast(&tx)?;
    Ok(format!("re-broadcast the settlement {txid} (posts d on-chain)"))
}

fn observe_and_claim(rec: &BetRecord, setup: &SetupData, chain: &dyn Chain, wallet: &dyn Wallet) -> Result<String> {
    let (w_b, guess) = match &rec.role {
        BetRole::Player(p) => (Scalar::from(p.claim.sk), p.guess),
        BetRole::Dealer(_) => return Err(Error::Protocol("only the player observes/claims")),
    };
    let settle_txid = setup.settle_tx.compute_txid();
    let stx = chain.get_transaction(settle_txid)?.ok_or(Error::Protocol("settlement not on-chain yet"))?;
    // Extract d from the settlement's completed adaptor signature.
    let sig_bytes = stx.input[0].witness.iter().next().ok_or(Error::Protocol("no settlement witness"))?;
    let compact = CompactSignature::from_bytes(sig_bytes).map_err(|_| Error::Protocol("bad settlement sig"))?;
    let final_sig = compact.lift_nonce().map_err(|_| Error::Protocol("cannot lift settlement sig"))?;
    let d = extract(&setup.settle_pre, &final_sig)
        .and_then(|m| m.into_option())
        .ok_or(Error::Protocol("could not extract d from settlement"))?;
    let a_c = recover_a_c(rec.params.pi_a_scheme, &setup.ctxt, &d)?;
    if !won(&a_c, &setup.thimbles[guess]) {
        return Ok("outcome: you lost — nothing to claim (the dealer reclaims after the timeout)".into());
    }
    // Won → key-path spend of the claim output (K = W_b + A_y; dlog = w_b + a_c), 2-out payment shape.
    let claim = ClaimOutput::new(setup.k, x_only(&setup.p_a)?, rec.params.alice_timeout)?;
    let pot = pot(rec)?;
    let out_value = pot.checked_sub(rec.params.fee).ok_or(Error::Protocol("fee exceeds claim"))?;
    let (pay, change) = split_payment(out_value)?;
    let pay_addr = wallet.receive_address()?;
    let change_addr = wallet.change_address()?;
    let claim_out = OutPoint { txid: settle_txid, vout: 0 };
    let mut tx = build_claim_spend(
        claim_out,
        Sequence::default(),
        vec![
            TxOut { value: pay, script_pubkey: pay_addr.script_pubkey() },
            TxOut { value: change, script_pubkey: change_addr.script_pubkey() },
        ],
    );
    let claim_sk = claim_secret(&w_b, &a_c)?;
    let sighash = key_spend_sighash(&tx, 0, &[claim.txout(pot)])?;
    let bsecp = bitcoin::secp256k1::Secp256k1::new();
    let sk = SecretKey::from_slice(&claim_sk.serialize()).map_err(|_| Error::Protocol("bad claim key"))?;
    let tweaked = BKeypair::from_secret_key(&bsecp, &sk).tap_tweak(&bsecp, claim.spend_info.merkle_root());
    let sig = bsecp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), &tweaked.to_keypair()).serialize();
    tx.input[0].witness = Witness::from_slice(&[sig.as_slice()]);
    let txid = chain.broadcast(&tx)?;
    Ok(format!("you won — claimed the pot via key-path, broadcast {txid}"))
}

fn reclaim_action(rec: &BetRecord, setup: &SetupData, chain: &dyn Chain) -> Result<String> {
    if !matches!(rec.role, BetRole::Dealer(_)) {
        return Err(Error::Protocol("only the dealer reclaims"));
    }
    let settle_txid = setup.settle_tx.compute_txid();
    let confs = chain.confirmations(settle_txid)?.unwrap_or(0);
    if confs < rec.params.alice_timeout as u32 {
        return Err(Error::Protocol("timeout leaf not mature yet (needs alice_timeout confirmations)"));
    }
    // The 2-out CSV-leaf reclaim was fully witnessed at setup (COVERT-TX-PLAN §8) — just broadcast it.
    let tx = setup.reclaim_tx.as_ref().ok_or(Error::Protocol("no pre-signed reclaim tx in record"))?;
    let txid = chain.broadcast(tx)?;
    Ok(format!("reclaimed the pot via the pre-signed timeout leaf, broadcast {txid}"))
}
