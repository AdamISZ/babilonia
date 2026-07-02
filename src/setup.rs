//! Interactive setup driver (hash-free, Bob-commits-first): Alice and Bob play the commit-blind
//! exchange over any [`Transport`], ending with a shared public view and the aggregated key
//! `Q = MuSig2(P_a, P_b)` (JOIN-CONSTRUCTION §3, PROTOCOL.md §2–§3).
//!
//! Alice sends her thimbles first (`Open`); Bob commits his pick (`Accept`: `K`, `π_r`) — this is
//! the commit-blind order (Alice's adaptor pre-signature does not exist yet, so nothing leaks
//! her choice). Proof verification goes through a [`Verifier`] (AssumeValid for now). The
//! pre-signing/funding flights are a later stage that consumes this state.
//!
//! **Two Bob keys.** Bob's *funding* key `P_b` is public (it enters `Q`); his *claim* key `W_b`
//! is hidden and only appears blinded in `K = W_b + H_y`. If `K` reused `P_b`, Alice would
//! recover it from `Q` and learn `y` — so they must differ.

use musig2::secp::Point;

use crate::keys::Keypair;
use crate::messages::{Accept, Open};
use crate::musig::KeyAgg;
use crate::proofs::{ProofA, ProofR, Verifier};
use crate::reveal::compute_k;
use crate::thimbles::Thimbles;
use crate::transport::Transport;
use crate::{Error, Result};

/// Game parameters Alice fixes in her opening offer (Bob adds his stake in `Accept`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GameParams {
    pub alice_stake: u64,
    pub delta: u64,
    pub reveal_window: u16,
    pub refund_locktime: u32,
}

/// Alice's private setup inputs.
pub struct AliceSecrets {
    /// Public identity/funding key `P_a`.
    pub identity: Keypair,
    /// Her two thimbles and secret choice `c`.
    pub thimbles: Thimbles,
}

/// Bob's private setup inputs.
pub struct BobSecrets {
    /// Public funding key `P_b` (enters `Q`).
    pub funding: Keypair,
    /// Hidden claim key `W_b` (`K = W_b + H_y`).
    pub claim: Keypair,
    /// Guess `y ∈ {0,1}`.
    pub guess: usize,
    pub stake: u64,
}

/// Shared public result of setup — identical on both sides.
pub struct SetupState {
    pub params: GameParams,
    pub bob_stake: u64,
    pub p_a: Point,
    /// Bob's public funding key.
    pub p_b: Point,
    /// Thimbles `[H_1, H_2]`.
    pub h: [Point; 2],
    /// Bob's pot-claim key `K = W_b + H_y`.
    pub k: Point,
    /// `Q = MuSig2(P_a, P_b)` with the key-path taproot tweak.
    pub keyagg: KeyAgg,
}

/// Run Alice's side: send her thimbles, receive and verify Bob's commitment.
pub fn run_alice<T: Transport, V: Verifier>(
    ch: &mut T,
    verifier: &V,
    params: GameParams,
    s: &AliceSecrets,
) -> Result<SetupState> {
    let p_a: Point = s.identity.pk.into();
    let [h1, h2] = s.thimbles.points();

    ch.send(
        &Open {
            alice_stake: params.alice_stake,
            delta: params.delta,
            reveal_window: params.reveal_window,
            refund_locktime: params.refund_locktime,
            p_a,
            h1,
            h2,
            pi_a: vec![], // AssumeValid
        }
        .encode(),
    )?;

    let accept = Accept::decode(&ch.recv()?)?;
    verifier.verify_pi_r(&ProofR { bytes: accept.pi_r })?;

    let p_b_pub: secp256k1::PublicKey = accept.p_b.into();
    let keyagg = KeyAgg::new_taproot([s.identity.pk, p_b_pub])?;

    Ok(SetupState {
        params,
        bob_stake: accept.bob_stake,
        p_a,
        p_b: accept.p_b,
        h: [h1, h2],
        k: accept.k,
        keyagg,
    })
}

/// Run Bob's side: receive + verify Alice's thimbles, commit his pick.
pub fn run_bob<T: Transport, V: Verifier>(
    ch: &mut T,
    verifier: &V,
    s: &BobSecrets,
) -> Result<SetupState> {
    if s.guess >= 2 {
        return Err(Error::Protocol("guess out of range (expected 0 or 1)"));
    }

    let open = Open::decode(&ch.recv()?)?;
    verifier.verify_pi_a(&ProofA { bytes: open.pi_a })?;
    if open.h1 == open.h2 {
        return Err(Error::Protocol("degenerate thimbles: H_1 == H_2"));
    }
    let h = [open.h1, open.h2];

    let p_b: Point = s.funding.pk.into();
    let w_b: Point = s.claim.pk.into();
    let k = compute_k(&w_b, &h[s.guess])?; // K = W_b + H_y

    ch.send(&Accept { bob_stake: s.stake, p_b, k, pi_r: vec![] }.encode())?;

    let p_a_pub: secp256k1::PublicKey = open.p_a.into();
    let keyagg = KeyAgg::new_taproot([p_a_pub, s.funding.pk])?;

    Ok(SetupState {
        params: GameParams {
            alice_stake: open.alice_stake,
            delta: open.delta,
            reveal_window: open.reveal_window,
            refund_locktime: open.refund_locktime,
        },
        bob_stake: s.stake,
        p_a: open.p_a,
        p_b,
        h,
        k,
        keyagg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proofs::AssumeValid;
    use crate::reveal::claim_secret;
    use crate::transport::memory::channel_pair;
    use musig2::secp::Scalar;

    fn scalar(secp: &secp256k1::Secp256k1<secp256k1::All>) -> Scalar {
        Scalar::from(Keypair::new(secp).sk)
    }

    #[test]
    fn setup_handshake_agrees() {
        let secp = secp256k1::Secp256k1::new();

        let c = 1usize;
        let thimbles = Thimbles::new(scalar(&secp), scalar(&secp), c);
        let h_chosen = thimbles.chosen().h_point;
        let alice = AliceSecrets { identity: Keypair::new(&secp), thimbles };
        let bob = BobSecrets {
            funding: Keypair::new(&secp),
            claim: Keypair::new(&secp),
            guess: c, // a winning guess
            stake: 100_000,
        };
        // Snapshots for the post-run check (Scalar/Point are Copy).
        let w_b = Scalar::from(bob.claim.sk);
        let params = GameParams { alice_stake: 100_000, delta: 10_000, reveal_window: 6, refund_locktime: 200 };

        let (mut alice_ch, mut bob_ch) = channel_pair();
        let bob_handle = std::thread::spawn(move || run_bob(&mut bob_ch, &AssumeValid, &bob));
        let a_state = run_alice(&mut alice_ch, &AssumeValid, params, &alice).unwrap();
        let b_state = bob_handle.join().unwrap().unwrap();

        // Identical shared view.
        assert_eq!(a_state.keyagg.agg_xonly(), b_state.keyagg.agg_xonly());
        assert_eq!(a_state.p_a, b_state.p_a);
        assert_eq!(a_state.p_b, b_state.p_b);
        assert_eq!(a_state.h, b_state.h);
        assert_eq!(a_state.k, b_state.k);
        assert_eq!(a_state.params, b_state.params);
        assert_eq!(a_state.bob_stake, b_state.bob_stake);

        // Bob guessed c: K is built against the chosen thimble, and equals W_b + H_c.
        assert_eq!(b_state.h[c], h_chosen);
        assert_eq!(b_state.k, compute_k(&w_b.base_point_mul(), &h_chosen).unwrap());
        // The claim secret w_b + h_c has K as its public key (Bob could claim on a win).
        assert_eq!(
            claim_secret(&w_b, &thimbles.chosen().h).unwrap().base_point_mul(),
            b_state.k
        );

        // Alice cannot recover y: she holds K, P_b, H_1, H_2 but not W_b, and K − P_b ≠ H_y.
        let p_b: Point = b_state.p_b;
        for hy in b_state.h {
            assert_ne!((a_state.k + (-(p_b))).not_inf().ok(), Some(hy));
        }
    }
}
