//! The reveal & Bob's claim (JOIN-CONSTRUCTION §2, §4, §5) — hash-free.
//!
//! The reveal is the adaptor secret `h_c` itself: Alice completes ChallengeTx's adaptor (point
//! `H_c`) with `h_c`, and Bob recovers it from the on-chain signature via [`crate::musig::extract`].
//! There is no `hash_p`, no `t⁻¹·X` back-solve, no `A_i` — Bob works with `h_c` directly.
//!
//! ```text
//! win  ⟺  H_c = H_y     (equivalently h_c = h_y),  Bob guessed right
//! K    = W_b + H_y      Bob's pot-claim key (W_b hidden claim key, distinct from funding P_b)
//! dlog(K) = w_b + h_y   Bob's claim secret — computable iff he won (h_y = h_c revealed)
//! ```

use musig2::secp::{Point, Scalar};

use crate::{Error, Result};

/// Bob's win test: does the revealed scalar `h_c` correspond to the thimble he guessed?
/// (`h_c·G == H_y`.)
pub fn won(h_revealed: &Scalar, h_guessed_point: &Point) -> bool {
    h_revealed.base_point_mul() == *h_guessed_point
}

/// Bob's pot-claim key `K = W_b + H_y`, where `W_b` is his **hidden claim key** (a public point
/// here) and `H_y` the thimble he guessed. `W_b` MUST be distinct from Bob's funding key `P_b`
/// (which appears in `Q`), or Alice would recover it and learn `y` — see JOIN-CONSTRUCTION §5.
pub fn compute_k(w_b_point: &Point, h_guessed_point: &Point) -> Result<Point> {
    (*w_b_point + *h_guessed_point)
        .not_inf()
        .map_err(|_| Error::Protocol("W_b + H_y is the identity"))
}

/// The discrete log of `K`: `dlog(K) = w_b + h_y`. Bob can form it **only** once `h_y` (= the
/// revealed `h_c`) is known and matches his guess (he won). Completing SettleBobWins's adaptor
/// with it is his claim. Invariant: `claim_secret(w_b, h)·G == compute_k(w_b·G, h·G)`.
pub fn claim_secret(w_b: &Scalar, h_win: &Scalar) -> Result<Scalar> {
    (*w_b + *h_win)
        .not_zero()
        .map_err(|_| Error::Protocol("w_b + h_win is zero"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    fn scalar(s: secp256k1::SecretKey) -> Scalar {
        s.into()
    }

    #[test]
    fn win_check_and_k_relation() {
        let secp = secp256k1::Secp256k1::new();

        // Alice's chosen thimble scalar/point, and Bob's guessed thimble point.
        let h_c = scalar(Keypair::new(&secp).sk);
        let h_c_point = h_c.base_point_mul();

        // Bob's hidden claim key W_b (distinct from any funding key).
        let w_b = scalar(Keypair::new(&secp).sk);
        let w_b_point = w_b.base_point_mul();

        // A win: Bob guessed the chosen thimble.
        assert!(won(&h_c, &h_c_point));
        let k = compute_k(&w_b_point, &h_c_point).unwrap();
        let secret = claim_secret(&w_b, &h_c).unwrap(); // dlog(K)
        assert_eq!(secret.base_point_mul(), k, "dlog(K)·G == K");

        // A loss: an unrelated thimble point.
        let other = scalar(Keypair::new(&secp).sk).base_point_mul();
        assert!(!won(&h_c, &other));
    }
}
