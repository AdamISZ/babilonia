//! Alice's thimbles: the commitment ranks (JOIN-CONSTRUCTION §1, §3). The reveal algebra and
//! the canonical `hash_p` live in [`crate::reveal`]; this module is the commit side and MUST
//! use the same `hash_p` so `H_k` here matches what Bob recomputes on reveal.
//!
//! ```text
//! a_k ← F_p            (thimble secret)
//! A_k = a_k·G          (first-rank commitment)
//! h_k = hash_p(A_k)    (second-rank, scalar)   -- see reveal::hash_p
//! H_k = h_k·G          (third-rank commitment, published)
//! ```

use musig2::secp::{Point, Scalar};

/// One thimble's commitment chain.
#[derive(Clone, Debug)]
pub struct Thimble {
    /// `a_k` — the thimble secret.
    pub a: Scalar,
    /// `A_k = a_k·G`.
    pub a_point: Point,
    /// `h_k = hash_p(A_k)`.
    pub h: Scalar,
    /// `H_k = h_k·G`, the published third-rank commitment.
    pub h_point: Point,
}

impl Thimble {
    /// Derive the full commitment chain from a thimble secret, using the canonical `hash_p`.
    pub fn from_secret(a: Scalar) -> Self {
        let a_point = a.base_point_mul();
        let h = crate::reveal::hash_p(&a_point);
        let h_point = h.base_point_mul();
        Thimble { a, a_point, h, h_point }
    }
}

/// Alice's two thimbles plus her secret choice `i*`.
#[derive(Clone, Debug)]
pub struct Thimbles {
    pub thimbles: [Thimble; 2],
    /// `i* ∈ {0,1}` (0-indexed here; `{1,2}` in the docs).
    pub choice: usize,
}

impl Thimbles {
    /// Build both thimbles from two secrets and record Alice's choice.
    pub fn new(a1: Scalar, a2: Scalar, choice: usize) -> Self {
        debug_assert!(choice < 2);
        Thimbles {
            thimbles: [Thimble::from_secret(a1), Thimble::from_secret(a2)],
            choice,
        }
    }

    /// The chosen thimble `A_{i*}`.
    pub fn chosen(&self) -> &Thimble {
        &self.thimbles[self.choice]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    /// The commit-side `H_{i*}` matches what the reveal side derives from the opened `A_{i*}`.
    #[test]
    fn commit_matches_reveal_derivation() {
        let secp = secp256k1::Secp256k1::new();
        let a1: Scalar = Keypair::new(&secp).sk.into();
        let a2: Scalar = Keypair::new(&secp).sk.into();
        let thimbles = Thimbles::new(a1, a2, 0);

        let chosen = thimbles.chosen();
        // Bob, given the opened A_{i*}, recomputes h_{i*}·G and it equals the committed H_{i*}.
        let derived = crate::reveal::bob_derive_win_scalar(&chosen.a_point, &chosen.h_point);
        assert_eq!(derived, Some(chosen.h));
    }
}
