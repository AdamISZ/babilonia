//! Alice's thimbles (JOIN-CONSTRUCTION §1). Hash-free redesign: a thimble is just a random
//! scalar and its point — no `A_i` rank, no `hash_p`. `H_i` is published (with a Schnorr PoK of
//! its dlog, carried opaquely for now) and is the adaptor point when chosen.
//!
//! ```text
//! h_i ←$ F_p ;   H_i = h_i·G
//! ```
//! The chosen thimble `H_c` is the ChallengeTx adaptor point; revealing its scalar `h_c` is the
//! whole reveal.

use musig2::secp::{Point, Scalar};

/// One thimble: its secret scalar and public point.
#[derive(Clone, Copy, Debug)]
pub struct Thimble {
    /// `h_i`.
    pub h: Scalar,
    /// `H_i = h_i·G` (published).
    pub h_point: Point,
}

impl Thimble {
    pub fn from_secret(h: Scalar) -> Self {
        Thimble { h, h_point: h.base_point_mul() }
    }
}

/// Alice's two thimbles plus her secret choice `c`.
#[derive(Clone, Copy, Debug)]
pub struct Thimbles {
    pub thimbles: [Thimble; 2],
    /// `c ∈ {0,1}` (0-indexed; `{1,2}` in the docs).
    pub choice: usize,
}

impl Thimbles {
    /// Build both thimbles from two secrets and record Alice's choice.
    pub fn new(h1: Scalar, h2: Scalar, choice: usize) -> Self {
        debug_assert!(choice < 2);
        Thimbles { thimbles: [Thimble::from_secret(h1), Thimble::from_secret(h2)], choice }
    }

    /// The chosen thimble `H_c` (its scalar `h_c` is the reveal / adaptor secret).
    pub fn chosen(&self) -> &Thimble {
        &self.thimbles[self.choice]
    }

    /// The public thimble points `[H_1, H_2]`.
    pub fn points(&self) -> [Point; 2] {
        [self.thimbles[0].h_point, self.thimbles[1].h_point]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    #[test]
    fn chosen_thimble_point_is_h_c_times_g() {
        let secp = secp256k1::Secp256k1::new();
        let h1: Scalar = Keypair::new(&secp).sk.into();
        let h2: Scalar = Keypair::new(&secp).sk.into();
        let t = Thimbles::new(h1, h2, 1);
        assert_eq!(t.chosen().h_point, t.chosen().h.base_point_mul());
        assert_eq!(t.points(), [h1.base_point_mul(), h2.base_point_mul()]);
    }
}
