//! The reveal & Bob's claim (v5 §P6) — one output, one hash, `d` from the settlement adaptor.
//!
//! In v5 the settlement `U1`-spend is a MuSig2 **adaptor signature locked to `D = d·G`**. Alice
//! completes it with the fresh dealer secret `d` to get paid, which posts `d` on-chain; Bob
//! [`extract`](crate::musig::extract)s `d`, computes `a_c = ctxt − H(d)` ([`recover_a_c`]; pad in
//! [`crate::sigma::h_p`]), and — if he won — spends `K = W_b + A_y` with `w_b + a_c`. `d` is
//! outcome-independent, so revealing it (or aborting) leaks nothing about the outcome. This module
//! holds the reveal algebra; the pad/ciphertext live in `sigma`.
//!
//! ```text
//! win  ⟺  A_c = A_y     (equivalently a_c = a_y),  Bob guessed right
//! K    = W_b + A_y      Bob's pot-claim key (W_b hidden claim key, distinct from funding P_b)
//! dlog(K) = w_b + a_y   Bob's claim secret — computable iff he won (a_y = a_c revealed)
//! ```

use musig2::secp::{Point, Scalar};

use crate::{Error, Result};

/// Bob's win test: does the revealed scalar `a_c` correspond to the thimble he guessed?
/// (`a_c·G == A_y`.)
pub fn won(a_revealed: &Scalar, a_guessed_point: &Point) -> bool {
    a_revealed.base_point_mul() == *a_guessed_point
}

/// Bob's pot-claim key `K = W_b + A_y`, where `W_b` is his **hidden claim key** (a public point
/// here) and `A_y` the thimble he guessed. `W_b` MUST be distinct from Bob's funding key `P_b`
/// (which appears in `Q`), or Alice would recover it and learn `y` — see JOIN-CONSTRUCTION §5.
pub fn compute_k(w_b_point: &Point, a_guessed_point: &Point) -> Result<Point> {
    (*w_b_point + *a_guessed_point)
        .not_inf()
        .map_err(|_| Error::Protocol("W_b + A_y is the identity"))
}

/// The discrete log of `K`: `dlog(K) = w_b + a_y`. Bob can form it **only** once `a_y` (= the
/// revealed `a_c`) is known and matches his guess (he won). Signing the claim leaf `<K>` with it is
/// his claim. Invariant: `claim_secret(w_b, a)·G == compute_k(w_b·G, a·G)`.
pub fn claim_secret(w_b: &Scalar, a_win: &Scalar) -> Result<Scalar> {
    (*w_b + *a_win)
        .not_zero()
        .map_err(|_| Error::Protocol("w_b + a_win is zero"))
}

/// Bob decrypts the winning thimble scalar `a_c = ctxt − H(d)` once `d` is on-chain (v5 §P6).
pub fn recover_a_c(ctxt: &Scalar, d: &Scalar) -> Result<Scalar> {
    (*ctxt + (-crate::sigma::h_p(d)))
        .not_zero()
        .map_err(|_| Error::Protocol("recovered a_c is zero"))
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
        let a_c = scalar(Keypair::new(&secp).sk);
        let a_c_point = a_c.base_point_mul();

        // Bob's hidden claim key W_b (distinct from any funding key).
        let w_b = scalar(Keypair::new(&secp).sk);
        let w_b_point = w_b.base_point_mul();

        // A win: Bob guessed the chosen thimble.
        assert!(won(&a_c, &a_c_point));
        let k = compute_k(&w_b_point, &a_c_point).unwrap();
        let secret = claim_secret(&w_b, &a_c).unwrap(); // dlog(K)
        assert_eq!(secret.base_point_mul(), k, "dlog(K)·G == K");

        // A loss: an unrelated thimble point.
        let other = scalar(Keypair::new(&secp).sk).base_point_mul();
        assert!(!won(&a_c, &other));
    }

    /// The v5 encrypted-outcome reveal, end to end with a *real* MuSig2 adaptor settlement: Alice
    /// forms `ctxt = a_c + H(d)`, `D = d·G`, `π_a` (Σ-part); Bob checks `π_a`; the settlement
    /// adaptor is completed with `d` and published; Bob extracts `d`, decrypts `a_c`, and confirms
    /// his win opens `K`. (The hash conjunct binding `ctxt` to `a_c` is the TODO circuit; here
    /// `ctxt` is honest.)
    #[test]
    fn v5_encrypted_outcome_reveal_end_to_end() {
        use crate::musig::{adapt, extract, KeyAgg};
        use crate::sigma::{h_p, prove_adaptor, verify_adaptor};
        use rand::RngCore;

        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let keyagg = KeyAgg::new_taproot([a.pk, b.pk]).unwrap();
        let msg = [0x55u8; 32]; // stands in for the U1 settlement sighash

        // Alice's thimbles A_i = a_i·G + choice c; Bob guessed c (a win).
        let c = 1usize;
        let a_thim = [scalar(Keypair::new(&secp).sk), scalar(Keypair::new(&secp).sk)];
        let thimbles = [a_thim[0].base_point_mul(), a_thim[1].base_point_mul()];
        let a_c = a_thim[c];
        let w_b = scalar(Keypair::new(&secp).sk); // Bob's hidden claim key

        // P4: fresh dealer secret d, ciphertext ctxt = a_c + H(d), and π_a Σ-part.
        let d = scalar(Keypair::new(&secp).sk);
        let d_point = d.base_point_mul();
        let ctxt = (a_c + h_p(&d)).unwrap();
        let r = scalar(Keypair::new(&secp).sk);
        let pi_a = prove_adaptor(&a_c, &r, &d, c, &thimbles, &d_point, b"sess").unwrap();
        assert!(verify_adaptor(&pi_a, &thimbles, &d_point, b"sess"), "Bob accepts π_a Σ-part");

        // Settlement: 2-party MuSig2 adaptor on D; Alice adapts with d and publishes → reveals d.
        let mut s1 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s1);
        let mut s2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s2);
        let (r1a, pna) = keyagg.first_round(0, a.sk, s1).unwrap();
        let (r1b, pnb) = keyagg.first_round(1, b.sk, s2).unwrap();
        let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, d_point, msg).unwrap();
        let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, d_point, msg).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        let pre = r2a.finalize().unwrap();
        let final_sig = adapt(&pre, &d).unwrap();

        // P6: Bob extracts d, decrypts a_c, and checks his win.
        let d_bob = extract(&pre, &final_sig).unwrap().unwrap();
        assert_eq!(d_bob, d, "Bob extracts d from the settlement signature");
        let a_c_bob = recover_a_c(&ctxt, &d_bob).unwrap();
        assert_eq!(a_c_bob, a_c, "Bob decrypts a_c = ctxt − H(d)");

        assert!(won(&a_c_bob, &thimbles[c]));
        let k = compute_k(&w_b.base_point_mul(), &thimbles[c]).unwrap();
        assert_eq!(claim_secret(&w_b, &a_c_bob).unwrap().base_point_mul(), k, "K spendable with w_b + a_c");
    }
}
