//! The reveal: Alice completes her adaptor on `ChallengeTx`, publishing `t`; Bob back-solves
//! to `h_{i*}` and, iff he won, to the scalar he folds into `dlog(K_b)` (JOIN-CONSTRUCTION §4, §5).
//!
//! The reveal is **outcome-blind**: Alice completes ChallengeTx before `π_r` resolves `j*`.
//! It is her *only* path toward the pot — withholding it just triggers RefundTx.
//!
//! ```text
//! t              recovered from the broadcast ChallengeTx via musig::extract
//! t^-1 · X = P_a + A_{i*}   ⇒   A_{i*} = t^-1 · X − P_a         (open_chosen_thimble)
//! h_{i*} = hash_p(A_{i*}) ;  win iff h_{i*}·G == H_{j*}          (bob_derive_win_scalar)
//! ```
//! All EC arithmetic is in the `secp` crate's `Point`/`Scalar` (it has the scalar inversion
//! that `t^-1` needs); conversions to bitcoin types happen only at the tx layer.

use musig2::secp::{Point, Scalar};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Domain separator for `hash_p`. The commit side (`thimbles`) and this reveal side MUST agree
/// byte-for-byte, so both go through [`hash_p`].
pub const HASH_P_DOMAIN: &[u8] = b"babilonia/hash_p/v1";

/// `hash_p : Point → F_p`, modeled as a random oracle: SHA-256 over the 33-byte compressed
/// point (domain-separated), reduced mod the curve order. This is the *only* point→scalar
/// bridge in the protocol (the lump `π_a` must prove in-circuit; DESIGN §4, §9).
pub fn hash_p(point: &Point) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(HASH_P_DOMAIN);
    hasher.update(point.serialize());
    let digest: [u8; 32] = hasher.finalize().into();
    Scalar::reduce_from(&digest)
}

/// From a recovered `t` and the public bridge `X = t·(P_a + A_{i*})`, back-solve to the opened
/// thimble point `A_{i*} = t⁻¹·X − P_a`.
///
/// Errors only if the result is the identity point, which can't happen for well-formed
/// `(t, X, P_a)` — it flags a malformed `X` (i.e. a bad `π_a` that slipped past verification).
pub fn open_chosen_thimble(t: &Scalar, x: &Point, p_a: &Point) -> Result<Point> {
    let recovered = ((*t).invert() * *x) + (-*p_a);
    recovered
        .not_inf()
        .map_err(|_| Error::Protocol("reveal produced identity point; malformed X or t"))
}

/// Bob's win test + key material. Compute `h_{i*} = hash_p(A_{i*})` and check it against his
/// committed third-rank point `H_{j*}`. On a match (`j* == i*`, Bob won) return the scalar
/// `h_{i*}`, which equals `h_{j*}` and completes `dlog(K_b) = t_b·(x_b + h_{j*})`. On a miss
/// (Bob lost) return `None` — he simply cannot form the key (Kurbatov match-gating).
pub fn bob_derive_win_scalar(a_chosen: &Point, h_committed: &Point) -> Option<Scalar> {
    let h = hash_p(a_chosen);
    (h.base_point_mul() == *h_committed).then_some(h)
}

/// Bob's pot-claim key `K_b = t_b·(P_b + H_{j*})` — the taproot key-path of `Q'` in the
/// all-or-nothing reduction, and the *adaptor point* for `SettleBobWins` in the δ-split model.
/// `H_{j*}` is the third-rank point of the thimble Bob guessed. Public; Bob sends it in `π_r`.
pub fn compute_k_b(t_b: &Scalar, p_b: &Point, h_guessed: &Point) -> Result<Point> {
    let sum = (*p_b + *h_guessed)
        .not_inf()
        .map_err(|_| Error::Protocol("P_b + H is the identity"))?;
    Ok(*t_b * sum)
}

/// The discrete log of `K_b`: `dlog(K_b) = t_b·(x_b + h_{j*})`. Bob can form this **only** once
/// `h_{j*}` is revealed (as `h_{i*}`) *and* it matches his guess (he won) — see
/// [`bob_derive_win_scalar`]. Completing `SettleBobWins`'s adaptor with it is his claim.
/// Invariant: `bob_claim_secret(t_b, x_b, h)·G == compute_k_b(t_b, x_b·G, h·G)`.
pub fn bob_claim_secret(t_b: &Scalar, x_b: &Scalar, h_win: &Scalar) -> Result<Scalar> {
    let inner = (*x_b + *h_win)
        .not_zero()
        .map_err(|_| Error::Protocol("x_b + h is zero"))?;
    Ok(*t_b * inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;
    use musig2::secp::MaybePoint;
    use rand::RngCore;

    fn point(p: secp256k1::PublicKey) -> Point {
        p.into()
    }
    fn scalar(s: secp256k1::SecretKey) -> Scalar {
        s.into()
    }
    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    }

    /// Pure algebra: build `X = t·(P_a + A_{i*})`, recover `A_{i*}`, and check the win/lose
    /// derivation against the committed `H`.
    #[test]
    fn open_thimble_and_win_lose() {
        let secp = secp256k1::Secp256k1::new();
        let p_a = point(Keypair::new(&secp).pk);
        let a_i = scalar(Keypair::new(&secp).sk);
        let a_i_point = a_i.base_point_mul();
        let t = scalar(Keypair::new(&secp).sk);

        // Alice's published bridge X = t·(P_a + A_{i*}).
        let sum: Point = match p_a + a_i_point {
            MaybePoint::Valid(p) => p,
            MaybePoint::Infinity => unreachable!("distinct random points"),
        };
        let x = t * sum;

        // Bob opens the thimble from t and X.
        assert_eq!(open_chosen_thimble(&t, &x, &p_a).unwrap(), a_i_point);

        // Win: H committed as h_{i*}·G matches ⇒ returns the scalar.
        let h = hash_p(&a_i_point);
        let big_h = h.base_point_mul();
        assert_eq!(bob_derive_win_scalar(&a_i_point, &big_h), Some(h));

        // Lose: an unrelated committed point ⇒ None.
        let other = point(Keypair::new(&secp).pk);
        assert_eq!(bob_derive_win_scalar(&a_i_point, &other), None);
    }

    /// Full reveal path: a two-party adaptor signature on `T = t·G` is completed and broadcast;
    /// Bob extracts `t` (via `musig`) and opens the thimble. This is ChallengeTx end to end.
    #[test]
    fn reveal_from_challenge_signature() {
        use crate::musig::{adapt, extract, KeyAgg};
        let secp = secp256k1::Secp256k1::new();
        let a = Keypair::new(&secp);
        let b = Keypair::new(&secp);
        let keyagg = KeyAgg::new([a.pk, b.pk]).unwrap();
        let msg = [7u8; 32];

        // Alice's blinding t (adaptor secret / point) and chosen thimble.
        let t = scalar(Keypair::new(&secp).sk);
        let big_t = t.base_point_mul();
        let p_a = point(a.pk);
        let a_i_point = scalar(Keypair::new(&secp).sk).base_point_mul();
        let sum = (p_a + a_i_point).not_inf().unwrap();
        let x = t * sum; // X = t·(P_a + A_{i*})

        // Two-party adaptor signing over ChallengeTx's message, offset by T.
        let (r1a, pna) = keyagg.first_round(0, a.sk, seed()).unwrap();
        let (r1b, pnb) = keyagg.first_round(1, b.sk, seed()).unwrap();
        let (mut r2a, psa) = r1a.sign_adaptor(1, pnb, a.sk, big_t, msg).unwrap();
        let (mut r2b, psb) = r1b.sign_adaptor(0, pna, b.sk, big_t, msg).unwrap();
        r2a.receive(1, psb).unwrap();
        r2b.receive(0, psa).unwrap();
        let pre = r2a.finalize().unwrap();

        // Alice completes + broadcasts; Bob recovers t and opens the thimble.
        let final_sig = adapt(&pre, &t).unwrap();
        let t_recovered: Scalar = extract(&pre, &final_sig).unwrap().unwrap();
        assert_eq!(t_recovered, t);
        assert_eq!(open_chosen_thimble(&t_recovered, &x, &p_a).unwrap(), a_i_point);
    }

    /// The pot-key relation: the secret Bob computes on winning is exactly `dlog(K_b)`.
    #[test]
    fn k_b_relation_holds() {
        let secp = secp256k1::Secp256k1::new();
        let t_b = scalar(Keypair::new(&secp).sk);
        let x_b = scalar(Keypair::new(&secp).sk);
        let p_b = x_b.base_point_mul();
        let h_win = scalar(Keypair::new(&secp).sk);
        let h_point = h_win.base_point_mul();

        let k_b = compute_k_b(&t_b, &p_b, &h_point).unwrap();
        let secret = bob_claim_secret(&t_b, &x_b, &h_win).unwrap();
        assert_eq!(secret.base_point_mul(), k_b, "dlog(K_b)·G == K_b");
    }
}
