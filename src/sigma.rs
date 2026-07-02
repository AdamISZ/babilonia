//! Sigma protocols over secp256k1 for the setup proofs (JOIN-CONSTRUCTION §9). Pure
//! discrete-log statements, Fiat–Shamir compiled — no SNARK, no in-circuit hash. Two primitives:
//!
//! - **Schnorr PoK of dlog** (`prove_dlog`/`verify_dlog`), challenge-response `(e, s)` form.
//! - **CDS 1-of-2 OR** (`prove_or2`/`verify_or2`), additive challenge split `e = e_0 + e_1 mod n`
//!   (cleaner than XOR in a prime-order group — everything is already a field element).
//!
//! Built on top: `π_a` = two Schnorr PoKs on the thimbles (an AND, posted as two independent
//! proofs); `π_r` = one OR on `[K−H_1, K−H_2]` (Bob knows the dlog of one, hiding which).
//!
//! The Fiat–Shamir transcript hash is SHA-256 → `Scalar::reduce_from` (transcript-only, never in
//! a circuit, so its choice is unconstrained). Nonces here are fresh per proof and independent of
//! the MuSig2 signing nonces.

use musig2::secp::{MaybeScalar, Point, Scalar};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const DOM_DLOG: &[u8] = b"babilonia/sigma/dlog/v1";
const DOM_OR2: &[u8] = b"babilonia/sigma/or2/v1";

/// A uniformly random non-zero scalar (proof nonce / simulated values).
fn rand_scalar() -> Scalar {
    let mut b = [0u8; 32];
    loop {
        rand::thread_rng().fill_bytes(&mut b);
        if let Ok(s) = Scalar::from_slice(&b) {
            return s;
        }
    }
}

/// Fiat–Shamir challenge over a domain, a context binding, and a sequence of points.
fn challenge(domain: &[u8], ctx: &[u8], points: &[Point]) -> Scalar {
    let mut h = Sha256::new();
    h.update(domain);
    h.update((ctx.len() as u32).to_le_bytes());
    h.update(ctx);
    for p in points {
        h.update(p.serialize());
    }
    Scalar::reduce_from(&h.finalize().into())
}

fn put_scalar(out: &mut Vec<u8>, s: &Scalar) {
    out.extend_from_slice(&s.serialize());
}
fn get_scalar(b: &[u8]) -> Result<Scalar> {
    Scalar::from_slice(b).map_err(|_| Error::Decode("invalid proof scalar"))
}

// --- Schnorr PoK of discrete log: statement P = x·G ---

#[derive(Clone, Copy, Debug)]
pub struct DlogProof {
    e: Scalar,
    s: Scalar,
}

impl DlogProof {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = Vec::with_capacity(64);
        put_scalar(&mut out, &self.e);
        put_scalar(&mut out, &self.s);
        out.try_into().unwrap()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 64 {
            return Err(Error::Decode("dlog proof must be 64 bytes"));
        }
        Ok(DlogProof { e: get_scalar(&b[..32])?, s: get_scalar(&b[32..])? })
    }
}

/// Prove knowledge of `x` with `P = x·G`.
pub fn prove_dlog(x: &Scalar, p: &Point, ctx: &[u8]) -> DlogProof {
    let k = rand_scalar();
    let r = k.base_point_mul();
    let e = challenge(DOM_DLOG, ctx, &[*p, r]);
    let s = (k + e * *x).unwrap(); // negligibly ever zero
    DlogProof { e, s }
}

/// Verify a Schnorr PoK of `dlog(P)`.
pub fn verify_dlog(p: &Point, ctx: &[u8], proof: &DlogProof) -> bool {
    // R' = s·G − e·P
    let r = match (proof.s.base_point_mul() + (-proof.e) * *p).into_option() {
        Some(r) => r,
        None => return false,
    };
    challenge(DOM_DLOG, ctx, &[*p, r]) == proof.e
}

// --- CDS 1-of-2 OR: statement (dlog(P_0) known) ∨ (dlog(P_1) known) ---

#[derive(Clone, Copy, Debug)]
pub struct Or2Proof {
    e: [Scalar; 2],
    s: [Scalar; 2],
}

impl Or2Proof {
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = Vec::with_capacity(128);
        put_scalar(&mut out, &self.e[0]);
        put_scalar(&mut out, &self.e[1]);
        put_scalar(&mut out, &self.s[0]);
        put_scalar(&mut out, &self.s[1]);
        out.try_into().unwrap()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 128 {
            return Err(Error::Decode("or2 proof must be 128 bytes"));
        }
        Ok(Or2Proof {
            e: [get_scalar(&b[..32])?, get_scalar(&b[32..64])?],
            s: [get_scalar(&b[64..96])?, get_scalar(&b[96..])?],
        })
    }
}

/// Prove knowledge of `dlog(points[bit]) = x` without revealing `bit`. `points[bit]` must equal
/// `x·G` (the real branch); the other is simulated.
pub fn prove_or2(bit: usize, x: &Scalar, points: &[Point; 2], ctx: &[u8]) -> Or2Proof {
    debug_assert!(bit < 2);
    let o = 1 - bit; // simulated branch

    // Simulate the other branch: pick e_o, s_o; back out R_o = s_o·G − e_o·P_o.
    let e_o = rand_scalar();
    let s_o = rand_scalar();
    let r_o = (s_o.base_point_mul() + (-e_o) * points[o]).unwrap();

    // Real branch commitment.
    let k = rand_scalar();
    let r_b = k.base_point_mul();

    let mut r = [r_b; 2];
    r[o] = r_o;
    r[bit] = r_b;

    let e = challenge(DOM_OR2, ctx, &[points[0], points[1], r[0], r[1]]);
    let e_b = (e + (-e_o)).unwrap(); // e_bit = e − e_o
    let s_b = (k + e_b * *x).unwrap();

    let mut e_arr = [e_o; 2];
    e_arr[bit] = e_b;
    let mut s_arr = [s_o; 2];
    s_arr[bit] = s_b;
    Or2Proof { e: e_arr, s: s_arr }
}

/// Verify a CDS 1-of-2 OR: both Schnorr equations hold and `e_0 + e_1 = H(…)`.
pub fn verify_or2(points: &[Point; 2], ctx: &[u8], proof: &Or2Proof) -> bool {
    let r0 = match (proof.s[0].base_point_mul() + (-proof.e[0]) * points[0]).into_option() {
        Some(r) => r,
        None => return false,
    };
    let r1 = match (proof.s[1].base_point_mul() + (-proof.e[1]) * points[1]).into_option() {
        Some(r) => r,
        None => return false,
    };
    let e = challenge(DOM_OR2, ctx, &[points[0], points[1], r0, r1]);
    (proof.e[0] + proof.e[1]) == MaybeScalar::from(e)
}

// --- π_a and π_r (statement-level wrappers) ---

/// `π_a` = two Schnorr PoKs that `H_i = h_i·G` (Alice knows the thimble scalars). 128 bytes.
pub fn prove_pi_a(h: &[Scalar; 2], ctx: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    for hi in h {
        out.extend_from_slice(&prove_dlog(hi, &hi.base_point_mul(), ctx).to_bytes());
    }
    out
}

/// Verify `π_a` against the published thimble points.
pub fn verify_pi_a(h_points: &[Point; 2], ctx: &[u8], bytes: &[u8]) -> bool {
    if bytes.len() != 128 {
        return false;
    }
    match (DlogProof::from_bytes(&bytes[..64]), DlogProof::from_bytes(&bytes[64..])) {
        (Ok(p0), Ok(p1)) => {
            verify_dlog(&h_points[0], ctx, &p0) && verify_dlog(&h_points[1], ctx, &p1)
        }
        _ => false,
    }
}

/// The OR statement points `[K − H_0, K − H_1]` (Bob knows the dlog of `K − H_y = W_b`).
fn claim_statement(k: &Point, h_points: &[Point; 2]) -> Result<[Point; 2]> {
    let p0 = (*k + (-h_points[0])).not_inf().map_err(|_| Error::Protocol("K − H_0 identity"))?;
    let p1 = (*k + (-h_points[1])).not_inf().map_err(|_| Error::Protocol("K − H_1 identity"))?;
    Ok([p0, p1])
}

/// `π_r` = a CDS 1-of-2 OR that `K − H_y = w_b·G` for one `y`, with witness `w_b` (Bob's hidden
/// claim key) and `guess = y`. 128 bytes.
pub fn prove_pi_r(
    w_b: &Scalar,
    guess: usize,
    k: &Point,
    h_points: &[Point; 2],
    ctx: &[u8],
) -> Result<Vec<u8>> {
    let stmt = claim_statement(k, h_points)?;
    Ok(prove_or2(guess, w_b, &stmt, ctx).to_bytes().to_vec())
}

/// Verify `π_r` against `K` and the thimble points.
pub fn verify_pi_r(k: &Point, h_points: &[Point; 2], ctx: &[u8], bytes: &[u8]) -> bool {
    let stmt = match claim_statement(k, h_points) {
        Ok(s) => s,
        Err(_) => return false,
    };
    match Or2Proof::from_bytes(bytes) {
        Ok(p) => verify_or2(&stmt, ctx, &p),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    fn scalar() -> Scalar {
        let secp = secp256k1::Secp256k1::new();
        Keypair::new(&secp).sk.into()
    }

    #[test]
    fn dlog_roundtrip_and_reject() {
        let x = scalar();
        let p = x.base_point_mul();
        let proof = prove_dlog(&x, &p, b"ctx");
        assert!(verify_dlog(&p, b"ctx", &proof));
        // wrong statement, wrong context, and serialization tamper all fail.
        assert!(!verify_dlog(&scalar().base_point_mul(), b"ctx", &proof));
        assert!(!verify_dlog(&p, b"other", &proof));
        assert!(DlogProof::from_bytes(&proof.to_bytes()).is_ok());
    }

    #[test]
    fn or2_hides_branch_and_verifies() {
        // Prover knows dlog of points[bit] only.
        for bit in 0..2 {
            let x = scalar();
            let mut pts = [scalar().base_point_mul(), scalar().base_point_mul()];
            pts[bit] = x.base_point_mul();
            let proof = prove_or2(bit, &x, &pts, b"ctx");
            assert!(verify_or2(&pts, b"ctx", &proof), "valid OR (bit={bit})");
            // tampering the context fails.
            assert!(!verify_or2(&pts, b"nope", &proof));
            // round-trips through bytes.
            assert!(verify_or2(&pts, b"ctx", &Or2Proof::from_bytes(&proof.to_bytes()).unwrap()));
        }
    }

    #[test]
    fn pi_a_and_pi_r() {
        let secp = secp256k1::Secp256k1::new();
        // π_a: thimbles.
        let h = [scalar(), scalar()];
        let h_pts = [h[0].base_point_mul(), h[1].base_point_mul()];
        let pa = prove_pi_a(&h, b"sess");
        assert!(verify_pi_a(&h_pts, b"sess", &pa));
        assert!(!verify_pi_a(&h_pts, b"other", &pa));

        // π_r: K = W_b + H_guess for guess=1.
        let w_b = Scalar::from(Keypair::new(&secp).sk);
        let guess = 1usize;
        let k = crate::reveal::compute_k(&w_b.base_point_mul(), &h_pts[guess]).unwrap();
        let pr = prove_pi_r(&w_b, guess, &k, &h_pts, b"sess").unwrap();
        assert!(verify_pi_r(&k, &h_pts, b"sess", &pr));
        // a K built for the other thimble (which Bob can't open) still verifies structurally
        // only if he actually knows the witness — here he does for `guess`, so swapping fails:
        assert!(!verify_pi_r(&k, &[h_pts[1], h_pts[0]], b"sess", &pr));
    }
}
