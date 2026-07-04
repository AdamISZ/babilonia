//! Sigma protocols over secp256k1 for the setup proofs (JOIN-CONSTRUCTION §9). Pure
//! discrete-log statements, Fiat–Shamir compiled — no SNARK, no in-circuit hash. Two primitives:
//!
//! - **Schnorr PoK of dlog** (`prove_dlog`/`verify_dlog`), challenge-response `(e, s)` form.
//! - **CDS 1-of-2 OR** (`prove_or2`/`verify_or2`), additive challenge split `e = e_0 + e_1 mod n`
//!   (cleaner than XOR in a prime-order group — everything is already a field element).
//!
//! Built on top (v5, `adaptor_construction_spec_v5`):
//! - **thimble PoKs** (`prove_thimble_poks`, §P2): two Schnorr PoKs that `A_i = a_i·G`.
//! - **`π_r`** (`prove_pi_r`, §P3): one OR on `[K−A_1, K−A_2]` (Bob knows the dlog of one).
//! - **`π_a` Σ-part** (`prove_adaptor`, §P4): the winning thimble scalar `a_c` is committed
//!   (`C_a = a_c·G + r·B_ped`) and proven one published thimble via an m-branch CDS OR, hiding which;
//!   plus a PoK of the settlement adaptor witness `d` (`D = d·G`). The hash conjunct
//!   `ctxt = a_c + H(d)` that binds the ciphertext to that committed `a_c` is the one **circuit**
//!   (`prove_recovery_circuit`, TODO) — non-affine, so not a sigma protocol.
//!
//! The Fiat–Shamir transcript hash is SHA-256 → `Scalar::reduce_from` (transcript-only, never in
//! a circuit, so its choice is unconstrained). Nonces here are fresh per proof and independent of
//! the MuSig2 signing nonces.

use std::sync::OnceLock;

use musig2::secp::{MaybeScalar, Point, Scalar};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const DOM_DLOG: &[u8] = b"babilonia/sigma/dlog/v1";
const DOM_OR2: &[u8] = b"babilonia/sigma/or2/v1";
const DOM_ORDLOG: &[u8] = b"babilonia/sigma/or-dlog/v1";
const DOM_PAD: &[u8] = b"babilonia/sigma/pad/v1";
const DOM_NUMS_H: &[u8] = b"babilonia/sigma/pedersen-H/v1";

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

/// The **thimble PoKs** (v4 §P2): two Schnorr PoKs that `H_i = h_i·G` (Alice knows the thimble
/// scalars). 128 bytes. *(Not to be confused with v4's `π_a`, the encrypted-adaptor proof —
/// [`prove_adaptor`].)*
pub fn prove_thimble_poks(h: &[Scalar; 2], ctx: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    for hi in h {
        out.extend_from_slice(&prove_dlog(hi, &hi.base_point_mul(), ctx).to_bytes());
    }
    out
}

/// Verify the thimble PoKs against the published thimble points.
pub fn verify_thimble_poks(h_points: &[Point; 2], ctx: &[u8], bytes: &[u8]) -> bool {
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

// ===========================================================================================
// v5 (adaptor_construction_spec_v5): the encrypted-outcome proof `π_a`.
//
// `π_a` proves knowledge of (a_c, d) — the winning thimble scalar and the settlement adaptor
// witness — such that:
//   (Σ, here)   D = d·G                                — she knows the settlement adaptor witness
//   (Σ, here)   ⋁_c ( a_c·G = A_c )                    — a_c is ONE published thimble, hiding c
//   (CIRCUIT)   ctxt = a_c + H(d), with d·G = D        — see `prove_recovery_circuit` (TODO)
//
// The Σ-part hides a_c behind a Pedersen commitment `C_a = a_c·G + r·B_ped` (`B_ped` a NUMS base,
// ≠ the hash H and ≠ the thimbles A_i). The OR is then the pure discrete-log fact that, for one c,
// `C_a − A_c = r·B_ped` (a dlog base `B_ped`), i.e. `a_c·G = A_c` for a *committed* a_c — hiding
// both a_c·G and c. The hash conjunct binding `ctxt` to this same committed a_c is the one circuit.
// ===========================================================================================

/// The NUMS Pedersen base `B_ped` (unknown `log_G B_ped`) — hash-to-curve by try-and-increment.
/// Distinct from the hash `H`, the thimbles `A_i`, and the taproot NUMS in `txgraph`.
fn nums_h() -> Point {
    static H: OnceLock<Point> = OnceLock::new();
    *H.get_or_init(|| {
        for ctr in 0u32.. {
            let mut hh = Sha256::new();
            hh.update(DOM_NUMS_H);
            hh.update(ctr.to_le_bytes());
            let mut comp = [0u8; 33];
            comp[0] = 0x02;
            comp[1..].copy_from_slice(&hh.finalize());
            if let Ok(p) = Point::from_slice(&comp) {
                return p;
            }
        }
        unreachable!("a valid x-coordinate is found with overwhelming probability")
    })
}

/// Pedersen commitment `value·G + blind·H` (binding + hiding; `H` is NUMS).
pub fn pedersen_commit(value: &Scalar, blind: &Scalar) -> Result<Point> {
    (value.base_point_mul() + *blind * nums_h())
        .not_inf()
        .map_err(|_| Error::Protocol("pedersen commitment is the identity"))
}

/// The random-oracle pad `H: F_p → F_p` (SHA-256 → scalar). Used to form the ciphertext
/// `ctxt = a_c + H(d)` (setup) and recover `a_c = ctxt − H(d)` (reveal). The *proof* that a
/// ciphertext is well-formed w.r.t. this pad is the circuit conjunct (`prove_recovery_circuit`).
pub fn h_p(d: &Scalar) -> Scalar {
    let mut hh = Sha256::new();
    hh.update(DOM_PAD);
    hh.update(d.serialize());
    Scalar::reduce_from(&hh.finalize().into())
}

/// A CDS 1-of-`m` OR of Schnorr PoKs over a common `base`: knowledge of `x` with
/// `targets[i] = x·base` for one hidden `i`. Additive challenge split; compact `(e_i, z_i)` form.
#[derive(Clone, Debug)]
pub struct OrProof {
    e: Vec<Scalar>,
    z: Vec<Scalar>,
}

impl OrProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 * self.e.len());
        for s in &self.e {
            put_scalar(&mut out, s);
        }
        for s in &self.z {
            put_scalar(&mut out, s);
        }
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.is_empty() || b.len() % 64 != 0 {
            return Err(Error::Decode("or-dlog proof length"));
        }
        let m = b.len() / 64;
        let mut e = Vec::with_capacity(m);
        let mut z = Vec::with_capacity(m);
        for i in 0..m {
            e.push(get_scalar(&b[i * 32..i * 32 + 32])?);
        }
        for i in 0..m {
            z.push(get_scalar(&b[(m + i) * 32..(m + i) * 32 + 32])?);
        }
        Ok(OrProof { e, z })
    }
}

/// Prove `⋁_i (targets[i] = x·base)` for the real branch `true_idx` (`x·base == targets[true_idx]`).
pub fn prove_or_dlog(
    base: &Point,
    targets: &[Point],
    x: &Scalar,
    true_idx: usize,
    ctx: &[u8],
) -> OrProof {
    let m = targets.len();
    debug_assert!(true_idx < m && m >= 2);
    let mut e = vec![Scalar::one(); m];
    let mut z = vec![Scalar::one(); m];
    let mut commits = vec![*base; m];

    // Simulate the false branches: pick (e_i, z_i), back out a_i = z_i·base − e_i·target_i.
    for i in 0..m {
        if i == true_idx {
            continue;
        }
        let ei = rand_scalar();
        let zi = rand_scalar();
        commits[i] = (zi * *base + (-ei) * targets[i])
            .into_option()
            .expect("simulated OR commitment non-identity");
        e[i] = ei;
        z[i] = zi;
    }

    // Real branch commitment.
    let rho = rand_scalar();
    commits[true_idx] = rho * *base;

    // Fiat–Shamir over base, targets, and all commitments.
    let mut pts = Vec::with_capacity(1 + 2 * m);
    pts.push(*base);
    pts.extend_from_slice(targets);
    pts.extend_from_slice(&commits);
    let chal = challenge(DOM_ORDLOG, ctx, &pts);

    let others: MaybeScalar = (0..m).filter(|&i| i != true_idx).map(|i| e[i]).sum();
    let e_true = (chal + (-others)).unwrap(); // e_true = chal − Σ_{i≠true} e_i
    e[true_idx] = e_true;
    z[true_idx] = (rho + e_true * *x).unwrap();

    OrProof { e, z }
}

/// Verify a [`prove_or_dlog`] proof.
pub fn verify_or_dlog(base: &Point, targets: &[Point], proof: &OrProof, ctx: &[u8]) -> bool {
    let m = targets.len();
    if proof.e.len() != m || proof.z.len() != m || m == 0 {
        return false;
    }
    let mut commits = Vec::with_capacity(m);
    for i in 0..m {
        match (proof.z[i] * *base + (-proof.e[i]) * targets[i]).into_option() {
            Some(a) => commits.push(a),
            None => return false,
        }
    }
    let mut pts = Vec::with_capacity(1 + 2 * m);
    pts.push(*base);
    pts.extend_from_slice(targets);
    pts.extend_from_slice(&commits);
    let chal = challenge(DOM_ORDLOG, ctx, &pts);
    let sum: MaybeScalar = proof.e.iter().copied().sum();
    sum == MaybeScalar::from(chal)
}

/// v5 `π_a` **Σ-part** (the hash conjunct is separate — [`prove_recovery_circuit`], TODO). Commits
/// the winning thimble scalar `a_c`, proves `D = d·G` (the settlement adaptor witness), and proves
/// via a 1-of-`m` OR that `a_c·G = A_c` for exactly one published thimble, hiding which.
#[derive(Clone, Debug)]
pub struct AdaptorProof {
    /// Pedersen commitment `C_a = a_c·G + r·B_ped`.
    pub c_a: Point,
    /// PoK that `D = d·G`.
    pub d_pok: DlogProof,
    /// 1-of-`m` OR: `C_a − A_c = r·B_ped` for one `c`.
    pub adaptor_or: OrProof,
}

impl AdaptorProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.c_a.serialize()); // 33
        out.extend_from_slice(&self.d_pok.to_bytes()); // 64
        out.extend_from_slice(&self.adaptor_or.to_bytes()); // 64·m
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 33 + 64 {
            return Err(Error::Decode("adaptor proof too short"));
        }
        let c_a = Point::from_slice(&b[..33]).map_err(|_| Error::Decode("adaptor proof C_a"))?;
        let d_pok = DlogProof::from_bytes(&b[33..33 + 64])?;
        let adaptor_or = OrProof::from_bytes(&b[33 + 64..])?;
        Ok(AdaptorProof { c_a, d_pok, adaptor_or })
    }
}

/// OR targets `C_a − A_c` — each equals `r·B_ped` iff `a_c·G = A_c`.
fn or_targets(c_a: &Point, thimbles: &[Point]) -> Result<Vec<Point>> {
    thimbles
        .iter()
        .map(|a_c| {
            (*c_a + (-*a_c))
                .not_inf()
                .map_err(|_| Error::Protocol("C_a − A_c is the identity"))
        })
        .collect()
}

/// Prove the `π_a` Σ-part. `a_c` = the winning thimble scalar, `blind = r`, `d` = the settlement
/// adaptor witness, `guess = c*` (the thimble `a_c` opens), `thimbles = [A_1..A_m]`, `d_point = D`.
#[allow(clippy::too_many_arguments)]
pub fn prove_adaptor(
    a_c: &Scalar,
    blind: &Scalar,
    d: &Scalar,
    guess: usize,
    thimbles: &[Point],
    d_point: &Point,
    ctx: &[u8],
) -> Result<AdaptorProof> {
    let c_a = pedersen_commit(a_c, blind)?;
    let d_pok = prove_dlog(d, d_point, ctx);
    let targets = or_targets(&c_a, thimbles)?;
    let adaptor_or = prove_or_dlog(&nums_h(), &targets, blind, guess, ctx);
    Ok(AdaptorProof { c_a, d_pok, adaptor_or })
}

/// Decode + verify the `π_a` Σ-part from its wire bytes.
pub fn verify_adaptor_bytes(bytes: &[u8], thimbles: &[Point], d_point: &Point, ctx: &[u8]) -> bool {
    match AdaptorProof::from_bytes(bytes) {
        Ok(p) => verify_adaptor(&p, thimbles, d_point, ctx),
        Err(_) => false,
    }
}

/// Verify the `π_a` Σ-part (the hash conjunct is not checked — see [`prove_recovery_circuit`]).
pub fn verify_adaptor(proof: &AdaptorProof, thimbles: &[Point], d_point: &Point, ctx: &[u8]) -> bool {
    if !verify_dlog(d_point, ctx, &proof.d_pok) {
        return false;
    }
    let targets = match or_targets(&proof.c_a, thimbles) {
        Ok(t) => t,
        Err(_) => return false,
    };
    verify_or_dlog(&nums_h(), &targets, &proof.adaptor_or, ctx)
}

/// **TODO — the one circuit (v5 §4 hash conjunct).** Bind the committed `a_c` (in
/// [`AdaptorProof::c_a`]) and `d` (with `D = d·G`) to the public ciphertext `ctxt = a_c + H(d)`,
/// enforcing `d·G = D` in-circuit. Non-affine (`H` is a random oracle), so this is **not** a sigma
/// protocol: Bulletproofs-over-R1CS with `H` arithmetised, or cut-and-choose / MPC-in-the-head
/// (RO-free) — backend decision pending. Until it lands, [`prove_adaptor`] proves only the Σ-part
/// (a committed `a_c` is one published thimble), **not** that `ctxt` decrypts to that `a_c`.
#[allow(clippy::too_many_arguments)]
pub fn prove_recovery_circuit(
    _c_a: &Point,
    _d_point: &Point,
    _ctxt: &Scalar,
    _a_c: &Scalar,
    _blind: &Scalar,
    _d: &Scalar,
    _ctx: &[u8],
) -> Result<Vec<u8>> {
    Err(Error::Todo(
        "pi_a hash conjunct: circuit proof of ctxt = a_c + H(d) with d*G = D (Bulletproofs or cut-and-choose)",
    ))
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
    fn thimble_poks_and_pi_r() {
        let secp = secp256k1::Secp256k1::new();
        // Thimble PoKs (P2).
        let h = [scalar(), scalar()];
        let h_pts = [h[0].base_point_mul(), h[1].base_point_mul()];
        let pa = prove_thimble_poks(&h, b"sess");
        assert!(verify_thimble_poks(&h_pts, b"sess", &pa));
        assert!(!verify_thimble_poks(&h_pts, b"other", &pa));

        // π_r: K = W_b + H_guess for guess=1.
        let w_b = Scalar::from(Keypair::new(&secp).sk);
        let guess = 1usize;
        let k = crate::reveal::compute_k(&w_b.base_point_mul(), &h_pts[guess]).unwrap();
        let pr = prove_pi_r(&w_b, guess, &k, &h_pts, b"sess").unwrap();
        assert!(verify_pi_r(&k, &h_pts, b"sess", &pr));
        assert!(!verify_pi_r(&k, &[h_pts[1], h_pts[0]], b"sess", &pr));
    }

    #[test]
    fn h_p_is_deterministic_and_nums_h_off_generator() {
        let t = scalar();
        assert_eq!(h_p(&t), h_p(&t));
        assert_ne!(h_p(&t), h_p(&scalar()));
        // H is stable across calls and not the generator.
        assert_eq!(nums_h(), nums_h());
        assert_ne!(nums_h(), Scalar::one().base_point_mul());
    }

    #[test]
    fn or_dlog_m_branches_hide_and_verify() {
        let base = nums_h();
        for m in [2usize, 3, 4] {
            for real in 0..m {
                let x = scalar();
                let mut targets: Vec<Point> = (0..m).map(|_| scalar().base_point_mul()).collect();
                targets[real] = x * base; // only the real branch is x·base
                let proof = prove_or_dlog(&base, &targets, &x, real, b"ctx");
                assert!(verify_or_dlog(&base, &targets, &proof, b"ctx"), "m={m} real={real}");
                assert!(!verify_or_dlog(&base, &targets, &proof, b"nope"));
                let rt = OrProof::from_bytes(&proof.to_bytes()).unwrap();
                assert!(verify_or_dlog(&base, &targets, &rt, b"ctx"));
            }
        }
    }

    #[test]
    fn adaptor_sigma_part_proves_and_rejects() {
        let secp = secp256k1::Secp256k1::new();
        let d = Scalar::from(Keypair::new(&secp).sk);
        let d_point = d.base_point_mul();

        for guess in 0..2usize {
            // Thimbles A_i = a_i·G; the winning scalar a_c opens thimble `guess` directly.
            let a = [scalar(), scalar()];
            let thimbles = [a[0].base_point_mul(), a[1].base_point_mul()];
            let a_c = a[guess];

            let r = Scalar::from(Keypair::new(&secp).sk);
            let proof = prove_adaptor(&a_c, &r, &d, guess, &thimbles, &d_point, b"sess").unwrap();
            assert!(verify_adaptor(&proof, &thimbles, &d_point, b"sess"), "guess={guess}");
            // wrong context / permuted thimbles are rejected.
            assert!(!verify_adaptor(&proof, &thimbles, &d_point, b"other"));
            assert!(!verify_adaptor(&proof, &[thimbles[1], thimbles[0]], &d_point, b"sess"));
            // round-trips through bytes.
            let rt = AdaptorProof::from_bytes(&proof.to_bytes()).unwrap();
            assert!(verify_adaptor(&rt, &thimbles, &d_point, b"sess"));
        }

        // The hash conjunct is a marked TODO.
        assert!(matches!(
            prove_recovery_circuit(&d_point, &d_point, &Scalar::one(), &Scalar::one(), &Scalar::one(), &d, b"sess"),
            Err(crate::Error::Todo(_))
        ));
    }
}
