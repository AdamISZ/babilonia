//! π_a — the well-formedness proof for the encrypted outcome, behind a **deliberately narrow,
//! mechanism-agnostic interface**. The rest of the protocol touches *only* [`Statement`],
//! [`Witness`], [`Proof`], [`pad`], [`prove`], [`verify`] — all in the protocol's own
//! `musig2::secp` types. The actual proof machinery (currently Bulletproofs + Poseidon over
//! secp256k1's scalar field) is sealed in the private [`circuit`] module and can be swapped wholesale
//! — even to something totally different — without touching `setup`/`reveal`.
//!
//! ## The relation
//! π_a proves, for public `(ctxt, D, {A_1, A_2})` and secret `(t, c, a_c)`:
//! ```text
//!   ctxt = a_c + H(t)          the ciphertext decrypts to a_c under the pad H(t)   [hash conjunct]
//! ∧ a_c·G = A_c  (c ∈ {1,2})   a_c is the chosen thimble's scalar (which one hidden) [Σ OR]
//! ∧ D = t·G                    t is the secret the settlement adaptor will reveal    [Σ PoK]
//! ```
//! `H` is deliberately abstract — "any function of `t`" — and is defined in exactly one place,
//! [`pad`], used by both this proof and the on-chain reveal ([`crate::reveal::recover_a_c`]), so they
//! can never disagree.
//!
//! ## Two swappable schemes ([`Scheme`], a PoC flag)
//! - **`Squaring`** (sigma-based, default, no heavy deps): `H(t) = t²`, and the *entire* relation is
//!   a CDS-OR of two Chaum–Pedersen DLEQ proofs (`docs/SquaringBasedProof.pdf`) — complete and cheap.
//!   Security: DDH/square-DH + high-entropy secrets (the `t²` mask is a quadratic residue).
//! - **`Poseidon`** (hand-rolled, `pi_a` feature): `H(t) = Poseidon(t)` over `F_n`; the hash conjunct
//!   `ctxt = a_c + H(t)` is a Bulletproofs circuit ([`circuit`]), plus the Σ-part. Fast, but the
//!   Poseidon params are bespoke (see the caveat below) — **not** yet safety-justified.
//! - A reviewed third option, **Purify** (MuSig-DN, DDH, field-native), is noted in `docs/PI-A-NOTES.md`.
//! - **Known gap (Poseidon path):** the Σ commitment to `a_c`/`t` and the Bulletproofs commitments are
//!   not yet cryptographically bound; a full impl links them (a cheap 2-base equality). The `Squaring`
//!   path has no such gap — the single OR-DLEQ proves the whole relation.

use musig2::secp::{Point, Scalar};

#[cfg(feature = "pi_a")]
use crate::keys::Keypair;
use crate::Result;

/// Public statement — what the verifier (Bob) checks π_a against. All fields are on the wire already.
#[derive(Clone, Debug)]
pub struct Statement {
    /// The ciphertext scalar `ctxt` (`= a_c + H(t)` when honest).
    pub ctxt: Scalar,
    /// `D = t·G` — the settlement adaptor lock; `t` is revealed when the settlement confirms.
    pub d_point: Point,
    /// The two thimble points `A_1 = a_1·G`, `A_2 = a_2·G`.
    pub thimbles: [Point; 2],
    /// Session/domain binding (Fiat–Shamir transcript separator).
    pub ctx: Vec<u8>,
}

/// Secret witness — what the prover (Alice) knows.
#[derive(Clone)]
pub struct Witness {
    /// Pad preimage `t` (the fresh dealer secret; `= d`, revealed by the settlement).
    pub t: Scalar,
    /// Choice `c` as a **thimble index** `∈ {0, 1}` (the "1,2" of the game, zero-based).
    pub choice: usize,
    /// The chosen thimble scalar `a_c = a_{choice}` (so `a_c·G = thimbles[choice]`).
    pub a_c: Scalar,
}

/// An opaque π_a proof. Its byte layout is entirely the implementation's business; the protocol
/// just ships these bytes in `AliceReveal.pi_a`.
#[derive(Clone, Debug)]
pub struct Proof(pub Vec<u8>);

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
    pub fn from_bytes(b: &[u8]) -> Self {
        Proof(b.to_vec())
    }
}

/// Which π_a construction to use. **PoC flag** — both prove the same relation `ctxt = a_c + H(t) ∧
/// a_c·G ∈ {A_i} ∧ D = t·G`; they differ in `H` and the proof machinery. Which is right for a real
/// system is open research.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Scheme {
    /// **Sigma-based (squaring).** `H(t) = t²`; well-formedness is a CDS-OR of two Chaum–Pedersen
    /// DLEQ proofs (`docs/SquaringBasedProof.pdf`). No heavy deps, complete, cheap. Security rests on
    /// a DDH/square-DH assumption AND requires the masked scalars to be **high-entropy** (the `t²`
    /// mask is a quadratic residue, so low-entropy plaintexts are QR-distinguishable). Our thimble
    /// scalars and `t` are uniform, so the caveat holds.
    Squaring,
    /// **Hand-rolled Poseidon — DISABLED.** `H(t) = Poseidon(t)` over `F_n`; the hash conjunct is a
    /// Bulletproofs circuit (requires the `pi_a` Cargo feature). Currently gated off in [`prove`] /
    /// [`verify`] pending a soundness fix (its Σ- and Bulletproofs commitments are unbound — see
    /// [`poseidon_disabled`] and `docs/planning/fable5-security-review.md` §1). The variant and the
    /// circuit code are kept for future re-enablement; the negotiation layer (`agent`) refuses to
    /// select it. See `docs/PI-A-NOTES.md` for Purify as a reviewed alternative.
    Poseidon,
}

/// **The pad `H` in `ctxt = a_c + H(t)`** for `scheme` — the single definition of `H`, used by both
/// `prove`/`verify` and the on-chain reveal ([`crate::reveal::recover_a_c`]) so they can't disagree.
pub fn pad(scheme: Scheme, t: &Scalar) -> Scalar {
    match scheme {
        Scheme::Squaring => squaring::pad(t),
        Scheme::Poseidon => poseidon_pad(t),
    }
}

/// Prove the π_a relation for `st` under witness `w`, using `scheme`.
pub fn prove(scheme: Scheme, st: &Statement, w: &Witness) -> Result<Proof> {
    match scheme {
        Scheme::Squaring => Ok(Proof(squaring::prove(st, w)?)),
        // Poseidon is gated off — fail closed. See `poseidon_disabled`.
        Scheme::Poseidon => Err(poseidon_disabled()),
    }
}

/// Verify a π_a proof against `st` using `scheme`. Returns `Ok(false)` on any check failure.
pub fn verify(scheme: Scheme, st: &Statement, proof: &Proof) -> Result<bool> {
    match scheme {
        Scheme::Squaring => squaring::verify(st, &proof.0),
        // Poseidon is gated off — never accept a proof under it. See `poseidon_disabled`.
        Scheme::Poseidon => Err(poseidon_disabled()),
    }
}

/// **`Scheme::Poseidon` is disabled pending a soundness fix.** Its Σ-part commitment to `a_c`/`d`
/// (`sigma::AdaptorProof`) and the Bulletproofs hash-circuit commitments (`comm_a_c`/`comm_d`) are
/// **not cryptographically bound** — nothing forces the `a_c`/`d` proven in the Σ-part to equal the
/// `a_c'`/`d'` in the circuit. A dealer can therefore commit a ciphertext that decrypts to a
/// non-thimble scalar, which makes `won()` always false — a **guaranteed dealer win**
/// (`docs/planning/fable5-security-review.md` §1). Both `prove` and `verify` reject it so it can
/// never gate a live bet. Re-enable **only** after adding the cross-commitment equality proof binding
/// `C_a`/`D` to the circuit's `comm_a_c`/`comm_d` (and reviewing it). Use [`Scheme::Squaring`].
fn poseidon_disabled() -> crate::Error {
    crate::Error::Protocol(
        "pi_a::Scheme::Poseidon is disabled pending a soundness fix (unbound Σ/Bulletproofs commitments); use Scheme::Squaring",
    )
}

// --- Poseidon scheme (feature-gated implementation) ---

#[cfg(feature = "pi_a")]
fn poseidon_pad(t: &Scalar) -> Scalar {
    circuit::poseidon_pad(t)
}
#[cfg(not(feature = "pi_a"))]
fn poseidon_pad(_t: &Scalar) -> Scalar {
    panic!("pi_a::Scheme::Poseidon requires the `pi_a` Cargo feature; use Scheme::Squaring or rebuild with --features pi_a")
}

#[cfg(feature = "pi_a")]
#[allow(dead_code)] // gated off in `prove`/`verify` pending the commitment-binding fix; kept for re-enablement
fn poseidon_prove(st: &Statement, w: &Witness) -> Result<Proof> {
    // Σ-part (binds a_c∈{A_i} and t to D) + the Bulletproofs hash conjunct.
    let blind = Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk);
    let sigma = crate::sigma::prove_adaptor(&w.a_c, &blind, &w.t, w.choice, &st.thimbles, &st.d_point, &st.ctx)?;
    let sig_bytes = sigma.to_bytes();
    let mut out = Vec::with_capacity(4 + sig_bytes.len());
    out.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&sig_bytes);
    out.extend_from_slice(&circuit::prove_hash(&st.ctxt, &w.a_c, &w.t)?);
    Ok(Proof(out))
}
#[cfg(not(feature = "pi_a"))]
#[allow(dead_code)] // gated off in `prove`/`verify`; kept for re-enablement
fn poseidon_prove(_st: &Statement, _w: &Witness) -> Result<Proof> {
    Err(crate::Error::Protocol("pi_a::Scheme::Poseidon requires the `pi_a` Cargo feature"))
}

#[cfg(feature = "pi_a")]
#[allow(dead_code)] // gated off in `prove`/`verify` pending the commitment-binding fix; kept for re-enablement
fn poseidon_verify(st: &Statement, proof: &Proof) -> Result<bool> {
    let b = &proof.0;
    if b.len() < 4 {
        return Ok(false);
    }
    let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if b.len() < 4 + n {
        return Ok(false);
    }
    if !crate::sigma::verify_adaptor_bytes(&b[4..4 + n], &st.thimbles, &st.d_point, &st.ctx) {
        return Ok(false);
    }
    if !circuit::verify_hash(&st.ctxt, &b[4 + n..])? {
        return Ok(false);
    }
    Ok(true)
}
#[cfg(not(feature = "pi_a"))]
#[allow(dead_code)] // gated off in `prove`/`verify`; kept for re-enablement
fn poseidon_verify(_st: &Statement, _proof: &Proof) -> Result<bool> {
    Err(crate::Error::Protocol("pi_a::Scheme::Poseidon requires the `pi_a` Cargo feature"))
}

// ===========================================================================
// Sigma-based squaring scheme (always compiled; pure Chaum–Pedersen OR, no heavy deps).
// H(t) = t²; the relation ctxt = a_c + t² ∧ a_c·G ∈ {A_i} is exactly
//   ∃ c∈{1,2}, t :  D = t·G  ∧  (ctxt·G − A_c) = t·D
// proven by a CDS-OR of two Chaum–Pedersen DLEQ(G,D; D, Y_i) proofs, Y_i = ctxt·G − A_i.
// See docs/SquaringBasedProof.pdf.
// ===========================================================================

mod squaring {
    use musig2::secp::{Point, Scalar};
    use sha2::{Digest, Sha256};

    use super::{Statement, Witness};
    use crate::keys::Keypair;
    use crate::{Error, Result};

    const DOM: &[u8] = b"babilonia/pi_a/squaring/or-dleq/v1";

    /// `H(t) = t²`. A quadratic residue — safe only for high-entropy `t` (see `Scheme::Squaring`).
    pub fn pad(t: &Scalar) -> Scalar {
        *t * *t // Scalar·Scalar → Scalar (t ≠ 0 ⇒ nonzero)
    }

    fn rand() -> Scalar {
        Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk)
    }

    /// `Y_i = ctxt·G − A_i` (the branch targets).
    fn targets(ctxt: &Scalar, thimbles: &[Point; 2]) -> Result<[Point; 2]> {
        let xg = ctxt.base_point_mul();
        let y = |a: &Point| (xg + (-*a)).into_option().ok_or(Error::Protocol("pi_a sq: Y_i at infinity"));
        Ok([y(&thimbles[0])?, y(&thimbles[1])?])
    }

    fn challenge(ctx: &[u8], ctxt: &Scalar, d: &Point, thimbles: &[Point; 2], u: &[Point; 2], v: &[Point; 2]) -> Scalar {
        let mut h = Sha256::new();
        h.update(DOM);
        h.update((ctx.len() as u32).to_le_bytes());
        h.update(ctx);
        h.update(ctxt.serialize());
        h.update(d.serialize());
        for p in thimbles.iter().chain(u.iter()).chain(v.iter()) {
            h.update(p.serialize());
        }
        Scalar::reduce_from(&h.finalize().into())
    }

    /// Prove `∃ c, t : D = t·G ∧ (ctxt·G − A_c) = t·D` as a CDS-OR of two Chaum–Pedersen DLEQs.
    /// Proof bytes = `e_0 ∥ z_0 ∥ e_1 ∥ z_1` (4 × 32 = 128 bytes).
    pub fn prove(st: &Statement, w: &Witness) -> Result<Vec<u8>> {
        if w.choice >= 2 {
            return Err(Error::Protocol("pi_a sq: choice out of range"));
        }
        // `D` and `A_i` are non-identity: the invariant is enforced at the wire boundary —
        // `messages::Reader::point` → `Point::from_slice` → `PublicKey::from_slice` rejects any
        // O/invalid encoding, so a hostile `O` aborts Bob's decode before it reaches here (and a
        // malformed `D` would only self-harm Alice anyway). `A_1 = A_2` is NOT excluded by the type
        // and makes the OR (and the game) degenerate, so reject it here for health.
        if st.thimbles[0] == st.thimbles[1] {
            return Err(Error::Protocol("pi_a sq: A_1 == A_2"));
        }
        let d = &st.d_point;
        let y = targets(&st.ctxt, &st.thimbles)?;
        let (c, j) = (w.choice, 1 - w.choice);

        // Simulated branch j: pick e_j, z_j; U_j = z_j·G − e_j·D, V_j = z_j·D − e_j·Y_j.
        let (e_j, z_j) = (rand(), rand());
        let u_j = (z_j.base_point_mul() + (-(e_j * *d))).into_option().ok_or(Error::Protocol("pi_a sq: U_j inf"))?;
        let v_j = (z_j * *d + (-(e_j * y[j]))).into_option().ok_or(Error::Protocol("pi_a sq: V_j inf"))?;

        // Real branch c: commit U_c = r·G, V_c = r·D.
        let r = rand();
        let u_c = r.base_point_mul();
        let v_c = r * *d;

        let (u, v) = if c == 0 { ([u_c, u_j], [v_c, v_j]) } else { ([u_j, u_c], [v_j, v_c]) };
        let e = challenge(&st.ctx, &st.ctxt, d, &st.thimbles, &u, &v);
        let e_c = (e + (-e_j)).not_zero().map_err(|_| Error::Protocol("pi_a sq: e_c zero"))?;
        let z_c = (r + e_c * w.t).not_zero().map_err(|_| Error::Protocol("pi_a sq: z_c zero"))?;

        let (e0, z0, e1, z1) = if c == 0 { (e_c, z_c, e_j, z_j) } else { (e_j, z_j, e_c, z_c) };
        let mut out = Vec::with_capacity(128);
        for s in [e0, z0, e1, z1] {
            out.extend_from_slice(&s.serialize());
        }
        Ok(out)
    }

    /// Verify the CDS-OR: recompute `U_i,V_i` from `(e_i,z_i)` and accept iff `e_0 + e_1 = H(transcript)`.
    pub fn verify(st: &Statement, bytes: &[u8]) -> Result<bool> {
        if bytes.len() != 128 {
            return Ok(false);
        }
        // Degenerate thimbles make the OR (and the game) meaningless — a health check. (`D`/`A_i` =
        // `O` is already rejected at the wire boundary by `Point::from_slice`; see `prove`.)
        if st.thimbles[0] == st.thimbles[1] {
            return Ok(false);
        }
        let sc = |k: usize| Scalar::from_slice(&bytes[k * 32..k * 32 + 32]);
        let (e0, z0, e1, z1) = match (sc(0), sc(1), sc(2), sc(3)) {
            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
            _ => return Ok(false),
        };
        let d = &st.d_point;
        let y = targets(&st.ctxt, &st.thimbles)?;
        let recompute = |e: Scalar, z: Scalar, yi: Point| -> Option<(Point, Point)> {
            let u = (z.base_point_mul() + (-(e * *d))).into_option()?;
            let v = (z * *d + (-(e * yi))).into_option()?;
            Some((u, v))
        };
        let (u0, v0) = match recompute(e0, z0, y[0]) {
            Some(x) => x,
            None => return Ok(false),
        };
        let (u1, v1) = match recompute(e1, z1, y[1]) {
            Some(x) => x,
            None => return Ok(false),
        };
        let e = challenge(&st.ctx, &st.ctxt, d, &st.thimbles, &[u0, u1], &[v0, v1]);
        Ok((e0 + e1).into_option() == Some(e))
    }
}

// ===========================================================================
// Implementation (swappable) — Bulletproofs + Poseidon over secp256k1's F_n.
// Nothing below is visible to the protocol; only the interface above is.
// ===========================================================================

#[cfg(feature = "pi_a")]
#[allow(dead_code)] // reachable only via the (currently gated-off) Poseidon path; kept for re-enablement
mod circuit {
    use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
    use ark_secp256k1::{Affine, Fr}; // Affine = secp256k1 group; Fr = its scalar field F_n
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use musig2::secp::Scalar;
    use sha2::{Digest, Sha256};

    use crate::keys::Keypair;
    use crate::{Error, Result};

    const T: usize = 3;
    /// `x^5` is a permutation of `F_n` (`gcd(5, n−1)=1`; `x^3` is not — `3 | n−1`).
    const ALPHA: u64 = 5;
    const R_F: usize = 8;
    /// TENTATIVE (standard for a ~256-bit field, α=5, t=3); finalize with the reference calculator.
    const R_P: usize = 56;
    const GENS_CAPACITY: usize = 1024;
    const TRANSCRIPT_LABEL: &[u8] = b"babilonia/pi_a/bulletproofs/v0";

    // --- protocol scalar <-> F_n bridge (both are integers mod n) ---

    fn scalar_to_fr(s: &Scalar) -> Fr {
        Fr::from_be_bytes_mod_order(&s.serialize())
    }
    /// Value-preserving `Fr → Scalar` (the exact inverse of `serialize` on `[1, n)`). NOT
    /// `Scalar::reduce_from`, which maps `z ↦ (z mod n−1) + 1` (nonzero-forcing) and would break the
    /// `Fr→Scalar→Fr` roundtrip that `ctxt = a_c + H(t)` relies on. `Fr` is always `< n`; the only
    /// rejected value is `0` (negligible for a hash output), mapped to `1`.
    fn fr_to_scalar(x: &Fr) -> Scalar {
        let bytes = x.into_bigint().to_bytes_be();
        let mut be = [0u8; 32];
        be[32 - bytes.len()..].copy_from_slice(&bytes);
        Scalar::from_slice(&be).unwrap_or(Scalar::one())
    }
    fn rand_fr() -> Fr {
        scalar_to_fr(&Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk))
    }

    // --- parameters (generated for F_n; TENTATIVE NUMS constants) ---

    fn nums_fr(tag: &str, round: usize, idx: usize) -> Fr {
        let mut h = Sha256::new();
        h.update(b"babilonia/pi_a/poseidon-secp256k1-Fn/v0");
        h.update(tag.as_bytes());
        h.update((round as u64).to_be_bytes());
        h.update((idx as u64).to_be_bytes());
        Fr::from_be_bytes_mod_order(&h.finalize())
    }
    fn round_constants() -> Vec<[Fr; T]> {
        (0..(R_F + R_P)).map(|r| core::array::from_fn(|i| nums_fr("ark", r, i))).collect()
    }
    /// Cauchy MDS: `x_i=i`, `y_j=t+j`, `mds[i][j]=1/(x_i+y_j)` — sums distinct+nonzero ⇒ MDS.
    fn mds_matrix() -> [[Fr; T]; T] {
        let xs: [Fr; T] = core::array::from_fn(|i| Fr::from(i as u64));
        let ys: [Fr; T] = core::array::from_fn(|j| Fr::from((T + j) as u64));
        core::array::from_fn(|i| core::array::from_fn(|j| (xs[i] + ys[j]).inverse().expect("Cauchy denom nonzero")))
    }
    fn is_full_round(r: usize) -> bool {
        let half = R_F / 2;
        r < half || r >= half + R_P
    }

    // --- native Poseidon over F_n (must match the gadget bit-for-bit) ---

    fn poseidon_permute(mut state: [Fr; T]) -> [Fr; T] {
        let ark = round_constants();
        let mds = mds_matrix();
        for r in 0..(R_F + R_P) {
            for i in 0..T {
                state[i] += ark[r][i];
            }
            if is_full_round(r) {
                for i in 0..T {
                    state[i] = state[i].pow([ALPHA]);
                }
            } else {
                state[0] = state[0].pow([ALPHA]);
            }
            state = core::array::from_fn(|i| (0..T).map(|j| mds[i][j] * state[j]).sum());
        }
        state
    }

    /// The pad `H(t) = Poseidon([t,0,0])[0]`, bridged to protocol scalars. This is what `pi_a::pad`
    /// calls with the feature on.
    pub fn poseidon_pad(t: &Scalar) -> Scalar {
        let out = poseidon_permute([scalar_to_fr(t), Fr::zero(), Fr::zero()])[0];
        fr_to_scalar(&out)
    }

    // --- in-circuit Poseidon gadget ---

    type LC = LinearCombination<Fr>;

    /// `x^5` as R1CS multiplication gates (`x2=x·x`, `x4=x2·x2`, `x5=x4·x`).
    fn sbox_gadget<CS: ConstraintSystem<Fr>>(cs: &mut CS, x: LC) -> LC {
        let (_, _, x2) = cs.multiply(x.clone(), x.clone());
        let x2: LC = x2.into();
        let (_, _, x4) = cs.multiply(x2.clone(), x2);
        let (_, _, x5) = cs.multiply(x4.into(), x);
        x5.into()
    }

    /// Pin an LC to a fresh variable (one multiply-by-one gate). **Load-bearing:** without it the
    /// un-S-boxed partial-round lanes' term count doubles every round (≈2^56) and exhausts RAM
    /// during synthesis; pinning after each MDS keeps all LCs O(t).
    fn pin<CS: ConstraintSystem<Fr>>(cs: &mut CS, lc: LC) -> LC {
        let (_, _, out) = cs.multiply(lc, LC::from(Fr::one()));
        out.into()
    }

    fn permute_gadget<CS: ConstraintSystem<Fr>>(cs: &mut CS, mut state: [LC; T]) -> [LC; T] {
        let ark = round_constants();
        let mds = mds_matrix();
        for r in 0..(R_F + R_P) {
            for i in 0..T {
                state[i] = state[i].clone() + ark[r][i];
            }
            if is_full_round(r) {
                for i in 0..T {
                    state[i] = sbox_gadget(cs, state[i].clone());
                }
            } else {
                state[0] = sbox_gadget(cs, state[0].clone());
            }
            let mixed: [LC; T] = core::array::from_fn(|i| {
                let mut acc = LC::from(Fr::zero());
                for j in 0..T {
                    acc = acc + state[j].clone() * mds[i][j];
                }
                acc
            });
            state = core::array::from_fn(|i| pin(cs, mixed[i].clone()));
        }
        state
    }

    /// Constrain `ctxt − a_c − Poseidon([d,0,0])[0] = 0`.
    fn pi_a_constraints<CS: ConstraintSystem<Fr>>(cs: &mut CS, a_c: LC, d: LC, ctxt: Fr) {
        let out = permute_gadget(cs, [d, LC::from(Fr::zero()), LC::from(Fr::zero())]);
        cs.constrain(LC::from(ctxt) - a_c - out[0].clone());
    }

    // --- Bulletproofs prove / verify over Fr ---

    struct HashProof {
        proof: R1CSProof<Affine>,
        comm_a_c: Affine,
        comm_d: Affine,
    }

    fn prove_fr(a_c: Fr, d: Fr, ctxt: Fr, r_ac: Fr, r_d: Fr) -> std::result::Result<HashProof, R1CSError> {
        let pc_gens = PedersenGens::<Affine>::default();
        let bp_gens = BulletproofGens::<Affine>::new(GENS_CAPACITY, 1);
        let mut prover = Prover::new(&pc_gens, Transcript::new(TRANSCRIPT_LABEL));
        let (comm_a_c, var_ac) = prover.commit(a_c, r_ac);
        let (comm_d, var_d) = prover.commit(d, r_d);
        pi_a_constraints(&mut prover, var_ac.into(), var_d.into(), ctxt);
        let proof = prover.prove(&bp_gens)?;
        Ok(HashProof { proof, comm_a_c, comm_d })
    }

    fn verify_fr(p: &HashProof, ctxt: Fr) -> std::result::Result<(), R1CSError> {
        let pc_gens = PedersenGens::<Affine>::default();
        let bp_gens = BulletproofGens::<Affine>::new(GENS_CAPACITY, 1);
        let mut verifier = Verifier::new(Transcript::new(TRANSCRIPT_LABEL));
        let var_ac = verifier.commit(p.comm_a_c);
        let var_d = verifier.commit(p.comm_d);
        pi_a_constraints(&mut verifier, var_ac.into(), var_d.into(), ctxt);
        verifier.verify(&p.proof, &pc_gens, &bp_gens)
    }

    // --- byte (de)serialization of the hash proof ---

    fn ser_affine(out: &mut Vec<u8>, p: &Affine) -> Result<()> {
        let mut buf = Vec::new();
        p.serialize_compressed(&mut buf).map_err(|_| Error::Protocol("pi_a: affine serialize"))?;
        out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
        out.extend_from_slice(&buf);
        Ok(())
    }
    fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
        if r.len() < n {
            return Err(Error::Protocol("pi_a: short proof"));
        }
        let (h, t) = r.split_at(n);
        *r = t;
        Ok(h)
    }
    fn take_u32(r: &mut &[u8]) -> Result<usize> {
        let b = take(r, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    fn de_affine(r: &mut &[u8]) -> Result<Affine> {
        let n = take_u32(r)?;
        let bytes = take(r, n)?;
        Affine::deserialize_compressed(bytes).map_err(|_| Error::Protocol("pi_a: affine deserialize"))
    }

    /// Prove `ctxt = a_c + H(t)` and serialize the proof + its two commitments to bytes.
    pub fn prove_hash(ctxt: &Scalar, a_c: &Scalar, t: &Scalar) -> Result<Vec<u8>> {
        let p = prove_fr(scalar_to_fr(a_c), scalar_to_fr(t), scalar_to_fr(ctxt), rand_fr(), rand_fr())
            .map_err(|_| Error::Protocol("pi_a: hash-circuit prove failed"))?;
        let pf = p.proof.to_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&(pf.len() as u32).to_le_bytes());
        out.extend_from_slice(&pf);
        ser_affine(&mut out, &p.comm_a_c)?;
        ser_affine(&mut out, &p.comm_d)?;
        Ok(out)
    }

    /// Deserialize and verify a hash-conjunct proof against public `ctxt`.
    pub fn verify_hash(ctxt: &Scalar, bytes: &[u8]) -> Result<bool> {
        let mut r = bytes;
        let pf_len = take_u32(&mut r)?;
        let pf = take(&mut r, pf_len)?;
        let proof = R1CSProof::<Affine>::from_bytes(pf).map_err(|_| Error::Protocol("pi_a: r1cs proof parse"))?;
        let comm_a_c = de_affine(&mut r)?;
        let comm_d = de_affine(&mut r)?;
        Ok(verify_fr(&HashProof { proof, comm_a_c, comm_d }, scalar_to_fr(ctxt)).is_ok())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ark_ff::UniformRand;

        const N_BE: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ];

        #[test]
        fn fr_is_the_secp256k1_scalar_field() {
            assert_eq!(<Fr as PrimeField>::MODULUS.to_bytes_be().as_slice(), &N_BE);
            assert_eq!(Fr::MODULUS_BIT_SIZE, 256);
        }

        #[test]
        fn sbox_alpha5_is_a_permutation() {
            let mut rng = ark_std::test_rng();
            for _ in 0..64 {
                let (x, y) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
                if x != y {
                    assert_ne!(x.pow([ALPHA]), y.pow([ALPHA]));
                }
            }
        }

        /// SAFETY GATE: synthesize on a Prover and read the multiplier count WITHOUT calling
        /// `prove()`. Bounded ⇒ the exponential-LC blowup is absent. Run this first.
        #[test]
        fn bounded_gadget_shape() {
            let pc_gens = PedersenGens::<Affine>::default();
            let mut prover = Prover::new(&pc_gens, Transcript::new(TRANSCRIPT_LABEL));
            let a_c = Fr::from(1u64);
            let d = Fr::from(2u64);
            let ctxt = a_c + poseidon_permute([d, Fr::zero(), Fr::zero()])[0];
            let (_, var_ac) = prover.commit(a_c, Fr::from(7u64));
            let (_, var_d) = prover.commit(d, Fr::from(8u64));
            pi_a_constraints(&mut prover, var_ac.into(), var_d.into(), ctxt);
            let m = prover.metrics();
            println!("[shape] multipliers={} constraints={}", m.multipliers, m.constraints);
            assert!(m.multipliers < 1000, "gadget must be bounded; got {}", m.multipliers);
        }

        /// Native `poseidon_pad` (protocol scalars) round-trips the outcome pad, and a full
        /// serialize→prove→bytes→verify cycle over secp256k1 accepts an honest ciphertext.
        #[test]
        fn hash_prove_verify_bytes_roundtrip() {
            let a_c = Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk);
            let t = Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk);
            let ctxt = (a_c + poseidon_pad(&t)).unwrap();
            let bytes = prove_hash(&ctxt, &a_c, &t).expect("prove_hash");
            assert!(verify_hash(&ctxt, &bytes).expect("verify_hash"), "honest hash proof verifies");
            let wrong = (ctxt + Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk)).unwrap();
            assert!(!verify_hash(&wrong, &bytes).unwrap(), "wrong ctxt rejected");
        }

        /// Benchmark the hash-conjunct prove/verify (and proof size). RELEASE only:
        ///   cargo test --release --features pi_a -- --ignored --nocapture pi_a_bench
        #[test]
        #[ignore = "benchmark; run in --release with --ignored --nocapture"]
        fn pi_a_bench() {
            use std::time::Instant;
            let secp = secp256k1::Secp256k1::new();
            let a_c = Scalar::from(Keypair::new(&secp).sk);
            let t = Scalar::from(Keypair::new(&secp).sk);
            let ctxt = (a_c + poseidon_pad(&t)).unwrap();

            // warmup (also captures proof size)
            let bytes = prove_hash(&ctxt, &a_c, &t).unwrap();
            assert!(verify_hash(&ctxt, &bytes).unwrap());
            let n = 20u32;
            let (mut pt, mut vt) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
            let mut pmin = std::time::Duration::MAX;
            let mut pmax = std::time::Duration::ZERO;
            for _ in 0..n {
                let s = Instant::now();
                let b = prove_hash(&ctxt, &a_c, &t).unwrap();
                let e = s.elapsed();
                pt += e;
                pmin = pmin.min(e);
                pmax = pmax.max(e);
                let s = Instant::now();
                assert!(verify_hash(&ctxt, &b).unwrap());
                vt += s.elapsed();
            }
            println!(
                "[pi_a_bench] n={n} | proof={} bytes | prove avg={:?} (min={:?} max={:?}) | verify avg={:?}",
                bytes.len(),
                pt / n,
                pmin,
                pmax,
                vt / n
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    /// Build an honest statement/witness for `scheme` with the given `choice`.
    fn honest(scheme: Scheme, choice: usize) -> (Statement, Witness) {
        let secp = secp256k1::Secp256k1::new();
        let s = || Scalar::from(Keypair::new(&secp).sk);
        let thimbles_s = [s(), s()];
        let a_c = thimbles_s[choice];
        let t = s();
        let thimbles = [thimbles_s[0].base_point_mul(), thimbles_s[1].base_point_mul()];
        let ctxt = (a_c + pad(scheme, &t)).unwrap();
        let st = Statement { ctxt, d_point: t.base_point_mul(), thimbles, ctx: b"sess".to_vec() };
        (st, Witness { t, choice, a_c })
    }

    /// Accept an honest proof (round-tripped through opaque bytes) for both choices; reject a proof
    /// against a tampered ctxt.
    fn roundtrip_and_soundness(scheme: Scheme) {
        for choice in 0..2 {
            let (st, w) = honest(scheme, choice);
            let proof = Proof::from_bytes(&prove(scheme, &st, &w).expect("prove").to_bytes());
            assert!(verify(scheme, &st, &proof).expect("verify"), "honest π_a verifies ({scheme:?}, c={choice})");

            // Tamper the ciphertext ⇒ must be rejected.
            let bad = Statement { ctxt: (st.ctxt + Scalar::one()).unwrap(), ..st.clone() };
            assert!(!verify(scheme, &bad, &proof).unwrap(), "tampered ctxt rejected ({scheme:?})");
        }
        // pad is deterministic.
        let t = Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk);
        assert_eq!(pad(scheme, &t), pad(scheme, &t));
    }

    #[test]
    fn squaring_scheme_roundtrip() {
        roundtrip_and_soundness(Scheme::Squaring);
    }

    /// Degenerate thimbles (`A_1 == A_2`) are rejected — `prove` errors, `verify` returns false.
    #[test]
    fn squaring_rejects_degenerate_thimbles() {
        let (st, w) = honest(Scheme::Squaring, 0);
        let good = prove(Scheme::Squaring, &st, &w).unwrap();
        let degen = Statement { thimbles: [st.thimbles[0], st.thimbles[0]], ..st.clone() };
        assert!(prove(Scheme::Squaring, &degen, &w).is_err(), "prove rejects A_1 == A_2");
        assert!(!verify(Scheme::Squaring, &degen, &good).unwrap(), "verify rejects A_1 == A_2");
    }

    /// The `t²` pad satisfies the reveal identity `a_c = ctxt − t²`.
    #[test]
    fn squaring_pad_reveal_identity() {
        let secp = secp256k1::Secp256k1::new();
        let a_c = Scalar::from(Keypair::new(&secp).sk);
        let t = Scalar::from(Keypair::new(&secp).sk);
        let ctxt = (a_c + pad(Scheme::Squaring, &t)).unwrap();
        assert_eq!((ctxt + (-pad(Scheme::Squaring, &t))).unwrap(), a_c);
    }

    /// Poseidon is gated off pending the commitment-binding fix (`docs/planning/
    /// fable5-security-review.md` §1): `prove`/`verify` must fail closed under it so it can never gate
    /// a live bet. (The dormant circuit code is still exercised directly in `mod circuit`'s tests.)
    #[cfg(feature = "pi_a")]
    #[test]
    fn poseidon_scheme_is_disabled() {
        let (st, w) = honest(Scheme::Squaring, 0);
        assert!(matches!(prove(Scheme::Poseidon, &st, &w), Err(crate::Error::Protocol(_))));
        assert!(matches!(verify(Scheme::Poseidon, &st, &Proof(vec![])), Err(crate::Error::Protocol(_))));
    }
}
