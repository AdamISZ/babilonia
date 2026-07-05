//! π_a hash-circuit ZKP — **research, in progress** (feature `pi_a`, off by default).
//!
//! Proves the non-affine reveal conjunct `ctxt = a_c + H(d)` in zero knowledge, so the pad `H` can be
//! evaluated inside a proof. Design: **Bulletproofs (transparent) over secp256k1** — the generic
//! arkworks R1CS from **Curve Trees** (Campanelli et al., USENIX Sec '23) — with `H = Poseidon over
//! the scalar field F_n`. Commitments live on secp256k1, the circuit runs over `F_n` (where `a_c`,
//! `d` live), so the committed `a_c`/`d` link to `A_c`/`D` via cheap sigma proofs (a later step).
//!
//! `F_n` admits the standard `x^5` S-box (`gcd(5, n−1)=1`; `x^3` does not — `3 | n−1`). No bundled
//! Poseidon params exist for this curve, so we generate them here (round constants + Cauchy MDS) and
//! run the **same** permutation natively and in-circuit, so `pad(d)` (native) always equals the
//! gadget's output — verified by the prove/verify tests.
//!
//! **Caveats (tentative):** round constants are a domain-separated SHA-256 NUMS construction, NOT the
//! Poseidon Grain LFSR; `R_P` is a standard value for a ~256-bit field — both must be finalized with
//! the reference generators before any security claim. The commitment↔`A_c`/`D` sigma link and the
//! swap of `sigma::h_p` (SHA-256) → this Poseidon are not done yet.

use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_secp256k1::{Affine, Fr}; // Affine = secp256k1 group; Fr = its scalar field F_n
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;
use sha2::{Digest, Sha256};

/// Poseidon width (state size) `t = rate + capacity`.
const T: usize = 3;
/// S-box exponent — `x^5` is a permutation of `F_n`.
const ALPHA: u64 = 5;
/// Full rounds (Poseidon standard).
const R_F: usize = 8;
/// Partial rounds — TENTATIVE (standard for a ~256-bit field, α=5, t=3, 128-bit).
const R_P: usize = 56;

// ---------------------------------------------------------------------------
// Parameters (generated for F_n — no bundled set for this curve)
// ---------------------------------------------------------------------------

/// A domain-separated nothing-up-my-sleeve field element (TENTATIVE — replace with the Grain LFSR).
fn nums_fr(tag: &str, round: usize, idx: usize) -> Fr {
    let mut h = Sha256::new();
    h.update(b"babilonia/pi_a/poseidon-secp256k1-Fn/v0");
    h.update(tag.as_bytes());
    h.update((round as u64).to_be_bytes());
    h.update((idx as u64).to_be_bytes());
    Fr::from_be_bytes_mod_order(&h.finalize())
}

/// Round constants `ark[round][state_element]`.
fn round_constants() -> Vec<[Fr; T]> {
    (0..(R_F + R_P))
        .map(|r| core::array::from_fn(|i| nums_fr("ark", r, i)))
        .collect()
}

/// A `t×t` Cauchy MDS matrix: `x_i = i`, `y_j = t + j`, `mds[i][j] = 1/(x_i + y_j)`. The sums are
/// distinct and nonzero, so every square submatrix is invertible — i.e. the matrix is MDS.
fn mds_matrix() -> [[Fr; T]; T] {
    let xs: [Fr; T] = core::array::from_fn(|i| Fr::from(i as u64));
    let ys: [Fr; T] = core::array::from_fn(|j| Fr::from((T + j) as u64));
    core::array::from_fn(|i| core::array::from_fn(|j| (xs[i] + ys[j]).inverse().expect("Cauchy denom nonzero")))
}

/// Whether round `r` is a full round (S-box on all state elements) vs partial (first element only).
fn is_full_round(r: usize) -> bool {
    let half = R_F / 2;
    r < half || r >= half + R_P
}

// ---------------------------------------------------------------------------
// Native Poseidon over F_n
// ---------------------------------------------------------------------------

/// The Poseidon permutation over `F_n` — `t=3`, α=5, `R_F` full + `R_P` partial rounds.
pub fn poseidon_permute(mut state: [Fr; T]) -> [Fr; T] {
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

/// The reveal pad `H(d)` — a single field element in, single out (drop-in for the current SHA-256
/// `sigma::h_p`, but ZK-friendly). `H(d) = Poseidon([d, 0, 0])[0]`.
pub fn pad(d: Fr) -> Fr {
    poseidon_permute([d, Fr::zero(), Fr::zero()])[0]
}

/// `F_n` element from 32 big-endian bytes (a secp256k1 scalar), reduced mod `n`.
pub fn fr_from_be(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// A field element as 32 big-endian bytes (left-padded).
pub fn fr_to_be(x: Fr) -> [u8; 32] {
    let bytes = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

// ---------------------------------------------------------------------------
// In-circuit Poseidon gadget (Bulletproofs R1CS over secp256k1)
// ---------------------------------------------------------------------------

type LC = LinearCombination<Fr>;

/// `x^5` as R1CS multiplication gates: `x2 = x·x`, `x4 = x2·x2`, `x5 = x4·x` (3 gates).
fn sbox_gadget<CS: ConstraintSystem<Fr>>(cs: &mut CS, x: LC) -> LC {
    let (_, _, x2) = cs.multiply(x.clone(), x.clone());
    let x2: LC = x2.into();
    let (_, _, x4) = cs.multiply(x2.clone(), x2);
    let (_, _, x5) = cs.multiply(x4.into(), x);
    x5.into()
}

/// Pin a linear combination to a fresh variable (one multiply-by-one gate: `out = lc·1`), so `out`
/// is a single-term LC. **Load-bearing:** `LinearCombination` `+` concatenates terms (no like-term
/// combine), so without pinning the un-S-boxed lanes' term count doubles every partial round
/// (≈2^56 terms → RAM exhaustion during synthesis). Pinning after each MDS keeps all LCs O(t).
fn pin<CS: ConstraintSystem<Fr>>(cs: &mut CS, lc: LC) -> LC {
    let (_, _, out) = cs.multiply(lc, LC::from(Fr::one()));
    out.into()
}

/// The Poseidon permutation as R1CS constraints — identical round structure to `poseidon_permute`,
/// so the prover's witness for the output equals `poseidon_permute(state)`.
fn permute_gadget<CS: ConstraintSystem<Fr>>(cs: &mut CS, mut state: [LC; T]) -> [LC; T] {
    let ark = round_constants();
    let mds = mds_matrix();
    for r in 0..(R_F + R_P) {
        for i in 0..T {
            state[i] = state[i].clone() + ark[r][i]; // add round constant (a constant term)
        }
        if is_full_round(r) {
            for i in 0..T {
                state[i] = sbox_gadget(cs, state[i].clone());
            }
        } else {
            state[0] = sbox_gadget(cs, state[0].clone());
        }
        // MDS linear layer, then PIN each lane to a fresh variable so LCs cannot grow across rounds.
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

/// Impose the π_a hash conjunct on `cs`: with `a_c`, `d` given as (committed) variables and `ctxt`
/// public, constrain `ctxt − a_c − Poseidon([d,0,0])[0] = 0`.
fn pi_a_constraints<CS: ConstraintSystem<Fr>>(cs: &mut CS, a_c: LC, d: LC, ctxt: Fr) {
    let out = permute_gadget(cs, [d, LC::from(Fr::zero()), LC::from(Fr::zero())]);
    let h = out[0].clone();
    cs.constrain(LC::from(ctxt) - a_c - h);
}

// ---------------------------------------------------------------------------
// Prove / verify
// ---------------------------------------------------------------------------

/// Generators — capacity ≥ the padded multiplier count: 240 S-box + 3·64 = 192 pin gates ≈ 432
/// (pads to 512); 1024 for margin.
const GENS_CAPACITY: usize = 1024;
const TRANSCRIPT_LABEL: &[u8] = b"babilonia/pi_a/bulletproofs/v0";

/// A π_a proof plus its two public Pedersen commitments (to `a_c` and `d`, on secp256k1). The
/// blindings stay with the prover — they are what a later sigma proof uses to bind the commitments
/// to `A_c = a_c·G` and `D = d·G`.
pub struct PiAProof {
    pub proof: R1CSProof<Affine>,
    pub comm_a_c: Affine,
    pub comm_d: Affine,
}

/// Prove `ctxt = a_c + H(d)` for `a_c`, `d` committed with blindings `r_ac`, `r_d`.
pub fn prove(a_c: Fr, d: Fr, ctxt: Fr, r_ac: Fr, r_d: Fr) -> Result<PiAProof, R1CSError> {
    let pc_gens = PedersenGens::<Affine>::default();
    let bp_gens = BulletproofGens::<Affine>::new(GENS_CAPACITY, 1);
    let transcript = Transcript::new(TRANSCRIPT_LABEL);
    let mut prover = Prover::new(&pc_gens, transcript);
    let (comm_a_c, var_ac) = prover.commit(a_c, r_ac);
    let (comm_d, var_d) = prover.commit(d, r_d);
    pi_a_constraints(&mut prover, var_ac.into(), var_d.into(), ctxt);
    let proof = prover.prove(&bp_gens)?;
    Ok(PiAProof { proof, comm_a_c, comm_d })
}

/// Verify a π_a proof against the public `ctxt`.
pub fn verify(p: &PiAProof, ctxt: Fr) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::<Affine>::default();
    let bp_gens = BulletproofGens::<Affine>::new(GENS_CAPACITY, 1);
    let transcript = Transcript::new(TRANSCRIPT_LABEL);
    let mut verifier = Verifier::new(transcript);
    let var_ac = verifier.commit(p.comm_a_c);
    let var_d = verifier.commit(p.comm_d);
    pi_a_constraints(&mut verifier, var_ac.into(), var_d.into(), ctxt);
    verifier.verify(&p.proof, &pc_gens, &bp_gens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    /// The secp256k1 group order `n` (the scalar field modulus), big-endian.
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
                assert_ne!(x.pow([ALPHA]), y.pow([ALPHA]), "x^5 must be injective");
            }
        }
    }

    #[test]
    fn poseidon_is_deterministic_and_sensitive() {
        let d = Fr::from(123456789u64);
        assert_eq!(pad(d), pad(d));
        assert_ne!(pad(d), pad(d + Fr::from(1u64)));
    }

    #[test]
    fn outcome_pad_roundtrip_over_fn() {
        let a_c = Fr::from(0xBABE_u64);
        let d = Fr::from(0xD00D_u64);
        let ctxt = a_c + pad(d);
        assert_eq!(ctxt - pad(d), a_c);
    }

    #[test]
    fn byte_roundtrip() {
        let x = Fr::from(0xDEAD_BEEF_u64);
        assert_eq!(fr_from_be(&fr_to_be(x)), x);
    }

    /// SAFETY GATE: synthesize the circuit on a Prover and read the multiplier count, WITHOUT
    /// calling `prove()`. A correct (bounded) gadget is a few hundred gates; the pre-fix version grew
    /// LCs exponentially and would exhaust RAM during this very synthesis. Run this FIRST.
    #[test]
    fn bounded_gadget_shape() {
        let pc_gens = PedersenGens::<Affine>::default();
        let transcript = Transcript::new(TRANSCRIPT_LABEL);
        let mut prover = Prover::new(&pc_gens, transcript);
        let a_c = Fr::from(1u64);
        let d = Fr::from(2u64);
        let ctxt = a_c + pad(d);
        let (_, var_ac) = prover.commit(a_c, Fr::from(7u64));
        let (_, var_d) = prover.commit(d, Fr::from(8u64));
        pi_a_constraints(&mut prover, var_ac.into(), var_d.into(), ctxt);
        let m = prover.metrics();
        println!("[shape] multipliers={} constraints={}", m.multipliers, m.constraints);
        assert!(
            m.multipliers < 1000,
            "gadget must be bounded (~hundreds of gates); got {} — exponential-blowup regression",
            m.multipliers
        );
    }

    /// A full prove→verify cycle over secp256k1: an honest `ctxt = a_c + H(d)` proof verifies. This
    /// also confirms the in-circuit Poseidon equals the native `pad` (else the constraint fails).
    #[test]
    fn pi_a_prove_verify_roundtrip() {
        let mut rng = ark_std::test_rng();
        let a_c = Fr::rand(&mut rng);
        let d = Fr::rand(&mut rng);
        let (r_ac, r_d) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let ctxt = a_c + pad(d); // honest ciphertext
        let proof = prove(a_c, d, ctxt, r_ac, r_d).expect("prove");
        verify(&proof, ctxt).expect("an honest π_a proof must verify");
    }

    /// Soundness smoke test: a proof made for the true `ctxt` does not verify against a wrong one.
    #[test]
    fn pi_a_rejects_wrong_ctxt() {
        let mut rng = ark_std::test_rng();
        let a_c = Fr::rand(&mut rng);
        let d = Fr::rand(&mut rng);
        let (r_ac, r_d) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let ctxt = a_c + pad(d);
        let proof = prove(a_c, d, ctxt, r_ac, r_d).expect("prove");
        assert!(verify(&proof, ctxt + Fr::from(1u64)).is_err(), "wrong ctxt must be rejected");
    }
}
