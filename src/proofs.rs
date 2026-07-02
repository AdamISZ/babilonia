//! The two sigma-protocol obligations, behind a trait so the plumbing can run **assume-valid**
//! first and swap in real proofs later (build order: stub → real `π_r` → `π_a` hash-circuit).
//!
//! - `π_a` (Alice): `H_k` derived correctly from committed `A_k`, and `X` bound to **one**
//!   `A_{i*}`. Generalized Schnorr + a DLEQ-OR, plus the *only* in-circuit hash: the two
//!   `hash_p(A_k)` evaluations. `hash_p` is an **internal** hash (not consensus `hash160`),
//!   so we are free to pick a proof-friendly instantiation later.
//! - `π_r` (Bob): `K_b` uses exactly one of `{H_1,H_2}` (blinds `j*`) plus `dlog(P_b)`.
//!   Pure generalized Schnorr — **no hash circuit**. This is the one to make real first.

use crate::Result;

/// Public statement + proof bytes for `π_a`. Opaque here; shape firms up with the prover.
#[derive(Clone, Debug)]
pub struct ProofA {
    pub bytes: Vec<u8>,
}

/// Public statement + proof bytes for `π_r`.
#[derive(Clone, Debug)]
pub struct ProofR {
    pub bytes: Vec<u8>,
}

/// Verifier abstraction. The stub returns `Ok(())` unconditionally — it exists so the tx /
/// reveal / settlement machinery can be exercised end-to-end on regtest before the ZK lands.
pub trait Verifier {
    fn verify_pi_a(&self, proof: &ProofA) -> Result<()>;
    fn verify_pi_r(&self, proof: &ProofR) -> Result<()>;
}

/// Assume-valid verifier. **DO NOT** ship: it accepts everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct AssumeValid;

impl Verifier for AssumeValid {
    fn verify_pi_a(&self, _proof: &ProofA) -> Result<()> {
        Ok(())
    }
    fn verify_pi_r(&self, _proof: &ProofR) -> Result<()> {
        Ok(())
    }
}
