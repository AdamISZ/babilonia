//! **Superseded / vestigial.** The real proofs are the hash-free sigma protocols in
//! [`crate::sigma`] — `π_a` = two Schnorr PoKs on the thimbles, `π_r` = a CDS 1-of-2 OR —
//! generated and verified inline by `setup`. This module is only the old assume-valid `Verifier`
//! seam, still referenced by the `protocol` skeleton; the live `setup` path does not use it.
//! `AssumeValid` accepts everything and **must not** ship.

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
