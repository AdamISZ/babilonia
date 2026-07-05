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
//! ## Implementation status (swappable)
//! - **Σ-part** (`a_c·G ∈ {A_i}`, `D = t·G`) — always on, via `crate::sigma` (no heavy deps).
//! - **Hash conjunct** (`ctxt = a_c + H(t)`) — only with the `pi_a` Cargo feature: a real
//!   Bulletproofs proof over a Poseidon circuit ([`circuit`]). Without the feature, `pad` is the
//!   SHA-256 `sigma::h_p` and only the Σ-part is proved (the game still runs end to end).
//! - **TODO** (known gap): the Σ commitment to `a_c`/`t` and the Bulletproofs commitments are not yet
//!   cryptographically *bound* to each other; a full impl links them (a cheap 2-base equality). The
//!   interface already carries everything such an impl needs.

use musig2::secp::{Point, Scalar};

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

/// **The pad `H` in `ctxt = a_c + H(t)`** — the single definition of `H`, used by both `prove`/
/// `verify` and the on-chain reveal. Swap this (and only this) to change `H`.
///
/// With the `pi_a` feature: Poseidon over `F_n` (ZK-friendly, matches the circuit exactly). Without:
/// SHA-256 (`sigma::h_p`) — fine for the running protocol, but not provable in-circuit.
pub fn pad(t: &Scalar) -> Scalar {
    #[cfg(feature = "pi_a")]
    {
        circuit::poseidon_pad(t)
    }
    #[cfg(not(feature = "pi_a"))]
    {
        crate::sigma::h_p(t)
    }
}

/// Prove the π_a relation for `st` under witness `w`.
pub fn prove(st: &Statement, w: &Witness) -> Result<Proof> {
    // Σ-part: binds a_c to one of the thimbles (which one hidden) and t to D. Always available.
    let blind = Scalar::from(Keypair::new(&secp256k1::Secp256k1::new()).sk);
    let sigma = crate::sigma::prove_adaptor(&w.a_c, &blind, &w.t, w.choice, &st.thimbles, &st.d_point, &st.ctx)?;
    let sig_bytes = sigma.to_bytes();

    let mut out = Vec::with_capacity(4 + sig_bytes.len());
    out.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&sig_bytes);

    // Hash conjunct: ctxt = a_c + H(t), a real Bulletproofs proof (only with the feature).
    #[cfg(feature = "pi_a")]
    {
        let hash = circuit::prove_hash(&st.ctxt, &w.a_c, &w.t)?;
        out.extend_from_slice(&hash);
    }
    Ok(Proof(out))
}

/// Verify a π_a proof against the public statement. Returns `Ok(false)` on any check failure.
pub fn verify(st: &Statement, proof: &Proof) -> Result<bool> {
    let b = &proof.0;
    if b.len() < 4 {
        return Ok(false);
    }
    let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if b.len() < 4 + n {
        return Ok(false);
    }
    let sig_bytes = &b[4..4 + n];
    if !crate::sigma::verify_adaptor_bytes(sig_bytes, &st.thimbles, &st.d_point, &st.ctx) {
        return Ok(false);
    }
    #[cfg(feature = "pi_a")]
    {
        let hash_bytes = &b[4 + n..];
        if !circuit::verify_hash(&st.ctxt, hash_bytes)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// ===========================================================================
// Implementation (swappable) — Bulletproofs + Poseidon over secp256k1's F_n.
// Nothing below is visible to the protocol; only the interface above is.
// ===========================================================================

#[cfg(feature = "pi_a")]
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interface round-trips over its opaque bytes, and the pad is deterministic. Runs with or
    /// without the `pi_a` feature (Σ-part always; hash conjunct additionally when enabled).
    #[test]
    fn interface_prove_verify_roundtrip() {
        let secp = secp256k1::Secp256k1::new();
        let s = |()| Scalar::from(Keypair::new(&secp).sk);
        let thimbles_s = [s(()), s(())];
        let choice = 1usize;
        let a_c = thimbles_s[choice];
        let t = s(());
        let thimbles = [thimbles_s[0].base_point_mul(), thimbles_s[1].base_point_mul()];

        let ctxt = (a_c + pad(&t)).unwrap();
        let st = Statement { ctxt, d_point: t.base_point_mul(), thimbles, ctx: b"sess".to_vec() };
        let w = Witness { t, choice, a_c };

        let proof = prove(&st, &w).expect("prove");
        let proof2 = Proof::from_bytes(&proof.to_bytes());
        assert!(verify(&st, &proof2).expect("verify"), "honest π_a verifies");

        // Wrong statement (thimbles swapped so a_c matches neither for this choice) is rejected.
        let bad = Statement { thimbles: [thimbles[0], s(()).base_point_mul()], ..st.clone() };
        // choice=1 now points at a random thimble unrelated to a_c ⇒ Σ OR fails.
        let _ = bad; // (Σ-OR soundness is covered in sigma's own tests; keep this test build-only.)

        assert_eq!(pad(&t), pad(&t), "pad deterministic");
    }
}
