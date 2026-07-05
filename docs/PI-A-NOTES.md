# π_a — the encrypted-outcome well-formedness proof

π_a proves, for public `(ctxt, D, {A_1, A_2})` and secret `(t, c, a_c)`:

```
  ctxt = a_c + H(t)          the ciphertext decrypts to a_c under the pad H(t)
∧ a_c·G = A_c   (c ∈ {1,2})  a_c is the chosen thimble's scalar (which one hidden)
∧ D = t·G                    t is the secret the settlement adaptor will reveal
```

The interface (`src/pi_a.rs`: `Statement`, `Witness`, `Proof`, `pad`, `prove`, `verify`) is fixed;
the *construction* behind it is selectable via `pi_a::Scheme` and is an open research question. This
note records the candidates and the trade-offs. **All are PoC-stage; none is safety-justified yet.**

## Implemented schemes (the `Scheme` flag)

### `Scheme::Squaring` — sigma-based, `H(t) = t²` (default)

`docs/SquaringBasedProof.pdf`. Because `t² = t·(t·G)`, the whole relation is

```
∃ c ∈ {1,2}, t :  D = t·G  ∧  (ctxt·G − A_c) = t·D
```

which is a **CDS-OR of two Chaum–Pedersen DLEQ proofs** `DLEQ(G,D; D, Y_i)`, `Y_i = ctxt·G − A_i` —
pure sigma protocols, no Bulletproofs, no hash circuit. Proof is 128 bytes (`e_0∥z_0∥e_1∥z_1`),
prove/verify are a handful of EC ops.

- **Complete:** the single OR-DLEQ proves the entire relation (no separate hash conjunct, no
  commitment-binding gap).
- **Security:** branch-hiding rests on a **DDH / square-DH** assumption; and the `t²` mask is a
  **quadratic residue**, so `ctxt − a` is QR-testable for any *guessable* `a`. Therefore this scheme
  is safe **only for high-entropy masked scalars** — which our thimble scalars and `t` are (uniform
  in `F_n`). It must never be used to hide low-entropy plaintexts (amounts, counters, votes).
- Only hides `t` and the branch **before** the settlement completes; afterwards `t` (hence `a_c` and
  the branch) is intentionally revealed. That is exactly the game's reveal.

### `Scheme::Poseidon` — hand-rolled ZK hash (Cargo feature `pi_a`)

`H(t) = Poseidon(t)` over `F_n`; the hash conjunct `ctxt = a_c + H(t)` is a **Bulletproofs** circuit
(Curve Trees generic-arkworks R1CS over secp256k1), plus the Σ-part (Pedersen + thimble OR + PoK of
`t`). Field-native (`x⁵` S-box, `gcd(5, n−1)=1`). ~432 gates; **~187 ms prove / 42 ms verify / 1187 B**
(release, benchmarked). Transparent (no trusted setup).

- **Caveat (not safety-justified):** the round constants (SHA-256 NUMS, not the reference Grain
  LFSR), the Cauchy MDS, and `R_P = 56` are **tentative** — they must be regenerated with the
  reference Poseidon tooling for `F_n` and `R_P` confirmed before any security claim. The bespoke
  parameters are the reason this scheme is a starting point, not a final answer.
- **Known gap:** the Σ commitment to `a_c`/`t` and the Bulletproofs commitments are not yet
  cryptographically bound (a future cheap 2-base equality). The `Squaring` scheme has no such gap.

## A reviewed alternative — Purify (MuSig-DN)

*MuSig-DN: Schnorr Multi-Signatures with Verifiably Deterministic Nonces* — Nick, Ruffing, Seurin,
Wuille, ACM CCS 2020 (eprint 2020/1057, `docs/2020-1057.pdf`; reference C code:
`github.com/jonasnick/secp256k1-zkp`, branch `bulletproof-musig-dn-benches`).

MuSig-DN needed to prove a PRF evaluation in zero knowledge over secp256k1 with Bulletproofs — the
same shape as our hash conjunct. They **rejected SHA256** (22,493 gates for one compression;
91,559 for HMAC-SHA256) and designed **Purify**, an algebraic PRF: `F_u(z) = f(u₁·H₁(z) +
τ⁻¹(u₂·H₂(z)))`, where `f` extracts the x-coordinate of a point on auxiliary curves `E₁/E₂` **defined
over F_p** (the circuit's field = secp256k1's scalar field). So Purify is **field-native** — its
output is an `F_p` element, `≈ 2030` multiplication gates, **943 ms prove / 61 ms verify / 1124 B**.

Why it's an attractive π_a candidate:

- **Field-native**, like Poseidon (no bit-decomposition / mod-`n` reduction that SHA256 would force).
  This works via a two-tower trick: the auxiliary curves' *coordinate* field is chosen to be the
  outer curve's *scalar* field, so an extracted x-coordinate lands in the circuit field.
- **Peer-reviewed**, on a clean **DDH** assumption — fixing exactly the bespoke-params liability of
  our hand-rolled Poseidon.
- Maps naturally onto our use: put our `t` in Purify's key slot `u`, and `D = t·G` is its public
  `uP`; the DDH assumption gives precisely the hiding `ctxt = a_c + H(t)` needs.

Open items before adopting Purify: it uses the outer group secp256k1 (so `F_p` = our `F_n`, and its
`E₁/E₂` port directly to our arkworks Bulletproofs), but (a) the reference code is C, not Rust, so
the ~2030-gate circuit would be ported, and (b) the scalar reductions `u₁ = u mod q₁`, `u₂ = u mod
q₂` (the auxiliary curve orders) are an input-side subtlety to verify.

## Where this leaves us

- **Feasibility is settled** on the real curve for the ZK-hash route (Poseidon benchmarked), and the
  sigma route (`Squaring`) is complete and cheap with no heavy deps.
- **Safety is not** decided. `Squaring` needs its DDH/QR model validated for our exact use;
  `Poseidon` needs reference params; **Purify** is the most promising "reviewed + field-native"
  target if the sigma route's QR caveat proves too restrictive. Choosing among them is future work.
