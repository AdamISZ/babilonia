# Join Construction — Hash-Free Adaptor Reveal, δ-split Settlement (L2 core)

> **⚠ SUPERSEDED BY v5 (2026-07-04).** The single-adaptor reveal described below does **not**
> achieve atomic settlement (see `adaptor_construction_spec_v5.tex` §1). The real construction: one
> output `U1` (pot), whose settlement is a MuSig2 **adaptor locked to `D = d·G`** (completing it
> posts the fresh dealer secret `d`); `RefundTx` at `t_r`; the winner `K = W_b + A_y` claims via a
> taproot `<K>` leaf, Alice reclaims via a `t_1` timeout leaf. The outcome is a hash-padded
> ciphertext `ctxt = a_c + H(d)` (thimbles `A_i = a_i·G`); Bob extracts `d`, gets `a_c = ctxt − H(d)`.
> `π_a` = Σ-part (built) + one hash circuit (TBD). **Implemented + regtest-validated to v5:**
> `src/txgraph.rs`, `src/reveal.rs`, `src/sigma.rs`. This document's construction details are pre-v5
> and scheduled for rewrite with the message layer.


> Status: worked cryptographic core for the **join** geometry (DESIGN.md §5, **[FOCUS]**).
>
> **[DECIDED 2026-07-02, hash-free redesign]** The reveal is carried entirely by a MuSig2
> **adaptor secret**, with **no separate output** exposing a ball point. That kills Kurbatov's
> `hash_p` indirection (it existed only for on-chain key-separation), collapses the thimbles to
> one rank `H_i = h_i·G`, and — with a **Bob-commits-first ordering** — makes both proofs pure
> **secp256k1 sigma protocols** (no SNARK, no trusted setup, no in-circuit hash). There is no
> longer any `t`/`X` blinding scalar or `t_b`: choice-hiding is **temporal** (ordering), not
> cryptographic. Formal note: `adaptor_construction_spec_v5.tex`.
>
> The settlement layout (single reveal-child pot `Q'`, δ-split, fully keypath) from the earlier
> design is unchanged and specified in §5a; the game theory (grief/refund) is unchanged (§7–§8).

---

## 1. Roles, keys, notation

- **Alice = Challenger/chooser**, **Bob = Accepter/guesser**.
- `P_a = x_a·G` — Alice's (public) identity/funding key.
- **Bob has two keys** (this is load-bearing): a **funding key** `P_b = x_b·G` (**public** — it
  enters `Q`) and a **claim key** `W_b = w_b·G` (**hidden until claim**). They *must* differ: if
  `K` reused `P_b`, Alice — who knows `P_b` from `Q` — would compute `K − P_b = H_y` and learn
  `y`. (The old design's `t_b` blind is what previously let one key serve both.)
- **Thimbles:** `h_1, h_2 ←$ F_p`; `H_i = h_i·G`, published with a Schnorr PoK of each `dlog`.
  (No `A_i` rank, no `hash_p` — `H_i` is a plain random point Alice knows the dlog of.)
- Alice's secret **choice** `c ∈ {1,2}`; Bob's secret **guess** `y ∈ {1,2}`.
  **Bob wins iff `y = c`.**
- **Pot key** `Q = MuSig2(P_a, P_b)`, funded by a single joint 2-of-2 output. Settlement spends
  `Q` via **keypath** — one ordinary Schnorr signature, indistinguishable from any P2TR transfer.
- **Reveal:** adaptor point `= H_c`, adaptor secret `= h_c` (surfaces on settlement).
- **Bob's pot-claim key** `K = W_b + H_y`, spendable with `dlog(K) = w_b + h_y`.

Transaction skeleton (δ-split, fully keypath — §5a):

```
TX1 (joint funding) ─► Q_fund = P2TR(Q) ─┬─ RefundTx    nLockTime t_r      [no-reveal fallback]
                                         └─ ChallengeTx (adaptor on H_c)   [THE REVEAL] ─► Q'
Q' = P2TR(Q), spent by exactly one of:
  • CooperativeClose  — fresh plain MuSig2, both sign live               [normal, fully clean]
  • SettleBobWins     — adaptor on K; Bob completes with dlog(K)=w_b+h_y iff he won
  • SettleAliceWins   — plain, pre-signed, nSequence = N relative to Q'
```

---

## 2. The hash-free reveal (the simplification)

Kurbatov used `hash_p(A_c) → h_c` for on-chain **key separation**: his reveal *spent a dedicated
output*, exposing `P_a + A_c`, and the hash kept that exposed value from coinciding with the
claim key. **Here nothing is spent to expose a ball** — the reveal *is* the adaptor secret and
nothing else. So:

- the adaptor secret is set to `h_c` **directly** (adaptor point `H_c`);
- Bob's claim key is `K = W_b + H_y` **directly** (secret `w_b + h_y`);
- no point→scalar bridge is needed, because the reveal already *is* the scalar `h_c`.

Both relations are now fully algebraic (dlog knowledge + a 1-of-2 disjunction) → sigma protocols
(§9). The only property `hash_p` otherwise gave — a domain-separated pseudorandom claim scalar
(replay hygiene) — is recovered by using **fresh thimbles/keys per session**, already assumed.

Choice-hiding does **not** come from the hash, nor from a blinding scalar. It comes from
**ordering** (§3). This is why the earlier design's `t`/`X`/`t_b` are all gone.

---

## 3. The ordering is security-critical — Bob commits first

An adaptor pre-signature `ŝ` locked to point `T` satisfies `ŝ·G + T = R̄ + e·Q`, and `ŝ, R̄, e, Q`
are all public to whoever must verify or complete it. Hence

```
T = R̄ + e·Q − ŝ·G
```

is computable by anyone. **The adaptor point cannot be hidden** — no zero-knowledge OR helps,
because `ŝ` is public and `T` is a deterministic function of it. So if Alice sends `ŝ` locked to
`H_c` **before** Bob picks, Bob computes `H_c`, matches it to the public `H_1, H_2`, sets `y := c`,
and wins with probability 1.

**The fix is temporal, not cryptographic:**

> **Bob commits his pick (`K`, `π_r`) and hands over his settlement partial `s_b`, before Alice's
> adaptor pre-signature `ŝ` exists.**

Then the adaptor point being public is inert: Bob is already locked to `y`. Alice, committing
second, learns nothing about `y` — `K = W_b + H_y` with `W_b` hidden is uniform, so she cannot
tell which thimble it uses. Mutual blindness holds; only the timing changed.

*(This replaces the old `t`-blinding, which hid the adaptor point cryptographically at all times.
The reorder only needs it hidden until Bob commits, which is cheaper — and at settlement the
point becomes public anyway, that being the reveal.)*

---

## 4. Funding + the reveal carrier (ChallengeTx)

`Q = MuSig2(P_a, P_b)` with aggregation coefficients `μ_a, μ_b`, `P_agg = μ_a·P_a + μ_b·P_b`.
Funded by joint 2-of-2 `TX1`. **RefundTx** (spends `Q_fund` back to the stakes, `nLockTime t_r`)
is pre-signed before `TX1` is broadcast — else a stake can be held hostage in the 2-of-2.
**Correctness condition:** `t_r > t_1`, where `t_1` is Alice's settlement fallback timelock; if
`t_r ≤ t_1` the refund becomes a new outcome-conditioned abort path (§7).

The reveal carrier **ChallengeTx** spends `Q_fund → Q'` as a MuSig2 keypath spend, message `m` =
its fixed sighash. Challenge `e = H(R̄, Q, m)` over the aggregate nonce (public). Alice's adaptor
pre-signature `ŝ` is locked to `H_c`:

```
ŝ·G + H_c = R̄ + e·Q ,   completion   s_a = ŝ + h_c .
```

This is the **s-value adaptor** convention: `e` is over the *un-adapted* nonce `R̄`, and `H_c`
enters only Alice's side of the `s`-equation. Consequently **Bob's partial `s_b` is a plain
MuSig2 partial that never references `H_c`** — so he can produce it in his commit (§3) *before*
`c` is revealed. That is exactly what makes the Bob-commits-first ordering implementable in one
pass. (The alternative nonce-adaptor convention, `e = H(R̄+H_c, …)`, would force Bob to know `H_c`
to sign, defeating the ordering. Code note: `SettleBobWins`'s adaptor point `K` is public to
both, so it may use the ordinary nonce form; only ChallengeTx needs the s-value form.)

Bob already provided his plain partial `s_b` (§3). Alice broadcasts ChallengeTx with the
completed aggregate `s = ŝ + h_c + s_b`, a valid BIP340 signature under `Q`. By adaptor
soundness, any `h' ≠ h_c` yields an invalid signature, so **settlement must reveal the true
`h_c`.** Bob recovers it from the on-chain signature:

```
h_c = s − ŝ − s_b .
```

> **BIP340 wrinkle (implementation):** x-only keys/nonces impose parity conventions; the `h_c`
> extraction must account for the sign of `H_c` (and `R`/`Q` parity). Handled by the MuSig2 +
> adaptor library; flagged so it isn't lost.

Alice's decision to broadcast (reveal) is **outcome-blind** — `π_r` and hidden `W_b` keep `y`
secret from her, so she cannot selectively withhold based on the result.

---

## 5. Bob's claim & `π_r`

Bob forms `K = W_b + H_y` (`dlog(K) = w_b + h_y`) and proves to Alice:

```
R_r = { (w_b, y) :  ⋁_{y∈{1,2}}  ( K − H_y = w_b·G ) }
```

A Fiat–Shamir CDS **1-of-2 OR** of Schnorr **dlog-knowledge** clauses: for the chosen `y`,
knowledge of `w_b = dlog(K − H_y)`. Since `W_b = K − H_y` on that branch, this *already*
establishes `W_b = w_b·G` — there is **no separate, duplicated `W_b = w_b·G` clause**. The proof
hides both `x_b` and `y`, binds `K` to exactly one thimble, and blocks a rogue `K` opening to
both. Hiding `y` is load-bearing: Alice's outcome-blindness depends on it.

---

## 5a. δ-split settlement — fully keypath **[BUILD TARGET]**

The pot `Q'` is the reveal-child of ChallengeTx, keyed by `Q = MuSig2(P_a,P_b)`. A δ-split means
the winner owes the loser `d−δ`, so a free keypath sweep can't settle → settlement is
fixed-output pre-signed txs (DESIGN §8.2), and every path stays keypath (the CSV-leaf all-or-
nothing reduction is retired).

**Amounts (v1 defaults; per-party stakes, see PROTOCOL.md §5).** Stakes `S_a, S_b` (may be
unequal); wager `δ` with `0 ≤ δ ≤ min(S_a,S_b)`; winner `S_i+δ`, loser `S_i−δ` (−fees).

Three ways to spend `Q'`, all keypath:

1. **CooperativeClose [normal path].** After the reveal, both compute the outcome and co-sign a
   fresh plain MuSig2 spend with the correct split, current fee, `SIGHASH_DEFAULT`. Fully clean.
2. **SettleBobWins [Bob's fallback].** Pre-signed, fixed outputs. Alice's partial is
   **adaptor-locked on `K`**, so Bob completes it iff he knows `dlog(K) = w_b + h_y` — i.e. iff
   he won (`h_c = h_y` revealed). Immediate; fixed outputs enforce Alice's `S_a−δ`.
3. **SettleAliceWins [Alice's fallback].** Pre-signed by both, fixed outputs,
   `nSequence = N` **relative to `Q'`**. Alice broadcasts after `N`. Needs no secret; the
   relative lock gives Bob his claim window measured from the reveal.

---

## 6. Settlement timeline

1. **Alice broadcasts ChallengeTx** (completes the adaptor with `h_c`) — the outcome-blind
   reveal; `h_c` goes public, `Q'` is created.
2. **Bob** recovers `h_c = s − ŝ − s_b`, and wins iff `H_c = H_y` (equivalently `h_c = h_y`).
3. **Bob won:** he holds `w_b + h_y` and takes `Q'` (CooperativeClose, or SettleBobWins within
   the `N`-block window). **Bob lost / negligent:** after `N`, Alice takes `Q'` (SettleAliceWins).
4. **Alice never reveals:** at `t_r`, RefundTx returns both stakes (no grief; §7).

---

## 7. Security & game theory

### Fairness — from ordering (§3), not from a hash

- **Mutual blindness at commit.** Bob fixes `y` (§3) *before* `ŝ` exists, so he cannot bias
  toward `c`. Alice fixes `c` knowing only `K, π_r`, which hide `y` (because `P_b` is secret), so
  she cannot bias toward `y`.
- **Alice cannot straddle.** `ŝ` locks to a single `H_c`; adaptor soundness forces exactly that
  `h_c` into the open at settlement.
- **Bob cannot straddle.** `π_r` forces `K = W_b + H_y` for exactly one `y`.
- **Early outcome knowledge is inert.** Bob may compute `H_c` from `ŝ` one step early; harmless,
  since a winning Bob only waits to claim and a losing Bob has no lever.
- **No outcome-conditioned abort.** After his commit Bob has no input to the settlement; Alice
  settles alone, **blind to the outcome**, so she has no basis to selectively withhold.

### Grief / liveness (unchanged; one still open)

- **No win-by-withholding (fairness).** Alice's only path to the pot runs through the reveal;
  not revealing ⇒ RefundTx ⇒ stakes back, nothing more. Withholding is a **blind abort**, not a
  grief. This is the fix Kurbatov's Algorithm 2 lacks (its pot fallback is "Alice wins").
- **Relative timeout (no window compression).** Alice's SettleAliceWins uses `nSequence = N`
  **relative to `Q'`**, so Bob always gets a full window from the reveal. An *absolute* `t_1`
  would let Alice compress it by revealing late — **[carryover fix vs the .tex, which still
  writes an absolute `t_1`]**.
- **No Bob veto.** Alice's timeout needs no close-time signature from Bob (he pre-signed
  SettleAliceWins at setup and cannot retract).
- **[OPEN] Liveness.** The refund fallback makes withholding *costless* as well as profitless —
  Alice can blind-abort at no penalty. Fairness is closed; penalizing abort needs a griefing
  bond (DESIGN §5).

**Still load-bearing:** soundness of `π_r`, `π_a`; the Schnorr PoKs on `H_1,H_2`; MuSig2 nonce
hygiene; and — critically — the **§3 ordering**.

---

## 8. Forcing & liveness — composition with DESIGN §5 (NOT solved here)

Fairness (no theft) is closed by the refund-not-Alice-win fallback. **Liveness** — a costless
blind abort — is not: a party can walk without penalty. Penalizing abort needs a griefing bond /
forcing deposit (DESIGN §5). Out of scope for this core.

---

## 9. Proofs — pure sigma protocols over secp256k1

The hash-free redesign removes the only non-Schnorr part of the old core (the two in-circuit
`hash_p` evaluations). **No general-purpose ZK backend is required.**

- **`π_r` (Bob → Alice):** the 1-of-2 CDS-OR of §5. Hides `y` and `w_b`, binds `K`. A few
  hundred bytes, sub-millisecond, no setup.
- **`π_a` (Alice → Bob): no OR.** Because Bob is *already committed* (§3), `c` need not be
  hidden, so `π_a` degenerates to (i) the two Schnorr PoKs on `H_1, H_2` (well-formedness,
  exchanged when the thimbles are published) and (ii) a **plain public** adaptor verification
  `R̄ + e·Q − ŝ·G ?= H_c` for the `c` Alice names. No zero-knowledge OR.
- **Fiat–Shamir transcript hash** is any standard hash (SHA-256 or a BIP340 tagged hash); it is
  transcript-only and never enters an arithmetic circuit, so its choice is unconstrained.
- **Nonces** in the sigma proofs must be fresh and independent of the MuSig2 signing nonces.

*(Optional late-reveal variant — keep Bob ignorant of the outcome until settlement: withhold
`ŝ` and OR-prove that a valid pre-sig exists locked to `H_1` or `H_2` with `ŝ` in the witness.
This is the one place an OR earns its keep, precisely because the blinded quantity `ŝ` is then
secret. See the .tex. Not needed in the base flow, where early knowledge is inert.)*

---

## 10. Round complexity — 3-flight fused setup

The commit **is** the pre-signature exchange, so commit + both MuSig sessions (refund,
settlement) + funding-template exchange fuse into **three message flights** (Alice → Bob →
Alice), which is the floor:

1. **Alice → Bob:** proposal + thimbles `H_1,H_2` (+ Schnorr PoKs) + her funding inputs/scripts
   + her MuSig nonces.
2. **Bob → Alice:** his inputs/scripts + `K` + `π_r` + his nonces + his partials (refund *and*
   settlement `s_b`).
3. **Alice → Bob:** her refund partial + adaptor pre-sig `ŝ` (+ the trivial `π_a`) + her `TX1`
   input signature.

Bob then assembles and broadcasts `TX1`. Three is the information-theoretic floor: the
commit-blind ordering forces Alice→Bob→Alice, and the 2-party MuSig2 refund (nonce round, then
partial round) forces the same. A 4th flight only if you want **Alice** to broadcast instead of
Bob. Full wire detail: PROTOCOL.md §7.

---

## 11. Open items

1. **Security proofs** (fairness, adaptor soundness under this ordering, `π_r`/`π_a` soundness &
   ZK) — being worked independently.
2. **[Liveness] forcing** — refund fallback fixes fairness but leaves costless abort; needs a
   griefing bond (DESIGN §5).
3. **Relative-timelock parameters** `N` (Bob's window) and `t_r > t_1`; carry the absolute→
   relative fix into the .tex.
4. **BIP340 parity** in the `h_c` extraction (§4 wrinkle).
5. MuSig2 nonce hygiene across RefundTx / ChallengeTx / settlements (independent per session).
6. Enforce `H_1 ≠ H_2` (distinct thimbles) on Bob's side.
