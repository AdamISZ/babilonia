# Join Construction — Single-Anchor Pot with In-Script Relative Timeout (L2 core)

> Status: worked cryptographic core for the **join** geometry (DESIGN.md §5, **[FOCUS]**).
>
> **[DECIDED 2026-07-02, two steps]**
> 1. Settlement is a **single post-reveal pot UTXO** `Q'` (created by the reveal), not two
>    sibling outputs — this closes Kurbatov's grief (see §8). All win-conditions descend from
>    the reveal; Alice's timeout is **relative to `Q'`** (no window-compression).
> 2. **[SUPERSEDES §5–§6 below]** With **δ-split stakes** (the chosen build target), the
>    winner must *not* sweep the whole pot (they owe the loser `d−δ`), so a free keypath spend
>    can't settle. This **forces fixed-output, pre-signed settlements** — the DESIGN §8.2
>    "both outcomes adaptor-signed at setup" model — which is **fully keypath**. So `Q'`
>    keypath = `MuSig2(P_a,P_b)`, `K_b` demotes to the *gating adaptor point* for Bob's
>    fallback, and the CSV **leaf is eliminated**. δ-splits therefore *recover* full
>    payment-indistinguishability rather than costing it; the residual is only DESIGN §8's
>    fee-rigidity tell on the **unilateral** fallbacks (the cooperative close is clean).
>
> §5–§6 below describe the **all-or-nothing reduction** (keypath = `K_b`, Alice on a CSV
> leaf). Keep as the simplest correct core; the δ-split model in **§5a** is the build target.

---

## 1. Roles, keys, notation

- **Alice = Challenger/chooser**, **Bob = Accepter/guesser**.
- `sk_A = x_a`, `P_a = x_a·G`; `sk_B = x_b`, `P_b = x_b·G`.
- `hash_p : {0,1}* → F_p` (hash-to-scalar), modeled as a random oracle.
- Alice thimble secrets `a_1, a_2 ← F_p`; `A_k = a_k·G`; `h_k = hash_p(A_k)`; `H_k = h_k·G`.
- Alice's secret **choice** `i* ∈ {1,2}`; Bob's secret **guess** `j* ∈ {1,2}`.
  **Bob wins iff `j* = i*`.**
- Blinding scalars `t` (Alice), `t_b` (Bob); `T = t·G`.
- **Auxiliary** value `X = t·(P_a + A_{i*})` — *published, NOT a signing key* (the decoupling, §2).
- Bob's pot-claim key `K_b = t_b·(P_b + H_{j*})`, with `dlog(K_b) = t_b·(x_b + h_{j*})`.

### Transaction skeleton (single shared anchor)

```
Funding TX1:  [Alice v_A, Bob v_B]  ->  Q_fund = MuSig2(P_a, P_b)     (+ change)

Q_fund is spent by exactly one of (both pre-arranged at setup over L1):
  (a) RefundTx    : Q_fund -> {v_A->Alice, v_B->Bob},  nLockTime T2, keypath (both pre-sign)
                    -- the NO-REVEAL fallback; NOT "Alice wins".
  (b) ChallengeTx : Q_fund -> Q' ;  Bob pre-signs his MuSig half, Alice completes with the
                    decoupled adaptor (§4), which LEAKS t on broadcast.   <-- THE REVEAL

The pot Q' (created only by ChallengeTx) is a taproot output with two conditions:
  keypath : K_b = t_b·(P_b + H_{j*})                          [Bob wins — immediate, private]
  leaf    : <N> OP_CSV OP_DROP <P_a'> OP_CHECKSIG             [Alice wins — after N blocks]
                (N = relative timelock, BIP68, counted from Q' confirmation)
```

- `Q'` is fully specified at setup: `K_b` comes from Bob's `π_r` (§5), the leaf is public, so
  the taproot output key `Q' = K_b ⊕ taptweak(K_b, leaf)` is computable before either party
  is committed on-chain. Hence `ChallengeTx` is pinned at setup and Bob can pre-sign it.
- `P_a'` is a fresh Alice key for the timeout leaf (unlinkable to `P_a`).
- **Why the pot must be the reveal's child, not a funding output:** a relative timelock
  (BIP68) counts from the confirmation of the *coin being spent*. Only if `Q'` is created by
  `ChallengeTx` does the CSV count from the **reveal**; and only then does Alice's win-path
  presuppose the reveal. Put the pot at funding and its leaf is a no-reveal Alice-win counted
  from funding — Kurbatov's grief (§8).

---

## 2. The decoupling (unchanged result)

The earlier draft made the *signing key* `X = t·(P_a + A_{i*})`, so the MuSig key-share's
secret `x = t·(x_a + a_{i*})` shared the factor `t` with the adaptor secret — a non-standard
adaptor signature. **We avoid this entirely:**

> `Q_fund = MuSig2(P_a, P_b)`. Alice signs with her ordinary secret `x_a`. The adaptor point
> is `T`. `X` is demoted to auxiliary data proven in `π_a`. The signing key is therefore
> **independent** of the adaptor secret → a textbook Schnorr adaptor signature.

Why this is safe and why we can't go further (use `a_{i*}` directly as the adaptor secret):
see §7.

---

## 3. Alice's commitments + proof `π_a`

Alice sends Bob: the TX1 template, `H_1, H_2`, `T`, `X`, and a proof `π_a` for

```
R_a = { witness (a_1, a_2, t) ; statement (P_a, H_1, H_2, T, X, G) :
        A_1 = a_1·G  ∧  A_2 = a_2·G
      ∧ h_1 = hash_p(A_1)  ∧  h_2 = hash_p(A_2)
      ∧ H_1 = h_1·G  ∧  H_2 = h_2·G
      ∧ T = t·G
      ∧ ( X = t·(P_a + A_1)  ∨  X = t·(P_a + A_2) ) }
```

- The OR hides `i*` from Bob; the conjuncts bind `X` to **one** well-formed thimble.
- `(P_a + A_1) ≠ (P_a + A_2)` ⇒ `X` equals exactly one branch ⇒ Alice is committed to `i*`
  and cannot equivocate later (§7).
- Knowledge of `x_a = dlog(P_a)` is **not** part of `π_a`; it is established by Alice
  actually signing in the MuSig (§4).

**Proof structure (DESIGN §4, §9):** everything except the two `hash_p` evaluations is
generalized Schnorr — DL-knowledge for `A_k,H_k,T`, and a Chaum–Pedersen DLEQ-OR for the `X`
branch. Only `h_k = hash_p(A_k)` (k=1,2) needs an in-circuit hash.

---

## 4. The reveal — decoupled adaptor on `ChallengeTx`

The reveal is folded into `ChallengeTx` (spending `Q_fund → Q'`). There is no separate
carrier output: Alice's *only* route to `Q'` is completing this adaptor, and completing it
publishes `t`. Message `m` = the fixed `ChallengeTx`; its fee is pinned at setup (DESIGN §8
fee-rigidity tell applies to this unilateral path).

`MuSig2(P_a, P_b)` with aggregation coefficients `μ_a = H_agg(L,P_a)`, `μ_b = H_agg(L,P_b)`,
`L = {P_a,P_b}`, `P_agg = μ_a·P_a + μ_b·P_b`. MuSig flow with adaptor point `T`:

1. Nonces: Alice `R_a = k_a·G`, Bob `R_b = k_b·G`. **Commitment round** `H(R_a), H(R_b)`
   exchanged *before* `R_a, R_b` — load-bearing (blocks adaptive nonce grinding).
   `R_agg = R_a + R_b`.
2. Challenge over the **adapted** nonce: `e = H(R_agg + T, P_agg, m)`.
3. Bob's partial (plain): `σ_b = k_b + e·μ_b·x_b`.
4. Alice's **adaptor** partial (on her ordinary key): `σ'_a = k_a + e·μ_a·x_a`.
5. Bob verifies the pre-signature: `σ'_a·G ?= R_a + e·μ_a·P_a`.
   (Bob computes `e` using the `T` committed in `π_a` — Alice is forced to adaptor against
   *that* `T`; she cannot substitute a `T'`.)

**Completion & reveal.** Alice (holding `σ_b` from setup) computes `σ_a = σ'_a + t`,
`s = σ_a + σ_b`, and broadcasts `ChallengeTx` with BIP340 signature `(R_agg + T, s)`.

Validity:
```
s·G = (σ'_a + t + σ_b)·G
    = (R_a + e·μ_a·P_a) + T + (R_b + e·μ_b·P_b)
    = R_agg + T + e·P_agg        ✓  (valid BIP340 sig for P_agg under nonce R_agg+T)
```
Bob recovers `t = s − σ_b − σ'_a`, then
```
t⁻¹·X = P_a + A_{i*}   ⇒   A_{i*} = (t⁻¹·X) − P_a   ⇒   h_{i*} = hash_p(A_{i*}).
```

> **BIP340 wrinkle (implementation):** x-only keys/nonces impose parity conventions; the
> `t = s − σ_b − σ'_a` extraction must account for the sign of `T` (and `R`/`P_agg` parity).
> Standard in adaptor-sig-on-taproot; flagged so it isn't lost.

---

## 5. Bob's side — the pot key `K_b` and proof `π_r`

Bob picks `j*`, blinds with `t_b`, sets `K_b = t_b·(P_b + H_{j*})`, and proves to Alice:

```
R_r = { witness (x_b, t_b) ; statement (P_b, H_1, H_2, K_b, G) :
        dlog(P_b) = x_b
      ∧ ( K_b = t_b·(P_b + H_1)  ∨  K_b = t_b·(P_b + H_2) ) }
```

- Alice needs this so `K_b` is genuinely gated on a real guess (`H_1` or `H_2`) and is not a
  key Bob could spend unconditionally (which would steal the pot regardless of the coin). The
  `dlog(P_b)` knowledge blocks rogue-key construction.
- `π_r` is **pure generalized Schnorr — no hash circuit** (the `H_k` are already public
  points; DLEQ-OR + DL-knowledge). The in-circuit hash lump lives only in `π_a`.

**`K_b` is the taproot keypath of `Q'`.** The output key is `Q' = K_b + taptweak(K_b, leaf)·G`.
Bob can spend the keypath only with `dlog(K_b) + taptweak`, and `dlog(K_b) = t_b·(x_b+h_{j*})`
requires `h_{j*}` — which becomes public (as `h_{i*}`) **iff `j* = i*`**. So:

- **Bob won (`j*=i*`):** `h_{j*}=h_{i*}` is revealed ⇒ Bob computes `dlog(K_b)` ⇒ **keypath spend**.
- **Bob lost (`j*≠i*`):** `h_{j*}` is never revealed (only `h_{i*}` is; `h_{j*}=hash_p(A_{j*})`
  needs `a_{j*}`, which Alice keeps). Neither party can spend the keypath — it is dead.

The inequality case needs **no** on-chain enforcement (Kurbatov's match-gating): a losing Bob
simply cannot produce the keypath signature. The leaf then carries Alice.

---

## 5a. δ-split settlement — fully keypath **[BUILD TARGET]**

The §5 layout sweeps the whole pot to the winner, so a free keypath spend suffices. With a
**δ-split** the winner owes the loser `d−δ`, so settlement outputs must be **fixed and
enforced**. That forces pre-signed settlements (DESIGN §8.2) — and the payoff is that *every*
path stays keypath; the §5 CSV leaf disappears.

**Amounts (v1 defaults).** Deterministic split `d_A = v_A`, `d_B = v_B` (each stake returned),
equal stakes `v_A = v_B = S` so the coin is fair, and a single wager `δ` fixed in Alice's
opening proposal. Outcomes: winner `d + δ`, loser `d − δ` (fees TBD). All placeholder.

**`Q'` (reveal-child) keypath = `MuSig2(P_a, P_b)`** — cooperative. `K_b` is demoted to a
*gating adaptor point* (below), not a spending key.

Three ways to spend `Q'`, all keypath:

1. **Cooperative close [normal path].** After `ChallengeTx` reveals `t`, both parties compute
   the outcome (`h_{i*}·G ?= H_{j*}`) and co-sign a **fresh** `MuSig2` keypath spend paying the
   correct split, current fee, `SIGHASH_DEFAULT`. Genuinely payment-shaped; no tells.
2. **`SettleBobWins` [Bob's unilateral fallback].** Pre-signed at setup, fixed outputs
   `{d_B+δ → Bob, d_A−δ → Alice}`. Alice's `MuSig2` partial is **adaptor-locked on `K_b`**, so
   Bob completes it **iff** he knows `dlog(K_b) = t_b·(x_b+h_{j*})` — i.e. **iff he won**
   (needs the revealed `h_{i*}=h_{j*}`). Immediate; fixed outputs enforce Alice's `d_A−δ`
   even though Bob drives the spend.
3. **`SettleAliceWins` [Alice's unilateral fallback].** Pre-signed by **both** at setup (Bob
   cannot later retract → no veto), fixed outputs `{d_A+δ → Alice, d_B−δ → Bob}`, with
   `nSequence = N` **relative to `Q'`** (BIP68 on a keypath spend — no opcode). Alice
   broadcasts after `N`. Needs no secret (her win isn't secret-gated); the relative lock gives
   Bob his priority window measured from the reveal.

**Settlement order.** `ChallengeTx` (reveal) → then one of {cooperative close | `SettleBobWins`
| `SettleAliceWins`}. If Bob won and is prompt he takes (1) or (2) within `N`; if he's negligent
past `N`, Alice's (3) pays the *Alice-wins* split (his liveness fault, as in §5). No reveal ⇒
`RefundTx` at `T2`.

**Pre-signing chain (setup ordering).** `K_b` (from `π_r`) and both settlement scripts are
known at setup ⇒ `Q'` is computable ⇒ `ChallengeTx` (spending the known `Q_fund` outpoint) is
pinned ⇒ its txid fixes the `Q'` outpoint ⇒ `SettleBobWins`/`SettleAliceWins` and `RefundTx`
can all be pre-signed **before TX1 is broadcast**. Invariant: no funds enter `Q_fund` until
`RefundTx` is fully pre-signed (recovery always guaranteed; a stalled setup is costless).

**What stays load-bearing / residual.** Game theory is identical to §7 (reveal-child anchor,
refund fallback, relative timeout, no Bob veto, outcome-blind reveal). Privacy: cooperative
close is fully clean; the two unilateral fallbacks carry DESIGN §8's fee-rigidity/anchor tell
(pre-signed ⇒ fixed fee). Nonce hygiene across `RefundTx`/`ChallengeTx`/all three settlements
is mandatory (distinct MuSig2 sessions; DESIGN §10 open #2).

> **Why the loser cooperates (the finesse, now with teeth).** Both parties are here to mix, so
> both want their *received* output (`d±δ`) to be clean coins. Only the cooperative close (1)
> gives that; the unilateral fallbacks taint both outputs with the §8 tell. In all-or-nothing
> the loser receives nothing, so had no such incentive — δ>0 is what makes cooperation
> individually rational, not just polite.

---

## 6. Settlement & timeline (all-or-nothing reduction)

Once live, Alice's only move toward the pot is to broadcast `ChallengeTx`.

1. **Alice broadcasts `ChallengeTx`** (completes the adaptor) ⇒ `Q'` is created; `t`, hence
   `A_{i*}`, `h_{i*}`, are public. This is **outcome-blind**: `π_r` hides `j*`, so Alice
   decides to reveal *before* she can learn whether Bob won.
2. **Bob won (`h_{j*}=h_{i*}`):** Bob spends `Q'` via **keypath** `K_b` immediately, inside
   the `N`-block window. Bare keypath spend — payment-shaped.
3. **Alice won (`j*≠i*`) or Bob negligent:** after `N` blocks (BIP68, relative to `Q'`),
   Alice spends `Q'` via the **CSV leaf**. Script-path spend — the indistinguishability cost.
4. **Alice never reveals:** at `T2`, `RefundTx` returns both stakes. Alice gains nothing by
   withholding.

**Timelock parameters.** `N` (relative, from `Q'`) sizes Bob's guaranteed claim window. `T2`
(absolute, on `RefundTx`) is the abort deadline for the reveal itself. Constraint: `T2` must
leave Alice time to reveal, and once `ChallengeTx` confirms, `RefundTx` is void (it spends the
now-spent `Q_fund`), so `N` may extend past `T2` without conflict. Nonce hygiene across
`RefundTx`/`ChallengeTx`/settlement spends is mandatory (DESIGN §10 open #2).

---

## 7. Security & game-theoretic properties

### Fairness / no-grief (the point of this layout)

Outcome `= [i* == j*]` with both committed blind before the reveal, and — crucially — **the
reveal is the single event both win-conditions descend from:**

- **No win-by-withholding.** Alice's *only* path to `Q'` is `ChallengeTx`. Not revealing ⇒
  `RefundTx` ⇒ stakes back, nothing more. Withholding is a **blind abort, not a grief**.
  *(This is the fix Kurbatov Algorithm 2 lacks — its pot fallback is "Alice wins", so a
  rational Alice never reveals and takes the pot; see §8.)*
- **No window compression.** Bob's window is `N` blocks **relative to `Q'`**, i.e. relative
  to the reveal. Alice cannot shrink it by revealing late — the flaw of an *absolute*
  timeout, where the window `[reveal, T1)` is Alice-controlled.
- **No Bob veto.** Alice's timeout needs no close-time signature from Bob — a CSV leaf she
  satisfies alone (reduction), or a settlement Bob *already* pre-signed at setup and cannot
  retract (δ-split target, §5a). Either way he cannot block her win (the failure mode of any
  two-cooperative-tx sequencing).
- **Outcome-blindness.** Alice must reveal before learning `j*` (`π_r` hides it), so she
  cannot reveal-only-when-winning. Her EV from aborting equals her EV from playing a fair
  coin ⇒ no profitable deviation. *(Liveness — costless abort — is a separate matter, §8.)*
- **Bob-negligence** (won but sleeps past `N`): pot goes to Alice's timeout branch. His own
  liveness fault, not an Alice lever — and with `N` fixed by the protocol (not Alice), it is
  genuinely his fault, not an engineered squeeze.

### Cryptographic properties (unchanged from the decoupled core)

- **Anti-equivocation.** `X` is bound to one branch by `π_a`; the adaptor is verified against
  the `T` committed in `π_a`. Alice cannot reveal a `t'` for a different thimble — the pre-sig
  fails Bob's §4 check. *(Resolves DESIGN open #1 for the join.)*
- **No early extraction.** Pre-broadcast, Bob holds `σ'_a = k_a + e·μ_a·x_a` (1 eqn, 2
  unknowns) and the DDH tuple `(G, T, P_a+A_{i*}, X)`; recovering `t` is CDH. He cannot learn
  the outcome or sign early.
- **Standard adaptor.** Signing key `x_a` ⟂ adaptor secret `t`, so Schnorr-adaptor security
  applies directly. *(Sidesteps DESIGN open #3.)*
  - Residual: publishing `X = t(P_a+A_{i*})` beside a standard adaptor on `P_a` adds only the
    DDH tuple above; extracting anything reduces to DL. Believed clean; written reduction owed.
- **Why not decouple further** (use `a_{i*}` as the adaptor secret): the adaptor point would
  be `A_{i*}`, which Bob sees pre-completion; he could compute `hash_p(A_{i*})·G` and match it
  to `H_1/H_2`, learning `i*` early and always winning. The `t`-blinding of `T` and `X` is
  therefore **essential to hiding the choice**.

**Still load-bearing:** soundness of `π_a` and `π_r`; MuSig nonce-commitment; `hash_p` as RO.

---

## 8. What this resolves, and what it costs

> **Scope note.** The **Resolved** part below (grief/fairness) holds for *both* models. The
> **Cost 1** indistinguishability accounting is for the **all-or-nothing reduction** only — the
> **δ-split build target (§5a) eliminates it**: settlement is fully keypath, so the
> "*Keypath relative-timeout*" and "*Cooperative Alice-win*" finesses listed below are already
> realized there, not deferred. **Cost 2** (liveness / costless abort) remains open in both.

**Resolved: the forcing/grief problem** that the two-output layout (and Kurbatov Algorithm 2)
left open. Kurbatov's pot output `(10B, addr_b ∨ (P_a + LT))` makes Alice's fallback *Alice
wins* on an absolute/funding-relative timelock; a rational Alice never reveals, waits out
`LT`, takes the pot, and recovers her carrier afterward — a total fairness break the paper
does not address. Routing both payouts through the reveal-child `Q'` with a **refund**
(not Alice-win) no-reveal fallback and a **relative** timeout closes it (§7).

**Cost 1 — indistinguishability (accepted for now).** Alice's timeout leaf is a taproot
script-path spend: it reveals the internal key `K_b`, the CSV+CHECKSIG leaf, and the merkle
path. So the *Alice-wins-unilaterally* branch is **not** payment-shaped. Everything else stays
keypath: funding (co-spend — shows *a* join happened, poisons clustering), `ChallengeTx`,
`RefundTx`, and **Bob's win**. So the leak is confined to Alice's unilateral timeout (~half of
outcomes, and only when not closed cooperatively).

**Cost 2 — liveness, not fairness (still open).** The refund fallback makes withholding
*costless* to Alice as well as profitless — she can abort a game she'd have to reveal into,
at no penalty. That is a **liveness** gap (griefing-as-denial), distinct from the fairness
gap now closed. Penalizing abort needs a griefing bond / forcing deposit (DESIGN §5) — out of
scope here.

**Deferred finesses toward full indistinguishability (§11):**
- *Cooperative Alice-win.* Even when Alice wins, if Bob cooperates at close she can take `Q'`
  via a fresh MuSig2 **keypath** spend (Bob co-signs) — payment-shaped. The CSV leaf is then
  only the *enforcement backstop* for an uncooperative Bob. Ties into the δ-dial (DESIGN §7):
  small `δ` leaves the loser wanting the cheap cooperative close.
- *Back-solve reveal* (DESIGN §5 optimization): fold `ChallengeTx` into an ordinary Alice
  spend to drop the extra-tx footprint. Hard: anti-equivocation must pin one outpoint, and
  Bob becomes quietly involved in Alice's "ordinary" payment.
- *Keypath relative-timeout:* a pre-signed `nSequence` keypath spend of `Q'` to Alice would be
  private too — but the keypath here is `K_b` (Bob's), so Alice's path is forced onto a leaf.
  Recovering a keypath Alice-branch means a different key assignment (e.g. cooperative-MuSig
  keypath, both wins as leaves) — a strictly different privacy/footprint tradeoff to weigh.

---

## 9. Proof system / tooling (unchanged)

- The only non-Schnorr part is the **two `hash_p` evaluations** in `π_a` (the point→scalar
  bridge; DESIGN §4). `π_r` is hash-free.
- **For now:** prove the two evaluations with off-the-shelf tooling (Bulletproofs or other),
  gluing the DLEQ-OR + DL parts as standalone generalized-Schnorr proofs sharing a Pedersen
  commitment to `A_k` (keeps the circuit to ~2 hash invocations).
- **Later:** the lump likely shrinks with a cleverer hash choice. Open optimization.

---

## 10. Open items

1. **Liveness / forcing** — refund fallback fixes fairness but leaves costless abort; needs a
   griefing bond (DESIGN §5). *(Fairness/grief itself is now resolved, §7–§8.)*
2. Written reduction that auxiliary `X` leaks nothing beyond DDH (§7 residual).
3. BIP340 parity handling in the `t` extraction (§4 wrinkle).
4. Choose `N` (Bob's window) and `T2` (abort deadline); confirm `N`-past-`T2` safety (§6).
5. MuSig2 nonce hygiene across `RefundTx`/`ChallengeTx`/settlement (DESIGN open #2).
6. Carry MuSig aggregation coefficients through all the algebra explicitly.
7. Hash-function choice / circuit-shrink (§9).

---

## 11. Roadmap back toward full indistinguishability

The script-leaf timeout is a deliberate *first working form*, not the endpoint. Order of
attack: (a) cooperative keypath Alice-win as the common case (δ-dial incentive) so the leaf
fires rarely; (b) re-examine key assignment on `Q'` to see whether both wins can be keypath;
(c) back-solve the reveal to erase the extra-tx footprint. Each is a privacy gain over this
baseline without disturbing the §7 game theory, which is the invariant to preserve.
