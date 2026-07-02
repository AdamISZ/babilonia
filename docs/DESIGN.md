# Babilonia — Design Skeleton

> Status: early architecture. This is a living spine to mark up, not a spec.
> Tags used below: **[DECIDED]** settled direction · **[FOCUS]** current build target ·
> **[OPEN]** unresolved · **[OUT]** explicitly out of scope.

---

## 0. Thesis

Co-design the **network layer** and the **chain layer** so that neither leaks, by
fusing three existing pieces:

1. **BIP324 subliminal channel** — the v2 transport's `garbage` (and, more usefully,
   `decoy` packets) carry arbitrary bytes that are *designed* to look like random
   padding. A covert, authenticated, point-to-point pipe between two Bitcoin nodes.
2. **OP_RAND emulation** (Kurbatov / Rarimo, arXiv:2501.16451) — a trustless 2-party
   interactive fair coin settled on Bitcoin with no special script and no consensus
   change.
3. **Steganographic mixing** — because the lottery is a *real* economic event whose
   transactions are ordinary taproot payments, running it breaks coin-history linkage
   while remaining indistinguishable from normal payment traffic.

**The novelty is the synthesis.** The same transaction is simultaneously a fair bet,
a payment, and a mix — so *intent is unprovable*. Existing tools fail at exactly this:
CoinJoin is chain-detectable and naked at the network layer; Tor+payments hides the
network but chain analysis still walks the graph. Babilonia's value is defeating the
**global passive adversary** that correlates *both* layers.

---

## 1. Threat model

| Adversary | Defeated by | Residual risk |
|---|---|---|
| Passive ISP / DPI | BIP324 stego (garbage/decoy ≈ padding) | garbage/decoy length distribution mismatch |
| Chain-analysis firm | payment-shaped taproot keypath txs | amount fingerprints, address reuse, tx-sequence motif |
| Counterparty | — (they know they're playing) | malicious abort / griefing |
| Active network prober | probe-resistant rendezvous | weak membership auth |
| **Global passive (network + chain)** | decoupling comms path from coin path | timing correlation, direct-connection tell |

The bottom row is the one nothing on the market handles, and it is the benchmark.

---

## 2. Scope

- **[DECIDED]** On-chain only. No Lightning, no channels, no off-chain protocol.
- **[DECIDED]** Two settlement geometries in scope: **join** (single tx) and **swap**
  (two unlinked txs).
- **[FOCUS]** Build and prove the **join** geometry first; it is strictly easier
  (see §5).
- **[OUT]** Probabilistic HTLCs / PTLCs-in-channels, force-close semantics,
  LN-penalty compatibility, large-`n` fine-grained odds (we use `n=2`).
- **[OUT, noted as v2 ambition]** A covert *overlay* that relays over the P2P graph
  (onion-over-BIP324). v1 is a direct two-party connection.

Dropping LN removes the two hardest objections raised in the Delving thread
(challenger/acceptor force-close role asymmetry; the "1000 commitments + ZKP per
channel update" bandwidth blowup). Neither applies to on-chain, small-`n`, one-shot.

---

## 3. Layer stack

- **L0 — Cover substrate.** Real BIP324 (v2) connections + real taproot keypath
  payments. Design rule for everything above: *reduce to indistinguishable-from-this.*
- **L1 — Covert transport.** Subliminal channel over BIP324 (§9).
- **L2 — OP_RAND core.** The fair-coin + adaptor machinery (§4). Geometry-independent.
- **L3 — Mixing orchestration.** Matchmaking, stake compatibility, anonymity-set
  management, timing/coin-lineage decorrelation, post-mix wallet hygiene. **[OPEN]**

---

## 4. L2 — OP_RAND core

**[DECIDED] Port Kurbatov's `hash160` construction to taproot + adaptor signatures
("Option B").** Two wins from one change, pulling both layers the same direction:

- **Chain cover:** funding and settlement become bare MuSig2 keypath spends — the most
  common, least distinguishable spend type. No revealed pubkey preimage, no script.
- **Network cover / bandwidth:** the relations collapse to **pure discrete-log sigma
  protocols**. The **[2026-07-02 hash-free redesign]** goes further than "no `hash160`
  in-circuit": there is now **no hash in any circuit at all** — Kurbatov's `hash_p` bridge is
  gone (see below), so the only proof is `π_r`, a CDS 1-of-2 OR of Schnorr dlog clauses, plus
  two Schnorr PoKs on the thimbles. `π_a` degenerates to a plain adaptor check (no OR). Sub-KB,
  sub-ms, no trusted setup. This *dissolves* the covert-channel byte-budget problem that first
  looked like the binding constraint. (`JOIN-CONSTRUCTION.md`, `adaptor_construction_spec (1).tex`.)

**[DECIDED] Fairness is geometry-independent.** The commit-blind-reveal ordering lives
entirely off-chain over L1. Whether we settle as one joined tx or two unlinked txs
changes nothing about whether the coin is fair — it only changes settlement/atomicity.
This is the seam: **core ⟂ geometry.**

### Notation  **[2026-07-02: hash-free, one thimble rank]**

- Roles: **Alice = Challenger/chooser**, **Bob = Accepter/guesser**.
- Funding keys `P_A = x_a·G`, `P_B = x_b·G` (both **public** — they form `Q`). Bob also has a
  **hidden claim key** `W_b = w_b·G` used only in `K = W_b + H_y`; it must differ from `P_B`, or
  Alice would recover it from `Q` and learn `y`.
- **Thimbles:** `h_1, h_2 ← F_p`; `H_i = h_i·G` (published with a Schnorr PoK of each `dlog`).
  No `A_i` rank, no `hash_p` — `H_i` is a plain random point.
- Alice's secret choice `c ∈ {1,2}`; Bob's secret guess `y ∈ {1,2}`. **Win:** Bob wins iff `y = c`.
- **Reveal:** adaptor point `H_c`, adaptor secret `h_c` (surfaces on settlement).
- Bob's pot-claim key `K = W_b + H_y`, secret `w_b + h_y`. He can compute it **iff** `h_c` is
  revealed and `y = c`. The inequality case needs *no* on-chain enforcement: a losing Bob simply
  cannot sign.

### Proof obligations (pure-DL sigma protocols — only one is an OR)

- **`H_i` well-formedness** (Alice): two Schnorr PoKs of `dlog(H_1), dlog(H_2)`; Bob checks
  `H_1 ≠ H_2`.
- **`π_r` (Bob):** `R_r = { (w_b, y) : ⋁_y (K − H_y = w_b·G) }` — a CDS 1-of-2 OR of Schnorr
  dlog-knowledge. Hides `y` and `w_b`, binds `K` to one thimble (and proves `W_b = w_b·G`
  implicitly, no duplicated clause).
- **`π_a` (Alice):** **no OR** — because Bob commits first (below), `c` needn't be hidden. Alice
  names `c`; Bob does a plain adaptor-signature check `R̄ + e·Q − ŝ·G ?= H_c`.

### Anti-equivocation / choice-hiding **[RESOLVED — via ordering]**

An adaptor point is **public** (`H_c = R̄ + e·Q − ŝ·G`), so it cannot be hidden by any ZK OR.
Choice-hiding is therefore **temporal, not cryptographic**: **Bob commits his pick (`K`, `π_r`)
before Alice's adaptor pre-signature `ŝ` exists.** Then Bob learning `H_c` is inert (he is locked
to `y`), and Alice commits `c` blind to `y` (hidden `P_B` masks `K`). This replaces the old
`t`-blinding and the "bind the reveal to one committed point" concern — Alice is bound to one
`H_c` by adaptor soundness, and cannot equivocate because she settles blind to the outcome.
(`JOIN-CONSTRUCTION.md` §3, §7.)

---

## 5. Settlement geometry: JOIN  **[FOCUS]**

> Worked cryptographic core (decoupled adaptor reveal, `π_a`/`π_r`, settlement) is specified
> in **`JOIN-CONSTRUCTION.md`**. The skeleton below is the tx/timelock framing it plugs into.

Single funding tx; the shared pot output is the anchor that the swap lacks, so the
forced reveal is clean. Everything below is pre-arranged at setup over L1 while both
parties are cooperative.

```
Funding TX1:  [Alice v_A, Bob v_B]  ->  Q_fund = MuSig2(P_A, P_B)   (+ change)

Q_fund spends (all pre-arranged at setup):
  (a) RefundTx     : Q_fund -> {v_A->Alice, v_B->Bob}, nLockTime T2, keypath
                     (both pre-sign; the NO-REVEAL fallback -- NOT "Alice wins")
  (b) ChallengeTx  : Q_fund -> Q' ; Bob pre-signs his plain half, Alice completes with an
                     adaptor on H_c that LEAKS h_c on broadcast   <-- THE REVEAL

  The pot Q' (created only by ChallengeTx) is ONE taproot UTXO with both payouts:
    keypath : K = W_b + H_y                         [Bob wins  -- immediate, keypath, private]
    leaf    : <N> OP_CSV OP_DROP <P_A'> OP_CHECKSIG [Alice wins -- N blocks RELATIVE to Q']
```

**Timeline once live.** Alice broadcasts **ChallengeTx** (publishes `h_c`, creates `Q'`) →
Bob's window is `N` blocks **relative to `Q'`**: if `y = c` then `h_c = h_y` and Bob takes
`Q'` (via `K = W_b + H_y`, secret `x_b+h_y`) → else Alice takes `Q'` by the CSV leaf after `N`
→ else (no reveal) RefundTx at `T2`.

> **[DECIDED 2026-07-02, refined]** The invariant: both payouts descend from the single
> reveal-child UTXO `Q'` (never two sibling outputs), and Alice's timeout is **relative to the
> reveal** — an *absolute* `nLockTime T1` is unsafe (Alice compresses Bob's window by revealing
> late). The diagram above is the **all-or-nothing reduction** (keypath = `K`, Alice on a CSV
> leaf — the lone script-path spend). **BUILD TARGET = the δ-split (§7), which is FULLY
> KEYPATH:** with a split the winner owes the loser `d−δ`, so a free keypath sweep can't settle
> → settlement becomes two fixed-output *pre-signed* keypath txs (the §8.2 model). Then `Q'`
> keypath = `MuSig2(P_a,P_b)`, `K` demotes to the *gating adaptor point* on Bob's fallback,
> and the **CSV leaf is eliminated**. So δ-splits *recover* full payment-indistinguishability
> rather than cost it; residual = only the §8 fee tell on the unilateral fallbacks. Full spec +
> game theory + indistinguishability accounting: `JOIN-CONSTRUCTION.md` §5a.

### The one move that makes it correct

ajtowns' grief (Delving thread): Alice sits on the reveal and takes the pot via her
own timelock fallback even when Bob won. Fix:

> **The no-reveal fallback is RefundTx (stakes back), not "Alice wins."**

Alice's *only* path to Bob's stake is `broadcast ChallengeTx → win`. Withholding
returns her own stake and nothing more → it is a pure **blind abort**, not a grief.
She must decide to reveal **before** she learns `y` (Bob's guess stays hidden behind
`π_r`/hidden `P_B` until the reveal resolves it), so the reveal is **outcome-blind** → fairness
holds. Kurbatov's match-gating is intact underneath (losing Bob can't sign).

- **Bob-negligence** (won but doesn't claim in his `N`-block window): pot goes to Alice's
  timeout branch — his own liveness fault, not a lever over Alice; and because `N` is fixed by
  the protocol (relative to `Q'`), not chosen by Alice, it is genuinely his fault and not an
  engineered squeeze. Alice can't exploit it either — she can't distinguish negligence from
  a loss (both look like "Bob didn't spend").
- **Cover:** with the δ-split build target *every* spend is keypath — funding, ChallengeTx,
  RefundTx, the cooperative close, and both unilateral fallbacks (`SettleBobWins`/
  `SettleAliceWins`). Only residual is the §8 fee-rigidity tell on the *unilateral* fallbacks;
  the cooperative close is fully clean. (In the all-or-nothing reduction, Alice's CSV leaf is
  the lone script-path spend.) The join's structural cover cost vs. the swap is that funding
  visibly co-spends two owners' inputs (poisons clustering, but shows *a* join happened).

### Optimization **[OPEN]**: eliminate ChallengeTx via back-solve

ChallengeTx is the extra-tx footprint cost. Fold the reveal (Alice's adaptor on `H_c`) into an
ordinary Alice spend she'd make anyway (carrier = a specific pre-committed
outpoint). Tricky points: the commit-now / reveal-later temporal split widens the
abort window; the carrier must be pinned (and stay compatible with the §4 Bob-commits-first
ordering); reconciling "reveal-on-spend" with taproot means the carrier payment's *signature* is
the adaptor,
so Bob is quietly involved in constructing Alice's "ordinary" payment.

---

## 6. Settlement geometry: SWAP  **[IN SCOPE, LATER]**

Two unlinked txs, no shared UTXO → **no on-chain join signal at all** (CoinSwap-grade),
and *unequal* amounts make the two legs read as independent payments. Strictly stronger
privacy than the join; strictly harder to build.

- Structurally a **PTLC / adaptor-CoinSwap whose payment point is the OP_RAND outcome
  key.** Spending logic needs no inequality gadget: make Bob the active claimant on
  both legs, Alice the timelock fallback on both; outcome routes both coins to one party.
- **Hard nut [OPEN]:** forcing the reveal with **no shared anchor**. The default
  winner's timelock path needs no reveal, so the armed state must be engineered so that
  *nothing* is spendable by anyone without `h_c` public. Inherits CoinSwap timelock
  asymmetry (winner's claim window before the abort `nLockTime`).
- **[DECIDED] Splits reduce to this:** a determined split `x:y` = a deterministic swap
  (pure CoinSwap, no randomness) + a small all-or-nothing bet on the residual. So
  feasibility of splits reduces to feasibility of the all-or-nothing swap.

---

## 7. The δ dial  **[DECIDED — conceptual]**

A determined split is `deterministic_share ± δ`, the coin choosing the sign. One knob
`δ` controls, monotonically and simultaneously:

- **variance** (how much is gambled),
- **bet ↔ mix** (`δ→0` is pure CoinSwap / pure mixer; large `δ` is a real wager),
- **cooperation incentive** (small `δ` leaves the loser most of their money, so they
  still *want* the cheap cooperative close),
- **privacy robustness** (cooperative close is the cleanest; see §8).

All four move together. The all-or-nothing extreme is worst on every axis; the
low-variance split is best on every axis. **Center the design on small-`δ` splits.**
This is the concrete form of "deliberately both a mixer and a bet."

---

## 8. Timelocks & privacy  **[DECIDED — approach]**

Problem: in-script `OP_CLTV` / `OP_CSV` reveal a non-normal (script-path) spend; in
private CoinSwap that's avoided only by *cooperation*, but in a lottery the **loser has
no incentive to cooperate at close.**

Resolution:

1. **Minimize in-script timelocks.** Prefer **pre-signed keypath (MuSig2) spends with a
   tx-field timelock** — `nLockTime` (absolute) or `nSequence`/BIP68 (relative), both
   consensus-enforced on a *keypath* spend without any opcode. Broadcast after its lock, it's
   just a keypath spend with a recent-past lock (which Core stamps on ~every tx).
   > **[DECIDED 2026-07-02, refined] The join is fully keypath.** For the δ-split build target
   > there is **no script leaf**: because the winner owes the loser `d−δ`, settlement is two
   > fixed-output *pre-signed* keypath txs (the §8.2 model just below) — `Q'` keypath =
   > `MuSig2(P_a,P_b)`, Bob's win gated by an adaptor on `K = W_b + H_y`, Alice's timeout a
   > pre-signed `nSequence`-relative keypath spend. A script-path CSV leaf appears *only* in the
   > all-or-nothing reduction (where `Q'` keypath = `K` forces Alice onto a leaf). §5,
   > `JOIN-CONSTRUCTION.md` §5a.
2. **Front-load cooperation to setup.** Exchange the adaptor sigs for *both* outcomes
   at setup (both parties cooperative by construction). The winner then completes the
   loser's setup-time adaptor into a full MuSig2 keypath signature and closes
   **unilaterally** — the loser's close-time cooperation is never required.
3. **Consequence:** the **loser cannot force a script reveal.** Privacy degrades only
   via *winner negligence* (sleeps past timeout → bet voids to refund — winner's fault)
   or via the fee tell below.

**Residual tell [OPEN]:** an adaptor sig commits to a *specific* tx, so its fee is fixed
at setup; bumping needs an anchor output + CPFP (non-default sighash is itself a tell).
So the **unilateral** close carries a modest anchor/fee fingerprint; the **cooperative**
close (fresh sig, current fee, `SIGHASH_DEFAULT`, no anchor) is the genuinely
indistinguishable one. Hence §7: keep the loser wanting to cooperate.

---

## 9. L1 — covert transport  **[grounded in Core source — see `BIP324-PATCH-NOTES.md`]**

Verified against Bitcoin Core HEAD; line-level detail and exact patch sites live in
`BIP324-PATCH-NOTES.md`. Summary + design consequences:

**Two surfaces, opposite visibility:**

- **Garbage** — cleartext on the wire, so content *and* length are observable. Native
  length is **uniform[0,4095]** (`GenerateRandomGarbage`), which is *friendly*: pad our
  payload to a uniform-random total length → no length tell, and a PRF authenticator is
  uniform-random → indistinguishable from native garbage. One-shot and *independent* each
  way (cannot carry a dependent round-trip). **Role: membership signaling / bootstrap.**
- **Decoy packets** — AEAD-encrypted, so a passive observer **cannot** distinguish a decoy
  from a real message; only packet size/count/timing are observable. Core never emits them
  and silently drops received ones, but that's a traffic-*shape* concern, not content
  detection, and OP_RAND payloads hide easily in the normal envelope. **Role: the sustained
  interactive channel** carrying the OP_RAND round-trips.

  > Correction vs. earlier drafts: the visible-on-wire surface is the **garbage**, *not* the
  > decoys. Decoys are the safe channel; garbage is the one with a (mild) distribution
  > constraint.

**Patch surface** — entirely in `net.{h,cpp}` + a small local IPC/RPC module; nothing in
consensus/validation/wallet. Garbage inject (send) / detect (recv); decoy emit (send) /
route (recv); plus a local control API. Patch-notes §6.

**Control interface [DECIDED: RPC is fine].** The orchestrator↔Core control plane is local
and never touches the wire, so it has **zero** bearing on detectability. Use RPC for v1
(reuses Core's auth/tooling); pair it with an async inbound path (ZMQ-style notification or
long-poll) since OP_RAND is interactive. A bespoke socket is a later ergonomic refinement,
not a security need.

**v1 scoping.** For direct two-party, garbage membership-auth is *optional*: Alice
`addnode`s Bob (optionally over Tor), peer identity is implicit, and the covert-frame key
derives from the **BIP324 session id ⊕ a pre-shared pairwise secret**. So the v1 patch
reduces to **decoy send/recv + control API**; rendezvous-in-garbage is a v2/overlay concern.

**Probe-resistant rendezvous [OPEN, v2].** No static marker — a PRF-keyed authenticator over
the ephemeral keys + a shared club secret; respond covertly only after the peer proves
membership (obfs4 / PAKE shape).

**Tor / topology.** Run the covert connection over Tor (Core carries v2-over-Tor unchanged)
to break the IP-level A–B link and look like any Tor node — directly attacking the
global-passive row. Decouple the comms node from the coin/wallet node. Capacity is *not* the
binding constraint (L2 proofs are sub-KB, §4).

---

## 10. Open problems register

1. **[L2] Anti-equivocation / choice-hiding** — **RESOLVED** by the hash-free redesign's
   **Bob-commits-first ordering**: adaptor points are public and can't be hidden by a proof, so
   the hiding is temporal, not cryptographic (`JOIN-CONSTRUCTION.md` §3). No more `X`/`T` binding
   or back-solve concern.
2. **[L2] MuSig2 nonce hygiene** across RefundTx / ChallengeTx / settlement spends —
   disjoint nonces or we leak keys. §5.
3. **[L2] Proofs / adaptor wiring** — **RESOLVED**: hash-free → pure sigma protocols (only `π_r`
   an OR; `π_a` a plain adaptor check; two thimble PoKs). No `hash_p`, no `t`/`X`, no SNARK.
   Formal security proofs being worked independently. `JOIN-CONSTRUCTION.md` §9,
   `adaptor_construction_spec (1).tex`.
3b. **[L2] ChallengeTx adaptor form** — must be the **s-value** adaptor (challenge over the
   un-adapted nonce) so Bob's partial doesn't reference `H_c`; needed for the ordering, and a
   code-integration point vs the `musig2` crate's nonce-adaptor default. §4, PROTOCOL §6.
4. **[geometry] Swap forced-reveal without a shared anchor** + timelock-asymmetry tree.
   §6.
5. **[privacy] Tx-sequence motif** — does a recurring funding→challenge→settle pattern
   become a fingerprint even when each tx is payment-shaped? §1, §5.
6. **[privacy] Unilateral-close fee tell** (anchors/CPFP). §8.
7. **[L1] Probe-resistant rendezvous** and **distribution matching**. §9.
8. **[L3] Mixing orchestration** — matchmaking, anonymity-set growth, post-mix hygiene.
9. **[L3] Variance vs. anonymity set** — gambling risk shrinks the participant pool;
   per-round set is 2, and real unlinkability needs many rounds × many counterparties.

---

## 11. Non-goals / explicit limitations

- Per-round anonymity set is only 2; the privacy is *steganographic* (anonymity set ≈
  all payment traffic), not combinatorial, and is only realized over many rounds with
  good wallet hygiene.
- "Properly private" relies on the cooperative close in the common case; the unilateral
  fallback is keypath but mildly marked.
- It is not a pure mixer: using it entails real gambling variance (tunable down via §7,
  never to exactly zero unless `δ=0`, which is just CoinSwap).

---

## References

- Kurbatov, *Emulating OP_RAND in Bitcoin* (Rarimo), arXiv:2501.16451v1. (in repo)
- Delving Bitcoin thread: <https://delvingbitcoin.org/t/emulating-op-rand/1409>
- Poelstra, *Scriptless Scripts* (adaptor signatures).
- Kurbatov et al., *Multichain Taprootized Atomic Swaps*, arXiv:2402.16735.
- BIP324 (v2 transport): garbage, garbage terminator, decoy packets.
