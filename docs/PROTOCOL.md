# Babilonia Wire Protocol

> **⚠ SUPERSEDED BY v5 (2026-07-04).** The handshake and single s-value adaptor described below are
> **pre-v5**. The real protocol (`adaptor_construction_spec_v5.tex`) is a 6-step flow P1–P6 over
> **one** output: settlement = MuSig2 adaptor on `D = d·G`; encrypted outcome `ctxt = a_c + H(d)`
> (thimbles `A_i = a_i·G`); `π_a` = Σ-part + hash circuit. The **crypto and tx layers are built to
> v5** (`src/txgraph.rs`, `src/reveal.rs`, `src/sigma.rs`), but the **message flow in this doc and
> in `src/messages.rs`/`src/setup.rs` is not yet reworked** — the next step, after which the flight
> details below get rewritten to v5's P1–P6.


> Status: **hash-free / reordered redesign** (2026-07-02). Setup is a **3-flight fused** exchange
> (Alice → Bob → Alice); the proofs are secp256k1 **sigma protocols** (only `π_r` is an OR). The
> code (`src/messages.rs`, `src/setup.rs`, `src/reveal.rs`, `src/txgraph.rs`) still reflects the
> older hashed design and needs a follow-up pass to match this.
>
> Layer: L1 interactive setup (DESIGN §9), carried as discrete **frames** over a
> `transport::Transport` (medium — BIP324 covert channel, TCP, in-memory — is pluggable, out of
> scope here). Cryptographic meaning of each field: `JOIN-CONSTRUCTION.md` §1–§5. Formal note:
> `adaptor_construction_spec_v5.tex`.

---

## 1. Conventions

- **Frames.** The transport delivers whole messages; no stream framing in this layer. A decoder
  consumes the whole frame and rejects trailing bytes.
- **Tag.** Every message starts with a 1-byte type tag; a decoder for type _X_ rejects other tags.
- **Points.** secp256k1 group elements are **33-byte compressed SEC1**; decoding rejects
  non-canonical/invalid points.
- **Integers.** Fixed-width **little-endian** unsigned (`u16`/`u32`/`u64`).
- **Variable bytes (`lp`).** `u32` LE length prefix, then that many bytes (proofs, scripts, tx data).
- **Only public data on the wire.** Group points, proofs, nonces, partial signatures, funding
  inputs — never secret scalars (`h_i`, `x_a`, `x_b`), and never `P_b` (kept hidden until claim).

Notation (`JOIN-CONSTRUCTION.md` §1): `P_a`, `P_b` = Alice's / Bob's **public funding keys** (they
form `Q`); `W_b` = Bob's **hidden claim key**; thimbles `H_i = h_i·G`; choice `c`, guess `y`; pot
key `Q = MuSig2(P_a,P_b)`; adaptor point `H_c`, secret `h_c`; Bob's claim key `K = W_b + H_y`,
secret `w_b + h_y` (`W_b` distinct from `P_b`, else Alice recovers it from `Q` and learns `y`).
**No `A_i`, no `hash_p`, no `t`/`X`/`t_b`.**

---

## 2. The three flights (commit-blind, Bob commits first)

```
1. Alice ─Open──►  Bob    thimbles H_1,H_2 (+PoKs), params, Alice inputs+scripts, Alice nonces
2. Bob   ─Accept─► Alice  K + π_r  (Bob's committed pick), Bob stake, Bob inputs+scripts,
                          Bob nonces, Bob partials (Refund, Challenge[plain], SettleBob, SettleAlice)
3. Alice ─Arm───► Bob     Alice partials (incl. Challenge adaptor on H_c, SettleBob adaptor on K),
                          π_a, Alice's TX1 input signatures
   → Bob assembles + broadcasts TX1.
```

**Ordering is security-critical** (JOIN-CONSTRUCTION §3): an adaptor point is public
(`H_c = R̄ + e·Q − ŝ·G`), so it cannot be hidden by a proof. Bob must commit `y` (flight 2)
*before* Alice's adaptor pre-signature exists (flight 3); then his learning `H_c` is inert.
Alice commits `c` in flight 3 blind to `y` (hidden `W_b` masks `K`). This replaces the old
`t`-blinding — the hiding is temporal.

The commit **is** the pre-signing: flights 1–3 also carry the funding template, both MuSig2
sessions (refund, settlement), and Alice's funding signature. Three flights is the floor
(JOIN-CONSTRUCTION §10). Everything settles on-chain afterward (§7 Phase Play).

---

## 3. Messages

Stable/simple fields are byte-specified; the MuSig2 nonce/partial and funding-input encodings
are **[TBD]** (they depend on the `musig2` serialization and the PSBT-ish funding format) and are
given by content, not offset.

### 3.1 `Open` — tag `0x01` — Alice → Bob (flight 1)
- **Params:** `alice_stake` u64le, `delta` u64le, `reveal_window` `N` u16le, `refund_locktime`
  `t_r` u32le. *(Per-party stakes: Bob's stake is in `Accept`.)*
- **`P_a`** point (Alice's public identity key).
- **`H_1`, `H_2`** points + a Schnorr **PoK of each `dlog`** (fixed-size sigma proofs). Bob MUST
  check `H_1 ≠ H_2`.
- **Alice funding template [TBD]:** her segwit inputs `[(outpoint, amount, spk)]`, and her
  destination scripts (TX1 change, refund payout, settlement payout).
- **Alice nonces [TBD]:** MuSig2 public nonces for the refund and settlement sessions.

### 3.2 `Accept` — tag `0x02` — Bob → Alice (flight 2)
- **`bob_stake`** u64le. (Must satisfy `δ ≤ min(alice_stake, bob_stake)`.)
- **`K`** point (`= W_b + H_y`) + **`π_r`** (§4). Hides `y` and `W_b`. This is Bob's commitment.
- **Bob funding template [TBD]:** his segwit inputs + destination scripts.
- **Bob nonces [TBD]** and **Bob partials [TBD]** for all four pre-signed txs:
  RefundTx *plain*; **ChallengeTx *plain*** (s-value adaptor — Bob's partial does **not** involve
  `H_c`, see §6); SettleBobWins adaptor on `K` (Bob knows `K`); SettleAliceWins *plain*.

### 3.3 `Arm` — tag `0x03` — Alice → Bob (flight 3)
- **Alice partials [TBD]** for all four: RefundTx *plain*; **ChallengeTx adaptor** (her partial
  offset by `−H_c`); SettleBobWins adaptor on `K`; SettleAliceWins *plain*.
- **`π_a`** (§4): names `c` and lets Bob check the adaptor point — essentially free.
- **Alice's TX1 input signatures [TBD]** (safe now: RefundTx is complete once this flight lands).

After `Arm`, Bob has a complete RefundTx, the settlement pre-signatures, and Alice's input sigs;
he signs his own inputs and **broadcasts TX1**. (A 4th flight instead, with Bob's input sigs to
Alice, if you want *Alice* to broadcast.)

---

## 4. The proofs — sigma protocols (no SNARK, no hash circuit)

Fiat–Shamir transcript hash is any standard hash (transcript-only, never in a circuit). Nonces
must be fresh and independent of the MuSig2 signing nonces.

- **`H_i` well-formedness** (in `Open`): two Schnorr PoKs of `dlog(H_1), dlog(H_2)`.
- **`π_r` (Bob → Alice)** — 1-of-2 **CDS-OR** of Schnorr dlog-knowledge:
  ```
  R_r = { (w_b, y) :  ⋁_{y∈{1,2}} ( K − H_y = w_b·G ) }
  ```
  Knowledge of `w_b = dlog(K − H_y)` for one `y`. Since `W_b = K − H_y`, this already proves
  `W_b = w_b·G` — **no duplicated PoK clause**. Hides `w_b` and `y`; binds `K` to one thimble.
- **`π_a` (Alice → Bob)** — **no OR** (Bob already committed, so `c` needn't be hidden): Alice
  names `c`, and Bob checks the exposed adaptor point directly,
  `R̄ + e·Q − ŝ·G ?= H_c`, against the `H_c` already proven well-formed in `Open`. A plain
  adaptor-signature verification.

---

## 5. Funding transaction — input & amount rules

`TX1` co-spends both parties' inputs into the pot and anchors the whole pre-signed graph. Message
construction is folded into flights 1–2 (§3); these rules **must** hold regardless.

```
TX1
  inputs : Alice's UTXO(s)   +   Bob's UTXO(s)
  outputs: Q_fund = S_a + S_b        — P2TR, keypath = Q = MuSig2(P_a, P_b)
           [Alice change]            — optional, Alice-controlled
           [Bob change]              — optional, Bob-controlled
```

1. **Sole control per input.** Every input is spendable by exactly one party, who signs it.
2. **Segwit inputs only — non-malleability (critical).** All funding inputs MUST be segwit
   (P2WPKH/P2WSH/P2TR). The pre-signed children reference `Q_fund` by `txid:vout`; a legacy input
   carries sigs in its `scriptSig`, letting a party malleate `TX1`'s txid *after* signing and
   orphan the chain. Segwit fixes the txid once inputs+outputs are chosen.
3. **Sufficient value.** Party *i*'s inputs sum to ≥ `S_i + fee_i` (+ change). Overshoot returns
   as that party's own change — no separate deposit; each spends existing UTXOs straight in.
4. **Pot is exactly the two stakes.** `Q_fund = S_a + S_b`. TX1's own fee comes from the inputs
   (reduced change), not the pot. Downstream chain fees (ChallengeTx, settlements) come from the
   pot and reduce payouts; apportionment across the two settlement outputs is a policy detail (TBD).
5. **Change is self-paid.** Each change output pays only its contributor; never a transfer to the
   other party. (Change minimization / payment-shaping for privacy is L3, out of scope.)
6. **Stakes may be unequal; the wager is shared and bounded.** `S_a, S_b` per-party, need not
   match — each side a self-mix of any size, fair because EV = own stake, independent of the
   other's. The wager `δ` is a single shared value with `0 ≤ δ ≤ min(S_a, S_b)` (loser output
   `S_i − δ ≥ 0`). Settlement pays winner `S_i + δ`, loser `S_i − δ`. Keep `δ` well below both
   stakes for low variance and cooperative-close incentive (DESIGN §7 δ-dial); Bob has latitude
   in `S_b` to satisfy the bound.
7. **Freeze before pre-sign; fund only after refund.** The full input set + all outputs (hence
   `Q_fund` outpoint) are fixed before any partial is signed, and `TX1` is not broadcast until
   RefundTx is fully pre-signed — a stalled setup is always recoverable, no funds committed
   without a recovery path.

---

## 6. Transaction structures

Deterministic given the params (§3.1), the funding templates (§3), and `Q = MuSig2(P_a,P_b)`. So
the txs never travel on the wire — only nonces and partials do — and both sides reconstruct
identical templates and sighashes.

| tx | spends | outputs | lock | key & signature |
|----|--------|---------|------|-----------------|
| **TX1** (funding) | Alice + Bob inputs | `Q_fund = S_a+S_b` @ P2TR(`Q`); changes | — | each party signs its **own** segwit inputs |
| **RefundTx** | `Q_fund` | `S_a`→Alice, `S_b`→Bob (−fee) | `nLockTime t_r`, input non-final | keypath `Q`, **plain** MuSig2 |
| **ChallengeTx** | `Q_fund` | `Q' = S_a+S_b−fee` @ P2TR(`Q`) | 0 | keypath `Q`, **adaptor on `H_c`** — Alice completes with `h_c` (the reveal) |
| **SettleBobWins** | `Q'` | `S_b+δ`→Bob, `S_a−δ`→Alice (−fee) | 0 | keypath `Q`, **adaptor on `K`** — Bob completes with `x_b+h_y` iff he won |
| **SettleAliceWins** | `Q'` | `S_a+δ`→Alice, `S_b−δ`→Bob (−fee) | `nSequence = N` (relative to `Q'`) | keypath `Q`, **plain** MuSig2 — Alice broadcasts after `N` |
| **CooperativeClose** | `Q'` | the outcome's split | 0 | keypath `Q`, **plain** MuSig2, signed **live** at settlement |

> **ChallengeTx adaptor convention (load-bearing).** The adaptor point `H_c` must stay hidden
> from Bob until he has committed (§2). So ChallengeTx uses the **s-value adaptor**: the challenge
> `e = H(R̄, Q, m)` is over the *un-adapted* nonce, and the pre-signature satisfies
> `ŝ·G + H_c = R̄ + e·Q` (Alice offsets her partial by `−H_c`). Then **Bob's partial is a plain
> MuSig2 partial that never references `H_c`**, so he can sign it in flight 2 before `c` is
> revealed — this is what makes the 3-flight ordering possible. SettleBobWins's adaptor point `K`
> is known to both parties, so it may use the ordinary nonce-adaptor. *(Code note: the `musig2`
> crate's adaptor is the nonce form; the s-value form is implemented on top of it as
> `musig::svalue_presig`/`svalue_reveal` and exercised in `tests/regtest_e2e.rs`.)*

- `Q_fund` and `Q'` share `Q` (differ only by outpoint).
- The three spends of `Q'` are mutually exclusive; the relative timelock on SettleAliceWins gives
  a winning Bob priority (JOIN-CONSTRUCTION §5a, §7).

---

## 7. Sequence & security ordering

Flights 1–3 (§2) arm everything; then TX1 is broadcast; then settlement is on-chain.

**Rules that must hold:**
1. **Bob commits before Alice's adaptor.** `K`/`π_r` (flight 2) precede `ŝ`/`π_a` (flight 3).
   This is the fairness-critical ordering (§2, JOIN-CONSTRUCTION §3).
2. **Recovery before funds.** No TX1 input signature is shared until RefundTx is complete +
   verified. All four pre-signed txs are complete by end of flight 3 (fully armed), so neither
   party gets a post-funding abort lever; RefundTx is the strict minimum.
3. **Fresh nonces per session.** The four MuSig2 sessions use independent nonces; reuse across
   sessions leaks the key. **No `H(R)` commitment round** is needed (MuSig2/BIP327).
4. **Adaptor points are the committed ones.** ChallengeTx adapts against `H_c` (from `π_a` /
   `Open`); SettleBobWins against `K` (from `π_r`).
5. **Templates frozen before signing.** Full outpoint chain + outputs fixed before any partial;
   segwit-only inputs keep txids stable (§5 rule 2).
6. **Reveal is Alice's, post-funding, outcome-blind.** Alice completes ChallengeTx only after TX1
   confirms, and before she can learn `y`.

**Phase Play (on-chain; primitives implemented/tested).**
1. Alice broadcasts **ChallengeTx** (completes with `h_c`) → reveal; `Q'` created.
2. Bob recovers `h_c = s − ŝ − s_b`; wins iff `H_c = H_y`.
3. **CooperativeClose** (both sign a fresh split live) — the clean path. Else the winner uses the
   pre-signed fallback: Bob's **SettleBobWins** within the `N`-block window, or Alice's
   **SettleAliceWins** after `N`.
4. No reveal ⇒ **RefundTx** at `t_r` returns both stakes (no grief; JOIN-CONSTRUCTION §7).

---

## 8. Versioning

No version byte yet (pre-1.0; message set will change as the ZKP/funding encodings finalize). A
protocol-version field belongs in `Open` before any external deployment.
