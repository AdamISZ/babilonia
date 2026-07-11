# Babilonia — wire messages & flows

This document specifies every message the two parties exchange over their [transport](../src/transport/mod.rs)
(a BIP324 covert decoy channel, or the in-memory channel used in tests), and the flows in which they
occur. It is the authoritative, unambiguous reference for the protocol's message layer.

## Roles

A bet has two parties. Their names are fixed by role, not by who dials whom:

| Party | Aliases | Does |
|-------|---------|------|
| **Dealer** | Alice, Proposer, "the parker" | picks the secret choice `c`; deals the encrypted outcome; funds the pot with a whole input and parks the surplus |
| **Player** | Bob, Accepter | picks the guess `y`; **wins iff `y = c`** |

The party who **proposes** a bet becomes the Dealer; the party who **accepts** becomes the Player.

## Transport & framing

The transport is an ordered, reliable, framed, authenticated, bidirectional byte channel. Each message
below is **one frame**. Every bet-protocol frame begins with a **1-byte tag** identifying the message
type, followed by its fields in the order listed. A bounds-checked reader rejects short or over-long
frames.

### Encoding primitives

| Type | Size | Encoding |
|------|------|----------|
| tag | 1 byte | message-type discriminant (first byte of every frame) |
| Point (group element / pubkey) | 33 bytes | SEC1 compressed |
| Scalar | 32 bytes | big-endian |
| PartialSignature | 32 bytes | MuSig2 partial |
| PubNonce | 66 bytes | MuSig2 public nonce (two points) |
| OutPoint | 36 bytes | 32-byte txid ‖ 4-byte vout (LE) |
| u64 | 8 bytes | little-endian |
| var-bytes | 4 + N bytes | `u32`-LE length prefix ‖ N payload bytes |
| String | var-bytes | UTF-8 (addresses, base64 PSBTs) |
| Transaction | var-bytes | Bitcoin consensus serialization |

---

## Phase 0 — Negotiation (control layer)

Small control frames exchanged by the peer-worker before it hands the transport to the bet protocol.
On backends with no peer discovery (e.g. the in-memory test transport) these are skipped and the two
sides start directly at Phase 1.

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 0 | `HELLO` | `0x00` | Dialer → Accepter | *(none)* | presence marker so the accepter can pick out our protocol among its v2 peers (sent once, by the dialer only) |
| 1 | `ProposeTerms` | `0x01` | Proposer → Accepter | `stake_sats: u64`, `fee_sats: u64`, `refund_locktime: u32`, `alice_timeout: u16`, `scheme: u8` | the offered bet terms; both sides derive the identical `GameParams` from it |
| 2 | `ACCEPT` | `0x02` | Accepter → Proposer | *(none)* | accept the terms → proposer becomes Dealer, accepter becomes Player |
| 3 | `REJECT` | `0x03` | Accepter → Proposer | *(none)* | decline; the session ends |

`scheme`: `0` = Squaring, `1` = Poseidon (the π_a construction; both parties must agree).

---

## Phase 1 — Joint funding

Builds the pot `U1` (a 2-of-2 MuSig2 key-path output) as a 2-in / 2-out payjoin. The **Player builds**
the funding transaction (its wallet's natural shape) and signs its own input; the **Dealer verifies and
co-signs**. The funding tx is *held, not broadcast*, until the refund is pre-signed in Phase 2.

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 4 | `FundOpen` | `0x05` | Dealer → Player | `p_a: Point`, `input: OutPoint`, `amount: u64` (= `F_A`), `alice_payout: String` | Alice's funding key, her **whole** input `F_A` (no funding change), and the address where her parked surplus `c_A` / refund return |
| 5 | `FundReply` | `0x06` | Player → Dealer | `p_b: Point`, `input: OutPoint`, `amount: u64` (= `F_B`), `change: String` (= `c_B` dest), `bob_payout: String`, `psbt: String` | Bob's funding key + input, his funding-change address, his refund payout address, and the **Player-built PSBT** with his own input signed |
| 6 | `FundFinal` | `0x07` | Dealer → Player | `psbt: String` | the same PSBT with Alice's input signature added, so the Player can combine + finalize `TX1` |

Amounts (Alice-pays fee): `U1 = F_A + b − fee`, `c_B = F_B − b`, parked `c_A = F_A − a − fee`
(`a`, `b` = the stakes; see `funding_amounts` / `check_park` in [`src/bet.rs`](../src/bet.rs)).

---

## Phase 2 — Setup (v5 driver, 4 flights)

The interactive protocol that pre-signs the transaction graph — the **refund** (2-of-2 key-path) and
the **settlement adaptor** locked to `D = d·G` — and commits the encrypted outcome `ctxt = a_c + H(d)`.
Two MuSig2 sessions (refund, settlement) run across these flights. This is where the zero-knowledge
proofs (thimble PoKs, `π_r`, `π_a`) are exchanged.

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 7 | `AliceOpen` | `0x01` | Alice → Bob | `p_a: Point`, `a1: Point`, `a2: Point`, `thimble_poks: var-bytes` | Alice's funding key and thimbles `A_1, A_2 = a_1·G, a_2·G` with proofs of knowledge |
| 8 | `BobCommit` | `0x02` | Bob → Alice | `p_b: Point`, `k: Point`, `pi_r: var-bytes`, `refund_nonce: PubNonce`, `settle_nonce: PubNonce` | Bob's funding key, his claim key `K = W_b + A_y` with proof `π_r`, and his nonces for both MuSig2 sessions |
| 9 | `AliceReveal` | `0x03` | Alice → Bob | `refund_nonce: PubNonce`, `settle_nonce: PubNonce`, `ctxt: Scalar`, `d_point: Point` (= `D`), `pi_a: var-bytes`, `refund_partial: PartialSignature`, `settle_partial: PartialSignature` | Alice's nonces, the encrypted outcome `ctxt`, the adaptor point `D`, proof `π_a`, and her partials for the refund and the `D`-locked settlement |
| 10 | `BobAuth` | `0x04` | Bob → Alice | `refund_partial: PartialSignature`, `settle_partial: PartialSignature` | Bob's partials, completing both MuSig2 sessions (authorises the settlement adaptor pre-signature) |

After Phase 2 both parties hold identical pre-signed refund and settlement-adaptor. The Dealer then
**broadcasts the funding tx** and waits for `U1` to confirm — an on-chain step, no message.

---

## Phase 3 — Resolution overlay (cooperative dealer-win)

Once `U1` is confirmed, the Dealer offers a cooperative close. She reveals the outcome off-chain; if
the **Player has lost**, he co-signs a single key-path `U1 → Alice` spend and the bet finishes
immediately — no settlement on-chain, no script, no timelock wait. Otherwise the protocol falls back to
the enforced on-chain path (see below). Implemented in [`src/bet.rs`](../src/bet.rs)
(`dealer_cooperative` / `player_cooperative`).

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 11 | `CoopReveal` | `0x08` | Alice → Bob | `settle_sig: var-bytes` (64-byte **completed** settlement signature), `coop_tx: Transaction` (unsigned `U1 → [S, c_A_out]`, both to Alice), `alice_nonce: PubNonce` | reveal `d` (Bob extracts it from `settle_sig` exactly as on-chain), offer the cooperative spend, and open a fresh MuSig2 session over `U1` |
| 12a | `CoopConcede` | `0x09` | Bob → Alice | `bob_nonce: PubNonce`, `bob_partial: PartialSignature` | Bob lost → his nonce + partial over `coop_tx`; its presence **is** the concession. Alice completes the signature and broadcasts |
| 12b | `CoopDecline` | `0x0A` | Bob → Alice | *(none)* | Bob won (or won't cooperate) → resolve on-chain via the enforced path |

MuSig2 note: `CoopReveal` carries Alice's **nonce** (not a partial — she can't sign until she has
Bob's nonce). Bob, already holding Alice's nonce, returns his nonce **and** partial together in
`CoopConcede`; Alice then produces her own partial, aggregates, and broadcasts. The coop session uses
**fresh** nonces, distinct from the Phase-2 refund/settlement nonces.

---

## Message-flow diagrams

Legend: `A` = Dealer/Alice, `B` = Player/Bob. Time flows downward. `[chain]` marks an on-chain action
(a broadcast/confirmation), **not** a message.

### Setup — the common prefix (identical for every outcome)

```
   A (Dealer)                                   B (Player)
      │                                              │
      │  ── HELLO (dialer only) ──────────────▶      │   Phase 0
      │  ── ProposeTerms ─────────────────────▶      │   (skipped on
      │      ◀───────────────────── ACCEPT ──        │    test transport)
      │                                              │
      │  ── FundOpen ─────────────────────────▶      │   Phase 1
      │      ◀──────────────────── FundReply ──      │   (joint funding)
      │  ── FundFinal ────────────────────────▶      │
      │                                              │
      │  ── AliceOpen ────────────────────────▶      │   Phase 2
      │      ◀──────────────────── BobCommit ──      │   (setup driver:
      │  ── AliceReveal ──────────────────────▶      │    refund + settlement
      │      ◀───────────────────── BobAuth ──       │    pre-signed)
      │                                              │
      │  [chain] broadcast funding TX1 → wait for U1 to confirm
      │                                              │
      ▼             (continues in one branch below)  ▼
```

### Branch 1 — Dealer wins, cooperatively (the fast path)

```
   A (Dealer)                                   B (Player)
      │  ── CoopReveal ───────────────────────▶      │   B extracts d,
      │                                              │   computes he LOST
      │      ◀────────────────── CoopConcede ──      │
      │                                              │
      │  [chain] broadcast coop_tx  (U1 → Alice, 1 tx)
      │                                              │
   DealerWins — no settlement, no d on-chain, no timeout. Done.
```

### Branch 2 — Player wins

```
   A (Dealer)                                   B (Player)
      │  ── CoopReveal ───────────────────────▶      │   B extracts d,
      │      ◀────────────────── CoopDecline ──      │   computes he WON
      │                                              │
      │  [chain] broadcast settlement (posts d) ─────▶  B observes it
      │                                              │
      │                          B [chain] claims O_K via key-path
      │  observes O_K spent                          │
      │                                              │
   PlayerWins. (2 on-chain txs: settlement + claim.)
```

### Branch 3 — Dealer wins, enforced (Player offline or uncooperative)

```
   A (Dealer)                                   B (Player)
      │  ── CoopReveal ───────────────────────▶      ✗   (no reply /
      │                                              │    B offline)
      │      … recv_deadline elapses (timeout) …     │
      │                                              │
      │  [chain] broadcast settlement (posts d)      │
      │  [chain] wait t_1 blocks, then reclaim O_K via the CSV leaf
      │                                              │
   DealerWins. (2 on-chain txs: settlement + timeout-reclaim.)
```

### Abort — refund (any time after Phase 2, if the bet is abandoned)

The refund is a 2-of-2 pre-signed in Phase 2 with `nLockTime = refund_locktime (t_r)`. Either party may
broadcast it once `t_r` is reached to return the stakes (`F_A → Alice`, `b → Bob`). No message — purely
on-chain, and available as a safety net from the moment `U1` is funded.

---

## Notes

- **No message reveals a private key or secret scalar.** Frames carry only public data: group points,
  MuSig2 nonces/partials, opaque proof bytes, `ctxt` (the *encrypted* outcome), and — only at
  resolution — the completed settlement signature from which `d` is derived.
- **Tags 1–4 (setup) and 5–10 (funding + overlay)** share a numeric space with the Phase-0 control
  bytes (`0x00`–`0x03`), but the phases are temporally separated: the peer-worker consumes the control
  frames before handing the transport to the bet protocol, which then only ever emits tagged bet frames.
- **On-chain transaction shapes** (funding, settlement, claim, refund, reclaim, cooperative spend) and
  their amount model live in the transaction-graph source ([`src/txgraph.rs`](../src/txgraph.rs),
  [`src/bet.rs`](../src/bet.rs)) and the v5 spec ([`adaptor_construction_spec_v5.tex`](adaptor_construction_spec_v5.tex));
  this document covers only the off-chain message layer.
