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

**BIP324 decoy framing.** On the covert transport, every frame is carried inside a BIP324 *decoy*
packet and stamped with a magic prefix so a receiver can tell a babilonia frame from the generic
decoys any v2 peer may emit:

```
DECOY_MAGIC ‖ <frame>        DECOY_MAGIC = b"babilon\x01"  (62 61 62 69 6c 6f 6e 01)
```

The prefix is added on send and stripped on receive — it is transparent to the message layer, so the
tags and fields below describe the frame *after* the magic is removed. The in-memory transport (tests)
has no such wrapping; frames go on the channel raw. Everything in the tables below is the post-magic
`<frame>`.

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

These control frames — except `ProposeTerms` — are a **single byte** (the whole frame is the one byte
shown in "Wire bytes"; there are no further fields). Note the byte value itself carries no identity: a
peer is recognised as running babilonia purely by the `DECOY_MAGIC` prefix (above), so the hello is
just *some* magic-carrying frame the dialer emits so the accepter can register it.

| # | Message | Wire bytes | Direction | Contents | Purpose |
|---|---------|-----------|-----------|----------|---------|
| 0 | hello | `0x00` (one byte) | Dialer → Accepter | the single `0x00` byte — no fields | presence ping so the accepter can pick out our protocol among its v2 peers (sent once, by the dialer only). `0x00` is a deliberate no-op — `ProposeTerms::decode` rejects it, so the worker ignores the content |
| 1 | `ProposeTerms` | `0x01` ‖ fields | Proposer → Accepter | `stake_sats: u64`, `fee_sats: u64`, `refund_locktime: u32`, `alice_timeout: u16`, `scheme: u8` | the offered bet terms; both sides derive the identical `GameParams` from it |
| 2 | accept | `0x02` (one byte) | Accepter → Proposer | the single `0x02` byte — no fields | accept the terms → proposer becomes Dealer, accepter becomes Player |
| 3 | reject | `0x03` (one byte) | Accepter → Proposer | the single `0x03` byte — no fields | decline; the session ends |

There is **no ASCII "HELLO"** on the wire — `hello`/`accept`/`reject` are the bare bytes `0x00`/`0x02`/
`0x03`. `scheme`: `0` = Squaring, `1` = Poseidon (the π_a construction; both parties must agree).

---

## Phase 1 — Joint funding

Builds the pot `U1` (a 2-of-2 MuSig2 key-path output) as a 2-in / 2-out payjoin. The **Player builds**
the funding transaction (its wallet's natural shape) and signs its own input; the **Dealer verifies and
co-signs**. The funding tx is *held, not broadcast*, until the refund is pre-signed in Phase 2.

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 4 | `FundOpen` | `0x05` | Dealer → Player | `p_a: Point`, `input: OutPoint`, `amount: u64` (= `F_A`), `alice_payout: String` | Alice's funding key, her **whole** input `F_A` (no funding change), and the address where her parked surplus `c_A` / refund return |
| 5 | `FundReply` | `0x06` | Player → Dealer | `p_b: Point`, `input: OutPoint`, `amount: u64` (= `F_B`), `change: String` (= `c_B` dest), `bob_payout: String`, `psbt: String` | Bob's funding key + input, his funding-change address, his refund payout address, and the **unsigned** Player-built funding PSBT |

Amounts (Alice-pays fee): `U1 = F_A + b − fee`, `c_B = F_B − b`, parked `c_A = F_A − a − fee`
(`a`, `b` = the stakes; see `funding_amounts` / `check_park` in [`src/bet.rs`](../src/bet.rs)).

> **No signatures are exchanged in Phase 1.** Both sides only *agree* the funding tx and derive `U1`'s
> outpoint (a segwit txid is witness-independent, so it is fixed before signing). The funding is signed
> only in **Phase 2b**, *after* the refund is pre-signed — so no broadcastable funding tx can exist
> before its refund does, and neither party can lock the other's coins into `U1` with no way out.

---

## Phase 2 — Setup (v5 driver, 4 flights)

The interactive protocol that pre-signs the transaction graph — the **refund** (2-of-2 key-path) and
the **settlement adaptor** locked to `D = d·G` — and commits the encrypted outcome `ctxt = a_c + H(d)`.
Two MuSig2 sessions (refund, settlement) run across these flights. This is where the zero-knowledge
proofs (thimble PoKs, `π_r`, `π_a`) are exchanged.

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 6 | `AliceOpen` | `0x01` | Alice → Bob | `p_a: Point`, `a1: Point`, `a2: Point`, `thimble_poks: var-bytes` | Alice's funding key and thimbles `A_1, A_2 = a_1·G, a_2·G` with proofs of knowledge |
| 7 | `BobCommit` | `0x02` | Bob → Alice | `p_b: Point`, `k: Point`, `pi_r: var-bytes`, `refund_nonce: PubNonce`, `settle_nonce: PubNonce`, `coop_nonce: PubNonce` | Bob's funding key, his claim key `K = W_b + A_y` with proof `π_r`, and his nonces for the refund, settlement, **and cooperative-overlay** MuSig2 sessions |
| 8 | `AliceReveal` | `0x03` | Alice → Bob | `refund_nonce: PubNonce`, `settle_nonce: PubNonce`, `ctxt: Scalar`, `d_point: Point` (= `D`), `pi_a: var-bytes`, `refund_partial: PartialSignature`, `settle_partial: PartialSignature`, `coop_nonce: PubNonce` | Alice's nonces (refund, settlement, **overlay**), the encrypted outcome `ctxt`, the adaptor point `D`, proof `π_a`, and her partials for the refund and the `D`-locked settlement |
| 9 | `BobAuth` | `0x04` | Bob → Alice | `refund_partial: PartialSignature`, `settle_partial: PartialSignature` | Bob's partials, completing both MuSig2 sessions (authorises the settlement adaptor pre-signature) |

After Phase 2 both parties hold the identical pre-signed refund and settlement-adaptor.

---

## Phase 2b — Funding signatures

Only now — with the refund pre-signed — are the funding signatures exchanged. The first broadcastable
funding tx to exist anywhere is produced here, with its refund already in hand. Then the Dealer (and
Player) broadcast it and wait for `U1` to confirm (on-chain, no message).

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 10 | `FundSign` | `0x0B` | Player → Dealer | `psbt: String` | the agreed funding PSBT with **Bob's** input now signed |
| 11 | `FundFinal` | `0x07` | Dealer → Player | `psbt: String` | the same PSBT with **Alice's** input signature added (both inputs signed), so the Player can combine + finalize `TX1`. The Dealer first checks it is byte-for-byte the tx agreed in Phase 1 |

---

## Phase 3 — Resolution overlay (a single message)

Once `U1` is confirmed, the Dealer resolves the bet with **one message** and then just watches the
chain — Bob drives the on-chain step in either outcome. Implemented in [`src/bet.rs`](../src/bet.rs)
(`dealer_cooperative` / `player_cooperative`).

| # | Message | Tag | Direction | Contents | Purpose |
|---|---------|-----|-----------|----------|---------|
| 12 | `CoopReveal` | `0x08` | Alice → Bob | `settle_sig: var-bytes` (64-byte **completed** settlement signature), `coop_tx: Transaction` (unsigned `U1 → [S, c_A_out]`, both to Alice), `alice_partial: PartialSignature` | reveal `d` (Bob extracts it from `settle_sig` exactly as on-chain), and hand Bob a **pre-signed** overlay: Alice's MuSig2 partial over `coop_tx`, using the coop nonce exchanged in Phase 2 |

**Bob replies with nothing.** From `d` he knows the outcome and acts on-chain himself:
- **lost** → adds his own partial to Alice's, aggregates, and **broadcasts `coop_tx`** (`U1 → Alice`) — no settlement, no script, no `t_1`.
- **won** → **broadcasts the settlement** himself (he holds `settle_sig`), then claims `O_K` via key-path.

Why Alice can pre-sign in message 1: the coop nonces were pre-exchanged in Phase 2, so she already has
Bob's nonce and can produce her partial up front. Handing it out is safe — her partial can only ever
complete a transaction that pays **Alice**. The Dealer then watches `U1`: an overlay spend ⇒ she won; a
settlement spend ⇒ he won; nothing by the deadline ⇒ Bob is offline and she runs the enforced fallback
(broadcast the settlement herself, reclaim via the `t_1` leaf).

> **Nonce hygiene:** the coop signing nonce is single-use and **in-memory only — never persisted**
> (a restored+reused nonce is key-compromising). A crash before resolution simply drops to the enforced
> fallback.

---

## Message-flow diagrams

Legend: `A` = Dealer/Alice, `B` = Player/Bob. Time flows downward. `[chain]` marks an on-chain action
(a broadcast/confirmation), **not** a message.

### Setup — the common prefix (identical for every outcome)

```
   A (Dealer)                                   B (Player)
      │                                              │
      │  ── hello 0x00 (dialer only) ─────────▶      │   Phase 0
      │  ── ProposeTerms ─────────────────────▶      │   (skipped on
      │      ◀────────────────── accept 0x02 ──      │    test transport)
      │                                              │
      │  ── FundOpen ─────────────────────────▶      │   Phase 1
      │      ◀──────────────────── FundReply ──      │   (agree funding —
      │                                              │    unsigned, no sigs)
      │                                              │
      │  ── AliceOpen ────────────────────────▶      │   Phase 2
      │      ◀──────────────────── BobCommit ──      │   (setup driver:
      │  ── AliceReveal ──────────────────────▶      │    refund + settlement
      │      ◀───────────────────── BobAuth ──       │    pre-signed)
      │                                              │
      │      ◀───────────────────── FundSign ──      │   Phase 2b
      │  ── FundFinal ────────────────────────▶      │   (sign funding —
      │                                              │    refund now exists)
      │  [chain] broadcast funding TX1 → wait for U1 to confirm
      │                                              │
      ▼             (continues in one branch below)  ▼
```

In all three branches the Dealer sends **one** message and then only observes; Bob broadcasts.

### Branch 1 — Dealer wins, cooperatively (the fast path)

```
   A (Dealer)                                   B (Player)
      │  ── CoopReveal (+ Alice's partial) ───▶      │   B extracts d,
      │                                              │   computes he LOST
      │                          B [chain] completes + broadcasts coop_tx (U1 → Alice)
      │  watches U1 → sees the overlay spend         │
      │                                              │
   DealerWins — one tx, no settlement, no d on-chain, no timeout. Done.
```

### Branch 2 — Player wins

```
   A (Dealer)                                   B (Player)
      │  ── CoopReveal (+ Alice's partial) ───▶      │   B extracts d,
      │                                              │   computes he WON
      │                          B [chain] broadcasts settlement (posts d)
      │                          B [chain] claims O_K via key-path
      │  watches U1 → sees the settlement spend      │
      │                                              │
   PlayerWins. (2 on-chain txs: settlement + claim, both broadcast by Bob.)
```

### Branch 3 — Dealer wins, enforced (Player offline or uncooperative)

```
   A (Dealer)                                   B (Player)
      │  ── CoopReveal (+ Alice's partial) ───▶      ✗   (B offline —
      │                                              │    never broadcasts)
      │      … deadline elapses, U1 still unspent …  │
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
- **The bet-frame tags** (`0x01`–`0x04` setup, `0x05`–`0x07` funding, `0x08` overlay, `0x0B`
  funding-signing) share a numeric space with the Phase-0 control bytes (`0x00`–`0x03`), but the phases
  are temporally separated: the peer-worker consumes the control frames before handing the transport to
  the bet protocol, which then only ever emits tagged bet frames.
- **On-chain transaction shapes** (funding, settlement, claim, refund, reclaim, cooperative spend) and
  their amount model live in the transaction-graph source ([`src/txgraph.rs`](../src/txgraph.rs),
  [`src/bet.rs`](../src/bet.rs)); this document covers only the off-chain message layer.
