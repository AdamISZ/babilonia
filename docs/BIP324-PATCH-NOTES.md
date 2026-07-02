# BIP324 Covert Channel — Bitcoin Core Patch Notes

Findings from reading the actual v2 transport code, to scope the L1 patch (DESIGN.md §9).

> **Source pinned:** github.com/bitcoin/bitcoin @ `dc282ff31d1cc97507530a541d9cec8a8f6a6ef4`
> (HEAD, 2026-06-30). Line numbers below are at this commit and **will drift** — treat
> them as "find the function named X," not gospel.
>
> Relevant files: `src/bip324.{h,cpp}` (the AEAD cipher), `src/net.{h,cpp}`
> (`V2Transport` state machine + `CConnman::SocketSendData` send loop).

---

## 1. How the v2 transport actually works (the parts we touch)

Handshake (per `V2Transport` state machine, `net.h:456`):

```
responder: KEY_MAYBE_V1 ─┬─> KEY -> GARB_GARBTERM -> VERSION -> APP -> APP_READY
initiator:               └─> KEY -> ...
on wire (cleartext):  [ellswift pubkey 64B][garbage 0..4095B][garbage terminator 16B]
then (AEAD-encrypted): [version packet][app packets...]
```

- **Garbage** is sent cleartext, right after the ellswift pubkey
  (`StartSendingHandshake`, `net.cpp:994`). It is **authenticated** by being fed as AAD
  into the first (version) packet (`net.cpp:1170-1176`).
- Each side's garbage is **independent** — sent before ECDH completes — so a single
  handshake yields **one independent message each way**, never a dependent round-trip.
- After the garbage terminator, everything is **AEAD-encrypted** (ChaCha20-Poly1305 via
  `FSChaCha20Poly1305`, rekeying every `REKEY_INTERVAL = 224` packets, transparent).
- Per-packet overhead `EXPANSION = 3 (length) + 1 (header byte) + 16 (Poly1305 tag) = 20
  bytes`. The 1-byte header carries the **ignore bit** (`IGNORE_BIT = 0x80`, `bip324.h:30`).

Send path: `CConnman::SocketSendData` (`net.cpp:~1600`) pulls from `node.vSendMsg` →
`m_transport->SetMessageToSend()` → `GetBytesToSend()` → socket. One message buffered at
a time. Per-type byte accounting at `net.cpp:1656` is **skipped when `msg_type` is empty**
(handshake/decoy bytes aren't attributed to a message type).

---

## 2. Garbage — findings

`GenerateRandomGarbage()` (`net.cpp:983`):

```cpp
ret.resize(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1));  // MAX_GARBAGE_LEN = 4095
rng.fillrand(MakeWritableByteSpan(ret));
```

- **Length is UNIFORM over [0, 4095]** (mean ~2047), content uniform random.
- This is *friendly* for stego: any length in range is equally likely, and uniform-random
  ciphertext is exactly what a membership authenticator looks like. To stay in-distribution
  we just pad our payload to a uniform-random total length in [0, 4095].
- There is already a **test-only constructor that accepts garbage as a parameter**
  (`net.h:651`, `net.cpp:1006`); the production constructor (`net.cpp:1023`) is the one that
  calls `GenerateRandomGarbage()`. So the seam to inject chosen garbage already exists.

**Injection point (send):** plumb a per-peer garbage provider through `MakeTransport`
(`net.cpp:4040`, `make_unique<V2Transport>(id, !inbound)`) into the constructor, replacing/
augmenting `GenerateRandomGarbage()`.

**Injection point (receive):** the peer's garbage accumulates in `m_recv_buffer` during
`GARB_GARBTERM` (`ProcessReceivedGarbageBytes`, `net.cpp:1185`) and is retained as
`m_recv_aad`. Hook there to test received garbage against the membership PRF.

---

## 3. Decoy packets — findings (the important ones)

- **Core NEVER emits decoys.** Every encrypt call sets `ignore=false`: the version packet
  (`net.cpp:1172`) and every app message (`SetMessageToSend`, `net.cpp:1514`). There is no
  decoy-generation path anywhere.
- **Core silently DROPS received decoys.** In `ProcessReceivedPacketBytes` (`net.cpp:1212`),
  a decrypted packet with `ignore==true` skips the `if (!ignore)` block (`net.cpp:1254`): no
  state transition, never surfaced to `GetReceivedMessage`, buffer wiped.

**Consequence — two patches needed for the sustained channel:**

- **Send:** add a decoy-emission path. Encrypt a covert frame with
  `m_cipher.Encrypt(contents, /*aad=*/{}, /*ignore=*/true, out)` and interleave it into
  `m_send_buffer` (when idle, or between real messages). Cleanest hook is around the
  `SetMessageToSend`/`GetBytesToSend` boundary in `SocketSendData` so decoys ride the normal
  send loop. Their empty `msg_type` already excludes them from per-type stats (`net.cpp:1656`).
- **Receive:** at `net.cpp:1254`, when `ignore==true`, test `m_recv_decode_buffer` for our
  frame magic; if it matches, route to the covert API instead of dropping.

**Crucial visibility fact:** decoy *content* is AEAD-encrypted, so a passive wire observer
**cannot** distinguish a decoy from a real message — only packet **size / count / timing**
are observable. So "Core emits zero decoys" is **not** a content-detection problem; it's only
a traffic-*shape* concern, and OP_RAND payloads are tiny next to normal tx/block relay, so
they fit inside the normal envelope. This inverts the earlier worry: the visible-on-wire
surface is the *garbage* (cleartext), not the decoys.

---

## 4. In-band alternative to decoys (noted, probably not preferred)

Unknown-but-valid message types also survive: `GetMessageType` (`net.cpp:1420`) accepts the
long-encoding 12-byte type string; unknown commands pass up and net_processing ignores them
("messages get ignored anyway", `net.cpp:921`). The short-id table `V2_MESSAGE_IDS`
(`net.cpp:925`) has reserved/unimplemented slots (ids 29–36). So a covert frame *could* ride
an unused short-id or a bespoke long type.

Downside vs. decoys: it routes through net_processing (logging, "other" message stats) and
is a real (`ignore=false`) packet. Decoys are cleaner — they're dropped before net_processing
by design. **Prefer decoys; keep this as a fallback.**

---

## 5. Connection & peer control

- v2 is selected by `use_v2transport` (the `NODE_P2P_V2` service bit); v2 is the default for
  capable peers, so a v2 connection is unremarkable.
- Forcing a connection to a *specific* peer (needed for v1's direct Alice↔Bob): `addnode` /
  `CConnman::AddConnection` (`net.h:1366`). A deliberate direct connection that then co-spends
  on-chain is itself a correlation signal.
- **Tor:** Core's existing proxy support carries v2 over Tor unchanged. Running the covert
  connection over Tor breaks the IP-level A–B link and looks like any Tor-using node —
  directly mitigating the global-passive correlation in the threat model. No transport patch
  needed for this; it's a connection-policy choice.

---

## 6. Minimal patch surface (all in the net layer — no consensus/validation/wallet)

| # | What | Where |
|---|---|---|
| A | **Garbage = membership auth** (send): inject PRF-keyed authenticator, pad to uniform length | `MakeTransport` `net.cpp:4040` → `V2Transport` ctor; `GenerateRandomGarbage` `net.cpp:983` |
| A'| **Garbage detect** (recv): test peer garbage against PRF | `ProcessReceivedGarbageBytes` `net.cpp:1185` |
| B | **Decoy emit** (send): queue covert frames, `Encrypt(..., ignore=true)`, interleave | `SocketSendData` `net.cpp:~1620`; new state in `V2Transport` |
| B'| **Decoy route** (recv): on `ignore==true`, match frame magic → covert API | `ProcessReceivedPacketBytes` `net.cpp:1254` |
| C | **Covert API**: local IPC socket (NOT RPC) — send/recv opaque frames keyed by NodeId, request covert session to a peer | new module; bridges to A/B; `AddConnection` for session setup |

Confined to `net.{h,cpp}` (+ a small new IPC module). Untouched: consensus, validation,
mempool, wallet — keeps the fork tractable across rebases.

---

## 7. Distribution-matching analysis

- **Garbage length:** native = uniform[0,4095] → pad covert garbage to a uniform-random total
  length. Trivial to match; no length tell.
- **Garbage content:** PRF output is uniform-random → indistinguishable from native random
  garbage to a passive observer and to a non-member active prober (who lacks the PRF key).
- **Decoy traffic shape:** the only residual signal. Keep decoy packet sizes/counts/timing
  within normal Bitcoin traffic envelopes (easy given tiny payloads). **[OPEN]** wants
  empirical confirmation against live captures.
- **Handshake timing:** unaffected by garbage content; no change.

---

## 8. v1 scoping — what we actually need first

For v1 (deliberate direct two-party), the garbage membership-auth (A/A') is **optional**:

- Alice `addnode`s Bob's known address (optionally over Tor) → peer identity is implicit.
- The covert frame key is derived from the **BIP324 session id ⊕ a pre-shared pairwise
  secret**, so no in-garbage handshake is required to bootstrap.
- That reduces the v1 patch to **B + B' + C** (decoy send/recv + local API). Garbage
  injection (A/A') and opportunistic/probe-resistant rendezvous belong to the v2 overlay.

So: **v1 patch ≈ decoy channel + local socket. Rendezvous-in-garbage is a v2 concern.**

---

## 9. To verify on a real build / later

- Confirm `randrange` uniformity and that nothing downstream reshapes garbage length.
- Confirm decoys interleaved mid-stream don't trip `GetMaxBytesToProcess` / flow-control
  assertions (`net.cpp:1281`) or the `more`/`MSG_MORE` prediction (`net.cpp:1627`).
- Confirm rekeying (`REKEY_INTERVAL=224`) counts decoys the same as real packets on both
  ends (it should — same `Encrypt`/`Decrypt` path) so counters stay in sync.
- Measure live garbage-length and any decoy usage across the network for §7.
```
