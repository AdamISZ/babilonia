# Babilonia

**A Bitcoin transaction that is a fair bet without a trusted dealer, but also indistinguishable from a payment (no scripts exposed, in the full version).** Babilonia co-designs the network and chain layers so neither leaks the execution of the protocol as distinct from Alice paying Bob.

1. **BIP324 covert channel** — the v2 transport's *decoy* packets carry arbitrary bytes designed to
   look like random padding: a covert, authenticated pipe between two Bitcoin nodes.
2. **OP_RAND emulation** (Kurbatov, [arXiv:2501.16451](https://arxiv.org/abs/2501.16451) is the basic idea, developed into a much more advanced form by [Gerhardt](https://arxiv.org/abs/2605.04975); this construction is between those two; see the [delving bitcoin thread](https://delvingbitcoin.org/t/emulating-op-rand/1409) for a discussion) —
   a trustless two-party fair coin settled on-chain with no special script and no consensus change.
3. **Steganographic mixing** — because the wager is a *real* economic event whose transactions are ordinary taproot payments, using it it breaks coin-history linkage while looking like normal traffic.

> **Research code.** This is a working scaffold for a thesis, not audited software. Security proofs not yet done, though there isn't a likely concern one can never be too cautious! See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design.

## How the game works (v5)

Alice (the **dealer**) picks a secret choice `c` from 1,2, encoded in a list of points `A_1, A_2`; Bob (the **player**) picks a secret guess `y` and
**wins iff `y = c`**. The roles are symmetrical but there is no trust. One jointly-funded taproot output `U1` (the pot) is spent by a MuSig2
**adaptor signature locked to `D = d·G`** for a fresh dealer secret `d`. Both sides get ZKPs that guarantee the other behaves honestly. Alice can't be paid without
completing that adaptor — which *posts `d` on-chain*. Bob then decrypts the outcome
`a_c = ctxt − H(d)` (from `ctxt = a_c + H(d)`) and, if he won, claims the pot via the taproot address which he only knows the secret key for because of that decryption; otherwise Alice reclaims it after a timeout. There is also a refund Tx if the payout Tx never gets broadcast.

### Architecture

```
game    business logic only — roles, outcome, the bet sequence. No bitcoin.
  │
node ·  the bitcoin translation layer — joint PSBT funding, settlement, claim,
bet     the covert transport, wallet/RPC. The only place transactions are built.
  │
txgraph · musig · sigma · reveal · setup   the crypto / tx primitives
```

The core library is transport-agnostic (`&mut dyn Transport`); the BIP324 covert channel is one
`Transport` implementation (in the sense that someone can implement others in future). The only piece still stubbed is the `π_a` **hash circuit**
(binding `ctxt` to `a_c`); everything else — sigma proofs, MuSig2 adaptor settlement, the taproot tx
graph, joint PSBT funding, and the covert channel — is built and regtest-validated.

## Installation

Needs a [Rust toolchain](https://rustup.rs/) (edition 2021).

```sh
git clone <this-repo> && cd babilonia
cargo build
cargo test          # unit tests (no bitcoind needed)
```

## Some concrete info about how to run tests locally, on regtest, to see it operating:

The runners drive a local `bitcoind` on **regtest**:

- `regtest-game` needs a stock `bitcoind` on your `PATH`.
- `party` (the two-node BIP324 demo) needs the **patched** Core build with the `senddecoy`/`getdecoys`
  RPCs. Build it once with `scripts/build-patched-node.sh` and point `$BABILONIA_BITCOIND` at it —
  see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

Library-only consumers who ship their own `Transport` (rendezvous, Nostr, Tor…) need no Bitcoin Core
at all: `cargo build --no-default-features` drops the RPC dependencies entirely.

## Quick start — run a full game

### Single process (stock `bitcoind` on `PATH`)

```sh
cargo run --bin regtest-game            # player wins
cargo run --bin regtest-game -- --lose  # player loses; dealer reclaims after timeout
```

It spins up a throwaway regtest node, funds two wallets, and plays the whole game, printing each step
(and the `decoderawtransaction` JSON of every transaction it builds):

```
── Babilonia regtest game ──────────────────────────────
spinning up bitcoind (regtest)… up (network=Regtest)
dealer chooses c=1; player guesses y=1  →  expecting PLAYER wins
funded two wallets (alice, bob); U1 will be jointly funded during play
── playing ─────────────────────────────────────────────
  [dealer] joint PSBT funding built — U1 = 9e2efa…:0 (500000 sat); TX1 held (not broadcast)
  [dealer] running the 4-flight setup …
  [dealer] settled — adapted with d and broadcast c930e1… (d now on-chain)
  [player] extracted d, decrypted a_c → PlayerWins
  [player] spent the pot via the <K> leaf — broadcast 18a72a…
🎉 PLAYER won and claimed the pot.
```

### Two windows, two nodes, over the real BIP324 covert channel

Requires the patched `bitcoind` (set `BABILONIA_BITCOIND`). Every game message — the joint-funding
sub-protocol and all four setup flights — rides the BIP324 decoy channel between the two peered nodes.

**Window 1 — the dealer** (spawns its node, becomes the sole miner, prints its P2P address):

```sh
BABILONIA_BITCOIND=/path/to/patched/bitcoind cargo run --bin party -- --role dealer
```

**Window 2 — the player** (copy the address the dealer printed):

```sh
BABILONIA_BITCOIND=/path/to/patched/bitcoind \
  cargo run --bin party -- --role player --connect 127.0.0.1:<port> --guess 1
```

The two nodes peer over BIP324 v2, the dealer funds the player's wallet over the channel, and the
game plays out on the shared regtest chain. Use `--guess 1` (default) for a win, `--guess 0` for a
loss (the dealer reclaims via the timeout leaf).

## Tests

```sh
cargo test                                            # unit tests, no node
cargo test --test game -- --ignored                   # full on-chain game (needs bitcoind on PATH)
cargo test --test regtest_e2e -- --ignored --test-threads=1   # tx-graph e2e
cargo test --test bip324 -- --ignored --test-threads=1        # covert channel (needs patched node)
```

