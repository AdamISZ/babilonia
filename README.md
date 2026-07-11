# Babilonia

**A Bitcoin transaction that is a fair bet without a trusted dealer, but also indistinguishable from a payment (no scripts exposed in the happy path).** Babilonia co-designs the network and chain layers so neither leaks the execution of the protocol as distinct from Alice paying Bob.

1. **BIP324 covert channel** — the v2 transport's *decoy* packets carry arbitrary bytes designed to look like random padding: a covert, authenticated pipe between two Bitcoin nodes.
2. **OP_RAND emulation** (Kurbatov, [arXiv:2501.16451](https://arxiv.org/abs/2501.16451) is the basic idea, developed into a much more advanced form by [Gerhardt](https://arxiv.org/abs/2605.04975); this construction is between those two; see the [delving bitcoin thread](https://delvingbitcoin.org/t/emulating-op-rand/1409) for a discussion) — a trustless two-party fair coin settled on-chain with no special script and no consensus change.
3. **Steganographic mixing** — because the wager is a *real* economic event whose transactions are ordinary taproot payments, using it breaks coin-history linkage while looking like normal traffic.

> **Research code.** This is a working experiment, not audited software. Security proofs not yet done, though there isn't a likely concern one can never be too cautious! A detailed outline in pdf is upcoming, for now see some notes on the ZK aspect at [`docs/PI-A-NOTES.md`](docs/PI-A-NOTES.md).

## How the game works

Alice (the **dealer**) picks a secret choice `c` from 1,2, encoded as points `A_1, A_2`; Bob (the **player**) picks a secret guess `y` and **wins iff `y = c`**. The roles are asymmetrical but there is no trust. One jointly-funded taproot output `U1` (the pot) is spent by a MuSig2
**adaptor signature locked to `D = d·G`** for a fresh dealer secret `d`. Both sides get ZKPs that guarantee the other behaves honestly. Alice can't be paid without
completing that adaptor — which *posts `d` on-chain*. Bob then decrypts the outcome
`a_c = ctxt − H(d)` (from `ctxt = a_c + H(d)`) and, if he won, claims the pot via the taproot address which he only knows the secret key for because of that decryption; otherwise Alice reclaims it after a timeout. There is also a refund Tx if the payout Tx never gets broadcast.

### The transactions

The pot lives in one jointly-funded taproot output `U1`. From there, two transactions carry the outcome: the **settlement** spends `U1` and, by completing the adaptor, publishes `d`; the **claim** then spends the settlement's output — Bob's honest win is a plain **key-path** spend (indistinguishable from an ordinary payment), and only if a *losing* Bob griefs does Alice fall back to a timelock **script leaf**. A **refund** is the fallback if the settlement is never broadcast. The graph below is the *enforced* path; when Bob cooperates a **cooperative overlay** (see below) collapses even the dealer-win into a single key-path payment.

```
   U1  — the pot: one jointly-funded P2TR output (key-path MuSig2(P_a, P_b))
    │
    ├─►  REFUND — spends U1 at nLockTime t_r, returning the stakes;
    │            the fallback if the settlement is never broadcast
    ▼
   ┌──────────────────────────────────────────────┐
   │ SETTLEMENT   (spends U1)                     │
   │                                              │
   │ wit: one MuSig2 Schnorr sig — the D = d·G    │
   │      adaptor completed with d, so            │
   │      broadcasting it publishes d on-chain    │
   │ out: the claim output  ↓                     │
   └──────────────────────────────────────────────┘
                          │
                          ▼
   the claim output — P2TR with internal key K; one script leaf (Alice timeout)
                    ┌───────────────────┴────────────────────┐
                    ▼                                        ▼
 ┌────────────────────────────────────┐   ┌────────────────────────────────────┐
 │ CLAIM — Bob wins (y = c)           │   │ CLAIM — Alice, after timeout       │
 │ KEY-PATH spend of K  (no script!)  │   │ leaf: <t_1> OP_CSV OP_DROP         │
 │ K = W_b + A_y; Bob knows dlog K    │   │       <P_a> OP_CHECKSIG            │
 │ = w_b + a_c once a_c is revealed   │   │ spendable after t_1 blocks;        │
 │ out: pot → Bob                     │   │ Bob lost / never claimed           │
 │                                    │   │ out: pot → Alice                   │
 └────────────────────────────────────┘   └────────────────────────────────────┘
```

**Cooperative overlay (the common dealer-win path).** The script-leaf reclaim above is a *fallback*: an `OP_CSV` spend is not a standard payment, so it's avoided when possible. Instead, once the pot is confirmed Alice reveals `d` off-chain; a *losing* Bob then co-signs a single key-path `U1 → Alice` spend — a plain 2-output payment, with **no settlement broadcast, no script, and no timelock wait**. Bob has every reason to cooperate (he's lost either way, and it's cheaper and more private for both sides), so this is the usual path; the settlement + timeout-leaf graph above runs only if Bob is offline or refuses. See `docs/MESSAGES.md` (Phase 3) for the message flow.

### Architecture

```
ui (CLI REPL / GUI)  ─┐
                      ├─ agent::NodeCore  ─  wallet · chain · transport   ← three swappable edges
                      ┘   (actor orchestrator)
  │
game   business logic only — roles, outcome, the bet sequence. No bitcoin.
  │
bet    the bitcoin translation layer — joint PSBT funding, settlement, claim.
  │
txgraph · musig · sigma · pi_a · reveal · setup   the crypto / tx primitives
```

**Three components are swappable behind traits**, around the `NodeCore` orchestrator: the **UI** (default: CLI REPL), **network messaging** (default: BIP324), and the **wallet**. Two wallets implement the `Wallet` seam: a lightweight default that drives `bitcoind`'s own wallet over RPC, and **`basic-wallet`** — a standalone reference wallet (a thin [BDK](https://bitcoindevkit.org) wrapper: BIP39, receive, spend, single-UTXO mode; regtest/signet/mainnet), a `basic-bitcoin-wallet` CLI in this
Cargo workspace that any wallet developer can also import. `π_a` is implemented with **two selectable proof schemes** — a sigma-based `t²` construction (default, no heavy deps) and a Bulletproofs+Poseidon hash circuit (behind the `pi_a` feature); see [`docs/PI-A-NOTES.md`](docs/PI-A-NOTES.md).

**Crash recovery.** A bet holds real funds across several on-chain steps, so its state is persisted to disk at every transition — a full record (secrets, params, and the funding/settlement/refund transactions with their signatures) under `~/.babilonia/bets/`, plus a human-readable refund. Funding is never broadcast until the co-signed refund is safely on disk. After a crash or restart, either party recovers from the record *alone*, with no live peer: the REPL's `recover` command lists open bets and drives whatever each needs — broadcast the refund past its locktime, (re)settle, extract `d` and claim a win, or reclaim the timeout leaf. (Records currently hold secrets in clear; encryption at rest is a planned follow-on.)

## Installation

Needs a [Rust toolchain](https://rustup.rs/) (edition 2021).

```sh
git clone <this-repo> && cd babilonia
cargo build
cargo test          # unit tests (no bitcoind needed)
```

## Some concrete info about how to run tests locally, on regtest, to see it operating:

The binaries drive a local `bitcoind` on **regtest**:

- `babilonia-node` (the REPL, above) and `party` (a scripted two-node demo) need the **patched** Core build with the `senddecoy`/`getdecoys` RPCs — build it once with `scripts/build-patched-node.sh` and point `$BABILONIA_BITCOIND` at it (see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)).
- `regtest-game` is a quick one-shot demo needing only a stock `bitcoind` on your `PATH`.

For **signet**, build with `--features basic-wallet` and run `babilonia-node --signet` — it **attaches** to your own running (patched) signet node (`--rpc-url` / `--cookie` / `--p2p-port`) and drives the BDK `basic-wallet`; `receive` an address, fund it from a signet faucet, then `propose`. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

Library-only consumers who ship their own `Transport` (rendezvous, Nostr, Tor…) need no Bitcoin Core at all: `cargo build --no-default-features` drops the RPC dependencies entirely.

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
  [player] spent the pot via the <K> key path — broadcast 18a72a…
🎉 PLAYER won and claimed the pot.
```

### Interactive — the `babilonia-node` REPL (two nodes, real BIP324)

The main way to run it. Each node is a bitcoin node (wallet + BIP324 transport) driven by a CLI; two of them connect by address and bet over the covert channel. Requires the patched `bitcoind` (`$BABILONIA_BITCOIND` — see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)).

```sh
# terminal 1 — funded, mining node; prints its P2P address:
BABILONIA_BITCOIND=… cargo run --bin babilonia-node

# terminal 2 — a joining node that syncs and auto-accepts:
BABILONIA_BITCOIND=… cargo run --bin babilonia-node -- --join --auto-accept
```

Then drive them (each `>` is a REPL prompt):

```
(2) > connect <addr-from-terminal-1>     # only the joiner dials; node 1 auto-registers the peer
                                         #   (wait for "· connected to …" on both before proposing)
(2) > receive                            # → an address; fund it:
(1) > send <that-address> 100000000      # (regtest) give the joining node coins
(1) > set stake_percent 1                # stake 1% of a UTXO (regtest coinbases are 50 BTC)
(1) > propose                            # → both play the bet over the decoy channel
```

Commands: `connect` · `propose` · `accept`/`reject <id>` · `receive` · `balance` ·
`send <addr> <sats>` · `set <key> <value>` · `config` · `help` · `quit`. Config (stake %,
`auto_accept`, …) persists to `~/.babilonia/config.txt`.

## Tests

```sh
cargo test                                                 # unit tests, no node
cargo test --test game   -- --ignored --test-threads=1     # full on-chain game (bitcoind on PATH)
cargo test --test agent  -- --ignored --test-threads=1     # node core: two cores bet via Command/Event
cargo test --test regtest_e2e -- --ignored --test-threads=1   # tx-graph e2e
cargo test --test bip324 -- --ignored --test-threads=1        # covert channel (needs patched node)
cargo test --features basic-wallet --test bet_basic_wallet -- --ignored --test-threads=1  # full bet on the BDK wallet
cargo test -p basic-wallet -- --ignored --test-threads=1      # the reference wallet's own functionality
```

