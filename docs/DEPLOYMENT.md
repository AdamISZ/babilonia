# Deployment

Maximal covertness has an irreducible cost: to be *indistinguishable from Bitcoin traffic* you have
to actually **be** a Bitcoin node. There's no packaging trick around that for the top tier. So rather
than fight it, Babilonia treats the patched node as **one `Transport` implementation among several**
and lets each consumer pick a point on the covertness/effort curve. The `Transport` trait
(`src/transport/`) is the load-bearing abstraction here.

## Two tiers

| Tier | Who | Runs | Covertness | Effort |
|---|---|---|---|---|
| **Library-only** | *Builder* | `babilonia` + a custom `Transport` (rendezvous server, Nostr, Tor HS, WebRTC…) | only as good as that medium | trivial — a pure-Rust dependency |
| **Patched-node** | *Power user* | a patched `bitcoind` + a transport driving it over RPC | maximal (real BIP324 decoys) | build Core once (below) |

The core `babilonia` library never depends on the patched node — the setup/settlement protocol runs
over `&mut dyn Transport`. A builder implements `Transport` over whatever medium they ship to end
users; those users compile no Bitcoin Core.

This is enforced by the **`node` Cargo feature** (on by default), which gates the only RPC-driving
code: the `regtest` harness and the `Bip324Transport`. A builder depends on the transport-agnostic
core with no RPC dependencies via:

```toml
babilonia = { version = "…", default-features = false }
```

`cargo build --no-default-features` compiles the core with `bitcoincore-rpc`/`serde_json` absent from
the dependency tree entirely; the power-user path is the default (`node` enabled). The default CLI
`Ui` is likewise behind a `repl` feature (pulling in `rustyline`), so a builder shipping their own UI
(a GUI, say) drops that too. The BIP324
transport itself — `Bip324Transport::new(rpc_client, peer_id)` — is just a thin `Transport` over the
`senddecoy`/`getdecoys` RPCs, so it's the reference implementation of the covert tier, not a special
case in the protocol.

### Run the patched node as a *dedicated comms node* (no funds)

Don't point Babilonia at the node holding your coins. Run the patched `bitcoind` as a throwaway
relay daemon with **no wallet / no funds** (node-decoupling). This reframes "trust a
Core fork with my money" into "run a relay that happens to speak Bitcoin P2P," and is the intended
topology anyway.

## Building the patched node (power-user path)

We do **not** vendor Bitcoin Core (no git submodule): a Core submodule would bake the ~GB Core repo
into every clone of this repo, punishing the many library-only users who never build the node. For a
~130-line patch, a pinned upstream tag + a patch file is smaller, reviewable, and cheap to rebase.

- `patches/bip324-decoy.patch` — the diff against the pinned tag (adds `senddecoy`/`getdecoys` and
  the decoy send/capture in `net.cpp`/`net.h`).
- `scripts/build-patched-node.sh` — clones `bitcoin/bitcoin` at the pinned tag into a cache dir,
  applies the patch from a clean checkout, and builds `bitcoind` + `bitcoin-cli`.

```sh
# macOS deps (Linux hint printed by the script):
brew install cmake pkgconf boost

scripts/build-patched-node.sh
# -> prints the binary path, e.g. ~/.cache/babilonia/bitcoin/build/bin/bitcoind
export BABILONIA_BITCOIND=~/.cache/babilonia/bitcoin/build/bin/bitcoind
```

Pin/override with `BITCOIN_TAG`, `BITCOIN_SRC`, `BITCOIN_URL`. The Babilonia test harness, the BIP324
transport, and the runner binaries all pick up `$BABILONIA_BITCOIND`.

## Runners

Three binaries exercise the game (all use the `node` feature). They sit above the layering:
`ui` → `agent::NodeCore` → `game` → `bet` → `txgraph`/`musig`/`sigma`/`pi_a`/`setup`, over the three
swappable edges (`Ui`, `Transport`, `Wallet`/`Chain`).

The `Wallet` edge has two implementations: the default `RpcWallet` (drives `bitcoind`'s own wallet
over RPC — used by the binaries and babilonia's own tests) and the standalone **`basic-wallet`** crate
(a BDK wallet where the keys live in the app, not bitcoind; behind babilonia's optional `basic-wallet`
feature). A wallet developer integrates by implementing this `Wallet` trait — `basic-wallet` is the
reference. See its own `basic-bitcoin-wallet` CLI and tests.

- **`babilonia-node`** — the interactive **REPL** (the main way to run; see the README): each process
  is a bitcoin node driving a CLI; two connect by address and bet over the **real BIP324 decoy
  channel**. Requires the patched build (`$BABILONIA_BITCOIND`).

  ```sh
  BABILONIA_BITCOIND=… cargo run --bin babilonia-node                    # funded + mining node
  BABILONIA_BITCOIND=… cargo run --bin babilonia-node -- --join --auto-accept   # joining node
  ```

  On **regtest** the node is spawned and self-funded (mining) for you. On **signet**, `--signet`
  instead **attaches** to a signet node *you* already run and syncs (babilonia doesn't manage its
  lifecycle), and the wallet is the BDK `basic-wallet` (keys in the app), funded from a faucet:

  ```sh
  cargo run --features basic-wallet --bin babilonia-node -- --signet \
      --rpc-url http://127.0.0.1:38332 --cookie ~/.bitcoin/signet/.cookie [--p2p-port 38333] [--wallet-dir <dir>]
  # then in the REPL:  receive → fund that address from a signet faucet → balance → propose / connect
  ```
  The attached signet node must still be the **patched** build for the BIP324 decoy channel.

  **Crash recovery.** Every bet's full state is persisted under `<config-dir>/bets/` (default
  `~/.babilonia/bets/`) at each transition — a `<id>.json` record (secrets, params, and the
  funding/settlement/refund txs + signatures) plus a human-readable `refund-<u1txid>.txt`, written
  *before* funding is broadcast. If a node crashes or restarts mid-bet, `recover` lists the open bets
  and what each needs, `recover <id>` drives the right action (settle / claim / reclaim), and
  `recover <id> refund` broadcasts the refund once its locktime passes — all from the record alone,
  no peer required. (Records hold secrets in clear; encryption at rest is a planned follow-on.)

- **`party`** — a scripted (non-interactive) two-node covert run, superseded by the REPL but kept as
  a fixed dealer/player script. Requires the patched build.

  ```sh
  BABILONIA_BITCOIND=… cargo run --bin party -- --role dealer
  BABILONIA_BITCOIND=… cargo run --bin party -- --role player --connect <addr> [--guess 0|1]
  ```

- **`regtest-game`** — single process: spins up a throwaway regtest `bitcoind`, funds two wallets,
  and plays a full game (joint PSBT funding → settlement → claim) over an in-memory transport. Needs
  only a stock `bitcoind` on `PATH`.

  ```sh
  cargo run --bin regtest-game            # player wins → claims via K
  cargo run --bin regtest-game -- --lose  # player loses → dealer reclaims after timeout
  ```

For the two-node runners the first node is the sole block producer (background miner); a `--join`
node spawns *unfunded* and syncs to it rather than forking.

### Why the build stays covert

Building from the **exact release tag** keeps the peer-visible user-agent stock — a patched node
still advertises `/Satoshi:29.3.0/`, byte-identical to any real v29.3 node (verified). Decoy packets
are AEAD-encrypted BIP324, indistinguishable on the wire from real messages. The new RPCs are a
*local* control interface only; RPC categories (`network` vs `hidden`) are cosmetic `help`-listing
and are never visible to peers. The one thing to preserve: build from a **clean checkout at the tag**
— a dirty tree or a non-tag commit can leak a `-dirty`/commit suffix into that user-agent string.

## Status / caveats

The patch is a **local proof-of-concept branch**, not shaped for upstreaming. Known rough edges: the
send path calls `PushMessage` inside `ForNode` (fine for the PoC; a reviewer would tighten the
locking), and the RPCs are unauthenticated beyond Core's normal RPC auth. Rebasing the patch onto a
new Core release is a small-diff job; bump `BITCOIN_TAG` and re-run the script (fix any hunk drift).
