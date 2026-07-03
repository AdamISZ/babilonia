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
the dependency tree entirely; the power-user path is the default (`node` enabled). The BIP324
transport itself — `Bip324Transport::new(rpc_client, peer_id)` — is just a thin `Transport` over the
`senddecoy`/`getdecoys` RPCs, so it's the reference implementation of the covert tier, not a special
case in the protocol.

### Run the patched node as a *dedicated comms node* (no funds)

Don't point Babilonia at the node holding your coins. Run the patched `bitcoind` as a throwaway
relay daemon with **no wallet / no funds** (per DESIGN §9's node-decoupling). This reframes "trust a
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

Pin/override with `BITCOIN_TAG`, `BITCOIN_SRC`, `BITCOIN_URL`. The Babilonia test harness and (in
future) the BIP324 transport pick up `$BABILONIA_BITCOIND`.

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
