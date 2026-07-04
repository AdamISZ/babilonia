#![cfg(feature = "node")] // drives a local bitcoind over RPC; needs the `node` feature
//! BIP324 covert-transport work (DESIGN §9, L1). Bottom-up:
//!   - `two_nodes_connect_over_v2`  — v2 peering (stock `bitcoind` on PATH; v2 is native)
//!   - `decoy_round_trip_over_v2`   — raw senddecoy/getdecoys RPCs (patched node)
//!   - `transport_round_trip_over_decoys` — the `Bip324Transport` framing (patched node)
//!   - `setup_handshake_over_bip324` — CAPSTONE: run_alice/run_bob over the covert channel
//!
//! Patched-node tests use `$BABILONIA_BITCOIND` (see scripts/build-patched-node.sh). Ignored by
//! default. Run **serially** — each test spawns two mining nodes, so parallel runs contend:
//!   cargo test --test bip324 -- --ignored --test-threads=1 --nocapture

use babilonia::keys::Keypair;
use babilonia::node::Node;
use babilonia::setup::{run_alice, run_bob, AliceSecrets, BobSecrets, GameParams};
use babilonia::transport::{bip324::Bip324Transport, Transport};
use musig2::secp::Scalar;
use secp256k1::Secp256k1;
use std::time::{Duration, Instant};

/// Path to the patched Bitcoin Core build (with the senddecoy/getdecoys RPCs). Honors
/// `$BABILONIA_BITCOIND` (e.g. what `scripts/build-patched-node.sh` prints), else the dev clone.
fn patched_bitcoind() -> String {
    std::env::var("BABILONIA_BITCOIND")
        .unwrap_or_else(|_| "/Users/waxwing/code/bitcoin/build/bin/bitcoind".into())
}

/// Poll `get_decoys` until something arrives (delivery is async), or time out.
fn wait_for_decoy(node: &Node, peer_id: i64) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let d = node.get_decoys(peer_id).unwrap();
        if !d.is_empty() {
            return d;
        }
        assert!(Instant::now() < deadline, "no decoy received before timeout");
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// Two nodes peer, and the connection negotiates BIP324 v2 (not the v1 plaintext transport).
#[test]
#[ignore = "requires bitcoind on PATH; run with --ignored"]
fn two_nodes_connect_over_v2() {
    let a = Node::regtest().expect("node A");
    let b = Node::regtest().expect("node B");
    println!("[up]   A @ {}, B @ {}", a.p2p_addr(), b.p2p_addr());

    // B dials A; both have -v2transport=1, so the outbound connection should be v2.
    b.connect_to(&a).expect("addnode");
    assert!(
        b.wait_for_v2_peers(1, Duration::from_secs(15)).unwrap(),
        "B established a v2 connection to A"
    );
    // A sees the inbound side as v2 too.
    assert!(
        a.wait_for_v2_peers(1, Duration::from_secs(15)).unwrap(),
        "A sees a v2 peer"
    );

    // Show the negotiated transport for eyeballing.
    for p in b.peers().unwrap() {
        println!(
            "[peer] B→ addr={} inbound={} transport={} session={}",
            p.get("addr").and_then(|v| v.as_str()).unwrap_or("?"),
            p.get("inbound").and_then(|v| v.as_bool()).unwrap_or(false),
            p.get("transport_protocol_type").and_then(|v| v.as_str()).unwrap_or("?"),
            p.get("session_id").and_then(|v| v.as_str()).unwrap_or("-"),
        );
    }
    println!("[ok]   two nodes connected over BIP324 v2 ✓");
}

/// Stage 3: two **patched** nodes exchange BIP324 decoy packets that each can read back via the
/// new `senddecoy`/`getdecoys` RPCs. This is the covert channel carrier working end to end.
#[test]
#[ignore = "requires the patched bitcoind build; run with --ignored"]
fn decoy_round_trip_over_v2() {
    let bin = patched_bitcoind();
    let a = Node::regtest_with_binary(&bin).expect("patched node A");
    let b = Node::regtest_with_binary(&bin).expect("patched node B");
    b.connect_to(&a).expect("addnode");
    assert!(b.wait_for_v2_peers(1, Duration::from_secs(15)).unwrap(), "B↔A on v2");
    assert!(a.wait_for_v2_peers(1, Duration::from_secs(15)).unwrap(), "A sees v2 peer");

    // Each node's single peer is the other.
    let b_id_on_a = a.only_peer_id().unwrap();
    let a_id_on_b = b.only_peer_id().unwrap();
    println!("[peers] on A, B is id={b_id_on_a}; on B, A is id={a_id_on_b}");

    // A → B: send a decoy, read it back on B.
    let msg_ab = b"babilonia covert channel: hello from A".to_vec();
    assert!(a.send_decoy(b_id_on_a, &msg_ab).unwrap(), "A queued decoy");
    let got_ab = wait_for_decoy(&b, a_id_on_b);
    assert_eq!(got_ab, vec![msg_ab.clone()], "B read A's decoy verbatim");
    println!("[A→B]  \"{}\"", String::from_utf8_lossy(&got_ab[0]));

    // B → A: the other direction.
    let msg_ba = b"...and a reply from B".to_vec();
    assert!(b.send_decoy(a_id_on_b, &msg_ba).unwrap(), "B queued decoy");
    let got_ba = wait_for_decoy(&a, b_id_on_a);
    assert_eq!(got_ba, vec![msg_ba.clone()], "A read B's decoy verbatim");
    println!("[B→A]  \"{}\"", String::from_utf8_lossy(&got_ba[0]));

    // Draining is exhaustive: a second read returns nothing.
    assert!(b.get_decoys(a_id_on_b).unwrap().is_empty(), "decoys drained on read");
    println!("[ok]   decoys exchanged over BIP324 v2, each side reads the other's payload ✓");
}

/// Peer two patched nodes and hand each side a `Bip324Transport`.
fn peered_transports() -> (Node, Node, Bip324Transport, Bip324Transport) {
    let bin = patched_bitcoind();
    let a = Node::regtest_with_binary(&bin).expect("patched node A");
    let b = Node::regtest_with_binary(&bin).expect("patched node B");
    b.connect_to(&a).expect("addnode");
    assert!(b.wait_for_v2_peers(1, Duration::from_secs(15)).unwrap(), "B↔A on v2");
    assert!(a.wait_for_v2_peers(1, Duration::from_secs(15)).unwrap(), "A sees v2 peer");
    let ta = Bip324Transport::new(a.new_rpc_client().unwrap(), a.only_peer_id().unwrap());
    let tb = Bip324Transport::new(b.new_rpc_client().unwrap(), b.only_peer_id().unwrap());
    (a, b, ta, tb)
}

/// The `Transport` trait works over real BIP324 decoys: ordered, framed, both directions.
#[test]
#[ignore = "requires the patched bitcoind build; run with --ignored"]
fn transport_round_trip_over_decoys() {
    let (_a, _b, mut ta, mut tb) = peered_transports();

    ta.send(b"flight-1: alice->bob").unwrap();
    assert_eq!(tb.recv().unwrap(), b"flight-1: alice->bob");
    tb.send(b"flight-2: bob->alice").unwrap();
    assert_eq!(ta.recv().unwrap(), b"flight-2: bob->alice");

    // Two frames back-to-back preserve order (getdecoys drains in batches; recv buffers).
    ta.send(b"one").unwrap();
    ta.send(b"two").unwrap();
    assert_eq!(tb.recv().unwrap(), b"one");
    assert_eq!(tb.recv().unwrap(), b"two");
    println!("[ok]   Transport frames ride BIP324 decoys, ordered, both ways ✓");
}

/// Capstone — L1 meets L2: the full **v5** setup driver (`run_alice`/`run_bob`, 4 flights, real
/// thimble PoKs + π_r + π_a Σ-part; hash conjunct stubbed) runs to completion over the covert decoy
/// channel between two nodes, pre-signing the settlement + refund.
#[test]
#[ignore = "requires the patched bitcoind build; run with --ignored"]
fn setup_handshake_over_bip324() {
    let (_a, _b, mut ta, mut tb) = peered_transports();

    let secp = Secp256k1::new();
    let scalar = |s: &Secp256k1<secp256k1::All>| Scalar::from(Keypair::new(s).sk);
    let c = 1usize;
    let alice = AliceSecrets {
        identity: Keypair::new(&secp),
        thimbles: [scalar(&secp), scalar(&secp)],
        choice: c,
        d: scalar(&secp),
    };
    let bob = BobSecrets {
        funding: Keypair::new(&secp),
        claim: Keypair::new(&secp),
        guess: c, // a winning guess
    };
    let params = GameParams {
        u1_outpoint: bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            vout: 0,
        },
        u1_value: bitcoin::Amount::from_sat(500_000),
        alice_stake: bitcoin::Amount::from_sat(250_000),
        bob_stake: bitcoin::Amount::from_sat(248_000),
        fee: bitcoin::Amount::from_sat(2_000),
        refund_locktime: 200,
        alice_timeout: 6,
    };

    // Bob runs on another thread; both sides talk only through their Bip324Transport.
    let params_b = params.clone();
    let bob_handle = std::thread::spawn(move || run_bob(&mut tb, &params_b, &bob));
    let a = run_alice(&mut ta, &params, &alice).expect("alice setup over decoys");
    let b = bob_handle.join().unwrap().expect("bob setup over decoys");

    // Both sides reached the same shared view — the whole 4-flight exchange survived the covert
    // transport (thimble PoKs + π_r + π_a Σ-part verified, both MuSig2 sessions co-signed).
    assert_eq!(a.keyagg.agg_xonly(), b.keyagg.agg_xonly());
    assert_eq!(a.k, b.k);
    assert_eq!(a.settle_sighash, b.settle_sighash);
    assert_eq!(a.ctxt, b.ctxt);
    println!("[ok]   full v5 OP_RAND setup driver completed over BIP324 decoys ✓");
}
