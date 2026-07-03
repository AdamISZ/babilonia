//! BIP324 covert-transport work (DESIGN §9, L1). Stage 1: stand up two regtest nodes and get
//! them talking over the **v2 (BIP324)** transport. Uses the stock `bitcoind` (v2 is native);
//! the decoy-packet patch + RPC come later.
//!
//! Requires `bitcoind` (v31) on PATH. Ignored by default. Run:
//!   cargo test --test bip324 -- --ignored --nocapture

use babilonia::regtest::RegtestNode;
use std::time::{Duration, Instant};

/// Path to the patched Bitcoin Core build (with the senddecoy/getdecoys RPCs). Honors
/// `$BABILONIA_BITCOIND` (e.g. what `scripts/build-patched-node.sh` prints), else the dev clone.
fn patched_bitcoind() -> String {
    std::env::var("BABILONIA_BITCOIND")
        .unwrap_or_else(|_| "/Users/waxwing/code/bitcoin/build/bin/bitcoind".into())
}

/// Poll `get_decoys` until something arrives (delivery is async), or time out.
fn wait_for_decoy(node: &RegtestNode, peer_id: i64) -> Vec<Vec<u8>> {
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
    let a = RegtestNode::start().expect("node A");
    let b = RegtestNode::start().expect("node B");
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
    let a = RegtestNode::start_with_binary(&bin).expect("patched node A");
    let b = RegtestNode::start_with_binary(&bin).expect("patched node B");
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
