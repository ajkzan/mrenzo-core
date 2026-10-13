//! 03-crypto §5.1: simultaneous initiation converges under Signal
//! semantics — every message decrypts in every delivery order, a replay never
//! promotes, and once both sides stop, one message per direction (a round
//! trip) leaves both sides on the same live session.

mod common;

use common::*;
use mrenzo_core::plaintext::TypedPlaintext;
use mrenzo_core::primitives::{b64, x25519_keypair, KeyPair};
use mrenzo_core::ratchet::{b64_strict, b64_strict32, Envelope};
use mrenzo_core::rng::{OsRng, StreamRng};
use mrenzo_core::session_set::{PeerSessions, SetDecrypt, Status};
use mrenzo_core::x3dh::{generate_signed_pre_key_v2, BundleV2};

struct Side {
    me: Ident,
    spk: KeyPair,
    spk_sig: [u8; 64],
    set: PeerSessions,
}

impl Side {
    fn new(me: Ident, label: &str) -> Side {
        let g = generate_signed_pre_key_v2(&me.ed_secret, 5, &mut StreamRng::new(label));
        Side {
            spk: KeyPair { public: b64_strict32(&g.pub_key).unwrap(), private: b64_strict32(&g.priv_key).unwrap() },
            spk_sig: b64_strict(&g.signature).unwrap().try_into().unwrap(),
            me,
            set: PeerSessions::default(),
        }
    }

    fn bundle(&self) -> BundleV2 {
        BundleV2 { spk_id: 5, spk_pub: self.spk.public, spk_sig: self.spk_sig, opk: None }
    }

    fn initiate_to(&mut self, peer: &Side, now: i64) {
        self.set.initiate(&self.me.ik, &self.me.ed_pub, &peer.me.ik.public, &peer.me.ed_pub, &peer.bundle(), now, &mut OsRng).unwrap();
    }

    fn send(&mut self, id: &str, now: i64) -> String {
        let pt = TypedPlaintext::Hello { id: id.into() };
        self.set.encrypt(&pt.to_json(), now, &mut OsRng).unwrap().to_wire()
    }

    fn recv(&mut self, wire: &str, from: &Ident, now: i64) -> SetDecrypt {
        let env = Envelope::parse(wire).unwrap();
        match self.set.decrypt(&env, now, &mut OsRng) {
            SetDecrypt::NeedsResponder => self
                .set
                .respond_and_decrypt(&env, &self.me.ik, &self.me.ed_pub, &self.spk, None, &from.ik.public, &from.ed_pub, now, &mut OsRng)
                .unwrap(),
            other => other,
        }
    }

    fn live_sid(&self) -> [u8; 32] {
        self.set.live().unwrap().session.sid
    }
}

/// xorshift for reproducible permutations without an extra crate.
struct Xs(u64);
impl Xs {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn run(order: &[(bool, usize)], a_count: usize, b_count: usize) {
    let mut a = Side::new(alice(), "p/a-spk");
    let mut b = Side::new(bob(), "p/b-spk");
    let mut now = T0;
    a.initiate_to(&b, now);
    b.initiate_to(&a, now);
    let a_wires: Vec<String> = (0..a_count).map(|i| a.send(&format!("a{i}"), now)).collect();
    let b_wires: Vec<String> = (0..b_count).map(|i| b.send(&format!("b{i}"), now)).collect();
    for &(from_a, i) in order {
        now += 1;
        let out = if from_a { b.recv(&a_wires[i], &a.me, now) } else { a.recv(&b_wires[i], &b.me, now) };
        assert!(matches!(out, SetDecrypt::Opened { .. }), "order {order:?}: {} {i} → {out:?}", if from_a { "a" } else { "b" });
    }
    // Replays never promote and never open.
    for &(from_a, i) in order.iter().take(3) {
        let (side, wire, from) = if from_a { (&mut b, &a_wires[i], &a.me) } else { (&mut a, &b_wires[i], &b.me) };
        let live = side.live_sid();
        let out = side.recv(wire, from, now);
        assert!(!matches!(out, SetDecrypt::Opened { .. }), "replay opened");
        assert_eq!(side.live_sid(), live, "replay promoted");
    }
    // Round trip: Alice → Bob, then Bob → Alice.
    now += 1;
    let w = a.send("ra", now);
    assert!(matches!(b.recv(&w, &a.me, now), SetDecrypt::Opened { .. }));
    let w = b.send("rb", now);
    assert!(matches!(a.recv(&w, &b.me, now), SetDecrypt::Opened { .. }));
    assert_eq!(a.live_sid(), b.live_sid(), "order {order:?}: converged on one session");
    assert!(a.set.entries.iter().filter(|e| e.status == Status::Archived).count() <= 3);
    // And it keeps working both ways.
    let w = a.send("x", now);
    assert!(matches!(b.recv(&w, &a.me, now), SetDecrypt::Opened { .. }));
    assert_eq!(a.live_sid(), b.live_sid());
}

/// Every order-preserving merge of the two send sequences, up to 4 per side.
#[test]
fn every_merge_of_up_to_four_per_side() {
    fn merges(a: usize, b: usize, prefix: &mut Vec<(bool, usize)>, ia: usize, ib: usize, out: &mut Vec<Vec<(bool, usize)>>) {
        if ia == a && ib == b {
            out.push(prefix.clone());
            return;
        }
        if ia < a {
            prefix.push((true, ia));
            merges(a, b, prefix, ia + 1, ib, out);
            prefix.pop();
        }
        if ib < b {
            prefix.push((false, ib));
            merges(a, b, prefix, ia, ib + 1, out);
            prefix.pop();
        }
    }
    for n in 1..=4 {
        let mut all = Vec::new();
        merges(n, n, &mut Vec::new(), 0, 0, &mut all);
        for order in all {
            run(&order, n, n);
        }
    }
}

/// Random full permutations (the server may reorder anything), 6 per side.
#[test]
fn random_delivery_orders_six_per_side() {
    let mut rng = Xs(0x9e37_79b9_7f4a_7c15);
    for _ in 0..400 {
        let mut order: Vec<(bool, usize)> = (0..6).map(|i| (true, i)).chain((0..6).map(|i| (false, i))).collect();
        for i in (1..order.len()).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        run(&order, 6, 6);
    }
}

/// A decrypt under an archived session promotes it; the previous live one is archived.
#[test]
fn promotion_under_archived() {
    let mut a = Side::new(alice(), "p/a-spk");
    let mut b = Side::new(bob(), "p/b-spk");
    a.initiate_to(&b, T0);
    let w = a.send("a0", T0);
    assert!(matches!(b.recv(&w, &a.me, T0), SetDecrypt::Opened { created: true, .. }));
    let w = b.send("b0", T0);
    assert!(matches!(a.recv(&w, &b.me, T0), SetDecrypt::Opened { .. }));
    let s1 = b.live_sid();
    let a_s1 = a.set.clone(); // Alice's S1, active (x dropped)
    // A second initiation (a reinstall of Alice's sessions): Bob's S1 is archived.
    a.set = PeerSessions::default();
    a.initiate_to(&b, T0 + 1);
    let w = a.send("a1", T0 + 1);
    assert!(matches!(b.recv(&w, &a.me, T0 + 1), SetDecrypt::Opened { created: true, .. }));
    let s2 = b.live_sid();
    assert_ne!(s1, s2);
    // A message on S1 (no x): live S2 fails, archived S1 opens → promoted.
    a.set = a_s1;
    let w = a.send("late", T0 + 2);
    assert!(Envelope::parse(&w).unwrap().x.is_none());
    assert!(matches!(b.recv(&w, &a.me, T0 + 2), SetDecrypt::Opened { promoted: true, created: false, .. }));
    assert_eq!(b.live_sid(), s1);
    assert_eq!(b.set.entries.iter().find(|e| e.session.sid == s2).unwrap().status, Status::Archived);
    // Its replay does not promote S2 back nor open.
    assert!(!matches!(b.recv(&w, &a.me, T0 + 3), SetDecrypt::Opened { .. }));
    assert_eq!(b.live_sid(), s1);
    let _ = (b64(&x25519_keypair(&mut OsRng).public), 0);
}

/// Reset binding (§5.5): only a `dh` of the live session archives it.
#[test]
fn reset_archives_only_the_matching_live_session() {
    let mut a = Side::new(alice(), "p/a-spk");
    let mut b = Side::new(bob(), "p/b-spk");
    a.initiate_to(&b, T0);
    let w = a.send("a0", T0);
    b.recv(&w, &a.me, T0);
    let reply = b.send("b0", T0);
    let bob_dh = Envelope::parse(&reply).unwrap().dh;
    // Alice cannot decrypt (simulated): she signs a reset naming Bob's dh.
    assert!(!b.set.archive_matching_dh(&[7u8; 32], T0), "an unrelated dh is a no-op");
    assert!(b.set.live().is_some());
    assert!(b.set.archive_matching_dh(&bob_dh, T0));
    assert!(b.set.live().is_none(), "the live session is archived");
    assert!(!b.set.archive_matching_dh(&bob_dh, T0), "a second reset for the same dh matches nothing");
}

// ───────────────────────────── lazy post-quantum upgrade (wire-1.1 §W6.5) ─────────────────────────────

/// One side upgrades a live classical session to a hybrid one while
/// classical messages are in flight in both directions. Whatever the delivery
/// order: every message opens, nobody is demoted back to the classical
/// session, and after one round trip both sides are on the hybrid session.
#[test]
fn a_lazy_pq_upgrade_survives_every_delivery_order() {
    use mrenzo_core::session_set::SetOpen;
    use mrenzo_core::x3dh::{generate_kem_pre_key, KemKind};

    fn open(side: &mut Side, wire: &str, from: &Ident, kem: Option<(&[u8; 64], KemKind)>, now: i64) -> SetOpen {
        let env = Envelope::parse(wire).unwrap();
        match side.set.open(&env, now, &mut OsRng) {
            SetOpen::NeedsResponder => {
                let kem = env.x.and_then(|x| x.kem).and(kem);
                side.set.respond_and_open(&env, &side.me.ik, &side.me.ed_pub, &side.spk, None, kem, &from.ik.public, &from.ed_pub, now, &mut OsRng).unwrap()
            }
            other => other,
        }
    }

    let mut rng = Xs(0x243f_6a88_85a3_08d3);
    for round in 0..120 {
        let mut a = Side::new(alice(), "p/a-spk");
        let mut b = Side::new(bob(), "p/b-spk");
        let kem = generate_kem_pre_key(&b.me.ed_secret, 9, KemKind::LastResort, &mut StreamRng::new("p/b-kem"));
        let seed = (&kem.seed, kem.kind);
        // Classical S1, confirmed both ways.
        a.initiate_to(&b, T0);
        let w = a.send("a0", T0);
        assert!(matches!(open(&mut b, &w, &a.me, None, T0), SetOpen::Typed { .. }));
        let w = b.send("b0", T0);
        assert!(matches!(open(&mut a, &w, &b.me, None, T0), SetOpen::Typed { .. }));
        let s1 = a.live_sid();
        // In flight on S1, both ways; then Alice upgrades and keeps sending.
        let mut wires: Vec<(bool, String)> = Vec::new(); // (from Alice, wire)
        for i in 0..3 {
            wires.push((true, a.send(&format!("a-c{i}"), T0 + 1)));
            wires.push((false, b.send(&format!("b-c{i}"), T0 + 1)));
        }
        let b_bundle = b.bundle();
        a.set.initiate_pq(&a.me.ik, &a.me.ed_pub, &b.me.ik.public, &b.me.ed_pub, &b_bundle, &kem.public(), T0 + 2, &mut OsRng).unwrap();
        let s2 = a.live_sid();
        assert_ne!(s1, s2);
        for i in 0..3 {
            wires.push((true, a.send(&format!("a-pq{i}"), T0 + 2)));
        }
        for i in (1..wires.len()).rev() {
            wires.swap(i, (rng.next() % (i as u64 + 1)) as usize);
        }
        let mut now = T0 + 3;
        for (from_a, wire) in &wires {
            now += 1;
            let out = if *from_a { open(&mut b, wire, &a.me, Some(seed), now) } else { open(&mut a, wire, &b.me, None, now) };
            assert!(matches!(out, SetOpen::Typed { .. }), "round {round}: {} → {out:?}", if *from_a { "a" } else { "b" });
            assert_eq!(a.live_sid(), s2, "round {round}: Alice was demoted");
        }
        assert_eq!(b.live_sid(), s2, "round {round}: Bob ends on the hybrid session");
        assert!(a.set.live_is_pq() && b.set.live_is_pq());
        // And it keeps working both ways on the hybrid session.
        let w = b.send("rb", now);
        assert!(matches!(open(&mut a, &w, &b.me, None, now), SetOpen::Typed { by, .. } if by.pq && by.sid == s2));
        let w = a.send("ra", now);
        assert!(matches!(open(&mut b, &w, &a.me, None, now), SetOpen::Typed { by, .. } if by.pq && by.sid == s2));
        assert_eq!((a.live_sid(), b.live_sid()), (s2, s2));
    }
}
