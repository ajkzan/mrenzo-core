//! «Отправить позже» (wire-1.1 §W7.10): a message encrypted now
//! and delivered by the server days later, after any number of other
//! messages in both directions. This is the proof behind the horizon the
//! app allows — nothing here changes the core.
//!
//! The sender is always this core (a 1.0.0 client cannot schedule). The
//! recipient is this core AND the frozen 1.0.0 core (`tests/legacy353`,
//! build 353): its bounds are the same three numbers — 1000 positions per
//! message, 2000 kept keys, 14 days from the moment the key was SKIPPED
//! (`ratchet.rs`, `SKIPPED_TTL_MS`, both at `712e1dcc` and now).
//!
//! What is proven:
//! 1. scheduled, then 400 messages both ways across 80 DH steps and seven
//!    days, then delivered: it opens, in both builds, with no failure on
//!    the way;
//! 2. the bound is 14 days from the moment the recipient walked PAST it,
//!    and it is sharp: at 14 days it opens, a millisecond later it does not
//!    — `Failed` in 353 (counted: the reason a 1.0.0 peer may have at most
//!    two such messages waiting, `ScheduledPolicy`); here `Stale` (never
//!    counted) while the chain is among the 64 this session remembers
//!    having retired, and `Failed` after more DH steps than that;
//! 3. a recipient that never walked past it (the sender wrote nothing
//!    after) opens it whenever it comes — the 14 days are not a lifetime of
//!    the message;
//! 4. the first message a peer ever gets may be a scheduled one, and a
//!    scheduled message made while the session was still unanswered opens
//!    under the session a later message built;
//! 5. a hundred held messages (the server's quota) are a walk of a hundred.

mod common;
mod legacy353;

use common::*;
use legacy353::ratchet as r353;
use legacy353::session_set as s353;
use mrenzo_core::plaintext::TypedPlaintext;
use mrenzo_core::ratchet::Envelope;
use mrenzo_core::rng::StreamRng;
use mrenzo_core::session_set::{PeerSessions, SetOpen};

const MINUTE: i64 = 60 * 1000;
const DAY: i64 = 24 * 60 * MINUTE;

#[derive(Debug, PartialEq, Eq)]
enum Got {
    Opened(String),
    /// Not opened, and not counted by the host.
    Stale,
    /// Not opened, and counted (three in five minutes reset a 353 session).
    Failed,
}

/// The receiving end of the chat, in either build.
trait Peer {
    fn recv(&mut self, wire: &str, now: i64, label: &str) -> Got;
    fn send(&mut self, id: &str, now: i64, label: &str) -> String;
}

fn chat(id: &str) -> String {
    TypedPlaintext::Chat { id: id.into(), body: id.into(), reply: None, fwd: None, expire: None, story: None }.to_json()
}

fn body_of(plaintext: &str) -> String {
    serde_json::from_str::<serde_json::Value>(plaintext).unwrap()["body"].as_str().unwrap().to_string()
}

struct Bob11 {
    set: PeerSessions,
    me: Ident,
    from: Ident,
    p: Prekeys,
}

impl Peer for Bob11 {
    fn recv(&mut self, wire: &str, now: i64, label: &str) -> Got {
        let env = Envelope::parse(wire).unwrap();
        let mut r = StreamRng::new(label);
        let out = match self.set.open(&env, now, &mut r) {
            SetOpen::NeedsResponder => self
                .set
                .respond_and_open(&env, &self.me.ik, &self.me.ed_pub, &self.p.spk, Some(&self.p.opk.private), None, &self.from.ik.public, &self.from.ed_pub, now, &mut r)
                .unwrap(),
            other => other,
        };
        match out {
            SetOpen::Typed { plaintext, .. } => Got::Opened(body_of(&plaintext)),
            SetOpen::Stale => Got::Stale,
            SetOpen::Failed => Got::Failed,
            other => panic!("{other:?}"),
        }
    }

    fn send(&mut self, id: &str, now: i64, label: &str) -> String {
        self.set.encrypt(&chat(id), now, &mut StreamRng::new(label)).unwrap().to_wire()
    }
}

struct Bob353 {
    set: s353::PeerSessions,
    me: Ident,
    from: Ident,
    p: Prekeys,
}

impl Peer for Bob353 {
    fn recv(&mut self, wire: &str, now: i64, label: &str) -> Got {
        let env = r353::Envelope::parse(wire).expect("353 parses the envelope");
        let mut r = StreamRng::new(label);
        let out = match self.set.decrypt(&env, now, &mut r) {
            s353::SetDecrypt::NeedsResponder => {
                let x = env.x.unwrap();
                self.set
                    .respond_and_decrypt(&env, &self.me.ik, &self.me.ed_pub, &self.p.spk, x.opk.map(|_| &self.p.opk.private), &self.from.ik.public, &self.from.ed_pub, now, &mut r)
                    .unwrap()
            }
            other => other,
        };
        match out {
            s353::SetDecrypt::Opened { plaintext, .. } => Got::Opened(body_of(&plaintext)),
            // 353 has no `Stale`: whatever does not open is `Failed`, and its host counts it.
            s353::SetDecrypt::Failed => Got::Failed,
            other => panic!("{other:?}"),
        }
    }

    fn send(&mut self, id: &str, now: i64, label: &str) -> String {
        self.set.encrypt(&chat(id), now, &mut StreamRng::new(label)).unwrap().to_wire()
    }
}

/// Alice as the app runs her: the set with its aux (the lossy run is counted).
struct Alice {
    set: PeerSessions,
}

impl Alice {
    /// A 1.0.0 peer publishes the classical bundle; `Prekeys::bundle` is that bundle in both builds.
    fn new(a: &Ident, b: &Ident, p: &Prekeys, label: &str) -> Alice {
        let mut set = PeerSessions { aux_enabled: true, ..Default::default() };
        set.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), T0, &mut StreamRng::new(label)).unwrap();
        Alice { set }
    }

    fn send(&mut self, id: &str, now: i64, label: &str) -> String {
        self.set.encrypt_counted(&chat(id), false, now, &mut StreamRng::new(label)).unwrap().to_wire()
    }

    /// The step of a held message: what `encrypt_held` of the FFI does.
    fn schedule(&mut self, id: &str, now: i64, label: &str) -> String {
        self.set.encrypt_counted(&chat(id), true, now, &mut StreamRng::new(label)).unwrap().to_wire()
    }

    fn recv(&mut self, wire: &str, now: i64, label: &str) -> String {
        match self.set.open(&Envelope::parse(wire).unwrap(), now, &mut StreamRng::new(label)) {
            SetOpen::Typed { plaintext, .. } => body_of(&plaintext),
            other => panic!("{other:?}"),
        }
    }
}

fn pair(tag: &str, legacy: bool) -> (Alice, Box<dyn Peer>) {
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let alice_side = Alice::new(&a, &b, &p, &format!("{tag}/x"));
    let bob_side: Box<dyn Peer> = if legacy {
        Box::new(Bob353 { set: s353::PeerSessions::default(), me: b, from: a, p })
    } else {
        // As the app keeps it: with the aux (the retired chains are remembered).
        Box::new(Bob11 { set: PeerSessions { aux_enabled: true, ..Default::default() }, me: b, from: a, p })
    };
    (alice_side, bob_side)
}

/// One message each way: the session is answered and the prekey header stops.
fn settle(a: &mut Alice, b: &mut dyn Peer, tag: &str) {
    let w = a.send("hello", T0, &format!("{tag}/h"));
    assert_eq!(b.recv(&w, T0, &format!("{tag}/hr")), Got::Opened("hello".into()));
    let w = b.send("hi", T0, &format!("{tag}/b0"));
    assert_eq!(a.recv(&w, T0, &format!("{tag}/b0r")), "hi");
}

/// `rounds` × (5 messages from Alice, 5 from Bob): two DH steps a round.
/// Every message is delivered and must open. Returns the time it ended at.
fn chatter(a: &mut Alice, b: &mut dyn Peer, tag: &str, from: i64, until: i64, rounds: i64) -> i64 {
    let step = (until - from) / rounds;
    let mut now = from;
    for round in 0..rounds {
        now = from + step * (round + 1);
        for i in 0..5 {
            let id = format!("a{round}.{i}");
            let w = a.send(&id, now, &format!("{tag}/{id}"));
            assert_eq!(b.recv(&w, now, &format!("{tag}/{id}r")), Got::Opened(id), "round {round}");
        }
        for i in 0..5 {
            let id = format!("b{round}.{i}");
            let w = b.send(&id, now, &format!("{tag}/{id}"));
            assert_eq!(a.recv(&w, now, &format!("{tag}/{id}r")), id, "round {round}");
        }
    }
    now
}

#[test]
fn scheduled_then_hundreds_of_messages_across_many_dh_steps_then_delivered() {
    for legacy in [false, true] {
        let tag = if legacy { "pt/353" } else { "pt/11" };
        let (mut a, mut b) = pair(tag, legacy);
        settle(&mut a, b.as_mut(), tag);
        // Scheduled now, for seven days ahead — the longest the app hands to the server.
        let held = a.schedule("scheduled", T0, &format!("{tag}/m"));
        // 400 messages, 80 DH steps, the whole week. The first of them walks past the held position.
        let end = chatter(&mut a, b.as_mut(), tag, T0, T0 + 7 * DAY - MINUTE, 40);
        assert!(end < T0 + 7 * DAY);
        // The server releases it at its time: an ordinary frame, out of order by 200 messages and 80 chains.
        assert_eq!(b.recv(&held, T0 + 7 * DAY, &format!("{tag}/mr")), Got::Opened("scheduled".into()), "legacy={legacy}");
        // …and the chat goes on.
        let w = a.send("after", T0 + 7 * DAY, &format!("{tag}/after"));
        assert_eq!(b.recv(&w, T0 + 7 * DAY, &format!("{tag}/afterr")), Got::Opened("after".into()));
        // A second delivery of the same frame (the server's crash recovery) is not a second message.
        assert_ne!(b.recv(&held, T0 + 7 * DAY, &format!("{tag}/mrr")), Got::Opened("scheduled".into()));
    }
}

#[test]
fn the_bound_is_fourteen_days_from_the_walk_past_and_it_is_sharp() {
    // (late by a millisecond, DH rounds between the walk and the delivery)
    for (late, rounds) in [(false, 4), (true, 4), (true, 70)] {
        for legacy in [false, true] {
            let tag = format!("pt/b{}{}{rounds}", legacy as u8, late as u8);
            let (mut a, mut b) = pair(&tag, legacy);
            settle(&mut a, b.as_mut(), &tag);
            let held = a.schedule("scheduled", T0, &format!("{tag}/m"));
            // Bob walks past it one minute later, on the same chain…
            let walked = T0 + MINUTE;
            let w = a.send("live", walked, &format!("{tag}/l"));
            assert_eq!(b.recv(&w, walked, &format!("{tag}/lr")), Got::Opened("live".into()));
            // …and DH steps follow (each round retires one chain of Alice), so the held position is on a chain long retired.
            chatter(&mut a, b.as_mut(), &tag, walked, walked + DAY, rounds);
            let opened_at = walked + 14 * DAY + if late { 1 } else { 0 };
            let got = b.recv(&held, opened_at, &format!("{tag}/mr"));
            match (late, legacy, rounds) {
                (false, _, _) => assert_eq!(got, Got::Opened("scheduled".into()), "at 14 days the key is still kept (legacy={legacy})"),
                (true, true, _) => assert_eq!(got, Got::Failed, "353: the key expired — one counted failure"),
                (true, false, 4) => assert_eq!(got, Got::Stale, "1.1: the key expired on a remembered chain — dropped, never counted"),
                (true, false, _) => assert_eq!(got, Got::Failed, "1.1: more than 64 chains retired since — it cannot tell it from a forgery"),
            }
            // Either way the session lives.
            let w = a.send("next", opened_at, &format!("{tag}/n"));
            assert_eq!(b.recv(&w, opened_at, &format!("{tag}/nr")), Got::Opened("next".into()));
        }
    }
}

#[test]
fn a_recipient_that_never_walked_past_it_opens_it_whenever_it_comes() {
    for legacy in [false, true] {
        let tag = if legacy { "pt/q353" } else { "pt/q11" };
        let (mut a, mut b) = pair(tag, legacy);
        settle(&mut a, b.as_mut(), tag);
        let held = a.schedule("scheduled", T0, &format!("{tag}/m"));
        // Alice writes nothing after it; Bob keeps writing (his own chain turns, hers does not).
        for i in 0..20 {
            let w = b.send(&format!("b{i}"), T0 + i * DAY, &format!("{tag}/b{i}"));
            a.recv(&w, T0 + i * DAY, &format!("{tag}/b{i}r"));
        }
        // Sixty days later — far past any horizon the app allows — it is simply the next message.
        assert_eq!(b.recv(&held, T0 + 60 * DAY, &format!("{tag}/mr")), Got::Opened("scheduled".into()), "legacy={legacy}");
    }
}

#[test]
fn a_first_message_and_an_unanswered_session() {
    for legacy in [false, true] {
        // The first thing the peer ever gets is the scheduled message, a week after it was made.
        let tag = if legacy { "pt/f353" } else { "pt/f11" };
        let (mut a, mut b) = pair(tag, legacy);
        let held = a.schedule("scheduled", T0, &format!("{tag}/m"));
        assert_eq!(b.recv(&held, T0 + 7 * DAY, &format!("{tag}/mr")), Got::Opened("scheduled".into()), "legacy={legacy}");

        // Made while the session was unanswered (the prekey header rides on it); a live message builds the
        // session first, and the held one opens under it from the kept key.
        let tag = if legacy { "pt/u353" } else { "pt/u11" };
        let (mut a, mut b) = pair(tag, legacy);
        let held = a.schedule("scheduled", T0, &format!("{tag}/m"));
        let w = a.send("live", T0 + MINUTE, &format!("{tag}/l"));
        assert_eq!(b.recv(&w, T0 + MINUTE, &format!("{tag}/lr")), Got::Opened("live".into()));
        let w = b.send("re", T0 + 2 * MINUTE, &format!("{tag}/re"));
        assert_eq!(a.recv(&w, T0 + 2 * MINUTE, &format!("{tag}/rer")), "re");
        chatter(&mut a, b.as_mut(), tag, T0 + 2 * MINUTE, T0 + 6 * DAY, 6);
        assert_eq!(b.recv(&held, T0 + 7 * DAY, &format!("{tag}/mr")), Got::Opened("scheduled".into()), "legacy={legacy}");
    }
}

#[test]
fn a_hundred_held_messages_are_a_walk_of_a_hundred() {
    for legacy in [false, true] {
        let tag = if legacy { "pt/h353" } else { "pt/h11" };
        let (mut a, mut b) = pair(tag, legacy);
        settle(&mut a, b.as_mut(), tag);
        // The server's quota: a hundred held messages of one account, here all for one chat.
        let held: Vec<String> = (0..100).map(|i| a.schedule(&format!("s{i}"), T0, &format!("{tag}/s{i}"))).collect();
        let w = a.send("live", T0 + MINUTE, &format!("{tag}/l"));
        assert_eq!(b.recv(&w, T0 + MINUTE, &format!("{tag}/lr")), Got::Opened("live".into()), "a walk of 100 ≤ 1000");
        chatter(&mut a, b.as_mut(), tag, T0 + MINUTE, T0 + 5 * DAY, 5);
        // Released in any order.
        for i in (0..100).rev() {
            assert_eq!(b.recv(&held[i], T0 + 7 * DAY, &format!("{tag}/s{i}r")), Got::Opened(format!("s{i}")), "legacy={legacy}");
        }
    }
}
