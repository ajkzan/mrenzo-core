//! Protocol v3 1:1 sessions: X3DH v2 (x3dhV2.json), the ratchet transcript
//! (ratchetV3.json), the downgrade/tamper surface (ratchetV3Negative.json)
//! and the skipped-key bounds (skippedCap.json). See tests/common for the
//! dual write/verify mode.

mod common;

use common::*;
use mrenzo_core::plaintext::{outer_matches_edit, outer_matches_p2p, parse_typed_plaintext, Reply, TypedPlaintext};
use mrenzo_core::primitives::{b64, x25519_keypair, KeyPair};
use mrenzo_core::ratchet::*;
use mrenzo_core::rng::StreamRng;
use mrenzo_core::session_set::{PeerSessions, SetDecrypt};
use mrenzo_core::x3dh::*;
use serde_json::{json, Map, Value};

struct BobPrekeys {
    spk: KeyPair,
    spk_id: i64,
    spk_sig: [u8; 64],
    opk: KeyPair,
    opk_id: i64,
}

fn bob_prekeys(bob: &Ident) -> BobPrekeys {
    let g = generate_signed_pre_key_v2(&bob.ed_secret, 17, &mut StreamRng::new("v3/bob-spk"));
    let spk = KeyPair {
        public: b64_strict32(&g.pub_key).unwrap(),
        private: b64_strict32(&g.priv_key).unwrap(),
    };
    let spk_sig: [u8; 64] = b64_strict(&g.signature).unwrap().try_into().unwrap();
    let opk = x25519_keypair(&mut StreamRng::new("v3/bob-opk"));
    BobPrekeys { spk, spk_id: 17, spk_sig, opk, opk_id: 118 }
}

fn bundle(p: &BobPrekeys, with_opk: bool) -> BundleV2 {
    BundleV2 { spk_id: p.spk_id, spk_pub: p.spk.public, spk_sig: p.spk_sig, opk: with_opk.then_some((p.opk_id, p.opk.public)) }
}

fn secret_json(s: &X3dhV2Secret) -> Value {
    json!({"skB64": b64(&s.sk), "adB64": b64(&s.ad), "sidB64": b64(&s.sid), "rk0B64": b64(&s.rk0)})
}

fn header_json(h: &PrekeyHeader) -> Value {
    let mut o = json!({"ik": b64(&h.ik), "ed": b64(&h.ed), "ek": b64(&h.ek), "spk": h.spk});
    if let Some(opk) = h.opk {
        o["opk"] = json!(opk);
    }
    o
}

#[test]
fn x3dh_v2_vectors() {
    let (a, b) = (alice(), bob());
    let p = bob_prekeys(&b);
    let mut cases = Map::new();
    for (name, with_opk, label) in [("withOpk", true, "v3/x3dh-ek-1"), ("withoutOpk", false, "v3/x3dh-ek-2")] {
        let init = x3dh_v2_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &bundle(&p, with_opk), &mut StreamRng::new(label)).unwrap();
        let resp = x3dh_v2_respond(&b.ik, &b.ed_pub, &p.spk, with_opk.then_some(&p.opk.private), &init.header, &a.ik.public, &a.ed_pub).unwrap();
        assert_eq!(resp, init.secret, "{name}: both sides derive SK/AD/sid/RK0");
        assert_eq!(init.secret.ad.len(), 140);
        assert_eq!(&init.secret.ad[..12], b"mrenzo-ad-v3");
        cases.insert(
            name.into(),
            json!({"rngLabel": label, "ekPrivB64": b64(&init.ek.private), "ekPubB64": b64(&init.ek.public),
                   "header": header_json(&init.header), "secret": secret_json(&init.secret)}),
        );
    }
    // Negatives.
    let v1_sig = mrenzo_core::compat::ed25519::tweetnacl_sign_detached(&p.spk.public, &b.ed_secret);
    let v1 = BundleV2 { spk_sig: v1_sig, ..bundle(&p, true) };
    assert_eq!(
        x3dh_v2_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &v1, &mut StreamRng::new("x")).unwrap_err(),
        X3dhV2Error::SpkSignature,
        "an SPK signed without the v2 label is rejected"
    );
    let forged = BundleV2 { spk_pub: carol().ik.public, ..bundle(&p, true) };
    assert_eq!(
        x3dh_v2_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &forged, &mut StreamRng::new("x")).unwrap_err(),
        X3dhV2Error::SpkSignature,
        "a server-substituted SPK does not verify under the pinned ED"
    );
    let zero = BundleV2 { spk_pub: [0u8; 32], spk_sig: sign_spk_v2(&b.ed_secret, &[0u8; 32]), opk: None, spk_id: 1 };
    assert_eq!(
        x3dh_v2_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &zero, &mut StreamRng::new("x")).unwrap_err(),
        X3dhV2Error::LowOrder
    );
    let init = x3dh_v2_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &bundle(&p, true), &mut StreamRng::new("v3/x3dh-ek-1")).unwrap();
    let c = carol();
    assert_eq!(
        x3dh_v2_respond(&b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), &init.header, &c.ik.public, &c.ed_pub).unwrap_err(),
        X3dhV2Error::IdentityMismatch,
        "a header identity that is not the sender's pin is refused before any DH"
    );
    assert_eq!(
        x3dh_v2_respond(&b.ik, &b.ed_pub, &p.spk, None, &init.header, &a.ik.public, &a.ed_pub).unwrap_err(),
        X3dhV2Error::BadKeyId,
        "a header naming an OPK needs its private"
    );

    let mut v = header(
        "x3dhV2",
        &[
            "SPK signature = Ed25519(ED, \"mrenzo-spk-v2\" ‖ raw 32 SPK bytes); a v1 (raw-bytes) signature is rejected.",
            "DH1 = X25519(IK_A, SPK_B), DH2 = X25519(EK_A, IK_B), DH3 = X25519(EK_A, SPK_B), DH4 = X25519(EK_A, OPK_B); any all-zero output aborts.",
            "SK = HKDF-SHA256(0^32, 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], \"mrenzo-x3dh-v2\", 32); sid = HKDF(SK, \"mrenzo-ratchet-session-id-v3\"); RK0 = HKDF(SK, \"mrenzo-ratchet-init-v3\").",
            "AD = \"mrenzo-ad-v3\" ‖ IK_A ‖ ED_A ‖ IK_B ‖ ED_B (initiator first, 140 bytes).",
            "The responder refuses a header whose ik/ed is not the pinned identity of the server-stamped sender, before computing any DH.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert(
        "bobPrekeys".into(),
        json!({"spk": {"rngLabel": "v3/bob-spk", "keyId": 17, "privB64": b64(&p.spk.private), "pubB64": b64(&p.spk.public), "signatureB64": b64(&p.spk_sig)},
               "opk": {"rngLabel": "v3/bob-opk", "keyId": 118, "privB64": b64(&p.opk.private), "pubB64": b64(&p.opk.public)},
               "v1SignatureB64": b64(&v1_sig)}),
    );
    v.insert("cases".into(), Value::Object(cases));
    check_or_write("x3dhV2.json", &Value::Object(v));
}

fn chat(id: &str, body: &str) -> TypedPlaintext {
    TypedPlaintext::Chat { id: id.into(), body: body.into(), reply: None, fwd: None, expire: None, story: None }
}

/// Alice ⇄ Bob, both sides as `PeerSessions` (what the app stores).
struct Pair {
    a: Ident,
    b: Ident,
    p: BobPrekeys,
    sa: PeerSessions,
    sb: PeerSessions,
    steps: Vec<Value>,
}

impl Pair {
    fn new() -> Pair {
        let (a, b) = (alice(), bob());
        let p = bob_prekeys(&b);
        Pair { a, b, p, sa: PeerSessions::default(), sb: PeerSessions::default(), steps: Vec::new() }
    }

    fn state_json(set: &PeerSessions) -> Value {
        serde_json::from_str(&set.live().unwrap().session.to_json()).unwrap()
    }

    fn send(&mut self, from_alice: bool, pt: &TypedPlaintext, label: &str, now: i64) -> String {
        let set = if from_alice { &mut self.sa } else { &mut self.sb };
        let env = set.encrypt(&pt.to_json(), now, &mut StreamRng::new(label)).unwrap();
        let wire = env.to_wire();
        self.steps.push(json!({
            "op": "encrypt", "by": if from_alice { "alice" } else { "bob" }, "rngLabel": label, "nowMs": now,
            "plaintext": pt.to_json(), "wire": wire, "macB64": b64(&env.mac),
            "headerHex": hex::encode(env.header_bytes()),
            "stateAfter": Self::state_json(set),
        }));
        wire
    }

    fn recv(&mut self, by_bob: bool, wire: &str, label: &str, now: i64) -> String {
        let env = Envelope::parse(wire).unwrap();
        let mut r = StreamRng::new(label);
        let out = if by_bob {
            match self.sb.decrypt(&env, now, &mut r) {
                SetDecrypt::NeedsResponder => {
                    let x = env.x.unwrap();
                    let opk = x.opk.map(|_| self.p.opk.private);
                    self.sb
                        .respond_and_decrypt(&env, &self.b.ik, &self.b.ed_pub, &self.p.spk, opk.as_ref(), &self.a.ik.public, &self.a.ed_pub, now, &mut r)
                        .unwrap()
                }
                other => other,
            }
        } else {
            self.sa.decrypt(&env, now, &mut r)
        };
        let SetDecrypt::Opened { plaintext, created, .. } = out else { panic!("{label}: {out:?}") };
        let set = if by_bob { &self.sb } else { &self.sa };
        self.steps.push(json!({
            "op": "decrypt", "by": if by_bob { "bob" } else { "alice" }, "rngLabel": label, "nowMs": now,
            "wire": wire, "plaintext": plaintext, "createdSession": created,
            "stateAfter": Self::state_json(set),
        }));
        plaintext
    }
}

#[test]
fn ratchet_v3_transcript() {
    let mut t = Pair::new();
    let now = T0;
    let sid = t
        .sa
        .initiate(&t.a.ik, &t.a.ed_pub, &t.b.ik.public, &t.b.ed_pub, &bundle(&t.p, true), now, &mut StreamRng::new("v3/x3dh-ek-1"))
        .unwrap();
    let initial = Pair::state_json(&t.sa);

    let a1 = TypedPlaintext::Chat {
        id: "a1".into(),
        body: "Привет 👋".into(),
        reply: Some(Reply { id: "m0".into(), text: "earlier".into(), name: "Bob".into() }),
        fwd: Some("Carol".into()),
        expire: Some(86400),
        story: None,
    };
    let mut file_body = Map::new();
    file_body.insert("fileId".into(), json!("f-123"));
    file_body.insert("key".into(), json!("AAAA"));
    let a2 = TypedPlaintext::File { id: "a2".into(), body: file_body, reply: None, fwd: None, expire: None };
    let w1 = t.send(true, &a1, "v3/t/a1", now + 1);
    let w2 = t.send(true, &a2, "v3/t/a2", now + 2);
    assert!(Envelope::parse(&w1).unwrap().x.is_some() && Envelope::parse(&w2).unwrap().x.is_some(), "x on every initiating message");

    // Bob gets a2 first: it creates the session (skipping n=0), then a1 opens by `ek` + skipped key.
    assert_eq!(t.recv(true, &w2, "v3/t/b-recv-a2", now + 10), a2.to_json());
    assert_eq!(t.sb.live().unwrap().session.skipped.len(), 1);
    assert_eq!(t.recv(true, &w1, "v3/t/b-recv-a1", now + 11), a1.to_json());
    assert_eq!(t.sb.live().unwrap().session.sid, sid, "same session id on both sides");

    let b1 = TypedPlaintext::Edit { id: "b1".into(), edit_of: "m0".into(), body: "fixed".into() };
    let b2 = TypedPlaintext::Hello { id: "b2".into() };
    let w3 = t.send(false, &b1, "v3/t/b1", now + 20);
    let w4 = t.send(false, &b2, "v3/t/b2", now + 21);
    assert!(Envelope::parse(&w3).unwrap().x.is_none(), "the responder never sends x");
    t.recv(false, &w3, "v3/t/a-recv-b1", now + 30);
    assert!(t.sa.live().unwrap().session.x.is_none(), "x dropped after the first inbound message");
    assert_eq!(t.sa.live().unwrap().session.confirmed_at, Some(now + 30));
    t.recv(false, &w4, "v3/t/a-recv-b2", now + 31);

    let a3 = chat("a3", "after the reply");
    let w5 = t.send(true, &a3, "v3/t/a3", now + 40);
    assert!(Envelope::parse(&w5).unwrap().x.is_none());
    t.recv(true, &w5, "v3/t/b-recv-a3", now + 41);

    let mut v = header(
        "ratchetV3",
        &[
            "Envelope {\"v\":3,\"dh\",\"pn\",\"n\",\"ct\",\"mac\"[,\"x\":{\"ik\",\"ed\",\"ek\",\"spk\"[,\"opk\"]}]}; x rides on every message while the initiator's session is initiating.",
            "(k_enc, k_mac) = HKDF-SHA256(0^32, mk, \"mrenzo-ratchet-msg-keys-v3\", 64); ct = nonce ‖ secretbox(typed plaintext, nonce, k_enc).",
            "hdr = 0x03 ‖ dh ‖ BE64(pn) ‖ BE64(n) ‖ xflag ‖ [ik ‖ ed ‖ ek ‖ BE64(spk) ‖ BE64(opk | 2^64-1)]; mac = HMAC-SHA256(k_mac, AD ‖ hdr ‖ ct), checked before the box is opened.",
            "Initiator: root = RK0, my_dh = EK, peer_dh = SPK, (root, send) = KDF_RK(RK0, DH3). Responder: my_dh = SPK, peer_dh = 0; its first decrypt runs the DH step.",
            "Steps replay in order; each records the PRNG label its randomness came from and the full state after it.",
        ],
    );
    v.insert("keys".into(), json!({"alice": t.a.json(), "bob": t.b.json()}));
    v.insert("x3dh".into(), json!({"case": "x3dhV2.json cases.withOpk", "sidB64": b64(&sid), "initiatorState": initial}));
    v.insert("steps".into(), Value::Array(t.steps));
    check_or_write("ratchetV3.json", &Value::Object(v));
}

fn opened(r: SetDecrypt) -> bool {
    matches!(r, SetDecrypt::Opened { .. })
}

#[test]
fn ratchet_v3_negative() {
    let mut t = Pair::new();
    let now = T0;
    t.sa.initiate(&t.a.ik, &t.a.ed_pub, &t.b.ik.public, &t.b.ed_pub, &bundle(&t.p, true), now, &mut StreamRng::new("v3/x3dh-ek-1")).unwrap();
    let w1 = t.send(true, &chat("a1", "one"), "v3/n/a1", now);
    let w2 = t.send(true, &chat("a2", "two"), "v3/n/a2", now);
    t.recv(true, &w1, "v3/n/b1", now);
    let w_reply = t.send(false, &chat("b1", "reply"), "v3/n/b-reply", now);
    t.recv(false, &w_reply, "v3/n/a-reply", now);
    let w3 = t.send(true, &chat("a3", "three"), "v3/n/a3", now);
    let bob_state = t.sb.clone();
    let mut cases: Vec<Value> = Vec::new();
    let mut case = |name: &str, wire: String, expect: &str| {
        cases.push(json!({"name": name, "wire": wire, "expect": expect}));
    };

    // Shape.
    let mut v2: Value = serde_json::from_str(&w3).unwrap();
    v2["v"] = json!(2);
    assert_eq!(Envelope::parse(&v2.to_string()), Err(EnvelopeError::Legacy));
    case("v2", v2.to_string(), "legacy");
    let mut nomac: Value = serde_json::from_str(&w3).unwrap();
    nomac.as_object_mut().unwrap().remove("mac");
    assert_eq!(Envelope::parse(&nomac.to_string()), Err(EnvelopeError::NotEnvelope));
    case("missingMac", nomac.to_string(), "notEnvelope");
    let dup = w3.replacen("{\"v\":3,", "{\"v\":3,\"v\":3,", 1);
    assert_eq!(Envelope::parse(&dup), Err(EnvelopeError::NotEnvelope));
    case("duplicateKey", dup, "notEnvelope");
    let float = w3.replacen("\"n\":", "\"n\":1.0,\"x_n\":", 1);
    assert!(Envelope::parse(&float).is_err());
    let loose_b64 = {
        let mut e: Value = serde_json::from_str(&w3).unwrap();
        let mac = e["mac"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = mac.chars().collect();
        let i = chars.len() - 2;
        const ALPHA: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let v = ALPHA.find(chars[i]).unwrap();
        chars[i] = ALPHA.as_bytes()[v ^ 1] as char; // a non-zero trailing (padding) bit
        e["mac"] = json!(chars.into_iter().collect::<String>());
        e.to_string()
    };
    assert_eq!(Envelope::parse(&loose_b64), Err(EnvelopeError::NotEnvelope), "non-canonical base64");
    case("nonCanonicalBase64", loose_b64, "notEnvelope");

    // Authentication (Bob's state after a1 and his reply).
    let decrypt = |wire: &str| {
        let mut s = bob_state.clone();
        match Envelope::parse(wire) {
            Ok(env) => s.decrypt(&env, now, &mut StreamRng::new("probe")),
            Err(_) => SetDecrypt::Failed,
        }
    };
    let mut stripped: Value = serde_json::from_str(&w2).unwrap();
    stripped.as_object_mut().unwrap().remove("x");
    assert_eq!(decrypt(&stripped.to_string()), SetDecrypt::Failed, "x stripped: the MAC covers xflag");
    case("xStripped", stripped.to_string(), "failed");
    let mut added: Value = serde_json::from_str(&w3).unwrap();
    added["x"] = serde_json::from_str::<Value>(&w1).unwrap()["x"].clone();
    assert_eq!(decrypt(&added.to_string()), SetDecrypt::Failed, "x added by a relay");
    case("xAdded", added.to_string(), "failed");
    let mut flipped: Value = serde_json::from_str(&w3).unwrap();
    flipped["pn"] = json!(flipped["pn"].as_u64().unwrap() + 1);
    assert_eq!(decrypt(&flipped.to_string()), SetDecrypt::Failed, "header byte flipped");
    case("headerFlipped", flipped.to_string(), "failed");
    let mut bitflip: Value = serde_json::from_str(&w3).unwrap();
    let mut ct = b64_strict(bitflip["ct"].as_str().unwrap()).unwrap();
    *ct.last_mut().unwrap() ^= 1;
    bitflip["ct"] = json!(b64(&ct));
    assert_eq!(decrypt(&bitflip.to_string()), SetDecrypt::Failed);
    case("ciphertextFlipped", bitflip.to_string(), "failed");
    assert!(opened(decrypt(&w3)), "the untouched wire opens");
    // Wrong AD: the same keys under another identity binding never open.
    let mut wrong_ad = bob_state.clone();
    wrong_ad.entries[0].session.ad[20] ^= 1;
    assert_eq!(wrong_ad.decrypt(&Envelope::parse(&w3).unwrap(), now, &mut StreamRng::new("probe")), SetDecrypt::Failed);
    // Replay of a delivered position.
    let mut after = bob_state.clone();
    assert!(opened(after.decrypt(&Envelope::parse(&w3).unwrap(), now, &mut StreamRng::new("probe"))));
    assert!(after.is_spent(&Envelope::parse(&w3).unwrap()));
    assert_eq!(after.decrypt(&Envelope::parse(&w3).unwrap(), now, &mut StreamRng::new("probe")), SetDecrypt::Failed, "a replay never opens");
    // A prekey message whose session is gone needs a responder; the host
    // drops it through the `ek` seen-set (init.ekReplayed).
    let mut empty = PeerSessions::default();
    assert_eq!(empty.decrypt(&Envelope::parse(&w1).unwrap(), now, &mut StreamRng::new("probe")), SetDecrypt::NeedsResponder);
    // Wrong SPK private (unknown/rotated-away id handled by the host): the root differs → MAC fails.
    let wrong_spk = x25519_keypair(&mut StreamRng::new("v3/n/wrong-spk"));
    let r = empty
        .respond_and_decrypt(&Envelope::parse(&w1).unwrap(), &t.b.ik, &t.b.ed_pub, &wrong_spk, Some(&t.p.opk.private), &t.a.ik.public, &t.a.ed_pub, now, &mut StreamRng::new("probe"))
        .unwrap();
    assert_eq!(r, SetDecrypt::Failed);
    assert!(empty.entries.is_empty(), "a failed responder decrypt installs nothing");
    // Relabelled sender: Carol's pin for the same frame.
    let c = carol();
    assert_eq!(
        empty
            .respond_and_decrypt(&Envelope::parse(&w1).unwrap(), &t.b.ik, &t.b.ed_pub, &t.p.spk, Some(&t.p.opk.private), &c.ik.public, &c.ed_pub, now, &mut StreamRng::new("probe"))
            .unwrap_err(),
        X3dhV2Error::IdentityMismatch
    );

    // Typed plaintext and the outer-frame agreement.
    let pt = parse_typed_plaintext(&chat("a1", "hi").to_json()).unwrap();
    assert!(outer_matches_p2p(&pt, "a1", None, None));
    assert!(!outer_matches_p2p(&pt, "other", None, None), "outer messageId ≠ inner id");
    assert!(!outer_matches_p2p(&pt, "a1", Some("sender-key-distribution"), None), "action ≠ t");
    let edit = TypedPlaintext::Edit { id: "e1".into(), edit_of: "m9".into(), body: "x".into() };
    assert!(outer_matches_edit(&edit, "m9"));
    assert!(!outer_matches_edit(&edit, "m8"), "an edit re-targeted by the server");
    let hello = TypedPlaintext::Hello { id: "h" .into() };
    assert!(outer_matches_p2p(&hello, "h", Some("session-hello"), None));
    assert!(!outer_matches_p2p(&hello, "h", None, None));
    for bad in [
        r#"{"t":"chat","id":"x"}"#,
        r#"{"t":"chat","id":"","body":"b"}"#,
        r#"{"t":"chat","id":"x","body":1}"#,
        r#"{"t":"edit","id":"x","body":"b"}"#,
        r#"{"t":"edit","id":"x","editOf":"y","body":"b","expire":5}"#,
        r#"{"t":"hello","id":"x","body":"b"}"#,
        r#"{"t":"chat","id":"x","body":"b","expire":0}"#,
        r#"{"t":"chat","id":"x","id":"y","body":"b"}"#,
        r#"{"t":"nope","id":"x"}"#,
    ] {
        assert!(parse_typed_plaintext(bad).is_none(), "{bad}");
    }
    let long_reply = json!({"t":"chat","id":"x","body":"b","reply":{"id":"r","text":"é".repeat(101),"name":"n"}}).to_string();
    assert!(parse_typed_plaintext(&long_reply).is_none(), "reply.text > 100 UTF-16 units");

    let mut v = header(
        "ratchetV3Negative",
        &[
            "Each wire is derived from the ratchetV3-style exchange recorded in this file (keys = x3dhV2.json). expect: legacy = placeholder «отправлено старой версией», not counted; notEnvelope = dropped, not counted; failed = MAC failure under every candidate session (counted).",
            "Also asserted in tests/golden_ratchet_v3.rs: wrong AD, replayed position, missing responder session (NeedsResponder → host seen-set), wrong SPK private, relabelled sender (IdentityMismatch), typed-plaintext and outer/inner agreement rules.",
        ],
    );
    v.insert("bobStateBefore".into(), serde_json::from_str::<Value>(&bob_state.live().unwrap().session.to_json()).unwrap());
    v.insert("cases".into(), Value::Array(cases));
    check_or_write("ratchetV3Negative.json", &Value::Object(v));
}

#[test]
fn skipped_key_cap_and_ttl() {
    let mut t = Pair::new();
    let now = T0;
    t.sa.initiate(&t.a.ik, &t.a.ed_pub, &t.b.ik.public, &t.b.ed_pub, &bundle(&t.p, false), now, &mut StreamRng::new("v3/x3dh-ek-2")).unwrap();
    let mut r = StreamRng::new("v3/cap/sender");
    let mut wires = Vec::new();
    for i in 0..2005 {
        wires.push(t.sa.encrypt(&chat(&format!("m{i}"), "x").to_json(), now, &mut r).unwrap().to_wire());
    }
    let mut rr = StreamRng::new("v3/cap/receiver");
    let mut counts = Vec::new();
    for (k, n) in [1000usize, 2000, 2002, 2004].into_iter().enumerate() {
        let env = Envelope::parse(&wires[n]).unwrap();
        let out = match t.sb.decrypt(&env, now + k as i64, &mut rr) {
            SetDecrypt::NeedsResponder => t
                .sb
                .respond_and_decrypt(&env, &t.b.ik, &t.b.ed_pub, &t.p.spk, None, &t.a.ik.public, &t.a.ed_pub, now, &mut rr)
                .unwrap(),
            other => other,
        };
        assert!(opened(out), "n={n}");
        counts.push(t.sb.live().unwrap().session.skipped.len());
    }
    assert_eq!(counts, vec![1000, 1999, 2000, MAX_SKIPPED_TOTAL]);
    let skipped = &t.sb.live().unwrap().session.skipped;
    assert_eq!(skipped[0].n, 1, "the oldest (n = 0) was evicted");
    // Over the per-message bound: not counted, nothing stored.
    let mut far = t.sb.clone();
    let mut big = Envelope::parse(&wires[2004]).unwrap();
    big.n += 5000;
    assert_eq!(far.decrypt(&big, now, &mut rr), SetDecrypt::TooManySkipped);
    // TTL: 14 days later every skipped key is gone on load.
    let json = t.sb.live().unwrap().session.to_json();
    let aged = Session::from_json(&json, now + SKIPPED_TTL_MS + 10).unwrap();
    assert!(aged.skipped.is_empty());
    let fresh = Session::from_json(&json, now + SKIPPED_TTL_MS - 10).unwrap();
    assert_eq!(fresh.skipped.len(), MAX_SKIPPED_TOTAL);
    // A late message still opens with its stored key.
    let env = Envelope::parse(&wires[5]).unwrap();
    assert!(opened(t.sb.decrypt(&env, now + 10, &mut rr)));

    let mut v = header(
        "skippedCap",
        &[
            "At most 1000 skipped keys per message, 2000 per session (oldest evicted first), and none older than 14 days (dropped on load and save).",
            "Alice sends m0…m2004 (x3dhV2 withoutOpk); Bob receives n = 1000, 2000, 2002, 2004 in that order.",
        ],
    );
    v.insert("receiveOrder".into(), json!([1000, 2000, 2002, 2004]));
    v.insert("skippedAfterEach".into(), json!(counts));
    v.insert("firstRemainingN".into(), json!(1));
    v.insert("maxSkippedTotal".into(), json!(MAX_SKIPPED_TOTAL));
    v.insert("maxSkipPerMessage".into(), json!(MAX_SKIP_PER_MESSAGE));
    v.insert("ttlMs".into(), json!(SKIPPED_TTL_MS));
    check_or_write("skippedCap.json", &Value::Object(v));
}

#[test]
fn state_json_round_trip_is_strict() {
    let mut t = Pair::new();
    t.sa.initiate(&t.a.ik, &t.a.ed_pub, &t.b.ik.public, &t.b.ed_pub, &bundle(&t.p, true), T0, &mut StreamRng::new("v3/x3dh-ek-1")).unwrap();
    let s = &t.sa.live().unwrap().session;
    let json = s.to_json();
    assert_eq!(&Session::from_json(&json, T0).unwrap(), s);
    let mut v: Value = serde_json::from_str(&json).unwrap();
    v["extra"] = json!(1);
    assert!(Session::from_json(&v.to_string(), T0).is_none(), "unknown keys are rejected at rest");
    let mut v: Value = serde_json::from_str(&json).unwrap();
    v["v"] = json!(2);
    assert!(Session::from_json(&v.to_string(), T0).is_none());
    assert!(!json.contains(&b64(&t.a.ik.private)), "no identity private key in a session blob");
}
