//! The mesh at wire level 2 (wire-1.1 §W8): meshV11.json (the strict frame
//! check and every rejection, the seen key, the forward rule, named kinds,
//! `ptt` and `ctl` frames, the blind ACK and its forgery, the link hello) and
//! meshCourierV1.json (the courier capsule). The 1.0.0 frames of meshV2.json
//! are verified unchanged by tests/golden_protocol_v3.rs — and re-checked
//! here against the strict rules.

mod common;

use common::*;
use mrenzo_core::mesh_envelope::{build_mesh_ack, build_mesh_envelope_from_ratchet, encode_inner_blob, pack_mesh_outer_json, MeshEnvelope, MeshError, MeshIdentity, MeshMode};
use mrenzo_core::mesh_v11::*;
use mrenzo_core::primitives::{b64, ed25519_sign, sha256, x25519_keypair};
use mrenzo_core::ptt;
use mrenzo_core::ratchet::{mesh_ack_payload, mesh_ack_seed};
use mrenzo_core::rng::StreamRng;
use serde_json::{json, Value};

const NOW: i64 = T0;

fn identity(i: &Ident) -> MeshIdentity {
    MeshIdentity { from_uid: i.uid, sign_priv_b64: b64(&i.ed_secret), sign_pub_b64: b64(&i.ed_pub) }
}

/// A 1.0.0-built `msg` (what every client still sends).
fn legacy_msg(a: &Ident, b: &Ident, id: &str, mode: MeshMode, label: &str) -> MeshEnvelope {
    let wire = r#"{"v":3,"dh":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pn":0,"n":0,"ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
    build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), wire, mode, &identity(a), Some(id), NOW, &mut StreamRng::new(label)).unwrap().unwrap()
}

/// A frame assembled field by field, so that every non-canonical variant can be made.
#[derive(Clone)]
struct Raw {
    id: String,
    ts: u64,
    ttl: u64,
    hops: u64,
    l: Option<u64>,
    mode: &'static str,
    flags: u8,
    uid: u64,
    to_idx: Option<[u8; 8]>,
    payload: Vec<u8>,
    /// The kind string put into the signed binding.
    kind: String,
    /// ACK: the payload as text; otherwise base64 of the payload.
    text_payload: bool,
    trailing: Vec<u8>,
    /// Extra outer JSON (starting with a comma), verbatim.
    extra: String,
}

impl Raw {
    fn named(name: &str, body: &[u8], uid: u64, to_idx: Option<[u8; 8]>, id: &str, ttl: u64, l: Option<u64>) -> Raw {
        let payload = [&[name.len() as u8][..], name.as_bytes(), body].concat();
        Raw { id: id.into(), ts: NOW as u64, ttl, hops: 0, l, mode: "realtime", flags: if to_idx.is_some() { 0x82 } else { 0x80 }, uid, to_idx, payload, kind: name.into(), text_payload: false, trailing: vec![], extra: String::new() }
    }

    fn msg(uid: u64, id: &str) -> Raw {
        Raw { id: id.into(), ts: NOW as u64, ttl: 7, hops: 0, l: Some(4), mode: "realtime", flags: 0x03, uid, to_idx: Some([7; 8]), payload: vec![0xaa; 256], kind: "msg".into(), text_payload: false, trailing: vec![], extra: String::new() }
    }

    fn ack(uid: u64, payload: &str) -> Raw {
        Raw { id: "ack-id".into(), ts: NOW as u64, ttl: 4, hops: 0, l: None, mode: "realtime", flags: 0x08, uid, to_idx: None, payload: payload.as_bytes().to_vec(), kind: "ack".into(), text_payload: true, trailing: vec![], extra: String::new() }
    }

    fn inner(&self, secret: &[u8; 64]) -> Vec<u8> {
        let mode = if self.mode == "pigeon" { MeshMode::Pigeon } else { MeshMode::Realtime };
        let text = if self.text_payload { String::from_utf8_lossy(&self.payload).into_owned() } else { b64(&self.payload) };
        let signed = binding(&self.id, self.ts, self.uid, self.to_idx.as_ref(), self.ttl, self.l, mode, &self.kind, &text);
        let mut blob = vec![self.flags];
        blob.extend_from_slice(&secret[32..]);
        blob.extend_from_slice(&self.uid.to_be_bytes());
        if let Some(t) = &self.to_idx {
            blob.extend_from_slice(t);
        }
        blob.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        blob.extend_from_slice(&self.payload);
        blob.extend_from_slice(&ed25519_sign(secret, signed.as_bytes()));
        blob.extend_from_slice(&self.trailing);
        blob
    }

    fn json(&self, secret: &[u8; 64]) -> String {
        self.json_with_b(&b64(&self.inner(secret)))
    }

    fn json_with_b(&self, b: &str) -> String {
        let l = self.l.map_or(String::new(), |l| format!(",\"L\":{l}"));
        format!("{{\"v\":2,\"id\":{},\"ttl\":{},\"hops\":{}{l},\"mode\":\"{}\",\"ts\":{},\"b\":\"{b}\"{}}}", json!(self.id), self.ttl, self.hops, self.mode, self.ts, self.extra)
    }
}

fn check(json: &str) -> Result<Frame, &'static str> {
    frame_check(json.as_bytes(), NOW)
}

#[test]
fn mesh_v11_vectors() {
    let (a, b, c) = (alice(), bob(), carol());
    let signer = Signer { uid: a.uid as u64, ed_secret64: &a.ed_secret };
    let tag = to_idx_bytes(&a.ik.private, &b.ik.public, NOW as u64);
    assert_eq!(b64(&tag), mrenzo_core::mesh_envelope::compute_to_idx(&b64(&a.ik.private), &b64(&b.ik.public), NOW as f64), "one definition of the recipient tag");

    // ── every kind that is valid ──
    let mut valid: Vec<Value> = Vec::new();
    let mut frames: Vec<(String, String, Frame)> = Vec::new();
    let mut ok = |name: &str, json: String| -> Frame {
        let f = check(&json).unwrap_or_else(|r| panic!("{name}: {r}"));
        valid.push(json!({
            "name": name, "frame": json, "kind": f.kind.label(), "bindingKind": f.kind.binding_kind(), "fromUid": f.from_uid,
            "ttl": f.ttl, "hops": f.hops, "L": f.l, "mode": f.mode.as_str(), "seenKey": f.seen_key, "payloadLen": f.payload.len(),
            "forwarded": forwarded_json(&f),
        }));
        frames.push((name.to_string(), json, f.clone()));
        f
    };
    let msg_rt = legacy_msg(&a, &b, "m-rt", MeshMode::Realtime, "m11/msg-rt");
    let f_msg = ok("msg, realtime — built by the 1.0.0 builder", pack_mesh_outer_json(&msg_rt).unwrap());
    assert_eq!((f_msg.kind.clone(), f_msg.ttl, f_msg.l), (FrameKind::Msg, 7, Some(4)));
    assert!(msg_envelope(&f_msg).unwrap().starts_with("{\"v\":3"));
    assert!(to_idx_matches(&f_msg, &b.ik.private, &a.ik.public), "addressed to Bob under the key of the sender");
    assert!(!to_idx_matches(&f_msg, &c.ik.private, &a.ik.public) && !to_idx_matches(&f_msg, &b.ik.private, &c.ik.public), "sender-bound: not «any key I know»");
    let f_pigeon = ok("msg, pigeon — built by the 1.0.0 builder", pack_mesh_outer_json(&legacy_msg(&a, &b, "m-pg", MeshMode::Pigeon, "m11/msg-pg")).unwrap());
    assert_eq!(f_pigeon.ttl, 86_400);
    let sid = [0x51u8; 32];
    let ack1 = build_mesh_ack(0, &mesh_ack_payload(&sid, "m-rt"), &identity(&b), NOW, &mut StreamRng::new("m11/ack1")).unwrap().unwrap();
    let f_ack = ok("ack, the 1.0.0 form (id.tag, the recipient's uid and key)", pack_mesh_outer_json(&ack1).unwrap());
    assert_eq!(f_ack.kind, FrameKind::Ack);
    let seed = mesh_ack_seed(&sid, "m-rt");
    let ack2 = build_ack2(&seed, "m-rt", NOW as u64, &mut StreamRng::new("m11/ack2")).unwrap();
    let f_ack2 = ok("ack, blind (uid 0, a one-time key, a hash of the id)", ack2.clone());
    assert_eq!((f_ack2.kind.clone(), f_ack2.from_uid), (FrameKind::AckBlind, 0));
    assert_eq!(f_ack2.sig_pub, ack2_public(&seed));
    assert_eq!(f_ack2.payload, ack2_payload("m-rt").as_bytes());
    assert!(ack2_matches(&f_ack2, &ack2_public(&seed), "m-rt"), "the author recognises it");
    assert!(!ack2_matches(&f_ack2, &ack2_public(&seed), "m-other") && !ack2_matches(&f_ack2, &ack2_public(&mesh_ack_seed(&[0x52; 32], "m-rt")), "m-rt"));

    let key = [0x42u8; 32];
    let ptt_id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let chunk0 = ptt::seal_chunk(&key, 0, false, &[vec![1; 60], vec![2; 61]], &mut StreamRng::new("m11/chunk0")).unwrap();
    let chunk_last = ptt::seal_chunk(&key, 1, true, &[vec![3; 20]], &mut StreamRng::new("m11/chunk1")).unwrap();
    let key_wire = r#"{"v":3,"dh":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pn":0,"n":0,"ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
    let ptt0 = build_ptt_frame(signer, &a.ik.private, &b.ik.public, ptt_id, 0, false, Some(key_wire), &chunk0, NOW as u64).unwrap();
    let f_ptt = ok("ptt, segment 0 with the key envelope", ptt0.clone());
    assert_eq!((f_ptt.kind.clone(), f_ptt.ttl, f_ptt.l, f_ptt.id.as_str()), (FrameKind::Ptt, 0, None, "0f8fad5b-d9cb-469f-a165-70867728950e.0"));
    let seg = ptt_parse(&f_ptt).unwrap();
    assert_eq!((seg.ptt_id.as_str(), seg.seq, seg.last, seg.key_wire.as_deref(), &seg.chunk), (ptt_id, 0, false, Some(key_wire), &chunk0));
    assert!(to_idx_matches(&f_ptt, &b.ik.private, &a.ik.public));
    assert_eq!(forwarded_json(&f_ptt), None, "signed ttl 0: never relayed");
    let ptt1 = build_ptt_frame(signer, &a.ik.private, &b.ik.public, ptt_id, 1, true, None, &chunk_last, NOW as u64).unwrap();
    let f_ptt1 = ok("ptt, the last segment, no key", ptt1);
    let seg1 = ptt_parse(&f_ptt1).unwrap();
    assert!(seg1.last && seg1.key_wire.is_none() && seg1.seq == 1);
    assert_eq!(ptt::open_chunk(&key, &seg1.chunk).unwrap().last, seg1.last, "the body's LAST bit is a copy of the chunk's");

    let ctl = build_ctl_frame(signer, &a.ik.private, &b.ik.public, "nb-7", key_wire, 1, NOW as u64).unwrap();
    let f_ctl = ok("ctl (a control envelope for a peer reachable only by radio), ttl 1", ctl);
    assert_eq!(f_ctl.kind, FrameKind::Ctl);
    assert_eq!(ctl_parse(&f_ctl).as_deref(), Some(key_wire));
    let fwd = check(&forwarded_json(&f_ctl).unwrap()).unwrap();
    assert_eq!((fwd.hops, forwarded_json(&fwd)), (1, None), "relayed once");

    let unknown = build_named_frame("poll9", b"hello from the future", signer, None, "u-1", 7, Some(4), NOW as u64).unwrap();
    let f_unknown = ok("a named frame of a name this build does not know (verified, relayed within bounds, never acted on)", unknown);
    assert_eq!(f_unknown.kind, FrameKind::Named("poll9".into()));
    assert_eq!(f_unknown.body(), b"hello from the future");
    assert!(ptt_parse(&f_unknown).is_none() && ctl_parse(&f_unknown).is_none() && msg_envelope(&f_unknown).is_none());
    let unknown_no_l = build_named_frame("poll9", b"x", signer, Some(tag), "u-2", 7, None, NOW as u64).unwrap();
    let f_no_l = ok("an unknown name without L: valid, NOT relayed", unknown_no_l);
    assert_eq!(forwarded_json(&f_no_l), None);
    let big = build_named_frame("poll9", &vec![0u8; 2048], signer, None, "u-3", 7, Some(4), NOW as u64).unwrap();
    let f_big = ok("an unknown name over 2048 payload bytes: valid, NOT relayed", big);
    assert_eq!(forwarded_json(&f_big), None);

    // ── the seen key is the signed content, not the id ──
    let relayed_by_353 = {
        // What a 1.0.0 radio re-emits: ttl − 1, hops + 1, L halved (the same inner blob).
        let mut v: Value = serde_json::from_str(&frames[0].1).unwrap();
        v["ttl"] = json!(6);
        v["hops"] = json!(1);
        v["L"] = json!(2);
        v.to_string()
    };
    assert_eq!(check(&relayed_by_353), Err("signature"), "a 1.0.0 relay breaks the copy");
    assert_eq!(frame_peek(relayed_by_353.as_bytes()).unwrap().seen_key, f_msg.seen_key, "…and it has the SAME seen key: it must not be recorded, or it would suppress the valid frame");
    let squatter = Raw { to_idx: Some(tag), ..Raw::msg(c.uid as u64, "m-rt") }.json(&c.ed_secret);
    let f_squat = check(&squatter).expect("a self-signed frame that reuses the id is a valid frame of its own");
    assert_ne!(f_squat.seen_key, f_msg.seen_key, "another key: reusing an id suppresses nothing");
    assert_eq!(frame_peek(frames[0].1.as_bytes()), Some(Peek { seen_key: f_msg.seen_key.clone(), claims_ptt: false, carries_capsule: false, hops: Some(0) }));
    assert!(frame_peek(ptt0.as_bytes()).unwrap().claims_ptt);
    assert_eq!(f_msg.seen_key, b64(&sha256(&mrenzo_core::strict_json::b64(&f_msg.b).unwrap())[..16]));

    // ── forward rule ──
    let table: Vec<Value> = [
        (7u64, 0u64, Some(4u64), Some(1u64), "msg: forwarded by the node that receives hops 0"),
        (7, 1, Some(4), Some(2), "…and hops 1"),
        (7, 2, Some(4), None, "…not hops 2: floor(4 / 8) = 0 (3 hops in all)"),
        (7, 0, Some(1), None, "L = 1 is never re-emitted"),
        (7, 0, Some(2), Some(1), "L = 2: one relay"),
        (7, 1, Some(2), None, ""),
        (4, 0, None, Some(1), "ack: forwarded at hops 0..3"),
        (4, 3, None, Some(4), ""),
        (4, 4, None, None, "hops reached ttl"),
        (0, 0, None, None, "ttl 0 (ptt) is never re-emitted"),
        (1, 0, None, Some(1), "ctl with ttl 1: one relay"),
        (1, 1, None, None, ""),
        (86_400, 1, Some(4), Some(2), "pigeon: the signed seconds are never touched; L bounds the radio reach"),
        (86_400, 2, Some(4), None, ""),
        (86_400, 16, None, Some(17), "hops 16 is the largest count the check accepts"),
        (86_400, 500, Some(4), None, "a shift past the word size is 0, not a wrap"),
        (u64::MAX, u64::MAX, None, None, "no overflow at the limit"),
    ]
    .iter()
    .map(|(ttl, hops, l, want, note)| {
        assert_eq!(forward_hops(*ttl, *hops, *l), *want, "ttl {ttl} hops {hops} L {l:?}");
        json!({"ttl": ttl, "hops": hops, "L": l, "forwardedHops": want, "note": note})
    })
    .collect();
    // A relayed copy verifies at every hop, and only `hops` changed.
    let mut relay_chain: Vec<Value> = Vec::new();
    for (name, reach) in [(0usize, 2usize), (2, 4)] {
        let (label, json, frame) = &frames[name];
        let (mut current, mut current_json, mut relays) = (frame.clone(), json.clone(), 0);
        while let Some(next) = forwarded_json(&current) {
            relays += 1;
            let f = check(&next).unwrap_or_else(|r| panic!("{label} after relay {relays}: {r}"));
            assert_eq!((f.hops, f.ttl, f.l, &f.b, &f.seen_key), (relays as u64, frame.ttl, frame.l, &frame.b, &frame.seen_key));
            relay_chain.push(json!({"of": label, "relay": relays, "frame": next}));
            current = f;
            current_json = next;
        }
        assert_eq!(relays, reach, "{label}");
        let _ = current_json;
    }
    // The forwarded frame is rebuilt: unsigned ballast and a mangled `c` do not travel.
    let ballast = frames[0].1.replacen("{\"v\":2,", &format!("{{\"v\":2,\"junk\":\"{}\",\"c\":7,", "x".repeat(4000)), 1);
    let f_ballast = check(&ballast).expect("unknown outer keys do not invalidate a frame");
    assert_eq!(f_ballast.courier, None, "a `c` that is not well formed is absent");
    assert_eq!(forwarded_json(&f_ballast), forwarded_json(&f_msg), "…and the relayed copy is the canonical one");
    assert!(forwarded_json(&f_msg).unwrap().len() < frames[0].1.len() + 8);

    // ── rejections, in the order of the check ──
    let s = &a.ed_secret;
    let good = Raw { to_idx: Some(tag), ..Raw::msg(a.uid as u64, "m-neg") };
    assert!(check(&good.json(s)).is_ok());
    let good_b = b64(&good.inner(s));
    let outer = |patch: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut v: Value = serde_json::from_str(&good.json(s)).unwrap();
        patch(v.as_object_mut().unwrap());
        v.to_string()
    };
    let named = |name: &str, body: &[u8], ttl: u64, l: Option<u64>, to: bool| Raw::named(name, body, a.uid as u64, to.then_some(tag), "n-1", ttl, l);
    let s_plus_l = {
        // The same signature with S + L: tweetnacl (1.0.0) verifies it, strict Ed25519 does not.
        let mut blob = good.inner(s);
        let n = blob.len();
        const L: [u8; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = blob[n - 32 + i] as u16 + L[i] as u16 + carry;
            blob[n - 32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S + L fits 32 bytes");
        good.json_with_b(&b64(&blob))
    };
    assert!(mrenzo_core::mesh_envelope::verify_mesh_envelope(&mrenzo_core::mesh_envelope::unpack_mesh_outer(&serde_json::from_str(&s_plus_l).unwrap()).unwrap().unwrap()), "the 1.0.0 verifier accepts the re-encoded S");
    let loose_b64 = {
        // Flip a trailing (padding) bit of the last base64 quantum: same bytes, another text.
        let mut chars: Vec<char> = good_b.chars().collect();
        let pad = chars.iter().rev().take_while(|c| **c == '=').count();
        assert!(pad > 0, "the sample blob ends in padding");
        const ALPHA: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let i = chars.len() - pad - 1;
        chars[i] = ALPHA.as_bytes()[ALPHA.find(chars[i]).unwrap() ^ 1] as char;
        good.json_with_b(&chars.into_iter().collect::<String>())
    };
    let cases: Vec<(&str, &str, String)> = vec![
        // 1
        ("not JSON", "json", "mesh".into()),
        ("a JSON array", "json", "[1,2]".into()),
        ("a duplicate top-level key", "json", good.json(s).replacen("\"ttl\":7", "\"ttl\":7,\"ttl\":7", 1)),
        ("a duplicate key inside an unknown outer value", "json", good.json(s).replacen("{\"v\":2,", "{\"v\":2,\"x\":{\"a\":1,\"a\":2},", 1)),
        // 2
        ("v 1", "v", outer(&|o| { o.insert("v".into(), json!(1)); })),
        ("v as a string", "v", outer(&|o| { o.insert("v".into(), json!("2")); })),
        ("v 2.0", "v", good.json(s).replacen("{\"v\":2,", "{\"v\":2.0,", 1)),
        ("no v", "v", outer(&|o| { o.remove("v"); })),
        ("an empty id", "id", outer(&|o| { o.insert("id".into(), json!("")); })),
        ("an id of 129 bytes", "id", outer(&|o| { o.insert("id".into(), json!("i".repeat(129))); })),
        ("an id containing the binding separator", "id", outer(&|o| { o.insert("id".into(), json!("a|b")); })),
        ("an id with a control character", "id", outer(&|o| { o.insert("id".into(), json!("a\u{0}b")); })),
        ("an id with a line break", "id", outer(&|o| { o.insert("id".into(), json!("a\nb")); })),
        ("an id that is not a string", "id", outer(&|o| { o.insert("id".into(), json!(5)); })),
        ("ttl 7.0", "number", good.json(s).replacen("\"ttl\":7", "\"ttl\":7.0", 1)),
        ("ttl 7e0", "number", good.json(s).replacen("\"ttl\":7", "\"ttl\":7e0", 1)),
        ("ttl as a string", "number", outer(&|o| { o.insert("ttl".into(), json!("7")); })),
        ("hops -1", "number", outer(&|o| { o.insert("hops".into(), json!(-1)); })),
        ("hops 0.5 (1.0.0 reads it as 0 after its own cast)", "number", outer(&|o| { o.insert("hops".into(), json!(0.5)); })),
        ("ts 2^53", "number", outer(&|o| { o.insert("ts".into(), json!(9007199254740992u64)); })),
        ("L 4.5", "number", outer(&|o| { o.insert("L".into(), json!(4.5)); })),
        ("no ts", "number", outer(&|o| { o.remove("ts"); })),
        ("hops 17", "hops", outer(&|o| { o.insert("hops".into(), json!(17)); })),
        ("mode in another case (1.0.0 reads it as realtime)", "mode", outer(&|o| { o.insert("mode".into(), json!("Realtime")); })),
        ("no mode", "mode", outer(&|o| { o.remove("mode"); })),
        // 3
        ("b with non-canonical trailing bits", "b64", loose_b64),
        ("b not base64", "b64", good.json_with_b("@@@@")),
        ("no b", "b64", outer(&|o| { o.remove("b"); })),
        ("an inner blob shorter than its fields", "blob", good.json_with_b(&b64(&good.inner(s)[..60]))),
        ("a byte after the signature (1.0.0 ignores it)", "blob", Raw { trailing: vec![0], ..good.clone() }.json(s)),
        ("an empty inner blob", "blob", good.json_with_b("")),
        ("flags 0x01 (padded, no toIdx)", "flags", Raw { flags: 0x01, to_idx: None, ..good.clone() }.json(s)),
        ("flags 0x02 (not padded: 1.0.0 would hand the payload to its pipeline unpadded)", "flags", Raw { flags: 0x02, ..good.clone() }.json(s)),
        ("flags 0x0b (ack with padding and toIdx)", "flags", Raw { flags: 0x0b, ..good.clone() }.json(s)),
        ("flags 0x83 (a named frame with the padded bit)", "flags", Raw { flags: 0x83, ..named("poll9", b"x", 7, None, true) }.json(s)),
        ("flags 0x07 (a recipient uid in clear: the pre-349 wire)", "flags", Raw { flags: 0x07, ..good.clone() }.json(s)),
        ("uid 0 on a msg", "from", Raw { uid: 0, ..good.clone() }.json(s)),
        ("uid 2^53 on a msg", "from", Raw { uid: 1 << 53, ..good.clone() }.json(s)),
        ("uid 0 on a named frame", "from", Raw { uid: 0, ..named("poll9", b"x", 7, None, true) }.json(s)),
        ("uid 2^53 on an ack", "from", Raw::ack(1 << 53, "m.tag").json(s)),
        // 4
        ("msg, realtime, ttl 8", "profile", Raw { ttl: 8, ..good.clone() }.json(s)),
        ("msg, pigeon, ttl 0", "profile", Raw { ttl: 0, mode: "pigeon", ..good.clone() }.json(s)),
        ("msg, pigeon, ttl 86401", "profile", Raw { ttl: 86_401, mode: "pigeon", ..good.clone() }.json(s)),
        ("msg without L", "profile", Raw { l: None, ..good.clone() }.json(s)),
        ("msg with L 0", "profile", Raw { l: Some(0), ..good.clone() }.json(s)),
        ("msg with L 5", "profile", Raw { l: Some(5), ..good.clone() }.json(s)),
        ("msg with an empty payload", "profile", Raw { payload: vec![], ..good.clone() }.json(s)),
        ("ack with L", "profile", Raw { l: Some(4), ..Raw::ack(b.uid as u64, "m.tag") }.json(&b.ed_secret)),
        ("ack with ttl 5", "profile", Raw { ttl: 5, ..Raw::ack(b.uid as u64, "m.tag") }.json(&b.ed_secret)),
        ("ack in pigeon mode", "profile", Raw { mode: "pigeon", ttl: 4, ..Raw::ack(b.uid as u64, "m.tag") }.json(&b.ed_secret)),
        ("ack with an empty payload", "profile", Raw::ack(b.uid as u64, "").json(&b.ed_secret)),
        ("ack whose payload is not UTF-8", "profile", Raw { payload: vec![0xff, 0xfe], ..Raw::ack(b.uid as u64, "") }.json(&b.ed_secret)),
        ("blind ack whose payload is not 24 base64 characters", "profile", Raw::ack(0, "m-rt.tagtagtagtagtagx").json(&b.ed_secret)),
        ("ptt with ttl 1", "profile", named("ptt", &[1; 300], 1, None, true).json(s)),
        ("ptt with L", "profile", named("ptt", &[1; 300], 0, Some(4), true).json(s)),
        ("ptt without toIdx", "profile", named("ptt", &[1; 300], 0, None, false).json(s)),
        ("ptt with an empty body", "profile", named("ptt", &[], 0, None, true).json(s)),
        ("ptt with a body over 16 384 bytes", "profile", named("ptt", &vec![1; 16_385], 0, None, true).json(s)),
        ("ctl with ttl 2", "profile", named("ctl", b"{}", 2, None, true).json(s)),
        ("ctl with a body over 8192 bytes", "profile", named("ctl", &vec![b'x'; 8193], 0, None, true).json(s)),
        ("a named frame in pigeon mode", "profile", Raw { mode: "pigeon", ..named("poll9", b"x", 7, Some(4), false) }.json(s)),
        ("an unknown name with ttl 8", "profile", named("poll9", b"x", 8, None, false).json(s)),
        ("an unknown name with L 5", "profile", named("poll9", b"x", 7, Some(5), false).json(s)),
        ("a name of length 0", "name", Raw { payload: vec![0, b'x'], ..named("poll9", b"", 7, None, false) }.json(s)),
        ("a name of 9 characters", "name", named("abcdefghi", b"x", 7, None, false).json(s)),
        ("a name in upper case", "name", named("Poll", b"x", 7, None, false).json(s)),
        ("a name length past the payload", "name", Raw { payload: vec![5, b'a', b'b'], ..named("poll9", b"", 7, None, false) }.json(s)),
        ("the reserved name msg (1.0.0 would VERIFY this frame)", "name", named("msg", b"x", 7, Some(4), true).json(s)),
        ("the reserved name ack", "name", named("ack", b"x", 4, None, false).json(s)),
        // 5
        ("ttl rewritten by a 1.0.0 relay (ttl − 1, hops + 1, L / 2)", "signature", relayed_by_353.clone()),
        ("L changed", "signature", outer(&|o| { o.insert("L".into(), json!(3)); })),
        ("ts changed", "signature", outer(&|o| { o.insert("ts".into(), json!(NOW + 1)); })),
        ("the id changed", "signature", outer(&|o| { o.insert("id".into(), json!("m-other")); })),
        ("mode changed to pigeon", "signature", outer(&|o| { o.insert("mode".into(), json!("pigeon")); })),
        ("a payload byte flipped", "signature", { let mut blob = good.inner(s); blob[60] ^= 1; good.json_with_b(&b64(&blob)) }),
        ("a msg payload signed as kind ack", "signature", Raw { kind: "ack".into(), ..good.clone() }.json(s)),
        ("a named frame signed with the 1.0.0 kind string", "signature", Raw { kind: "msg".into(), ..named("poll9", b"x", 7, Some(4), true) }.json(s)),
        ("S + L: the signature 1.0.0 accepts and strict Ed25519 refuses", "signature", s_plus_l),
        // 6
        ("older than 25 h", "window", Raw { ts: (NOW - REPLAY_PAST_MS - 1) as u64, ..good.clone() }.json(s)),
        ("more than 5 min ahead", "window", Raw { ts: (NOW + REPLAY_FUTURE_MS + 1) as u64, ..good.clone() }.json(s)),
    ];
    let mut rejected: Vec<Value> = Vec::new();
    for (name, want, frame) in &cases {
        assert_eq!(check(frame).err(), Some(*want), "{name}");
        rejected.push(json!({"name": name, "reason": want, "frame": frame}));
    }
    // Bytes that are not a JSON text at all, and the size cap.
    assert_eq!(frame_check(&[0xff, 0xfe, b'{'], NOW).err(), Some("utf8"));
    let oversize = good.json(s).replacen("{\"v\":2,", &format!("{{\"v\":2,\"x\":\"{}\",", "y".repeat(MAX_FRAME_BYTES)), 1);
    assert_eq!(check(&oversize).err(), Some("size"));
    // The window is inclusive at both ends.
    assert!(check(&Raw { ts: (NOW - REPLAY_PAST_MS) as u64, ..good.clone() }.json(s)).is_ok());
    assert!(check(&Raw { ts: (NOW + REPLAY_FUTURE_MS) as u64, ..good.clone() }.json(s)).is_ok());
    assert!(frame_check(good.json(s).as_bytes(), i64::MAX).is_err() && frame_check(good.json(s).as_bytes(), i64::MIN).is_err(), "no overflow at the extremes of the clock");
    // `hops` is the one unsigned field: changing it does not invalidate the frame.
    assert_eq!(check(&outer(&|o| { o.insert("hops".into(), json!(16)); })).unwrap().hops, 16);
    // Send-side guard: a payload that does not fit the u16 length is an error, not a wrapped length.
    let huge = "x".repeat(63_485);
    assert_eq!(
        build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), &huge, MeshMode::Realtime, &identity(&a), Some("big"), NOW, &mut StreamRng::new("x")).unwrap_err(),
        MeshError::PayloadTooLarge
    );
    let fits = "x".repeat(63_484);
    let big_env = build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), &fits, MeshMode::Realtime, &identity(&a), Some("big"), NOW, &mut StreamRng::new("m11/big")).unwrap().unwrap();
    assert_eq!(msg_envelope(&check(&pack_mesh_outer_json(&big_env).unwrap()).unwrap()).unwrap().len(), 63_484, "the largest message that fits: 63 488 padded bytes");
    assert_eq!(build_named_frame("poll9", &vec![0u8; 65_530], signer, None, "x", 7, None, NOW as u64).unwrap_err(), BuildError::TooLarge);
    assert_eq!(build_named_frame("msg", b"x", signer, None, "x", 7, None, NOW as u64).unwrap_err(), BuildError::Name);
    assert_eq!(build_ptt_frame(signer, &a.ik.private, &b.ik.public, "not-a-uuid", 0, false, None, &chunk0, NOW as u64).unwrap_err(), BuildError::Id);

    // ── a forged blind ACK: valid for everyone, recognisable only by the author ──
    let forged = {
        // Anyone in range knows the id (it is in clear in the message frame): a made-up key, the same payload.
        let (secret, _) = mrenzo_core::primitives::ed25519_keypair_from_seed(&[0x99; 32]);
        let payload = ack2_payload("m-rt");
        Raw { id: "forged-ack".into(), ..Raw::ack(0, &payload) }.json(&secret)
    };
    let f_forged = check(&forged).expect("a forged blind ACK passes the frame check — nothing but the author's key comparison tells it apart");
    assert_eq!((f_forged.kind.clone(), &f_forged.payload), (FrameKind::AckBlind, &f_ack2.payload));
    assert!(!ack2_matches(&f_forged, &ack2_public(&seed), "m-rt"), "the author is not fooled");

    // ── link hello ──
    let hello = json!({
        "ble": link_hello_json(Some("A1B2C3D4")), "mpc": link_hello_json(None),
        "parsed": [
            {"frame": r#"{"hello":1,"name":"A1B2C3D4","w":2}"#, "w": link_hello_parse(br#"{"hello":1,"name":"A1B2C3D4","w":2}"#).unwrap().w},
            {"frame": r#"{"hello":1,"name":"A1B2C3D4"}"#, "w": link_hello_parse(br#"{"hello":1,"name":"A1B2C3D4"}"#).unwrap().w, "note": "a 1.0.0 node: no named frame is written to this link"},
            {"frame": r#"{"hello":1,"w":3}"#, "w": link_hello_parse(br#"{"hello":1,"w":3}"#).unwrap().w},
        ],
    });
    assert_eq!(hello["parsed"][1]["w"], 1);

    let mut v = header_v11(
        "meshV11",
        &[
            "Outer frame and inner blob as in meshV2.json: {\"v\":2,\"id\",\"ttl\",\"hops\"[,\"L\"],\"mode\",\"ts\",\"b\"[,\"c\"]}; b = base64(flags ‖ sig_pub[32] ‖ from u64 ‖ [toIdx 8] ‖ len u16 ‖ payload ‖ sig[64]). binding = \"mrenzo-mesh-v2|\" + id|ts|from.uid|0|(toIdx or -)|ttl|(L or -)|mode|kind|payload; payload in the binding = the ACK text, else base64 of every payload byte.",
            "Strict check, in this order (`reason`): size (> 131 072 B) · utf8 · json (not an object, a duplicate key at any depth) · v · id (1..128 B, no '|') · number (ttl, hops, ts, L exact integers in [0, 2^53)) · hops (> 16) · mode · b64 (canonical) · blob (short, bytes after sig) · flags (exactly 0x03 msg, 0x08 ack, 0x80 / 0x82 named) · from · name · profile · signature (strict Ed25519 under sig_pub) · window (older than 25 h, more than 5 min ahead).",
            "Profiles: msg flags 0x03, realtime ttl ≤ 7 or pigeon 1..86400, L in 1..4. ack flags 0x08, realtime, ttl ≤ 4, no L; from.uid 0 = the blind form (payload = b64(SHA-256(id)[0..16]), a one-time key). named: payload = BE8(nlen) ‖ name ‖ body, name ^[a-z0-9]{1,8}$, never msg / ack; ptt flags 0x82, ttl 0, no L, body ≤ 16 384; ctl flags 0x82, ttl ≤ 1, no L, body ≤ 8192; any other name realtime, ttl ≤ 7, L absent or 1..4.",
            "seenKey = b64(SHA-256(inner blob)[0..16]) — inserted only for a frame that passed the check. Forward rule: forward iff hops < ttl AND (L absent OR floor(L / 2^(hops+1)) ≥ 1); the forwarded frame is REBUILT with only hops incremented (unknown outer keys dropped, c kept when well formed); a frame of an unknown name is relayed only with L present and ≤ 2048 payload bytes.",
            "Blind ACK key: seed = HKDF-SHA256(0^32, sid, \"mrenzo-mesh-ack-v3|\" + id); the Ed25519 key pair of that seed signs the frame. Only the author (who knows sid) can recognise it: `forgedBlindAck` passes the frame check, so on any other node an ACK never prunes anything.",
            "ptt body = 0x01 ‖ sflags ‖ tx[16] ‖ BE16(seq) ‖ [BE16(wlen) ‖ w] ‖ chunk; sflags bit0 LAST (a copy of the chunk's flag), bit1 HAS_KEY; outer id = <pttId>.<seq>. Keys alice / bob / carol as in x3dhV2.json; now = 1790000000000.",
        ],
    );
    v.insert("nowMs".into(), json!(NOW));
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json(), "carol": c.json()}));
    v.insert("valid".into(), Value::Array(valid));
    v.insert("rejected".into(), Value::Array(rejected));
    v.insert("forwardTable".into(), Value::Array(table));
    v.insert("relayChains".into(), Value::Array(relay_chain));
    v.insert(
        "blindAck".into(),
        json!({"sessionIdB64": b64(&sid), "ackedId": "m-rt", "seedB64": b64(&seed), "publicB64": b64(&ack2_public(&seed)), "payload": ack2_payload("m-rt"), "rngLabel": "m11/ack2", "frame": ack2}),
    );
    v.insert("forgedBlindAck".into(), json!({"frame": forged, "frameCheck": "valid", "authorMatches": false, "rule": "on a node that is not the author an ACK of either form never removes, skips or delays a stored frame"}));
    v.insert("ptt".into(), json!({"pttId": ptt_id, "keyHex": hx(&key), "keyWire": key_wire, "chunk0B64": b64(&chunk0), "chunkLastB64": b64(&chunk_last)}));
    v.insert("linkHello".into(), hello);
    check_or_write("meshV11.json", &Value::Object(v));
}

#[test]
fn mesh_courier_vectors() {
    let (a, b, c) = (alice(), bob(), carol());
    let courier = x25519_keypair(&mut StreamRng::new("courier/server-key"));
    let kid = 1u8;
    let env = legacy_msg(&a, &b, "m-courier", MeshMode::Realtime, "courier/msg");
    let blob = encode_inner_blob(&env).unwrap();
    let capsule = courier_capsule_build(&courier.public, kid, b.uid as u64, &env.id, NOW as u64, a.uid as u64, &a.ed_secret, &blob, &mut StreamRng::new("courier/eph"));
    assert_eq!(capsule.len(), 164, "123 bytes");
    let raw = mrenzo_core::strict_json::b64(&capsule).unwrap();
    assert_eq!((raw.len(), raw[0], raw[1]), (123, 0x01, kid));
    // 0x01 ‖ kid ‖ eph_pub[32] ‖ box[9 + 16] ‖ csig[64]; csig covers `eph_pub ‖ box`.
    let sealed = &raw[2..59];
    let csig_msg = courier_csig_message(&env.id, NOW as u64, a.uid as u64, kid, &blob, sealed);
    assert_eq!(csig_msg, format!("mrenzo-courier-v1|m-courier|{NOW}|1001|1|{}|{}", b64(&sha256(&blob)), b64(&sha256(sealed))));
    assert!(courier_capsule_verifies(&capsule, &env.id, NOW as u64, a.uid as u64, &a.ed_pub, &blob), "anyone can check it: no secret involved");

    let with_c = MeshEnvelope { courier: Some(capsule.clone()), ..env.clone() };
    let frame_json = pack_mesh_outer_json(&with_c).unwrap();
    let without_c = pack_mesh_outer_json(&env).unwrap();
    assert!(frame_json.ends_with(&format!(",\"c\":\"{capsule}\"}}")), "c is the last outer key");
    let frame = frame_check(frame_json.as_bytes(), NOW).unwrap();
    assert_eq!(frame.courier.as_deref(), Some(capsule.as_str()));
    assert_eq!(frame.seen_key, frame_check(without_c.as_bytes(), NOW).unwrap().seen_key, "c is outside the v2 binding and outside the seen key");
    assert_eq!(courier_open(&frame, kid, &courier.private), Some(b.uid as u64));
    assert!(frame_peek(frame_json.as_bytes()).unwrap().carries_capsule && !frame_peek(without_c.as_bytes()).unwrap().carries_capsule);
    // The capsule survives a relay, and the queue JSON keeps it.
    let relayed = frame_check(forwarded_json(&frame).unwrap().as_bytes(), NOW).unwrap();
    assert_eq!(courier_open(&relayed, kid, &courier.private), Some(b.uid as u64));
    let queued = MeshEnvelope::from_value(&serde_json::from_str(&with_c.to_json()).unwrap()).unwrap();
    assert_eq!(queued.courier.as_deref(), Some(capsule.as_str()));
    // What the server routes.
    let envelope = msg_envelope(&frame).unwrap();
    let routed = courier_routed_json(b.uid as u64, &env.id, &envelope);
    let routed_v: Value = serde_json::from_str(&routed).unwrap();
    assert_eq!(routed_v, json!({"toUserId": 1002, "messageId": "m-courier", "text": envelope, "encrypted": true, "transport": "mesh-courier"}));
    assert!(routed_v.get("type").is_none() && routed_v.get("action").is_none());

    // Negatives. Two different questions: does a RELAY keep the capsule (the frame itself stays
    // valid either way: `c` is outside the v2 binding), and does the SERVER get a recipient out of it.
    let mut negatives: Vec<Value> = Vec::new();
    let mut neg = |name: &str, c_field: Option<String>, of: &MeshEnvelope, k: u8, key: &[u8; 32], relay_keeps: bool| {
        let json = pack_mesh_outer_json(&MeshEnvelope { courier: c_field.clone(), ..of.clone() }).unwrap();
        let f = frame_check(json.as_bytes(), NOW).expect("the frame itself is valid: c is outside the v2 binding");
        assert_eq!(f.courier.is_some(), relay_keeps, "{name}: kept by a relay");
        assert_eq!(f.seen_key, frame_check(pack_mesh_outer_json(of).unwrap().as_bytes(), NOW).unwrap().seen_key, "{name}: the same frame for the seen set");
        assert_eq!(courier_open(&f, k, key), None, "{name}");
        // Even handed to the server as it came (no relay in between), it names nobody.
        assert_eq!(courier_open(&Frame { courier: c_field, ..f.clone() }, k, key), None, "{name}: server");
        // What a relay passes on never carries a capsule it could not verify.
        if let Some(fwd) = forwarded_json(&f) {
            assert_eq!(fwd.contains(",\"c\":"), relay_keeps, "{name}: forwarded");
        }
        negatives.push(json!({"name": name, "frame": json, "kid": k, "courierPrivB64": b64(key), "relayKeeps": relay_keeps, "serverOpens": false}));
    };
    let raw_with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut r = raw.clone();
        f(&mut r);
        b64(&r)
    };
    neg("no capsule", None, &env, kid, &courier.private, false);
    // The server's two own checks: the capsule is the sender's (a relay keeps it), but it is not for this key.
    neg("another courier key id (kid is signed: the capsule says 1)", Some(capsule.clone()), &env, 2, &courier.private, true);
    neg("not the server's key (the box does not open)", Some(capsule.clone()), &env, kid, &c.ik.private, true);
    // Everything else is refused by EVERY node, so it never reaches a courier store or the air again.
    neg("a truncated capsule", Some(b64(&raw[..100])), &env, kid, &courier.private, false);
    neg("another capsule version", Some(raw_with(&|r| r[0] = 2)), &env, kid, &courier.private, false);
    neg("kid changed after signing", Some(raw_with(&|r| r[1] = 2)), &env, 2, &courier.private, false);
    neg("a flipped byte of the ephemeral key", Some(raw_with(&|r| r[2] ^= 1)), &env, kid, &courier.private, false);
    neg("a flipped byte of the box (the sealed recipient)", Some(raw_with(&|r| r[40] ^= 1)), &env, kid, &courier.private, false);
    neg("a flipped byte of csig", Some(raw_with(&|r| r[100] ^= 1)), &env, kid, &courier.private, false);
    // The capsule of one frame attached to another frame of the same sender: csig names the other inner blob.
    let other = legacy_msg(&a, &b, "m-other", MeshMode::Realtime, "courier/other");
    neg("the capsule of another frame of the same sender", Some(capsule.clone()), &other, kid, &courier.private, false);
    // A bystander: it can seal a recipient (the courier key is public) and sign with ITS key — not with the sender's.
    let bystander = courier_capsule_build(&courier.public, kid, c.uid as u64, &env.id, NOW as u64, a.uid as u64, &c.ed_secret, &blob, &mut StreamRng::new("courier/evil"));
    neg("a capsule attached by a bystander (re-addressed to itself; csig is not the sender's)", Some(bystander.clone()), &env, kid, &courier.private, false);
    // Its sealed recipient under the sender's csig of the genuine capsule: csig covers the sealed bytes.
    let spliced = {
        let evil = mrenzo_core::strict_json::b64(&bystander).unwrap();
        b64(&[&evil[..59], &raw[59..]].concat())
    };
    neg("a bystander's sealed recipient spliced under the sender's csig", Some(spliced), &env, kid, &courier.private, false);
    drop(neg);

    // The race a bystander can no longer win: its copy of the frame — junk capsule attached — is
    // heard FIRST. The frame is valid and is delivered by radio as usual, but no courier keeps that
    // capsule; the sender's copy, a duplicate by its seen key, still carries one that verifies.
    let junk_first = pack_mesh_outer_json(&MeshEnvelope { courier: Some(bystander.clone()), ..env.clone() }).unwrap();
    let heard_first = frame_check(junk_first.as_bytes(), NOW).unwrap();
    assert_eq!(heard_first.courier, None);
    let duplicate = frame_peek(frame_json.as_bytes()).unwrap();
    assert!(duplicate.seen_key == heard_first.seen_key && duplicate.carries_capsule, "a duplicate that claims a capsule: the courier runs the full check on it");
    assert_eq!(frame_check(frame_json.as_bytes(), NOW).unwrap().courier.as_deref(), Some(capsule.as_str()));

    // ── the seen set: the two things no frame signature covers cannot suppress a relay (§W8.3) ──
    let with_hops = |json: &str, hops: u64| json.replacen("\"hops\":0", &format!("\"hops\":{hops}"), 1);
    let junk_c = pack_mesh_outer_json(&MeshEnvelope { courier: Some(bystander.clone()), ..env.clone() }).unwrap();
    let signer = Signer { uid: a.uid as u64, ed_secret64: &a.ed_secret };
    let ptt_chunk = ptt::seal_chunk(&[7; 32], 0, true, &[vec![1; 20]], &mut StreamRng::new("courier/seen-ptt")).unwrap();
    let ptt_frame = build_ptt_frame(signer, &a.ik.private, &b.ik.public, "0f8fad5b-d9cb-469f-a165-70867728950e", 0, true, None, &ptt_chunk, NOW as u64).unwrap();
    let unbounded = build_named_frame("poll9", b"x", signer, None, "u-seen", 7, None, NOW as u64).unwrap();
    let own = pack_mesh_outer_json(&legacy_msg(&b, &a, "m-own", MeshMode::Realtime, "courier/own")).unwrap();
    // What one node did, over a transcript: the verified capsule it knows per frame and how often
    // it put the frame on the air on each lane. The properties of §W8.3 are checked on EVERY
    // emission: it carries the capsule exactly when the node knows a verified one, and no frame
    // goes out a third time on one lane.
    #[derive(Default)]
    struct Node {
        capsule: std::collections::HashMap<String, String>,
        emitted: std::collections::HashMap<(String, u8), u32>,
    }
    /// One copy off the air: the frame, the lane (radio) it came in on, and whether that radio
    /// has somebody to pass it on to.
    struct Heard {
        json: String,
        lane: u8,
        can_relay: bool,
    }
    let on = |lane: u8, json: String| Heard { json, lane, can_relay: true };
    // `want` = (first, the emissions as (lane, hops), capsuleUpgrade).
    type Want = Option<(bool, Vec<(u8, u64)>, bool)>;
    let step = |seen: &mut SeenSet, node: &mut Node, rows: &mut Vec<Value>, name: &str, heard: Heard, want_admit: Admission, want: Want| {
        let Heard { json, lane, can_relay } = heard;
        let peek = frame_peek(json.as_bytes()).unwrap();
        let admit = seen.admit(&peek, lane, can_relay);
        assert_eq!(admit, want_admit, "{name}: admit");
        let mut row = json!({"name": name, "frame": json, "lane": lane, "canRelay": can_relay, "admit": format!("{admit:?}").to_lowercase()});
        if admit != Admission::Duplicate {
            let frame = frame_check(json.as_bytes(), NOW).unwrap();
            let r = seen.record(&frame, lane, can_relay);
            if let Some(c) = &frame.courier {
                node.capsule.entry(frame.seen_key.clone()).or_insert_with(|| c.clone());
            }
            let emitted: Vec<(u8, Frame)> = r.forward.iter().map(|e| (e.lane, frame_check(e.frame.as_bytes(), NOW).expect("what a node re-emits is a valid frame"))).collect();
            let (first, hops, capsule_upgrade) = want.expect("an admitted frame has an expectation");
            assert_eq!((r.first, emitted.iter().map(|(l, e)| (*l, e.hops)).collect::<Vec<_>>(), r.capsule_upgrade), (first, hops, capsule_upgrade), "{name}: record");
            for (l, e) in &emitted {
                assert_eq!(e.seen_key, frame.seen_key, "{name}: the same frame");
                assert_eq!(e.courier.as_ref(), node.capsule.get(&frame.seen_key), "{name}: an emission carries the capsule exactly when the node knows a verified one");
                let n = node.emitted.entry((frame.seen_key.clone(), *l)).or_default();
                *n += 1;
                assert!(*n <= 2, "{name}: a frame was emitted a third time on lane {l}");
            }
            row["first"] = json!(r.first);
            row["forward"] = Value::Array(r.forward.iter().map(|e| json!({"lane": e.lane, "frame": e.frame})).collect());
            row["capsuleUpgrade"] = json!(r.capsule_upgrade);
        }
        rows.push(row);
    };
    use Admission::{Duplicate, New, Upgrade};
    let mut seen = SeenSet::new(64);
    let mut seen_steps: Vec<Value> = Vec::new();
    let mut node = Node::default();
    let rows: Vec<(&str, String, Admission, Want)> = vec![
        ("a copy that arrives with its budget spent (hops 2 of L 4): delivered, not relayed", with_hops(&without_c, 2), New, Some((true, vec![], false))),
        ("the same copy again", with_hops(&without_c, 2), Duplicate, None),
        ("a copy with an inflated hops", with_hops(&without_c, 16), Duplicate, None),
        ("a copy with budget left (hops 1) and a bystander's capsule: relayed now — a relay upgrade — without that capsule", with_hops(&junk_c, 1), Upgrade, Some((false, vec![(0, 2)], false))),
        ("hops 0, no capsule: relayed already", without_c.clone(), Duplicate, None),
        ("the bystander's capsule again: the claim buys a check and nothing else", junk_c.clone(), Upgrade, Some((false, vec![], false))),
        ("the sender's capsule (hops 0): a capsule upgrade — emitted once more with it, at the hops this node relayed with (2), not at this copy's", frame_json.clone(), Upgrade, Some((false, vec![(0, 2)], true))),
        ("the sender's capsule again", frame_json.clone(), Duplicate, None),
        ("the bystander's capsule after the sender's", junk_c.clone(), Duplicate, None),
        ("a ptt segment: never relayed", ptt_frame.clone(), New, Some((true, vec![], false))),
        ("its copy", ptt_frame.clone(), Duplicate, None),
        ("an unknown name without L: verified, never relayed", unbounded.clone(), New, Some((true, vec![], false))),
        ("its copy (no upgrade for a kind that is not relayed)", unbounded.clone(), Duplicate, None),
    ];
    for (name, json, admit, want) in rows {
        step(&mut seen, &mut node, &mut seen_steps, name, on(0, json), admit, want);
    }
    assert!(seen.mark_own(own.as_bytes()) && !seen.mark_own(b"{}"));
    seen_steps.push(json!({"name": "a frame this node transmits itself is marked before it goes on the air", "frame": own, "markOwn": true}));
    for lane in [0u8, 1] {
        assert_eq!(seen.admit(&frame_peek(own.as_bytes()).unwrap(), lane, true), Duplicate, "its echo is a duplicate on every lane: never relayed back");
        seen_steps.push(json!({"name": "the echo of that frame", "frame": own, "lane": lane, "canRelay": true, "admit": "duplicate"}));
    }
    // The two unsigned levers TOGETHER, and the two radios (§W8.3): each transcript is a fresh
    // node. Whatever the order of the copies, the sender's capsule ends up on the air from this
    // node — on every lane it relays on.
    let orderings: Vec<(&str, Vec<(&str, Heard, Admission, Want)>)> = vec![
        (
            "the capsule arrives on a copy nobody relays (hops inflated to 16), then a relayable copy somebody stripped: the relay carries the capsule the node already verified",
            vec![
                ("the sender's capsule, hops 16: delivered, capsule kept, not relayed", on(0, with_hops(&frame_json, 16)), New, Some((true, vec![], false))),
                ("the stripped copy, hops 0: a relay upgrade — emitted WITH the capsule", on(0, without_c.clone()), Upgrade, Some((false, vec![(0, 1)], false))),
                ("the sender's capsule, hops 0", on(0, frame_json.clone()), Duplicate, None),
                ("the stripped copy again", on(0, without_c.clone()), Duplicate, None),
            ],
        ),
        (
            "relayed without the capsule (a stripped copy came first), then the capsule on a copy nobody relays: emitted once more with it, at the hops of the first emission",
            vec![
                ("the stripped copy, hops 0: relayed without a capsule", on(0, without_c.clone()), New, Some((true, vec![(0, 1)], false))),
                ("the sender's capsule, hops 16: a capsule upgrade — emitted with hops 1, not 17", on(0, with_hops(&frame_json, 16)), Upgrade, Some((false, vec![(0, 1)], true))),
                ("the sender's capsule, hops 0", on(0, frame_json.clone()), Duplicate, None),
            ],
        ),
        (
            "no attacker: the capsule copy arrives with its L budget spent (hops 2), then a 1.0.0 re-flush of the same frame (hops 0, no capsule)",
            vec![
                ("the sender's capsule, hops 2", on(0, with_hops(&frame_json, 2)), New, Some((true, vec![], false))),
                ("the 1.0.0 re-flush, hops 0: relayed with the capsule", on(0, without_c.clone()), Upgrade, Some((false, vec![(0, 1)], false))),
                ("the sender's capsule, hops 1", on(0, with_hops(&frame_json, 1)), Duplicate, None),
            ],
        ),
        (
            "nothing relayable yet: the capsule is kept for the stores (capsuleUpgrade without an emission) and rides on the relay when a copy with budget comes",
            vec![
                ("no capsule, hops 2", on(0, with_hops(&without_c, 2)), New, Some((true, vec![], false))),
                ("the sender's capsule, hops 16: kept, nothing emitted", on(0, with_hops(&frame_json, 16)), Upgrade, Some((false, vec![], true))),
                ("a bystander's capsule, hops 2: nothing left to claim", on(0, with_hops(&junk_c, 2)), Duplicate, None),
                ("no capsule, hops 1: a relay upgrade — emitted with the capsule", on(0, with_hops(&without_c, 1)), Upgrade, Some((false, vec![(0, 2)], false))),
                ("the sender's capsule, hops 0", on(0, frame_json.clone()), Duplicate, None),
            ],
        ),
        (
            "two radios: heard on lane 0 first and relayed there — a copy on lane 1 is still relayed THERE (a frame is relayed only on the radio it was heard on), and acted on once",
            vec![
                ("lane 0, hops 0: delivered, relayed on lane 0", on(0, frame_json.clone()), New, Some((true, vec![(0, 1)], false))),
                ("lane 0 again", on(0, frame_json.clone()), Duplicate, None),
                ("lane 1, hops 1: a relay upgrade on lane 1 — not delivered a second time", on(1, with_hops(&frame_json, 1)), Upgrade, Some((false, vec![(1, 2)], false))),
                ("lane 1 again", on(1, frame_json.clone()), Duplicate, None),
            ],
        ),
        (
            "two radios, relayed on both without the capsule; the capsule then arrives on lane 1: emitted once more on BOTH lanes, each at its own hops",
            vec![
                ("lane 0, no capsule, hops 0", on(0, without_c.clone()), New, Some((true, vec![(0, 1)], false))),
                ("lane 1, no capsule, hops 1", on(1, with_hops(&without_c, 1)), Upgrade, Some((false, vec![(1, 2)], false))),
                ("lane 1, the sender's capsule, hops 16", on(1, with_hops(&frame_json, 16)), Upgrade, Some((false, vec![(0, 1), (1, 2)], true))),
                ("lane 0, the sender's capsule", on(0, frame_json.clone()), Duplicate, None),
            ],
        ),
        (
            "a radio with nobody to pass the frame on to (canRelay false) relays nothing and is not marked: the copy that comes when somebody is there still goes",
            vec![
                ("lane 1, nobody else on it: delivered, not relayed, lane left open", Heard { json: frame_json.clone(), lane: 1, can_relay: false }, New, Some((true, vec![], false))),
                ("lane 1 again, still nobody: a duplicate (a relay upgrade could come to nothing)", Heard { json: frame_json.clone(), lane: 1, can_relay: false }, Duplicate, None),
                ("lane 1, somebody is there now: relayed", on(1, frame_json.clone()), Upgrade, Some((false, vec![(1, 1)], false))),
                ("lane 1 again", on(1, frame_json.clone()), Duplicate, None),
            ],
        ),
    ];
    let mut ordering_rows: Vec<Value> = Vec::new();
    for (name, rows) in orderings {
        let (mut set, mut node, mut out) = (SeenSet::new(64), Node::default(), Vec::new());
        for (row_name, heard, admit, want) in rows {
            step(&mut set, &mut node, &mut out, row_name, heard, admit, want);
        }
        assert_eq!(node.capsule.values().next(), Some(&capsule), "{name}: the node knows the sender's capsule");
        // The last emission on every lane the node emitted on carries the sender's capsule.
        let mut last: std::collections::BTreeMap<u64, String> = Default::default();
        for e in out.iter().flat_map(|r| r["forward"].as_array().cloned().unwrap_or_default()) {
            last.insert(e["lane"].as_u64().unwrap(), e["frame"].as_str().unwrap().to_string());
        }
        assert!(!last.is_empty() && last.values().all(|f| f.ends_with(&format!(",\"c\":\"{capsule}\"}}"))), "{name}: the last emission on each lane carries the sender's capsule");
        ordering_rows.push(json!({"name": name, "steps": out}));
    }
    // A frame this node sent itself without a capsule, heard back with its own capsule (it alone
    // can sign one): the stores are told, the set re-emits nothing — whatever sent it sends it again.
    let mut mine = SeenSet::new(16);
    assert!(mine.mark_own(without_c.as_bytes()));
    assert_eq!(mine.admit(&frame_peek(with_hops(&frame_json, 3).as_bytes()).unwrap(), 0, true), Upgrade);
    let r = mine.record(&frame_check(with_hops(&frame_json, 3).as_bytes(), NOW).unwrap(), 0, true);
    assert!(!r.first && r.capsule_upgrade && r.forward.is_empty(), "{r:?}");
    assert!(mine.mark_own(frame_json.as_bytes()), "marking it again changes nothing");
    assert_eq!(mine.admit(&frame_peek(frame_json.as_bytes()).unwrap(), 1, true), Duplicate);
    // A frame relayed and THEN flushed from the store keeps the hops it was relayed with.
    let mut carried = SeenSet::new(16);
    assert_eq!(carried.record(&frame_check(without_c.as_bytes(), NOW).unwrap(), 0, true).forward.len(), 1);
    assert!(carried.mark_own(without_c.as_bytes()));
    assert_eq!(carried.admit(&frame_peek(without_c.as_bytes()).unwrap(), 1, true), Duplicate, "sent by the node itself: not relayed on the other radio either");
    let r = carried.record(&frame_check(frame_json.as_bytes(), NOW).unwrap(), 1, true);
    assert!(r.capsule_upgrade && r.forward.len() == 1 && r.forward[0].lane == 0 && r.forward[0].frame.contains("\"hops\":1,"), "{r:?}");
    // A lane that does not exist: nothing is admitted and nothing recorded.
    let mut odd = SeenSet::new(16);
    assert_eq!(odd.admit(&frame_peek(frame_json.as_bytes()).unwrap(), MAX_LANES as u8, true), Duplicate);
    let r = odd.record(&frame_check(frame_json.as_bytes(), NOW).unwrap(), MAX_LANES as u8, true);
    assert!(!r.first && r.forward.is_empty() && odd.is_empty());
    // The first copy relayed at once; a capsule that arrives with the first copy needs no upgrade.
    let mut fresh = SeenSet::default();
    let r = fresh.record(&frame_check(frame_json.as_bytes(), NOW).unwrap(), 0, true);
    assert!(r.first && !r.capsule_upgrade && r.forward.len() == 1 && r.forward[0].frame.contains(",\"c\":"));
    assert_eq!(fresh.admit(&frame_peek(junk_c.as_bytes()).unwrap(), 0, true), Duplicate);
    // Bounded: the oldest entries go.
    let mut small = SeenSet::new(16);
    for i in 0..40 {
        let f = pack_mesh_outer_json(&legacy_msg(&a, &b, &format!("m-cap-{i}"), MeshMode::Realtime, &format!("courier/cap{i}"))).unwrap();
        small.record(&frame_check(f.as_bytes(), NOW).unwrap(), 0, true);
    }
    assert_eq!(small.len(), 16);
    small.clear();
    assert!(small.is_empty());

    // A capsule is honoured only on a `msg`.
    let ack = build_mesh_ack(0, "m.tag", &identity(&b), NOW, &mut StreamRng::new("courier/ack")).unwrap().unwrap();
    let ack_with_c = pack_mesh_outer_json(&MeshEnvelope { courier: Some(capsule.clone()), ..ack }).unwrap();
    assert_eq!(frame_check(ack_with_c.as_bytes(), NOW).unwrap().courier, None);

    let mut v = header_v11(
        "meshCourierV1",
        &[
            "c = b64(0x01 ‖ kid ‖ eph_pub[32] ‖ box[25] ‖ csig[64]) (123 bytes, 164 characters), an outer key of a msg frame OUTSIDE the v2 binding; box = crypto_box(pt, nonce, courier_pub, eph_priv); pt = 0x01 ‖ BE64(to); nonce = SHA-256(\"mrenzo-courier-nonce-v1\" ‖ eph_pub ‖ courier_pub)[0..24].",
            "csig = Ed25519(ED_from, UTF-8(\"mrenzo-courier-v1|\" + id + \"|\" + ts + \"|\" + from + \"|\" + kid + \"|\" + b64(SHA-256(inner blob bytes)) + \"|\" + b64(SHA-256(eph_pub ‖ box)))), verified strictly under the frame's own sig_pub. The builder draws the ephemeral secret (32 bytes).",
            "EVERY node checks csig (no secret is needed): a capsule that does not verify is ABSENT — the frame stays valid, but the capsule is neither stored nor relayed (`relayKeeps`). So a bystander cannot put its own capsule in the place of the sender's.",
            "Each negative: `frame` passes the strict frame check; `relayKeeps` = the check returns the capsule; `serverOpens` = opening it for key id `kid` with the private key `courierPrivB64` yields a recipient (never, in this list).",
            "Server, per uploaded frame: strict frame check (meshV11.json, its own freshness window; this includes csig) → kind msg → kid known → open the box with the courier private key → to → sig_pub is the directory key of from → claim H(from|id) → route `routed` as if from had sent it.",
            "A 1.0.0 node does not see c (it reads only the keys it knows); it verifies, delivers and ACKs the frame unchanged.",
        ],
    );
    v.insert("nowMs".into(), json!(NOW));
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json(), "carol": c.json()}));
    v.insert("courierKey".into(), json!({"rngLabel": "courier/server-key", "kid": kid, "privB64": b64(&courier.private), "pubB64": b64(&courier.public)}));
    v.insert(
        "capsule".into(),
        json!({
            "rngLabel": "courier/eph", "to": b.uid, "from": a.uid, "id": env.id, "ts": NOW,
            "innerBlobSha256B64": b64(&sha256(&blob)), "sealedSha256B64": b64(&sha256(sealed)), "csigMessage": csig_msg, "c": capsule,
        }),
    );
    v.insert("frame".into(), json!(frame_json));
    v.insert("frameWithoutCapsule".into(), json!(without_c));
    v.insert("queueJson".into(), json!(with_c.to_json()));
    v.insert("routed".into(), json!(routed));
    v.insert("negatives".into(), Value::Array(negatives));
    v.insert(
        "seenSet".into(),
        json!({
            "note": "One node, one seen set, in order (§W8.3). Each row is a copy heard on `lane` (a radio: a frame is relayed only on the radio it was heard on) with `canRelay` = that radio has somebody to pass the frame on to. `admit` is decided BEFORE any signature work from the peeked seen key, `hops` and capsule claim: new | duplicate (dropped, free) | upgrade (checked again). For an admitted frame: `first` = act on it (once per node, whatever the lane); `forward` = the exact frames to emit, each with its lane (empty = none); `capsuleUpgrade` = the first verified capsule for a frame seen without one. The set remembers, per frame, the hops THIS node relayed it with on each lane and — for the node as a whole — the verified capsule itself: an emission carries that capsule whether or not the copy in hand does, and a capsule upgrade is emitted on every lane the node relayed on, at the hops of that earlier emission, whatever the upgrading copy's hops or lane are. A row with `markOwn` records a frame the node transmits itself (its echo is a duplicate on every lane). A node emits one frame at most twice per lane, and only a copy that passed the whole check can cause any emission. `orderings`: each entry is a FRESH node — the two unsigned levers (hops, the capsule) used together in every order, and the two-radio cases; in each, the last emission on every lane carries the sender's capsule.",
            "steps": seen_steps,
            "orderings": ordering_rows,
        }),
    );
    check_or_write("meshCourierV1.json", &Value::Object(v));
}

/// The admission budgets and the 1.0.0-shaped entry points on top of the strict rules.
#[test]
fn legacy_frames_pass_the_strict_check() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/meshV2.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    for (name, kind) in [("msg", FrameKind::Msg), ("ack", FrameKind::Ack)] {
        let json = v[name]["outerJson"].as_str().unwrap();
        let f = frame_check(json.as_bytes(), NOW).unwrap_or_else(|r| panic!("the 1.0.0 {name} of meshV2.json: {r}"));
        assert_eq!(f.kind, kind);
        let legacy = mrenzo_core::mesh_envelope::unpack_mesh_outer(&serde_json::from_str(json).unwrap()).unwrap().unwrap();
        assert_eq!(f.to_legacy_envelope().unwrap(), legacy, "the strict parser reports what the 1.0.0 decoder reports");
    }
}
