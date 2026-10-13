//! 1.0.0 ↔ 1.1 compatibility, proven by running the OLD code (wire-1.1 §W10).
//!
//! `tests/legacy353/` is the 1.0.0 core, frozen at `712e1dcc` (build 353,
//! live in the App Store) together with everything it calls — it shares no
//! code with this crate but the primitives and the PRNG, and its own test
//! (`legacy353::frozen`) pins every one of those files to the App Store
//! commit. Every test here feeds what THIS core produces to those functions,
//! or the reverse. Where the 1.0.0 rule lives in Swift
//! (the pipeline guard, the radio's admission and relay), it is rebuilt
//! below as test-only code next to the lines it comes from.
//!
//! What is proven:
//! 1. every level-1 kind built by 1.1 with the new soft keys parses in 353 to
//!    the same value, and a 353 session decrypts the 1.1 envelope and advances;
//! 2. every level-2 kind is `None` in the 353 parser and `Failed` in a 353
//!    session — the trap the carrier rule exists for — and none of the
//!    level-2 carriers reaches a 353 ratchet;
//! 3. a classical 1.1 session and a 353 session interoperate both ways and
//!    their state JSON is byte-identical; a hybrid envelope fails its MAC
//!    cleanly in 353 and a hybrid state does not load there;
//! 4. mesh: a 1.1 `msg` (with a capsule) verifies in 353, named frames and
//!    353-relayed copies do not, a blind ACK and a 1.1-relayed copy do;
//! 5. the airtime trap of mesh push-to-talk against a 353 neighbour, and the
//!    link rule that avoids it.

mod common;
mod legacy353;

use common::*;
use legacy353::files as f353;
use legacy353::mesh_envelope as m353;
use legacy353::plaintext as p353;
use legacy353::ratchet as r353;
use legacy353::session_set as s353;
use legacy353::x3dh as x353;
use mrenzo_core::caps::Caps;
use mrenzo_core::files;
use mrenzo_core::mesh_envelope::{build_mesh_envelope_from_ratchet, encode_inner_blob, pack_mesh_outer_json, MeshEnvelope, MeshIdentity, MeshMode};
use mrenzo_core::mesh_v11::{self, Signer};
use mrenzo_core::nearby::NearbyOp;
use mrenzo_core::plaintext::{self, build, classify, Classified, Soft, TypedPlaintext};
use mrenzo_core::primitives::{b64, ed25519_sign};
use mrenzo_core::ptt::{self, PttKey};
use mrenzo_core::ratchet::{mesh_ack_seed, Envelope, Session};
use mrenzo_core::rng::StreamRng;
use mrenzo_core::session_set::{PeerSessions, SetOpen};
use mrenzo_core::x3dh::{generate_kem_pre_key, KemKind};
use serde_json::{json, Map, Value};

fn caps() -> Caps {
    Caps::own(&["pq", "ptt"]).unwrap()
}

fn soft() -> Soft {
    Soft { caps: Some(caps()), ..Default::default() }
}

fn old_bundle(p: &Prekeys, with_opk: bool) -> x353::BundleV2 {
    x353::BundleV2 { spk_id: p.spk_id, spk_pub: p.spk.public, spk_sig: p.spk_sig, opk: with_opk.then_some((p.opk_id, p.opk.public)) }
}

/// A 353 client receiving one wire from `from` (the full §5.3 path of the old core).
fn recv_353(set: &mut s353::PeerSessions, wire: &str, me: &Ident, p: &Prekeys, from: &Ident, label: &str) -> s353::SetDecrypt {
    let env = r353::Envelope::parse(wire).expect("353 parses the envelope");
    let mut r = StreamRng::new(label);
    match set.decrypt(&env, T0, &mut r) {
        s353::SetDecrypt::NeedsResponder => {
            let x = env.x.unwrap();
            set.respond_and_decrypt(&env, &me.ik, &me.ed_pub, &p.spk, x.opk.map(|_| &p.opk.private), &from.ik.public, &from.ed_pub, T0, &mut r).unwrap()
        }
        other => other,
    }
}

/// The attachment a sticker travels as.
fn sticker_attachment() -> files::FileEnvelope {
    files::FileEnvelope {
        placeholder: "📎".into(),
        file_id: "f-1".into(),
        key: b64(&[1u8; 32]),
        nonce: b64(&[2u8; 24]),
        mime_type: "image/png".into(),
        file_name: None,
        file_size: Some(32_784.0),
        duration: None,
    }
}

/// A `file` body exactly as build 353 writes it (`TypedPlaintext.swift`
/// `fileBodyJSON`: the FileEnvelope JSON of 03 §8.3 — `p, id, k, n, m, s` —
/// plus `kind`), with the level-2 soft key `st` added.
fn file_body_with_sticker() -> Map<String, Value> {
    let mut body: Map<String, Value> = serde_json::from_str(&files::build_file_envelope(&sticker_attachment())).unwrap();
    body.insert("kind".into(), json!("image"));
    body.insert("st".into(), json!({"v": 1, "id": "a".repeat(64), "w": 512, "h": 512}));
    body
}

/// What build 353 does with a received `file` body (`TypedPlaintext.swift:74-80`
/// `fileBody`, then `fileEnvelopeParse`): `kind` must be a media kind and is
/// removed; the rest is read by the FileEnvelope parser — the 1.0.0
/// `files.rs`, frozen with the JSON and number helpers it calls.
fn file_body_as_353_reads_it(body: &Map<String, Value>) -> Option<(String, f353::FileEnvelope)> {
    let kind = body.get("kind")?.as_str().filter(|k| ["image", "video", "voice", "file"].contains(k))?.to_string();
    let mut rest = body.clone();
    rest.remove("kind");
    Some((kind, f353::parse_file_envelope(&Value::Object(rest).to_string())?))
}

/// The same attachment as the 1.0.0 type.
fn as_353(e: &files::FileEnvelope) -> f353::FileEnvelope {
    f353::FileEnvelope {
        placeholder: e.placeholder.clone(),
        file_id: e.file_id.clone(),
        key: e.key.clone(),
        nonce: e.nonce.clone(),
        mime_type: e.mime_type.clone(),
        file_name: e.file_name.clone(),
        file_size: e.file_size,
        duration: e.duration,
    }
}

// ───────────────────────────── 1 ─────────────────────────────

#[test]
fn level_1_kinds_with_soft_keys_are_plain_messages_for_353() {
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let mut alice_11 = PeerSessions { aux_enabled: true, ..Default::default() };
    alice_11.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), T0, &mut StreamRng::new("c353/x")).unwrap();
    let mut bob_353 = s353::PeerSessions::default();

    let invite = NearbyOp::Invite { ns: [3; 16], exp: 1_790_000_300_000 };
    let chat = |id: &str| TypedPlaintext::Chat { id: id.into(), body: "текст".into(), reply: None, fwd: None, expire: Some(60), story: None };
    let mut skdm_body = Map::new();
    skdm_body.insert("v".into(), json!(2));
    let messages: Vec<(TypedPlaintext, Soft, Option<usize>)> = vec![
        (chat("m1"), soft(), None),
        // «Отправить без звука» (§W7.9): `silent` is one more key 353 does not read.
        (chat("m2"), Soft { caps: Some(caps()), alt: Some("fallback".into()), nearby: Some(invite), silent: true }, Some(64)),
        (TypedPlaintext::File { id: "m3".into(), body: file_body_with_sticker(), reply: None, fwd: None, expire: None }, Soft { silent: true, ..soft() }, None),
        (TypedPlaintext::Hello { id: "m4".into() }, soft(), None),
        (TypedPlaintext::Edit { id: "m5".into(), edit_of: "m1".into(), body: "правка".into() }, soft(), None),
        (TypedPlaintext::Skdm { id: "m6".into(), body: skdm_body }, soft(), None),
    ];
    for (i, (pt, soft, pad)) in messages.iter().enumerate() {
        let json = build(pt, soft, *pad).unwrap();
        assert!(json.contains("\"caps\":"), "the 1.1 plaintext really carries the new keys");
        assert_eq!(json.contains("\"silent\":true"), soft.silent);
        // The 353 PARSER: the same kind, the same own fields, the new keys ignored (F2, F9).
        let old = p353::parse_typed_plaintext(&json).unwrap_or_else(|| panic!("353 rejects {}", pt.kind()));
        assert_eq!(old.to_json(), pt.to_json(), "{}: 353 reads exactly the 1.0.0 part", pt.kind());
        // A 353 SESSION decrypts the 1.1 envelope and advances.
        let wire = alice_11.encrypt(&json, T0, &mut StreamRng::new(&format!("c353/a{i}"))).unwrap().to_wire();
        let before = bob_353.clone();
        let out = recv_353(&mut bob_353, &wire, &b, &p, &a, &format!("c353/b{i}"));
        assert!(matches!(&out, s353::SetDecrypt::Opened { plaintext, .. } if *plaintext == json), "{}: {out:?}", pt.kind());
        assert_ne!(bob_353, before, "the 353 ratchet advanced");
    }
    // A sticker is an ordinary photo for 353: its body reads to the SAME attachment as the body
    // without `st` (the envelope parser reads the keys it knows and ignores the rest, F9).
    let p353::TypedPlaintext::File { body, .. } = p353::parse_typed_plaintext(&build(&messages[2].0, &soft(), None).unwrap()).unwrap() else { panic!() };
    assert!(body.contains_key("st"));
    let (kind, envelope) = file_body_as_353_reads_it(&body).expect("353 reads the sticker body as an attachment");
    assert_eq!((kind.as_str(), &envelope), ("image", &as_353(&sticker_attachment())));
    assert_eq!(envelope.mime_type, "image/png");

    // 353 → 1.1: its plaintexts carry no caps; everything opens as Typed.
    let reply = p353::TypedPlaintext::Chat { id: "b1".into(), body: "ответ".into(), reply: None, fwd: None, expire: None, story: None }.to_json();
    let wire = bob_353.encrypt(&reply, T0, &mut StreamRng::new("c353/b-send")).unwrap().to_wire();
    let out = alice_11.open(&Envelope::parse(&wire).unwrap(), T0, &mut StreamRng::new("c353/a-recv"));
    assert!(matches!(&out, SetOpen::Typed { plaintext, parsed, by } if *plaintext == reply && parsed.soft == Soft::default() && !by.pq), "{out:?}");
}

// ───────────────────────────── 2 ─────────────────────────────

fn level_2_plaintexts() -> Vec<(&'static str, String)> {
    let ptt_id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    vec![
        ("react", build(&TypedPlaintext::React { id: "rx-1".into(), to: "m1".into(), e: vec!["👍".into()], ts: 5 }, &soft(), Some(64)).unwrap()),
        ("nearby", build(&TypedPlaintext::Nearby { id: "nb-1".into(), nearby: NearbyOp::Stop { ns: [1; 16], why: None } }, &soft(), None).unwrap()),
        ("ptt", build(&TypedPlaintext::Ptt { id: ptt_id.into(), ptt: PttKey { k: [9; 32], codec: "opus".into(), sr: 16_000 } }, &soft(), None).unwrap()),
        ("a kind neither build knows", r#"{"t":"poll","id":"p-1","q":"?"}"#.to_string()),
    ]
}

/// The verified trap (F1): a 353 core returns `None` from inside the decrypt
/// for an unknown `t`, its session set reports `Failed`, and Swift counts it
/// (three in five minutes archive the session). This is why a level-2 kind
/// never travels in a field a 353 ratchet reads.
#[test]
fn a_level_2_kind_fed_to_a_353_ratchet_is_a_counted_failure() {
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    for (name, json) in level_2_plaintexts() {
        assert!(p353::parse_typed_plaintext(&json).is_none(), "{name}: the 353 parser does not know it");
        // Established pair, 353 on Bob's side.
        let mut alice_11 = PeerSessions::default();
        alice_11.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), T0, &mut StreamRng::new("t353/x")).unwrap();
        let mut bob_353 = s353::PeerSessions::default();
        let hello = TypedPlaintext::Hello { id: "h".into() }.to_json();
        let w = alice_11.encrypt(&hello, T0, &mut StreamRng::new("t353/h")).unwrap().to_wire();
        assert!(matches!(recv_353(&mut bob_353, &w, &b, &p, &a, "t353/bh"), s353::SetDecrypt::Opened { .. }));
        let w = alice_11.encrypt(&json, T0, &mut StreamRng::new("t353/k")).unwrap().to_wire();
        let before = bob_353.clone();
        assert_eq!(recv_353(&mut bob_353, &w, &b, &p, &a, "t353/bk"), s353::SetDecrypt::Failed, "{name}: Failed — what Swift counts");
        assert_eq!(bob_353, before, "…and the 353 ratchet did not move");
        // The 1.1 core on the same wire: an outcome, the step consumed, nothing to count.
        let mut bob_11 = PeerSessions::from_rows(
            &before.rows().into_iter().map(|r| mrenzo_core::session_set::Row { sid_b64: r.sid_b64, peer_ek_b64: r.peer_ek_b64, status: mrenzo_core::session_set::Status::parse(r.status.as_str()).unwrap(), state_json: r.state_json, updated_at: r.updated_at }).collect::<Vec<_>>(),
            T0,
        );
        let out = bob_11.open(&Envelope::parse(&w).unwrap(), T0, &mut StreamRng::new("t353/bk"));
        match name {
            "a kind neither build knows" => assert!(matches!(out, SetOpen::Unsupported { .. }), "{out:?}"),
            _ => assert!(matches!(out, SetOpen::Typed { .. }), "{name}: {out:?}"),
        }
    }
}

/// `MessagePipeline.swift:384` (712e1dcc), with `ChatFrames.swift:48`
/// (`text` decodes to "" when absent):
/// `guard data.encrypted, !data.text.isEmpty else { Log.warn("INBOX", "plaintext.dropped"…); return }`
/// — true when a `p2p-message` `data` object goes on to the 353 ratchet.
fn reaches_the_353_ratchet(data: &Value) -> bool {
    data.get("encrypted").and_then(Value::as_bool).unwrap_or(false) && !data.get("text").and_then(Value::as_str).unwrap_or("").is_empty()
}

#[test]
fn no_level_2_carrier_reaches_a_353_ratchet() {
    // The `ctl` frame: `action: session-hello` goes to the chat path (MessagePipeline.swift:224-227), which drops it at :384.
    let frame: Value = serde_json::from_str(&plaintext::ctl_frame_json(1002, "rx-1", "{\"v\":3}")).unwrap();
    assert_eq!(frame["type"], "p2p-message");
    assert_eq!(frame["data"]["action"], "session-hello");
    let keys: Vec<&str> = frame["data"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["toUserId", "messageId", "action", "ctl"], "no text, no encrypted, no type");
    assert!(!reaches_the_353_ratchet(&frame["data"]));
    // `ptt-start`: a frame type 353 does not know (`CallEngine.swift:526-574`, `default: break`).
    let frame: Value = serde_json::from_str(&plaintext::ptt_start_frame_json(1002, "0f8fad5b-d9cb-469f-a165-70867728950e", "{\"v\":3}")).unwrap();
    assert!(!["p2p-message", "p2p-sealed", "p2p-pending-sealed", "message-edit"].contains(&frame["type"].as_str().unwrap()));
    // The courier's routed object is the opposite case: it MUST reach the ratchet of either version,
    // and agree with a `chat` (`MessagePipeline.swift:345-358`: the outer kind is absent or "text").
    let routed: Value = serde_json::from_str(&mesh_v11::courier_routed_json(1002, "m-1", "{\"v\":3}")).unwrap();
    assert!(reaches_the_353_ratchet(&routed));
    assert!(routed.get("type").is_none() && routed.get("action").is_none());
    assert_eq!(routed["transport"], "mesh-courier");
}

// ───────────────────────────── 3 ─────────────────────────────

#[test]
fn classical_sessions_interoperate_and_their_state_is_byte_identical() {
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let chat = |id: &str| TypedPlaintext::Chat { id: id.into(), body: id.into(), reply: None, fwd: None, expire: None, story: None }.to_json();
    // The same transcript twice: 1.1 Alice ↔ 353 Bob, and 353 Alice ↔ 1.1 Bob. Same PRNG labels, so the bytes must agree.
    let mut a11 = PeerSessions::default();
    let mut b353 = s353::PeerSessions::default();
    let mut a353 = s353::PeerSessions::default();
    let mut b11 = PeerSessions::default();
    a11.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), T0, &mut StreamRng::new("i/x")).unwrap();
    a353.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &old_bundle(&p, true), T0, &mut StreamRng::new("i/x")).unwrap();
    for round in 0..3 {
        // Alice → Bob
        let w_new = a11.encrypt(&chat(&format!("a{round}")), T0, &mut StreamRng::new(&format!("i/a{round}"))).unwrap().to_wire();
        let w_old = a353.encrypt(&chat(&format!("a{round}")), T0, &mut StreamRng::new(&format!("i/a{round}"))).unwrap().to_wire();
        assert_eq!(w_new, w_old, "round {round}: a classical 1.1 envelope is byte for byte the 1.0.0 envelope");
        assert!(matches!(recv_353(&mut b353, &w_new, &b, &p, &a, &format!("i/b{round}")), s353::SetDecrypt::Opened { .. }));
        let env = Envelope::parse(&w_old).unwrap();
        let mut r = StreamRng::new(&format!("i/b{round}"));
        let out = match b11.open(&env, T0, &mut r) {
            SetOpen::NeedsResponder => b11.respond_and_open(&env, &b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), None, &a.ik.public, &a.ed_pub, T0, &mut r).unwrap(),
            other => other,
        };
        assert!(matches!(out, SetOpen::Typed { .. }), "round {round}: {out:?}");
        // Bob → Alice
        let w_new = b11.encrypt(&chat(&format!("b{round}")), T0, &mut StreamRng::new(&format!("i/bs{round}"))).unwrap().to_wire();
        let w_old = b353.encrypt(&chat(&format!("b{round}")), T0, &mut StreamRng::new(&format!("i/bs{round}"))).unwrap().to_wire();
        assert_eq!(w_new, w_old);
        assert!(matches!(a11.open(&Envelope::parse(&w_old).unwrap(), T0, &mut StreamRng::new(&format!("i/ar{round}"))), SetOpen::Typed { .. }));
        assert!(matches!(a353.decrypt(&r353::Envelope::parse(&w_new).unwrap(), T0, &mut StreamRng::new(&format!("i/ar{round}"))), s353::SetDecrypt::Opened { .. }));
        // The at-rest JSON of the two builds is the same text, and each build loads the other's.
        for (new, old) in [(&a11, &a353), (&b11, &b353)] {
            let (jn, jo) = (new.live().unwrap().session.to_json(), old.live().unwrap().session.to_json());
            assert_eq!(jn, jo, "round {round}: session JSON");
            assert_eq!(r353::Session::from_json(&jn, T0).unwrap().to_json(), jn);
            assert_eq!(Session::from_json(&jo, T0).unwrap().to_json(), jo);
        }
    }
}

#[test]
fn a_hybrid_envelope_fails_cleanly_in_353_and_a_hybrid_state_does_not_load() {
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let kem = generate_kem_pre_key(&b.ed_secret, 42, KemKind::OneTime, &mut StreamRng::new("pq/bob-kem-otk"));
    let mut alice_11 = PeerSessions::default();
    alice_11.initiate_pq(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), &kem.public(), T0, &mut StreamRng::new("h/x")).unwrap();
    let wire = alice_11.encrypt(&TypedPlaintext::Hello { id: "h".into() }.to_json(), T0, &mut StreamRng::new("h/m")).unwrap().to_wire();
    assert!(wire.contains("\"kem\":{"));
    // 353 parses the envelope: an unknown key inside `x` is ignored (F7)…
    let env = r353::Envelope::parse(&wire).expect("353 parses a hybrid envelope");
    assert_eq!(env.x.unwrap().spk, 17);
    // …derives the classical secret, and fails the MAC: one counted failure, nothing installed, no crash.
    let mut bob_353 = s353::PeerSessions::default();
    assert_eq!(recv_353(&mut bob_353, &wire, &b, &p, &a, "h/b"), s353::SetDecrypt::Failed);
    assert!(bob_353.entries.is_empty());
    // A hybrid state row is not a state for 353 (strict at rest): after a rollback the row is dropped.
    let json = alice_11.live().unwrap().session.to_json();
    assert!(json.contains("\"pq\":true"));
    assert!(r353::Session::from_json(&json, T0).is_none());
    assert!(Session::from_json(&json, T0).is_some());
}

// ───────────────────────────── 4 ─────────────────────────────

fn identity(i: &Ident) -> MeshIdentity {
    MeshIdentity { from_uid: i.uid, sign_priv_b64: b64(&i.ed_secret), sign_pub_b64: b64(&i.ed_pub) }
}

/// What a 353 client does with a frame off the radio, up to the signature
/// (`MeshService.swift:329-345`): unpack, `v == 2`, `to == 0`, verify.
fn verifies_in_353(frame_json: &str) -> Option<m353::MeshEnvelope> {
    let value: Value = serde_json::from_str(frame_json).ok()?;
    let env = m353::unpack_mesh_outer(&value).ok()??;
    (env.v == json!(2) && env.to == 0.0 && m353::verify_mesh_envelope(&env)).then_some(env)
}

/// `MeshFrameCore.forwardedFrame` (712e1dcc `Mesh/MeshFrameCore.swift:83-93`):
/// forward iff ttl > 0 and (no L or floor(L/2) ≥ 1); ttl − 1, hops + 1, L halved.
fn forwarded_by_353(frame_json: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(frame_json).ok()?;
    let o = v.as_object_mut()?;
    let int = |x: Option<&Value>| x.and_then(Value::as_i64).unwrap_or(0);
    let ttl = int(o.get("ttl"));
    let has_l = o.get("L").is_some_and(Value::is_number);
    let new_l = int(o.get("L")) / 2;
    if ttl <= 0 || (has_l && new_l < 1) {
        return None;
    }
    let hops = int(o.get("hops"));
    o.insert("ttl".into(), json!(ttl - 1));
    o.insert("hops".into(), json!(hops + 1));
    if has_l {
        o.insert("L".into(), json!(new_l));
    }
    Some(v.to_string())
}

/// A named frame assembled by hand (the builder refuses reserved names).
fn hand_named(name: &str, flags: u8, signed_kind: &str, body: &[u8], who: &Ident, to_idx: Option<[u8; 8]>) -> String {
    let payload = [&[name.len() as u8][..], name.as_bytes(), body].concat();
    let signed = mesh_v11::binding("hand-1", T0 as u64, who.uid as u64, to_idx.as_ref(), 7, Some(4), MeshMode::Realtime, signed_kind, &b64(&payload));
    let mut blob = vec![flags];
    blob.extend_from_slice(&who.ed_pub);
    blob.extend_from_slice(&(who.uid as u64).to_be_bytes());
    if let Some(t) = &to_idx {
        blob.extend_from_slice(t);
    }
    blob.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    blob.extend_from_slice(&payload);
    blob.extend_from_slice(&ed25519_sign(&who.ed_secret, signed.as_bytes()));
    format!("{{\"v\":2,\"id\":\"hand-1\",\"ttl\":7,\"hops\":0,\"L\":4,\"mode\":\"realtime\",\"ts\":{T0},\"b\":\"{}\"}}", b64(&blob))
}

#[test]
fn mesh_frames_between_the_two_builds() {
    let (a, b) = (alice(), bob());
    let signer = Signer { uid: a.uid as u64, ed_secret64: &a.ed_secret };
    let wire = r#"{"v":3,"dh":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pn":0,"n":0,"ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
    let env = build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), wire, MeshMode::Realtime, &identity(&a), Some("m-1"), T0, &mut StreamRng::new("mc/msg")).unwrap().unwrap();
    let blob = encode_inner_blob(&env).unwrap();
    let capsule = mesh_v11::courier_capsule_build(&[5u8; 32], 1, b.uid as u64, &env.id, T0 as u64, a.uid as u64, &a.ed_secret, &blob, &mut StreamRng::new("mc/cap"));
    let with_c = pack_mesh_outer_json(&MeshEnvelope { courier: Some(capsule), ..env.clone() }).unwrap();
    assert!(with_c.contains(",\"c\":\""));

    // A 1.1 msg — capsule and all — is an ordinary valid frame for 353, and unpads to the envelope.
    let seen = verifies_in_353(&with_c).expect("353 verifies a 1.1 msg that carries a capsule");
    assert_eq!(seen.kind, Some(m353::MeshKind::Msg));
    assert_eq!(m353::unpad_payload(&seen.payload).as_deref(), Some(wire));
    assert_eq!(m353::compute_to_idx(&b64(&b.ik.private), &b64(&a.ik.public), T0 as f64), seen.to_idx.clone().unwrap(), "353 Bob finds himself addressed");

    // The copy a 1.1 relay re-emits (only `hops` changed) verifies in 353 at every hop.
    let mut frame = mesh_v11::frame_check(with_c.as_bytes(), T0).unwrap();
    let mut hops = 0;
    while let Some(next) = mesh_v11::forwarded_json(&frame) {
        hops += 1;
        assert_eq!(verifies_in_353(&next).expect("353 verifies a copy relayed by 1.1").hops, hops as f64);
        frame = mesh_v11::frame_check(next.as_bytes(), T0).unwrap();
    }
    assert_eq!(hops, 2);
    // The copy a 353 radio re-emits verifies in NEITHER build — and on 1.1 it no longer poisons anything.
    let broken = forwarded_by_353(&with_c).unwrap();
    assert!(verifies_in_353(&broken).is_none());
    assert_eq!(mesh_v11::frame_check(broken.as_bytes(), T0).err(), Some("signature"));

    // Named frames: 353 decodes them as `msg`, rebuilds the binding with kind "msg" and fails the signature (F10).
    let chunk = ptt::seal_chunk(&[1; 32], 0, true, &[vec![7; 30]], &mut StreamRng::new("mc/chunk")).unwrap();
    let ptt_frame = mesh_v11::build_ptt_frame(signer, &a.ik.private, &b.ik.public, "0f8fad5b-d9cb-469f-a165-70867728950e", 0, true, Some(wire), &chunk, T0 as u64).unwrap();
    let ctl_frame = mesh_v11::build_ctl_frame(signer, &a.ik.private, &b.ik.public, "nb-1", wire, 1, T0 as u64).unwrap();
    let unknown = mesh_v11::build_named_frame("poll9", b"x", signer, None, "u-1", 7, Some(4), T0 as u64).unwrap();
    for (name, f) in [("ptt", &ptt_frame), ("ctl", &ctl_frame), ("an unknown name", &unknown)] {
        assert!(mesh_v11::frame_check(f.as_bytes(), T0).is_ok());
        let value: Value = serde_json::from_str(f).unwrap();
        let decoded = m353::unpack_mesh_outer(&value).unwrap().expect("353 unpacks it");
        assert_eq!(decoded.kind, Some(m353::MeshKind::Msg), "{name}: 353 sees a msg");
        assert!(!m353::verify_mesh_envelope(&decoded), "{name}: recv.sigInvalid in 353 — its ratchet never sees the body");
        assert!(verifies_in_353(f).is_none());
    }

    // WHY `msg` is a reserved name (F16): a named frame called `msg` has exactly the 353 binding string.
    let trap = hand_named("msg", 0x82, "msg", b"anything", &a, Some([7; 8]));
    assert!(verifies_in_353(&trap).is_some(), "353 would verify a named frame called msg");
    assert_eq!(mesh_v11::frame_check(trap.as_bytes(), T0).err(), Some("name"), "1.1 rejects the name, and its builder refuses to make it");
    // WHY `ack` is reserved: the signature of a named frame called `ack` over payload P is also a
    // valid signature for a real ACK (flags 0x08) whose text is base64(P) — one signature, two frames.
    let named_ack = hand_named("ack", 0x80, "ack", b"body", &a, None);
    assert_eq!(mesh_v11::frame_check(named_ack.as_bytes(), T0).err(), Some("name"), "1.1 rejects the name");
    let named_blob = mrenzo_core::strict_json::b64(serde_json::from_str::<Value>(&named_ack).unwrap()["b"].as_str().unwrap()).unwrap();
    let (p_bytes, sig) = (&named_blob[43..named_blob.len() - 64], &named_blob[named_blob.len() - 64..]);
    let text = b64(p_bytes);
    let mut real_ack = vec![0x08u8];
    real_ack.extend_from_slice(&a.ed_pub);
    real_ack.extend_from_slice(&(a.uid as u64).to_be_bytes());
    real_ack.extend_from_slice(&(text.len() as u16).to_be_bytes());
    real_ack.extend_from_slice(text.as_bytes());
    real_ack.extend_from_slice(sig);
    // (ttl 7 and L 4 of the hand-made frame are not an ACK profile, so 1.1 refuses this one too; 353 has no profile.)
    let transplanted = format!("{{\"v\":2,\"id\":\"hand-1\",\"ttl\":7,\"hops\":0,\"L\":4,\"mode\":\"realtime\",\"ts\":{T0},\"b\":\"{}\"}}", b64(&real_ack));
    let seen = verifies_in_353(&transplanted).expect("353 verifies the transplanted signature as a real ACK");
    assert_eq!((seen.kind, seen.payload.as_str()), (Some(m353::MeshKind::Ack), text.as_str()));
    assert!(mesh_v11::frame_check(transplanted.as_bytes(), T0).is_err());

    // The blind ACK: 353 verifies it (the signature is good under the embedded key) and finds
    // no pin for uid 0 (`MeshService.swift:448-452`), so it does nothing with it.
    let ack2 = mesh_v11::build_ack2(&mesh_ack_seed(&[4; 32], "m-1"), "m-1", T0 as u64, &mut StreamRng::new("mc/ack2")).unwrap();
    let seen = verifies_in_353(&ack2).expect("353 verifies a blind ACK");
    assert_eq!((seen.kind, seen.from.uid), (Some(m353::MeshKind::Ack), 0.0));
    // And every frame 353 originates passes the strict check of 1.1.
    let old_msg = m353::build_mesh_envelope_from_ratchet(0, &b64(&b.ik.private), &b64(&a.ik.public), wire, m353::MeshMode::Pigeon,
        &m353::MeshIdentity { from_uid: b.uid, sign_priv_b64: b64(&b.ed_secret), sign_pub_b64: b64(&b.ed_pub) }, Some("o-1"), T0, &mut StreamRng::new("mc/old")).unwrap().unwrap();
    let old_json = m353::pack_mesh_outer_json(&old_msg).unwrap();
    let f = mesh_v11::frame_check(old_json.as_bytes(), T0).expect("a 353 msg passes the strict check");
    assert_eq!(mesh_v11::msg_envelope(&f).as_deref(), Some(wire));
    assert!(mesh_v11::to_idx_matches(&f, &a.ik.private, &b.ik.public));
    let old_ack = m353::build_mesh_ack(0, "o-1.tagtagtagtagtagx", &m353::MeshIdentity { from_uid: a.uid, sign_priv_b64: b64(&a.ed_secret), sign_pub_b64: b64(&a.ed_pub) }, T0, &mut StreamRng::new("mc/oldack")).unwrap().unwrap();
    assert_eq!(mesh_v11::frame_check(m353::pack_mesh_outer_json(&old_ack).unwrap().as_bytes(), T0).unwrap().kind, mesh_v11::FrameKind::Ack);
}

// ───────────────────────────── 5 ─────────────────────────────

/// `MeshFrameCore.admitFrameId` (712e1dcc `Mesh/MeshFrameCore.swift:12-13`,
/// `:66-73`): a duplicate id is free; a new id costs one slot of the peer's
/// 30-per-60-s window BEFORE anything is verified; the 31st is dropped and
/// not marked seen.
struct Radio353 {
    seen: std::collections::HashSet<String>,
    window: Vec<i64>,
}

#[derive(Debug, PartialEq)]
enum Admit353 {
    New,
    Duplicate,
    RateLimited,
}

impl Radio353 {
    fn new() -> Radio353 {
        Radio353 { seen: Default::default(), window: Vec::new() }
    }

    /// One frame off the link (`BleMeshTransport.swift:310-333`, `MultipeerTransport.swift:162-180`).
    fn receive(&mut self, frame_json: &str, now_ms: i64) -> Admit353 {
        let object: Value = serde_json::from_str(frame_json).unwrap_or(Value::Null);
        if object.get("hello").is_some() {
            // BLE reads only `name`; either way one slot.
            self.slot(now_ms);
            return Admit353::New;
        }
        let Some(id) = object.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()) else {
            self.slot(now_ms); // «malformed»: still one slot
            return Admit353::RateLimited;
        };
        if self.seen.contains(id) {
            return Admit353::Duplicate;
        }
        if !self.slot(now_ms) {
            return Admit353::RateLimited;
        }
        self.seen.insert(id.to_string());
        Admit353::New
    }

    fn slot(&mut self, now_ms: i64) -> bool {
        self.window.retain(|t| now_ms - t < 60_000);
        if self.window.len() >= 30 {
            return false;
        }
        self.window.push(now_ms);
        true
    }
}

#[test]
fn thirty_ptt_frames_then_a_message_on_a_353_link() {
    let (a, b) = (alice(), bob());
    let signer = Signer { uid: a.uid as u64, ed_secret64: &a.ed_secret };
    let ptt_id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let segments: Vec<String> = (0..30u32)
        .map(|seq| {
            let chunk = ptt::seal_chunk(&[1; 32], seq, seq == 29, &[vec![7; 40]], &mut StreamRng::new(&format!("air/{seq}"))).unwrap();
            mesh_v11::build_ptt_frame(signer, &a.ik.private, &b.ik.public, ptt_id, seq, seq == 29, None, &chunk, (T0 + seq as i64 * 1000) as u64).unwrap()
        })
        .collect();
    let wire = r#"{"v":3,"dh":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","pn":0,"n":0,"ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
    let msg = pack_mesh_outer_json(&build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), wire, MeshMode::Realtime, &identity(&a), Some("m-after"), T0 + 30_000, &mut StreamRng::new("air/msg")).unwrap().unwrap()).unwrap();

    // THE TRAP: a talker that writes its segments to a 353 neighbour's link.
    let mut bob_353 = Radio353::new();
    for (seq, frame) in segments.iter().enumerate() {
        assert_eq!(bob_353.receive(frame, T0 + seq as i64 * 1000), Admit353::New, "each segment has a fresh id and costs a slot");
        assert!(verifies_in_353(frame).is_none(), "…before 353 rejects its signature");
    }
    assert_eq!(bob_353.receive(&msg, T0 + 30_000), Admit353::RateLimited, "the real message that follows is dropped by the radio: the talker's link is exhausted");

    // THE RULE (wire-1.1 §W8.3): named frames go only to links whose peer announced w ≥ 2.
    let hello_353 = br#"{"hello":1,"name":"A1B2C3D4"}"#;
    let peer_level = mesh_v11::link_hello_parse(hello_353).unwrap().w;
    assert_eq!(peer_level, 1, "a 353 node announces no level");
    let mut bob_353 = Radio353::new();
    for (seq, frame) in segments.iter().enumerate() {
        if peer_level >= 2 {
            bob_353.receive(frame, T0 + seq as i64 * 1000);
        }
    }
    assert_eq!(bob_353.receive(&msg, T0 + 30_000), Admit353::New, "with the rule the message is admitted");
    assert!(verifies_in_353(&msg).is_some());

    // The 1.1 hello itself is harmless to 353: BLE reads `name` and ignores `w`; MPC counts one malformed frame.
    let mut radio = Radio353::new();
    assert_eq!(radio.receive(&mesh_v11::link_hello_json(Some("A1B2C3D4")), T0), Admit353::New);
    let hello: Value = serde_json::from_str(&mesh_v11::link_hello_json(Some("A1B2C3D4"))).unwrap();
    assert_eq!(hello["name"], "A1B2C3D4");
    assert_eq!(radio.window.len(), 1, "one slot");
    let mut mpc = Radio353::new();
    assert_eq!(mpc.receive(&mesh_v11::link_hello_json(None).replace("\"hello\":1,", ""), T0), Admit353::RateLimited, "MPC has no hello handling: a frame without id is «malformed»");
    assert_eq!(mpc.window.len(), 1, "one slot, nothing else");

    // On a level-2 link the transmission has its own budget and leaves the general one alone.
    let mut budget = mesh_v11::LinkBudget::new(T0);
    for (seq, frame) in segments.iter().enumerate() {
        let now = T0 + seq as i64 * 1000;
        let peek = mesh_v11::frame_peek(frame.as_bytes()).unwrap();
        assert!(peek.claims_ptt && budget.admit(true, now), "segment {seq} at one a second");
        assert!(mesh_v11::frame_check(frame.as_bytes(), now).is_ok());
    }
    assert!((0..30).all(|i| budget.admit(false, T0 + 30_000 + i)), "the general budget is untouched: 30 ordinary frames still pass");
}

/// The typed-plaintext classification of 1.1 agrees with the 353 parser on
/// everything 353 accepts (soft keys aside): no message 353 shows becomes a
/// notice row after the update.
#[test]
fn everything_353_accepts_is_typed_in_1_1() {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/ratchetV3.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let mut checked = 0;
    for step in v["steps"].as_array().unwrap() {
        let text = step["plaintext"].as_str().unwrap();
        let old = p353::parse_typed_plaintext(text).expect("a 1.0.0 vector plaintext");
        let Classified::Typed(new) = classify(text) else { panic!("1.1 does not type {text}") };
        assert_eq!(new.pt.to_json(), old.to_json());
        assert_eq!(new.soft, Soft::default());
        checked += 1;
    }
    assert!(checked >= 8);
    // The leniencies of the 353 struct parser that 1.1 keeps (an explicit null is an absent field).
    for text in [r#"{"t":"hello","id":"h","body":null,"reply":null,"expire":null}"#, r#"{"t":"chat","id":"m","body":"b","story":null,"fwd":null,"editOf":null}"#] {
        assert_eq!(p353::parse_typed_plaintext(text).is_some(), matches!(classify(text), Classified::Typed(_)), "{text}");
        assert!(p353::parse_typed_plaintext(text).is_some());
    }
    // And what 353 rejects stays rejected-as-a-kind (it is `unsupported` now, not a failure).
    for text in [r#"{"t":"chat","id":"x"}"#, r#"{"t":"edit","id":"x","body":"b"}"#, r#"{"t":"chat","id":"x","body":"b","expire":0}"#, r#"{"t":"chat","id":"x","body":"b","reply":{"id":"r","text":"t","name":"n","extra":1}}"#] {
        assert!(p353::parse_typed_plaintext(text).is_none() && matches!(classify(text), Classified::Unsupported(_)), "{text}");
    }
}
