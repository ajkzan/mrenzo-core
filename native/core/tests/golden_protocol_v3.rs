//! Protocol v3 vectors outside the ratchet itself: ratchetReset.json,
//! safetyNumbersV2.json, sdpSigningV2.json, meshV2.json, contactPairV2.json,
//! sealedSenderCert.json, senderKeysV3.json. Dual mode: see tests/common.

mod common;

use common::*;
use mrenzo_core::contact_pair::*;
use mrenzo_core::group_chains::*;
use mrenzo_core::mesh_envelope::*;
use mrenzo_core::plaintext::TypedPlaintext;
use mrenzo_core::primitives::{b64, KeyPair};
use mrenzo_core::ratchet::{b64_strict, b64_strict32, mesh_ack_matches, mesh_ack_payload, session_binding_mac, Envelope};
use mrenzo_core::ratchet_reset::{self, RatchetReset, ResetVerify};
use mrenzo_core::rng::StreamRng;
use mrenzo_core::safety_numbers::*;
use mrenzo_core::sdp_signing::*;
use mrenzo_core::sealed_sender::verify_cert;
use mrenzo_core::sender_keys::{build_skdm, generate_sender_key, SkContext, PLACEHOLDER_UNDECRYPTABLE};
use mrenzo_core::session_set::{PeerSessions, SetDecrypt};
use mrenzo_core::x3dh::{generate_signed_pre_key_v2, BundleV2};
use serde_json::{json, Value};

#[test]
fn ratchet_reset_vectors() {
    let (a, b) = (alice(), bob());
    let dh = b64_strict32(&b64(&[9u8; 32])).unwrap();
    let rr = ratchet_reset::sign(&a.ed_secret, a.uid, b.uid, &dh, T0, &mut StreamRng::new("v3/reset"));
    let canonical = ratchet_reset::canonical(a.uid, b.uid, rr.ts, &rr.nonce, &dh);
    assert_eq!(ratchet_reset::verify(&a.ed_pub, a.uid, b.uid, &rr, T0 + 1000), ResetVerify::Ok);
    assert_eq!(RatchetReset::parse(&rr.to_json()).unwrap(), rr);
    // A server forging the reset (no ED), relabelling it or replaying it late.
    assert_eq!(ratchet_reset::verify(&b.ed_pub, a.uid, b.uid, &rr, T0), ResetVerify::BadSignature);
    assert_eq!(ratchet_reset::verify(&a.ed_pub, carol().uid, b.uid, &rr, T0), ResetVerify::BadSignature);
    assert_eq!(ratchet_reset::verify(&a.ed_pub, a.uid, carol().uid, &rr, T0), ResetVerify::BadSignature);
    let mut other_dh = rr.clone();
    other_dh.dh = [8u8; 32];
    assert_eq!(ratchet_reset::verify(&a.ed_pub, a.uid, b.uid, &other_dh, T0), ResetVerify::BadSignature);
    assert_eq!(ratchet_reset::verify(&a.ed_pub, a.uid, b.uid, &rr, T0 + 10 * 60 * 1000 + 1), ResetVerify::Stale);
    assert!(RatchetReset::parse(&rr.to_json().replace("\"v\":2", "\"v\":1")).is_none());

    let mut v = header(
        "ratchetReset",
        &[
            "canonical = \"mrenzo-ratchet-reset-v2|\" + from + \"|\" + to + \"|\" + ts + \"|\" + nonce + \"|\" + dh; sig = Ed25519(ED_from, canonical).",
            "dh = the ratchet key (envelope `dh`) of the message that could not be decrypted; the receiver archives the LIVE session whose current or previous sending key is dh — anything else is a no-op (reset.noMatch), so a reset never loops.",
            "Receiver: pinned + confirmed ED of the server-stamped sender, |now − ts| ≤ 10 min, nonce not among the last 32 seen from that peer.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert(
        "reset".into(),
        json!({"rngLabel": "v3/reset", "from": a.uid, "to": b.uid, "dhB64": b64(&dh), "canonical": canonical, "rrJson": rr.to_json(),
               "verify": {"ok": true, "signedByBob": false, "fromCarol": false, "toCarol": false, "otherDh": false, "after10min": "stale"}}),
    );
    check_or_write("ratchetReset.json", &serde_json::Value::Object(v));
}

#[test]
fn safety_numbers_v2_vectors() {
    let (a, b) = (alice(), bob());
    let pa = IdentityPair { ik: a.ik.public, ed: a.ed_pub };
    let pb = IdentityPair { ik: b.ik.public, ed: b.ed_pub };
    let n = safety_number_v2(&pa, &pb);
    assert_eq!(n, safety_number_v2(&pb, &pa), "symmetric");
    assert_eq!(n.len(), 35);
    let other_ed = IdentityPair { ed: carol().ed_pub, ..pb };
    assert_ne!(n, safety_number_v2(&pa, &other_ed), "the signing key is covered");
    let (sa, sb) = ([1u8; 32], [2u8; 32]);
    let pair = pair_safety_number_v2(&pa, &sa, &pb, &sb);
    assert_eq!(pair, pair_safety_number_v2(&pb, &sb, &pa, &sa));
    assert_ne!(pair, n);
    assert_eq!(safety_number_v2_b64(&b64(&a.ik.public), &b64(&a.ed_pub), &b64(&b.ik.public), &b64(&b.ed_pub)).unwrap(), n);
    assert!(safety_number_v2_b64("AA==", &b64(&a.ed_pub), &b64(&b.ik.public), &b64(&b.ed_pub)).is_err());
    let mut v = header(
        "safetyNumbersV2",
        &[
            "K = IK(32) ‖ ED(32) per side; (x, y) = bytewise sort; d = SHA-512(\"mrenzo-safety-v2\" ‖ x ‖ y); 6 blocks of BE_uint40(d[5i..5i+5]) mod 100000, zero-padded to 5, joined by spaces.",
            "Pair number (in-person pairing): the same with the two sorted 32-byte seeds appended after y.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert("safetyNumber".into(), json!(n));
    v.insert("pair".into(), json!({"aliceSeedB64": b64(&sa), "bobSeedB64": b64(&sb), "number": pair}));
    check_or_write("safetyNumbersV2.json", &serde_json::Value::Object(v));
}

const SDP: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:sha-256 AB:CD:EF\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";

#[test]
fn sdp_signing_v2_vectors() {
    let (a, b) = (alice(), bob());
    let sid = [5u8; 32];
    let archived = [6u8; 32];
    let s = sign_sdp_v2(SDP, "offer", &a.ed_secret, a.uid, "1002", "call-1", Some(&sid), T0, &mut StreamRng::new("v3/sdp")).unwrap();
    let data = sdp_wire_data_v2("offer", SDP, &s, "1002", "call-1");
    let fp = extract_sdp_fingerprints(SDP);
    let payload = payload_v2(&fp, s.ts, &s.nonce, a.uid, "1002", "call-1", "offer");
    assert_eq!(s.rb.as_deref(), Some(session_binding_mac(&sid, &payload).as_str()));
    let expect = SdpExpectV2 { from: a.uid, to: "1002".into(), sdp_type: "offer".into(), call_id: "call-1".into(), require_rb: true };
    let check = |d: &Value, e: &SdpExpectV2, ed: Option<&[u8; 32]>, sessions: &[[u8; 32]]| verify_sdp_v2(d, e, ed, sessions, T0 + 5);
    let mut outcomes = serde_json::Map::new();
    let mut rec = |name: &str, r: SdpVerificationV2, want: &str| {
        assert_eq!(r.reason, want, "{name}");
        outcomes.insert(name.into(), json!(want));
    };
    rec("ok", check(&data, &expect, Some(&a.ed_pub), &[sid]), "ok");
    let r = check(&data, &expect, Some(&a.ed_pub), &[archived, sid]);
    assert_eq!(r.rb, RbCheckV2::Match { index: 1 });
    rec("rbArchivedOk", r, "ok");
    let mut no_rb = data.clone();
    no_rb.as_object_mut().unwrap().remove("rb");
    rec("rbMissing", check(&no_rb, &expect, Some(&a.ed_pub), &[sid]), "rb-missing");
    rec("rbNoSession", check(&data, &expect, Some(&a.ed_pub), &[]), "rb-no-session");
    rec("rbMismatch", check(&data, &expect, Some(&a.ed_pub), &[archived]), "rb-mismatch");
    rec("callIdMismatch", check(&data, &SdpExpectV2 { call_id: "call-2".into(), ..expect.clone() }, Some(&a.ed_pub), &[sid]), "callId-mismatch");
    rec("toUserIdMismatch", check(&data, &SdpExpectV2 { to: "1003".into(), ..expect.clone() }, Some(&a.ed_pub), &[sid]), "to-mismatch");
    rec("typeMismatch", check(&data, &SdpExpectV2 { sdp_type: "answer".into(), ..expect.clone() }, Some(&a.ed_pub), &[sid]), "type-mismatch");
    rec("fromMismatch", check(&data, &SdpExpectV2 { from: 1003, ..expect.clone() }, Some(&a.ed_pub), &[sid]), "userId-mismatch");
    rec("wrongSigningKey", check(&data, &expect, Some(&b.ed_pub), &[sid]), "signature-mismatch");
    rec("noPinnedKey", check(&data, &expect, None, &[sid]), "peer-signing-key-unavailable");
    let mut no_pv = data.clone();
    no_pv.as_object_mut().unwrap().remove("pv");
    rec("pvMissing", check(&no_pv, &expect, Some(&a.ed_pub), &[sid]), "pv");
    let mut stale = data.clone();
    stale["ts"] = json!(T0 - 61_000);
    rec("tsSkew", check(&stale, &expect, Some(&a.ed_pub), &[sid]), "ts-skew");
    // Reflection: the same signed offer delivered as an answer, or to Carol.
    let mut reflected = data.clone();
    reflected["type"] = json!("answer");
    rec("reflectedAsAnswer", check(&reflected, &SdpExpectV2 { sdp_type: "answer".into(), ..expect.clone() }, Some(&a.ed_pub), &[sid]), "signature-mismatch");
    // Rooms: toUserId = callId = roomId, signature only.
    let room = sign_sdp_v2(SDP, "answer", &a.ed_secret, a.uid, "abc-def-ghi-jkl", "abc-def-ghi-jkl", None, T0, &mut StreamRng::new("v3/sdp-room")).unwrap();
    let room_data = sdp_wire_data_v2("answer", SDP, &room, "abc-def-ghi-jkl", "abc-def-ghi-jkl");
    let room_expect = SdpExpectV2 { from: a.uid, to: "abc-def-ghi-jkl".into(), sdp_type: "answer".into(), call_id: "abc-def-ghi-jkl".into(), require_rb: false };
    rec("roomOk", check(&room_data, &room_expect, Some(&a.ed_pub), &[]), "ok");

    let mut v = header(
        "sdpSigningV2",
        &[
            "payload = fp|ts|nonce|fromUserId|toUserId|callId|type|2; sig = Ed25519(ED, payload); rb = b64(HKDF(sid, \"mrenzo-ratchet-bind-v2|\" + payload)).",
            "data = {type, sdp, sig, ts, nonce, fromUserId, toUserId, callId, pv:2, rb}; 1:1 calls require rb to match the live or an archived session (live first).",
            "Rooms sign with toUserId = callId = roomId and are verified by signature only (no 1:1 session).",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert("sessionIdB64".into(), json!(b64(&sid)));
    v.insert("archivedSessionIdB64".into(), json!(b64(&archived)));
    v.insert("sdp".into(), json!(SDP));
    v.insert("offer".into(), json!({"rngLabel": "v3/sdp", "nowMs": T0, "payload": payload, "data": data}));
    v.insert("room".into(), json!({"rngLabel": "v3/sdp-room", "data": room_data}));
    v.insert("verifyAtMs".into(), json!(T0 + 5));
    v.insert("verify".into(), Value::Object(outcomes));
    check_or_write("sdpSigningV2.json", &serde_json::Value::Object(v));
}

fn mesh_identity(i: &Ident) -> MeshIdentity {
    MeshIdentity { from_uid: i.uid, sign_priv_b64: b64(&i.ed_secret), sign_pub_b64: b64(&i.ed_pub) }
}

#[test]
fn mesh_v2_vectors() {
    let (a, b) = (alice(), bob());
    let wire = "{\"v\":3}"; // any payload text; the pipeline decrypts it later
    let env = build_mesh_envelope_from_ratchet(0, &b64(&a.ik.private), &b64(&b.ik.public), wire, MeshMode::Pigeon, &mesh_identity(&a), Some("m-1"), T0, &mut StreamRng::new("v3/mesh"))
        .unwrap()
        .unwrap();
    assert!(verify_mesh_envelope(&env));
    let outer = pack_mesh_outer_json(&env).unwrap();
    let unpacked = unpack_mesh_outer(&serde_json::from_str(&outer).unwrap()).unwrap().unwrap();
    assert!(verify_mesh_envelope(&unpacked), "the unpacked frame verifies");
    // A relay may bump hops, nothing else.
    let mut hopped = unpacked.clone();
    hopped.hops += 1.0;
    assert!(verify_mesh_envelope(&hopped));
    let mutate = |f: &dyn Fn(&mut MeshEnvelope)| {
        let mut e = unpacked.clone();
        f(&mut e);
        verify_mesh_envelope(&e)
    };
    assert!(!mutate(&|e| e.ttl += 1.0), "ttl");
    assert!(!mutate(&|e| e.l = Some(8.0)), "L");
    assert!(!mutate(&|e| e.l = None), "L removed");
    assert!(!mutate(&|e| e.mode = MeshMode::Realtime), "mode");
    assert!(!mutate(&|e| e.to_idx = Some(b64(&[1u8; 8]))), "toIdx re-targeted");
    assert!(!mutate(&|e| e.to = 1002.0), "to");
    assert!(!mutate(&|e| e.kind = Some(MeshKind::Ack)), "kind");
    assert!(!mutate(&|e| e.v = json!(1)), "v1");
    assert!(!mutate(&|e| e.ts = T0 as f64 + 0.5), "non-integer");
    // ACK: payload = id + "." + tag under the session id.
    let sid = [3u8; 32];
    let ack_payload = mesh_ack_payload(&sid, "m-1");
    assert_eq!(mesh_ack_matches(&sid, &ack_payload).as_deref(), Some("m-1"));
    assert_eq!(mesh_ack_matches(&[4u8; 32], &ack_payload), None, "a tag under another session");
    assert_eq!(mesh_ack_matches(&sid, "m-1"), None, "an untagged (pre-349) ACK");
    let ack = build_mesh_ack(0, &ack_payload, &mesh_identity(&b), T0, &mut StreamRng::new("v3/mesh-ack")).unwrap().unwrap();
    assert!(verify_mesh_envelope(&ack));
    let ack_outer = pack_mesh_outer_json(&ack).unwrap();

    let mut v = header(
        "meshV2",
        &[
            "Outer {\"v\":2,\"id\",\"ttl\",\"hops\",\"L\"?,\"mode\",\"ts\",\"b\"}; inner blob layout unchanged (04 §5).",
            "binding = \"mrenzo-mesh-v2|\" + id|ts|from.uid|to|(toIdx or -)|ttl|(L or -)|mode|kind|payload, signed with the sender's ED; only hops is outside it.",
            "Receiver: sig_pub MUST equal the PINNED signing key of from.uid (an unpinned sender's msg is held, its ACK dropped).",
            "ACK payload = id + \".\" + b64(HMAC-SHA256(HKDF(sid, \"mrenzo-mesh-ack-v2\"), id))[..16], sid = the session the message was decrypted under.",
            "to is 0 on the air: the recipient is addressed only by toIdx.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert(
        "msg".into(),
        json!({"rngLabel": "v3/mesh", "nowMs": T0, "payloadText": wire, "binding": signed_binding(&env), "outerJson": outer, "envelopeJson": env.to_json()}),
    );
    v.insert("ack".into(), json!({"rngLabel": "v3/mesh-ack", "sessionIdB64": b64(&sid), "payload": ack_payload, "binding": signed_binding(&ack), "outerJson": ack_outer}));
    v.insert("rejected".into(), json!(["ttl", "L", "L removed", "mode", "toIdx", "to", "kind", "v1", "non-integer ts"]));
    check_or_write("meshV2.json", &serde_json::Value::Object(v));
}

#[test]
fn contact_pair_v2_vectors() {
    let a = alice();
    let link = PairLink { uid: a.uid, username: Some("alice".into()) };
    let link_url = encode_link(&link);
    assert_eq!(decode_pair_url(&link_url), Some(PairPayload::Link(link.clone())));
    let seed = [0x5a; 32];
    let scan = sign_scan(a.uid, Some("alice".into()), Some("Alice".into()), a.ik.public, &a.ed_secret, seed, T0);
    assert!(verify_scan(&scan));
    let scan_url = encode_scan(&scan);
    assert_eq!(decode_pair_url(&scan_url), Some(PairPayload::Scan(scan.clone())));
    // Tampering: another uid under the same signature, a v1 link, keys without a signature.
    let forged = PairScan { uid: 1003, ..scan.clone() };
    assert!(!verify_scan(&forged));
    assert_eq!(decode_pair_url(&encode_scan(&forged)), None);
    let b64url = |j: &str| {
        use base64::Engine;
        format!("mrenzo://pair/{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(j))
    };
    let v1 = b64url(&format!("{{\"v\":1,\"uid\":{},\"ipk\":\"{}\",\"spk\":\"{}\",\"seed\":\"{}\",\"ts\":{T0}}}", a.uid, scan.ipk, scan.spk, scan.seed));
    assert_eq!(decode_pair_url(&v1), None);
    let unsigned = b64url(&format!("{{\"v\":2,\"uid\":{},\"ipk\":\"{}\",\"spk\":\"{}\",\"seed\":\"{}\",\"ts\":{T0}}}", a.uid, scan.ipk, scan.spk, scan.seed));
    assert_eq!(decode_pair_url(&unsigned), None, "a link with keys but no signature");
    let extra = b64url(&format!("{{\"v\":2,\"uid\":{},\"ipk\":\"{}\"}}", a.uid, scan.ipk));
    assert_eq!(decode_pair_url(&extra), None, "a key-less link must carry no key at all");

    let mut v = header(
        "contactPairV2",
        &[
            "Link (deep link, paste, https): mrenzo://pair/ + base64url(no padding) of {\"v\":2,\"uid\",\"username\"?} — no keys; opening it is an online directory lookup.",
            "Scan (in-app QR only): {\"v\":2,\"uid\",\"username\"?,\"displayName\"?,\"ipk\",\"spk\",\"seed\",\"ts\",\"sig\"}, sig = Ed25519(spk, \"mrenzo-pair-v2|\" + uid|ipk|spk|seed|ts) over the base64 strings.",
            "Rejected: v1, unknown keys, keys without sig, a bad sig, non-canonical base64.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json()}));
    v.insert("link".into(), json!({"uid": a.uid, "username": "alice", "url": link_url}));
    v.insert(
        "scan".into(),
        json!({"seedB64": b64(&seed), "ts": T0, "signedText": scan_signed_text(scan.uid, &scan.ipk, &scan.spk, &scan.seed, scan.ts), "sigB64": scan.sig, "url": scan_url}),
    );
    v.insert("rejected".into(), json!({"forgedUid": encode_scan(&forged), "v1": v1, "unsignedKeys": unsigned, "linkWithKey": extra}));
    check_or_write("contactPairV2.json", &serde_json::Value::Object(v));
}

#[test]
fn sealed_sender_cert_vectors() {
    use mrenzo_core::sealed_sender::issue_cert;
    let server = Ident::new("v3/server", 0);
    let a = alice();
    let cert = issue_cert(&server.ed_secret, a.uid, &b64(&a.ik.public), T0).unwrap();
    let good = cert.to_value();
    let key = b64(&server.ed_pub);
    assert!(verify_cert(&good, &key, T0));
    let exp = good["expires_at_ms"].as_u64().unwrap();
    let mut cases = serde_json::Map::new();
    let mut case = |name: &str, cert: Value, now: i64, want: bool| {
        assert_eq!(verify_cert(&cert, &key, now), want, "{name}");
        cases.insert(name.into(), json!({"certJson": cert.to_string(), "nowMs": now, "expected": want}));
    };
    case("genuine", good.clone(), T0, true);
    case("expired", good.clone(), exp as i64 + 1, false);
    let with = |k: &str, v: Value| {
        let mut c = good.clone();
        c[k] = v;
        c
    };
    // exp + 2^64 (as a JSON number, exact in the text) signed mod 2^64 by RN.
    let wrapped: Value = serde_json::from_str(&good.to_string().replace(&format!("\"expires_at_ms\":{exp}"), &format!("\"expires_at_ms\":{}", exp as u128 + (1u128 << 64)))).unwrap_or(Value::Null);
    if !wrapped.is_null() {
        case("expPlus2pow64", wrapped, exp as i64 + 1, false);
    }
    case("expAsString", with("expires_at_ms", json!(exp.to_string())), T0, false);
    case("expAsFloat", with("expires_at_ms", json!(exp as f64 + 0.5)), T0, false);
    case("expNegative", with("expires_at_ms", json!(-1)), T0, false);
    case("uidAsString", with("uid", json!(a.uid.to_string())), T0, false);
    case("uidFloat", with("uid", json!(1001.0)), T0, false);
    let mut v = header(
        "sealedSenderCert",
        &[
            "uid and expires_at_ms MUST be JSON integers in [0, 2^53); each is parsed once and the same values feed the expiry check and the signed payload BE64(uid) ‖ BE64(exp) ‖ ASCII(sender_pub). Anything else is false.",
            "The Go issuer is unchanged; certs are valid 24 h.",
        ],
    );
    v.insert("serverSigningPubB64".into(), json!(key));
    v.insert("cases".into(), Value::Object(cases));
    check_or_write("sealedSenderCert.json", &serde_json::Value::Object(v));
}

#[test]
fn sender_keys_v3_vectors() {
    let (a, b) = (alice(), bob());
    // The SKDM rides as typed plaintext t:"skdm" on a v3 prekey message.
    let chain = generate_sender_key(&mut StreamRng::new("v3/sk-chain"));
    let skdm = build_skdm("g-1", &chain, a.uid).unwrap();
    let skdm_obj: Value = serde_json::from_str(&skdm.to_json()).unwrap();
    let pt = TypedPlaintext::Skdm { id: "skdm-1".into(), body: skdm_obj.as_object().unwrap().clone() };
    let g = generate_signed_pre_key_v2(&b.ed_secret, 9, &mut StreamRng::new("v3/sk-bob-spk"));
    let spk = KeyPair { public: b64_strict32(&g.pub_key).unwrap(), private: b64_strict32(&g.priv_key).unwrap() };
    let bundle = BundleV2 { spk_id: 9, spk_pub: spk.public, spk_sig: b64_strict(&g.signature).unwrap().try_into().unwrap(), opk: None };
    let mut sa = PeerSessions::default();
    sa.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &bundle, T0, &mut StreamRng::new("v3/sk-x3dh")).unwrap();
    let wire = sa.encrypt(&pt.to_json(), T0, &mut StreamRng::new("v3/sk-skdm")).unwrap().to_wire();
    let frame = skdm_v2_frame_json(b.uid, "skdm-1", &wire);
    let mut sb = PeerSessions::default();
    let env = Envelope::parse(&wire).unwrap();
    let SetDecrypt::Opened { plaintext, .. } = sb
        .respond_and_decrypt(&env, &b.ik, &b.ed_pub, &spk, None, &a.ik.public, &a.ed_pub, T0, &mut StreamRng::new("probe"))
        .unwrap()
    else {
        panic!()
    };
    let TypedPlaintext::Skdm { body, .. } = mrenzo_core::plaintext::parse_typed_plaintext(&plaintext).unwrap() else { panic!() };
    let valid = validate_skdm(&Value::Object(body.clone()), a.uid).unwrap();
    assert_eq!(validate_skdm(&Value::Object(body.clone()), carol().uid), Err(IngestError::FromMismatch));
    let set = ingest_skdm_v2(&ChainSet::default(), &valid).set;

    // An sk2 post by Alice in g-1.
    let post_pt = TypedPlaintext::Chat { id: "p-1".into(), body: "hi group".into(), reply: None, fwd: None, expire: None, story: None }.to_json();
    let out = encrypt_outgoing("g-1", a.uid, &chain, &post_pt, &mut StreamRng::new("v3/sk-post")).unwrap();
    let ctx = SkContext { group_id: "g-1", sender_uid: a.uid };
    let opened = decrypt_with_chains(&set, &out.wire, &ctx);
    assert_eq!(opened.kind, GroupDecryptKind::Opened);
    assert_eq!(opened.text, post_pt);
    assert_eq!(decrypt_with_chains(&set, &out.wire, &SkContext { sender_uid: carol().uid, ..ctx }).kind, GroupDecryptKind::Failed);
    assert_eq!(decrypt_with_chains(&set, &out.wire, &SkContext { group_id: "g-2", ..ctx }).kind, GroupDecryptKind::Failed);
    assert_eq!(decrypt_with_chains(&set, &out.wire.replacen("sk2:", "sk1:", 1), &ctx).text, PLACEHOLDER_UNDECRYPTABLE);

    let mut v = header(
        "senderKeysV3",
        &[
            "SKDM v2 = typed plaintext {\"t\":\"skdm\",\"id\",\"body\":{\"v\":2,\"groupId\",\"chainKey\",\"signingPub\",\"startCounter\",\"from\"}} on a v3 ratchet message; frame action sender-key-distribution, skdmTransport 3.",
            "body.from MUST equal the server-stamped sender; skdmTransport ≠ 3 or v ≠ 2 is rejected (not counted).",
            "Post = \"sk2:\" + {\"v\":2,\"ctr\",\"n\",\"ct\",\"sig\"}; sig = Ed25519(chain signing key, \"mrenzo-sk2|\" + groupId + \"|\" + senderUid + \"|\" ‖ BE64(ctr) ‖ ct), groupId/senderUid taken from where the post arrived, never from the envelope.",
            "Chain KDFs unchanged: message key = HKDF(chainKey, \"mrenzo-sender-msg\"), next = HMAC(chainKey, 0x02).",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert("skdm".into(), json!({"chainRngLabel": "v3/sk-chain", "json": skdm.to_json(), "typedPlaintext": pt.to_json(), "frameJson": frame}));
    v.insert("post".into(), json!({"rngLabel": "v3/sk-post", "groupId": "g-1", "senderUid": a.uid, "plaintext": post_pt, "wire": out.wire}));
    v.insert("rejected".into(), json!(["other senderUid", "other groupId", "sk1 prefix", "SKDM from ≠ sender", "SKDM v1"]));
    check_or_write("senderKeysV3.json", &serde_json::Value::Object(v));
}
