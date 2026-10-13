//! Replays docs/native/vectors/offlineSeal.json — server `OSB1:` blobs opened
//! by the RN client's production `openSealedOffline` — against the Rust port,
//! byte for byte, in both directions (seal with the recorded draws, open the
//! recorded blob), plus every recorded open case.

use mrenzo_core::offline_seal::*;
use mrenzo_core::primitives::{b64, b64d, b64d32, ed25519_public_from_secret64, sha256, x25519_base};
use mrenzo_core::rng::ReplayRng;
use serde_json::{json, Value};

fn v() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/offlineSeal.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("offlineSeal.json")).unwrap()
}

fn s(x: &Value) -> &str {
    x.as_str().unwrap_or_else(|| panic!("expected string, got {x}"))
}

fn draws(rng: &Value) -> Vec<Vec<u8>> {
    rng["draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let b = hex::decode(s(&d["hex"])).unwrap();
            assert_eq!(b.len() as u64, d["n"].as_u64().unwrap(), "draw n/hex length");
            b
        })
        .collect()
}

fn replay(rng: &Value) -> ReplayRng {
    ReplayRng::new(s(&rng["label"]), draws(rng))
}

fn bob_priv_b64(v: &Value) -> &str {
    s(&v["keys"]["bob"]["x25519PrivB64"])
}

/// Every top-level section is accounted for: a new section in the vector file
/// must get a test here before this passes.
#[test]
fn header_and_section_inventory() {
    let v = v();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "area", "encodings", "generator", "innerJson", "keys", "layout", "notes", "openCases", "rng", "schema",
            "sealed", "sources",
        ]
    );
    assert_eq!(s(&v["area"]), "offlineSeal");
    assert_eq!(v["schema"], json!(1));
    assert_eq!(s(&v["generator"]), "mobile/src/__tests__/goldenVectors.test.ts");
    assert!(s(&v["encodings"]).contains("*B64"));
    assert_eq!(v["sources"].as_array().unwrap().len(), 3);
    assert!(v["sources"].as_array().unwrap().iter().any(|x| s(x).contains("openSealedOffline")));
    assert!(v["notes"].as_array().unwrap().iter().any(|x| s(x).contains("ephemeral pub FIRST")));
    let bob_keys: Vec<&String> = v["keys"].as_object().unwrap().keys().collect();
    assert_eq!(bob_keys, ["bob"]);
}

#[test]
fn keys_are_consistent() {
    let v = v();
    let bob = &v["keys"]["bob"];
    assert_eq!(bob["uid"], json!(2002));
    let x_priv = b64d32(s(&bob["x25519PrivB64"])).unwrap();
    assert_eq!(b64(&x25519_base(&x_priv)), s(&bob["x25519PubB64"]));
    let ed_priv: [u8; 64] = b64d(s(&bob["ed25519PrivB64"])).unwrap().try_into().unwrap();
    assert_eq!(b64(&ed25519_public_from_secret64(&ed_priv)), s(&bob["ed25519PubB64"]));
}

/// The recorded draws are the README PRNG stream for the recorded label:
/// SHA-256(UTF-8("mrenzo-golden-prng-v1|" + label) || be32(i)), read contiguously.
#[test]
fn rng_draws_are_the_documented_prng_stream() {
    let v = v();
    let rng = &v["rng"];
    assert_eq!(s(&rng["label"]), "offlineSeal/server.sealOfflineBlob");
    let recorded = draws(rng);
    assert_eq!(recorded.iter().map(Vec::len).collect::<Vec<_>>(), [32, 24], "box.keyPair() then randomBytes(24)");
    let d = format!("mrenzo-golden-prng-v1|{}", s(&rng["label"])).into_bytes();
    let mut stream = Vec::new();
    for i in 0u32..2 {
        let mut block = d.clone();
        block.extend_from_slice(&i.to_be_bytes());
        stream.extend_from_slice(&sha256(&block));
    }
    assert_eq!(recorded.concat(), stream[..56].to_vec());
}

/// Producer side: the server construction with the recorded draws yields the
/// recorded blob byte for byte, consuming exactly the recorded draws.
#[test]
fn seal_is_byte_exact() {
    let v = v();
    let bob_pub = b64d32(s(&v["keys"]["bob"]["x25519PubB64"])).unwrap();
    let mut rng = replay(&v["rng"]);
    let sealed = seal_offline_blob(s(&v["innerJson"]).as_bytes(), &bob_pub, &mut rng);
    rng.assert_exhausted();
    assert_eq!(sealed, s(&v["sealed"]));
}

/// Layout: ephemeralPub(32) || nonce(24) || box — ephemeral FIRST; the
/// ephemeral pub is X25519-base of draw #1, the nonce is draw #2.
#[test]
fn layout_is_ephemeral_then_nonce_then_box() {
    let v = v();
    let sealed = s(&v["sealed"]);
    assert!(sealed.starts_with(OFFLINE_SEAL_MARKER));
    assert!(is_offline_sealed(sealed));
    assert!(!is_offline_sealed(s(&v["innerJson"])));
    let raw = b64d(&sealed[OFFLINE_SEAL_MARKER.len()..]).unwrap();
    let layout = &v["layout"];
    assert_eq!(layout.as_object().unwrap().len(), 3);
    assert_eq!(hex::encode(&raw[..32]), s(&layout["ephemeralPubHex"]));
    assert_eq!(hex::encode(&raw[32..56]), s(&layout["nonceHex"]));
    assert_eq!(hex::encode(&raw[56..]), s(&layout["boxHex"]));
    assert_eq!(raw.len(), 56 + BOX_OVERHEAD_LENGTH + s(&v["innerJson"]).len());

    let d = draws(&v["rng"]);
    let eph_priv: [u8; 32] = d[0].clone().try_into().unwrap();
    assert_eq!(hex::encode(x25519_base(&eph_priv)), s(&layout["ephemeralPubHex"]));
    assert_eq!(hex::encode(&d[1]), s(&layout["nonceHex"]));
}

/// Consumer side: the recorded blob opens to the exact innerJson string.
#[test]
fn open_recorded_blob() {
    let v = v();
    assert_eq!(open_sealed_offline(s(&v["sealed"]), bob_priv_b64(&v)).as_deref(), Some(s(&v["innerJson"])));
}

/// Every recorded open case, including the negatives (expected null).
#[test]
fn open_cases_exactly_as_recorded() {
    let v = v();
    let priv_b64 = bob_priv_b64(&v);
    let cases = v["openCases"].as_array().unwrap();
    let mut names = Vec::new();
    for c in cases {
        let name = s(&c["name"]);
        let got = open_sealed_offline(s(&c["input"]), priv_b64);
        let expected = match &c["expected"] {
            Value::Null => None,
            Value::String(x) => Some(x.as_str()),
            other => panic!("{name}: unexpected expected {other}"),
        };
        assert_eq!(got.as_deref(), expected, "case {name:?}");
        names.push(name);
    }
    assert_eq!(
        names,
        ["legacy plaintext passes through", "tampered box", "too short", "bad base64 after marker"]
    );

    // The negative inputs are what their names say, relative to the good blob.
    let raw = b64d(&s(&v["sealed"])[5..]).unwrap();
    let mut tampered = raw.clone();
    tampered[60] ^= 0x80; // inside the Poly1305 tag
    assert_eq!(s(&cases[1]["input"]), format!("OSB1:{}", b64(&tampered)));
    assert_eq!(s(&cases[2]["input"]), format!("OSB1:{}", b64(&raw[..MIN_SEALED_RAW_LEN - 1])));
    assert_eq!(s(&cases[0]["input"]), s(&v["innerJson"]));
}

/// Quirks of the production decoder beyond the recorded cases. Expected values
/// were confirmed by running the verbatim TS `openSealedOffline` body under
/// Node with the app's tweetnacl + tweetnacl-util.
#[test]
fn open_quirks_match_tweetnacl() {
    let v = v();
    let sealed = s(&v["sealed"]);
    let inner = s(&v["innerJson"]);
    let priv_b64 = bob_priv_b64(&v);

    // Non-canonical trailing bits are ACCEPTED (regex shape check + atob), both
    // in the blob ("…FnM=" → "…FnN=") and in the key ("…as=" → "…at=").
    assert!(sealed.ends_with("FnM="));
    let non_canon = format!("{}N=", &sealed[..sealed.len() - 2]);
    assert!(b64d(&non_canon[5..]).is_none(), "primitives::b64d is stricter than tweetnacl-util");
    assert_eq!(open_sealed_offline(&non_canon, priv_b64).as_deref(), Some(inner));
    assert!(priv_b64.ends_with("as="));
    let priv_nc = format!("{}t=", &priv_b64[..priv_b64.len() - 2]);
    assert_eq!(open_sealed_offline(sealed, &priv_nc).as_deref(), Some(inner));

    // ...but the shape is strict: extra padding / whitespace → null.
    assert_eq!(open_sealed_offline(&format!("{sealed}="), priv_b64), None);
    assert_eq!(open_sealed_offline(&format!("{sealed}\n"), priv_b64), None);
    assert_eq!(open_sealed_offline(&sealed.replacen("OSB1:", "OSB1: ", 1), priv_b64), None);

    // Legacy passthrough never looks at the key; the marker is case-sensitive.
    assert_eq!(open_sealed_offline("{\"a\":1}", "").as_deref(), Some("{\"a\":1}"));
    assert_eq!(open_sealed_offline("osb1:abc", priv_b64).as_deref(), Some("osb1:abc"));
    assert_eq!(open_sealed_offline("", priv_b64).as_deref(), Some(""));

    // Marked but unopenable → null: empty/garbage/wrong-size key, marker only.
    assert_eq!(open_sealed_offline(sealed, ""), None);
    assert_eq!(open_sealed_offline(sealed, "@@@"), None);
    assert_eq!(open_sealed_offline(sealed, s(&v["keys"]["bob"]["ed25519PrivB64"])), None);
    assert_eq!(open_sealed_offline(sealed, s(&v["keys"]["bob"]["x25519PubB64"])), None);
    assert_eq!(open_sealed_offline("OSB1:", priv_b64), None);

    // Exactly 72 bytes (empty plaintext) opens to "", invalid UTF-8 → null.
    let bob_pub = b64d32(s(&v["keys"]["bob"]["x25519PubB64"])).unwrap();
    let mut r = ReplayRng::new("empty", vec![vec![7; 32], vec![0; 24]]);
    let empty = seal_offline_blob(b"", &bob_pub, &mut r);
    r.assert_exhausted();
    assert_eq!(b64d(&empty[5..]).unwrap().len(), MIN_SEALED_RAW_LEN);
    assert_eq!(open_sealed_offline(&empty, priv_b64).as_deref(), Some(""));
    let mut r = ReplayRng::new("ff", vec![vec![7; 32], vec![0; 24]]);
    let bad_utf8 = seal_offline_blob(&[0xff], &bob_pub, &mut r);
    r.assert_exhausted();
    assert_eq!(open_sealed_offline(&bad_utf8, priv_b64), None);
    let mut r = ReplayRng::new("cesu", vec![vec![7; 32], vec![0; 24]]);
    let surrogate = seal_offline_blob(&[0xed, 0xa0, 0x80], &bob_pub, &mut r);
    r.assert_exhausted();
    assert_eq!(open_sealed_offline(&surrogate, priv_b64), None);
}

/// App.tsx:1126-1145 on the recorded blob plus the routing quirks (expected
/// values confirmed against the verbatim handler logic under Node).
#[test]
fn pending_sealed_handler() {
    let v = v();
    let priv_b64 = bob_priv_b64(&v);
    let inner: Value = serde_json::from_str(s(&v["innerJson"])).unwrap();
    let data = json!({ "toUserId": 2002, "blob": s(&v["sealed"]), "messageId": "m-offline-1", "ts": 1 });
    assert_eq!(
        handle_pending_sealed(Some(&data), Some(priv_b64)),
        PendingSealed::Dispatch { msg_type: "p2p-message".into(), data: inner.clone() }
    );
    // Gates, in handler order.
    assert_eq!(handle_pending_sealed(None, Some(priv_b64)), PendingSealed::Ignored);
    assert_eq!(handle_pending_sealed(Some(&json!("x")), Some(priv_b64)), PendingSealed::Ignored);
    for falsy in [json!(null), json!(""), json!(0), json!(false)] {
        assert_eq!(handle_pending_sealed(Some(&json!({ "blob": falsy })), Some(priv_b64)), PendingSealed::Ignored);
    }
    assert_eq!(handle_pending_sealed(Some(&data), None), PendingSealed::NoPriv);
    assert_eq!(handle_pending_sealed(Some(&data), Some("")), PendingSealed::NoPriv);
    assert_eq!(handle_pending_sealed(Some(&json!({ "blob": 5 })), None), PendingSealed::NoPriv);
    // A truthy non-string blob passes both gates, then throws at sealed.startsWith.
    assert_eq!(
        handle_pending_sealed(Some(&json!({ "blob": 5 })), Some(priv_b64)),
        PendingSealed::Error("TypeError: sealed.startsWith is not a function")
    );
    let tampered = s(&v["openCases"][1]["input"]);
    assert_eq!(handle_pending_sealed(Some(&json!({ "blob": tampered })), Some(priv_b64)), PendingSealed::UnsealFailed);

    // Unmarked blobs route too (defensive legacy passthrough) — use them to
    // pin the __type rules without needing new ciphertext.
    let route = |blob: &str| handle_pending_sealed(Some(&json!({ "blob": blob })), Some(priv_b64));
    let dispatch = |t: &str, d: Value| PendingSealed::Dispatch { msg_type: t.into(), data: d };
    let r = route(r#"{"a":1,"__type":"read-receipt","b":2}"#);
    assert_eq!(r, dispatch("read-receipt", json!({"a":1,"b":2})));
    if let PendingSealed::Dispatch { data, .. } = &r {
        assert_eq!(data.to_string(), r#"{"a":1,"b":2}"#, "key order preserved");
    }
    assert_eq!(route(r#"{"__type":"p2p-message","x":1}"#), dispatch("p2p-message", json!({"__type":"p2p-message","x":1})));
    assert_eq!(route(r#"{"__type":5}"#), dispatch("p2p-message", json!({"__type":5})));
    assert_eq!(route(r#"{"__type":""}"#), dispatch("", json!({})));
    assert_eq!(route("5"), dispatch("p2p-message", json!(5)));
    assert_eq!(route(r#""s""#), dispatch("p2p-message", json!("s")));
    assert_eq!(route("[1]"), dispatch("p2p-message", json!([1])));
    // Two distinct throw sites: JSON.parse itself, then `inner.__type` on null.
    assert_eq!(route("null"), PendingSealed::Error("TypeError: Cannot read property '__type' of null"));
    assert_eq!(route("not json"), PendingSealed::Error("SyntaxError: JSON.parse"));
}

/// App.tsx:1621-1650 storage offline fetch, per item.
#[test]
fn storage_offline_item() {
    let v = v();
    let priv_b64 = bob_priv_b64(&v);
    let inner: Value = serde_json::from_str(s(&v["innerJson"])).unwrap();
    let outer = json!(77);

    // Sealed and plaintext copies deliver the same payload; inner fromUserId wins.
    assert_eq!(process_offline_item(s(&v["sealed"]), Some(&outer), Some(priv_b64)), OfflineItem::Deliver(inner.clone()));
    assert_eq!(process_offline_item(s(&v["innerJson"]), Some(&outer), Some(priv_b64)), OfflineItem::Deliver(inner.clone()));
    // Every recorded open case through the storage path: a recorded null is
    // acked + skipped, a recorded string is parsed and delivered.
    for c in v["openCases"].as_array().unwrap() {
        let want = match &c["expected"] {
            Value::Null => OfflineItem::UnsealFailedAck,
            Value::String(x) => OfflineItem::Deliver(serde_json::from_str(x).unwrap()),
            other => panic!("unexpected expected {other}"),
        };
        assert_eq!(process_offline_item(s(&c["input"]), Some(&outer), Some(priv_b64)), want, "{}", s(&c["name"]));
    }
    // With no key EVERY sealed item is acked.
    assert_eq!(process_offline_item(s(&v["sealed"]), Some(&outer), None), OfflineItem::UnsealFailedAck);
    // ...but a plaintext item still delivers without a key.
    assert_eq!(process_offline_item(s(&v["innerJson"]), Some(&outer), None), OfflineItem::Deliver(inner));

    // `if (!payload.fromUserId)` is JS falsiness.
    let item = |p: &str| process_offline_item(p, Some(&outer), Some(priv_b64));
    let wire = |r: OfflineItem| match r {
        OfflineItem::Deliver(p) => p.to_string(),
        other => panic!("expected Deliver, got {other:?}"),
    };
    assert_eq!(wire(item(r#"{"fromUserId":1001,"a":1}"#)), r#"{"fromUserId":1001,"a":1}"#);
    assert_eq!(wire(item(r#"{"a":1}"#)), r#"{"a":1,"fromUserId":77}"#);
    assert_eq!(wire(item(r#"{"fromUserId":0,"a":1}"#)), r#"{"fromUserId":77,"a":1}"#);
    assert_eq!(wire(item(r#"{"fromUserId":"","a":1}"#)), r#"{"fromUserId":77,"a":1}"#);
    assert_eq!(wire(item(r#"{"fromUserId":null,"a":1}"#)), r#"{"fromUserId":77,"a":1}"#);
    assert_eq!(wire(item(r#"{"fromUserId":false}"#)), r#"{"fromUserId":77}"#);
    assert_eq!(wire(item(r#"{"fromUserId":-0.0}"#)), r#"{"fromUserId":77}"#);
    assert_eq!(wire(item(r#"{"fromUserId":-0}"#)), r#"{"fromUserId":77}"#);
    // Underflows to 0 in JSON.parse → falsy (node: {"fromUserId":77}).
    assert_eq!(wire(item(r#"{"fromUserId":1e-400}"#)), r#"{"fromUserId":77}"#);
    assert_eq!(wire(item(r#"{"fromUserId":"0"}"#)), r#"{"fromUserId":"0"}"#);
    assert_eq!(wire(item("5")), "5");
    assert_eq!(wire(item("true")), "true");
    assert_eq!(wire(item("[1]")), "[1]");
    // Throws are NOT acked (refetched next time), unlike an unseal failure.
    assert_eq!(item("null"), OfflineItem::Error("TypeError: Cannot read property 'fromUserId' of null"));
    assert_eq!(item("{"), OfflineItem::Error("SyntaxError: JSON.parse"));
    // m.fromUserId undefined → the backfilled field reads as absent.
    assert_eq!(wire(process_offline_item(r#"{"fromUserId":0,"a":1}"#, None, Some(priv_b64))), r#"{"a":1}"#);
}
