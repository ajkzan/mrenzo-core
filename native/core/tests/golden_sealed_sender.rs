//! Replays docs/native/vectors/sealedSender.json — produced by the RN client's
//! real TypeScript (sealedEnvelope.ts, ratchet.ts) — against the Rust port,
//! byte for byte. Every section of the file is walked; an unknown section fails
//! the test so a regenerated vector file cannot silently outgrow it.
//!
//! A second, differential corpus (`DIFFERENTIAL`, bottom of this file) pins the
//! JavaScript-semantics quirks the golden file does not reach (coercions in
//! verifyCert, JSON.parse/JSON.stringify edge cases, tweetnacl-util base64,
//! tweetnacl's non-canonical-S acceptance). It was produced by running the
//! PRODUCTION `mobile/src/services/sealedEnvelope.ts` (types stripped, nothing
//! else changed) with tweetnacl 1.0.3 + tweetnacl-util 0.15.1 under Node 22
//! (atob branch, as in Hermes), tweetnacl's PRNG replaced by fixed draws.

use std::collections::BTreeSet;

use mrenzo_core::primitives::{b64, b64d, b64d32, box_open, ed25519_keypair, ed25519_public_from_secret64, x25519_base};
use mrenzo_core::rng::ReplayRng;
use mrenzo_core::sealed_sender::*;
use serde_json::Value;

/// README.md: fixed clock of every vector.
const T0: i64 = 1_758_800_000_000;

const SECTIONS: &[&str] = &[
    "area",
    "schema",
    "generator",
    "encodings",
    "sources",
    "notes",
    "keys",
    "serverSigningKey",
    "cert",
    "certCanonicalPayloadHex",
    "verifyCert",
    "inner",
    "seal",
    "openWithWrongKey",
];

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/sealedSender.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("sealedSender.json")).unwrap()
}

fn replay(rng: &Value) -> ReplayRng {
    let label = rng["label"].as_str().unwrap_or("?").to_string();
    let draws = rng["draws"]
        .as_array()
        .map(|a| a.iter().map(|d| hex::decode(d["hex"].as_str().unwrap()).unwrap()).collect())
        .unwrap_or_default();
    ReplayRng::new(label, draws)
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("expected string, got {v}"))
}

fn k32(v: &Value) -> [u8; 32] {
    b64d32(s(v)).unwrap()
}

fn k64(v: &Value) -> [u8; 64] {
    b64d(s(v)).unwrap().try_into().unwrap()
}

fn cert_with(v: &Value, key: &str, value: Value) -> Value {
    let mut c = v["cert"].clone();
    c[key] = value;
    c
}

#[test]
fn every_section_is_known_and_header_matches() {
    let v = vectors();
    let have: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let want: BTreeSet<&str> = SECTIONS.iter().copied().collect();
    assert_eq!(have, want, "vector file sections changed: extend this test");
    assert_eq!(v["area"], "sealedSender");
    assert_eq!(v["schema"], 1);
    assert_eq!(v["generator"], "mobile/src/__tests__/goldenVectors.test.ts");
    assert!(s(&v["encodings"]).contains("base64"));
    let sources: Vec<&str> = v["sources"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(
        sources,
        [
            "mobile/src/services/sealedEnvelope.ts",
            "mobile/src/services/sealedSender.ts",
            "internal/sealedsender/sealedsender.go (IssueCert/Verify/signedPayload)",
            "mobile/src/screens/ChatScreen.tsx:896-940 (send), mobile/src/App.tsx:1040-1100 (receive)",
        ],
        "a new source means the port must be extended"
    );
    let notes: Vec<&str> = v["notes"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(notes.len(), 6);
    // The traps the notes spell out, each pinned by a test below.
    assert!(notes[0].contains("ASCII bytes of the sender_pub BASE64 STRING"));
    assert!(notes[1].contains("equal is still valid"));
    assert!(notes[2].contains("nonce FIRST"));
    assert!(notes[3].contains("ephemeral keypair (32) BEFORE the nonce (24)"));
    assert!(notes[4].contains("ratchet envelope JSON STRING"));
    assert!(notes[5].contains("verifyCert"));
}

#[test]
fn keys_derive_their_public_halves() {
    let v = vectors();
    let keys = v["keys"].as_object().unwrap();
    assert_eq!(keys.len(), 2);
    for (name, k) in keys {
        assert_eq!(b64(&x25519_base(&k32(&k["x25519PrivB64"]))), s(&k["x25519PubB64"]), "{name}: x25519");
        assert_eq!(b64(&ed25519_public_from_secret64(&k64(&k["ed25519PrivB64"]))), s(&k["ed25519PubB64"]), "{name}: ed25519");
        assert!(k["uid"].as_i64().unwrap() > 0, "{name}: uid");
    }
    assert_eq!(v["keys"]["alice"]["uid"], 1001);
    assert_eq!(v["keys"]["bob"]["uid"], 2002);
}

#[test]
fn server_signing_key_from_rng() {
    let v = vectors();
    let sk = &v["serverSigningKey"];
    let mut rng = replay(&sk["rng"]);
    let (secret, public) = ed25519_keypair(&mut rng); // nacl.sign.keyPair(): 32-byte seed
    rng.assert_exhausted();
    assert_eq!(b64(&secret), s(&sk["privB64"]));
    assert_eq!(b64(&public), s(&sk["pubB64"]));
}

#[test]
fn cert_is_exactly_what_the_go_issuer_signs() {
    let v = vectors();
    let cert = &v["cert"];
    let alice = &v["keys"]["alice"];
    // Field set and order = Go `Cert` JSON tags.
    let keys: Vec<&str> = cert.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["uid", "expires_at_ms", "sender_pub", "sig"]);
    assert_eq!(cert["uid"], alice["uid"]);
    assert_eq!(cert["sender_pub"], alice["x25519PubB64"]);
    assert_eq!(cert["expires_at_ms"].as_i64().unwrap(), T0 + CERT_VALIDITY_MS);

    let issued = issue_cert(&k64(&v["serverSigningKey"]["privB64"]), 1001, s(&alice["x25519PubB64"]), T0).unwrap();
    assert_eq!(&issued.to_value(), cert, "Ed25519 is deterministic: the cert must be reproduced exactly");
    // Byte-exact (field order included) against the recorded wire text.
    assert_eq!(inner_plaintext_json(&issued.to_value(), s(&v["inner"]["ratchetWire"])), s(&v["inner"]["innerJson"]));
    assert_eq!(issue_cert(&[0u8; 64], 0, "x", T0), Err("sealed-sender: uid must be positive"));
    assert_eq!(issue_cert(&[0u8; 64], 1, "", T0), Err("sealed-sender: sender pub must not be empty"));
}

#[test]
fn cert_canonical_payload_hex() {
    let v = vectors();
    let c = &v["cert"];
    let (uid, exp, sp) = (c["uid"].as_i64().unwrap(), c["expires_at_ms"].as_i64().unwrap(), s(&c["sender_pub"]));
    let want = s(&v["certCanonicalPayloadHex"]);
    assert_eq!(hex::encode(canonical_signed_payload(uid, exp, sp).unwrap()), want);
    assert_eq!(hex::encode(go_signed_payload(uid, exp, sp)), want, "Go and TS agree for an ASCII sender_pub");
    // be64 ‖ be64 ‖ the base64 TEXT (44 ASCII bytes), not the decoded 32-byte key.
    assert_eq!(want.len(), 2 * (16 + 44));
    assert_eq!(&want[32..], hex::encode(sp.as_bytes()));
}

#[test]
fn verify_cert_every_recorded_case() {
    let v = vectors();
    let key = s(&v["serverSigningKey"]["pubB64"]);
    let exp = v["cert"]["expires_at_ms"].as_i64().unwrap();
    let cases = v["verifyCert"].as_object().unwrap();
    let mut checked = 0;
    for (name, expected) in cases {
        let (cert, now) = match name.as_str() {
            "atT0" => (v["cert"].clone(), T0),
            "atExpiry" => (v["cert"].clone(), exp),
            "afterExpiry" => (v["cert"].clone(), exp + 1),
            "wrongUid" => (cert_with(&v, "uid", v["keys"]["bob"]["uid"].clone()), T0),
            "wrongSenderPub" => (cert_with(&v, "sender_pub", v["keys"]["bob"]["x25519PubB64"].clone()), T0),
            other => panic!("unknown verifyCert case {other}: extend this test"),
        };
        assert_eq!(verify_cert(&cert, key, now), expected.as_bool().unwrap(), "verifyCert.{name}");
        checked += 1;
    }
    assert_eq!(checked, 5);
}

#[test]
fn inner_ratchet_wire_and_plaintext_json() {
    // The ratchet wire inside the vector is an RN v2 envelope (build ≤ 348);
    // the sealing layer is independent of it and unchanged.
    let v = vectors();
    let inner = &v["inner"];
    // `ratchet` is the envelope's JSON TEXT, escaped once more inside the inner JSON.
    let inner_json = inner_plaintext_json(&v["cert"], s(&inner["ratchetWire"]));
    assert_eq!(inner_json, s(&inner["innerJson"]));
    // JSON.parse → JSON.stringify round trip is the identity on this text.
    assert_eq!(js_json_stringify(&js_json_parse(&inner_json).unwrap()), inner_json);
}

#[test]
fn seal_blob_byte_exact_and_layout() {
    let v = vectors();
    let seal = &v["seal"];
    let bob = &v["keys"]["bob"];
    let draws = seal["rng"]["draws"].as_array().unwrap();
    assert_eq!(draws.iter().map(|d| d["n"].as_u64().unwrap()).collect::<Vec<_>>(), [32, 24], "ephemeral BEFORE nonce");

    let mut r = replay(&seal["rng"]);
    let blob = seal_envelope(&v["cert"], s(&v["inner"]["ratchetWire"]), s(&bob["x25519PubB64"]), &mut r).unwrap();
    r.assert_exhausted();
    assert_eq!(blob, s(&seal["blobB64"]));

    // Typed cert → identical bytes.
    let typed = SealedSenderCert {
        uid: 1001,
        expires_at_ms: v["cert"]["expires_at_ms"].as_i64().unwrap(),
        sender_pub: s(&v["cert"]["sender_pub"]).into(),
        sig: s(&v["cert"]["sig"]).into(),
    };
    let mut r = replay(&seal["rng"]);
    assert_eq!(seal_envelope(&typed.to_value(), s(&v["inner"]["ratchetWire"]), s(&bob["x25519PubB64"]), &mut r).unwrap(), blob);
    r.assert_exhausted();

    // Layout: nonce(24) ‖ ephemeralPub(32) ‖ box — nonce FIRST.
    let raw = b64d(&blob).unwrap();
    let layout = &seal["layout"];
    assert_eq!(hex::encode(&raw[..24]), s(&layout["nonceHex"]));
    assert_eq!(s(&layout["nonceHex"]), s(&draws[1]["hex"]), "the nonce is the SECOND draw");
    assert_eq!(hex::encode(&raw[24..56]), s(&layout["ephemeralPubHex"]));
    let eph_priv: [u8; 32] = hex::decode(s(&draws[0]["hex"])).unwrap().try_into().unwrap();
    assert_eq!(hex::encode(x25519_base(&eph_priv)), s(&layout["ephemeralPubHex"]), "unclamped 32-byte draw");
    assert_eq!(hex::encode(&raw[56..]), s(&layout["boxHex"]));
    let nonce: [u8; 24] = raw[..24].try_into().unwrap();
    let eph_pub: [u8; 32] = raw[24..56].try_into().unwrap();
    let pt = box_open(&raw[56..], &nonce, &eph_pub, &k32(&bob["x25519PrivB64"])).unwrap();
    assert_eq!(String::from_utf8(pt).unwrap(), s(&v["inner"]["innerJson"]));
}

#[test]
fn open_by_recipient_then_ratchet_decrypt() {
    let v = vectors();
    let bob = &v["keys"]["bob"];
    let inner = open_envelope(s(&bob["x25519PrivB64"]), s(&v["seal"]["blobB64"])).expect("bob opens");
    assert_eq!(inner.cert, v["cert"]);
    assert_eq!(inner.ratchet, s(&v["inner"]["ratchetWire"]));
    assert_eq!(js_json_stringify(&inner.object), s(&v["inner"]["innerJson"]));

    // Consumer side: the cert verifies. The sealed text is an RN v2 ratchet
    // envelope, which a build-349 pipeline rejects as legacy (not decrypted).
    assert!(verify_cert(&inner.cert, s(&v["serverSigningKey"]["pubB64"]), T0));
    assert_eq!(
        mrenzo_core::ratchet::Envelope::parse(&inner.ratchet),
        Err(mrenzo_core::ratchet::EnvelopeError::Legacy)
    );
}

#[test]
fn open_with_wrong_key_is_null() {
    let v = vectors();
    assert!(v["openWithWrongKey"].is_null(), "vector records null");
    assert_eq!(open_envelope(s(&v["keys"]["alice"]["x25519PrivB64"]), s(&v["seal"]["blobB64"])), None);
}

#[test]
fn sealed_inbox_injects_the_p2p_message() {
    let v = vectors();
    let bob_priv = s(&v["keys"]["bob"]["x25519PrivB64"]);
    let key = s(&v["serverSigningKey"]["pubB64"]).to_string();
    let blob = s(&v["seal"]["blobB64"]);
    let mut verify = |c: &Value| verify_cert_with_refresh(c, T0, &mut |_| Some(key.clone())).ok;

    // Live delivery carries "from":"server"; the replay after reconnect does not.
    for frame in [
        serde_json::json!({"type":"p2p-sealed","from":"server","data":{"toUserId":2002,"blob":blob,"messageId":"m-1","ts":T0 + 5}}),
        serde_json::json!({"type":"p2p-sealed","data":{"toUserId":2002,"blob":blob,"messageId":"m-1","ts":T0 + 5}}),
    ] {
        let data = sealed_inbox_to_p2p_message(&frame, bob_priv, &mut verify).expect("injected");
        let want = format!(
            "{{\"fromUserId\":1001,\"fromUsername\":\"\",\"fromDisplayName\":\"\",\"messageId\":\"m-1\",\"type\":\"text\",\"text\":{},\"encrypted\":true,\"transport\":\"sealed\",\"ts\":{}}}",
            serde_json::to_string(s(&v["inner"]["ratchetWire"])).unwrap(),
            T0 + 5
        );
        assert_eq!(js_json_stringify(&data), want);
    }
    // No ts → no ts key (JS: undefined).
    let no_ts = serde_json::json!({"type":"p2p-sealed","data":{"blob":blob,"messageId":"m-2"}});
    let data = sealed_inbox_to_p2p_message(&no_ts, bob_priv, &mut verify).unwrap();
    assert_eq!(
        js_json_stringify(&data),
        format!(
            "{{\"fromUserId\":1001,\"fromUsername\":\"\",\"fromDisplayName\":\"\",\"messageId\":\"m-2\",\"type\":\"text\",\"text\":{},\"encrypted\":true,\"transport\":\"sealed\"}}",
            serde_json::to_string(s(&v["inner"]["ratchetWire"])).unwrap()
        )
    );

    // Early returns.
    let none = |frame: Value, pk: &str, ok: bool| {
        let mut f = |_: &Value| ok;
        sealed_inbox_to_p2p_message(&frame, pk, &mut f)
    };
    assert_eq!(none(serde_json::json!({"type":"p2p-sealed","data":{"messageId":"m"}}), bob_priv, true), None, "no blob");
    assert_eq!(none(serde_json::json!({"type":"p2p-sealed","data":{"blob":blob,"messageId":""}}), bob_priv, true), None, "falsy messageId");
    assert_eq!(none(serde_json::json!({"type":"p2p-sealed"}), bob_priv, true), None, "no data");
    assert_eq!(none(serde_json::json!({"type":"p2p-sealed","data":{"blob":blob,"messageId":"m"}}), "", true), None, "no private key");
    assert_eq!(
        none(serde_json::json!({"type":"p2p-sealed","data":{"blob":blob,"messageId":"m"}}), s(&v["keys"]["alice"]["x25519PrivB64"]), true),
        None,
        "openFailed"
    );
    assert_eq!(none(serde_json::json!({"type":"p2p-sealed","data":{"blob":blob,"messageId":"m"}}), bob_priv, false), None, "certInvalid");
    // A non-string blob goes through ToString (decodeBase64 → regex + atob): ["<b64>"] still opens.
    let arr = none(serde_json::json!({"type":"p2p-sealed","data":{"blob":[blob],"messageId":7}}), bob_priv, true).unwrap();
    assert_eq!(
        js_json_stringify(&arr),
        format!(
            "{{\"fromUserId\":1001,\"fromUsername\":\"\",\"fromDisplayName\":\"\",\"messageId\":7,\"type\":\"text\",\"text\":{},\"encrypted\":true,\"transport\":\"sealed\"}}",
            serde_json::to_string(s(&v["inner"]["ratchetWire"])).unwrap()
        )
    );
}

#[test]
fn verify_cert_with_refresh_branches() {
    let v = vectors();
    let cert = &v["cert"];
    let good = s(&v["serverSigningKey"]["pubB64"]).to_string();
    let stale = s(&v["keys"]["bob"]["ed25519PubB64"]).to_string();
    let run = |cached: Option<&str>, fresh: Option<&str>, now: i64| {
        let mut calls = Vec::new();
        let out = verify_cert_with_refresh(cert, now, &mut |force| {
            calls.push(force);
            if force { fresh.map(String::from) } else { cached.map(String::from) }
        });
        (out, calls)
    };
    let ok = |ok, refreshed| CertCheck { ok, refreshed };
    assert_eq!(run(Some(&good), Some(&good), T0), (ok(true, false), vec![false]));
    assert_eq!(run(Some(&stale), Some(&good), T0), (ok(true, true), vec![false, true]), "rotation recovered");
    assert_eq!(run(Some(&stale), Some(&stale), T0), (ok(false, false), vec![false, true]), "same key: no retry");
    assert_eq!(run(Some(&stale), None, T0), (ok(false, false), vec![false, true]));
    assert_eq!(run(Some(&stale), Some(""), T0), (ok(false, false), vec![false, true]));
    assert_eq!(run(None, Some(&good), T0), (ok(false, false), vec![false]), "no key: no refresh");
    assert_eq!(run(Some(""), Some(&good), T0), (ok(false, false), vec![false]), "empty key is falsy");
    let exp = cert["expires_at_ms"].as_i64().unwrap();
    assert_eq!(run(Some(&stale), Some(&good), exp + 1), (ok(false, true), vec![false, true]), "expired stays false");
}

#[test]
fn p2p_sealed_frame_bytes() {
    assert_eq!(
        p2p_sealed_frame(2002, "m-1", "QUJD", "aa:bb"),
        r#"{"type":"p2p-sealed","data":{"toUserId":2002,"messageId":"m-1","blob":"QUJD","deliveryToken":"aa:bb"}}"#
    );
}

// ───────── differential corpus (production TS under Node) ─────────

fn differential() -> Value {
    serde_json::from_str(DIFFERENTIAL).expect("DIFFERENTIAL parses")
}

fn resolve<'a>(x: &'a str, v: &'a Value) -> &'a str {
    match x {
        "=server" => s(&v["serverSigningKey"]["pubB64"]),
        "=bob" => s(&v["keys"]["bob"]["x25519PrivB64"]),
        other => other,
    }
}

/// The RN differential cases, re-judged under the strict rule —
/// a cert verifies only when RN accepted it AND `uid` / `expires_at_ms` are
/// JSON integers in [0, 2^53) and `sender_pub` / `sig` are strings.
#[test]
fn differential_verify_cert() {
    let v = vectors();
    let d = differential();
    let cases = d["verifyCert"].as_array().unwrap();
    assert_eq!(cases.len(), 98);
    let strict_shape = |c: &Value| {
        let int = |k: &str| c.get(k).and_then(Value::as_u64).is_some_and(|x| x < (1u64 << 53)) && c[k].is_u64();
        int("uid")
            && int("expires_at_ms")
            && c.get("sender_pub").is_some_and(Value::is_string)
            && c.get("sig").and_then(Value::as_str).is_some_and(|sig| b64d(sig).is_some())
    };
    let (mut flipped, mut kept) = (0, 0);
    for c in cases {
        let name = s(&c["name"]);
        let cert = js_json_parse(s(&c["certJson"])).unwrap_or_else(|| panic!("{name}: certJson parses"));
        let got = verify_cert(&cert, resolve(s(&c["keyB64"]), &v), c["nowMs"].as_i64().unwrap());
        let rn = c["expected"].as_bool().unwrap();
        let key_ok = b64d(resolve(s(&c["keyB64"]), &v)).is_some();
        // RFC 8032 verification: a non-canonical S (S + L) no longer verifies.
        let canonical_s = !name.contains("S+") ;
        let want = rn && strict_shape(&cert) && key_ok && canonical_s;
        assert_eq!(got, want, "verifyCert strict: {name}");
        if rn && !want { flipped += 1 } else { kept += 1 }
    }
    assert!(flipped > 0, "the RN coercion cases are rejected now");
    assert!(kept > 0);
}

#[test]
fn differential_canonical_payload() {
    let d = differential();
    assert_eq!(d["canonicalPayload"].as_array().unwrap().len(), 6);
    for c in d["canonicalPayload"].as_array().unwrap() {
        let sp = s(&c["senderPub"]);
        let got = canonical_signed_payload(c["uid"].as_i64().unwrap(), c["expMs"].as_i64().unwrap(), sp).map(hex::encode);
        assert_eq!(got.as_deref(), c["expectedHex"].as_str(), "canonicalSignedPayload({sp:?})");
    }
}

#[test]
fn differential_open_envelope() {
    let v = vectors();
    let d = differential();
    let cases = d["open"].as_array().unwrap();
    assert_eq!(cases.len(), 55);
    for c in cases {
        let name = s(&c["name"]);
        let got = open_envelope(resolve(s(&c["privB64"]), &v), s(&c["blobB64"]));
        match c["expected"].as_str() {
            None => assert_eq!(got, None, "openEnvelope differential: {name} must be null"),
            Some(whole) => {
                let inner = got.unwrap_or_else(|| panic!("openEnvelope differential: {name} must open"));
                assert_eq!(js_json_stringify(&inner.object), whole, "{name}: parsed object (JS order/numbers)");
                assert_eq!(Value::String(inner.ratchet.clone()), inner.object["ratchet"], "{name}: ratchet");
                assert_eq!(inner.cert, inner.object["cert"], "{name}: cert");
            }
        }
    }
}

#[test]
fn differential_seal_envelope() {
    let v = vectors();
    let d = differential();
    let draws: Vec<Vec<u8>> = d["seal"]["drawsHex"].as_array().unwrap().iter().map(|h| hex::decode(s(h)).unwrap()).collect();
    assert_eq!(d["seal"]["cases"].as_array().unwrap().len(), 14);
    for c in d["seal"]["cases"].as_array().unwrap() {
        let name = s(&c["name"]);
        let cert = js_json_parse(s(&c["certJson"])).unwrap();
        let ratchet = s(&c["ratchet"]);
        assert_eq!(inner_plaintext_json(&cert, ratchet), s(&c["innerJson"]), "{name}: JSON.stringify");
        let pub_b64 = match s(&c["recipientPubB64"]) {
            "=bob" => s(&v["keys"]["bob"]["x25519PubB64"]),
            other => other,
        };
        let consumed = c["drawsConsumed"].as_u64().unwrap() as usize;
        let mut r = ReplayRng::new(name, draws[..consumed].to_vec());
        let got = seal_envelope(&cert, ratchet, pub_b64, &mut r);
        r.assert_exhausted();
        assert_eq!(got.as_deref(), c["expectedBlobB64"].as_str(), "sealEnvelope differential: {name}");
    }
}

#[test]
fn js_json_parse_rejects_what_json_parse_rejects() {
    for bad in ["", " ", "01", "1.", ".5", "+1", "NaN", "[1,]", "{\"a\":1,}", "'a'", "\"\\x\"", "\"a\u{1}\"", "tru", "{\"a\" 1}", "[1 2]", "1 2", "\"\\u12\""] {
        assert_eq!(js_json_parse(bad), None, "{bad:?}");
    }
    let deep_ok = format!("{}{}", "[".repeat(MAX_JSON_DEPTH), "]".repeat(MAX_JSON_DEPTH));
    assert!(js_json_parse(&deep_ok).is_some());
    let too_deep = format!("{}{}", "[".repeat(MAX_JSON_DEPTH + 1), "]".repeat(MAX_JSON_DEPTH + 1));
    assert_eq!(js_json_parse(&too_deep), None, "documented depth limit");
    // Documented divergences: JSON.parse accepts these (±Infinity, lone surrogate); the port cannot represent them.
    assert_eq!(js_json_parse("1e400"), None);
    assert_eq!(js_json_parse("\"\\ud800\""), None);
    assert_eq!(js_json_parse("\"\\ud83d\\ude00\"").unwrap(), "\u{1F600}");
}

/// The nesting cap is one rule for both directions: a certificate sits one
/// level inside the sealed `{cert, ratchet}` object, so the deepest one that
/// opens nests `MAX_JSON_DEPTH − 1` levels — and that is also the deepest one
/// the core seals. (Before, a certificate at exactly the cap sealed and then
/// failed to open on the receiver.) A refused seal draws nothing.
#[test]
fn the_core_never_seals_what_it_cannot_open() {
    let v = vectors();
    let bob = &v["keys"]["bob"];
    let shapes: [fn(usize) -> String; 2] =
        [|n| format!("{}{}", "[".repeat(n), "]".repeat(n)), |n| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n))];
    for shape in shapes {
        for depth in [1, 32, MAX_JSON_DEPTH - 1] {
            let cert = js_json_parse(&shape(depth)).unwrap();
            let blob = seal_envelope(&cert, "wire", s(&bob["x25519PubB64"]), &mut mrenzo_core::rng::StreamRng::new("seal/depth")).expect("seals");
            let inner = open_envelope(s(&bob["x25519PrivB64"]), &blob).unwrap_or_else(|| panic!("depth {depth} opens"));
            assert_eq!((inner.cert, inner.ratchet.as_str()), (cert, "wire"));
        }
        // At the cap the certificate itself still parses, but the sealed object would not.
        let at_cap = js_json_parse(&shape(MAX_JSON_DEPTH)).expect("the certificate alone is within the cap");
        let mut none = ReplayRng::new("no draws", vec![]);
        assert_eq!(seal_envelope(&at_cap, "wire", s(&bob["x25519PubB64"]), &mut none), None);
        none.assert_exhausted();
        assert_eq!(js_json_parse(&shape(MAX_JSON_DEPTH + 1)), None);
    }
}

/// Regression found in review: JSON.stringify breaks an EXACT tie between two shortest
/// digit strings to the EVEN one (V8; Hermes' dtoa likewise), while Rust's
/// `{:e}` rounds it up. Inputs are exact decimal expansions of the f64; outputs
/// were recorded from `JSON.stringify` under Node 22. The seal row is the
/// PRODUCTION `sealEnvelope` with the vector's seal draws — the boxed bytes
/// depend on this rule whenever a cert carries such a number.
#[test]
fn js_number_formatting_breaks_exact_ties_to_even() {
    const ROWS: &[(&str, &str)] = &[
        ("2135157283105460.25", "2135157283105460.2"),
        ("75391648701562.625", "75391648701562.62"),
        ("1948902201127797.25", "1948902201127797.2"),
        ("-1388676479507540.25", "-1388676479507540.2"),
        ("859939635025589.25", "859939635025589.2"),
        ("1497599544669316.25", "1497599544669316.2"),
        ("1186291116014963.75", "1186291116014963.8"),
        ("2232857311904845.75", "2232857311904845.8"),
        ("1769127415011091.75", "1769127415011091.8"),
        ("1444656156794055.75", "1444656156794055.8"),
        ("0.1000000000000000055511151231257827021181583404541015625", "0.1"),
        ("5e-324", "5e-324"),
        ("123000000000000000000", "123000000000000000000"),
        ("1000000000000000000000", "1e+21"),
        ("9007199254740993", "9007199254740992"),
    ];
    for (input, js) in ROWS {
        assert_eq!(js_json_stringify(&js_json_parse(input).unwrap()), *js, "JSON.stringify({input})");
    }

    let v = vectors();
    let cert = js_json_parse(r#"{"uid":1001,"x":75391648701562.625,"y":[2135157283105460.25]}"#).unwrap();
    assert_eq!(
        inner_plaintext_json(&cert, "r"),
        r#"{"cert":{"uid":1001,"x":75391648701562.62,"y":[2135157283105460.2]},"ratchet":"r"}"#
    );
    let mut r = replay(&v["seal"]["rng"]);
    let blob = seal_envelope(&cert, "r", s(&v["keys"]["bob"]["x25519PubB64"]), &mut r);
    r.assert_exhausted();
    assert_eq!(
        blob.as_deref(),
        Some("UBt4mf+ZPxX7JyTQJUtIEWQN5UaXNZzo1ySzxNs6KV3T78v6pXROU8i1oqNSF2pLju9BXMq9KHldsCjPMNdut1owifN2WbOr7iESFRUKeThZxbBwVaymxLO5MsfnHlaP2k6yakFDONuHt/fgpe8nf8WXr3Rv11NoVjDbP6UFSuTDFt7+yDMHbsAo/MEQByNN3n7/n2fkE01HzQ==")
    );
}

/// Generated by the Node run described in the module docs (98 verifyCert, 6 payload, 55 open, 14 seal cases).
const DIFFERENTIAL: &str = r##"{"note":"Produced by running the PRODUCTION mobile/src/services/sealedEnvelope.ts (type-stripped) with tweetnacl 1.0.3 + tweetnacl-util 0.15.1 under Node v22.14.0 (atob branch, as in Hermes). Not part of docs/native/vectors; differential evidence for the JS-semantics quirks.",
"verifyCert":[
 {"name":"baseline","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid string","certJson":"{\"uid\":\"1001\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid string padded ws","certJson":"{\"uid\":\" \\t1001\\n ﻿\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid string with U+0085 (not JS ws)","certJson":"{\"uid\":\"1001\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid hex string","certJson":"{\"uid\":\"0x3e9\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid hex string upper","certJson":"{\"uid\":\"0X3E9\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid octal string","certJson":"{\"uid\":\"0o1751\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid binary string","certJson":"{\"uid\":\"0b1111101001\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid plus-sign string","certJson":"{\"uid\":\"+1001\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid signed hex string (SyntaxError)","certJson":"{\"uid\":\"-0x3e9\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid leading zeros string","certJson":"{\"uid\":\"0001001\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid decimal-point string (SyntaxError)","certJson":"{\"uid\":\"1001.0\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid exponent string (SyntaxError)","certJson":"{\"uid\":\"1.001e3\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid empty string -> 0n","certJson":"{\"uid\":\"\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid array","certJson":"{\"uid\":[1001],\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid nested array","certJson":"{\"uid\":[[\" 1001 \"]],\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid two-element array","certJson":"{\"uid\":[1001,2],\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid float text 1001.0","certJson":"{\"uid\":1001.0,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid exp text 1.001e3","certJson":"{\"uid\":1.001e3,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid non-integer","certJson":"{\"uid\":1001.5,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid true","certJson":"{\"uid\":true,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid null","certJson":"{\"uid\":null,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid missing","certJson":"{\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid object","certJson":"{\"uid\":{},\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid +2^64 string (wraps to 1001)","certJson":"{\"uid\":\"18446744073709552617\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid -2^64 string (wraps to 1001)","certJson":"{\"uid\":\"-18446744073709550615\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid +2^64 as JSON number (rounds)","certJson":"{\"uid\":18446744073709552617,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid +2^70 string","certJson":"{\"uid\":\"1180591620717411304425\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp string","certJson":"{\"uid\":1001,\"expires_at_ms\":\"1758886400000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp string after expiry","certJson":"{\"uid\":1001,\"expires_at_ms\":\"1758886400000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758886400001,"expected":false},
 {"name":"exp string equal","certJson":"{\"uid\":1001,\"expires_at_ms\":\"1758886400000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758886400000,"expected":true},
 {"name":"exp array","certJson":"{\"uid\":1001,\"expires_at_ms\":[1758886400000],\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp hex string","certJson":"{\"uid\":1001,\"expires_at_ms\":\"0x19985cc9000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp decimal-point string","certJson":"{\"uid\":1001,\"expires_at_ms\":\"1758886400000.0\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp float text","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000.0,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp exponent text","certJson":"{\"uid\":1001,\"expires_at_ms\":1.7588864e12,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp +2^64 string, 10 days after expiry (expiry bypass)","certJson":"{\"uid\":1001,\"expires_at_ms\":\"18446745832595951616\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1759750400000,"expected":true},
 {"name":"exp +2^64 JSON number, 10 days after expiry (expiry bypass)","certJson":"{\"uid\":1001,\"expires_at_ms\":18446745832595951616,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1759750400000,"expected":true},
 {"name":"exp -2^64 string (rejected as expired)","certJson":"{\"uid\":1001,\"expires_at_ms\":\"-18446742314823151616\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp true","certJson":"{\"uid\":1001,\"expires_at_ms\":true,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp null","certJson":"{\"uid\":1001,\"expires_at_ms\":null,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp missing","certJson":"{\"uid\":1001,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp object","certJson":"{\"uid\":1001,\"expires_at_ms\":{},\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp empty array","certJson":"{\"uid\":1001,\"expires_at_ms\":[],\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sender_pub wrong","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sender_pub array","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":[\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\"],\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sender_pub number","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":5,\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sender_pub null","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":null,\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sender_pub non-ASCII, Go-signed","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=é\",\"sig\":\"PMizD0a789UCQscZdeonfZ1WpB8TQ8/o8xIwTD4ivyWtpZDyYgzkia6F1RdtBt/QsZf3HVrCEhnNmsKEgNbBBw==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sender_pub short, Go-signed","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"x\",\"sig\":\"f7LZbiVtupH4TQ0tRyZIlLZU9KviVOAOhEltoZEWwH1/daAUlCE78Hndc4tURTr5qGbuaLciwO3HRkOxh/frAw==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"sender_pub empty, signed","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"\",\"sig\":\"c8G9JsvgiZ1nCiPwRkxLDE0zoFZkqzqx7Vdi7ppSC3pDwZkYV+ThBJZ3H/W7FTnIhKe+t/MpW1M9y6SwhaQJBg==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"sender_pub with control chars, signed","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"a\\u0000b\",\"sig\":\"YkYqHwm6rz98DyK9cqdR3uIFan6rkxSyOREBfxqxWfMV73vMl3yYStMEUr4PmfXWwS5rQ/pTSg5AAjxXFkO7Dg==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid 0 signed","certJson":"{\"uid\":0,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"E9EGrFoisWLTfIofIyeWBcKNVNKcN2QnZPUg3l0Y7qFkDruuzafW0ccyfa+fcPrKA5RyMoij31IxEcyUwQ8jDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid negative signed","certJson":"{\"uid\":-5,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"3kn/WvjoHkuWOLZJWxXOB13VDHQ4mCZwVkp09ipqRUijI2mP2NHM2oxcZ4cz/pEqFGc18ivFAK73AGnzaTVnDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"sig array","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":[\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"]}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"sig nonzero trailing bits","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDR==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"sig url-safe alphabet","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ-XmCMEFm65dbo_fKZ3n8G0oq-eMoE0EGuDi-Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA_jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig unpadded","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig with newline","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy\\n4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig 63 bytes","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbz\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig 65 bytes","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQA=\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig null","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":null}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig missing","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig flipped bit","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMFFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"sig S+L (non-canonical S)","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHd+3PY/KrGENOjhmQyIEmd7w5RA/jN9PYCOwKU7mbzHQ==\",\"_overflow\":0}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"sig S+2L","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHKz2k1Fw7ZaKlAfgcRGiiy7w5RA/jN9PYCOwKU7mbzLQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"sig S+14L","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHmvu+QU7O1ibWaGauA0Jus8A5RA/jN9PYCOwKU7mbz7Q==\",\"_over\":0}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"uid numeric separator string","certJson":"{\"uid\":\"1_001\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid Infinity string","certJson":"{\"uid\":\"Infinity\",\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid [\" \"] -> 0n","certJson":"{\"uid\":[\" \"],\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid [null] -> 0n","certJson":"{\"uid\":[null],\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid object with toString key","certJson":"{\"uid\":{\"toString\":1},\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp Infinity string","certJson":"{\"uid\":1001,\"expires_at_ms\":\"Infinity\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp -Infinity string","certJson":"{\"uid\":1001,\"expires_at_ms\":\"-Infinity\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp whitespace-only string","certJson":"{\"uid\":1001,\"expires_at_ms\":\" \\n \",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp nested array","certJson":"{\"uid\":\"1001\",\"expires_at_ms\":[[1758886400000]],\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp binary string","certJson":"{\"uid\":1001,\"expires_at_ms\":\"0b11001100110000101110011001001000000000000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp octal string","certJson":"{\"uid\":1001,\"expires_at_ms\":\"0o31460563110000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758886400000,"expected":true},
 {"name":"exp hex string after expiry","certJson":"{\"uid\":1001,\"expires_at_ms\":\"0x19985cc9000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758886400001,"expected":false},
 {"name":"exp tiny fraction text","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000.0000001,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp fraction text (RangeError)","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000.5,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp string with leading +","certJson":"{\"uid\":1001,\"expires_at_ms\":\"+1758886400000\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"exp string 1.7588864e12 (Number ok, BigInt SyntaxError)","certJson":"{\"uid\":1001,\"expires_at_ms\":\"1.7588864e12\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp string \".5\" style","certJson":"{\"uid\":1001,\"expires_at_ms\":\".5\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"exp object with toString key","certJson":"{\"uid\":1001,\"expires_at_ms\":{\"toString\":1},\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"uid +2^64 string AND exp +2^64 number, far future","certJson":"{\"uid\":\"18446744073709552617\",\"expires_at_ms\":18446745832595951616,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"=server","nowMs":1790422400000,"expected":true},
 {"name":"extra fields ignored","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\",\"extra\":[1,{\"a\":2}],\"v\":9}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"keys reordered","certJson":"{\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\",\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"expires_at_ms\":1758886400000,\"uid\":1001}","keyB64":"=server","nowMs":1758800000000,"expected":true},
 {"name":"cert empty object","certJson":"{}","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"cert array","certJson":"[{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}]","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"cert string","certJson":"\"x\"","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"cert null","certJson":"null","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"cert number","certJson":"5","keyB64":"=server","nowMs":1758800000000,"expected":false},
 {"name":"key nonzero trailing bits","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"+GVFI/dhCa2TLt5HKxIX7EWeEh6Uy+dDmisnZp5BIXx=","nowMs":1758800000000,"expected":true},
 {"name":"key bob x25519 (wrong key)","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","nowMs":1758800000000,"expected":false},
 {"name":"key 31 bytes","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"+GVFI/dhCa2TLt5HKxIX7EWeEh6Uy+dDmisnZp5BIQ==","nowMs":1758800000000,"expected":false},
 {"name":"key empty string","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"","nowMs":1758800000000,"expected":false},
 {"name":"key garbage","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","keyB64":"not base64!","nowMs":1758800000000,"expected":false}
],
"canonicalPayload":[
 {"uid":1001,"expMs":1758886400000,"senderPub":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","expectedHex":"00000000000003e90000019985cc90006f78317753573442414f36455447625350427141612f62354b5757534652377a5463543565384a4b32456b3d"},
 {"uid":0,"expMs":0,"senderPub":"","expectedHex":"00000000000000000000000000000000"},
 {"uid":-1,"expMs":-1,"senderPub":"abc","expectedHex":"ffffffffffffffffffffffffffffffff616263"},
 {"uid":9007199254740991,"expMs":9007199254740991,"senderPub":"x","expectedHex":"001fffffffffffff001fffffffffffff78"},
 {"uid":1,"expMs":2,"senderPub":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=é","expectedHex":null},
 {"uid":1,"expMs":2,"senderPub":"\u0000","expectedHex":"00000000000000010000000000000002007f"}
],
"open":[
 {"name":"cert 0","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOUoazgkz4azibEUv4fx/i9txjJuspXVEDKDwSSEe62vhl//0ryhLXS","expected":null},
 {"name":"cert -0","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMtgryq3KJP0fGS74ETA1s3txjJuspXVEDXEwrCAvuhtRRuqVLq3u+N+Q==","expected":null},
 {"name":"cert 0.0e5","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPYiwCrljEFtufKFuKA6X1ptxjJuspXVEDKDRaFRbb3pB1/vhi1iLWVpo6uYw==","expected":null},
 {"name":"cert false","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMypAVVtw1eHJPh6q5QpLcZtxjJuspXVECcQkqTFbb3pB1/vhi1iLWVpo6uYw==","expected":null},
 {"name":"cert null","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxNzJNHE7fz1ZcZxn5Cqe8EitxjJuspXVECUVkqMXLintwhotRWk3q2N/NTx","expected":null},
 {"name":"cert empty string","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMqxWUdu2LYh5LJ5CvTTKsTtxjJuspXVEDYAQrCAvuhtRRuqVLq3u+N+Q==","expected":null},
 {"name":"cert true","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxNMp+UEjQr87GdedrTQ/L2itxjJuspXVECOUVOFXLintwhotRWk3q2Npos=","expected":"{\"cert\":true,\"ratchet\":\"\"}"},
 {"name":"cert 1","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":"{\"cert\":1,\"ratchet\":\"x\"}"},
 {"name":"cert string","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPtfcJabj7gFczDyaq8cOg1txjJuspXVEDYQgTMUui0oh9juATyxrXXpos=","expected":"{\"cert\":\"a\",\"ratchet\":\"x\"}"},
 {"name":"cert empty object","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxP30RyC3nrF2PSElNmkm7c8txjJuspXVECBXgrCAvuhtRRuqVLq3u+N+Q==","expected":"{\"cert\":{},\"ratchet\":\"x\"}"},
 {"name":"cert empty array","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMDneuJjqXZLMYngnS9g0oktxjJuspXVEChfgrCAvuhtRRuqVLq3u+N+Q==","expected":"{\"cert\":[],\"ratchet\":\"x\"}"},
 {"name":"cert missing","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxN3/AH+gGmQFNcGDU8JprxdtxjYvsxAHh+OARzCCLio","expected":null},
 {"name":"ratchet number","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxNPMo8YUOl+QS1It9p/6DGXtxjJuspXVECBAVOJFLjv5wEn/wKxiPTH4YKuJNOR","expected":null},
 {"name":"ratchet null","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMFVivFcU5wwEKc20d8t3s1txjJuspXVECBAVOJFLjv5wEn/wKxiPTH4YKuJIiZDb+k","expected":null},
 {"name":"ratchet missing","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOaDyCZrtKEoLGfe9Bpr6sFtxjJuspXVECBAVOJFLjv5wF2","expected":null},
 {"name":"duplicate keys, last wins","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPv4UukK+iF5nva8haarD7otxjJuspXVEDKDwSSEe62vhl//0rynbWDppXpbJLOW6j7NMw3hgQ5LSLK9WupnlKV/u2ithistQqPtVI=","expected":"{\"cert\":{\"b\":1,\"a\":2},\"ratchet\":\"b\"}"},
 {"name":"extra keys ignored","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMaTtBcnj8KOv/AOet0Sg6KtxjPp8wBTCHLD13CCrjvuAlnsQ2N0LXM4YT4PNyXQ6awMsw3hhgrfX3c5WTkyEOc7/ro6U78rQTP4Q20nWs=","expected":"{\"ext\":[1,{\"z\":null}],\"cert\":{\"uid\":1001},\"ratchet\":\"r\",\"v\":3}"},
 {"name":"integer-like keys inside cert","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOA7bz303kpEQZEO6n/4u37txjJuspXVECBAUTCSqv59E4p50L83qaNvsWgPIfOW+f1dN48lRIuYCLE9S+xhRbDuLf+8Va4owrZpRa6lyCxgn47Wh+QOsqS30c2GObO6G+zyjWVOg==","expected":"{\"cert\":{\"1\":3,\"2\":2,\"4294967294\":6,\"b\":1,\"a\":4,\"01\":5,\"4294967295\":7},\"ratchet\":\"x\"}"},
 {"name":"number forms inside cert","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMlMX5VuzQwyJlzPoQCT0yptxjJuspXVECBAUfCSqvl5k0l7VzynrWVtdi7K97UWeXtM98/mwp4bjrBoiS0kAKQqLT7/Vnroh/BtUqslDu2nGVoWh+WddWEmBB1Q7ebrX+63HiBfzh3Ltt8TI81sbVaB5UKMdb7UeIuRLBeOsdd9exHOfgsPETdL/ipq0PxE/7TuAP62mRweR876UCHoovQDOu04yZMLgg7WDBA5fLhlV0pp9FmlD4vhAXKi//pNPRNB2QEPQbEb53DqeboBPi4WXJ8+Yke5kCZ8+pXP2vOsnSl","expected":"{\"cert\":{\"a\":1001,\"b\":1758886400000,\"c\":1e+21,\"d\":1.5e-7,\"e\":0,\"f\":123456789012345680000,\"g\":9007199254740992,\"h\":0.1,\"i\":5e-324,\"j\":1.7976931348623157e+308,\"k\":100,\"l\":1e-7,\"m\":1.23e-18,\"n\":-1.5},\"ratchet\":\"x\"}"},
 {"name":"string escapes","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxNEgIUe+kwOYKtqFGMno76MtxjJuspXVECBAVXCSriJo0w7uEmMiaeftMfQa9bcULWFdLJR6wdHOTLA9S7ZyRDEveiWpgi2vEyx4kvrniakzWssCkTTJI7V2QR4WdLFwDnVihHRG3plYw==","expected":"{\"cert\":{\"s\":\"é\\u0001\\u001f\\\"\\\\/ 😀\"},\"ratchet\":\"\\n\\t\\b\\f\\r\"}"},
 {"name":"raw UTF-8 multibyte","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOMuzGdha4eNaJBC/UeUL/StxjJuspXVECBAVXCSrgFSa2LDcgATkcaVXSs7nl04fGkesx/1lx4JGWE5SynbJbW9w==","expected":"{\"cert\":{\"s\":\"Привет 😀\"},\"ratchet\":\"ж\"}"},
 {"name":"surrounding whitespace","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxP2qZ/1TWEWjwZlx/mYaBOU7DOg0sMBFR+IVwTaQbb3pB1/vhi1iLWVpo6uY+zM","expected":"{\"cert\":1,\"ratchet\":\"x\"}"},
 {"name":"BOM prefix","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxN6ci0Gc3qm6rctzJecl9CTI4EVpJpAEwiOARzRXLintwhotRWk3q2N/NTx","expected":null},
 {"name":"top-level array","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOSFIuYGdf+WRArUiF8IElLlwv3","expected":null},
 {"name":"top-level string","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxO+Bk8syNVjwwyG+Xfia34f7kmI","expected":null},
 {"name":"top-level null","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMY8xlzOZSAVyV0I5N7jf9mok/Gsw==","expected":null},
 {"name":"top-level 0","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPr4d9PcNyA4egoexuA6w+Q/A==","expected":null},
 {"name":"not JSON","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOOuLuhdyM5GRrvsmECaq55pF/Gs9c=","expected":null},
 {"name":"trailing garbage","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxNEZvqnTzQSS31Mk0AEz/xntxjJuspXVEDLDwSSEe62vhl//0ryhLXS/A==","expected":null},
 {"name":"trailing comma","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOq1VwpEYw1Wyuv527R/o5otxjJuspXVEDLDwSSEe62vhl//0ryhLWD+Q==","expected":null},
 {"name":"single-quoted","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxNXyzmzAEaOaKgXrDg1C+ietx3JuspXUUDLDwGSEe62vhl/+kr3hLDS","expected":null},
 {"name":"invalid UTF-8","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxNAWAQH7ML+JLAwjkFKXt/qt8XX","expected":null},
 {"name":"overlong UTF-8","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOHX5Q0Gz/SFPQW51outhxttxjJuspXVEDLDwSSEe62vhl//0ryPDiN+Q==","expected":null},
 {"name":"CESU surrogate UTF-8","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxO4ZrxEmC+lG+tXw3CccvpStxjJuspXVEDLDwSSEe62vhl//0ryETcvpos=","expected":null},
 {"name":"raw control char in string","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMzj+mRiizZnCnFOGZ7BWmftxjJuspXVEDLDwSSEe62vhl//0rynZbNpos=","expected":null},
 {"name":"raw DEL in string","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMQCnIBKPi27A0xNSONc3R5txjJuspXVEDLDwSSEe62vhl//0rynejNpos=","expected":"{\"cert\":1,\"ratchet\":\"ab\"}"},
 {"name":"empty plaintext","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxP4oarrxMzBoWO2FtFjIB/X","expected":null},
 {"name":"deeply nested cert","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxP3JxmUIrGtPdCW+f4nZXVEtxjJuspXVECheH27K8GOjSdQplKx3q30tdrXLMq3Uo6EC5NQ6nVGEV2tmkvYkAKG6/qpuwn6rRLP7w3z","expected":"{\"cert\":[[[[[[[[[[{\"a\":[1,[2,[3]]]}]]]]]]]]]],\"ratchet\":\"x\"}"},
 {"name":"number with leading zero","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxOIyNPR3RoOaKs47K7XT2NMtxjJuspXVEDKEgrCAvuhtRRuqVLq3u+N+Q==","expected":null},
 {"name":"NaN literal","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxND0iIs/RfWps6Qf+OOPeOrtxjJuspXVEC0QmjMUui0oh9juATyxrXXpos=","expected":null},
 {"name":"good baseline","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":"{\"cert\":1,\"ratchet\":\"x\"}"},
 {"name":"priv 31 bytes","privB64":"/jHUBE5Mh4TUdmo67V9Um6Z0UI96nvyeCY57YWxrfQ==","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":null},
 {"name":"priv 64 bytes","privB64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":null},
 {"name":"priv garbage","privB64":"***","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":null},
 {"name":"blob garbage","privB64":"=bob","blobB64":"not base64","expected":null},
 {"name":"blob url-safe","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxPc0bpSd_z8dZXCK-p0CfMytxjJuspXVEDLDwSSEe62vhl__0ryhLXS","expected":null},
 {"name":"blob 71 bytes","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfM=","expected":null},
 {"name":"blob 72 bytes","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMy","expected":null},
 {"name":"blob empty","privB64":"=bob","blobB64":"","expected":null},
 {"name":"blob truncated by one byte","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLU=","expected":null},
 {"name":"blob with trailing byte","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXSAA==","expected":null},
 {"name":"blob tampered","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpS9/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":null},
 {"name":"blob nonce/eph swapped (OSB1 order)","privB64":"=bob","blobB64":"e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxMiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiLc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":null},
 {"name":"blob nonzero trailing bits","privB64":"=bob","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPC+h6wGIGaXBXLsAcUdkCUtxjJuspXVEDLDwSSEe62vhl//0ryhO6N+R==","expected":"{\"cert\":1,\"ratchet\":\"xy\"}"},
 {"name":"wrong recipient (alice)","privB64":"7GTOhc5jH/jLU/wWVrj1L2y9/J5F7vr460ATMM9yvgs=","blobB64":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIie06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxPc0bpSd/z8dZXCK+p0CfMytxjJuspXVEDLDwSSEe62vhl//0ryhLXS","expected":null}
],
"seal":{"drawsHex":["3333333333333333333333333333333333333333333333333333333333333333","444444444444444444444444444444444444444444444444"],"cases":[
 {"name":"vector cert","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","ratchet":"{\"v\":2,\"dh\":\"/DLCGSiSWpE/aC/RIeLTSSwJBwZYxa2Ej0M6M+u/5nU=\",\"pn\":0,\"n\":0,\"ct\":\"S2qqUlpW/G2s/+iumi3g1zyQl+L2IVRRKFguU+/CCZSR2E6/MGdDT4P8wbbroa1NjK+QCQ==\"}","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxS3oZ6QQ4p8nP4NP1Q8IBPUZ+70TS90uWcDZQnpf/YfMsFwUFG06P6ZWhuBnAD8oTzJR4YDbQjb3oZj16+1YrQ4NpqhBJBitnQmnXvD3kmnQh99VT1Y4L7hUAE2qYWFwv2vHQpTXYwWVtcT27pzwh3c1lY6oIStIOBIy9Gza23hPA9oKCxULMVkxoTSJhmrK7R5n/gFvHuE5lytm1iU09IhTGDuBnL1uba4JYKE4QywSCLShX08GR355CRIVH6/ad75bKMtzCmT2AWj0M3fmFru3mcJErrdUf4A8cbtElaQGHPobdgQUwxuXbwrOsZMsEyekw+dVEhCDRik8J7DNd0XOAQlvKsWFFU6qcBzveofw3rulaUAqREd6AMN3D1l6n334w0ede+utnK4O8BDl5fo1IrqP17iWE6Z4zXml22Y7W2TfeYtSNCfmqh0HvT6BHUAWoU3eHIPN+hho0drZ5RJ4TqJQZ+XUhAUy0j0YZox/8gzc8ZWIpOsyz5ugh+N9xyulKH6TQazi/jYzlzSavPaHba3","innerJson":"{\"cert\":{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"},\"ratchet\":\"{\\\"v\\\":2,\\\"dh\\\":\\\"/DLCGSiSWpE/aC/RIeLTSSwJBwZYxa2Ej0M6M+u/5nU=\\\",\\\"pn\\\":0,\\\"n\\\":0,\\\"ct\\\":\\\"S2qqUlpW/G2s/+iumi3g1zyQl+L2IVRRKFguU+/CCZSR2E6/MGdDT4P8wbbroa1NjK+QCQ==\\\"}\"}"},
 {"name":"cert keys in non-Go order","certJson":"{\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\",\"uid\":1001,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"expires_at_ms\":1758886400000}","ratchet":"r","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxQJJtfnw7Lvj3dC++8obKDdZ+70TS90uWcDZQ/pfPYfIZIRSiX7zsusdQTS2jv/ukzCf/4KMgep1tEqyv7IPcE4Q/H2M5wnnWhghkPB9lioV0RuAXp+5/3ke3ZGuJuv0efIKE5AfYweLaUU1ap652HztVgM76XEV5ZYopj7ICXhdVc/Oidabecq8I30GQOdM+BuwbgF6yy47zj34V7riuZebk/SEwDBv6LTLpyAz2+nRgevzBxoeUP57BtTEXy+bLqBBKsk9XeWiCS9ntPOzHmVpxlJbNfSBKpOhafgH0SQGHPobdgQUwxuXbwrM7gT","innerJson":"{\"cert\":{\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\",\"uid\":1001,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"expires_at_ms\":1758886400000},\"ratchet\":\"r\"}"},
 {"name":"number forms in cert","certJson":"{\"uid\":1001.0,\"expires_at_ms\":1.7588864e12,\"p\":1e23,\"q\":2.2250738585072014e-308,\"r\":1.2e-6,\"s\":123e18,\"t\":999999999999999999999,\"u\":4.35,\"v\":0.30000000000000004,\"w\":5e-7,\"x\":18446745832595951616,\"y\":2.5e-5,\"z\":1e300,\"a\":1e21,\"b\":1.5e-7,\"c\":-0,\"d\":123456789012345680000,\"e\":9007199254740993,\"f\":0.1,\"g\":5e-324,\"h\":1.7976931348623157e308,\"i\":1e-7,\"j\":123e-20,\"k\":-1.5,\"l\":0.000001,\"m\":1e20,\"n\":2.5e+25,\"o\":-1e-10}","ratchet":"r","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxQwkA+2EoZbA4+fjBQiypSjZ+70TS90uWcDZQnpf/YfMsFwUFG06P6ZWhuBnAD8oTzJR4YDbQjb3oZj16+1YrQ4NpqhB9c243R/8Dianhq/WkIrVng+h72QKXs42eH1kp7Oax4/D5NMT742rtMFvhqWsgVepNO5SNhYtIu8enHzf1Y/OiZGf6R/rtmhW2zddq5uj7hQonjkjl7vgWqGhpckGhitYTSSxPPSf5n7qAjEMGWohng7HUas5GU0AU73a63IC/lwp2bG12bay5Onlj6CpRtMbNbfBalKhafgA1aUFmuqIpxDC1koSqorO7hU93WXmg2BJEhHR363r+nTK7V5GWFM5NZ0AT0i5KE/zZlKowzZ5Oh72VVzhE1b1kE/6wLymhNdYurw03/IO4k9j962uJ/hNkuMTxTy9T/vggOWrH/tZexfW6+PjPsbR+GAGAAGBYh0Mz1TcOw/pQsrBclRmTD2Jf70LGEWlS7vdvVQzLlbcOZNOvLJxVgAh2GHsxvh1/a3XiP7+v64ozjDdcPaWqTkGWQ2SkeDSnMh6/m1xOfMxr5EMlQGlMn9v5POQc29ib4QVIBmz119WSlr7nPRxPcNPXrbTnlSa6JzqYo6DxLkJSgUwdmIeu0=","innerJson":"{\"cert\":{\"uid\":1001,\"expires_at_ms\":1758886400000,\"p\":1e+23,\"q\":2.2250738585072014e-308,\"r\":0.0000012,\"s\":123000000000000000000,\"t\":1e+21,\"u\":4.35,\"v\":0.30000000000000004,\"w\":5e-7,\"x\":18446745832595950000,\"y\":0.000025,\"z\":1e+300,\"a\":1e+21,\"b\":1.5e-7,\"c\":0,\"d\":123456789012345680000,\"e\":9007199254740992,\"f\":0.1,\"g\":5e-324,\"h\":1.7976931348623157e+308,\"i\":1e-7,\"j\":1.23e-18,\"k\":-1.5,\"l\":0.000001,\"m\":100000000000000000000,\"n\":2.5e+25,\"o\":-1e-10},\"ratchet\":\"r\"}"},
 {"name":"integer-like keys reorder","certJson":"{\"b\":1,\"2\":2,\"1\":3,\"a\":4,\"01\":5,\"4294967294\":6,\"4294967295\":7,\"-1\":8,\"0\":9}","ratchet":"r","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxRyCgmBvoyT1EfZFyeChbIoZ+70TS90uWcDZUyiIe0JIcBiW066r7TLCVvIzWuv7FedApMLZQvM3Ih3w/mnaLUkJNehTcEg8CFl4DGDkEmpUkkxXXw8hbOWM3Q3wPPvkYzFZwY+HtEVF/8s6Z0XqgjUoEg=","innerJson":"{\"cert\":{\"0\":9,\"1\":3,\"2\":2,\"4294967294\":6,\"b\":1,\"a\":4,\"01\":5,\"4294967295\":7,\"-1\":8},\"ratchet\":\"r\"}"},
 {"name":"string escapes","certJson":"{\"s\":\"\\u00e9\\u0001\\u001f\\\"\\\\\\/\\u2028\\u2029\\u007f\\ud83d\\ude00 Привет\"}","ratchet":"line\nbreak\t\"q\"\\ \u0000 \u001f","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxQOQRGHhtkC4nHebDI0HN83Z+70TS90uWcDZQ+iIfbmqq01UU2mvNqcA1nViQO/iT+L1iSRvr9HmU7EeRulghvZhmY7p0fcZ8DW4Haanhn8FBNtAT4pjajPeCBlsL+g0sueNCdmYIEFP74Y0Mlp5RqWsgVOyZSlWpocrMc=","innerJson":"{\"cert\":{\"s\":\"é\\u0001\\u001f\\\"\\\\/  😀 Привет\"},\"ratchet\":\"line\\nbreak\\t\\\"q\\\"\\\\ \\u0000 \\u001f\"}"},
 {"name":"nested structures","certJson":"{\"a\":[],\"b\":{},\"c\":[null,true,false,[1,[2]],{\"x\":{\"y\":[]}}],\"d\":null}","ratchet":"","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxQTLOnxpRygO2V/6G4istF4Z+70TS90uWcDZR2iIY94L9MiQ0ft8KrLUEvetDHouQ+IQNZMOROIh9IohLfeY6hTNOveW44uqjNuuSnPnlHGPQ14OWYp06iZfztsgKzugtyeKxh6WddWWb5m8Q==","innerJson":"{\"cert\":{\"a\":[],\"b\":{},\"c\":[null,true,false,[1,[2]],{\"x\":{\"y\":[]}}],\"d\":null},\"ratchet\":\"\"}"},
 {"name":"cert is a string","certJson":"\"just a string\"","ratchet":"r","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxRPFELedzoORm1vvof9hyYeZ+70TS90uWdaLQnzb/REI4I0ExT46qTFERuFmzz1sBeGDoZLfkI=","innerJson":"{\"cert\":\"just a string\",\"ratchet\":\"r\"}"},
 {"name":"cert is null","certJson":"null","ratchet":"r","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxSXim0tw3aZiGz5lRglrZj8Z+70TS90uWcWMhDsN/ZXYoUjCRjir7zLQUuZ","innerJson":"{\"cert\":null,\"ratchet\":\"r\"}"},
 {"name":"duplicate keys in cert input","certJson":"{\"a\":1,\"b\":2,\"a\":3}","ratchet":"r","recipientPubB64":"=bob","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxRhc0JsOdTZGNdbiwBy78T+Z+70TS90uWcDZR2iIecJIZNiW0/roaSbUh2Hhzrp91mGRoZE","innerJson":"{\"cert\":{\"a\":3,\"b\":2},\"ratchet\":\"r\"}"},
 {"name":"recipient pub nonzero trailing bits","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","ratchet":"r","recipientPubB64":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxl=","drawsConsumed":2,"expectedBlobB64":"REREREREREREREREREREREREREREREREew1H2TQn+DERYHgcfHM/2J+IlwrvSQ2KoO4ZpMuKGxQlO2pOfNzguxV5TTWdQrivZ+70TS90uWcDZQnpf/YfMsFwUFG06P6ZWhuBnAD8oTzJR4YDbQjb3oZj16+1YrQ4NpqhBJBitnQmnXvD3kmnQh99VT1Y4L7hUAE2qYWFwv2vHQpTXYwWVtcT27pzwh3c1lY6oIStIOBIy9Gza23hPA9oKCxULMVkxoTSJhmrK7R5n/gFvHuE5lytm1iU09IhTGDuBnL1uba4JYKE4QywSCLShX08GR355CRIVH6/ad75bKMtzCmT2AWj0M3fmFru3mcJErrdUf4A8cbtElaQGHPobdgQUwxuXbwrM7gT","innerJson":"{\"cert\":{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"},\"ratchet\":\"r\"}"},
 {"name":"recipient pub 31 bytes","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","ratchet":"r","recipientPubB64":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGw==","drawsConsumed":0,"expectedBlobB64":null,"innerJson":"{\"cert\":{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"},\"ratchet\":\"r\"}"},
 {"name":"recipient pub 33 bytes","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","ratchet":"r","recipientPubB64":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxkB","drawsConsumed":0,"expectedBlobB64":null,"innerJson":"{\"cert\":{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"},\"ratchet\":\"r\"}"},
 {"name":"recipient pub garbage","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","ratchet":"r","recipientPubB64":"garbage!","drawsConsumed":0,"expectedBlobB64":null,"innerJson":"{\"cert\":{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"},\"ratchet\":\"r\"}"},
 {"name":"recipient pub empty","certJson":"{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"}","ratchet":"r","recipientPubB64":"","drawsConsumed":0,"expectedBlobB64":null,"innerJson":"{\"cert\":{\"uid\":1001,\"expires_at_ms\":1758886400000,\"sender_pub\":\"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=\",\"sig\":\"cQ+XmCMEFm65dbo/fKZ3n8G0oq+eMoE0EGuDi+Oy4DHwJ3574ke0uPwGj8FTJmqI7w5RA/jN9PYCOwKU7mbzDQ==\"},\"ratchet\":\"r\"}"}
]}}"##;
