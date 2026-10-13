//! Replays docs/native/vectors/legacyBox.json — produced by the RN client's
//! real TypeScript (`crypto.ts` computeSharedKey / encryptMessage /
//! decryptMessage) — against the Rust port, byte for byte, plus the RN
//! null-vs-throw behaviour of the decoder on malformed input.
//!
//! The expectations in `decrypt_quirks_match_rn` / `compute_shared_key_*` /
//! `deep_nesting_*` / `decrypt_plaintext_*` that are not in the vector file
//! were obtained by running crypto.ts's computeSharedKey / decryptMessage
//! verbatim under tweetnacl 1.0.3 + tweetnacl-util 0.15.1 on the app's own
//! engine — the Hermes 0.14.1 VM pinned in mobile/ios/Podfile.lock (its
//! `atob` branch) — on these exact wires. NOT V8: V8's JSON.parse has no
//! nesting cap, Hermes' throws at depth 512 (see deep_nesting_*).

use std::collections::BTreeSet;

use mrenzo_core::legacy_box::*;
use mrenzo_core::primitives::{b64, b64d, b64d32, ed25519_public_from_secret64, secretbox_open, secretbox_seal, sha256, x25519_base};
use mrenzo_core::rng::{ReplayRng, Rng};
use serde_json::Value;

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/legacyBox.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("legacyBox.json")).unwrap()
}

fn replay(rng: &Value) -> ReplayRng {
    assert_eq!(keys_of(rng), ["draws", "label"], "rng block shape");
    let label = rng["label"].as_str().unwrap().to_string();
    let draws = rng["draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            assert_eq!(keys_of(d), ["hex", "n"], "draw shape");
            let bytes = hex::decode(d["hex"].as_str().unwrap()).unwrap();
            // The recorded request size must match the recorded bytes, so the
            // size ReplayRng enforces is the one the TS actually asked for.
            assert_eq!(d["n"].as_u64(), Some(bytes.len() as u64), "{label}: draw n vs hex length");
            bytes
        })
        .collect();
    ReplayRng::new(label, draws)
}

/// Sorted member names of a JSON object (structure guards: a new field in the
/// vector file must fail the test until it is covered).
fn keys_of(v: &Value) -> Vec<&str> {
    let mut k: Vec<&str> = v.as_object().expect("object").keys().map(String::as_str).collect();
    k.sort_unstable();
    k
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn shared(v: &Value) -> [u8; 32] {
    hex::decode(s(&v["sharedKeyHex"])).unwrap().try_into().unwrap()
}

/// `{n, c}` of a wire string, as strings.
fn nc(wire: &str) -> (String, String) {
    let o: Value = serde_json::from_str(wire).unwrap();
    (s(&o["n"]).to_string(), s(&o["c"]).to_string())
}

#[test]
fn every_section_is_covered() {
    let v = vectors();
    let got: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let covered: BTreeSet<&str> = [
        "area", "schema", "generator", "encodings", "sources", "notes", // header (checked here)
        "keys",         // keys_section
        "sharedKeyHex", // shared_key_is_symmetric_box_before
        "messages",     // messages_encrypt_byte_exact_and_decrypt
        "invalidUtf8",  // invalid_utf8_is_null
    ]
    .into_iter()
    .collect();
    assert_eq!(got, covered, "legacyBox.json gained/lost a section: cover it in this test");
    assert_eq!(s(&v["area"]), "legacyBox");
    assert_eq!(v["schema"], 1);
    assert_eq!(s(&v["generator"]), "mobile/src/__tests__/goldenVectors.test.ts");
    assert!(s(&v["encodings"]).contains("WITH \"=\" padding"));
    let sources = v["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1);
    assert!(s(&sources[0]).starts_with("mobile/src/utils/crypto.ts"));
    assert_eq!(v["notes"].as_array().unwrap().len(), 5);
}

#[test]
fn keys_section() {
    let v = vectors();
    let keys = v["keys"].as_object().unwrap();
    assert_eq!(keys.keys().collect::<Vec<_>>(), ["alice", "bob"]);
    for (name, uid) in [("alice", 1001), ("bob", 2002)] {
        let k = &v["keys"][name];
        assert_eq!(keys_of(k), ["ed25519PrivB64", "ed25519PubB64", "uid", "x25519PrivB64", "x25519PubB64"], "{name}");
        assert_eq!(k["uid"], uid);
        let x_priv = b64d32(s(&k["x25519PrivB64"])).unwrap();
        assert_eq!(b64(&x25519_base(&x_priv)), s(&k["x25519PubB64"]), "{name} x25519 pub");
        let e_priv: [u8; 64] = b64d(s(&k["ed25519PrivB64"])).unwrap().try_into().unwrap();
        assert_eq!(b64(&ed25519_public_from_secret64(&e_priv)), s(&k["ed25519PubB64"]), "{name} ed25519 pub");
    }
}

#[test]
fn shared_key_is_symmetric_box_before() {
    let v = vectors();
    let (a, b) = (&v["keys"]["alice"], &v["keys"]["bob"]);
    let mut cache = SharedKeyCache::new();
    // Exactly as the generator: alice→bob keyed by bob's uid, bob→alice by alice's.
    let a_shared = cache.compute_shared_key(s(&a["x25519PrivB64"]), s(&b["x25519PubB64"]), 2002).unwrap();
    let b_shared = cache.compute_shared_key(s(&b["x25519PrivB64"]), s(&a["x25519PubB64"]), 1001).unwrap();
    assert_eq!(hex::encode(a_shared), s(&v["sharedKeyHex"]));
    assert_eq!(a_shared, b_shared);
}

#[test]
fn compute_shared_key_caches_by_numeric_peer_id_only() {
    let v = vectors();
    let (a, b) = (&v["keys"]["alice"], &v["keys"]["bob"]);
    let mut cache = SharedKeyCache::new();
    let k = cache.compute_shared_key(s(&a["x25519PrivB64"]), s(&b["x25519PubB64"]), 2002).unwrap();
    // Cache hit: the key arguments are not even decoded (rotated/garbage keys ignored).
    assert_eq!(cache.compute_shared_key("!!!", "", 2002), Ok(k));
    assert_eq!(cache.compute_shared_key(s(&b["x25519PrivB64"]), s(&a["x25519PubB64"]), 2002), Ok(k));
    // A different peer id is a miss.
    assert_eq!(cache.compute_shared_key("!!!", "", 2003), Err(LegacyBoxError::InvalidEncoding));
    // Errors never populate the cache.
    assert_eq!(cache.compute_shared_key("!!!", "", 2003), Err(LegacyBoxError::InvalidEncoding));
    cache.clear_shared_key(2002);
    assert_eq!(cache.compute_shared_key("!!!", "", 2002).unwrap_err().to_string(), "invalid encoding");
    let k2 = cache.compute_shared_key(s(&a["x25519PrivB64"]), s(&b["x25519PubB64"]), 2002).unwrap();
    cache.clear_all_shared_keys();
    assert_eq!(cache.compute_shared_key("", "", 2002), Err(LegacyBoxError::BadPublicKeySize));
    assert_eq!(k, k2);
}

#[test]
fn compute_shared_key_errors_match_ts() {
    let v = vectors();
    let (a, b) = (&v["keys"]["alice"], &v["keys"]["bob"]);
    let (ap, bp) = (s(&a["x25519PrivB64"]), s(&b["x25519PubB64"]));
    // Flip the low bit of the last data char before '=' — one of the 2 trailing
    // bits of a 32-byte key's encoding. ("…vgs=" → "…vgt=", "…Gxk=" → "…Gxl=")
    let flip42 = |x: &str| {
        const AL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut c: Vec<u8> = x.bytes().collect();
        let i = AL.iter().position(|&a| a == c[42]).unwrap();
        c[42] = AL[i ^ 1];
        String::from_utf8(c).unwrap()
    };
    assert_eq!(flip42(ap), "7GTOhc5jH/jLU/wWVrj1L2y9/J5F7vr460ATMM9yvgt=");
    assert_eq!(flip42(bp), "0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxl=");
    assert_eq!(b64d32(&flip42(ap)), None, "primitives::b64d is stricter than tweetnacl-util");
    let urlsafe = |x: &str| x.replace('+', "-").replace('/', "_");
    let expected = hex::decode(s(&v["sharedKeyHex"])).unwrap();
    // (priv, pub) → Ok(sharedKeyHex) or the TS exception message.
    type Case<'a> = (String, String, Result<Vec<u8>, &'a str>);
    let cases: Vec<Case> = vec![
        (ap.into(), bp.into(), Ok(expected.clone())),
        // atob discards non-zero trailing bits: same key bytes, same shared key.
        (flip42(ap), bp.into(), Ok(expected.clone())),
        (ap.into(), flip42(bp), Ok(expected.clone())),
        (ap[..ap.len() - 1].into(), bp.into(), Err("invalid encoding")), // unpadded
        (urlsafe(ap), bp.into(), Err("invalid encoding")),
        (format!("{ap}AAAA"), bp.into(), Err("invalid encoding")), // '=' mid-string
        ("!!!!".into(), "AAAA".into(), Err("invalid encoding")),   // own key decoded first
        ("AAAA".into(), "!!!!".into(), Err("invalid encoding")),
        ("".into(), "".into(), Err("bad public key size")), // public size checked first
        (ap.into(), "".into(), Err("bad public key size")),
        (ap.into(), "AAAA".into(), Err("bad public key size")),
        (ap.into(), s(&b["ed25519PrivB64"]).into(), Err("bad public key size")),
        ("".into(), bp.into(), Err("bad secret key size")),
        ("AAAA".into(), bp.into(), Err("bad secret key size")),
        (s(&a["ed25519PrivB64"]).into(), bp.into(), Err("bad secret key size")),
    ];
    for (i, (p, q, want)) in cases.iter().enumerate() {
        let got = SharedKeyCache::new().compute_shared_key(p, q, 7);
        match want {
            Ok(k) => assert_eq!(got.map(|x| x.to_vec()).as_ref(), Ok(k), "case {i}"),
            Err(msg) => assert_eq!(got.unwrap_err().to_string(), *msg, "case {i}"),
        }
    }
}

#[test]
fn messages_encrypt_byte_exact_and_decrypt() {
    let v = vectors();
    let key = shared(&v);
    let msgs = v["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 2);
    for m in msgs {
        assert_eq!(keys_of(m), ["plaintext", "rng", "wire"], "message shape");
        let pt = s(&m["plaintext"]);
        let wire = s(&m["wire"]);
        let mut rng = replay(&m["rng"]);
        assert_eq!(encrypt_message(pt, &key, &mut rng), wire, "{pt}: wire bytes differ");
        rng.assert_exhausted();
        // The nonce on the wire is exactly the one 24-byte draw.
        let (n, c) = nc(wire);
        assert_eq!(hex::encode(b64d(&n).unwrap()), s(&m["rng"]["draws"][0]["hex"]));
        assert_eq!(b64d(&c).unwrap().len(), 16 + pt.len(), "tag16 || ct");
        assert_eq!(decrypt_message(wire, &key).as_deref(), Some(pt), "{pt}: decrypt");
    }
}

#[test]
fn invalid_utf8_is_null() {
    let v = vectors();
    let key = shared(&v);
    let bad = &v["invalidUtf8"];
    assert_eq!(keys_of(bad), ["expectedDecrypt", "rng", "wire"], "invalidUtf8 shape");
    let wire = s(&bad["wire"]);
    assert!(bad["expectedDecrypt"].is_null());
    assert_eq!(decrypt_message(wire, &key), None);

    // Rebuild the generator's wire from its recorded draw: box.after([0xff,0xfe]).
    let mut rng = replay(&bad["rng"]);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    rng.assert_exhausted();
    let rebuilt = format!("{{\"n\":\"{}\",\"c\":\"{}\"}}", b64(&nonce), b64(&secretbox_seal(&[0xff, 0xfe], &nonce, &key)));
    assert_eq!(rebuilt, wire);
    // It authenticates — the null comes from encodeUTF8 throwing, not from the tag.
    let (n, c) = nc(wire);
    let n: [u8; 24] = b64d(&n).unwrap().try_into().unwrap();
    assert_eq!(secretbox_open(&b64d(&c).unwrap(), &n, &key), Some(vec![0xff, 0xfe]));
}

#[test]
fn encrypt_round_trips_and_draws_one_nonce() {
    let v = vectors();
    let key = shared(&v);
    for text in ["", "\"quoted\" \\ </script> \u{2028}", "💥 ok"] {
        let mut rng = ReplayRng::new("roundtrip", vec![vec![7u8; 24]]);
        let wire = encrypt_message(text, &key, &mut rng);
        rng.assert_exhausted();
        assert!(wire.starts_with("{\"n\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\",\"c\":\""));
        assert_eq!(decrypt_message(&wire, &key).as_deref(), Some(text));
    }
}

#[test]
fn decrypt_quirks_match_rn() {
    let v = vectors();
    let key = shared(&v);
    let w0 = s(&v["messages"][0]["wire"]);
    let w1 = s(&v["messages"][1]["wire"]);
    let p0 = s(&v["messages"][0]["plaintext"]);
    let p1 = s(&v["messages"][1]["plaintext"]);
    let (n0, c0) = nc(w0);
    let (n1, c1) = nc(w1);
    let pad = c1.rfind('=').unwrap();
    let c1_with = |ch: char| format!("{}{}{}", &c1[..pad - 1], ch, &c1[pad..]);

    let cases: Vec<(String, Option<&str>)> = vec![
        // JSON.parse leniency that serde_json lacks, and JS object semantics.
        (format!(" \t\n\r{{ \"n\" : \"{n0}\" ,\n \"c\" :\t\"{c0}\" }} \r\n"), Some(p0)),
        (format!("{{\"c\":\"{c0}\",\"n\":\"{n0}\"}}"), Some(p0)),
        (format!("{{\"n\":\"AAAA\",\"n\":\"{n0}\",\"c\":\"{c0}\"}}"), Some(p0)), // last duplicate wins
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"n\":\"AAAA\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"c\":\"{c1}\"}}"), None),
        (format!("{{\"\\u006e\":\"{n0}\",\"\\u0063\":\"{c0}\"}}"), Some(p0)),
        (format!("{{\"n\":\"{}\",\"c\":\"{}\"}}", n0.replace('/', "\\/"), c0.replace('/', "\\/")), Some(p0)),
        (format!("{{\"n\":\"\\u00{:x}{}\",\"c\":\"{c0}\"}}", n0.as_bytes()[0], &n0[1..]), Some(p0)),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\\ud800\"}}"), Some(p0)), // lone surrogate elsewhere
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\\udc00\\ud800 \\uDBFF\"}}"), Some(p0)),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1e400,\"y\":-0,\"z\":1E+2,\"w\":-1.5e-400}}"), Some(p0)),
        // Hermes' JSON.parse nesting cap (value depth 512 → RangeError → null),
        // even in a member nobody reads. The boundary is pinned in deep_nesting_*.
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":{}{}}}", "[".repeat(3000), "]".repeat(3000)), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":{}{}}}", "[".repeat(510), "]".repeat(510)), Some(p0)),
        (
            format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":{{\"n\":\"AAAA\",\"c\":[{{\"a\":[1,2,{{\"b\":null}}]}}]}},\"y\":[true,false,null,\"s\\\"\\\\\\/\\b\\f\\n\\r\\t\"]}}"),
            Some(p0),
        ),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\u{2028}\u{2029} é 🦔\"}}"), Some(p0)),
        (format!("{{\"n\":\"{n0}\\ud800\",\"c\":\"{c0}\"}}"), None),
        // Syntax errors anywhere → null.
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\\u12\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\\uZZZZ\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\\x41\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\u{1}\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":\"\u{7f}\"}}"), Some(p0)),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\"}} x"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\"}}}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\""), None),
        (format!("{{'n':\"{n0}\",\"c\":\"{c0}\"}}"), None),
        (format!("{{n:\"{n0}\",\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":01}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":NaN}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":.5}}"), None),
        // Hermes' number lexer (strtod over the [-+.eE0-9] run) is looser than
        // RFC 8259 / V8: these PARSE on device. Exhaustive pin: json_numbers_*.
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1.}}"), Some(p0)),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":[-1.,0.,0.e1,1.E+5,-.5,-01,-00,-9.e-9]}}"), Some(p0)),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":00}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1.5.}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1..5}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":-.}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1.e}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1e5e5}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1-2}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":-Infinity}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":+1}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":1e}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":-}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":tru}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":nulls}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":[1,]}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":[,1]}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":{{\"a\"}}}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":{{\"a\":1,}}}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\" \"y\"}}"), None),
        (format!("\u{feff}{{\"n\":\"{n0}\",\"c\":\"{c0}\"}}"), None), // BOM is not JSON whitespace
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\"}}\u{a0}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\"}}\u{b}"), None),
        // Not an object / missing fields.
        (String::new(), None),
        ("   ".into(), None),
        ("{}".into(), None),
        ("null".into(), None),
        ("[]".into(), None),
        (format!("[\"{n0}\",\"{c0}\"]"), None),
        (format!("\"{n0}\""), None),
        ("42".into(), None),
        ("true".into(), None),
        (format!("{{\"n\":\"{n0}\"}}"), None),
        (format!("{{\"c\":\"{c0}\"}}"), None),
        // decodeBase64 ToString-coerces: single-element array chains DECRYPT.
        (format!("{{\"n\":[\"{n0}\"],\"c\":[\"{c0}\"]}}"), Some(p0)),
        (format!("{{\"n\":[[[\"{n0}\"]]],\"c\":[ [ \"{c0}\" ] ]}}"), Some(p0)),
        (format!("{{\"n\":[\"{n0}\",null],\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":[\"{n0}\"],\"c\":[\"{c0}\", []]}}"), None),
        (format!("{{\"n\":[],\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":[null],\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":null,\"c\":\"{c0}\"}}"), None), // "null" is valid base64 (3 bytes)
        (format!("{{\"n\":\"{n0}\",\"c\":null}}"), None),
        (format!("{{\"n\":true,\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":false,\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":{{}},\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":1234,\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":123456789012345678901}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":[123456789012345678901234]}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":{{\"c\":\"{c0}\"}}}}"), None),
        // Base64: strict regex, but atob discards non-zero trailing bits.
        (format!("{{\"n\":\"{n1}\",\"c\":\"{c1}\"}}"), Some(p1)),
        (format!("{{\"n\":\"{n1}\",\"c\":\"{}\"}}", c1_with('J')), Some(p1)),
        (format!("{{\"n\":\"{n1}\",\"c\":\"{}\"}}", c1_with('L')), Some(p1)),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{}\"}}", c1_with('J')), None), // wrong nonce
        (format!("{{\"n\":\"{n1}\",\"c\":\"{}\"}}", &c1[..c1.len() - 1]), None), // unpadded
        (format!("{{\"n\":\"{n1}\",\"c\":\"{c1}=\"}}"), None),
        (format!("{{\"n\":\"{n1}\",\"c\":\"{c1} \"}}"), None),
        (format!("{{\"n\":\"{n1}\",\"c\":\"{}\"}}", c1.replace('+', "-").replace('/', "_")), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{} {}\"}}", &c0[..20], &c0[20..]), None),
        (format!("{{\"n\":\"{n0}=\",\"c\":\"{c0}\"}}"), None),
        (format!("{{\"n\":\"{}\",\"c\":\"{c0}\"}}", &n0[..28]), None), // 21-byte nonce: 'bad nonce size'
        (format!("{{\"n\":\"{n0}AAAA\",\"c\":\"{c0}\"}}"), None),        // 27-byte nonce
        // Box shape / authentication.
        (format!("{{\"n\":\"{n0}\",\"c\":\"\"}}"), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{}\"}}", b64(&[0u8; 15])), None),
        (format!("{{\"n\":\"{n0}\",\"c\":\"{}\"}}", b64(&[0u8; 16])), None),
    ];
    for (i, (wire, want)) in cases.iter().enumerate() {
        assert_eq!(decrypt_message(wire, &key).as_deref(), *want, "case {i}: {wire:?}");
    }

    // Tampering: any flipped bit in tag, ciphertext or nonce → null; truncation → null.
    let cb = b64d(&c0).unwrap();
    for i in [0, 15, 16, cb.len() - 1] {
        let mut t = cb.clone();
        t[i] ^= 1;
        assert_eq!(decrypt_message(&format!("{{\"n\":\"{n0}\",\"c\":\"{}\"}}", b64(&t)), &key), None, "tamper c[{i}]");
    }
    let mut nb = b64d(&n0).unwrap();
    nb[0] ^= 1;
    assert_eq!(decrypt_message(&format!("{{\"n\":\"{}\",\"c\":\"{c0}\"}}", b64(&nb)), &key), None);
    assert_eq!(decrypt_message(&format!("{{\"n\":\"{n0}\",\"c\":\"{}\"}}", b64(&cb[..cb.len() - 1])), &key), None);
    let mut wrong = key;
    wrong[0] ^= 1;
    assert_eq!(decrypt_message(w0, &wrong), None);
}

#[test]
fn deep_nesting_follows_hermes_json_parse_cap() {
    let v = vectors();
    let key = shared(&v);
    let p0 = s(&v["messages"][0]["plaintext"]);
    let (n0, c0) = nc(s(&v["messages"][0]["wire"]));
    let chain = |d: usize, x: &str| format!("{}{x}{}", "[".repeat(d), "]".repeat(d));
    let objs = |d: usize, x: &str| format!("{}{x}{}", "{\"k\":".repeat(d), "}".repeat(d));
    let with_x = |x: String| format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":{x}}}");
    let n_str = format!("\"{n0}\"");
    let c_str = format!("\"{c0}\"");
    // Hermes 0.14.1 (mobile/ios/Podfile.lock): JSON.parse throws RangeError
    // "Maximum nesting level in JSON parser exceeded" once ANY value is at
    // depth 512 (the top-level object is depth 1) → decryptMessage null.
    // Each row: (wire, outcome on that VM). OK = the plaintext.
    const OK: bool = true;
    let rows: Vec<(String, bool)> = vec![
        (with_x(chain(510, "")), OK),        // innermost [] at depth 511
        (with_x(chain(511, "")), !OK),       // innermost [] at depth 512
        (with_x(chain(509, "1")), OK),       // scalar at 511
        (with_x(chain(510, "1")), !OK),      // scalar at 512
        (with_x(chain(509, "{}")), OK),      // {} at 511
        (with_x(chain(510, "{}")), !OK),     // {} at 512
        (with_x(objs(509, "{}")), OK),       // objects only: {} at 511
        (with_x(objs(510, "{}")), !OK),      // objects only: {} at 512
        (with_x(objs(509, "null")), OK),     // objects only: scalar at 511
        (with_x(objs(510, "null")), !OK),    // objects only: scalar at 512
        (with_x(chain(508, "[1,2]")), OK),   // scalars at 511
        (with_x(chain(509, "[1,2]")), !OK),  // [1,2] at 511, its scalars at 512
        (with_x(chain(1_000_000, "")), !OK), // (V8 would decrypt this one)
        // The fields themselves, wrapped (ToString of a single-element chain).
        (format!("{{\"n\":{},\"c\":{c_str}}}", chain(509, &n_str)), OK), // string at 511
        (format!("{{\"n\":{},\"c\":{c_str}}}", chain(510, &n_str)), !OK),
        (format!("{{\"n\":{n_str},\"c\":{}}}", chain(509, &c_str)), OK),
        (format!("{{\"n\":{n_str},\"c\":{}}}", chain(510, &c_str)), !OK),
        (format!("{{\"n\":{},\"c\":{c_str}}}", chain(1000, &n_str)), !OK), // (V8 would decrypt)
        (format!("{{\"n\":{},\"c\":{c_str}}}", chain(1_000_000, &n_str)), !OK),
    ];
    for (i, (wire, ok)) in rows.iter().enumerate() {
        let want = if *ok { Some(p0) } else { None };
        assert_eq!(decrypt_message(wire, &key).as_deref(), want, "row {i}");
    }
    // Bounded work on hostile input (iterative parser, linear time).
    let unclosed = format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":{}}}", "[".repeat(1_000_000));
    assert_eq!(decrypt_message(&unclosed, &key), None);
}

#[test]
fn json_numbers_follow_hermes_lexer_exhaustively() {
    // Every string of length 1..=6 over `-+.eE019` (299,592 of them), placed as
    // `"x":[<s>]` next to a valid {n,c}: the set that DECRYPTS must be exactly
    // the set crypto.ts's decryptMessage accepted on Hermes 0.14.1 — 8307
    // strings; sha256 over them in this enumeration order, each + "\n".
    let v = vectors();
    let key = shared(&v);
    let p0 = s(&v["messages"][0]["plaintext"]);
    let (n0, c0) = nc(s(&v["messages"][0]["wire"]));
    const AL: [char; 8] = ['-', '+', '.', 'e', 'E', '0', '1', '9'];
    fn walk(prefix: &mut String, left: usize, f: &mut dyn FnMut(&str)) {
        if left == 0 {
            return;
        }
        for c in AL {
            prefix.push(c);
            f(prefix);
            walk(prefix, left - 1, f);
            prefix.pop();
        }
    }
    let (mut total, mut accepted, mut digest_input) = (0usize, 0usize, String::new());
    walk(&mut String::new(), 6, &mut |t| {
        total += 1;
        let got = decrypt_message(&format!("{{\"n\":\"{n0}\",\"c\":\"{c0}\",\"x\":[{t}]}}"), &key);
        if let Some(pt) = got {
            assert_eq!(pt, p0);
            accepted += 1;
            digest_input.push_str(t);
            digest_input.push('\n');
        }
    });
    assert_eq!(total, 299_592);
    assert_eq!(accepted, 8307, "Hermes accepts 8307 of these");
    assert_eq!(hex::encode(sha256(digest_input.as_bytes())), "220e8e046b782510a850fcd3d890eab00715c345fbd99f9e02ec7ac800ad968c");
}

#[test]
fn decrypt_plaintext_utf8_is_strict_and_empty_is_not_null() {
    let v = vectors();
    let key = shared(&v);
    let nonce: [u8; 24] = hex::decode(s(&v["messages"][0]["rng"]["draws"][0]["hex"])).unwrap().try_into().unwrap();
    let wire = |bytes: &[u8]| format!("{{\"n\":\"{}\",\"c\":\"{}\"}}", b64(&nonce), b64(&secretbox_seal(bytes, &nonce, &key)));
    // encodeUTF8 = decodeURIComponent(escape(..)): RFC 3629 UTF-8, else URIError → null.
    let table: &[(&[u8], Option<&str>)] = &[
        (&[], Some("")), // empty Uint8Array is truthy → "" (not null)
        (&[0x00], Some("\u{0}")),
        (&[0x7f], Some("\u{7f}")),
        (&[0xc2, 0x80], Some("\u{80}")),
        (&[0xc0, 0x80], None), // overlong
        (&[0xc1, 0xbf], None),
        (&[0xe0, 0x80, 0x80], None),
        (&[0xe0, 0xa0, 0x80], Some("\u{800}")),
        (&[0xed, 0x9f, 0xbf], Some("\u{d7ff}")),
        (&[0xed, 0xa0, 0x80], None), // UTF-8-encoded surrogate
        (&[0xed, 0xbf, 0xbf], None),
        (&[0xee, 0x80, 0x80], Some("\u{e000}")),
        (&[0xef, 0xbb, 0xbf, 0x41], Some("\u{feff}A")), // BOM kept
        (&[0xf0, 0x80, 0x80, 0x80], None),
        (&[0xf0, 0x90, 0x80, 0x80], Some("\u{10000}")),
        (&[0xf4, 0x8f, 0xbf, 0xbf], Some("\u{10ffff}")),
        (&[0xf4, 0x90, 0x80, 0x80], None),
        (&[0xf5, 0x80, 0x80, 0x80], None),
        (&[0xf8, 0x88, 0x80, 0x80, 0x80], None),
        (&[0xe2, 0x82], None), // truncated
        (&[0x80], None),
        (&[0xbf], None),
        (&[0xfe], None),
        (&[0xff], None),
        (&[0x41, 0xc3], None),
        (&[0xc3, 0x28], None),
        (b"%25", Some("%25")), // escape/decodeURIComponent is the identity on ASCII
        (b"%", Some("%")),
        (b"+ %~", Some("+ %~")),
    ];
    for (bytes, want) in table {
        assert_eq!(decrypt_message(&wire(bytes), &key).as_deref(), *want, "plaintext {bytes:02x?}");
    }
    // Two wires recorded from the RN run, pinning the empty-plaintext and NUL boxes.
    assert_eq!(wire(&[]), "{\"n\":\"AEKGRuJY+/KYpB8JBoFe3XS3I7t5TBWc\",\"c\":\"aSilv+x8cct0F1BxWa+FWg==\"}");
    assert_eq!(wire(&[0]), "{\"n\":\"AEKGRuJY+/KYpB8JBoFe3XS3I7t5TBWc\",\"c\":\"Unj/LBxcj8EpYo5ju0dknN8=\"}");
}
