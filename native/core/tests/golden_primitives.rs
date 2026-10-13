//! docs/native/vectors/primitives.json — the shared foundation every other
//! module stands on (key generation, DH, box.before, Ed25519, encodings).

use mrenzo_core::primitives::*;
use mrenzo_core::rng::ReplayRng;
use serde_json::Value;

fn v() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/primitives.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn replay(rng: &Value) -> ReplayRng {
    let draws = rng["draws"].as_array().unwrap().iter().map(|d| hex::decode(d["hex"].as_str().unwrap()).unwrap()).collect();
    ReplayRng::new(rng["label"].as_str().unwrap(), draws)
}

fn s(x: &Value) -> &str {
    x.as_str().unwrap()
}

#[test]
fn key_generation() {
    let v = v();
    let x = &v["keyGeneration"]["x25519"];
    let mut r = replay(&x["rng"]);
    let kp = x25519_keypair(&mut r);
    r.assert_exhausted();
    assert_eq!(b64(&kp.private), s(&x["privateKeyB64"]));
    assert_eq!(b64(&kp.public), s(&x["publicKeyB64"]));
    assert_eq!(b64(&x25519_base(&kp.private)), s(&x["derivePublicKeyB64"]));

    let e = &v["keyGeneration"]["ed25519"];
    let mut r = replay(&e["rng"]);
    let (secret64, public) = ed25519_keypair(&mut r);
    r.assert_exhausted();
    assert_eq!(b64(&secret64), s(&e["privateKeyB64"]));
    assert_eq!(b64(&public), s(&e["publicKeyB64"]));
    assert_eq!(ed25519_public_from_secret64(&secret64), public);
}

#[test]
fn dh_and_box_before() {
    let v = v();
    let d = &v["dh"];
    let a = b64d32(s(&d["alicePrivB64"])).unwrap();
    let b = b64d32(s(&d["bobPubB64"])).unwrap();
    assert_eq!(hex::encode(x25519(&a, &b)), s(&d["rawX25519Hex"]));
    assert_eq!(hex::encode(box_before(&b, &a)), s(&d["naclBoxBeforeHex"]));
}

#[test]
fn ed25519_signatures() {
    let v = v();
    let alice = &v["keys"]["alice"];
    let secret: [u8; 64] = b64d(s(&alice["ed25519PrivB64"])).unwrap().try_into().unwrap();
    let bob_pub = b64d32(s(&v["keys"]["bob"]["ed25519PubB64"])).unwrap();
    for sig in v["signatures"].as_array().unwrap() {
        let msg = hex::decode(s(&sig["payloadUtf8Hex"])).unwrap();
        let signer = b64d32(s(&sig["signerEd25519PubB64"])).unwrap();
        let expected = b64d(s(&sig["sigB64"])).unwrap();
        if signer == ed25519_public_from_secret64(&secret) {
            assert_eq!(ed25519_sign(&secret, &msg).to_vec(), expected, "deterministic signature bytes");
        }
        assert!(ed25519_verify(&signer, &msg, &expected));
        assert_eq!(ed25519_verify(&bob_pub, &msg, &expected), sig["verifiesWithBobKey"].as_bool().unwrap());
    }
}

#[test]
fn random_identifiers() {
    let v = v();
    let ids = &v["randomIdentifiers"];
    let mut r = replay(&ids["secureUUID"]["rng"]);
    assert_eq!(secure_uuid(&mut r), s(&ids["secureUUID"]["value"]));
    r.assert_exhausted();
    let mut r = replay(&ids["secureRandomB64_16"]["rng"]);
    assert_eq!(secure_random_b64(&mut r, 16), s(&ids["secureRandomB64_16"]["value"]));
    r.assert_exhausted();
    let mut r = replay(&ids["getStableDeviceId"]["rng"]);
    assert_eq!(stable_device_id(&mut r), s(&ids["getStableDeviceId"]["value"]));
    r.assert_exhausted();
}

#[test]
fn base64_strictness_matches_tweetnacl_util() {
    for c in v()["base64Strictness"].as_array().unwrap() {
        let got = b64d(s(&c["input"]));
        assert_eq!(got.is_some(), c["accepted"].as_bool().unwrap(), "input {:?}", c["input"]);
        if let (Some(bytes), Some(h)) = (got, c.get("bytesHex")) {
            assert_eq!(hex::encode(bytes), s(h));
        }
    }
}

#[test]
fn utf8_strictness_matches_tweetnacl_util() {
    for c in v()["utf8Strictness"].as_array().unwrap() {
        let bytes = hex::decode(s(&c["bytesHex"])).unwrap();
        let got = String::from_utf8(bytes).ok();
        assert_eq!(got.is_some(), c["accepted"].as_bool().unwrap(), "bytes {}", s(&c["bytesHex"]));
        if let (Some(st), Some(exp)) = (got, c.get("string")) {
            assert_eq!(st, s(exp));
        }
    }
}
