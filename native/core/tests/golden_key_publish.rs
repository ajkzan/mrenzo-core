//! Replays docs/native/vectors/keyPublish.json — produced by the RN client's
//! real `uploadPublicKey` (services/api.ts) — against the Rust port, byte for
//! byte, then the edge cases the vector file does not record.
//!
//! The extra tables below (`TS_UPLOADS`, `TS_SIGN`, `TS_VERIFY`, `PY_SERVER`,
//! `PY_B64`) were produced on 2026-09-25 by running the REAL code, not by
//! reading it: the production `uploadPublicKey` / `signPayload` /
//! `verifyPayload` under jest with the app's own jest config (tweetnacl 1.0.3,
//! tweetnacl-util 0.15.1, fetch + Date.now stubbed, auth store set per case),
//! and routes_keys.py:64-79 verbatim under CPython 3.12.1 + PyNaCl.
//! A second pass by the same AI agents (not an outside audit) re-derived every table entry independently (tweetnacl 1.0.3 /
//! tweetnacl-util 0.15.1 under Node 22, the same production functions under the
//! app's jest config, and the same Python) and added the `signingPubNotOfPriv`,
//! decoder-on-canonical verify, non-ASCII server, `spkNotOfSigner`, `CRAFTED`,
//! exotic-`publicKey` and extra `PY_B64` rows from those real runs. Out of band
//! it also checked the two base64 decoders exhaustively (client: 87,381 strings
//! vs tweetnacl-util; server: 960,800 strings vs CPython 3.12.1) and both
//! verifiers on 2414 crafted signatures: 0 differences.

use mrenzo_core::key_publish::*;
use mrenzo_core::primitives::{b64, b64d, b64d32, ed25519_public_from_secret64, ed25519_sign, x25519_base};
use serde_json::Value;

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/keyPublish.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("keyPublish.json")).unwrap()
}

fn s(x: &Value) -> &str {
    x.as_str().unwrap_or_else(|| panic!("expected string, got {x}"))
}

// Inputs shared by the session-generated tables (== the vector's alice / T0).
const T0: i64 = 1_758_800_000_000;
const X_PUB: &str = "ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=";
const E_PUB: &str = "YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo=";
const E_PRIV: &str = "qlkYtSwxMdggeIQK9+b62+0I40oF+YZQ+b25YFtgJoli4/RZNDd/LUSFhBrS4MJmtJzuMnChfcjOaMC/P/z46g==";
/// alice's seed with pub half = 0x01..0x20 (TS: `mm.set(sk[0..32]); mm[32+i] = i+1`).
const MM_PRIV: &str = "qlkYtSwxMdggeIQK9+b62+0I40oF+YZQ+b25YFtgJokBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA==";
/// E_PRIV with non-zero trailing bits (`g==` → `h==`): same 64 bytes under atob.
const NC_PRIV: &str = "qlkYtSwxMdggeIQK9+b62+0I40oF+YZQ+b25YFtgJoli4/RZNDd/LUSFhBrS4MJmtJzuMnChfcjOaMC/P/z46h==";
/// alice's 32-byte seed only.
const SHORT_PRIV: &str = "qlkYtSwxMdggeIQK9+b62+0I40oF+YZQ+b25YFtgJok=";
const SIG: &str = "SGwxd16J+7q//ddym54WQmnNRDJ3vBPeiPKda6DnuS/wui2pPFLN6lavHteEgILMSjD1QH1W1y4pzwNAfXhiAA==";
/// SIG with S := S + L (little-endian add) — tweetnacl accepts, libsodium rejects.
const SIG_S_PLUS_L: &str = "SGwxd16J+7q//ddym54WQmnNRDJ3vBPeiPKda6DnuS/djiMGV7XfQi1MFnpjemHhSjD1QH1W1y4pzwNAfXhiEA==";
/// Signature of `canonical` by MM_PRIV (tweetnacl hashes the bogus pub half).
const SIG_MM: &str = "SGwxd16J+7q//ddym54WQmnNRDJ3vBPeiPKda6DnuS8oQRy+LEzURasoDS6NYYcdwBtuUGiO1Lh6HQqK0UzlCQ==";
/// (R = B, S = 1) under the identity public key: verifies for ANY message in tweetnacl.
const SIG_IDENTITY_FORGERY: &str = "WGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const IDENTITY_PUB: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn canonical_t0(uid: i64) -> String {
    format!("{X_PUB}|{E_PUB}|{uid}|{T0}")
}

// ─────────────────────────── the vector file ───────────────────────────

/// Every top-level section of keyPublish.json must be consumed by a test
/// below; a new section added by the generator fails here until it is.
#[test]
fn every_section_is_covered() {
    let v = vectors();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    keys.sort_unstable();
    let mut covered = vec![
        "area", "schema", "generator", "encodings", "sources", "notes", // header_is_key_publish
        "keys",                                                        // keys_block_is_self_consistent
        "clockMs", "uid", "path", "method", "bodyJson", "canonical",   // producer / consumer / server
    ];
    covered.sort_unstable();
    assert_eq!(keys, covered, "keyPublish.json sections changed — cover the new ones");
    // No `rng` anywhere: Ed25519 signing draws 0 bytes (README#prng), and the
    // port takes no Rng — there is nothing to replay.
    assert!(!v.to_string().contains("\"rng\""), "keyPublish now records rng draws — replay them");
}

#[test]
fn header_is_key_publish() {
    let v = vectors();
    assert_eq!(s(&v["area"]), "keyPublish");
    assert_eq!(v["schema"].as_i64(), Some(1));
    assert_eq!(s(&v["generator"]), "mobile/src/__tests__/goldenVectors.test.ts");
    // Verbatim: a reworded contract (encodings/notes) must be re-reviewed here.
    assert_eq!(
        s(&v["encodings"]),
        r#"*B64 = RFC 4648 §4 standard base64 WITH "=" padding (tweetnacl-util); *Hex = lowercase hex; *Json / wire = exact UTF-8 string as emitted by JSON.stringify; rng.draws = PRNG draws in call order (see README.md#prng)"#
    );
    let sources: Vec<&str> = v["sources"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(
        sources,
        ["mobile/src/services/api.ts:710-745 (uploadPublicKey)", "storage/app/routes_keys.py:16,64-79 (verify)"]
    );
    let notes: Vec<&str> = v["notes"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(
        notes,
        [
            r#"POST <STORAGE_BASE>/api/keys/publish. Body JSON = {"publicKey","signingPublicKey","ts","signature"} — ts is a decimal STRING, signature = b64 Ed25519 over UTF-8 of `${publicKey}|${signingPublicKey}|${uid}|${ts}` (the two keys as their base64 strings)."#,
            r#"Server (routes_keys.py) rebuilds the canonical string with the JWT user_id and rejects |now − ts| > 5 min ("stale publish signature") or a bad signature (401). Unsigned publishes are still accepted during rollout."#,
            "Signed with the NEW signing key being published (self-signature, no dependency on a previously stored key).",
        ]
    );
    assert_eq!(SIG_MAX_AGE_MS, 5 * 60 * 1000);
}

#[test]
fn keys_block_is_self_consistent() {
    let v = vectors();
    let keys = v["keys"].as_object().unwrap();
    assert_eq!(keys.keys().collect::<Vec<_>>(), ["alice"]);
    let a = &v["keys"]["alice"];
    // Every field of the key block is consumed below; a new one fails here.
    assert_eq!(
        a.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["uid", "x25519PrivB64", "x25519PubB64", "ed25519PrivB64", "ed25519PubB64"]
    );
    assert_eq!(a["uid"], v["uid"]);
    let xp = b64d32(s(&a["x25519PrivB64"])).unwrap();
    assert_eq!(b64(&x25519_base(&xp)), s(&a["x25519PubB64"]));
    let sk: [u8; 64] = b64d(s(&a["ed25519PrivB64"])).unwrap().try_into().unwrap();
    assert_eq!(b64(&ed25519_public_from_secret64(&sk)), s(&a["ed25519PubB64"]));
    assert_eq!(b64(&sk[32..]), s(&a["ed25519PubB64"]), "secret = seed ‖ pub");
    // The session tables below reuse these exact inputs.
    assert_eq!((s(&a["x25519PubB64"]), s(&a["ed25519PubB64"]), s(&a["ed25519PrivB64"])), (X_PUB, E_PUB, E_PRIV));
    assert_eq!(v["clockMs"].as_i64(), Some(T0));
}

/// Producer side: the RN body, byte for byte (field order, string ts, b64 sig).
#[test]
fn producer_publish_request_is_byte_exact() {
    let v = vectors();
    let a = &v["keys"]["alice"];
    let req = upload_public_key_request(
        s(&a["x25519PubB64"]),
        Some(s(&a["ed25519PubB64"])),
        AuthSnapshot { signing_private_key: Some(s(&a["ed25519PrivB64"])), uid: v["uid"].as_i64() },
        v["clockMs"].as_i64().unwrap(),
    );
    assert_eq!(req.method, s(&v["method"]));
    assert_eq!(req.path, s(&v["path"]));
    assert_eq!(req.body_json, s(&v["bodyJson"]), "wire body differs");
    assert_eq!(
        publish_canonical(
            s(&a["x25519PubB64"]),
            s(&a["ed25519PubB64"]),
            v["uid"].as_i64().unwrap(),
            v["clockMs"].as_i64().unwrap()
        ),
        s(&v["canonical"])
    );
}

/// Consumer side, exactly as the TS verify-mode `consume` does it.
#[test]
fn consumer_rebuilds_canonical_verifies_and_resigns() {
    let v = vectors();
    let a = &v["keys"]["alice"];
    let body: Value = serde_json::from_str(s(&v["bodyJson"])).unwrap();
    let fields: Vec<&str> = body.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    assert_eq!(fields, ["publicKey", "signingPublicKey", "ts", "signature"], "JSON.stringify key order");
    assert!(body["ts"].is_string(), "ts travels as a decimal STRING");
    assert_eq!(s(&body["ts"]), v["clockMs"].as_i64().unwrap().to_string());
    let uid = v["uid"].as_i64().unwrap();
    let canonical = format!("{}|{}|{}|{}", s(&body["publicKey"]), s(&body["signingPublicKey"]), uid, s(&body["ts"]));
    assert_eq!(canonical, s(&v["canonical"]));
    assert!(verify_payload(s(&v["canonical"]), s(&body["signature"]), s(&a["ed25519PubB64"])));
    assert_eq!(sign_payload(s(&v["canonical"]), s(&a["ed25519PrivB64"])).unwrap(), s(&body["signature"]));
    // The re-derived-A signer in primitives agrees whenever the halves match.
    let sk: [u8; 64] = b64d(s(&a["ed25519PrivB64"])).unwrap().try_into().unwrap();
    assert_eq!(b64(&ed25519_sign(&sk, s(&v["canonical"]).as_bytes())), s(&body["signature"]));
    // Self-signature: it verifies under the key BEING published, and binds uid.
    assert!(!verify_payload(&canonical.replace("|1001|", "|1002|"), s(&body["signature"]), s(&a["ed25519PubB64"])));
    assert!(!verify_payload(s(&v["canonical"]), s(&body["signature"]), s(&a["x25519PubB64"])));
}

/// The storage server (routes_keys.py) accepts the recorded publish, using the
/// JWT uid and pydantic's int of the string `ts`, inside ±5 min only.
#[test]
fn server_accepts_vector_publish_within_window() {
    let v = vectors();
    let body: Value = serde_json::from_str(s(&v["bodyJson"])).unwrap();
    let ts: i64 = s(&body["ts"]).parse().unwrap();
    let uid = v["uid"].as_i64().unwrap();
    let now = v["clockMs"].as_i64().unwrap();
    let check = |jwt: i64, now: i64| {
        server_check_publish_signature(
            s(&body["publicKey"]),
            Some(s(&body["signingPublicKey"])),
            Some(s(&body["signature"])),
            Some(ts),
            jwt,
            now,
        )
    };
    assert_eq!(check(uid, now), Ok(ServerSignatureCheck::Verified));
    assert_eq!(check(uid, now + SIG_MAX_AGE_MS), Ok(ServerSignatureCheck::Verified));
    assert_eq!(check(uid, now - SIG_MAX_AGE_MS), Ok(ServerSignatureCheck::Verified));
    assert_eq!(check(uid, now + SIG_MAX_AGE_MS + 1), Err(ServerRejection::StalePublishSignature));
    assert_eq!(check(uid, now - SIG_MAX_AGE_MS - 1), Err(ServerRejection::StalePublishSignature));
    assert_eq!(check(uid + 1, now), Err(ServerRejection::SignatureInvalid));
    assert_eq!(ServerRejection::StalePublishSignature.status(), 400);
    assert_eq!(ServerRejection::StalePublishSignature.detail(), "stale publish signature");
    assert_eq!(ServerRejection::SignatureInvalid.status(), 401);
    assert_eq!(ServerRejection::SignatureInvalid.detail(), "key publish signature invalid");
}

// ─────────────── edge cases (real TS / real Python, see file header) ───────────────

struct Upload {
    name: &'static str,
    spk: Option<&'static str>,
    priv_key: Option<&'static str>,
    uid: Option<i64>,
    now: i64,
    body: &'static str,
}

const BODY_KEYS_ONLY: &str = r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","signingPublicKey":"YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo="}"#;
const BODY_TS_NO_SIG: &str = r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","signingPublicKey":"YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo=","ts":"1758800000000"}"#;
const BODY_X25519_ONLY: &str = r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek="}"#;
const BODY_BASELINE: &str = r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","signingPublicKey":"YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo=","ts":"1758800000000","signature":"SGwxd16J+7q//ddym54WQmnNRDJ3vBPeiPKda6DnuS/wui2pPFLN6lavHteEgILMSjD1QH1W1y4pzwNAfXhiAA=="}"#;

/// `uploadPublicKey` bodies captured from the real TS (api.ts:714-745).
const TS_UPLOADS: &[Upload] = &[
    Upload { name: "baseline", spk: Some(E_PUB), priv_key: Some(E_PRIV), uid: Some(1001), now: T0, body: BODY_BASELINE },
    Upload { name: "noSigningPub", spk: None, priv_key: Some(E_PRIV), uid: Some(1001), now: T0, body: BODY_X25519_ONLY },
    Upload { name: "emptySigningPub", spk: Some(""), priv_key: Some(E_PRIV), uid: Some(1001), now: T0, body: BODY_X25519_ONLY },
    Upload { name: "noPriv", spk: Some(E_PUB), priv_key: None, uid: Some(1001), now: T0, body: BODY_KEYS_ONLY },
    Upload { name: "emptyPriv", spk: Some(E_PUB), priv_key: Some(""), uid: Some(1001), now: T0, body: BODY_KEYS_ONLY },
    Upload { name: "uid0", spk: Some(E_PUB), priv_key: Some(E_PRIV), uid: Some(0), now: T0, body: BODY_KEYS_ONLY },
    Upload { name: "noUser", spk: Some(E_PUB), priv_key: Some(E_PRIV), uid: None, now: T0, body: BODY_KEYS_ONLY },
    // signPayload throws AFTER body.ts was set: ts survives, signature absent.
    Upload { name: "badB64Priv", spk: Some(E_PUB), priv_key: Some("not base64!"), uid: Some(1001), now: T0, body: BODY_TS_NO_SIG },
    Upload { name: "shortPriv", spk: Some(E_PUB), priv_key: Some(SHORT_PRIV), uid: Some(1001), now: T0, body: BODY_TS_NO_SIG },
    Upload {
        name: "mismatchedPubHalf",
        spk: Some(E_PUB),
        priv_key: Some(MM_PRIV),
        uid: Some(1001),
        now: T0,
        body: r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","signingPublicKey":"YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo=","ts":"1758800000000","signature":"SGwxd16J+7q//ddym54WQmnNRDJ3vBPeiPKda6DnuS8oQRy+LEzURasoDS6NYYcdwBtuUGiO1Lh6HQqK0UzlCQ=="}"#,
    },
    Upload { name: "nonCanonicalTrailingBits", spk: Some(E_PUB), priv_key: Some(NC_PRIV), uid: Some(1001), now: T0, body: BODY_BASELINE },
    Upload {
        name: "negativeUid",
        spk: Some(E_PUB),
        priv_key: Some(E_PRIV),
        uid: Some(-7),
        now: T0,
        body: r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","signingPublicKey":"YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo=","ts":"1758800000000","signature":"mldiNnXY4MQQJOeUGO0qYvVFge3ivEtnr9i3A9uCpiPPk/LSdATR0Lc1DjbfaVSFJJL1qW/7i0FsXLiJrGnDAQ=="}"#,
    },
    // The client never checks that signingPublicKey belongs to the private key
    // it holds: here the X25519 pub is passed as the signing pub, and alice's
    // Ed25519 key signs a canonical text that names it.
    Upload {
        name: "signingPubNotOfPriv",
        spk: Some(X_PUB),
        priv_key: Some(E_PRIV),
        uid: Some(1001),
        now: T0,
        body: r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","signingPublicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","ts":"1758800000000","signature":"G05n9XSxAlBSsYR363MjkSvJHDCk1LYtcVmZcq5nmNk7sE+JvuQc/KYfz8sIUF97CFUuccK70SLLrEsmkO3SCQ=="}"#,
    },
    Upload {
        name: "otherClock",
        spk: Some(E_PUB),
        priv_key: Some(E_PRIV),
        uid: Some(1001),
        now: 1,
        body: r#"{"publicKey":"ox1wSW4BAO6ETGbSPBqAa/b5KWWSFR7zTcT5e8JK2Ek=","signingPublicKey":"YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo=","ts":"1","signature":"OwP5B5hlPUo7LT0H9PTMoRpbeJeADnj671IjcZeAe8O8zPqHvr8WYQJmfeuL4aFQPGPtt0HeKpTbeliWOQuoAg=="}"#,
    },
];

#[test]
fn ts_upload_paths_byte_exact() {
    assert_eq!(b64(&b64d(MM_PRIV).unwrap()[32..]), b64(&(1u8..=32).collect::<Vec<u8>>()));
    assert_eq!(&b64d(MM_PRIV).unwrap()[..32], &b64d(E_PRIV).unwrap()[..32]);
    assert_eq!(SHORT_PRIV, b64(&b64d(E_PRIV).unwrap()[..32]));
    for c in TS_UPLOADS {
        let req = upload_public_key_request(
            X_PUB,
            c.spk,
            AuthSnapshot { signing_private_key: c.priv_key, uid: c.uid },
            c.now,
        );
        assert_eq!((req.method, req.path), ("POST", "/api/keys/publish"), "{}", c.name);
        assert_eq!(req.body_json, c.body, "{}: body differs", c.name);
    }
}

/// `publicKey` is an arbitrary string to `uploadPublicKey`: the body must escape
/// it exactly like `JSON.stringify` (short escapes, lowercase `\u00xx`, DEL and
/// U+2028/2029 raw), and the canonical text signs its raw UTF-8. Expected bytes
/// from `JSON.stringify` + tweetnacl `signPayload` under Node 22 (hex, UTF-8).
#[test]
fn exotic_public_key_serializes_like_json_stringify() {
    let pk = "q\"\\\u{0}\u{1}\u{1f}\u{7f}\u{2028}\u{2029}/é😀\t\n\r\u{8}\u{c}\u{b}";
    let unsigned = upload_public_key_request(pk, None, AuthSnapshot { signing_private_key: Some(E_PRIV), uid: Some(1001) }, T0);
    assert_eq!(
        hex::encode(unsigned.body_json.as_bytes()),
        "7b227075626c69634b6579223a22715c225c5c5c75303030305c75303030315c75303031667fe280a8e280a92fc3a9f09f98805c745c6e5c725c625c665c7530303062227d"
    );
    let signed = upload_public_key_request(pk, Some(E_PUB), AuthSnapshot { signing_private_key: Some(E_PRIV), uid: Some(1001) }, T0);
    assert_eq!(
        hex::encode(signed.body_json.as_bytes()),
        "7b227075626c69634b6579223a22715c225c5c5c75303030305c75303030315c75303031667fe280a8e280a92fc3a9f09f98805c745c6e5c725c625c665c7530303062222c227369676e696e675075626c69634b6579223a2259755030575451336679314568595161307544435a725363376a4a776f5833497a6d6a41767a2f382b4f6f3d222c227473223a2231373538383030303030303030222c227369676e6174757265223a2257662b6b475465747978343559465834354d532f7632334a38644e6b672b74376e6e38652b2b4462556b337139726d6a445061345261476a474c6b647061435a7630554c766d6566646f7758304c61706542523842513d3d227d"
    );
}

struct Sign {
    name: &'static str,
    payload: &'static str,
    key: &'static str,
    /// Ok(signature b64) or Err(JS `e.constructor.name: e.message`).
    expected: Result<&'static str, &'static str>,
}

/// `signPayload` results from the real TS (crypto.ts:536-541).
const TS_SIGN: &[Sign] = &[
    Sign { name: "unicode", payload: "ключ|é|😀", key: E_PRIV, expected: Ok("PlhRh/p8nH9tZRGsqIjJsYlpasRX5UBOcjQ/axCh17TSZkO2pnlmrer5Uu46pSvqh+SRGZ2Ocr9YO6xLLF10BA==") },
    Sign { name: "empty", payload: "", key: E_PRIV, expected: Ok("dgT3f6s51ZkjC/SBnEzDdgMIIUsxIvLYCjZUw55aBKydXgYHLNFIKnsCvkzOgM+MV4Ic+93c+qg6X2P0Col0CA==") },
    Sign { name: "emptyKey", payload: "p", key: "", expected: Err("Error: bad secret key size") },
    Sign { name: "badKey", payload: "p", key: "AAA", expected: Err("TypeError: invalid encoding") },
    Sign { name: "shortKey", payload: "p", key: SHORT_PRIV, expected: Err("Error: bad secret key size") },
    Sign { name: "notB64", payload: "p", key: "not base64!", expected: Err("TypeError: invalid encoding") },
];

#[test]
fn ts_sign_payload_results_and_throws() {
    let canonical = canonical_t0(1001);
    assert_eq!(sign_payload(&canonical, E_PRIV).unwrap(), SIG);
    assert_eq!(sign_payload(&canonical, NC_PRIV).unwrap(), SIG, "atob discards trailing bits");
    let mm = sign_payload(&canonical, MM_PRIV).unwrap();
    assert_eq!(mm, SIG_MM, "tweetnacl hashes the STORED pub half");
    assert_eq!(&b64d(&mm).unwrap()[..32], &b64d(SIG).unwrap()[..32], "R is unchanged, only S differs");
    let mm_sk: [u8; 64] = b64d(MM_PRIV).unwrap().try_into().unwrap();
    assert_ne!(b64(&ed25519_sign(&mm_sk, canonical.as_bytes())), SIG_MM, "primitives re-derives A (differs)");
    for c in TS_SIGN {
        match (sign_payload(c.payload, c.key), c.expected) {
            (Ok(sig), Ok(want)) => assert_eq!(sig, want, "{}", c.name),
            (Err(e), Err(want)) => {
                // Both the JS error class and its message must match.
                let (class, msg) = want.split_once(": ").unwrap();
                let want_variant = match class {
                    "TypeError" => SignError::InvalidEncoding,
                    "Error" => SignError::BadSecretKeySize,
                    other => panic!("{}: unexpected JS error class {other}", c.name),
                };
                assert_eq!(e, want_variant, "{}", c.name);
                assert_eq!(e.to_string(), msg, "{}", c.name);
            }
            (got, want) => panic!("{}: got {got:?}, TS {want:?}", c.name),
        }
    }
}

/// `verifyPayload` results from the real TS (crypto.ts:548-564):
/// (name, payload, signature, public key, TS result).
fn ts_verify_cases() -> Vec<(&'static str, String, String, &'static str, bool)> {
    let c = canonical_t0(1001);
    vec![
        ("valid", c.clone(), SIG.into(), E_PUB, true),
        ("malleatedSPlusL", c.clone(), SIG_S_PLUS_L.into(), E_PUB, true),
        ("wrongUid", canonical_t0(1002), SIG.into(), E_PUB, false),
        ("emptySig", c.clone(), String::new(), E_PUB, false),
        ("emptyPub", c.clone(), SIG.into(), "", false),
        ("badSigB64", c.clone(), "x".into(), E_PUB, false),
        ("shortSig", c.clone(), b64(&b64d(SIG).unwrap()[..63]), E_PUB, false),
        ("wrongKey", c.clone(), SIG.into(), X_PUB, false),
        ("sigNonCanonicalTrailingBits", c.clone(), SIG.replace("A==", "B=="), E_PUB, true),
        ("mismatchedPubHalfSigVsRealPub", c.clone(), SIG_MM.into(), E_PUB, false),
        ("identityKeyForgery", "anything at all".into(), SIG_IDENTITY_FORGERY.into(), IDENTITY_PUB, true),
        // The decoder cases below use the REAL canonical text, so `false` can
        // only come from tweetnacl-util's strict regex, not from a wrong message.
        ("sigUrlSafe", c.clone(), SIG.replace('+', "-").replace('/', "_"), E_PUB, false),
        ("sigExcessPadding", c.clone(), format!("{SIG}===="), E_PUB, false),
        ("sigNoPadding", c.clone(), SIG.trim_end_matches('=').into(), E_PUB, false),
        ("sigTrailingGarbageAfterPad", c.clone(), format!("{SIG}garbage!!"), E_PUB, false),
        ("sigWithNewline", c.clone(), format!("{}\n{}", &SIG[..44], &SIG[44..]), E_PUB, false),
        ("sigPadInMiddle", c.clone(), format!("{}==AA", &SIG[..84]), E_PUB, false),
        ("sigTrailingNonAscii", c.clone(), format!("{SIG}é"), E_PUB, false),
        ("pubNonCanonicalTrailingBits", c.clone(), SIG.into(), "YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Op=", true),
    ]
}

#[test]
fn ts_verify_payload_quirks() {
    assert_eq!(b64(&b64d(&SIG.replace("A==", "B==")).unwrap_or_default()), "", "primitives b64d is stricter");
    for (name, payload, sig, key, want) in ts_verify_cases() {
        assert_eq!(verify_payload(&payload, &sig, key), want, "{name}");
    }
}

/// routes_keys.py:64-79 run verbatim under CPython 3.12.1 + PyNaCl:
/// (name, publicKey, signingPublicKey, signature, ts, jwt uid, now, outcome).
type ServerCase = (&'static str, String, Option<String>, Option<String>, Option<i64>, i64, i64, Result<ServerSignatureCheck, ServerRejection>);

fn py_server_cases() -> Vec<ServerCase> {
    use ServerRejection::*;
    use ServerSignatureCheck::*;
    let (pk, spk, sig) = (X_PUB.to_string(), Some(E_PUB.to_string()), Some(SIG.to_string()));
    // 'Oo=' → 'Op=': same 32 bytes to Python, a different canonical string.
    let spk_nc = format!("{}p=", &E_PUB[..E_PUB.len() - 2]);
    // PyNaCl SigningKey(seed).sign(f"{X_PUB}|{spk_nc}|1001|{T0}").
    let sig_nc = "XD4vGhr0Xo7K+bbFXR46UyYGWOodDiavkWVqm2r57K2sW3Xr5XBZygDvZYKfD4q1PvfuP8fmrR5lDPWVI4ISAA==";
    assert_eq!(spk_nc, "YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Op=");
    vec![
        ("vector", pk.clone(), spk.clone(), sig.clone(), Some(T0), 1001, T0, Ok(Verified)),
        ("edgeFuture300000", pk.clone(), spk.clone(), sig.clone(), Some(T0), 1001, T0 + 300000, Ok(Verified)),
        ("edgePast300000", pk.clone(), spk.clone(), sig.clone(), Some(T0), 1001, T0 - 300000, Ok(Verified)),
        ("stale300001", pk.clone(), spk.clone(), sig.clone(), Some(T0), 1001, T0 + 300001, Err(StalePublishSignature)),
        ("staleFuture300001", pk.clone(), spk.clone(), sig.clone(), Some(T0), 1001, T0 - 300001, Err(StalePublishSignature)),
        ("tsMissing", pk.clone(), spk.clone(), sig.clone(), None, 1001, T0, Err(StalePublishSignature)),
        ("tsMissingButSigNone", pk.clone(), spk.clone(), None, None, 1001, T0, Ok(Unchecked)),
        ("wrongJwtUid", pk.clone(), spk.clone(), sig.clone(), Some(T0), 1002, T0, Err(SignatureInvalid)),
        ("sigNone", pk.clone(), spk.clone(), None, Some(T0), 1001, T0, Ok(Unchecked)),
        ("spkNone", pk.clone(), None, sig.clone(), Some(T0), 1001, T0, Ok(Unchecked)),
        ("spkEmpty", pk.clone(), Some(String::new()), sig.clone(), Some(T0), 1001, T0, Ok(Unchecked)),
        ("sigEmpty", pk.clone(), spk.clone(), Some(String::new()), Some(T0), 1001, T0, Err(SignatureInvalid)),
        ("malleatedSPlusL", pk.clone(), spk.clone(), Some(SIG_S_PLUS_L.into()), Some(T0), 1001, T0, Err(SignatureInvalid)),
        (
            "sigWithNewlines",
            pk.clone(),
            spk.clone(),
            Some(format!("{}\n{} \t{}", &SIG[..20], &SIG[20..40], &SIG[40..])),
            Some(T0),
            1001,
            T0,
            Ok(Verified),
        ),
        ("sigTrailingGarbageAfterPad", pk.clone(), spk.clone(), Some(format!("{SIG}garbage!!")), Some(T0), 1001, T0, Ok(Verified)),
        ("sigNoPadding", pk.clone(), spk.clone(), Some(SIG.trim_end_matches('=').into()), Some(T0), 1001, T0, Err(SignatureInvalid)),
        ("sigUrlSafe", pk.clone(), spk.clone(), Some(SIG.replace('+', "-").replace('/', "_")), Some(T0), 1001, T0, Err(SignatureInvalid)),
        ("sigNonCanonicalTrailingBits", pk.clone(), spk.clone(), Some(format!("{}B==", &SIG[..SIG.len() - 3])), Some(T0), 1001, T0, Ok(Verified)),
        ("spkNonCanonicalTrailingBitsSigned", pk.clone(), Some(spk_nc), Some(sig_nc.into()), Some(T0), 1001, T0, Ok(Verified)),
        ("spkNonAscii", pk.clone(), Some(format!("{}é", &E_PUB[..E_PUB.len() - 1])), sig.clone(), Some(T0), 1001, T0, Err(SignatureInvalid)),
        ("spkShort", pk.clone(), Some(b64(&b64d(E_PUB).unwrap()[..31])), sig.clone(), Some(T0), 1001, T0, Err(SignatureInvalid)),
        (
            "identityKeyForgery",
            pk.clone(),
            Some(IDENTITY_PUB.into()),
            Some(SIG_IDENTITY_FORGERY.into()),
            Some(T0),
            1001,
            T0,
            Err(SignatureInvalid),
        ),
        ("padInMiddleStopsDecode", pk.clone(), spk.clone(), Some(format!("{}==AAAA", &SIG[..84])), Some(T0), 1001, T0, Err(SignatureInvalid)),
        ("sigExcessPadding", pk.clone(), spk.clone(), Some(format!("{SIG}====")), Some(T0), 1001, T0, Ok(Verified)),
        // Non-ASCII raises in b64decode BEFORE any decoding (str.encode('ascii')),
        // even where the same text with an ASCII junk char instead would verify.
        (
            "spkNonAsciiSigned",
            pk.clone(),
            Some(format!("{E_PUB}é")),
            Some("4qSVpvXPR124XIFJrNQXMlig+xvfj8Uxc6wRmaaByFLIjWoGM4Gea3wTTVSGeZXHmnk87fIqoc/gnvKyx2pxCg==".into()),
            Some(T0),
            1001,
            T0,
            Err(SignatureInvalid),
        ),
        (
            "spkAsciiJunkSigned",
            pk.clone(),
            Some(format!("{E_PUB}!")),
            Some("OVGZlSBYiIUW6ujaRKL5A/FT8Y40PkEJcMZLHQZpCi8PYhsFHjM5JU8uy8fh1hEwrEPPdJekwNLtMn+Kl+MhDg==".into()),
            Some(T0),
            1001,
            T0,
            Ok(Verified),
        ),
        ("sigTrailingNonAscii", pk.clone(), spk.clone(), Some(format!("{SIG}é")), Some(T0), 1001, T0, Err(SignatureInvalid)),
        // TS_UPLOADS "signingPubNotOfPriv": the client signs it, the server 401s.
        (
            "spkNotOfSigner",
            pk.clone(),
            Some(X_PUB.into()),
            Some("G05n9XSxAlBSsYR363MjkSvJHDCk1LYtcVmZcq5nmNk7sE+JvuQc/KYfz8sIUF97CFUuccK70SLLrEsmkO3SCQ==".into()),
            Some(T0),
            1001,
            T0,
            Err(SignatureInvalid),
        ),
    ]
}

#[test]
fn py_server_signature_gate() {
    for (name, pk, spk, sig, ts, jwt, now, want) in py_server_cases() {
        let got = server_check_publish_signature(&pk, spk.as_deref(), sig.as_deref(), ts, jwt, now);
        assert_eq!(got, want, "{name}");
    }
}

/// Python 3.12.1 `base64.b64decode(s)` (hex, or None when it raises).
const PY_B64: &[(&str, Option<&str>)] = &[
    ("AAAA", Some("000000")),
    ("AA==", Some("00")),
    ("AAA=", Some("0000")),
    ("AAA", None),
    ("AA", None),
    ("A", None),
    ("-_8=", None),
    ("+/8=", Some("fbff")),
    ("AAAA\nAAAA", Some("000000000000")),
    (" AAAA", Some("000000")),
    ("AAAA=", Some("000000")),
    ("AA==AAAA", Some("00")),
    ("A=A=AA==", Some("000000")),
    ("=AAAA", Some("000000")),
    ("AB==", Some("00")),
    ("A===", None),
    ("AAAAA", None),
    ("AAAAA=", None),
    ("AAAAA==", None),
    ("AA=A", None),
    ("Zm9v!!YmFy", Some("666f6f626172")),
    ("AAA==", Some("0000")),
    ("", Some("")),
    ("AAAé", None),
    ("A=AA=", Some("0000")),
    ("AB=C==", Some("0010")),
    ("==AA", None),
    ("AAA=A==", Some("0000")),
    ("AA=A==", Some("0000")),
    ("AAAAé", None),
    ("AA==é", None),
];

#[test]
fn py_b64decode_leniency() {
    for &(input, want) in PY_B64 {
        let got = server_b64decode(input).map(hex::encode);
        assert_eq!(got.as_deref(), want, "{input:?}");
    }
}

/// The ported tweetnacl `modL`/`crypto_sign` path equals the RFC 8032 signer
/// whenever the secret's halves agree, and the verifier's S-reduction accepts
/// exactly the tweetnacl `S+L` malleation — over 256 deterministic keys/messages.
#[test]
fn nacl_signer_matches_rfc8032_when_halves_agree() {
    use mrenzo_core::primitives::{ed25519_keypair_from_seed, sha512};
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    for i in 0u32..256 {
        let h = sha512(format!("key-publish-modL-{i}").as_bytes());
        let seed: [u8; 32] = h[..32].try_into().unwrap();
        let (secret, public) = ed25519_keypair_from_seed(&seed);
        let msg = publish_canonical(&b64(&h[32..]), &b64(&public), i as i64, T0 + i as i64);
        let sig = sign_payload(&msg, &b64(&secret)).unwrap();
        assert_eq!(sig, b64(&ed25519_sign(&secret, msg.as_bytes())), "#{i}");
        assert!(verify_payload(&msg, &sig, &b64(&public)), "#{i}");
        let mut mal = b64d(&sig).unwrap();
        let mut carry = 0u16;
        for k in 0..32 {
            let v = mal[32 + k] as u16 + L[k] as u16 + carry;
            mal[32 + k] = v as u8;
            carry = v >> 8;
        }
        assert!(verify_payload(&msg, &b64(&mal), &b64(&public)), "#{i}: S+L must verify like tweetnacl");
    }
}

/// Crafted self-signed publishes (spk, signature) over
/// `{X_PUB}|{spk}|1001|{T0}`, drawn from a 2414-case differential run (Python
/// point arithmetic; results from tweetnacl 1.0.3 `verifyPayload` under Node 22
/// and the routes_keys.py gate under PyNaCl 1.6.2; the Rust port agreed on all
/// 2414): (name, spk, signature, TS verifyPayload, server outcome).
type CraftedCase = (&'static str, &'static str, &'static str, bool, Result<ServerSignatureCheck, ServerRejection>);
const CRAFTED: &[CraftedCase] = &[
    (
        "sPlus15L",
        "6baZytttb/TXf7flUThc29ZXz7NNkMS63fmbMblHKjo=",
        "zQUI1vaS6wF0TriCPDshfvGN/VeuR6/sEJhwWYMhsnLvqGqhcRN1Fa123ZBdywl9WC4lRW0u5+OSJJBW8OLD9A==",
        true,
        Err(ServerRejection::SignatureInvalid),
    ),
    (
        "identitySignBitX0",
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=",
        "7lXMElzHQayoLfrjtwWIP2xxvO0/MnFkB36qS1ilOdIuLDlzmPuoEJtf3ZRSmKM0OqVRGbyTQdbl+uO5B9ySBw==",
        true,
        Err(ServerRejection::SignatureInvalid),
    ),
    (
        "identityNonCanonicalY",
        "7v///////////////////////////////////////38=",
        "HCTCosPkLZb3rD1MbFiFgsHNRb3dCgMQRPrJqe4LhJD1UjQLRYFata07S+tn0DRk8I4jejCYueHDNMs2mB2AAg==",
        true,
        Err(ServerRejection::SignatureInvalid),
    ),
    (
        "order8Key",
        "JuiVj8KyJ7BFw/SJ8u+Y8NXfrAXTxjM5sTgCiG1T/AU=",
        "yPvKLtgOUg0ipjHCKChzcAJwOKhPCUOhs/DDOveSPsDsuZ7M1l4ZlCxYRJtmtapVTjgOzp9JygtHCPSJI/XlAw==",
        true,
        Err(ServerRejection::SignatureInvalid),
    ),
    // alice's REAL key, R = identity (r = 0, S = h·a): tweetnacl accepts, while
    // libsodium rejects a small-order R. Anyone holding the key can emit this.
    (
        "aliceIdentityR",
        E_PUB,
        "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAC+VAQAfkRBkhWs7o2Esmwa8SiAIYYGvK/e4NluUNDQ==",
        true,
        Err(ServerRejection::SignatureInvalid),
    ),
    // A = a·B + T8 (torsion component): neither side checks the subgroup.
    (
        "mixedOrderKey",
        "kWoUcFouohMMG/t97U7XOOzyBJXM1N+LDCdxSdz0zWk=",
        "Rklf8hOM5FAjLFvBMcFGXod0+S2ehm1e2Y13DoW8mRaM5ojWgOVdaYeDXS4LNUQD7eRbouXuQczawVCfeEptAA==",
        true,
        Ok(ServerSignatureCheck::Verified),
    ),
];

#[test]
fn crafted_signatures_client_and_server() {
    for &(name, spk, sig, client, server) in CRAFTED {
        let msg = format!("{X_PUB}|{spk}|1001|{T0}");
        assert_eq!(verify_payload(&msg, sig, spk), client, "{name}: client");
        assert_eq!(server_check_publish_signature(X_PUB, Some(spk), Some(sig), Some(T0), 1001, T0), server, "{name}: server");
    }
}

/// Where the RN verifier and the server disagree — both are faithful; this
/// pins the divergence so a "fix" on either side shows up here.
#[test]
fn client_and_server_verifiers_diverge_on_crafted_inputs() {
    let c = canonical_t0(1001);
    assert!(verify_payload(&c, SIG_S_PLUS_L, E_PUB));
    assert_eq!(
        server_check_publish_signature(X_PUB, Some(E_PUB), Some(SIG_S_PLUS_L), Some(T0), 1001, T0),
        Err(ServerRejection::SignatureInvalid)
    );
    let ws_sig = format!("{}\n{}", &SIG[..44], &SIG[44..]);
    assert!(!verify_payload(&c, &ws_sig, E_PUB));
    assert_eq!(
        server_check_publish_signature(X_PUB, Some(E_PUB), Some(&ws_sig), Some(T0), 1001, T0),
        Ok(ServerSignatureCheck::Verified)
    );
    // An unsigned-with-ts body (signPayload threw) passes the gate unchecked.
    let body: Value = serde_json::from_str(BODY_TS_NO_SIG).unwrap();
    assert_eq!(
        server_check_publish_signature(
            s(&body["publicKey"]),
            Some(s(&body["signingPublicKey"])),
            body.get("signature").and_then(Value::as_str),
            Some(s(&body["ts"]).parse().unwrap()),
            1001,
            T0 + 10 * SIG_MAX_AGE_MS
        ),
        Ok(ServerSignatureCheck::Unchecked)
    );
}
