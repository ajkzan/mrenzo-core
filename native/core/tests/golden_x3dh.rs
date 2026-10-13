//! Replays docs/native/vectors/x3dh.json — produced by the RN client's real
//! TypeScript (`mobile/src/utils/x3dh.ts`) — against the Rust port, byte for
//! byte, then the edge cases the vector file does not record.
//!
//! `TS_EDGE` (bottom of this file) was produced on 2026-09-25 by RUNNING the
//! real code, not by reading it: `mobile/src/utils/x3dh.ts` and
//! `mobile/src/services/x3dhBootstrap.ts` transpiled with the app's own
//! typescript and executed under node (versions in `TS_EDGE.produced`;
//! tweetnacl-util on its `atob` branch, as on Hermes). Randomness came from the
//! README's golden PRNG (labels and draws recorded per case), `Date.now` was
//! stubbed, MMKV was an in-memory map, and the three `/api/x3dh/*` calls were
//! stubs recording `JSON.stringify` of exactly the bodies api.ts:381,391 send.

use mrenzo_core::primitives::{
    b64, b64d, b64d32, ed25519_public_from_secret64, ed25519_sign, ed25519_verify, hkdf32, sha256, x25519, x25519_base,
};
use mrenzo_core::rng::{ReplayRng, Rng};
use mrenzo_core::x3dh::*;
use serde_json::Value;

const T0: i64 = 1_758_800_000_000;

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/x3dh.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("x3dh.json")).unwrap()
}

fn edge() -> Value {
    serde_json::from_str(TS_EDGE).expect("TS_EDGE parses")
}

fn replay(rng: &Value) -> ReplayRng {
    let label = rng["label"].as_str().unwrap_or("?").to_string();
    let draws = rng["draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let bytes = hex::decode(s(&d["hex"])).unwrap();
            assert_eq!(bytes.len() as u64, d["n"].as_u64().unwrap(), "{label}: draw size");
            bytes
        })
        .collect();
    ReplayRng::new(label, draws)
}

fn s(x: &Value) -> &str {
    x.as_str().unwrap_or_else(|| panic!("expected string, got {x}"))
}

fn i(x: &Value) -> i64 {
    x.as_i64().unwrap_or_else(|| panic!("expected integer, got {x}"))
}

fn bytes(x: &Value) -> Vec<u8> {
    b64d(s(x)).unwrap_or_else(|| panic!("bad base64 {x}"))
}

fn unhex(x: &Value) -> Vec<u8> {
    hex::decode(s(x)).unwrap()
}

fn bundle(x: &Value) -> PrekeyBundle {
    serde_json::from_value(x.clone()).unwrap_or_else(|e| panic!("bundle {x}: {e}"))
}

/// Exact `JSON.stringify` text of a recorded object (preserve_order keeps keys).
fn js(x: &Value) -> String {
    serde_json::to_string(x).unwrap()
}

/// docs/native/vectors/README.md#prng: `SHA-256(D ‖ be32(i))` blocks with
/// `D = "mrenzo-golden-prng-v1|" + label`; reads never re-align to a block.
struct StreamRng {
    prefix: Vec<u8>,
    counter: u32,
    block: Vec<u8>,
    pos: usize,
    draws: usize,
}

impl StreamRng {
    fn new(label: &str) -> Self {
        let prefix = format!("mrenzo-golden-prng-v1|{label}").into_bytes();
        StreamRng { prefix, counter: 0, block: Vec::new(), pos: 0, draws: 0 }
    }
}

impl Rng for StreamRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            if self.pos == self.block.len() {
                let mut input = self.prefix.clone();
                input.extend_from_slice(&self.counter.to_be_bytes());
                self.block = sha256(&input).to_vec();
                self.counter += 1;
                self.pos = 0;
            }
            *b = self.block[self.pos];
            self.pos += 1;
        }
        self.draws += 1;
    }
}

// ───────────────────────── the vector file ─────────────────────────

#[test]
fn every_section_of_the_vector_file_is_covered() {
    let v = vectors();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    // A section added to x3dh.json must get a test here before this passes.
    assert_eq!(
        keys,
        [
            "area",
            "schema",
            "generator",
            "encodings",
            "sources",
            "notes",
            "keys",
            "signedPreKey",
            "oneTimePreKeys",
            "bundleWithOpk",
            "bundleWithoutOpk",
            "verifyBundleSignature",
            "fourDh",
            "threeDh",
        ]
    );
    assert_eq!(s(&v["area"]), "x3dh");
    assert_eq!(v["schema"], 1);
    assert_eq!(s(&v["generator"]), "mobile/src/__tests__/goldenVectors.test.ts");
    let sources: Vec<&str> = v["sources"].as_array().unwrap().iter().map(s).collect();
    assert!(sources.contains(&"mobile/src/utils/x3dh.ts"));
    assert!(sources.contains(&"mobile/src/services/x3dhBootstrap.ts"));
    // The construction the notes pin down is the one this crate implements.
    let notes = v["notes"].as_array().unwrap().iter().map(s).collect::<Vec<_>>().join("\n");
    assert!(notes.contains(&format!("info = \"{X3DH_INFO}\"")));
    assert!(notes.contains("no 0x05 type byte"));
    assert!(notes.contains("AD = IKa_pub(32) || IKb_pub(32)"));
}

#[test]
fn keys_block_is_self_consistent() {
    let v = vectors();
    for (who, uid) in [("alice", 1001), ("bob", 2002)] {
        let k = &v["keys"][who];
        assert_eq!(i(&k["uid"]), uid);
        let xpriv = b64d32(s(&k["x25519PrivB64"])).unwrap();
        assert_eq!(b64(&x25519_base(&xpriv)), s(&k["x25519PubB64"]), "{who} x25519");
        let epriv: [u8; 64] = bytes(&k["ed25519PrivB64"]).try_into().unwrap();
        assert_eq!(b64(&ed25519_public_from_secret64(&epriv)), s(&k["ed25519PubB64"]), "{who} ed25519");
    }
    // Both bundles are bob's.
    for name in ["bundleWithOpk", "bundleWithoutOpk"] {
        let b = &v[name];
        assert_eq!(b["userId"], v["keys"]["bob"]["uid"]);
        assert_eq!(b["identityKey"], v["keys"]["bob"]["x25519PubB64"]);
        assert_eq!(b["signingKey"], v["keys"]["bob"]["ed25519PubB64"]);
    }
}

#[test]
fn golden_prng_reproduces_every_recorded_draw() {
    let v = vectors();
    for sec in ["signedPreKey", "oneTimePreKeys", "fourDh", "threeDh"] {
        let rng = &v[sec]["rng"];
        let mut stream = StreamRng::new(s(&rng["label"]));
        for d in rng["draws"].as_array().unwrap() {
            let mut buf = vec![0u8; d["n"].as_u64().unwrap() as usize];
            stream.fill(&mut buf);
            assert_eq!(hex::encode(&buf), s(&d["hex"]), "{sec}");
        }
    }
}

#[test]
fn signed_pre_key_byte_exact() {
    let v = vectors();
    let sec = &v["signedPreKey"];
    let key_id = i(&sec["keyId"]);
    assert_eq!(s(&sec["function"]), format!("x3dh.generateSignedPreKey(ed25519Priv, keyId={key_id})"));
    let bob_ed = bytes(&v["keys"]["bob"]["ed25519PrivB64"]);

    let mut rng = replay(&sec["rng"]);
    let spk = generate_signed_pre_key(&bob_ed, key_id, &mut rng).unwrap();
    rng.assert_exhausted();

    assert_eq!(spk.key_id, key_id);
    assert_eq!(spk.priv_key, s(&sec["privKey"]));
    assert_eq!(spk.pub_key, s(&sec["pubKey"]));
    assert_eq!(spk.signature, s(&sec["signature"]));
    // Same object, same key order as `...spk.value` in the vector.
    let recorded: serde_json::Map<String, Value> = sec
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| *k != "function" && *k != "rng")
        .map(|(k, x)| (k.clone(), x.clone()))
        .collect();
    assert_eq!(serde_json::to_string(&spk).unwrap(), js(&Value::Object(recorded)));

    // The private key is the RAW draw (unclamped), the pub its base multiple.
    let draw = unhex(&sec["rng"]["draws"][0]["hex"]);
    assert_eq!(bytes(&sec["privKey"]), draw);
    assert_eq!(bytes(&sec["pubKey"]), x25519_base(&draw.clone().try_into().unwrap()));

    // Signature is over the RAW 32 pub bytes — not 0x05‖pub, not the base64 text.
    let bob_pub = b64d32(s(&v["keys"]["bob"]["ed25519PubB64"])).unwrap();
    let sig = bytes(&sec["signature"]);
    let raw_pub = bytes(&sec["pubKey"]);
    assert!(ed25519_verify(&bob_pub, &raw_pub, &sig));
    let mut libsignal = vec![0x05];
    libsignal.extend_from_slice(&raw_pub);
    assert!(!ed25519_verify(&bob_pub, &libsignal, &sig));
    assert!(!ed25519_verify(&bob_pub, s(&sec["pubKey"]).as_bytes(), &sig));
}

#[test]
fn one_time_pre_keys_byte_exact() {
    let v = vectors();
    let sec = &v["oneTimePreKeys"];
    let keys = sec["keys"].as_array().unwrap();
    let start = i(&keys[0]["keyId"]);
    let count = keys.len() as i64;
    assert_eq!(s(&sec["function"]), format!("x3dh.generateOneTimePreKeys(startId={start}, count={count})"));

    let mut rng = replay(&sec["rng"]);
    let out = generate_one_time_pre_keys(start, count, &mut rng);
    rng.assert_exhausted();

    assert_eq!(serde_json::to_string(&out).unwrap(), js(&sec["keys"]));
    for (k, d) in out.iter().zip(sec["rng"]["draws"].as_array().unwrap()) {
        let draw: [u8; 32] = unhex(&d["hex"]).try_into().unwrap();
        assert_eq!(k.priv_key, b64(&draw));
        assert_eq!(k.pub_key, b64(&x25519_base(&draw)));
    }
}

#[test]
fn bundles_byte_exact() {
    let v = vectors();
    let b4 = bundle(&v["bundleWithOpk"]);
    let b3 = bundle(&v["bundleWithoutOpk"]);
    // Parse → serialise reproduces the recorded objects exactly (key order too).
    assert_eq!(serde_json::to_string(&b4).unwrap(), js(&v["bundleWithOpk"]));
    assert_eq!(serde_json::to_string(&b3).unwrap(), js(&v["bundleWithoutOpk"]));

    // And they are exactly what the generator built from the other sections.
    let spk = &v["signedPreKey"];
    let opk0 = &v["oneTimePreKeys"]["keys"][0];
    let rebuilt = PrekeyBundle {
        user_id: i(&v["keys"]["bob"]["uid"]),
        identity_key: s(&v["keys"]["bob"]["x25519PubB64"]).into(),
        signing_key: Some(s(&v["keys"]["bob"]["ed25519PubB64"]).into()),
        signed_pre_key: SignedPreKey {
            key_id: i(&spk["keyId"]),
            pub_key: s(&spk["pubKey"]).into(),
            signature: s(&spk["signature"]).into(),
        },
        one_time_pre_key: Some(OneTimePreKey { key_id: i(&opk0["keyId"]), pub_key: s(&opk0["pubKey"]).into() }),
    };
    assert_eq!(rebuilt, b4);
    assert_eq!(PrekeyBundle { one_time_pre_key: None, ..rebuilt }, b3);
}

#[test]
fn verify_bundle_signature_as_recorded() {
    let v = vectors();
    let sec = &v["verifyBundleSignature"];
    assert_eq!(sec.as_object().unwrap().keys().collect::<Vec<_>>(), ["bundleWithOpk", "tamperedSpkPub", "tamperedBundle"]);
    assert_eq!(verify_bundle_signature(&bundle(&v["bundleWithOpk"])), sec["bundleWithOpk"].as_bool().unwrap());
    assert!(verify_bundle_signature(&bundle(&v["bundleWithoutOpk"])), "the OPK is not covered by the signature");

    // tamperedBundle = bundleWithOpk with the SPK pub swapped for OPK #2's pub.
    let mut expected_tampered = v["bundleWithOpk"].clone();
    expected_tampered["signedPreKey"]["pubKey"] = v["oneTimePreKeys"]["keys"][1]["pubKey"].clone();
    assert_eq!(js(&sec["tamperedBundle"]), js(&expected_tampered));
    let tampered = bundle(&sec["tamperedBundle"]);
    assert_eq!(serde_json::to_string(&tampered).unwrap(), js(&sec["tamperedBundle"]));
    assert_eq!(verify_bundle_signature(&tampered), sec["tamperedSpkPub"].as_bool().unwrap());
}

#[test]
fn four_dh_and_three_dh_byte_exact() {
    let v = vectors();
    let alice_priv = bytes(&v["keys"]["alice"]["x25519PrivB64"]);
    let alice_pub = bytes(&v["keys"]["alice"]["x25519PubB64"]);
    let bob_priv = bytes(&v["keys"]["bob"]["x25519PrivB64"]);
    let bob_pub = bytes(&v["keys"]["bob"]["x25519PubB64"]);
    let mut roots = Vec::new();

    for (sec, bundle_name) in [("fourDh", "bundleWithOpk"), ("threeDh", "bundleWithoutOpk")] {
        let d = &v[sec];
        let b = bundle(&v[bundle_name]);

        // Sender (alice), replaying the recorded ephemeral draw.
        let mut rng = replay(&d["rng"]);
        let hs = derive_shared_secret_as_sender(&alice_priv, &alice_pub, &b, &mut rng).unwrap();
        rng.assert_exhausted();
        assert_eq!(b64(&hs.ephemeral_pub), s(&d["ephemeralPubB64"]), "{sec}");
        assert_eq!(hex::encode(hs.shared_root), s(&d["sharedRootHex"]), "{sec}");
        assert_eq!(hex::encode(&hs.associated_data), s(&d["associatedDataHex"]), "{sec}");
        assert_eq!(hs.used_signed_pre_key_id, i(&d["usedSignedPreKeyId"]), "{sec}");
        assert_eq!(hs.used_one_time_pre_key_id, d["usedOneTimePreKeyId"].as_i64(), "{sec}");
        assert_eq!(d["usedOneTimePreKeyId"].is_null(), b.one_time_pre_key.is_none(), "{sec}");

        // Recipient (bob): look up the privates by the ids the sender reports.
        assert_eq!(v["signedPreKey"]["keyId"], d["usedSignedPreKeyId"]);
        let spk_priv = bytes(&v["signedPreKey"]["privKey"]);
        let opk_priv = d["usedOneTimePreKeyId"].as_i64().map(|id| {
            let k = v["oneTimePreKeys"]["keys"].as_array().unwrap().iter().find(|k| i(&k["keyId"]) == id).unwrap();
            bytes(&k["privKey"])
        });
        let eph = bytes(&d["ephemeralPubB64"]);
        let r = derive_shared_secret_as_recipient(&bob_priv, &bob_pub, &spk_priv, opk_priv.as_deref(), &alice_pub, &eph)
            .unwrap();
        assert_eq!(hex::encode(r.shared_root), s(&d["sharedRootHex"]), "{sec} recipient");
        assert_eq!(hex::encode(&r.associated_data), s(&d["associatedDataHex"]), "{sec} recipient AD");

        // Independent recomputation of the notes' formula from primitives.
        let ek: [u8; 32] = unhex(&d["rng"]["draws"][0]["hex"]).try_into().unwrap();
        assert_eq!(x25519_base(&ek).to_vec(), eph);
        let k32 = |x: &[u8]| -> [u8; 32] { x.try_into().unwrap() };
        let spkb = k32(&b64d(&b.signed_pre_key.pub_key).unwrap());
        let mut ikm = vec![0xffu8; 32];
        ikm.extend_from_slice(&x25519(&k32(&alice_priv), &spkb));
        ikm.extend_from_slice(&x25519(&ek, &k32(&bob_pub)));
        ikm.extend_from_slice(&x25519(&ek, &spkb));
        if let Some(opk) = &b.one_time_pre_key {
            ikm.extend_from_slice(&x25519(&ek, &k32(&b64d(&opk.pub_key).unwrap())));
        }
        assert_eq!(ikm.len(), if b.one_time_pre_key.is_some() { 160 } else { 128 });
        assert_eq!(hex::encode(hkdf32(&ikm, b"mr.enzo.x3dh.v1")), s(&d["sharedRootHex"]), "{sec} formula");
        assert_eq!(hex::encode([alice_pub.as_slice(), bob_pub.as_slice()].concat()), s(&d["associatedDataHex"]));
        roots.push(hs.shared_root);
    }
    assert_ne!(roots[0], roots[1]);
}

// ───────────────── edge cases recorded from the running TS ─────────────────

fn opt_err<T>(r: &Result<T, X3dhError>) -> Value {
    match r {
        Ok(_) => Value::Null,
        Err(e) => Value::String(e.to_string()),
    }
}

#[test]
fn ts_edge_verify_bundle_signature() {
    let e = edge();
    let cases = e["verifyBundleSignature"].as_array().unwrap();
    assert_eq!(cases.len(), 19);
    for c in cases {
        let name = s(&c["name"]);
        assert_eq!(verify_bundle_signature(&bundle(&c["bundle"])), c["result"].as_bool().unwrap(), "{name}");
    }
    // The ones that matter for interop, spelled out.
    let r = |n: &str| cases.iter().find(|c| c["name"] == n).unwrap()["result"].as_bool().unwrap();
    assert!(!r("signingKeyEmpty"), "Go serves an empty signingKey today");
    assert!(r("signatureSPlusL"), "tweetnacl accepts a non-reduced S");
    assert!(r("signatureTrailingBits") && r("signingKeyTrailingBits") && r("spkPubTrailingBits"));
    assert!(r("spkPub33SignedByBob") && r("spkPubEmptySignedByBob"), "SPK length unchecked");
    assert!(!r("libsignalStyle0x05") && !r("signatureOverB64String"));
}

#[test]
fn ts_edge_derive_as_sender() {
    let e = edge();
    let cases = e["deriveSharedSecretAsSender"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for c in cases {
        let name = s(&c["name"]);
        let mut rng = replay(&serde_json::json!({ "label": c["label"], "draws": c["draws"] }));
        let got = derive_shared_secret_as_sender(
            &unhex(&c["myIdentityPrivHex"]),
            &unhex(&c["myIdentityPubHex"]),
            &bundle(&c["bundle"]),
            &mut rng,
        );
        // Draw count is part of the contract even when the TS throws.
        rng.assert_exhausted();
        assert_eq!(opt_err(&got), c["error"], "{name}: error");
        match (&got, c.get("result").filter(|x| !x.is_null())) {
            (Ok(hs), Some(x)) => {
                assert_eq!(hex::encode(hs.shared_root), s(&x["sharedRootHex"]), "{name}");
                assert_eq!(b64(&hs.ephemeral_pub), s(&x["ephemeralPubB64"]), "{name}");
                assert_eq!(hex::encode(&hs.associated_data), s(&x["associatedDataHex"]), "{name}");
                assert_eq!(hs.used_signed_pre_key_id, i(&x["usedSignedPreKeyId"]), "{name}");
                assert_eq!(hs.used_one_time_pre_key_id, x["usedOneTimePreKeyId"].as_i64(), "{name}");
            }
            (Err(_), None) => {}
            (got, want) => panic!("{name}: got {got:?}, TS {want:?}"),
        }
    }
}

#[test]
fn ts_edge_derive_as_recipient() {
    let e = edge();
    let cases = e["deriveSharedSecretAsRecipient"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for c in cases {
        let name = s(&c["name"]);
        let a: Vec<Option<Vec<u8>>> =
            c["args"].as_array().unwrap().iter().map(|x| x.as_str().map(|h| hex::decode(h).unwrap())).collect();
        let got = derive_shared_secret_as_recipient(
            a[0].as_deref().unwrap(),
            a[1].as_deref().unwrap(),
            a[2].as_deref().unwrap(),
            a[3].as_deref(),
            a[4].as_deref().unwrap(),
            a[5].as_deref().unwrap(),
        );
        assert_eq!(opt_err(&got), c["error"], "{name}: error");
        match (&got, c.get("result").filter(|x| !x.is_null())) {
            (Ok(r), Some(x)) => {
                assert_eq!(hex::encode(r.shared_root), s(&x["sharedRootHex"]), "{name}");
                assert_eq!(hex::encode(&r.associated_data), s(&x["associatedDataHex"]), "{name}");
            }
            (Err(_), None) => {}
            (got, want) => panic!("{name}: got {got:?}, TS {want:?}"),
        }
    }
}

#[test]
fn ts_edge_generate() {
    let e = edge();
    let cases = e["generate"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let v = vectors();
    for c in cases {
        let name = s(&c["name"]);
        let inp = &c["inputs"];
        let mut rng = replay(&serde_json::json!({ "label": c["label"], "draws": c["draws"] }));
        let mut stream = StreamRng::new(s(&c["label"]));
        match s(&inp["fn"]) {
            "generateSignedPreKey" => {
                let ed = unhex(&inp["ed25519PrivHex"]);
                let got = generate_signed_pre_key(&ed, i(&inp["keyId"]), &mut rng);
                rng.assert_exhausted();
                assert_eq!(opt_err(&got), c["error"], "{name}");
                if let Ok(spk) = &got {
                    assert_eq!(serde_json::to_string(spk).unwrap(), js(&c["result"]), "{name}");
                }
                assert_eq!(generate_signed_pre_key(&ed, i(&inp["keyId"]), &mut stream), got, "{name} (stream)");
            }
            "generateOneTimePreKeys" => {
                let got = generate_one_time_pre_keys(i(&inp["startId"]), i(&inp["count"]), &mut rng);
                rng.assert_exhausted();
                assert_eq!(serde_json::to_string(&got).unwrap(), js(&c["result"]), "{name}");
                assert_eq!(generate_one_time_pre_keys(i(&inp["startId"]), i(&inp["count"]), &mut stream), got);
            }
            f => panic!("unknown fn {f}"),
        }
    }
    // tweetnacl's stored-pub-half signing: same R as the real signature, other S.
    let mixed = cases.iter().find(|c| c["name"] == "spkMixedPubHalf").unwrap();
    let sig = bytes(&mixed["result"]["signature"]);
    let real = bytes(&v["signedPreKey"]["signature"]);
    assert_eq!(sig[..32], real[..32]);
    assert_ne!(sig[32..], real[32..]);
    let bob_ed: [u8; 64] = bytes(&v["keys"]["bob"]["ed25519PrivB64"]).try_into().unwrap();
    assert_eq!(ed25519_sign(&bob_ed, &bytes(&v["signedPreKey"]["pubKey"])).to_vec(), real);
}

#[test]
fn ts_edge_get_stored_spk_priv() {
    let e = edge();
    let cases = e["getStoredSPKPriv"].as_array().unwrap();
    assert_eq!(cases.len(), 28);
    for c in cases {
        let name = s(&c["name"]);
        let got = get_stored_spk_priv(c["raw"].as_str(), i(&c["keyId"]));
        assert_eq!(got.map(hex::encode), c["resultHex"].as_str().map(String::from), "{name}");
    }
}

#[test]
fn ts_edge_consume_stored_opk_priv() {
    let e = edge();
    let cases = e["consumeStoredOPKPriv"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        let name = s(&c["name"]);
        let raw = c["raw"].as_str();
        let got = consume_stored_opk_priv(raw);
        assert_eq!(got.priv_key.map(hex::encode), c["resultHex"].as_str().map(String::from), "{name}");
        let still_stored = c["stillStored"].as_bool().unwrap();
        assert_eq!(got.delete_entry, raw.is_some() && !still_stored, "{name}: delete");
    }
    assert_eq!(opk_storage_key(100), "opk:100");
}

#[test]
fn ts_edge_ensure_spk_rotation() {
    let e = edge();
    let bob_ed = bytes(&vectors()["keys"]["bob"]["ed25519PrivB64"]);
    let cases = e["ensureSPK"].as_array().unwrap();
    assert_eq!(cases.len(), 34);
    let mut uploads = 0;
    for c in cases {
        let name = s(&c["name"]);
        let raw = c["raw"].as_str();
        let now = i(&c["nowMs"]);
        let uploaded = c["uploadedSpk"].as_bool().unwrap();
        assert_eq!(spk_needs_new(raw, now), uploaded, "{name}");
        let before = i(&c["nextBefore"]);
        // Every case carries the full TS record (no row may be trimmed): the
        // draws, the upload body and the stored entry, even when nothing happened.
        let mut rng = replay(&serde_json::json!({ "label": c["label"], "draws": c["draws"] }));
        if uploaded {
            uploads += 1;
            let (key_id, next) = next_key_id(Some(before));
            assert_eq!(key_id, before);
            assert_eq!(next, i(&c["nextKeyId"]), "{name}");
            assert_eq!(i(&c["spkRotatedAt"]), now, "{name}");
            let spk = generate_signed_pre_key(&bob_ed, key_id, &mut rng).unwrap();
            rng.assert_exhausted();
            assert_eq!(spk_upload_body(spk.key_id, &spk.pub_key, &spk.signature), s(&c["spkBody"]), "{name}");
            assert_eq!(StoredSpk::from_generated(&spk, now).to_json(), s(&c["storedSpk"]), "{name}");
            let parsed: StoredSpk = serde_json::from_str(s(&c["storedSpk"])).unwrap();
            assert_eq!(parsed, StoredSpk::from_generated(&spk, now));
            // Right after a rotation the stored entry is fresh and readable.
            assert!(!spk_needs_new(c["storedSpk"].as_str(), now), "{name}");
            assert_eq!(get_stored_spk_priv(c["storedSpk"].as_str(), spk.key_id), b64d(&spk.priv_key));
        } else {
            // No rotation: no draw, no upload, and storage left exactly as it was.
            rng.assert_exhausted();
            assert_eq!(i(&c["nextKeyId"]), before, "{name}");
            assert!(c["spkRotatedAt"].is_null(), "{name}");
            assert!(c["spkBody"].is_null(), "{name}");
            assert_eq!(c["storedSpk"].as_str(), raw, "{name}");
        }
    }
    assert_eq!(uploads, 17);
}

#[test]
fn ts_edge_ensure_opks_refill_and_key_ids() {
    let e = edge();
    let bob_ed = bytes(&vectors()["keys"]["bob"]["ed25519PrivB64"]);
    let cases = e["ensureOPKs"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for c in cases {
        let name = s(&c["name"]);
        let mut rng = StreamRng::new(s(&c["label"]));
        let mut next = c.get("next").map(i);
        // ensureSPK
        let spk_raw = c["spkRaw"].as_str();
        assert_eq!(spk_raw.is_some(), c["spkPresent"].as_bool().unwrap());
        if spk_needs_new(spk_raw, T0) {
            let (key_id, n) = next_key_id(next);
            next = Some(n);
            let spk = generate_signed_pre_key(&bob_ed, key_id, &mut rng).unwrap();
            assert_eq!(spk_upload_body(spk.key_id, &spk.pub_key, &spk.signature), s(&c["spkBody"]), "{name}");
        } else {
            assert!(c["spkBody"].is_null(), "{name}");
        }
        // ensureOPKs
        let pending = c.get("pending").and_then(Value::as_bool).unwrap_or(false);
        let mut pending_after = if pending { Some(true) } else { None };
        let uploads = !c["countFail"].as_bool().unwrap() && opk_refill_needed(c.get("count"), pending);
        assert_eq!(uploads, c["uploadedOtps"].as_bool().unwrap(), "{name}");
        let mut stored = Vec::new();
        if uploads {
            let (start, n) = next_key_id(next);
            next = Some(n);
            let batch = generate_one_time_pre_keys(start, OPK_REFILL_BATCH, &mut rng);
            let body = otps_upload_body(&batch);
            assert_eq!(hex::encode(sha256(body.as_bytes())), s(&c["otpsBodySha256"]), "{name}");
            if c["otpFail"].as_bool().unwrap() {
                pending_after = Some(true);
            } else {
                pending_after = None;
                next = Some(next_key_id_after_opk_upload(start));
                stored = batch.iter().map(|k| (opk_storage_key(k.key_id), k.priv_key.clone())).collect();
            }
        }
        assert_eq!(rng.draws as u64, c["drawCount"].as_u64().unwrap(), "{name}: draws");
        assert_eq!(next, c["nextKeyIdAfter"].as_i64(), "{name}: nextKeyId");
        assert_eq!(pending_after, c["pendingAfter"].as_bool(), "{name}: pending");
        assert_eq!(stored.len() as u64, c["storedOpkCount"].as_u64().unwrap(), "{name}");
        if let Some((first, last)) = stored.first().zip(stored.last()) {
            assert_eq!((first.0.as_str(), first.1.as_str()), (s(&c["storedOpkFirst"]["key"]), s(&c["storedOpkFirst"]["value"])));
            assert_eq!((last.0.as_str(), last.1.as_str()), (s(&c["storedOpkLast"]["key"]), s(&c["storedOpkLast"]["value"])));
        }
    }
    // The failed-upload overlap quirk: the retry batch re-uses start+1 … start+99.
    let (start, after_fail) = next_key_id(Some(50));
    assert_eq!((start, after_fail), (50, 51));
    assert_eq!(next_key_id(Some(after_fail)).0, 51);
    assert_eq!(next_key_id_after_opk_upload(start), 150);
}

#[test]
fn bootstrap_constants_and_bodies() {
    assert_eq!(MMKV_ID, "mrenzo-x3dh");
    assert_eq!((KEY_SPK, KEY_OPK_PREFIX, KEY_NEXT_ID), ("spk:current", "opk:", "nextKeyId"));
    assert_eq!((KEY_SPK_ROTATED_AT, KEY_OPK_RETRY), ("spkRotatedAt", "opkRefillPending"));
    assert_eq!(SPK_ROTATION_INTERVAL_MS, 604_800_000);
    assert_eq!((OPK_LOW_WATERMARK, OPK_REFILL_BATCH), (20, 100));
    assert_eq!((PATH_SPK, PATH_OTPS, PATH_OTP_COUNT, PATH_BUNDLE_PREFIX), ("/api/x3dh/spk", "/api/x3dh/otps", "/api/x3dh/otp-count", "/api/x3dh/bundle/"));
    assert_eq!(next_key_id(None), (1, 2));
    assert_eq!(next_key_id(Some(0)), (0, 1), "`?? 1`, not `|| 1`");

    // Upload bodies from the vector's own SPK / OPKs.
    let v = vectors();
    let spk = &v["signedPreKey"];
    assert_eq!(
        spk_upload_body(i(&spk["keyId"]), s(&spk["pubKey"]), s(&spk["signature"])),
        format!(r#"{{"keyId":1,"pubKey":"{}","signature":"{}"}}"#, s(&spk["pubKey"]), s(&spk["signature"]))
    );
    let opks: Vec<GeneratedOneTimePreKey> = serde_json::from_value(v["oneTimePreKeys"]["keys"].clone()).unwrap();
    assert_eq!(
        otps_upload_body(&opks),
        format!(
            r#"{{"keys":[{{"keyId":100,"pubKey":"{}"}},{{"keyId":101,"pubKey":"{}"}}]}}"#,
            opks[0].pub_key, opks[1].pub_key
        )
    );

    // The Go bundle response (sorted keys, extra signedPreKey.userId, no OPK)
    // parses to the same bundle.
    let go = format!(
        r#"{{"identityKey":"{}","signedPreKey":{{"userId":2002,"keyId":1,"pubKey":"{}","signature":"{}"}},"signingKey":"{}","userId":2002}}"#,
        s(&v["bundleWithoutOpk"]["identityKey"]),
        s(&spk["pubKey"]),
        s(&spk["signature"]),
        s(&v["bundleWithoutOpk"]["signingKey"])
    );
    assert_eq!(serde_json::from_str::<PrekeyBundle>(&go).unwrap(), bundle(&v["bundleWithoutOpk"]));
}

#[test]
fn error_texts_are_the_ts_messages() {
    assert_eq!(X3dhError::BadIdentityPrivLength.to_string(), "myIdentityPriv must be 32 bytes (X25519 secret)");
    assert_eq!(X3dhError::InvalidEncoding.to_string(), "invalid encoding");
    assert_eq!(X3dhError::BadNSize.to_string(), "bad n size");
    assert_eq!(X3dhError::BadPSize.to_string(), "bad p size");
    assert_eq!(X3dhError::BadSecretKeySize.to_string(), "bad secret key size");
}

/// Recorded from the running TypeScript — see the module docs.
const TS_EDGE: &str = r##"{
"produced": "node v22.14.0, tweetnacl 1.0.3, tweetnacl-util 0.15.1, @noble/hashes 1.7.1, typescript 5.9.3, tweetnacl-util atob branch: true",
"verifyBundleSignature": [
{"name":"vector","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":true},
{"name":"signingKeyEmpty","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signingKeyNull","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":null,"signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signingKeyMissing","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signatureTrailingBits","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDh=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":true},
{"name":"signingKeyTrailingBits","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GV=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":true},
{"name":"spkPubTrailingBits","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyZ=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":true},
{"name":"signatureSPlusL","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm5pv98QJW8x+O53AoCKOOC810oQyMCibAuIIlAsIulIHg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":true},
{"name":"signature63","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulI"},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signingKey31","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8A==","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signingKeyInvalidB64","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"not base64!","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"spkPubInvalidB64","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"abc","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signatureInvalidB64","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg==="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"spkPub33SignedByBob","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyYH","signature":"xKTH67dn/oAexuhOdcUkZDWYawY22qvbdNl8I+lPphq7Q0MFxWbG+tf8EcxjvZ6pOoP8xCrZL34Gn5O3CJyFAw=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":true},
{"name":"spkPubEmptySignedByBob","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"","signature":"QNxQrwLaO2EC0WZczLetN5WXKwIToqrbSrmBvHciZmQmLh6zSjsqfJqQ0Z0vD16Xx51OcjZ4T5vl5rMHpTvODA=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":true},
{"name":"libsignalStyle0x05","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"rC2eBRD1ldAMbiDp06+EmN0GOcrQxnBEL1RKQmjc8EMiIXlHK3ctzp7kLxH3Hj6Wt4pkvLVOC6Uje7jCzaqcAg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"wrongSigningKeyAlice","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"YuP0WTQ3fy1EhYQa0uDCZrSc7jJwoX3IzmjAvz/8+Oo=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signatureOverB64String","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"yl18OfjQQJK85kTNwEOkkEG/tT1IBSzmCSRhQndbRsz6P9gimue4ZSdZU37aGTNl1CcTipawz+lkK5i5+r7kAQ=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false},
{"name":"signingKeyIdentityPoint","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"result":false}
],
"deriveSharedSecretAsSender": [
{"name":"priv31","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[],"error":"myIdentityPriv must be 32 bytes (X25519 secret)"},
{"name":"identityKeyInvalidB64","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"not base64!","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":"invalid encoding"},
{"name":"spkPub31","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXw==","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":"bad p size"},
{"name":"identityKey33","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxkA","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":"bad p size"},
{"name":"opkPubInvalidB64","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"@@@@"}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":"invalid encoding"},
{"name":"opkPubEmpty","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":""}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":"bad p size"},
{"name":"opkInvalidAndSpk31","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXw==","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"@@@@"}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":"invalid encoding"},
{"name":"myPubEmpty","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":null,"result":{"sharedRootHex":"ce2d503df39a40450ed9b79681138a1d02a7163b690064fd256bc1355639c5e1","ephemeralPubB64":"DY4VljMxj32q5kNTO8emLlDy69K6YYpP+6sULCQW90M=","associatedDataHex":"d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","usedSignedPreKeyId":1,"usedOneTimePreKeyId":100}},
{"name":"myPubWrong","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":null,"result":{"sharedRootHex":"ce2d503df39a40450ed9b79681138a1d02a7163b690064fd256bc1355639c5e1","ephemeralPubB64":"DY4VljMxj32q5kNTO8emLlDy69K6YYpP+6sULCQW90M=","associatedDataHex":"d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","usedSignedPreKeyId":1,"usedOneTimePreKeyId":100}},
{"name":"identityKeyTrailingBits","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxl=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":null,"result":{"sharedRootHex":"ce2d503df39a40450ed9b79681138a1d02a7163b690064fd256bc1355639c5e1","ephemeralPubB64":"DY4VljMxj32q5kNTO8emLlDy69K6YYpP+6sULCQW90M=","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","usedSignedPreKeyId":1,"usedOneTimePreKeyId":100}},
{"name":"spkLowOrderZero","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":null,"result":{"sharedRootHex":"eb1f1735957667c0ca2c36013bd29df6d55c209df93aafae838862b55e5e05fc","ephemeralPubB64":"DY4VljMxj32q5kNTO8emLlDy69K6YYpP+6sULCQW90M=","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","usedSignedPreKeyId":1,"usedOneTimePreKeyId":100}},
{"name":"identityKeyHighBit","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMG5k=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":null,"result":{"sharedRootHex":"ce2d503df39a40450ed9b79681138a1d02a7163b690064fd256bc1355639c5e1","ephemeralPubB64":"DY4VljMxj32q5kNTO8emLlDy69K6YYpP+6sULCQW90M=","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b99","usedSignedPreKeyId":1,"usedOneTimePreKeyId":100}},
{"name":"opkPresentNoSignatureCheck","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"","signedPreKey":{"keyId":1,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":""},"oneTimePreKey":{"keyId":100,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":null,"result":{"sharedRootHex":"ce2d503df39a40450ed9b79681138a1d02a7163b690064fd256bc1355639c5e1","ephemeralPubB64":"DY4VljMxj32q5kNTO8emLlDy69K6YYpP+6sULCQW90M=","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","usedSignedPreKeyId":1,"usedOneTimePreKeyId":100}},
{"name":"opkKeyIdZero","label":"x3dh/alice.derive.4dh","bundle":{"userId":2002,"identityKey":"0j4jbZrCELLrekjb0sefwfEc8X89uN2S0+thnzfMGxk=","signingKey":"ILHzH2/hyV/rzur5RwmeNOvwcwOblysQMDIsADWD8GU=","signedPreKey":{"keyId":7,"pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="},"oneTimePreKey":{"keyId":0,"pubKey":"mq9sV+UW7kHO6JLEhLMdxGivL1lrP4aCDOu0agNHoH4="}},"myIdentityPrivHex":"ec64ce85ce631ff8cb53fc1656b8f52f6cbdfc9e45eefaf8eb401330cf72be0b","myIdentityPubHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","draws":[{"n":32,"hex":"82c8d0fa1f64f5596996e957dcdfa6e47d8cf509d014e8c1ceb039d59cbc7237"}],"error":null,"result":{"sharedRootHex":"ce2d503df39a40450ed9b79681138a1d02a7163b690064fd256bc1355639c5e1","ephemeralPubB64":"DY4VljMxj32q5kNTO8emLlDy69K6YYpP+6sULCQW90M=","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","usedSignedPreKeyId":7,"usedOneTimePreKeyId":0}}
],
"deriveSharedSecretAsRecipient": [
{"name":"opkEmpty","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506","","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":"bad n size","result":null},
{"name":"spkPriv31","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e5","48f22fb925bdb71fc617b4db1136bd02b999d445c0935b91d88741cf61d6934b","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":"bad n size","result":null},
{"name":"senderEph31","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506","48f22fb925bdb71fc617b4db1136bd02b999d445c0935b91d88741cf61d6934b","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f7"],"error":"bad p size","result":null},
{"name":"senderIk31","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506","48f22fb925bdb71fc617b4db1136bd02b999d445c0935b91d88741cf61d6934b","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad8","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":"bad p size","result":null},
{"name":"myPriv31","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7d","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506","48f22fb925bdb71fc617b4db1136bd02b999d445c0935b91d88741cf61d6934b","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":"bad n size","result":null},
{"name":"opkMissingButSenderUsedOne","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506",null,"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":null,"result":{"sharedRootHex":"3057cec138b26922e859870acf83ee12610791bcefaa7eaf7a35febf41c00f2f","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19"}},
{"name":"myPubEmpty","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506","48f22fb925bdb71fc617b4db1136bd02b999d445c0935b91d88741cf61d6934b","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":null,"result":{"sharedRootHex":"ce2d503df39a40450ed9b79681138a1d02a7163b690064fd256bc1355639c5e1","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849"}},
{"name":"wrongOpk","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506","9c9b9bb492400521d08a0c7c514d08c538cdf74e708eb631fa0d77a47cb881d1","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":null,"result":{"sharedRootHex":"895032d6409ec49473510780ef8de14e6c0d07a132139b1862566f8610f980b2","associatedDataHex":"a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19"}},
{"name":"opk33","args":["fe31d4044e4c8784d4766a3aed5f549ba674508f7a9efc9e098e7b616c6b7dab","d23e236d9ac210b2eb7a48dbd2c79fc1f11cf17f3db8dd92d3eb619f37cc1b19","73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506","000000000000000000000000000000000000000000000000000000000000000000","a31d70496e0100ee844c66d23c1a806bf6f9296592151ef34dc4f97bc24ad849","0d8e159633318f7daae643533bc7a62e50f2ebd2ba618a4ffbab142c2416f743"],"error":"bad n size","result":null}
],
"generate": [
{"name":"spkEdPriv32","label":"x3dh/bob.generateSignedPreKey","inputs":{"fn":"generateSignedPreKey","ed25519PrivHex":"50060d872b8275527f7e4dd4d99236bd0cda496c2270648e1ca919fd03079692","keyId":1},"draws":[{"n":32,"hex":"73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506"}],"error":"bad secret key size","result":null},
{"name":"spkMixedPubHalf","label":"x3dh/bob.generateSignedPreKey","inputs":{"fn":"generateSignedPreKey","ed25519PrivHex":"50060d872b8275527f7e4dd4d99236bd0cda496c2270648e1ca919fd0307969262e3f45934377f2d4485841ad2e0c266b49cee3270a17dc8ce68c0bf3ffcf8ea","keyId":1},"draws":[{"n":32,"hex":"73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506"}],"error":null,"result":{"keyId":1,"privKey":"c7DdrJkYjwSPJNTcDRFRrGR1MTmPX1+bwMussrWw5QY=","pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm4vXphFtENNeewd0Qhwuv+3vfvDL73xan5WmtRhFRAxAA=="}},
{"name":"spkKeyIdNeg","label":"x3dh/bob.generateSignedPreKey","inputs":{"fn":"generateSignedPreKey","ed25519PrivHex":"50060d872b8275527f7e4dd4d99236bd0cda496c2270648e1ca919fd0307969220b1f31f6fe1c95febceeaf947099e34ebf073039b972b1030322c003583f065","keyId":-5},"draws":[{"n":32,"hex":"73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506"}],"error":null,"result":{"keyId":-5,"privKey":"c7DdrJkYjwSPJNTcDRFRrGR1MTmPX1+bwMussrWw5QY=","pubKey":"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=","signature":"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg=="}},
{"name":"opkCount0","label":"x3dh/extra.opk.count0","inputs":{"fn":"generateOneTimePreKeys","startId":100,"count":0},"draws":[],"error":null,"result":[]},
{"name":"opkCountNeg","label":"x3dh/extra.opk.countNeg","inputs":{"fn":"generateOneTimePreKeys","startId":100,"count":-3},"draws":[],"error":null,"result":[]},
{"name":"opkStart5Count3","label":"x3dh/extra.opk.start5","inputs":{"fn":"generateOneTimePreKeys","startId":5,"count":3},"draws":[{"n":32,"hex":"7cfc9f1a72583ca46cdac01f1ee7995bbd4b08b17107022e309046b38826d2c5"},{"n":32,"hex":"b28e42b56917b377941d59a58f22d658be64c46a3eb58f056e04eda13a5ef4c1"},{"n":32,"hex":"c4fcce29b877495069892a706ca94aef056a81fcb321eae2745b230bd9c2136f"}],"error":null,"result":[{"keyId":5,"privKey":"fPyfGnJYPKRs2sAfHueZW71LCLFxBwIuMJBGs4gm0sU=","pubKey":"qC7dh4wMrIjFXqyGil2kOnshfd57d+W9oWOaUrJ8p1E="},{"keyId":6,"privKey":"so5CtWkXs3eUHVmljyLWWL5kxGo+tY8FbgTtoTpe9ME=","pubKey":"71d3HBD17PAwSDuTEw9bQRuDSg386Hn+oJRNpnzl9AQ="},{"keyId":7,"privKey":"xPzOKbh3SVBpiSpwbKlK7wVqgfyzIeridFsjC9nCE28=","pubKey":"UWxPGJToFT/lVO2dBjZObUU8OLpAtEW4tuTLkx9oung="}]}
],
"getStoredSPKPriv": [
{"name":"valid","raw":"{\"keyId\":1,\"privKey\":\"c7DdrJkYjwSPJNTcDRFRrGR1MTmPX1+bwMussrWw5QY=\",\"pubKey\":\"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=\",\"signature\":\"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg==\",\"rotatedAt\":1758800000000}","keyId":1,"resultHex":"73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506"},
{"name":"keyIdMismatch","raw":"{\"keyId\":1,\"privKey\":\"c7DdrJkYjwSPJNTcDRFRrGR1MTmPX1+bwMussrWw5QY=\",\"pubKey\":\"rG1yhW9DslkfWsZ4Mi7CD7SAaKPa5fUSR3KeQ6ZXXyY=\",\"signature\":\"SiMY1QLt36yWNZ3lac7W8BgeOq2XV5I1v1PPWRlKFm586+mzCgwfoBjbCt2rPgGo10oQyMCibAuIIlAsIulIDg==\",\"rotatedAt\":1758800000000}","keyId":2,"resultHex":null},
{"name":"unset","raw":null,"keyId":1,"resultHex":null},
{"name":"empty","raw":"","keyId":1,"resultHex":null},
{"name":"invalidJson","raw":"{","keyId":1,"resultHex":null},
{"name":"jsonNull","raw":"null","keyId":1,"resultHex":null},
{"name":"jsonNumber","raw":"5","keyId":1,"resultHex":null},
{"name":"jsonArray","raw":"[1]","keyId":1,"resultHex":null},
{"name":"keyIdString","raw":"{\"keyId\":\"1\",\"privKey\":\"AAAA\"}","keyId":1,"resultHex":null},
{"name":"keyIdFloatEqual","raw":"{\"keyId\":1.0,\"privKey\":\"AAAA\"}","keyId":1,"resultHex":"000000"},
{"name":"privKeyNull","raw":"{\"keyId\":1,\"privKey\":null}","keyId":1,"resultHex":"9ee965"},
{"name":"privKeyTrue","raw":"{\"keyId\":1,\"privKey\":true}","keyId":1,"resultHex":"b6bb9e"},
{"name":"privKeyFalse","raw":"{\"keyId\":1,\"privKey\":false}","keyId":1,"resultHex":null},
{"name":"privKeyMissing","raw":"{\"keyId\":1}","keyId":1,"resultHex":null},
{"name":"privKeyNumber","raw":"{\"keyId\":1,\"privKey\":1234}","keyId":1,"resultHex":"d76df8"},
{"name":"privKeyNumberFrac","raw":"{\"keyId\":1,\"privKey\":12.5}","keyId":1,"resultHex":null},
{"name":"privKeyNumberBig","raw":"{\"keyId\":1,\"privKey\":1e21}","keyId":1,"resultHex":null},
{"name":"privKeyNumberSmall","raw":"{\"keyId\":1,\"privKey\":1.5e-7}","keyId":1,"resultHex":null},
{"name":"privKeyArray","raw":"{\"keyId\":1,\"privKey\":[\"c7DdrJkYjwSPJNTcDRFRrGR1MTmPX1+bwMussrWw5QY=\"]}","keyId":1,"resultHex":"73b0ddac99188f048f24d4dc0d1151ac647531398f5f5f9bc0cbacb2b5b0e506"},
{"name":"privKeyArrayNested","raw":"{\"keyId\":1,\"privKey\":[[\"AAAA\"]]}","keyId":1,"resultHex":"000000"},
{"name":"privKeyArrayTwo","raw":"{\"keyId\":1,\"privKey\":[\"AA\",\"AA\"]}","keyId":1,"resultHex":null},
{"name":"privKeyArrayNulls","raw":"{\"keyId\":1,\"privKey\":[null,\"AAAA\"]}","keyId":1,"resultHex":null},
{"name":"privKeyObject","raw":"{\"keyId\":1,\"privKey\":{}}","keyId":1,"resultHex":null},
{"name":"privKeyTrailingBits","raw":"{\"keyId\":1,\"privKey\":\"AB==\"}","keyId":1,"resultHex":"00"},
{"name":"privKeyEmpty","raw":"{\"keyId\":1,\"privKey\":\"\"}","keyId":1,"resultHex":""},
{"name":"privKeyShort","raw":"{\"keyId\":1,\"privKey\":\"AAAA\"}","keyId":1,"resultHex":"000000"},
{"name":"duplicateKeyIdLastWins","raw":"{\"keyId\":2,\"keyId\":1,\"privKey\":\"AAAA\"}","keyId":1,"resultHex":"000000"},
{"name":"negKeyId","raw":"{\"keyId\":-1,\"privKey\":\"AAAA\"}","keyId":-1,"resultHex":"000000"}
],
"consumeStoredOPKPriv": [
{"name":"valid","raw":"SPIvuSW9tx/GF7TbETa9ArmZ1EXAk1uR2IdBz2HWk0s=","resultHex":"48f22fb925bdb71fc617b4db1136bd02b999d445c0935b91d88741cf61d6934b","stillStored":false},
{"name":"unset","raw":null,"resultHex":null,"stillStored":false},
{"name":"empty","raw":"","resultHex":null,"stillStored":true},
{"name":"invalid","raw":"abc","resultHex":null,"stillStored":false},
{"name":"trailingBits","raw":"AB==","resultHex":"00","stillStored":false}
],
"ensureSPK": [
{"name":"none","raw":null,"nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.none","draws":[{"n":32,"hex":"b5c3d940f62e6e65f8f3e3c2b42fe65842592bdbe412040cdc4652ae0609f46c"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"owNKxr+0mG6Ccf+Z71+9Qh+fwozK97z0Gv2d2eGbATs=\",\"signature\":\"ut2UNFTdP7KLZy6DTCL2QYHGiq4zFaVVul3e3Y4alo0R/FYIuU5AMvxM90l83h1ZSNkKTIJ4BGke2+NvqiLjCQ==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"tcPZQPYubmX48+PCtC/mWEJZK9vkEgQM3EZSrgYJ9Gw=\",\"pubKey\":\"owNKxr+0mG6Ccf+Z71+9Qh+fwozK97z0Gv2d2eGbATs=\",\"signature\":\"ut2UNFTdP7KLZy6DTCL2QYHGiq4zFaVVul3e3Y4alo0R/FYIuU5AMvxM90l83h1ZSNkKTIJ4BGke2+NvqiLjCQ==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"empty","raw":"","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.empty","draws":[{"n":32,"hex":"4e4f641bea268530cf77c751aebfd43b0cd2d07bc9f1ddea5e28ebb51e3db98d"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"L2kdEKZ2bAJZiLJQtlWDsdoQhC5B1r9h8Y3o5yH/A2U=\",\"signature\":\"FqN7BDMFPkCWIENrR/6Bp0sUmWJoelsIX+Ow4IVf+otCi6w0i5MyTVRwWEZIcgCNNTWwt3uBEbgJWp26w5HvDA==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"Tk9kG+omhTDPd8dRrr/UOwzS0HvJ8d3qXijrtR49uY0=\",\"pubKey\":\"L2kdEKZ2bAJZiLJQtlWDsdoQhC5B1r9h8Y3o5yH/A2U=\",\"signature\":\"FqN7BDMFPkCWIENrR/6Bp0sUmWJoelsIX+Ow4IVf+otCi6w0i5MyTVRwWEZIcgCNNTWwt3uBEbgJWp26w5HvDA==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"invalidJson","raw":"{","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.invalidJson","draws":[{"n":32,"hex":"a1c38e1c82d43675ae540ff834d46f85d07875629f3d43a6d7beb03cde82cf61"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"6UdWRfMbFYk6opcETadaBa/Yv0Uq2lngDcNMLORNfgw=\",\"signature\":\"4CvU8eSzWKp5C0n3faUFLzyFONWrIZ5z5+MOQ3IZ+8rBTZzYIzG3Eq3BJqWa4o3sTXVN1dB/roFVbOc4lathAg==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"ocOOHILUNnWuVA/4NNRvhdB4dWKfPUOm176wPN6Cz2E=\",\"pubKey\":\"6UdWRfMbFYk6opcETadaBa/Yv0Uq2lngDcNMLORNfgw=\",\"signature\":\"4CvU8eSzWKp5C0n3faUFLzyFONWrIZ5z5+MOQ3IZ+8rBTZzYIzG3Eq3BJqWa4o3sTXVN1dB/roFVbOc4lathAg==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"jsonNull","raw":"null","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.jsonNull","draws":[{"n":32,"hex":"218bce3b98b60284cdc9628b08659adfbbc157a7f70b64fed4aad34ebf2cd80b"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"8zk6mA2/hkyLLvsj1IbMMmyjd+FaMbNAzG11oTJmkmw=\",\"signature\":\"Np9DgiO9g4tNQvFfWx9AZSj2aOBjfzMC8LYnhrVJjkRhTkymYtpPUsG1B49FU76U8n9rUKRRIHLYDb9jGVQSCw==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"IYvOO5i2AoTNyWKLCGWa37vBV6f3C2T+1KrTTr8s2As=\",\"pubKey\":\"8zk6mA2/hkyLLvsj1IbMMmyjd+FaMbNAzG11oTJmkmw=\",\"signature\":\"Np9DgiO9g4tNQvFfWx9AZSj2aOBjfzMC8LYnhrVJjkRhTkymYtpPUsG1B49FU76U8n9rUKRRIHLYDb9jGVQSCw==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"jsonNumber","raw":"5","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.jsonNumber","draws":[{"n":32,"hex":"fb9b20e27648d0a036171d4704195b7c24e646fe5553bc381cf32ce878b9bda5"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"oiwI2zOqEXzmmZQ7WZLmv5kh00w7h0fJTIN96sma9ns=\",\"signature\":\"QqHeJfpo8FtKsD+6efW9iYSXJudr7ugJkQ1XGfjFTleFYUw68hkVsIo5h6WK53fnaDpububwuSjL41dB8QCTAg==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"+5sg4nZI0KA2Fx1HBBlbfCTmRv5VU7w4HPMs6Hi5vaU=\",\"pubKey\":\"oiwI2zOqEXzmmZQ7WZLmv5kh00w7h0fJTIN96sma9ns=\",\"signature\":\"QqHeJfpo8FtKsD+6efW9iYSXJudr7ugJkQ1XGfjFTleFYUw68hkVsIo5h6WK53fnaDpububwuSjL41dB8QCTAg==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtMissing","raw":"{\"keyId\":1}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtMissing","draws":[{"n":32,"hex":"07b9d5e7ed07a75025d7376675fa671f026741ee130bab530cd16a96517f02f3"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"oVS3pOZarhdGVYUNra7+f35YYuVLfDTJvMflr6572C8=\",\"signature\":\"LOX9ug5KcFhw6/HYpDjUeVoHKvhSdVczWczMYFZxXsMHcKWDyrzupodVKfn0zNBtxvuIBCJZub05IXBIazG0Aw==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"B7nV5+0Hp1Al1zdmdfpnHwJnQe4TC6tTDNFqllF/AvM=\",\"pubKey\":\"oVS3pOZarhdGVYUNra7+f35YYuVLfDTJvMflr6572C8=\",\"signature\":\"LOX9ug5KcFhw6/HYpDjUeVoHKvhSdVczWczMYFZxXsMHcKWDyrzupodVKfn0zNBtxvuIBCJZub05IXBIazG0Aw==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"exactlyWeek","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","nowMs":1759404800000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.exactlyWeek","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","spkRotatedAt":null,"nextKeyId":9},
{"name":"weekPlus1","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","nowMs":1759404800001,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.weekPlus1","draws":[{"n":32,"hex":"e7001b6402b667e08c142f55984c4d712ae412f474066f9179572c163b87aa49"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"DRijKZ3cekrK2303gkH3R7ni1hO9xHF4lPQZYw6Djn4=\",\"signature\":\"123QwRBbiMKF65aDpalvvcbcHnXNNisBl3iZFKdLucnMX4vcc/rtaDikaUth7x83UEosIaCFeO/CrA/cfQH6BA==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"5wAbZAK2Z+CMFC9VmExNcSrkEvR0Bm+ReVcsFjuHqkk=\",\"pubKey\":\"DRijKZ3cekrK2303gkH3R7ni1hO9xHF4lPQZYw6Djn4=\",\"signature\":\"123QwRBbiMKF65aDpalvvcbcHnXNNisBl3iZFKdLucnMX4vcc/rtaDikaUth7x83UEosIaCFeO/CrA/cfQH6BA==\",\"rotatedAt\":1759404800001}","spkRotatedAt":1759404800001,"nextKeyId":10},
{"name":"fresh","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.fresh","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","spkRotatedAt":null,"nextKeyId":9},
{"name":"future","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1764848000000}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.future","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1764848000000}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtZero","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":0}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtZero","draws":[{"n":32,"hex":"bc215543b3524154019e3b0f7a4b0babc255a4217971217bbd1014703a39ef5b"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"1zNYArTM1lSyzsEu5qwqIwim5elyqMz7XWwRkR94XWg=\",\"signature\":\"kyc8kNAKG1J9qjvhDlQf0DvAijUYiQbjOpQnwZA2HqWZ6PMw2xfa/DCG8AhnnwzyUdrwUdmizgOudc6aHku7AA==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"vCFVQ7NSQVQBnjsPeksLq8JVpCF5cSF7vRAUcDo571s=\",\"pubKey\":\"1zNYArTM1lSyzsEu5qwqIwim5elyqMz7XWwRkR94XWg=\",\"signature\":\"kyc8kNAKG1J9qjvhDlQf0DvAijUYiQbjOpQnwZA2HqWZ6PMw2xfa/DCG8AhnnwzyUdrwUdmizgOudc6aHku7AA==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtNull","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":null}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtNull","draws":[{"n":32,"hex":"665bbc6625f9689098a0fe6f16fef9c24573cfbbd80e913c8d47825da811725b"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"d3J79qaCXAgqtT+3/VB7K4CqDU+qK5Kx8C4TU+7of2o=\",\"signature\":\"wVph3ydXc/a6JrGHbk7zP+AG3wZswVSpiSr9dta/15EYta3Alu3IPcd8haqial26ScqiIyvrFNuOQYGXlT28DA==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"Zlu8ZiX5aJCYoP5vFv75wkVzz7vYDpE8jUeCXagRcls=\",\"pubKey\":\"d3J79qaCXAgqtT+3/VB7K4CqDU+qK5Kx8C4TU+7of2o=\",\"signature\":\"wVph3ydXc/a6JrGHbk7zP+AG3wZswVSpiSr9dta/15EYta3Alu3IPcd8haqial26ScqiIyvrFNuOQYGXlT28DA==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtAbc","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"abc\"}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtAbc","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"abc\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtNumericString","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\" 1758800000000\\n\"}","nowMs":1759404800000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtNumericString","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\" 1758800000000\\n\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtNumericStringOld","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\" 1758800000000\\n\"}","nowMs":1759404800001,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtNumericStringOld","draws":[{"n":32,"hex":"dd19b367216e3d8594b4040a34e5b3bfb1ae35b462bb9f5ce18658e7f45303e3"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"vgeBbpkiOqk19YEgeWXTTArtvBD3p7Yd7ncWLAfktBc=\",\"signature\":\"nSBH5DLdCzOGPQcjqkFgFdv938TsCBejOAlGBImx7x1Q/+oZh24lCuglQ51RO+/YEFsGwyAufO83PtMjUkCfCw==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"3RmzZyFuPYWUtAQKNOWzv7GuNbRiu59c4YZY5/RTA+M=\",\"pubKey\":\"vgeBbpkiOqk19YEgeWXTTArtvBD3p7Yd7ncWLAfktBc=\",\"signature\":\"nSBH5DLdCzOGPQcjqkFgFdv938TsCBejOAlGBImx7x1Q/+oZh24lCuglQ51RO+/YEFsGwyAufO83PtMjUkCfCw==\",\"rotatedAt\":1759404800001}","spkRotatedAt":1759404800001,"nextKeyId":10},
{"name":"rotatedAtHexString","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"0x10\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtHexString","draws":[{"n":32,"hex":"0a2a203f140203f0274da7863fdca4d1cc21900407fc26eea280c629f6f26133"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"P378Vtmb/2dPtI94HjycBppox+Cwyccg3Pc5D7jtPVs=\",\"signature\":\"DXMb0L+3dHAkTxQ0nVeIz87KzqGk9fgr8ipD8DYSCZzRW14Rav/HLhJrrXknk9RCwbHPEKt+m8bnsqndWfFtAg==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"CiogPxQCA/AnTaeGP9yk0cwhkAQH/CbuooDGKfbyYTM=\",\"pubKey\":\"P378Vtmb/2dPtI94HjycBppox+Cwyccg3Pc5D7jtPVs=\",\"signature\":\"DXMb0L+3dHAkTxQ0nVeIz87KzqGk9fgr8ipD8DYSCZzRW14Rav/HLhJrrXknk9RCwbHPEKt+m8bnsqndWfFtAg==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtExpString","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"1.7588e12\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtExpString","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"1.7588e12\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtInfinityString","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"Infinity\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtInfinityString","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"Infinity\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtNegInfinityString","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"-Infinity\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtNegInfinityString","draws":[{"n":32,"hex":"0aaa8c873509f32e312564415c3d9f66421a9a08823c3ac20a330a0d8aa16be0"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"/jm5hYvogZpyNRKKtolG8Ousc3/oLkOgQqYDRRtfhAc=\",\"signature\":\"wpil1N5USsPjNCqteuAY+/Nx3bWkAti83geu4P0BSr8kNYVkqF8JrK/zgVH80kimBQX2XsllEEOvZUXCytooAA==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"CqqMhzUJ8y4xJWRBXD2fZkIamgiCPDrCCjMKDYqha+A=\",\"pubKey\":\"/jm5hYvogZpyNRKKtolG8Ousc3/oLkOgQqYDRRtfhAc=\",\"signature\":\"wpil1N5USsPjNCqteuAY+/Nx3bWkAti83geu4P0BSr8kNYVkqF8JrK/zgVH80kimBQX2XsllEEOvZUXCytooAA==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtInfString","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"inf\"}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtInfString","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"inf\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtEmptyString","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtEmptyString","draws":[{"n":32,"hex":"aeaacf044e614a26e03ae0f537e072ec7918e6d2bbe6309beb9160aefb504723"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"wxTkLF51kWKwlDEKqpHZgSfQnRUvfKIzn6wrA5ujmQc=\",\"signature\":\"dsX3uD5gqGPncMzuDRo56MTEw/Sorojp/LsDKOHDcAcVjJ5DO6+80RHH78NSev5qpAi3KzbxhqhJxuJSO56DCg==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"rqrPBE5hSibgOuD1N+By7HkY5tK75jCb65FgrvtQRyM=\",\"pubKey\":\"wxTkLF51kWKwlDEKqpHZgSfQnRUvfKIzn6wrA5ujmQc=\",\"signature\":\"dsX3uD5gqGPncMzuDRo56MTEw/Sorojp/LsDKOHDcAcVjJ5DO6+80RHH78NSev5qpAi3KzbxhqhJxuJSO56DCg==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtTrue","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":true}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtTrue","draws":[{"n":32,"hex":"219a408cfad18c67e8f05c9ad1c5574749611462b521579143c244bc5bae3805"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"cN23iaMubKtUnnaQNJUgJ1N9xUENGDtHjmo/m6HFBwQ=\",\"signature\":\"wIqJOc6WoUcuTEfhZkfYIcVTvfdoy8GUjFPprY4ROkCf/JmXcUg8yt+vqjbm9/VxWZjBXFeEvkAK0WCI/nb2Dw==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"IZpAjPrRjGfo8Fya0cVXR0lhFGK1IVeRQ8JEvFuuOAU=\",\"pubKey\":\"cN23iaMubKtUnnaQNJUgJ1N9xUENGDtHjmo/m6HFBwQ=\",\"signature\":\"wIqJOc6WoUcuTEfhZkfYIcVTvfdoy8GUjFPprY4ROkCf/JmXcUg8yt+vqjbm9/VxWZjBXFeEvkAK0WCI/nb2Dw==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtArrayOne","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":[1758800000000]}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtArrayOne","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":[1758800000000]}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtArrayEmpty","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":[]}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtArrayEmpty","draws":[{"n":32,"hex":"a74eecb5f0f37e0fada1598d9eedd7c5dae6cb3446320cc8128e5ecd630e31ab"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"z4PkeNo5HoKK+DLehbzHlcrYltZwzJV8mgTrr09w+3c=\",\"signature\":\"V2EdHzMUORRrcDueZ3/2mAOSbRLq4c4BzEWtv0vS1HL8JNV/Qz2LqeY1CoTCMWM30AyeQZey8cGizUp3AhX6BQ==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"p07stfDzfg+toVmNnu3XxdrmyzRGMgzIEo5ezWMOMas=\",\"pubKey\":\"z4PkeNo5HoKK+DLehbzHlcrYltZwzJV8mgTrr09w+3c=\",\"signature\":\"V2EdHzMUORRrcDueZ3/2mAOSbRLq4c4BzEWtv0vS1HL8JNV/Qz2LqeY1CoTCMWM30AyeQZey8cGizUp3AhX6BQ==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtArrayTwo","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":[1758800000000,1]}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtArrayTwo","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":[1758800000000,1]}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtObject","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":{}}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtObject","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":{}}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtUnderscore","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"1_000\"}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtUnderscore","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"1_000\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtDotOnly","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\".\"}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtDotOnly","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\".\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtTrailingDot","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"1758800000000.\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtTrailingDot","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"1758800000000.\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtLeadingDot","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\".5\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtLeadingDot","draws":[{"n":32,"hex":"73c35c0ca6139e8f21d308c091de1526c6ed95a4ad760f251bacacf714023e8f"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"KK8ek8np91lTNIF9LcwhpcwtxWAg8y+nMFnQ6vNpKyc=\",\"signature\":\"I/guW0dt2+vCWQTok1L1qIR995VE7E7+putFZB75AIV1GW33/ovbX8f+OIs5b9uAJFNfEwsaBH2gdC5V3N6aCQ==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"c8NcDKYTno8h0wjAkd4VJsbtlaStdg8lG6ys9xQCPo8=\",\"pubKey\":\"KK8ek8np91lTNIF9LcwhpcwtxWAg8y+nMFnQ6vNpKyc=\",\"signature\":\"I/guW0dt2+vCWQTok1L1qIR995VE7E7+putFZB75AIV1GW33/ovbX8f+OIs5b9uAJFNfEwsaBH2gdC5V3N6aCQ==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtBinary","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"0b101\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":true,"label":"x3dh/extra.bootstrap.rotatedAtBinary","draws":[{"n":32,"hex":"2703c5218b797c9937958766cb167fadc2572b26fb99bcbb84daaf94650715de"}],"spkBody":"{\"keyId\":9,\"pubKey\":\"IAsPmccfvqGE0L+440XIYsw7pbDhb8zreebw4s+pPnA=\",\"signature\":\"aryXx5yTYmi958AyBc9+kk7bXikMLPKsh/8cU44xg21Ng52XZQ7iVZQKc2pasADpztq8pdcNsocKlRdza43RAg==\"}","storedSpk":"{\"keyId\":9,\"privKey\":\"JwPFIYt5fJk3lYdmyxZ/rcJXKyb7mby7hNqvlGUHFd4=\",\"pubKey\":\"IAsPmccfvqGE0L+440XIYsw7pbDhb8zreebw4s+pPnA=\",\"signature\":\"aryXx5yTYmi958AyBc9+kk7bXikMLPKsh/8cU44xg21Ng52XZQ7iVZQKc2pasADpztq8pdcNsocKlRdza43RAg==\",\"rotatedAt\":1758800000000}","spkRotatedAt":1758800000000,"nextKeyId":10},
{"name":"rotatedAtSignedHex","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"-0x10\"}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtSignedHex","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"-0x10\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtNbsp","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"\u00a01758800000000\ufeff\"}","nowMs":1758800000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtNbsp","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"\u00a01758800000000\ufeff\"}","spkRotatedAt":null,"nextKeyId":9},
{"name":"rotatedAtNel","raw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"\u00851758800000000\"}","nowMs":1819280000000,"nextBefore":9,"uploadedSpk":false,"label":"x3dh/extra.bootstrap.rotatedAtNel","draws":[],"spkBody":null,"storedSpk":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":\"\u00851758800000000\"}","spkRotatedAt":null,"nextKeyId":9}
],
"ensureOPKs": [
{"name":"fresh","count":0,"countFail":false,"spkRaw":null,"otpFail":false,"spkPresent":false,"label":"x3dh/extra.opk.fresh","drawCount":101,"uploadedOtps":true,"otpsBodySha256":"f98aac6b69bdd0c13b9eee323dc7701fd065359d5df1c4028901e93e7398d519","spkBody":"{\"keyId\":1,\"pubKey\":\"oJtHMK4UMjal+svlpvbGfpQskmUhoi+0z2ESACs48m4=\",\"signature\":\"xAKQ1AN3AECLlQPXn870j7Qhs7pgz9RxpFMfky/LtwtWW7YioUjPkhvRzl4DA7aK7Z8IPRa3WGdPkshf/YC7BQ==\"}","nextKeyIdAfter":102,"pendingAfter":null,"storedOpkCount":100,"storedOpkFirst":{"key":"opk:2","value":"NMxm0Iw44ZfszHzYXREoMyONy7N7kHe47ECd3a5E0Eg="},"storedOpkLast":{"key":"opk:101","value":"f7dWPI6v5ZLmQdZUpPvAc2WjWnngBZHDG4gCuqRM9Is="}},
{"name":"atWatermark","count":20,"countFail":false,"next":50,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":false,"spkPresent":true,"label":"x3dh/extra.opk.atWatermark","drawCount":0,"uploadedOtps":false,"otpsBodySha256":null,"spkBody":null,"nextKeyIdAfter":50,"pendingAfter":null,"storedOpkCount":0,"storedOpkFirst":null,"storedOpkLast":null},
{"name":"belowWatermark","count":19,"countFail":false,"next":50,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":false,"spkPresent":true,"label":"x3dh/extra.opk.belowWatermark","drawCount":100,"uploadedOtps":true,"otpsBodySha256":"9e1bc6595cc3c074ffce26ec1ced2faed66e98ecbdb427cbe2356561f58d91fa","spkBody":null,"nextKeyIdAfter":150,"pendingAfter":null,"storedOpkCount":100,"storedOpkFirst":{"key":"opk:50","value":"jEA0LI9AomOBCWqsSomBRHC6evFjY73pwsdi1LMV2zg="},"storedOpkLast":{"key":"opk:149","value":"7DwqQk8oe3ljloPRiYGqXNzUgaebUdv98lW7JK3rbF8="}},
{"name":"pendingAtWatermark","count":500,"countFail":false,"pending":true,"next":50,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":false,"spkPresent":true,"label":"x3dh/extra.opk.pendingAtWatermark","drawCount":100,"uploadedOtps":true,"otpsBodySha256":"5dae3046370fa27708a9ca30983c7d52cf15e089719faed5aab287735a7908a9","spkBody":null,"nextKeyIdAfter":150,"pendingAfter":null,"storedOpkCount":100,"storedOpkFirst":{"key":"opk:50","value":"r2ZfJQUkqyMGK7eei8kU/5hqcs2nJKXWiCjjOpj9MMc="},"storedOpkLast":{"key":"opk:149","value":"4eosRrjUk+1dN0NUte7zFnbEZ7tyTdPS9lghUCnysqA="}},
{"name":"countUndefined","countFail":false,"next":50,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":false,"spkPresent":true,"label":"x3dh/extra.opk.countUndefined","drawCount":100,"uploadedOtps":true,"otpsBodySha256":"8fdd7946ad5da542e85ba70d472d2628d4b1d0492b42206472ad07192271d312","spkBody":null,"nextKeyIdAfter":150,"pendingAfter":null,"storedOpkCount":100,"storedOpkFirst":{"key":"opk:50","value":"dxuBh3qkjbnZoUr6kckLJ1fQpvRRVuvrhwMuONp2/A8="},"storedOpkLast":{"key":"opk:149","value":"bif7j3sLuYcQh0Un2zEk9qzwJqGawkFWQrwRbjBx4i8="}},
{"name":"countStringHigh","count":"25","countFail":false,"next":50,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":false,"spkPresent":true,"label":"x3dh/extra.opk.countStringHigh","drawCount":0,"uploadedOtps":false,"otpsBodySha256":null,"spkBody":null,"nextKeyIdAfter":50,"pendingAfter":null,"storedOpkCount":0,"storedOpkFirst":null,"storedOpkLast":null},
{"name":"countFail","count":0,"countFail":true,"next":50,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":false,"spkPresent":true,"label":"x3dh/extra.opk.countFail","drawCount":0,"uploadedOtps":false,"otpsBodySha256":null,"spkBody":null,"nextKeyIdAfter":50,"pendingAfter":null,"storedOpkCount":0,"storedOpkFirst":null,"storedOpkLast":null},
{"name":"uploadFails","count":0,"countFail":false,"next":50,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":true,"spkPresent":true,"label":"x3dh/extra.opk.uploadFails","drawCount":100,"uploadedOtps":true,"otpsBodySha256":"7139740645b148a5abec340f7454b2ddf8eaf06c079eae4e8089812f4fd91c2a","spkBody":null,"nextKeyIdAfter":51,"pendingAfter":true,"storedOpkCount":0,"storedOpkFirst":null,"storedOpkLast":null},
{"name":"nextZero","count":0,"countFail":false,"next":0,"spkRaw":"{\"keyId\":1,\"privKey\":\"AAAA\",\"pubKey\":\"AAAA\",\"signature\":\"AAAA\",\"rotatedAt\":1758800000000}","otpFail":false,"spkPresent":true,"label":"x3dh/extra.opk.nextZero","drawCount":100,"uploadedOtps":true,"otpsBodySha256":"fd63146a3d7f061bc7066b3a0321383a158cbc3999c4ff896aec0cf8531e7a6e","spkBody":null,"nextKeyIdAfter":100,"pendingAfter":null,"storedOpkCount":100,"storedOpkFirst":{"key":"opk:0","value":"fVSVULBavIzysScapJ6eTUZTmgp+tgsANI+0icxdJiA="},"storedOpkLast":{"key":"opk:99","value":"bVJb0UoKaJL+5o2DMBgDIalJHggRLjJFVaNmYWacEqI="}}
]
}"##;
