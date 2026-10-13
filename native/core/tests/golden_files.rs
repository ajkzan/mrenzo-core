//! Replays docs/native/vectors/files.json — produced by the RN client's real
//! TypeScript (`crypto.ts` encryptFileBase64 / decryptFileBase64 /
//! buildFileEnvelope / parseFileEnvelope) — against the Rust port, byte for
//! byte. Every section of the file is walked (`vectors`, `envelopes`,
//! `wrongKey`); an unknown section fails the test so it cannot go unreplayed.
//!
//! The `node_*` tests pin edge cases the vector file does not record. Their
//! expected values were obtained by running the production
//! `mobile/src/utils/crypto.ts` (transpiled, unmodified) under node 22 with
//! the app's own tweetnacl 1.0.3 / tweetnacl-util 0.15.1, not by reasoning.

use mrenzo_core::files::*;
use mrenzo_core::primitives::{b64, b64d};
use mrenzo_core::rng::ReplayRng;
use serde_json::Value;

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/native/vectors/files.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("files.json")).unwrap()
}

fn replay(rng: &Value) -> ReplayRng {
    let label = rng["label"].as_str().unwrap_or("?").to_string();
    let draws = rng["draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let bytes = hex::decode(d["hex"].as_str().unwrap()).unwrap();
            assert_eq!(bytes.len() as u64, d["n"].as_u64().unwrap(), "{label}: draw n vs hex length");
            bytes
        })
        .collect();
    ReplayRng::new(label, draws)
}

fn s(x: &Value) -> &str {
    x.as_str().unwrap_or_else(|| panic!("expected string, got {x}"))
}

fn keys(v: &Value) -> Vec<&str> {
    let mut k: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    k.sort_unstable();
    k
}

/// A recorded `FileEnvelope` object (TS field names) → the Rust struct.
/// Absent optional = `undefined`. Unknown fields fail.
fn envelope_from_json(o: &Value) -> FileEnvelope {
    for k in o.as_object().unwrap().keys() {
        assert!(
            ["placeholder", "fileId", "key", "nonce", "mimeType", "fileName", "fileSize", "duration"].contains(&k.as_str()),
            "unexpected FileEnvelope field {k}"
        );
    }
    FileEnvelope {
        placeholder: s(&o["placeholder"]).to_string(),
        file_id: s(&o["fileId"]).to_string(),
        key: s(&o["key"]).to_string(),
        nonce: s(&o["nonce"]).to_string(),
        mime_type: s(&o["mimeType"]).to_string(),
        file_name: o.get("fileName").map(|v| s(v).to_string()),
        file_size: o.get("fileSize").map(|v| v.as_f64().unwrap()),
        duration: o.get("duration").map(|v| v.as_f64().unwrap()),
    }
}

/// Bitwise f64 equality (distinguishes -0 from 0, matches ±Infinity).
fn same_num(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.to_bits() == y.to_bits(),
        _ => false,
    }
}

fn assert_same_envelope(got: &FileEnvelope, want: &FileEnvelope, ctx: &str) {
    assert_eq!(got.placeholder, want.placeholder, "{ctx}: placeholder");
    assert_eq!(got.file_id, want.file_id, "{ctx}: fileId");
    assert_eq!(got.key, want.key, "{ctx}: key");
    assert_eq!(got.nonce, want.nonce, "{ctx}: nonce");
    assert_eq!(got.mime_type, want.mime_type, "{ctx}: mimeType");
    assert_eq!(got.file_name, want.file_name, "{ctx}: fileName");
    assert!(same_num(got.file_size, want.file_size), "{ctx}: fileSize {:?} vs {:?}", got.file_size, want.file_size);
    assert!(same_num(got.duration, want.duration), "{ctx}: duration {:?} vs {:?}", got.duration, want.duration);
}

#[test]
fn every_section_is_replayed() {
    let v = vectors();
    assert_eq!(v["area"], "files");
    assert_eq!(v["schema"], 1);
    assert_eq!(
        keys(&v),
        ["area", "encodings", "envelopes", "generator", "notes", "schema", "sources", "vectors", "wrongKey"],
        "files.json grew a section this test does not replay"
    );
    assert_eq!(v["vectors"].as_array().unwrap().len(), 3);
    assert_eq!(v["envelopes"].as_array().unwrap().len(), 2);
}

#[test]
fn encrypt_file_base64_byte_exact() {
    let v = vectors();
    for t in v["vectors"].as_array().unwrap() {
        let name = s(&t["name"]);
        assert_eq!(
            keys(t),
            ["ciphertextB64", "ciphertextLen", "keyB64", "name", "nonceB64", "plaintextB64", "rng"],
            "{name}: unexpected fields"
        );
        let draws = t["rng"]["draws"].as_array().unwrap();
        // Key (32) is drawn BEFORE the nonce (24).
        assert_eq!(draws.len(), 2, "{name}");
        assert_eq!(b64(&hex::decode(s(&draws[0]["hex"])).unwrap()), s(&t["keyB64"]), "{name}: key = draw #1");
        assert_eq!(b64(&hex::decode(s(&draws[1]["hex"])).unwrap()), s(&t["nonceB64"]), "{name}: nonce = draw #2");

        let mut rng = replay(&t["rng"]);
        let enc = encrypt_file_base64(s(&t["plaintextB64"]), &mut rng).unwrap_or_else(|e| panic!("{name}: threw {e}"));
        rng.assert_exhausted();
        assert_eq!(enc.ciphertext_b64, s(&t["ciphertextB64"]), "{name}: ciphertext");
        assert_eq!(enc.key_b64, s(&t["keyB64"]), "{name}: key");
        assert_eq!(enc.nonce_b64, s(&t["nonceB64"]), "{name}: nonce");

        // The raw-bytes API (what a native uploader sends) is the same bytes.
        let plaintext = b64d(s(&t["plaintextB64"])).unwrap();
        let mut rng = replay(&t["rng"]);
        let raw = encrypt_file(&plaintext, &mut rng);
        rng.assert_exhausted();
        assert_eq!(b64(&raw.ciphertext), s(&t["ciphertextB64"]), "{name}: raw ciphertext");
        assert_eq!(b64(&raw.key), s(&t["keyB64"]), "{name}: raw key");
        assert_eq!(b64(&raw.nonce), s(&t["nonceB64"]), "{name}: raw nonce");
        assert_eq!(raw.ciphertext.len() as u64, t["ciphertextLen"].as_u64().unwrap(), "{name}: ciphertextLen");
        assert_eq!(raw.ciphertext.len(), plaintext.len() + 16, "{name}: tag16 || ct");
    }
}

#[test]
fn decrypt_file_base64_consumer_side() {
    let v = vectors();
    for t in v["vectors"].as_array().unwrap() {
        let name = s(&t["name"]);
        let (ct, k, n, pt) = (s(&t["ciphertextB64"]), s(&t["keyB64"]), s(&t["nonceB64"]), s(&t["plaintextB64"]));
        assert_eq!(decrypt_file_base64(ct, k, n).as_deref(), Some(pt), "{name}: decryptFileBase64");

        let ct_raw = b64d(ct).unwrap();
        let pt_raw = b64d(pt).unwrap();
        assert_eq!(decrypt_file(&ct_raw, k, n), Some(pt_raw.clone()), "{name}: raw decrypt");
        // api.ts download tail: `if (!plaintextB64) throw` — an empty file
        // decrypts fine ("" above) but the RN download path rejects it.
        if pt_raw.is_empty() {
            assert_eq!(decrypt_downloaded_file(&ct_raw, k, n), Err(FileError::DecryptionFailed), "{name}: empty-file quirk");
        } else {
            assert_eq!(decrypt_downloaded_file(&ct_raw, k, n), Ok(pt_raw), "{name}: download");
        }
    }
}

#[test]
fn wrong_key_is_null() {
    let v = vectors();
    // Generator: decryptFileBase64(vectors[2].ciphertextB64, vectors[1].keyB64, vectors[2].nonceB64)
    assert!(v["wrongKey"].is_null(), "recorded wrongKey result must be null");
    let t = v["vectors"].as_array().unwrap();
    let got = decrypt_file_base64(s(&t[2]["ciphertextB64"]), s(&t[1]["keyB64"]), s(&t[2]["nonceB64"]));
    assert_eq!(got, None);
    let ct = b64d(s(&t[2]["ciphertextB64"])).unwrap();
    assert_eq!(decrypt_downloaded_file(&ct, s(&t[1]["keyB64"]), s(&t[2]["nonceB64"])), Err(FileError::DecryptionFailed));
}

#[test]
fn envelopes_build_and_parse_byte_exact() {
    let v = vectors();
    let vecs = v["vectors"].as_array().unwrap();
    for (i, e) in v["envelopes"].as_array().unwrap().iter().enumerate() {
        assert_eq!(keys(e), ["input", "json", "parsed"], "envelope #{i}: unexpected fields");
        let input = envelope_from_json(&e["input"]);
        let json = s(&e["json"]);
        assert_eq!(build_file_envelope(&input), json, "envelope #{i}: buildFileEnvelope bytes");

        let parsed = parse_file_envelope(json).unwrap_or_else(|| panic!("envelope #{i}: parse returned null"));
        assert_same_envelope(&parsed, &envelope_from_json(&e["parsed"]), &format!("envelope #{i}"));
        // Building the parsed envelope reproduces the wire string.
        assert_eq!(build_file_envelope(&parsed), json, "envelope #{i}: re-build");

        // End to end: the envelope's key/nonce open the matching attachment
        // (generator: photo → vectors[2], voice → vectors[1]).
        let t = &vecs[if i == 0 { 2 } else { 1 }];
        assert_eq!(parsed.key, s(&t["keyB64"]), "envelope #{i}: key source");
        assert_eq!(parsed.nonce, s(&t["nonceB64"]), "envelope #{i}: nonce source");
        assert_eq!(
            decrypt_file_base64(s(&t["ciphertextB64"]), &parsed.key, &parsed.nonce).as_deref(),
            Some(s(&t["plaintextB64"])),
            "envelope #{i}: opens its attachment"
        );
    }
}

// ───────── edge cases pinned by running production crypto.ts under node ─────────

#[test]
fn node_decrypt_edge_cases() {
    // (name, ciphertextB64, keyB64, nonceB64, decryptFileBase64 result)
    let cases: &[(&str, &str, &str, &str, Option<&str>)] = &[
        ("vec0 empty -> \"\"", "vTCewexoeEexIruAEdirSA==", "W8twGzCPU/RHjv9PHuCdK/aqN8RO3CB/26DkXkgyxqM=", "/LN7EUCUYBvmrK/B00loF5GBtHtewNQH", Some("")),
        ("control (vec1)", "3tmDtV59pLqeUXuEinrtJII=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", Some("AA==")),
        // tweetnacl-util accepts non-zero trailing bits: …y2Z= decodes like …y2Y=.
        ("noncanonical key trailing bits", "3tmDtV59pLqeUXuEinrtJII=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Z=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", Some("AA==")),
        ("key 31", "3tmDtV59pLqeUXuEinrtJII=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDyw==", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("key 33", "3tmDtV59pLqeUXuEinrtJII=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2YA", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("key empty", "3tmDtV59pLqeUXuEinrtJII=", "", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("nonce 23", "3tmDtV59pLqeUXuEinrtJII=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKY=", None),
        ("ct empty", "", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("ct 15 bytes", "3tmDtV59pLqeUXuEinrt", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("ct 16 of 17 bytes", "3tmDtV59pLqeUXuEinrtJA==", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("ct unpadded", "3tmDtV59pLqeUXuEinrtJII", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("ct trailing newline", "3tmDtV59pLqeUXuEinrtJII=\n", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("ct noncanonical AB== (1 byte)", "AB==", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("key urlsafe", "3tmDtV59pLqeUXuEinrtJII=", "1HHCULsFrpOSWN2ZNPhQ5P-BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("flip tag bit", "39mDtV59pLqeUXuEinrtJII=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("flip body bit", "3tmDtV59pLqeUXuEinrtJAI=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "aHo3kwk9uy160Tru2Cdu3PPdnNsuNKYU", None),
        ("wrongKey", "WKyp1KP/UD7LliPB+xBam2LEl9BbYItwCu2AluFBh4sU4eRFhfknMabAHaVjGnn4F0XbXdaEuBRDMmZrJZTX/Ake5v0osdhNgCZ0ryweYfTqY9RWD5XgTFiHQZ/72BhYp0GLN4K7gC22h6GF7ZnyUYfIB6JOP8jTw7FgX7gEI+eYLEwO3997ttn8/pk4VQgPAeQPXcyK41wZOSyaM7RxrfIeLpe99VXuYOrNOi+bZB5DLqfgFDvFgGhN13x4kndztL9S0UffPVgc0IKCOV3PfhTjhBAAOpMuTb9OaCkViPj8XBgrYcJjWCvvgKQJuoC5Lv3ji5UnSu04gvuHN/fRAX29W8I0R1RAXn3xyUHdeOg=", "1HHCULsFrpOSWN2ZNPhQ5P+BuKbxWCd0x0mWSZFDy2Y=", "qZxkzyU31bNipfD6B7rjgJEHSzJ26tjz", None),
        ("ct urlsafe", "WKyp1KP_UD7LliPB-xBam2LEl9BbYItwCu2AluFBh4sU4eRFhfknMabAHaVjGnn4F0XbXdaEuBRDMmZrJZTX_Ake5v0osdhNgCZ0ryweYfTqY9RWD5XgTFiHQZ_72BhYp0GLN4K7gC22h6GF7ZnyUYfIB6JOP8jTw7FgX7gEI-eYLEwO3997ttn8_pk4VQgPAeQPXcyK41wZOSyaM7RxrfIeLpe99VXuYOrNOi-bZB5DLqfgFDvFgGhN13x4kndztL9S0UffPVgc0IKCOV3PfhTjhBAAOpMuTb9OaCkViPj8XBgrYcJjWCvvgKQJuoC5Lv3ji5UnSu04gvuHN_fRAX29W8I0R1RAXn3xyUHdeOg=", "Y5cpdFR7ARpkfOsQuMh8lPa8BtHvyVgaJW0VJKPSCbY=", "qZxkzyU31bNipfD6B7rjgJEHSzJ26tjz", None),
    ];
    for (name, c, k, n, want) in cases {
        assert_eq!(decrypt_file_base64(c, k, n).as_deref(), *want, "{name}");
    }
}

#[test]
fn node_encrypt_edge_cases() {
    // node harness PRNG: every randombytes(x, n) call filled x[i] = (7i + 3) & 0xff.
    let pattern = |n: usize| (0..n).map(|i| ((i * 7 + 3) & 0xff) as u8).collect::<Vec<u8>>();
    let key = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw=";
    let nonce = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2k";
    let ok: &[(&str, &str)] = &[
        ("", "JIY4g14tLw1lO+qwdkHrug=="),
        ("AA==", "Oclfbbw5P1HQjDGbFC6M8ZI="),
        // Non-zero trailing bits accepted: "AB==" is the one byte 0x00.
        ("AB==", "Oclfbbw5P1HQjDGbFC6M8ZI="),
        ("AAE=", "rT0otgjVOo2wN08TSotckpJj"),
        ("AQ==", "x2tUe8CkU1Pk3fWeAISx/5M="),
    ];
    for (pt, ct) in ok {
        let mut rng = ReplayRng::new(format!("node/{pt}"), vec![pattern(32), pattern(24)]);
        let enc = encrypt_file_base64(pt, &mut rng).unwrap();
        rng.assert_exhausted();
        assert_eq!(enc, EncryptedFile { ciphertext_b64: ct.to_string(), key_b64: key.to_string(), nonce_b64: nonce.to_string() }, "{pt:?}");
    }
    // decodeBase64 throws TypeError('invalid encoding') BEFORE any draw: an
    // empty ReplayRng panics on the first draw, so zero draws is enforced.
    for pt in ["abc", "YQ==\n", "ab-_", "A===", "=AAA", "AAAA=", " AAA"] {
        let mut rng = ReplayRng::new(format!("node/throw/{pt}"), vec![]);
        assert_eq!(encrypt_file_base64(pt, &mut rng), Err(FileError::InvalidEncoding), "{pt:?}");
        rng.assert_exhausted();
    }
    assert_eq!(FileError::InvalidEncoding.to_string(), "invalid encoding");
    assert_eq!(FileError::DecryptionFailed.to_string(), "decryption failed");
}

/// Expected `parseFileEnvelope` result (TS field names abbreviated).
struct E {
    p: &'static str,
    id: &'static str,
    k: &'static str,
    n: &'static str,
    m: &'static str,
    fname: Option<&'static str>,
    s: Option<f64>,
    d: Option<f64>,
}

impl E {
    fn envelope(&self) -> FileEnvelope {
        FileEnvelope {
            placeholder: self.p.into(),
            file_id: self.id.into(),
            key: self.k.into(),
            nonce: self.n.into(),
            mime_type: self.m.into(),
            file_name: self.fname.map(Into::into),
            file_size: self.s,
            duration: self.d,
        }
    }
}

const OCT: &str = "application/octet-stream";

#[test]
fn node_parse_edge_cases() {
    let e = |id: &'static str| Some(E { p: "", id, k: "b", n: "c", m: OCT, fname: None, s: None, d: None });
    #[rustfmt::skip]
    let cases: Vec<(&str, Option<E>)> = vec![
        // JSON.parse throws / not an object / missing or falsy id,k,n → null
        ("", None),
        ("null", None),
        ("[]", None),
        ("\"str\"", None),
        ("123", None),
        ("true", None),
        ("{}", None),
        ("{\"id\":\"a\",\"k\":\"b\"}", None),
        ("{\"id\":\"\",\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":0,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":-0,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":0.0e5,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":false,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":null,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":\"a\",\"k\":\"\",\"n\":\"c\"}", None),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":0}", None),
        // String(o.id): JS number formatting
        ("{\"id\":7,\"k\":\"b\",\"n\":\"c\"}", e("7")),
        ("{\"id\":1e21,\"k\":\"b\",\"n\":\"c\"}", e("1e+21")),
        ("{\"id\":1e20,\"k\":\"b\",\"n\":\"c\"}", e("100000000000000000000")),
        ("{\"id\":123456789012345678901234567890,\"k\":\"b\",\"n\":\"c\"}", e("1.2345678901234568e+29")),
        ("{\"id\":1.5e-7,\"k\":\"b\",\"n\":\"c\"}", e("1.5e-7")),
        ("{\"id\":0.000001,\"k\":\"b\",\"n\":\"c\"}", e("0.000001")),
        ("{\"id\":-12.5,\"k\":\"b\",\"n\":\"c\"}", e("-12.5")),
        ("{\"id\":9007199254740993,\"k\":\"b\",\"n\":\"c\"}", e("9007199254740992")),
        ("{\"id\":0.30000000000000004,\"k\":\"b\",\"n\":\"c\"}", e("0.30000000000000004")),
        ("{\"id\":5e-324,\"k\":\"b\",\"n\":\"c\"}", e("5e-324")),
        ("{\"id\":1.7976931348623157e308,\"k\":\"b\",\"n\":\"c\"}", e("1.7976931348623157e+308")),
        ("{\"id\":123e-20,\"k\":\"b\",\"n\":\"c\"}", e("1.23e-18")),
        ("{\"id\":1e400,\"k\":\"b\",\"n\":\"c\"}", e("Infinity")),
        ("{\"id\":-1e400,\"k\":\"b\",\"n\":\"c\"}", e("-Infinity")),
        ("{\"id\":1E+2,\"k\":\"b\",\"n\":\"c\"}", e("100")),
        ("{\"id\":-5e-7,\"k\":\"b\",\"n\":\"c\"}", e("-5e-7")),
        ("{\"id\":1e-6,\"k\":\"b\",\"n\":\"c\"}", e("0.000001")),
        ("{\"id\":1e-7,\"k\":\"b\",\"n\":\"c\"}", e("1e-7")),
        ("{\"id\":144115188075855877,\"k\":\"b\",\"n\":\"c\"}", e("144115188075855870")),
        ("{\"id\":18446744073709551616,\"k\":\"b\",\"n\":\"c\"}", e("18446744073709552000")),
        ("{\"id\":-9223372036854775809,\"k\":\"b\",\"n\":\"c\"}", e("-9223372036854776000")),
        ("{\"id\":1,\"k\":2,\"n\":3,\"m\":\"x\"}", Some(E { p: "", id: "1", k: "2", n: "3", m: "x", fname: None, s: None, d: None })),
        // String() of booleans / objects / arrays; own toString → TypeError → null
        ("{\"id\":true,\"k\":{},\"n\":[]}", Some(E { p: "", id: "true", k: "[object Object]", n: "", m: OCT, fname: None, s: None, d: None })),
        ("{\"id\":[1,[2,\"x\"],null,true,{},[]],\"k\":\"b\",\"n\":\"c\"}", e("1,2,x,,true,[object Object],")),
        ("{\"id\":[[[[]]]],\"k\":\"b\",\"n\":\"c\"}", e("")),
        ("{\"id\":{\"toString\":1},\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":[{\"toString\":\"x\"}],\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":{\"valueOf\":1},\"k\":\"b\",\"n\":\"c\"}", e("[object Object]")),
        ("{\"id\":{\"__proto__\":{\"toString\":1}},\"k\":\"b\",\"n\":\"c\"}", e("[object Object]")),
        ("{\"__proto__\":{\"id\":\"x\"},\"k\":\"b\",\"n\":\"c\"}", None),
        // typeof gates on p / m / fn / s / d
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\",\"s\":1e400,\"d\":-0}", Some(E { p: "", id: "a", k: "b", n: "c", m: OCT, fname: None, s: Some(f64::INFINITY), d: Some(-0.0) })),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\",\"s\":\"256\",\"d\":\"3.5\",\"fn\":7,\"m\":5,\"p\":null}", e("a")),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\",\"p\":\"\",\"m\":\"\",\"fn\":\"\"}", Some(E { p: "", id: "a", k: "b", n: "c", m: "", fname: Some(""), s: None, d: None })),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\",\"s\":256,\"d\":3.5,\"fn\":\"f.jpg\",\"m\":\"image/png\",\"p\":\"hi\"}", Some(E { p: "hi", id: "a", k: "b", n: "c", m: "image/png", fname: Some("f.jpg"), s: Some(256.0), d: Some(3.5) })),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\",\"s\":1.0,\"d\":100}", Some(E { p: "", id: "a", k: "b", n: "c", m: OCT, fname: None, s: Some(1.0), d: Some(100.0) })),
        // JSON.parse grammar
        ("{\"id\":\"a\",\"id\":\"b\",\"k\":\"x\",\"n\":\"y\"}", Some(E { p: "", id: "b", k: "x", n: "y", m: OCT, fname: None, s: None, d: None })),
        (" \t\n{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\"}\r\n ", e("a")),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\"} ", e("a")),
        ("\u{feff}{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\"}x", None),
        ("{\"id\":\"a\\u0041\\n\\/\\\"\",\"k\":\"b\",\"n\":\"c\",\"p\":\"\\u0000\\u00E9\"}", Some(E { p: "\u{0}\u{e9}", id: "aA\n/\"", k: "b", n: "c", m: OCT, fname: None, s: None, d: None })),
        ("{\"\\u0069d\":\"a\",\"k\":\"b\",\"n\":\"c\"}", e("a")),
        ("{\"id\":\"\\uD83D\\uDCF7\",\"k\":\"b\",\"n\":\"c\"}", e("\u{1f4f7}")),
        ("{\"id\":\"\u{2028}\u{7f}\",\"k\":\"b\",\"n\":\"c\"}", e("\u{2028}\u{7f}")),
        ("{\"id\":01,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":1.,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":.5,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":+1,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":1e,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":NaN,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":-,\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":\"a\tb\",\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":\"\\x\",\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":\"\\u12\",\"k\":\"b\",\"n\":\"c\"}", None),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\",}", None),
        ("{\"id\":\"a\",\"k\":\"b\",\"n\":\"c\",\"x\":[1,2,]}", None),
        ("{'id':'a'}", None),
        ("{\"id\":\"a\" \"k\":\"b\"}", None),
        ("nul", None),
        // Lone surrogates: JS keeps them, a Rust String cannot → U+FFFD
        // (node: fileId === "\ud800" / "\udcf7\ud83d").
        ("{\"id\":\"\\ud800\",\"k\":\"x\",\"n\":\"y\"}", Some(E { p: "", id: "\u{fffd}", k: "x", n: "y", m: OCT, fname: None, s: None, d: None })),
        ("{\"id\":\"\\udcf7\\ud83d\",\"k\":\"b\",\"n\":\"c\"}", e("\u{fffd}\u{fffd}")),
    ];
    for (text, want) in &cases {
        let got = parse_file_envelope(text);
        match (got, want) {
            (None, None) => {}
            (Some(g), Some(w)) => assert_same_envelope(&g, &w.envelope(), text),
            (g, w) => panic!("{text:?}: got {g:?}, want {}", if w.is_some() { "an envelope" } else { "null" }),
        }
    }
}

#[test]
fn node_build_edge_cases() {
    let base = |s: Option<f64>, d: Option<f64>| E { p: "p", id: "i", k: "k", n: "n", m: "m", fname: None, s, d };
    #[rustfmt::skip]
    let cases: Vec<(E, &str)> = vec![
        // QuoteJSONString: short escapes, lowercase \u00xx, DEL / U+2028 / non-ASCII raw
        (E { p: "a\"b\\c\n\u{1}\u{1f}\u{7f}\u{2028}\u{8}\u{c}\r\t/\u{e9}", id: "x", k: "k", n: "n", m: "m", fname: None, s: None, d: None },
         "{\"p\":\"a\\\"b\\\\c\\n\\u0001\\u001f\u{7f}\u{2028}\\b\\f\\r\\t/\u{e9}\",\"id\":\"x\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\"}"),
        (E { p: "", id: "", k: "", n: "", m: "", fname: Some(""), s: Some(0.0), d: Some(0.0) },
         "{\"p\":\"\",\"id\":\"\",\"k\":\"\",\"n\":\"\",\"m\":\"\",\"fn\":\"\",\"s\":0,\"d\":0}"),
        (base(Some(-0.0), Some(1e21)), "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":0,\"d\":1e+21}"),
        (base(Some(f64::NAN), Some(f64::INFINITY)), "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":null,\"d\":null}"),
        (base(Some(1.5e-7), Some(1e-6)), "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":1.5e-7,\"d\":0.000001}"),
        (base(Some(123456789.0), Some(12.345678901234567)), "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":123456789,\"d\":12.345678901234567}"),
        (base(Some(1e20), Some(5e-324)), "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":100000000000000000000,\"d\":5e-324}"),
        (base(Some(-1.7976931348623157e308), Some(1e-7)), "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":-1.7976931348623157e+308,\"d\":1e-7}"),
        (base(None, Some(0.1)), "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"d\":0.1}"),
    ];
    for (input, want) in &cases {
        assert_eq!(build_file_envelope(&input.envelope()), *want);
    }
}

/// Number::toString on EXACT half-way ties: JS picks the even digit string,
/// Rust's `{:e}` rounds half up. These values are exactly representable
/// (float32-derived durations look like this). Expected strings come from
/// the production crypto.ts under node 22, and are not derived by hand. A
/// differential fuzz against that TS found the divergence
/// (158508.102783203125 → JS "…312", the earlier port "…313").
#[test]
#[allow(clippy::excessive_precision)] // the exact values ARE the tie
fn node_number_ties_round_half_even() {
    let env = |s: f64, d: f64| FileEnvelope {
        placeholder: "p".into(),
        file_id: "i".into(),
        key: "k".into(),
        nonce: "n".into(),
        mime_type: "m".into(),
        file_name: None,
        file_size: Some(s),
        duration: Some(d),
    };
    #[rustfmt::skip]
    let build: &[(f64, f64, &str)] = &[
        (158508.102783203125, 624716405291110.25, "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":158508.10278320312,\"d\":624716405291110.2}"),
        (1732058872003108.25, 9487.8560791015625, "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":1732058872003108.2,\"d\":9487.856079101562}"),
        // tie resolved to the LOWER candidate (even last digit below)
        (226309001991.890625, 1629471159462595.25, "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":226309001991.89062,\"d\":1629471159462595.2}"),
        // tie resolved to the UPPER candidate (even last digit above)
        (994724964205457.75, 1928961863976278.75, "{\"p\":\"p\",\"id\":\"i\",\"k\":\"k\",\"n\":\"n\",\"m\":\"m\",\"s\":994724964205457.8,\"d\":1928961863976278.8}"),
    ];
    for (s, d, want) in build {
        assert_eq!(build_file_envelope(&env(*s, *d)), *want);
    }
    // String(o.id) goes through the same Number::toString.
    for (lit, want) in [("158508.102783203125", "158508.10278320312"), ("27046.3106689453125", "27046.310668945312")] {
        let text = format!("{{\"id\":{lit},\"k\":\"b\",\"n\":\"c\"}}");
        assert_eq!(parse_file_envelope(&text).map(|e| e.file_id).as_deref(), Some(want), "{lit}");
    }
}

#[test]
fn deep_json_is_null_not_a_crash() {
    // RN never nests envelopes; this port bounds JSON nesting (128) and must
    // answer null, not overflow the stack, for adversarial depth. KNOWN
    // divergence: V8 (node 22) parses 100 000 levels; the envelope would then
    // still be valid there (String([[…]]) === ""). Hermes' own bound differs.
    let deep = |levels: usize| format!("{{\"id\":{}{},\"k\":\"b\",\"n\":\"c\"}}", "[".repeat(levels), "]".repeat(levels));
    assert_eq!(parse_file_envelope(&deep(100)).map(|e| e.file_id), Some(String::new()));
    assert_eq!(parse_file_envelope(&deep(100_000)), None);
    let deep_obj = format!("{}{}", "{\"a\":".repeat(100_000), "}".repeat(100_000));
    assert_eq!(parse_file_envelope(&deep_obj), None);
}
