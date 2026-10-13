//! Replays docs/native/vectors/identityBackup.json — the RN client's sealed
//! identity-key backup slot (crypto.ts:251-331, secureStorage.ts:346-351,
//! auth.ts:491-622) — against the Rust port, byte for byte: the subkey, the
//! recorded blob opened, and the blob re-sealed from the recorded draw. Then
//! every rejection path of `openIdentityBackup` (all → null in TS) and the
//! auth.ts restore gate / backfill decision built on it.
//!
//! The vector records no explicit negative cases; the negatives below are
//! derived from the recorded blob/key exactly as the TS code would treat them
//! (its try/catch → null, its falsy checks). Alice's public key and uids come
//! from primitives.json (also TS-recorded), not from the Rust port.

use mrenzo_core::identity_backup::*;
use mrenzo_core::primitives::{b64, b64d, b64d32, secretbox_open, secretbox_seal, sha512};
use mrenzo_core::rng::ReplayRng;
use serde_json::{json, Value};

fn load(name: &str) -> Value {
    let p = format!("{}/../../docs/native/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap()
}

fn v() -> Value {
    load("identityBackup.json")
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

fn mmkv(v: &Value) -> Option<&str> {
    Some(s(&v["mmkvKeyHex"]))
}

fn subkey(v: &Value) -> [u8; 32] {
    hex::decode(s(&v["subkeyHex"])).unwrap().try_into().unwrap()
}

fn nonce(v: &Value) -> [u8; 24] {
    draws(&v["rng"])[0].clone().try_into().unwrap()
}

/// Build a slot the way sealIdentityBackup lays it out, from arbitrary
/// plaintext bytes (to reach states a &str cannot, e.g. non-UTF-8).
fn slot_with_plaintext(v: &Value, pt: &[u8]) -> String {
    let n = nonce(v);
    let mut raw = n.to_vec();
    raw.extend_from_slice(&secretbox_seal(pt, &n, &subkey(v)));
    b64(&raw)
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
            "area", "blobB64", "context", "encodings", "generator", "mmkvKeyHex", "notes", "privateKeyB64", "rng",
            "schema", "sources", "subkeyHex",
        ]
    );
    assert_eq!(s(&v["area"]), "identityBackup");
    assert_eq!(v["schema"], json!(1));
    assert_eq!(s(&v["generator"]), "mobile/src/__tests__/goldenVectors.test.ts");
    assert!(s(&v["encodings"]).contains("*B64"));
    let sources: Vec<&str> = v["sources"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(
        sources,
        [
            "mobile/src/utils/crypto.ts:251-331",
            "mobile/src/services/secureStorage.ts:346-351 (deriveStorageSubkey)",
            "mobile/src/store/auth.ts:564-621",
        ]
    );
    let notes: Vec<&str> = v["notes"].as_array().unwrap().iter().map(s).collect();
    assert_eq!(notes.len(), 3);
    assert!(notes[0].starts_with("LOCAL-ONLY"));
    assert!(notes[1].contains("the hex STRING is concatenated, not decoded"));
    assert!(notes[2].contains("the plaintext is the base64 text of the key, not the raw 32 bytes"));
    assert_eq!(s(&v["rng"]["label"]), "identityBackup/sealIdentityBackup");
    assert_eq!(draws(&v["rng"]).len(), 1);
}

#[test]
fn context_and_storage_key_names() {
    let v = v();
    assert_eq!(IDENTITY_BACKUP_CONTEXT, s(&v["context"]));
    assert_eq!(IDENTITY_KEY_BACKUP, "identity_key_backup_v1");
    assert_eq!(IDENTITY_KEY_BACKUP_UID, "identity_key_backup_uid");
    // The recorded key is a 32-char lowercase hex STRING (Keychain com.mrenzo.mmkv.key).
    let k = s(&v["mmkvKeyHex"]);
    assert_eq!(k.len(), 32);
    assert!(k.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

/// subkey = SHA-512(UTF-8(context + mmkvKeyHex))[0:32] — string concat.
#[test]
fn subkey_hashes_the_hex_string() {
    let v = v();
    let ctx = s(&v["context"]);
    let expected = s(&v["subkeyHex"]);
    assert_eq!(hex::encode(derive_storage_subkey(ctx, mmkv(&v)).unwrap()), expected);
    assert_eq!(hex::encode(identity_backup_subkey(mmkv(&v)).unwrap()), expected);
    // Independent re-derivation from the note's formula.
    let concat = format!("{ctx}{}", s(&v["mmkvKeyHex"]));
    assert_eq!(hex::encode(&sha512(concat.as_bytes())[..32]), expected);
    // Trap: hashing the 16 DECODED key bytes is a different (wrong) key.
    let mut decoded = ctx.as_bytes().to_vec();
    decoded.extend_from_slice(&hex::decode(s(&v["mmkvKeyHex"])).unwrap());
    assert_ne!(hex::encode(&sha512(&decoded)[..32]), expected);
    // It is the STRING: an uppercase rendering of the same bytes is another key.
    let upper = s(&v["mmkvKeyHex"]).to_ascii_uppercase();
    assert_ne!(hex::encode(derive_storage_subkey(ctx, Some(&upper)).unwrap()), expected);
}

#[test]
fn opens_recorded_blob() {
    let v = v();
    assert_eq!(open_identity_backup(s(&v["blobB64"]), mmkv(&v)).as_deref(), Some(s(&v["privateKeyB64"])));
}

#[test]
fn seal_replays_recorded_draw_byte_exact() {
    let v = v();
    let mut r = replay(&v["rng"]);
    let blob = seal_identity_backup(s(&v["privateKeyB64"]), mmkv(&v), &mut r).unwrap();
    r.assert_exhausted();
    assert_eq!(blob, s(&v["blobB64"]));

    // Layout: nonce(24) || tag(16) || ct(len(plaintext)).
    let raw = b64d(&blob).unwrap();
    let pk_text = s(&v["privateKeyB64"]);
    assert_eq!(&raw[..24], nonce(&v).as_slice());
    assert_eq!(raw.len(), 24 + 16 + pk_text.len());
    // Trap: the plaintext is the 44-char base64 TEXT, not the 32 raw bytes.
    assert_eq!(pk_text.len(), 44);
    let pt = secretbox_open(&raw[24..], &nonce(&v), &subkey(&v)).unwrap();
    assert_eq!(pt, pk_text.as_bytes());
    assert_ne!(pt.as_slice(), b64d32(pk_text).unwrap().as_slice());
}

/// identityBackupSubkey() throws before nacl.randomBytes(24): no draw happens.
#[test]
fn storage_not_ready_throws_before_drawing_and_opens_null() {
    let v = v();
    for key in [None, Some("")] {
        let mut r = ReplayRng::new("identityBackup/notReady", vec![]);
        let err = seal_identity_backup(s(&v["privateKeyB64"]), key, &mut r).unwrap_err();
        r.assert_exhausted();
        assert_eq!(err, IdentityBackupError::StorageNotReady);
        assert_eq!(err.to_string(), "secure storage not ready — cannot derive backup key");
        assert_eq!(derive_storage_subkey(s(&v["context"]), key), None);
        assert_eq!(identity_backup_subkey(key), Err(IdentityBackupError::StorageNotReady));
        assert_eq!(open_identity_backup(s(&v["blobB64"]), key), None, "key {key:?}");
    }
}

/// The slot is device-bound: another device's MMKV key cannot open it.
#[test]
fn another_devices_key_is_rejected() {
    let v = v();
    for other in ["ffeeddccbbaa99887766554433221100", "00112233445566778899aabbccddeef0", "00112233445566778899AABBCCDDEEFF"] {
        assert_eq!(open_identity_backup(s(&v["blobB64"]), Some(other)), None, "{other}");
    }
}

/// Any single-bit tamper anywhere (nonce, tag, ciphertext) → null.
#[test]
fn every_bit_flip_is_rejected() {
    let v = v();
    let raw = b64d(s(&v["blobB64"])).unwrap();
    for i in 0..raw.len() {
        for bit in 0..8 {
            let mut t = raw.clone();
            t[i] ^= 1 << bit;
            assert_eq!(open_identity_backup(&b64(&t), mmkv(&v)), None, "byte {i} bit {bit}");
        }
    }
}

/// `raw.length < 24 + overheadLength` → null; exactly 40 bytes is allowed
/// through the length gate (a sealed empty string opens to "").
#[test]
fn length_gate_boundary() {
    let v = v();
    let raw = b64d(s(&v["blobB64"])).unwrap();
    for len in [0usize, 1, 24, 39] {
        assert_eq!(open_identity_backup(&b64(&raw[..len]), mmkv(&v)), None, "len {len}");
    }
    // 40 bytes cut from the recorded blob: passes the gate, fails the MAC.
    assert_eq!(open_identity_backup(&b64(&raw[..40]), mmkv(&v)), None);
    // Any truncation of the ciphertext tail fails the MAC.
    assert_eq!(open_identity_backup(&b64(&raw[..raw.len() - 1]), mmkv(&v)), None);

    // A sealed "" is exactly 40 bytes and opens to Some("") (JS returns '').
    let mut r = replay(&v["rng"]);
    let empty = seal_identity_backup("", mmkv(&v), &mut r).unwrap();
    r.assert_exhausted();
    assert_eq!(b64d(&empty).unwrap().len(), 40);
    assert_eq!(open_identity_backup(&empty, mmkv(&v)).as_deref(), Some(""));
}

/// decodeBase64 throws (validateBase64 regex) → caught → null.
#[test]
fn invalid_base64_is_rejected() {
    let v = v();
    let blob = s(&v["blobB64"]);
    assert!(blob.contains('+') && blob.contains('/'));
    let url_safe = blob.replace('+', "-").replace('/', "_");
    let cases = [
        blob[1..].to_string(),                       // length % 4 != 0
        format!("{blob}="),                          // stray pad
        format!(" {blob}"),                          // leading whitespace
        format!("{blob}\n"),                         // trailing newline
        format!("{}\n{}", &blob[..56], &blob[56..]), // embedded newline
        url_safe,                                    // base64url alphabet
        "not base64!".to_string(),
    ];
    for c in &cases {
        assert_eq!(open_identity_backup(c, mmkv(&v)), None, "{c:?}");
    }
    // "" is valid base64 (0 bytes) but fails the length gate.
    assert_eq!(open_identity_backup("", mmkv(&v)), None);
}

/// Build 294 stored the raw b64 key string, unauthenticated. It decodes to
/// 32 bytes (< 40) → null; the backfill then re-seals over it.
#[test]
fn legacy_raw_294_slot_is_untrusted() {
    let v = v();
    let pk = s(&v["privateKeyB64"]);
    assert_eq!(open_identity_backup(pk, mmkv(&v)), None);
    assert_eq!(restore_gate(Some(pk), None, "1001", Some("anything"), mmkv(&v)), RestoreGate::Tampered);
    assert!(backfill_needs_reseal(Some(pk), Some("1001"), pk, "1001", mmkv(&v)));
}

/// encodeUTF8 = decodeURIComponent(escape(..)) throws on invalid UTF-8 → null;
/// valid multi-byte UTF-8 round-trips through decodeUTF8/encodeUTF8.
#[test]
fn plaintext_must_be_valid_utf8() {
    let v = v();
    for bad in [&[0xffu8][..], &[0xc3], &[0xed, 0xa0, 0x80], &[0xc0, 0xaf]] {
        assert_eq!(open_identity_backup(&slot_with_plaintext(&v, bad), mmkv(&v)), None, "{bad:02x?}");
    }
    let mut r = replay(&v["rng"]);
    let sealed = seal_identity_backup("é👋", mmkv(&v), &mut r).unwrap();
    r.assert_exhausted();
    assert_eq!(sealed, slot_with_plaintext(&v, "é👋".as_bytes()));
    assert_eq!(open_identity_backup(&sealed, mmkv(&v)).as_deref(), Some("é👋"));
}

/// tweetnacl-util's decodeBase64 (atob / Buffer) discards non-zero trailing
/// bits of the last quantum, so RN opens such a blob; the port must too.
#[test]
fn non_canonical_trailing_bits_are_accepted_like_atob() {
    let v = v();
    let pk = s(&v["privateKeyB64"]);
    let text = format!("{pk}x"); // 45 bytes → raw 85 bytes → "xx==" tail (4 spare bits)
    let mut r = replay(&v["rng"]);
    let canonical = seal_identity_backup(&text, mmkv(&v), &mut r).unwrap();
    r.assert_exhausted();
    assert!(canonical.ends_with("=="));
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let i = canonical.len() - 3;
    let c = canonical.as_bytes()[i];
    let idx = alphabet.iter().position(|&a| a == c).unwrap();
    assert_eq!(idx & 0x0f, 0, "canonical tail has zero spare bits");
    for spare in 1..16 {
        let mut t = canonical.clone().into_bytes();
        t[i] = alphabet[idx | spare];
        let t = String::from_utf8(t).unwrap();
        assert_eq!(open_identity_backup(&t, mmkv(&v)).as_deref(), Some(text.as_str()), "spare bits {spare}");
    }
}

/// auth.ts:495-549 — which slots RN adopts after a Keychain read-miss.
#[test]
fn restore_gate_matches_auth_ts() {
    let v = v();
    let prim = load("primitives.json");
    let alice = &prim["keys"]["alice"];
    let blob = s(&v["blobB64"]);
    let pk = s(&v["privateKeyB64"]);
    assert_eq!(pk, s(&alice["x25519PrivB64"]), "vector seals alice's X25519 key");
    let alice_pub = s(&alice["x25519PubB64"]);
    let me = alice["uid"].to_string(); // String(user.id)
    let other = prim["keys"]["bob"]["uid"].to_string();
    let key = mmkv(&v);
    let adopt = |legacy| RestoreGate::Adopt { private_key_b64: pk.to_string(), legacy_accepted: legacy };

    // No slot: undefined or '' (falsy) — nothing logged.
    assert_eq!(restore_gate(None, Some(&me), &me, Some(alice_pub), key), RestoreGate::NoSlot);
    assert_eq!(restore_gate(Some(""), Some(&me), &me, Some(alice_pub), key), RestoreGate::NoSlot);

    // Bound to me: adopt, with NO public-key check at all.
    for known in [Some(alice_pub), None, Some(""), Some("not-my-pub")] {
        assert_eq!(restore_gate(Some(blob), Some(&me), &me, known, key), adopt(false));
    }
    // Bound to someone else (or I have no user): refuse.
    assert_eq!(
        restore_gate(Some(blob), Some(&other), &me, Some(alice_pub), key),
        RestoreGate::UidMismatch { bound: other.clone(), me: me.clone() }
    );
    assert_eq!(
        restore_gate(Some(blob), Some(&me), "", Some(alice_pub), key),
        RestoreGate::UidMismatch { bound: me.clone(), me: String::new() }
    );

    // Legacy (no uid recorded; '' is the same as undefined): adopt only if the
    // derived public half equals the stored user's publicKey.
    for slot_uid in [None, Some("")] {
        assert_eq!(restore_gate(Some(blob), slot_uid, &me, Some(alice_pub), key), adopt(true));
        assert_eq!(restore_gate(Some(blob), slot_uid, "", Some(alice_pub), key), adopt(true));
        for known in [None, Some("")] {
            assert_eq!(
                restore_gate(Some(blob), slot_uid, &me, known, key),
                RestoreGate::LegacyUnproven { have_derived: true, have_known_pub: false }
            );
        }
        let bob_pub = s(&prim["keys"]["bob"]["x25519PubB64"]);
        assert_eq!(
            restore_gate(Some(blob), slot_uid, &me, Some(bob_pub), key),
            RestoreGate::LegacyUnproven { have_derived: true, have_known_pub: true }
        );
    }
    // Legacy slot whose plaintext is not a 32-byte base64 key: derivePublicKey
    // throws → derived '' → unproven.
    for junk in ["not-a-key", "AAAA", "7GTOhc5jH/jLU/wWVrj1L2y9/J5F7vr460ATMM9yvg=="] {
        let slot = slot_with_plaintext(&v, junk.as_bytes());
        assert_eq!(open_identity_backup(&slot, key).as_deref(), Some(junk));
        assert_eq!(
            restore_gate(Some(&slot), None, &me, Some(alice_pub), key),
            RestoreGate::LegacyUnproven { have_derived: false, have_known_pub: true },
            "{junk}"
        );
        // Bound to me: adopted verbatim — RN checks nothing else here
        // (storePrivateKey/derivePublicKey then throw → identity.restore.failed).
        assert_eq!(
            restore_gate(Some(&slot), Some(&me), &me, Some(alice_pub), key),
            RestoreGate::Adopt { private_key_b64: junk.to_string(), legacy_accepted: false }
        );
    }

    // Tampered / wrong device / storage not ready → tampered (checked before uid).
    let mut raw = b64d(blob).unwrap();
    raw[50] ^= 0x01;
    let flipped = b64(&raw);
    assert_eq!(restore_gate(Some(&flipped), Some(&me), &me, Some(alice_pub), key), RestoreGate::Tampered);
    assert_eq!(restore_gate(Some(&flipped), Some(&other), &me, None, key), RestoreGate::Tampered);
    assert_eq!(restore_gate(Some(blob), Some(&me), &me, Some(alice_pub), None), RestoreGate::Tampered);
    assert_eq!(
        restore_gate(Some(blob), Some(&me), &me, Some(alice_pub), Some("ffeeddccbbaa99887766554433221100")),
        RestoreGate::Tampered
    );
    // A slot that opens to '' is falsy: logged as tampered, never adopted.
    let empty = slot_with_plaintext(&v, b"");
    assert_eq!(open_identity_backup(&empty, key).as_deref(), Some(""));
    assert_eq!(restore_gate(Some(&empty), Some(&me), &me, Some(alice_pub), key), RestoreGate::Tampered);
}

/// auth.ts:616-619 — `!existing || open(existing) !== privKey || existingUid !== meUid`.
#[test]
fn backfill_reseal_decision_matches_auth_ts() {
    let v = v();
    let blob = s(&v["blobB64"]);
    let pk = s(&v["privateKeyB64"]);
    let key = mmkv(&v);

    // Slot is current: nothing to do.
    assert!(!backfill_needs_reseal(Some(blob), Some("1001"), pk, "1001", key));
    // No user and no uid recorded: ('' || '') === '' → current.
    assert!(!backfill_needs_reseal(Some(blob), None, pk, "", key));
    assert!(!backfill_needs_reseal(Some(blob), Some(""), pk, "", key));

    // Missing / empty slot.
    assert!(backfill_needs_reseal(None, Some("1001"), pk, "1001", key));
    assert!(backfill_needs_reseal(Some(""), Some("1001"), pk, "1001", key));
    // Slot holds a different key (Keychain is authoritative).
    let bob_priv = s(&load("primitives.json")["keys"]["bob"]["x25519PrivB64"]).to_string();
    assert!(backfill_needs_reseal(Some(blob), Some("1001"), &bob_priv, "1001", key));
    // Uid missing (pre-316) or foreign → re-bind.
    assert!(backfill_needs_reseal(Some(blob), None, pk, "1001", key));
    assert!(backfill_needs_reseal(Some(blob), Some("2002"), pk, "1001", key));
    // Unopenable slot (tamper, other device, storage not ready) → re-seal.
    let mut raw = b64d(blob).unwrap();
    raw[0] ^= 0x80;
    assert!(backfill_needs_reseal(Some(&b64(&raw)), Some("1001"), pk, "1001", key));
    assert!(backfill_needs_reseal(Some(blob), Some("1001"), pk, "1001", Some("ffeeddccbbaa99887766554433221100")));
    assert!(backfill_needs_reseal(Some(blob), Some("1001"), pk, "1001", None));
}
