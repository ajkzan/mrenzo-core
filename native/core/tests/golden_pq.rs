//! The hybrid session setup (wire-1.1 §W6): mlkem768Kat.json (the KEM pinned
//! for this build and for the Go cross-check), pqxdhV1.json (signed KEM
//! prekeys, the derivation, the header and every way it must fail) and
//! ratchetV3Pq.json (a transcript over a hybrid session). The classical
//! vectors (x3dhV2.json, ratchetV3.json) are verified unchanged by
//! tests/golden_ratchet_v3.rs.

mod common;

use common::*;
use mrenzo_core::kem;
use mrenzo_core::plaintext::TypedPlaintext;
use mrenzo_core::primitives::{b64, sha256};
use mrenzo_core::ratchet::*;
use mrenzo_core::rng::{Rng, StreamRng};
use mrenzo_core::session_set::{PeerSessions, SetDecrypt, SetOpen, Status};
use mrenzo_core::x3dh::*;
use serde_json::{json, Map, Value};

fn chat(id: &str, body: &str) -> String {
    TypedPlaintext::Chat { id: id.into(), body: body.into(), reply: None, fwd: None, expire: None, story: None }.to_json()
}

fn kem_json(k: &GeneratedKemPreKey, label: &str) -> Value {
    json!({
        "rngLabel": label, "keyId": k.key_id, "kind": if k.kind == KemKind::LastResort { "lastResort" } else { "oneTime" },
        "seedHex": hx(&k.seed), "pubB64": b64(&k.ek), "pubSha256Hex": hx(&sha256(&k.ek)),
        "signedBytesSha256Hex": hx(&sha256(&kem_prekey_signed_bytes(k.key_id, k.kind, &k.ek))),
        "signatureB64": b64(&k.signature), "uploadEntry": kem_upload_entry(k),
    })
}

fn bob_kem(b: &Ident) -> (GeneratedKemPreKey, GeneratedKemPreKey) {
    (
        generate_kem_pre_key(&b.ed_secret, 42, KemKind::OneTime, &mut StreamRng::new("pq/bob-kem-otk")),
        generate_kem_pre_key(&b.ed_secret, 7, KemKind::LastResort, &mut StreamRng::new("pq/bob-kem-lr")),
    )
}

#[test]
fn mlkem768_known_answers() {
    assert_eq!((kem::EK_LEN, kem::CT_LEN, kem::SEED_LEN, kem::SS_LEN), (1184, 1088, 64, 32), "FIPS 203 ML-KEM-768 sizes");
    let mut cases: Vec<Value> = Vec::new();
    for i in 0..4 {
        let mut r = StreamRng::new(&format!("pq/kat/{i}"));
        let (mut seed, mut m) = ([0u8; 64], [0u8; 32]);
        r.fill(&mut seed);
        r.fill(&mut m);
        let ek = kem::encapsulation_key(&seed);
        assert!(kem::validate_encapsulation_key(&ek));
        let (ct, ss) = kem::encapsulate(&ek, &m).unwrap();
        assert_eq!(kem::decapsulate(&seed, &ct), ss);
        // Deterministic: the same seed and randomness give the same bytes.
        assert_eq!(kem::encapsulate(&kem::encapsulation_key(&seed), &m).unwrap(), (ct, ss));
        // Implicit rejection (FIPS 203 §6.3): a ciphertext not made for this key
        // decapsulates to a pseudorandom secret that depends on the key and the ciphertext.
        let mut bad = ct;
        bad[i * 97] ^= 0x01;
        let rejected = kem::decapsulate(&seed, &bad);
        assert_ne!(rejected, ss);
        assert_eq!(kem::decapsulate(&seed, &bad), rejected);
        cases.push(json!({
            "rngLabel": format!("pq/kat/{i}"), "seedHex": hx(&seed), "ekSha256Hex": hx(&sha256(&ek)), "ekB64": b64(&ek),
            "mHex": hx(&m), "ctB64": b64(&ct), "ssHex": hx(&ss),
            "rejectCtB64": b64(&bad), "rejectSsHex": hx(&rejected),
        }));
    }
    let mut v = header_v11(
        "mlkem768Kat",
        &[
            "ML-KEM-768 (FIPS 203) as this build computes it (libcrux-ml-kem 0.0.10, the PORTABLE instantiation on every target): seed = d ‖ z (64 bytes) → ek (1184) ; Encaps_internal(ek, m) → (ct 1088, ss 32) ; Decaps(dk(seed), ct) = ss.",
            "Each case draws seed (64) then m (32) from the golden PRNG under its label. Any silent upstream change of the crate fails this file.",
            "Cross-check for the server (Go crypto/mlkem): NewDecapsulationKey768(seed).EncapsulationKey().Bytes() == ek ; Decapsulate(ct) == ss ; Decapsulate(rejectCt) == rejectSs (implicit rejection is deterministic).",
            "These are not the NIST ACVP files (not in the tree); they pin this build and give a second implementation something to agree with.",
        ],
    );
    v.insert("sizes".into(), json!({"ek": kem::EK_LEN, "ct": kem::CT_LEN, "seed": kem::SEED_LEN, "ss": kem::SS_LEN, "algByte": kem::ALG_MLKEM768, "algName": kem::ALG_NAME_MLKEM768}));
    v.insert("cases".into(), Value::Array(cases));
    check_or_write("mlkem768Kat.json", &Value::Object(v));
}

fn secret_json(s: &X3dhV2Secret) -> Value {
    json!({"skB64": b64(&s.sk), "adB64": b64(&s.ad), "sidB64": b64(&s.sid), "rk0B64": b64(&s.rk0)})
}

#[test]
fn pqxdh_vectors() {
    let (a, b, c) = (alice(), bob(), carol());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let (otk, lr) = bob_kem(&b);
    assert_eq!(otk.seed.len(), 64);
    assert!(verify_kem_prekey(&b.ed_pub, &otk.public()) && verify_kem_prekey(&b.ed_pub, &lr.public()));
    assert!(!verify_kem_prekey(&c.ed_pub, &otk.public()), "another identity's key does not verify under the pin");
    assert_eq!(kem_prekey_signed_bytes(42, KemKind::OneTime, &otk.ek).len(), 20 + 8 + 2 + 1184);
    assert_eq!(&kem_prekey_signed_bytes(42, KemKind::OneTime, &otk.ek)[..30], [b"mrenzo-kem-prekey-v1".as_slice(), &42u64.to_be_bytes(), &[0x02, 0x0a]].concat());

    let mut cases = Map::new();
    let mut wires: Vec<(String, Envelope, bool, &GeneratedKemPreKey)> = Vec::new();
    for (name, with_opk, key, label) in [
        ("opk+oneTime", true, &otk, "pq/x3dh-1"),
        ("noOpk+oneTime", false, &otk, "pq/x3dh-2"),
        ("opk+lastResort", true, &lr, "pq/x3dh-3"),
        ("noOpk+lastResort", false, &lr, "pq/x3dh-4"),
    ] {
        let init = x3dh_pq_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(with_opk), &key.public(), &mut StreamRng::new(label)).unwrap();
        let kem_header = init.header.kem.expect("a hybrid header");
        assert_eq!(kem_header.id, key.key_id);
        let resp = x3dh_pq_respond(&b.ik, &b.ed_pub, &p.spk, with_opk.then_some(&p.opk.private), Some((&key.seed, key.kind)), &init.header, &a.ik.public, &a.ed_pub).unwrap();
        assert_eq!(resp, init.secret, "{name}: both sides derive SK/AD/sid/RK0");
        // The same DHs without the KEM are another session entirely.
        let classical = x3dh_v2_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(with_opk), &mut StreamRng::new(label)).unwrap();
        assert_eq!(classical.ek, init.ek, "the ephemeral is drawn first in both");
        assert_ne!(classical.secret.sk, init.secret.sk);
        assert_eq!(classical.secret.ad, init.secret.ad, "AD is the same 140 bytes");
        // One message under the session: header bytes with xflag 2.
        let mut set = PeerSessions::default();
        set.initiate_pq(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(with_opk), &key.public(), T0, &mut StreamRng::new(label)).unwrap();
        assert!(set.live_is_pq());
        let env = set.encrypt(&chat("pq-1", "привет"), T0, &mut StreamRng::new(&format!("{label}/msg"))).unwrap();
        let hdr = env.header_bytes();
        assert_eq!(hdr.len(), 1 + 32 + 16 + 1 + 112 + 8 + 1088);
        assert_eq!(hdr[49], 2, "xflag 2");
        assert_eq!(&hdr[162..170], &(key.key_id as u64).to_be_bytes());
        assert_eq!(&hdr[170..], &kem_header.ct);
        let wire = env.to_wire();
        assert_eq!(Envelope::parse(&wire).unwrap(), env);
        assert!(wire.ends_with(&format!(",\"kem\":{{\"id\":{},\"ct\":\"{}\"}}}}}}", key.key_id, b64(&kem_header.ct))), "kem is the last key of x");
        cases.insert(
            name.into(),
            json!({
                "rngLabel": label, "withOpk": with_opk, "kemKeyId": key.key_id,
                "ekPrivB64": b64(&init.ek.private), "ekPubB64": b64(&init.ek.public),
                "kemCtB64": b64(&kem_header.ct), "kemCtSha256Hex": hx(&sha256(&kem_header.ct)),
                "secret": secret_json(&init.secret), "classicalSkB64": b64(&classical.secret.sk),
                "message": {"rngLabel": format!("{label}/msg"), "plaintext": chat("pq-1", "привет"), "wire": wire, "headerSha256Hex": hx(&sha256(&hdr)), "headerLen": hdr.len(), "macB64": b64(&env.mac)},
            }),
        );
        wires.push((name.to_string(), env, with_opk, key));
    }

    // ── negatives ──
    let mut negatives: Vec<Value> = Vec::new();
    let init = |key: &KemPreKeyPublic| x3dh_pq_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), key, &mut StreamRng::new("pq/neg"));
    let mut neg = |name: &str, got: Result<X3dhV2Initiation, X3dhV2Error>, want: X3dhV2Error| {
        assert_eq!(got.unwrap_err(), want, "{name}");
        negatives.push(json!({"name": name, "side": "initiator", "expect": want.to_string()}));
    };
    neg("signed as last-resort, offered as one-time", init(&KemPreKeyPublic { kind: KemKind::OneTime, ..lr.public() }), X3dhV2Error::KemSignature);
    neg("another key id", init(&KemPreKeyPublic { id: 43, ..otk.public() }), X3dhV2Error::KemSignature);
    let mut flipped = otk.public();
    flipped.ek[100] ^= 1;
    neg("a flipped key byte", init(&flipped), X3dhV2Error::KemSignature);
    let spk_label = KemPreKeyPublic { sig: sign_spk_v2(&b.ed_secret, &[0u8; 32]), ..otk.public() };
    neg("a signature made under the SPK label", init(&spk_label), X3dhV2Error::KemSignature);
    let foreign = generate_kem_pre_key(&c.ed_secret, 42, KemKind::OneTime, &mut StreamRng::new("pq/carol-kem"));
    neg("signed by another identity (a server-substituted key)", init(&foreign.public()), X3dhV2Error::KemSignature);
    // An encapsulation key that is validly SIGNED but fails the modulus check.
    let mut unreduced = otk.ek;
    unreduced[0] = 0xff;
    unreduced[1] = 0xff;
    let bad_ek = KemPreKeyPublic { id: 42, kind: KemKind::OneTime, ek: unreduced, sig: mrenzo_core::primitives::ed25519_sign(&b.ed_secret, &kem_prekey_signed_bytes(42, KemKind::OneTime, &unreduced)) };
    neg("a signed key that fails the FIPS 203 modulus check", init(&bad_ek), X3dhV2Error::KemInvalid);
    neg("key id out of range", init(&KemPreKeyPublic { id: -1, ..otk.public() }), X3dhV2Error::BadKeyId);
    let forged_spk = BundleV2 { spk_pub: c.ik.public, ..p.bundle(true) };
    neg(
        "the SPK is checked first",
        x3dh_pq_initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &forged_spk, &otk.public(), &mut StreamRng::new("pq/neg")),
        X3dhV2Error::SpkSignature,
    );

    // Responder side, on the first wire (opk + one-time).
    let (_, env, _, key) = &wires[0];
    let header = env.x.unwrap();
    let respond = |seed: Option<(&[u8; 64], KemKind)>, h: &PrekeyHeader| x3dh_pq_respond(&b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), seed, h, &a.ik.public, &a.ed_pub);
    let good = respond(Some((&key.seed, key.kind)), &header).unwrap();
    let mut rneg = |name: &str, got: Result<X3dhV2Secret, X3dhV2Error>, expect: &str| {
        match &got {
            Ok(s) => assert_ne!(s.sk, good.sk, "{name}: another session, so the envelope MAC fails"),
            Err(e) => assert_eq!(e.to_string(), expect, "{name}"),
        }
        assert_eq!(if got.is_ok() { "macFails" } else { expect }, expect, "{name}");
        negatives.push(json!({"name": name, "side": "responder", "expect": expect}));
    };
    rneg("a hybrid header without its KEM seed", respond(None, &header), "bad-key-id");
    let classical_header = PrekeyHeader { kem: None, ..header };
    rneg("a KEM seed for a classical header", respond(Some((&key.seed, key.kind)), &classical_header), "bad-key-id");
    rneg("the 1.0.0 responder entry point on a hybrid header", x3dh_v2_respond(&b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), &header, &a.ik.public, &a.ed_pub), "bad-key-id");
    rneg("the seed of another KEM key", respond(Some((&lr.seed, key.kind)), &header), "macFails");
    rneg("the right seed under the wrong kind", respond(Some((&key.seed, KemKind::LastResort)), &header), "macFails");
    let mut tampered = header;
    tampered.kem.as_mut().unwrap().ct[500] ^= 1;
    rneg("a tampered ciphertext (implicit rejection)", respond(Some((&key.seed, key.kind)), &tampered), "macFails");
    let mut other_id = header;
    other_id.kem.as_mut().unwrap().id = 43;
    rneg("another kem id in the header", respond(Some((&key.seed, key.kind)), &other_id), "macFails");
    rneg(
        "a header identity that is not the pin",
        x3dh_pq_respond(&b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), Some((&key.seed, key.kind)), &header, &c.ik.public, &c.ed_pub),
        "identity-mismatch",
    );

    // Envelope level: the MAC covers the flag, the id and the ciphertext.
    let wire = env.to_wire();
    let open = |w: &str, seed: Option<(&[u8; 64], KemKind)>| -> String {
        let Ok(e) = Envelope::parse(w) else { return "notEnvelope".into() };
        let mut set = PeerSessions::default();
        match set.respond_and_open(&e, &b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), seed, &a.ik.public, &a.ed_pub, T0, &mut StreamRng::new("pq/open")) {
            Ok(SetOpen::Typed { by, .. }) => {
                assert!(by.created && by.pq == e.x.is_some_and(|x| x.kem.is_some()));
                "typed".into()
            }
            Ok(SetOpen::Failed) => "failed".into(),
            Ok(o) => format!("{o:?}"),
            Err(err) => err.to_string(),
        }
    };
    let mut ecase = |name: &str, w: String, seed: Option<(&[u8; 64], KemKind)>, want: &str| {
        assert_eq!(open(&w, seed), want, "{name}");
        negatives.push(json!({"name": name, "side": "envelope", "wire": w, "expect": want}));
    };
    assert_eq!(open(&wire, Some((&key.seed, key.kind))), "typed");
    let mut stripped: Value = serde_json::from_str(&wire).unwrap();
    stripped["x"].as_object_mut().unwrap().remove("kem");
    ecase("kem stripped by a relay: the classical secret does not open it", stripped.to_string(), None, "failed");
    // A classical wire with a kem added.
    let mut classical_set = PeerSessions::default();
    classical_set.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), T0, &mut StreamRng::new("pq/classical")).unwrap();
    assert!(!classical_set.live_is_pq());
    let classical_wire = classical_set.encrypt(&chat("c-1", "x"), T0, &mut StreamRng::new("pq/classical/msg")).unwrap().to_wire();
    assert_eq!(open(&classical_wire, None), "typed", "a classical prekey message still opens");
    let mut added: Value = serde_json::from_str(&classical_wire).unwrap();
    added["x"]["kem"] = serde_json::from_str::<Value>(&wire).unwrap()["x"]["kem"].clone();
    ecase("kem added by a relay", added.to_string(), Some((&key.seed, key.kind)), "failed");
    let set_ct = |ct: String| {
        let mut v: Value = serde_json::from_str(&wire).unwrap();
        v["x"]["kem"]["ct"] = json!(ct);
        v.to_string()
    };
    let ct = header.kem.unwrap().ct;
    ecase("ct one byte short", set_ct(b64(&ct[..1087])), Some((&key.seed, key.kind)), "notEnvelope");
    ecase("ct one byte long", set_ct(b64(&[&ct[..], &[0u8]].concat())), Some((&key.seed, key.kind)), "notEnvelope");
    ecase("ct not base64", set_ct("!!!".into()), Some((&key.seed, key.kind)), "notEnvelope");
    let mut bad_id: Value = serde_json::from_str(&wire).unwrap();
    bad_id["x"]["kem"]["id"] = json!(9007199254740992u64);
    ecase("kem id of 2^53", bad_id.to_string(), Some((&key.seed, key.kind)), "notEnvelope");
    let mut float_id: Value = serde_json::from_str(&wire).unwrap();
    float_id["x"]["kem"]["id"] = json!(42.5);
    ecase("kem id not an integer", float_id.to_string(), Some((&key.seed, key.kind)), "notEnvelope");
    let mut not_obj: Value = serde_json::from_str(&wire).unwrap();
    not_obj["x"]["kem"] = json!("x");
    ecase("kem not an object", not_obj.to_string(), Some((&key.seed, key.kind)), "notEnvelope");

    let mut v = header_v11(
        "pqxdhV1",
        &[
            "Hybrid setup = X3DH v2 (x3dhV2.json, unchanged) plus ML-KEM-768 to a KEM prekey signed by the responder's identity key. Keys alice / bob and Bob's SPK (17) / OPK (118) are those of x3dhV2.json.",
            "KEM prekey signature = Ed25519(ED, \"mrenzo-kem-prekey-v1\" ‖ BE64(keyId) ‖ kind ‖ 0x0A ‖ ek[1184]); kind 0x01 last-resort, 0x02 one-time; verified strictly under the PINNED ED, then ek by the FIPS 203 modulus check. Generation draws 64 bytes (d ‖ z).",
            "Initiator draws EK (32) then m (32). (ct, SS) = Encaps(ek, m). info = \"mrenzo-pqxdh-v1\" ‖ 0x0A ‖ kind ‖ BE64(keyId) ‖ SHA-256(ek) ‖ SHA-256(ct). SK = HKDF-SHA256(0^32, 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] ‖ SS, info, 32). AD, sid, RK0 as in X3DH v2.",
            "Envelope: x.kem = {\"id\",\"ct\":<b64 1088>} is the last key of x; hdr = … ‖ 0x02 ‖ ik ‖ ed ‖ ek ‖ BE64(spk) ‖ BE64(opk | 2^64-1) ‖ BE64(kem.id) ‖ ct. The MAC covers the flag, the id and the ciphertext.",
            "Negatives: `macFails` = the responder derives another session (the envelope MAC then fails, as for a wrong SPK); the envelope cases give the outcome of respond_and_open on Bob's side.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert("bobKemPrekeys".into(), json!({"oneTime": kem_json(&otk, "pq/bob-kem-otk"), "lastResort": kem_json(&lr, "pq/bob-kem-lr"), "otpsUploadBody": kem_otps_upload_body(std::slice::from_ref(&otk))}));
    v.insert("cases".into(), Value::Object(cases));
    v.insert("negatives".into(), Value::Array(negatives));
    check_or_write("pqxdhV1.json", &Value::Object(v));
}

#[test]
fn ratchet_v3_pq_transcript() {
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let (otk, _) = bob_kem(&b);
    let (mut sa, mut sb) = (PeerSessions::default(), PeerSessions::default());
    let sid = sa.initiate_pq(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), &otk.public(), T0, &mut StreamRng::new("pq/x3dh-1")).unwrap();
    let state = |s: &PeerSessions| -> Value { serde_json::from_str(&s.live().unwrap().session.to_json()).unwrap() };
    let initial = state(&sa);
    assert_eq!(initial["pq"], true);
    assert_eq!(initial["x"]["kem"]["id"], 42);
    let mut steps: Vec<Value> = Vec::new();

    let w1 = sa.encrypt(&chat("a1", "один"), T0 + 1, &mut StreamRng::new("pq/t/a1")).unwrap().to_wire();
    let w2 = sa.encrypt(&chat("a2", "два"), T0 + 2, &mut StreamRng::new("pq/t/a2")).unwrap().to_wire();
    steps.push(json!({"op": "encrypt", "by": "alice", "rngLabel": "pq/t/a1", "nowMs": T0 + 1, "plaintext": chat("a1", "один"), "wire": w1}));
    steps.push(json!({"op": "encrypt", "by": "alice", "rngLabel": "pq/t/a2", "nowMs": T0 + 2, "plaintext": chat("a2", "два"), "wire": w2, "stateAfter": state(&sa)}));
    assert!(Envelope::parse(&w2).unwrap().x.unwrap().kem.is_some(), "x.kem rides on every message while initiating");

    // Bob gets a2 first and builds the session; a1 then matches by `ek`.
    let env2 = Envelope::parse(&w2).unwrap();
    let mut r = StreamRng::new("pq/t/b-recv-a2");
    assert!(matches!(sb.open(&env2, T0 + 10, &mut r), SetOpen::NeedsResponder));
    let out = sb.respond_and_open(&env2, &b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), Some((&otk.seed, otk.kind)), &a.ik.public, &a.ed_pub, T0 + 10, &mut r).unwrap();
    assert!(matches!(&out, SetOpen::Typed { by, .. } if by.created && by.pq));
    steps.push(json!({"op": "respondAndOpen", "by": "bob", "rngLabel": "pq/t/b-recv-a2", "nowMs": T0 + 10, "wire": w2, "kemSeedHex": hx(&otk.seed), "kemKind": "oneTime", "plaintext": chat("a2", "два"), "stateAfter": state(&sb)}));
    assert!(matches!(sb.open(&Envelope::parse(&w1).unwrap(), T0 + 11, &mut StreamRng::new("pq/t/b-recv-a1")), SetOpen::Typed { by, .. } if !by.created));
    assert_eq!(sb.live().unwrap().session.sid, sid);
    assert!(sb.live_is_pq());
    assert_eq!(state(&sb)["pq"], true);
    assert!(state(&sb)["x"].is_null(), "the responder never holds a prekey header");

    let w3 = sb.encrypt(&chat("b1", "ответ"), T0 + 20, &mut StreamRng::new("pq/t/b1")).unwrap().to_wire();
    assert!(Envelope::parse(&w3).unwrap().x.is_none());
    assert!(matches!(sa.open(&Envelope::parse(&w3).unwrap(), T0 + 30, &mut StreamRng::new("pq/t/a-recv-b1")), SetOpen::Typed { by, .. } if by.pq));
    steps.push(json!({"op": "roundTrip", "by": "bob→alice", "rngLabels": ["pq/t/b1", "pq/t/a-recv-b1"], "wire": w3, "plaintext": chat("b1", "ответ"), "aliceStateAfter": state(&sa)}));
    assert!(state(&sa)["x"].is_null(), "x (and kem) dropped after the first inbound message");
    assert_eq!(state(&sa)["pq"], true, "the session stays a hybrid one");

    // At rest: strict both ways.
    let json = sa.live().unwrap().session.to_json();
    assert_eq!(Session::from_json(&json, T0).unwrap(), sa.live().unwrap().session);
    let initiating = initial.to_string();
    let mut no_pq: Value = serde_json::from_str(&initiating).unwrap();
    no_pq.as_object_mut().unwrap().remove("pq");
    assert!(Session::from_json(&no_pq.to_string(), T0).is_none(), "x.kem without pq is not a state");
    assert!(Session::from_json(&initiating, T0).is_some());
    // A classical session's JSON carries neither key.
    let mut classical = PeerSessions::default();
    classical.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), T0, &mut StreamRng::new("v3/x3dh-ek-1")).unwrap();
    let cj = classical.live().unwrap().session.to_json();
    assert!(!cj.contains("\"pq\"") && !cj.contains("\"kem\""));

    let mut v = header_v11(
        "ratchetV3Pq",
        &[
            "A transcript over a hybrid session (pqxdhV1.json case opk+oneTime). The ratchet itself is that of ratchetV3.json; what differs is the root it starts from, the prekey header (x.kem, xflag 2) and two at-rest keys.",
            "Session JSON: \"pq\":true (top level, last key) and x.kem {id, ct} while initiating — each written only when present, so a classical session's JSON is byte for byte what 1.0.0 writes; a 1.0.0 client (strict at rest) drops a hybrid row.",
        ],
    );
    v.insert("keys".into(), json!({"alice": a.json(), "bob": b.json()}));
    v.insert("x3dh".into(), json!({"case": "pqxdhV1.json cases.opk+oneTime", "sidB64": b64(&sid), "initiatorState": initial}));
    v.insert("steps".into(), Value::Array(steps));
    check_or_write("ratchetV3Pq.json", &Value::Object(v));
}

/// No demotion (wire-1.1 §W6.5): an in-flight classical message does not
/// undo a lazy post-quantum upgrade, in any delivery order.
#[test]
fn a_classical_message_in_flight_does_not_undo_the_upgrade() {
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let (otk, _) = bob_kem(&b);
    // Classical S1, confirmed both ways.
    let (mut sa, mut sb) = (PeerSessions::default(), PeerSessions::default());
    let s1 = sa.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(false), T0, &mut StreamRng::new("nd/x1")).unwrap();
    let recv_b = |sb: &mut PeerSessions, wire: &str, kem: bool, now: i64, label: &str| -> SetOpen {
        let env = Envelope::parse(wire).unwrap();
        let mut r = StreamRng::new(label);
        match sb.open(&env, now, &mut r) {
            SetOpen::NeedsResponder => sb
                .respond_and_open(&env, &b.ik, &b.ed_pub, &p.spk, env.x.unwrap().opk.map(|_| &p.opk.private), kem.then_some((&otk.seed, otk.kind)), &a.ik.public, &a.ed_pub, now, &mut r)
                .unwrap(),
            other => other,
        }
    };
    let w = sa.encrypt(&chat("a0", "x"), T0, &mut StreamRng::new("nd/a0")).unwrap().to_wire();
    assert!(matches!(recv_b(&mut sb, &w, false, T0, "nd/b0"), SetOpen::Typed { .. }));
    let w = sb.encrypt(&chat("b0", "x"), T0, &mut StreamRng::new("nd/b0s")).unwrap().to_wire();
    assert!(matches!(sa.open(&Envelope::parse(&w).unwrap(), T0, &mut StreamRng::new("nd/a0r")), SetOpen::Typed { .. }));

    // Bob has a classical message in flight; Alice upgrades lazily.
    let late_from_bob = sb.encrypt(&chat("b-late", "x"), T0 + 1, &mut StreamRng::new("nd/b-late")).unwrap().to_wire();
    let late_from_alice = sa.encrypt(&chat("a-late", "x"), T0 + 1, &mut StreamRng::new("nd/a-late")).unwrap().to_wire();
    let s2 = sa.initiate_pq(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), &otk.public(), T0 + 2, &mut StreamRng::new("nd/x2")).unwrap();
    assert_ne!(s1, s2);
    let upgrade = sa.encrypt(&chat("a-pq", "x"), T0 + 2, &mut StreamRng::new("nd/a-pq")).unwrap().to_wire();

    // Alice: the classical straggler opens under archived S1 and does NOT demote.
    let out = sa.open(&Envelope::parse(&late_from_bob).unwrap(), T0 + 3, &mut StreamRng::new("nd/a-late-r"));
    assert!(matches!(&out, SetOpen::Typed { by, .. } if by.sid == s1 && !by.promoted && !by.pq), "{out:?}");
    assert_eq!(sa.live().unwrap().session.sid, s2, "the hybrid session stays live");
    assert_eq!(sa.entries.iter().find(|e| e.session.sid == s1).unwrap().status, Status::Archived);

    // Bob, both orders of (upgrade, Alice's classical straggler).
    for upgrade_first in [true, false] {
        let mut bob_set = sb.clone();
        let order: [(&str, bool); 2] = if upgrade_first { [(&upgrade, true), (&late_from_alice, false)] } else { [(&late_from_alice, false), (&upgrade, true)] };
        for (i, (wire, kem)) in order.iter().enumerate() {
            let out = recv_b(&mut bob_set, wire, *kem, T0 + 4 + i as i64, &format!("nd/b-{upgrade_first}-{i}"));
            assert!(matches!(out, SetOpen::Typed { .. }), "upgrade_first={upgrade_first} step {i}: {out:?}");
        }
        assert_eq!(bob_set.live().unwrap().session.sid, s2, "upgrade_first={upgrade_first}: Bob ends on the hybrid session");
        assert!(bob_set.live_is_pq());
        // The 1.0.0-shaped entry point follows the same rule.
        let mut legacy = sb.clone();
        let env = Envelope::parse(&late_from_alice).unwrap();
        assert!(matches!(legacy.decrypt(&env, T0 + 9, &mut StreamRng::new("nd/legacy")), SetDecrypt::Opened { promoted: false, .. }));
    }
    // Among sessions of equal kind promotion is unchanged (covered by tests/session_set_property.rs);
    // a HYBRID archived session that decrypts IS promoted over a classical live one.
    let mut alice_back = sa.clone();
    let w = sb.encrypt(&chat("b1", "x"), T0 + 5, &mut StreamRng::new("nd/b1")).unwrap().to_wire(); // Bob still on S1
    assert!(matches!(alice_back.open(&Envelope::parse(&w).unwrap(), T0 + 6, &mut StreamRng::new("nd/a1")), SetOpen::Typed { by, .. } if !by.promoted));
    assert_eq!(alice_back.live().unwrap().session.sid, s2);
}
