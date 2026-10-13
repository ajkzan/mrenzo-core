//! Shared helpers of the protocol-v3 golden vectors (build 349).
//!
//! The v3 vectors are produced by THIS crate from the golden PRNG
//! (`rng::StreamRng`, docs/native/vectors/README.md#prng) — there is no other
//! implementation to take them from. Dual mode, like the RN generator:
//!
//! ```text
//! GOLDEN_WRITE=1 cargo test --test golden_…   # (re)write docs/native/vectors/<file>.json
//! cargo test                                  # verify: regenerate and compare byte for byte
//! ```
//!
//! Never regenerate to make a test pass; regenerate only for an intentional,
//! versioned protocol change and update docs/native/protocol in the same commit.

#![allow(dead_code)]

use mrenzo_core::primitives::{b64, ed25519_keypair, x25519_keypair, KeyPair};
use mrenzo_core::rng::StreamRng;
use serde_json::{json, Value};

pub const T0: i64 = 1_790_000_000_000;

pub struct Ident {
    pub uid: i64,
    pub ik: KeyPair,
    pub ed_secret: [u8; 64],
    pub ed_pub: [u8; 32],
}

impl Ident {
    /// Deterministic identity from the golden PRNG: X25519 draw, then Ed25519 seed.
    pub fn new(label: &str, uid: i64) -> Ident {
        let mut r = StreamRng::new(label);
        let ik = x25519_keypair(&mut r);
        let (ed_secret, ed_pub) = ed25519_keypair(&mut r);
        Ident { uid, ik, ed_secret, ed_pub }
    }

    pub fn json(&self) -> Value {
        json!({
            "uid": self.uid,
            "x25519PrivB64": b64(&self.ik.private),
            "x25519PubB64": b64(&self.ik.public),
            "ed25519SecretB64": b64(&self.ed_secret),
            "ed25519PubB64": b64(&self.ed_pub),
        })
    }
}

pub fn alice() -> Ident {
    Ident::new("v3/alice", 1001)
}

pub fn bob() -> Ident {
    Ident::new("v3/bob", 1002)
}

pub fn carol() -> Ident {
    Ident::new("v3/carol", 1003)
}

pub fn header(area: &str, notes: &[&str]) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("area".into(), json!(area));
    m.insert("schema".into(), json!(1));
    m.insert("generator".into(), json!("native/core/tests (GOLDEN_WRITE=1 cargo test) — protocol v3, build 349"));
    m.insert(
        "encodings".into(),
        json!("*B64 = RFC 4648 §4 standard base64 WITH padding, canonical trailing bits; *Hex = lowercase hex; wire / *Json = exact UTF-8 text; randomness = the golden PRNG stream (README.md#prng) under the recorded label"),
    );
    m.insert("notes".into(), json!(notes));
    m
}

fn path(name: &str) -> String {
    format!("{}/../../docs/native/vectors/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Write (GOLDEN_WRITE=1) or verify the vector file `name`.
pub fn check_or_write(name: &str, value: &Value) {
    let text = serde_json::to_string_pretty(value).unwrap() + "\n";
    if std::env::var("GOLDEN_WRITE").as_deref() == Ok("1") {
        std::fs::write(path(name), &text).unwrap();
        return;
    }
    let stored = std::fs::read_to_string(path(name)).unwrap_or_else(|_| panic!("{name} missing: run with GOLDEN_WRITE=1"));
    let stored: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(&stored, value, "{name}: regenerated vector differs from the committed file");
}

pub fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

/// Header of a wire-level-2 vector file (mr.enzo 1.1; wire-1.1.md).
pub fn header_v11(area: &str, notes: &[&str]) -> serde_json::Map<String, Value> {
    let mut m = header(area, notes);
    m.insert("generator".into(), json!("native/core/tests (GOLDEN_WRITE=1 cargo test) — wire level 2, mr.enzo 1.1"));
    m.insert("contract".into(), json!("wire-1.1.md (design record, not published); normative text: docs/native/protocol/03-crypto.md V3.16-V3.21 and 04-mesh.md"));
    m
}

pub fn hx(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Bob's prekeys of the v3 vectors (x3dhV2.json): the SPK from "v3/bob-spk"
/// (id 17) and the OPK from "v3/bob-opk" (id 118).
pub struct Prekeys {
    pub spk: KeyPair,
    pub spk_id: i64,
    pub spk_sig: [u8; 64],
    pub opk: KeyPair,
    pub opk_id: i64,
}

pub fn prekeys(owner: &Ident, spk_label: &str, opk_label: &str) -> Prekeys {
    use mrenzo_core::ratchet::{b64_strict, b64_strict32};
    let g = mrenzo_core::x3dh::generate_signed_pre_key_v2(&owner.ed_secret, 17, &mut StreamRng::new(spk_label));
    Prekeys {
        spk: KeyPair { public: b64_strict32(&g.pub_key).unwrap(), private: b64_strict32(&g.priv_key).unwrap() },
        spk_id: 17,
        spk_sig: b64_strict(&g.signature).unwrap().try_into().unwrap(),
        opk: x25519_keypair(&mut StreamRng::new(opk_label)),
        opk_id: 118,
    }
}

impl Prekeys {
    pub fn bundle(&self, with_opk: bool) -> mrenzo_core::x3dh::BundleV2 {
        mrenzo_core::x3dh::BundleV2 {
            spk_id: self.spk_id,
            spk_pub: self.spk.public,
            spk_sig: self.spk_sig,
            opk: with_opk.then_some((self.opk_id, self.opk.public)),
        }
    }
}

/// Two parties with an established classical session (Alice initiated with
/// an OPK, Bob answered once), each side keeping an aux — the starting point
/// of most level-2 vectors. Deterministic: every draw comes from `label`.
pub struct Linked {
    pub a: Ident,
    pub b: Ident,
    pub p: Prekeys,
    pub sa: mrenzo_core::session_set::PeerSessions,
    pub sb: mrenzo_core::session_set::PeerSessions,
}

pub fn linked(label: &str) -> Linked {
    use mrenzo_core::plaintext::TypedPlaintext;
    use mrenzo_core::ratchet::Envelope;
    use mrenzo_core::session_set::{PeerSessions, SetOpen};
    let (a, b) = (alice(), bob());
    let p = prekeys(&b, "v3/bob-spk", "v3/bob-opk");
    let mut sa = PeerSessions { aux_enabled: true, ..Default::default() };
    let mut sb = PeerSessions { aux_enabled: true, ..Default::default() };
    sa.initiate(&a.ik, &a.ed_pub, &b.ik.public, &b.ed_pub, &p.bundle(true), T0, &mut StreamRng::new(&format!("{label}/x3dh"))).unwrap();
    let hello = TypedPlaintext::Hello { id: "h-a".into() }.to_json();
    let w = sa.encrypt(&hello, T0, &mut StreamRng::new(&format!("{label}/a-hello"))).unwrap();
    let env = Envelope::parse(&w.to_wire()).unwrap();
    let mut r = StreamRng::new(&format!("{label}/b-recv"));
    assert!(matches!(sb.open(&env, T0, &mut r), SetOpen::NeedsResponder));
    let out = sb.respond_and_open(&env, &b.ik, &b.ed_pub, &p.spk, Some(&p.opk.private), None, &a.ik.public, &a.ed_pub, T0, &mut r).unwrap();
    assert!(matches!(out, SetOpen::Typed { .. }));
    let reply = TypedPlaintext::Hello { id: "h-b".into() }.to_json();
    let w = sb.encrypt(&reply, T0, &mut StreamRng::new(&format!("{label}/b-hello"))).unwrap();
    let out = sa.open(&Envelope::parse(&w.to_wire()).unwrap(), T0, &mut StreamRng::new(&format!("{label}/a-recv")));
    assert!(matches!(out, SetOpen::Typed { .. }));
    Linked { a, b, p, sa, sb }
}
