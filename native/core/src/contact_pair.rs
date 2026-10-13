//! First-contact pairing v2 (03-crypto §12, build 349).
//! Conformance: docs/native/vectors/contactPairV2.json (tests/golden_contact_pair_v2.rs).
//!
//! Two shapes behind the one prefix `mrenzo://pair/<base64url(JSON), no padding>`:
//!
//! - **Link** `{"v":2,"uid":N,"username"?:"…"}` — carries NO keys. Opening it
//!   is an online lookup of that uid (directory pin); it never pins, never
//!   verifies, never overwrites anything.
//! - **Scan** (in-app QR only) `{"v":2,"uid","username"?,"displayName"?,"ipk","spk","seed","ts","sig"}`
//!   with `sig = Ed25519(spk-secret, UTF-8("mrenzo-pair-v2|" + uid + "|" + ipk + "|" + spk + "|" + seed + "|" + ts))`
//!   (base64 strings as they appear in the JSON). A scan proves the presenter
//!   holds the signing key it shows — not that the uid is theirs: the
//!   receiver still reconciles it with the directory before any online use.
//!
//! Anything else (v:1, unknown keys, a link with keys, a scan with a bad
//! signature, non-canonical base64) is invalid.

use serde::{Deserialize, Serialize};

use crate::primitives::{b64, ed25519_sign};
use crate::ratchet::{b64_strict, b64_strict32};

pub const PAIR_VERSION: u64 = 2;
pub const PAIR_URL_PREFIX: &str = "mrenzo://pair/";
pub const PAIR_SIG_LABEL: &str = "mrenzo-pair-v2";
const MAX_SAFE: u64 = (1u64 << 53) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairLink {
    pub uid: i64,
    pub username: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairScan {
    pub uid: i64,
    pub username: Option<String>,
    pub display_name: Option<String>,
    /// base64 X25519 identity.
    pub ipk: String,
    /// base64 Ed25519 signing key.
    pub spk: String,
    /// base64 32 random bytes (pair safety number input).
    pub seed: String,
    pub ts: i64,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairPayload {
    Link(PairLink),
    Scan(PairScan),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Wire {
    v: u64,
    uid: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

pub fn scan_signed_text(uid: i64, ipk: &str, spk: &str, seed: &str, ts: i64) -> String {
    format!("{PAIR_SIG_LABEL}|{uid}|{ipk}|{spk}|{seed}|{ts}")
}

/// Our scan payload: `ed_secret64` is our signing secret (its public half is `spk`).
pub fn sign_scan(
    uid: i64,
    username: Option<String>,
    display_name: Option<String>,
    ipk: [u8; 32],
    ed_secret64: &[u8; 64],
    seed: [u8; 32],
    ts: i64,
) -> PairScan {
    let spk = b64(&ed_secret64[32..]);
    let (ipk, seed) = (b64(&ipk), b64(&seed));
    let sig = b64(&ed25519_sign(ed_secret64, scan_signed_text(uid, &ipk, &spk, &seed, ts).as_bytes()));
    PairScan { uid, username, display_name, ipk, spk, seed, ts, sig }
}

pub fn verify_scan(scan: &PairScan) -> bool {
    let (Some(spk), Some(sig)) = (b64_strict32(&scan.spk), b64_strict(&scan.sig)) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&spk) else { return false };
    vk.verify_strict(
        scan_signed_text(scan.uid, &scan.ipk, &scan.spk, &scan.seed, scan.ts).as_bytes(),
        &ed25519_dalek::Signature::from_bytes(&sig),
    )
    .is_ok()
}

fn b64url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(s).ok()
}

pub fn encode_link(link: &PairLink) -> String {
    let w = Wire {
        v: PAIR_VERSION,
        uid: link.uid as u64,
        username: link.username.clone(),
        display_name: None,
        ipk: None,
        spk: None,
        seed: None,
        ts: None,
        sig: None,
    };
    format!("{PAIR_URL_PREFIX}{}", b64url(serde_json::to_string(&w).expect("link serializes").as_bytes()))
}

pub fn encode_scan(scan: &PairScan) -> String {
    let w = Wire {
        v: PAIR_VERSION,
        uid: scan.uid as u64,
        username: scan.username.clone(),
        display_name: scan.display_name.clone(),
        ipk: Some(scan.ipk.clone()),
        spk: Some(scan.spk.clone()),
        seed: Some(scan.seed.clone()),
        ts: Some(scan.ts as u64),
        sig: Some(scan.sig.clone()),
    };
    format!("{PAIR_URL_PREFIX}{}", b64url(serde_json::to_string(&w).expect("scan serializes").as_bytes()))
}

/// Strict decode of `mrenzo://pair/<body>`. A scan must verify.
pub fn decode_pair_url(url: &str) -> Option<PairPayload> {
    let body = url.strip_prefix(PAIR_URL_PREFIX)?;
    let json = b64url_decode(body)?;
    let w: Wire = serde_json::from_slice(&json).ok()?;
    if w.v != PAIR_VERSION || w.uid == 0 || w.uid > MAX_SAFE {
        return None;
    }
    let uid = w.uid as i64;
    match (w.ipk, w.spk, w.seed, w.ts, w.sig) {
        (None, None, None, None, None) => {
            if w.display_name.is_some() {
                return None;
            }
            Some(PairPayload::Link(PairLink { uid, username: w.username }))
        }
        (Some(ipk), Some(spk), Some(seed), Some(ts), Some(sig)) => {
            if ts > MAX_SAFE || b64_strict32(&ipk).is_none() || b64_strict32(&seed).is_none() {
                return None;
            }
            let scan = PairScan { uid, username: w.username, display_name: w.display_name, ipk, spk, seed, ts: ts as i64, sig };
            verify_scan(&scan).then_some(PairPayload::Scan(scan))
        }
        _ => None,
    }
}
