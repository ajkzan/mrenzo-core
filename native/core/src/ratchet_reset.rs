//! Signed ratchet reset (03-crypto §5.5): replaces the unsigned WS
//! `ratchet-reset` / `peer-ratchet-reset`. It is bound to the `dh` of the
//! envelope that could not be decrypted, so the peer archives exactly the
//! session that envelope came from — and a second reset for the same `dh`
//! matches nothing once the peer re-initiated (no reset loop).
//!
//! ```text
//! canonical = "mrenzo-ratchet-reset-v2|" + from + "|" + to + "|" + ts + "|" + nonce + "|" + dh
//! sig       = Ed25519(ED_from, UTF-8(canonical))
//! rr        = {"v":2,"ts":…,"nonce":"<b64 16>","dh":"<b64 32>","sig":"<b64 64>"}
//! ```

use serde::Deserialize;

use crate::primitives::{b64, ed25519_sign};
use crate::ratchet::{b64_strict, b64_strict32};
use crate::rng::Rng;

pub const RESET_LABEL: &str = "mrenzo-ratchet-reset-v2";
pub const RESET_VERSION: u64 = 2;
/// Receiver freshness window: `|now − ts| ≤ 10 min`.
pub const RESET_TS_WINDOW_MS: i64 = 10 * 60 * 1000;
pub const RESET_NONCE_BYTES: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetReset {
    pub ts: i64,
    pub nonce: String,
    pub dh: [u8; 32],
    pub sig: [u8; 64],
}

pub fn canonical(from: i64, to: i64, ts: i64, nonce: &str, dh: &[u8; 32]) -> String {
    format!("{RESET_LABEL}|{from}|{to}|{ts}|{nonce}|{}", b64(dh))
}

/// Signs a reset for the envelope ratchet key `dh` (16 random nonce bytes).
pub fn sign(ed_secret64: &[u8; 64], from: i64, to: i64, dh: &[u8; 32], now_ms: i64, rng: &mut dyn Rng) -> RatchetReset {
    let mut n = [0u8; RESET_NONCE_BYTES];
    rng.fill(&mut n);
    let nonce = b64(&n);
    let sig = ed25519_sign(ed_secret64, canonical(from, to, now_ms, &nonce, dh).as_bytes());
    RatchetReset { ts: now_ms, nonce, dh: *dh, sig }
}

impl RatchetReset {
    /// `{"v":2,"ts","nonce","dh","sig"}` (the `rr` object of the frame).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"v\":2,\"ts\":{},\"nonce\":\"{}\",\"dh\":\"{}\",\"sig\":\"{}\"}}",
            self.ts,
            self.nonce,
            b64(&self.dh),
            b64(&self.sig)
        )
    }

    /// Strict parse of the `rr` object text.
    pub fn parse(json: &str) -> Option<RatchetReset> {
        #[derive(Deserialize)]
        struct W {
            v: u64,
            ts: i64,
            nonce: String,
            dh: String,
            sig: String,
        }
        let w: W = serde_json::from_str(json).ok()?;
        if w.v != RESET_VERSION || b64_strict(&w.nonce)?.len() != RESET_NONCE_BYTES {
            return None;
        }
        let sig: [u8; 64] = b64_strict(&w.sig)?.try_into().ok()?;
        Some(RatchetReset { ts: w.ts, nonce: w.nonce, dh: b64_strict32(&w.dh)?, sig })
    }
}

/// Why a reset was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetVerify {
    Ok,
    BadSignature,
    Stale,
}

/// Signature under the sender's pinned ED, then the ts window. The caller
/// checks the nonce against the last ones seen and matches `dh`.
pub fn verify(ed_pub: &[u8; 32], from: i64, to: i64, rr: &RatchetReset, now_ms: i64) -> ResetVerify {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(ed_pub) else { return ResetVerify::BadSignature };
    let sig = ed25519_dalek::Signature::from_bytes(&rr.sig);
    if vk.verify_strict(canonical(from, to, rr.ts, &rr.nonce, &rr.dh).as_bytes(), &sig).is_err() {
        return ResetVerify::BadSignature;
    }
    // `ts` is a wire number: `abs_diff` cannot overflow where `(now − ts).abs()`
    // panics in a debug build and, in release, lets `ts = now − 2^63` wrap to
    // `i64::MIN`, whose `abs()` is negative and passes the window.
    if now_ms.abs_diff(rr.ts) > RESET_TS_WINDOW_MS as u64 {
        return ResetVerify::Stale;
    }
    ResetVerify::Ok
}
