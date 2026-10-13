//! Stickers (wire-1.1 §W7.5; 03-crypto §V3.19).
//!
//! A sticker is an ordinary encrypted image attachment (`t:"file"`,
//! `kind:"image"`, `image/png`) whose body carries one soft key:
//!
//! ```text
//! "st":{"v":1,"id":"<64 lowercase hex>","pack":"<24 lowercase hex>"?,"e":"😀"?,"w":512,"h":512}
//! ```
//!
//! A 1.0.0 client ignores `st` and shows the photo. Any violation makes `st`
//! ABSENT — the message is then a plain photo, never a broken message.
//!
//! `id` is the SHA-256 of the CANONICAL PNG bytes. The copy on the wire may
//! carry one private ancillary chunk of zero bytes right before `IEND`, so
//! that the server cannot tell WHICH public sticker a blob is by its exact
//! size:
//!
//! ```text
//! PNG   = 89 50 4E 47 0D 0A 1A 0A ‖ chunk*      chunk = BE32(len) ‖ type[4] ‖ data[len] ‖ CRC32(type ‖ data)
//! pad   = type "mrPd", data = zero bytes; padded size = the smallest multiple of 32 768 ≥ canonical size + 12
//! canonical bytes = the PNG without the "mrPd" chunk
//! ```
//!
//! Nothing here decodes pixels: the walk only follows chunk lengths, inside
//! the buffer. A receiver still checks the real decoded size itself.

use serde_json::{Map, Value};

use crate::primitives::sha256;
use crate::strict_json;

pub const STICKER_VERSION: u64 = 1;
pub const STICKER_MAX_SIDE: u64 = 512;
pub const STICKER_EMOJI_MAX_BYTES: usize = 64;
/// Largest PNG the functions here look at.
pub const PNG_MAX_BYTES: usize = 1024 * 1024;
pub const PAD_BUCKET: usize = 32_768;
pub const PAD_CHUNK_TYPE: [u8; 4] = *b"mrPd";
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
/// len(4) + type(4) + crc(4).
const CHUNK_OVERHEAD: usize = 12;

/// The validated `st` object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerRef {
    /// SHA-256 of the canonical PNG, 64 lowercase hex digits.
    pub id: String,
    /// A public pack this sticker CLAIMS to belong to (bound to nothing: a
    /// receiver shows the pack link only after the fetched manifest lists `id`).
    pub pack: Option<String>,
    pub emoji: Option<String>,
    pub w: u32,
    pub h: u32,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl StickerRef {
    pub fn from_value(v: &Value) -> Option<StickerRef> {
        let o = v.as_object()?;
        if o.get("v").and_then(strict_json::uint) != Some(STICKER_VERSION) {
            return None;
        }
        let id = o.get("id")?.as_str().filter(|s| is_lower_hex(s, 64))?.to_string();
        let pack = match o.get("pack") {
            None => None,
            Some(p) => Some(p.as_str().filter(|s| is_lower_hex(s, 24))?.to_string()),
        };
        let emoji = match o.get("e") {
            None => None,
            Some(e) => Some(
                e.as_str()
                    .filter(|s| (1..=STICKER_EMOJI_MAX_BYTES).contains(&s.len()) && !s.chars().any(char::is_control))?
                    .to_string(),
            ),
        };
        let side = |k: &str| o.get(k).and_then(strict_json::uint).filter(|n| (1..=STICKER_MAX_SIDE).contains(n));
        Some(StickerRef { id, pack, emoji, w: side("w")? as u32, h: side("h")? as u32 })
    }

    /// Key order: v, id, pack, e, w, h.
    pub fn to_value(&self) -> Value {
        let mut o = Map::new();
        o.insert("v".into(), Value::from(STICKER_VERSION));
        o.insert("id".into(), Value::String(self.id.clone()));
        if let Some(p) = &self.pack {
            o.insert("pack".into(), Value::String(p.clone()));
        }
        if let Some(e) = &self.emoji {
            o.insert("e".into(), Value::String(e.clone()));
        }
        o.insert("w".into(), Value::from(self.w));
        o.insert("h".into(), Value::from(self.h));
        Value::Object(o)
    }

    pub fn to_json(&self) -> String {
        self.to_value().to_string()
    }
}

/// The sticker reference of a `file` body (the body object as JSON text);
/// `None` = an ordinary attachment.
pub fn sticker_ref_parse(file_body_json: &str) -> Option<StickerRef> {
    StickerRef::from_value(strict_json::parse_object(file_body_json)?.get("st")?)
}

// ───────────────────────────── PNG padding ─────────────────────────────

fn crc32(parts: &[&[u8]]) -> u32 {
    // Bitwise CRC-32 (IEEE 802.3, reflected): a pad chunk is at most 32 KB
    // and is hashed once per sticker sent, so no table is worth its bytes.
    let mut crc = 0xffff_ffffu32;
    for part in parts {
        for byte in *part {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
            }
        }
    }
    !crc
}

/// What the chunk walk found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PngInfo {
    /// From IHDR (the declared size; decoding may still disagree).
    pub width: u32,
    pub height: u32,
    /// Byte range of the `mrPd` chunk, when there is one.
    pad: Option<(usize, usize)>,
}

/// Walks the chunks of `png`: signature, IHDR first (13 bytes), every length
/// inside the buffer, `IEND` (empty) as the last chunk with nothing after
/// it, at most one `mrPd`, which then sits immediately before `IEND`, holds
/// only zero bytes and carries the right CRC. `None` for anything else, and
/// for a buffer over 1 MiB.
pub fn png_info(png: &[u8]) -> Option<PngInfo> {
    if png.len() > PNG_MAX_BYTES || png.len() < PNG_SIGNATURE.len() || png[..8] != PNG_SIGNATURE {
        return None;
    }
    let mut p = PNG_SIGNATURE.len();
    let mut first = true;
    let (mut width, mut height) = (0u32, 0u32);
    let mut pad: Option<(usize, usize)> = None;
    let mut pad_was_previous = false;
    loop {
        // len(4) ‖ type(4) must fit.
        if png.len() - p < 8 {
            return None;
        }
        let len = u32::from_be_bytes([png[p], png[p + 1], png[p + 2], png[p + 3]]) as usize;
        let kind = [png[p + 4], png[p + 5], png[p + 6], png[p + 7]];
        // data ‖ crc(4) must fit; `len` < 2^32 and the buffer ≤ 1 MiB, so
        // the comparison cannot overflow.
        if len > png.len() - p - 8 || png.len() - p - 8 - len < 4 {
            return None;
        }
        let data = &png[p + 8..p + 8 + len];
        let end = p + CHUNK_OVERHEAD + len;
        if first {
            if kind != *b"IHDR" || len != 13 {
                return None;
            }
            width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            first = false;
        } else if kind == *b"IHDR" {
            return None;
        }
        if kind == *b"IEND" {
            if len != 0 || end != png.len() || (pad.is_some() && !pad_was_previous) {
                return None;
            }
            return Some(PngInfo { width, height, pad });
        }
        pad_was_previous = kind == PAD_CHUNK_TYPE;
        if pad_was_previous {
            let crc = u32::from_be_bytes([png[end - 4], png[end - 3], png[end - 2], png[end - 1]]);
            if pad.is_some() || data.iter().any(|b| *b != 0) || crc != crc32(&[&kind, data]) {
                return None;
            }
            pad = Some((p, end));
        }
        p = end;
    }
}

/// The canonical bytes: `png` without its `mrPd` chunk. `None` for a
/// malformed PNG.
pub fn sticker_strip_padding(png: &[u8]) -> Option<Vec<u8>> {
    let info = png_info(png)?;
    Some(match info.pad {
        None => png.to_vec(),
        Some((start, end)) => [&png[..start], &png[end..]].concat(),
    })
}

/// `hex(SHA-256(canonical bytes))` — what `st.id` must equal.
pub fn sticker_canonical_id(png: &[u8]) -> Option<String> {
    let canonical = sticker_strip_padding(png)?;
    Some(sha256(&canonical).iter().map(|b| format!("{b:02x}")).collect())
}

/// The wire copy: the canonical PNG with one `mrPd` chunk before `IEND` that
/// brings the size to the next multiple of 32 768 at or above `size + 12`.
/// `None` for a malformed PNG or a result over 1 MiB.
pub fn sticker_pad_png(png: &[u8]) -> Option<Vec<u8>> {
    let canonical = sticker_strip_padding(png)?;
    let target = (canonical.len() + CHUNK_OVERHEAD).div_ceil(PAD_BUCKET) * PAD_BUCKET;
    if target > PNG_MAX_BYTES {
        return None;
    }
    let data = vec![0u8; target - canonical.len() - CHUNK_OVERHEAD];
    // `png_info` proved the last 12 bytes are the IEND chunk.
    let iend = canonical.len() - CHUNK_OVERHEAD;
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&canonical[..iend]);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&PAD_CHUNK_TYPE);
    out.extend_from_slice(&data);
    out.extend_from_slice(&crc32(&[&PAD_CHUNK_TYPE, &data]).to_be_bytes());
    out.extend_from_slice(&canonical[iend..]);
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut c = (data.len() as u32).to_be_bytes().to_vec();
        c.extend_from_slice(kind);
        c.extend_from_slice(data);
        c.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
        c
    }

    /// A structurally valid PNG (the pixel data is not decodable; nothing here decodes it).
    pub(crate) fn tiny_png(w: u32, h: u32, idat: &[u8]) -> Vec<u8> {
        let mut ihdr = w.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        [PNG_SIGNATURE.to_vec(), chunk(b"IHDR", &ihdr), chunk(b"IDAT", idat), chunk(b"IEND", &[])].concat()
    }

    #[test]
    fn crc32_is_the_png_crc() {
        // The CRC of an empty IEND chunk is the well-known AE 42 60 82.
        assert_eq!(crc32(&[b"IEND"]), 0xae42_6082);
        assert_eq!(crc32(&[b"123456789"]), 0xcbf4_3926);
    }

    #[test]
    fn pad_strip_and_id() {
        let png = tiny_png(512, 512, &[1, 2, 3, 4, 5]);
        let info = png_info(&png).unwrap();
        assert_eq!((info.width, info.height), (512, 512));
        let padded = sticker_pad_png(&png).unwrap();
        assert_eq!(padded.len(), PAD_BUCKET);
        assert_eq!(sticker_strip_padding(&padded).unwrap(), png);
        assert_eq!(sticker_canonical_id(&padded), sticker_canonical_id(&png));
        assert_eq!(sticker_pad_png(&padded).unwrap(), padded, "padding is idempotent");
        // A canonical size that leaves less than 12 bytes to the bucket goes to the next one.
        let near = tiny_png(1, 1, &vec![0u8; PAD_BUCKET - 57 - 5]);
        assert_eq!(near.len(), PAD_BUCKET - 5);
        assert_eq!(sticker_pad_png(&near).unwrap().len(), 2 * PAD_BUCKET);
    }

    #[test]
    fn malformed_pngs_are_refused() {
        let png = tiny_png(4, 4, &[9; 20]);
        let padded = sticker_pad_png(&png).unwrap();
        let mut cases: Vec<Vec<u8>> = vec![vec![], png[..7].to_vec(), png[..png.len() - 1].to_vec(), [png.clone(), vec![0]].concat()];
        let mut bad_sig = png.clone();
        bad_sig[0] = 0x88;
        cases.push(bad_sig);
        let mut huge_len = png.clone();
        huge_len[8 + 25..8 + 29].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        cases.push(huge_len);
        // Two pad chunks; a pad chunk that is not directly before IEND; non-zero padding.
        let iend = png.len() - 12;
        cases.push([&png[..iend], &chunk(&PAD_CHUNK_TYPE, &[0; 4])[..], &chunk(&PAD_CHUNK_TYPE, &[0; 4])[..], &png[iend..]].concat());
        cases.push([&png[..iend], &chunk(&PAD_CHUNK_TYPE, &[0; 4])[..], &chunk(b"tEXt", b"x")[..], &png[iend..]].concat());
        cases.push([&png[..iend], &chunk(&PAD_CHUNK_TYPE, &[0, 1, 0])[..], &png[iend..]].concat());
        let mut bad_crc = padded.clone();
        let n = bad_crc.len();
        bad_crc[n - 13] ^= 1;
        cases.push(bad_crc);
        cases.push([PNG_SIGNATURE.to_vec(), chunk(b"IDAT", &[1]), chunk(b"IEND", &[])].concat());
        cases.push(vec![0u8; PNG_MAX_BYTES + 1]);
        for (i, c) in cases.iter().enumerate() {
            assert!(png_info(c).is_none(), "case {i}");
            assert!(sticker_canonical_id(c).is_none() && sticker_pad_png(c).is_none() && sticker_strip_padding(c).is_none());
        }
    }

    #[test]
    fn the_reference_is_strict() {
        let id = "a".repeat(64);
        let ok = serde_json::json!({"v":1,"id":id,"pack":"0123456789abcdef01234567","e":"😀","w":512,"h":1,"x":1});
        let st = StickerRef::from_value(&ok).unwrap();
        assert_eq!(StickerRef::from_value(&st.to_value()), Some(st.clone()));
        assert_eq!(st.to_json(), format!(r#"{{"v":1,"id":"{id}","pack":"0123456789abcdef01234567","e":"😀","w":512,"h":1}}"#));
        for (k, v) in [
            ("v", serde_json::json!(2)),
            ("id", serde_json::json!("A".repeat(64))),
            ("id", serde_json::json!("a".repeat(63))),
            ("pack", serde_json::json!("xyz")),
            ("pack", serde_json::Value::Null),
            ("e", serde_json::json!("")),
            ("e", serde_json::json!("a\u{0}")),
            ("w", serde_json::json!(513)),
            ("w", serde_json::json!(0)),
            ("h", serde_json::json!(1.0)),
        ] {
            let mut bad = ok.clone();
            bad[k] = v.clone();
            assert!(StickerRef::from_value(&bad).is_none(), "{k}={v}");
        }
        assert_eq!(sticker_ref_parse(&serde_json::json!({"fileId":"f","kind":"image","st":ok}).to_string()), Some(st));
        assert!(sticker_ref_parse(r#"{"fileId":"f","kind":"image"}"#).is_none());
        assert!(sticker_ref_parse(r#"{"st":{"v":1},"st":{"v":1}}"#).is_none());
    }
}
