//! Group-room ids (`utils/roomId.ts`, server `validRoomID`).
//!
//! The server accepts only `^[a-z0-9]{3}-[a-z0-9]{3}-[a-z0-9]{3}-[a-z0-9]{3}$`
//! (`handleJoin`, `GET /api/room-check`). RN mints ids client-side from
//! `secureUUID()`: the first 12 bytes of the UUID hex (version/variant bits
//! included — byte 6 is always `0x4?`, byte 8 `0b10??????`), each folded
//! `% 36` into `a-z0-9`. Reproduced draw-for-draw so fixed RNG bytes give the
//! same id on RN, iOS and Android.

use crate::primitives::secure_uuid;
use crate::rng::Rng;

const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn format_12(chars: &str) -> String {
    format!("{}-{}-{}-{}", &chars[0..3], &chars[3..6], &chars[6..9], &chars[9..12])
}

/// `generateRoomId()`: one 16-byte draw (via `secureUUID`).
pub fn generate_room_id(rng: &mut dyn Rng) -> String {
    let hex: String = secure_uuid(rng).chars().filter(|c| *c != '-').collect();
    let out: String = (0..12)
        .map(|i| {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("uuid hex");
            ALPHABET[(byte as usize) % ALPHABET.len()] as char
        })
        .collect();
    format_12(&out)
}

/// `normalizeRoomId(raw)`: trim (JS whitespace), lowercase, drop every `-`;
/// exactly 12 `[a-z0-9]` remain → canonical `xxx-xxx-xxx-xxx`, else `None`.
pub fn normalize_room_id(raw: &str) -> Option<String> {
    let cleaned: String = raw.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}').to_lowercase().chars().filter(|c| *c != '-').collect();
    if cleaned.len() != 12 || !cleaned.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return None;
    }
    // All ASCII here, so byte slicing is safe.
    Some(format_12(&cleaned))
}

/// The server's `validRoomID` (and RN's room-invite check, App.tsx:722).
pub fn is_valid_room_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 15
        && b.iter().enumerate().all(|(i, &c)| {
            if i % 4 == 3 {
                c == b'-'
            } else {
                c.is_ascii_lowercase() || c.is_ascii_digit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_shapes() {
        assert!(is_valid_room_id("abc-def-123-xyz"));
        assert!(!is_valid_room_id("ABC-def-123-xyz"));
        assert!(!is_valid_room_id("abcdef123xyz"));
        assert!(!is_valid_room_id("abc-def-123-xyz-"));
        assert!(!is_valid_room_id("abc_def-123-xyz"));
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_room_id(" ABC-DEF-123-XYZ ").as_deref(), Some("abc-def-123-xyz"));
        assert_eq!(normalize_room_id("abcdef123xyz").as_deref(), Some("abc-def-123-xyz"));
        assert_eq!(normalize_room_id("abcdef123xy"), None);
        assert_eq!(normalize_room_id("abcdef123xyé"), None);
    }
}
