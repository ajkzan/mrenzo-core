//! The 1.0.0 core, frozen: `plaintext.rs`, `ratchet.rs`, `x3dh.rs`,
//! `session_set.rs`, `mesh_envelope.rs`, `files.rs` (the attachment parser a
//! sticker must degrade through) — and everything of the crate they call
//! into: `crypto_ts.rs` and the whole `compat/` layer — exactly as they are
//! at `712e1dcc` (build 353, live in the App Store). They were copied from
//! `712e1dcc:native/core/src/<file>` of the closed-source repository by a script
//! that is not part of this export; the only change is the rewrite of the `crate::` paths:
//!
//! ```text
//! crate::<one of the files above>   →  crate::legacy353::<the same>
//! crate::primitives, crate::rng     →  mrenzo_core::primitives, mrenzo_core::rng
//! ```
//!
//! So the frozen code depends on nothing a later package edits. `compat/` is
//! vendored for that reason: the live `compat/` has been made panic-free
//! since (wire-1.1 §W9), and a behaviour change in a number formatter or a
//! JSON quoter would otherwise move the «353» side of every compatibility
//! test with it, unnoticed. The two modules still taken from the live crate —
//! the primitives (X25519, secretbox, HKDF, Ed25519) and the golden PRNG,
//! which the tests share between the two cores — are pinned to their
//! `712e1dcc` bytes by [`frozen`] below, together with every vendored file.
//!
//! `tests/compat_353.rs` feeds 1.1 output to these functions: that is the
//! compatibility proof of wire-1.1 §W10. Never edit a file here; if
//! `primitives.rs` or `rng.rs` must change, vendor the 1.0.0 file first
//! (add it to the vendored set, drop it from `LIVE` below).
//!
//! The test crate that includes this module declares it at its root
//! (`mod legacy353;`) — the rewritten paths start there.

#![allow(dead_code, unused_imports, clippy::all)]

pub mod compat;
pub mod crypto_ts;
pub mod files;
pub mod mesh_envelope;
pub mod plaintext;
pub mod ratchet;
pub mod session_set;
pub mod x3dh;

/// The premise of the proof, checked instead of stated: every file the
/// «353» side of a compatibility test executes is byte for byte the App
/// Store commit.
#[cfg(test)]
mod frozen {
    use mrenzo_core::primitives::sha256;

    /// (path under `native/core/src` at `712e1dcc`, the vendored text,
    /// SHA-256 of `git show 712e1dcc:native/core/src/<path>`).
    const VENDORED: [(&str, &str, &str); 15] = [
        ("plaintext.rs", include_str!("plaintext.rs"), "351b07512a62f2d61b47a553fbc8ed927db769681d91988105218007ba8bbc25"),
        ("ratchet.rs", include_str!("ratchet.rs"), "b919a22bf2aabb6e1671d60658593db61ad535810ef69b06f70b9c2a9b31126b"),
        ("x3dh.rs", include_str!("x3dh.rs"), "41ff2a794edb1492f3c6a0d77354a0656b5c888ee9849ff0997c6dc1947eeca2"),
        ("session_set.rs", include_str!("session_set.rs"), "563850d5fb0bf1f003cd39a7d2d444f3fdcec4e3371f049263ad93101772465f"),
        ("mesh_envelope.rs", include_str!("mesh_envelope.rs"), "2d49e9f5ae9a948cba7753edd3b08f9e8e0135df733d1a1b8f1e91bfc23ab65e"),
        ("files.rs", include_str!("files.rs"), "3fa74a037d904fcc55240ed689aee052853316c2dd9b565737129d654b744e5d"),
        ("crypto_ts.rs", include_str!("crypto_ts.rs"), "66cd85802b8aa8ccb374343d0b1a7cbd2ccee3307518d911fb38c4cbb5000274"),
        ("compat/mod.rs", include_str!("compat/mod.rs"), "782110b0e2df9697cf3a1ee00f82b38accb318420ab058686338c4d19427efd4"),
        ("compat/b64.rs", include_str!("compat/b64.rs"), "5d496c4652f4fcd2edd6712635d167bb73b5435b57f46bef0483ed6d3729f8c4"),
        ("compat/ed25519.rs", include_str!("compat/ed25519.rs"), "579c288562aa542d953968f66a4d3e356e90443b9d701f82b7b5134db44fcf41"),
        ("compat/js_number.rs", include_str!("compat/js_number.rs"), "c2903ab044daac478acad203c4be3eb325325045e5701974db5c088e815e3f54"),
        ("compat/js_string.rs", include_str!("compat/js_string.rs"), "c7ac6bee9e25033838dc06108f0c1a358ebb6a62a4429b399f8f0b012918a25f"),
        ("compat/js_value.rs", include_str!("compat/js_value.rs"), "0a74a520e3123e2d08dea459e1e49f758371984cc8fad6ccdf3b11324ee30332"),
        ("compat/json.rs", include_str!("compat/json.rs"), "7ca424e09786581e6b82708250baa6a13b3af35ac2dce3adf3006d394b659c87"),
        ("compat/utf8.rs", include_str!("compat/utf8.rs"), "94025c1992eba388643eaa5faefe62888a347f3cde67614ab278162023b20f2e"),
    ];

    /// The modules the frozen code takes from the LIVE crate: they must still
    /// be the `712e1dcc` files.
    const LIVE: [(&str, &str, &str); 2] = [
        ("primitives.rs", include_str!("../../src/primitives.rs"), "7a2a1c60a211dd1129b5270ef3a166aca320c8b647cf183ed3e24fce894c9d22"),
        ("rng.rs", include_str!("../../src/rng.rs"), "1fc0cbd9345dd4235eef6d4cc8ae1c3ea16e827d7366f31d350383aadfc23f64"),
    ];

    #[test]
    fn the_frozen_core_is_the_app_store_commit() {
        for (path, vendored, want) in VENDORED {
            // Undo the path rewrite made when the files were copied. Neither replacement string occurs in a 1.0.0 file.
            let original = vendored.replace("crate::legacy353::", "crate::").replace("mrenzo_core::", "crate::");
            assert_eq!(hex::encode(sha256(original.as_bytes())), want, "tests/legacy353/{path} is not 712e1dcc:native/core/src/{path} — never edit a vendored file");
            // No path back into today's crate except the two pinned modules.
            for (at, _) in vendored.match_indices("mrenzo_core::") {
                let rest = &vendored[at + "mrenzo_core::".len()..];
                assert!(rest.starts_with("primitives") || rest.starts_with("rng"), "tests/legacy353/{path} calls into the live crate: {}", &rest[..rest.len().min(40)]);
            }
        }
        for (path, live, want) in LIVE {
            assert_eq!(
                hex::encode(sha256(live.as_bytes())),
                want,
                "src/{path} changed since 712e1dcc, and the frozen 1.0.0 core calls it: vendor the 1.0.0 file into tests/legacy353/ before changing it"
            );
        }
    }
}
