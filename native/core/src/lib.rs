//! mr.enzo protocol core.
//!
//! Protocol v3 (build 349): authenticated X3DH sessions, typed plaintext,
//! signed resets, `sk2` groups, mesh v2, pairing v2 — plus the unchanged
//! byte-compatible pieces of the React Native client's layer (files,
//! identity backup, sealed sender, offline seal, key publishing).
//! The contract is `docs/native/protocol/*.md`; conformance is proven by the
//! golden vectors in `docs/native/vectors/*.json` (see `tests/`).
//!
//! Pure logic only: no networking, no storage, no UI. Randomness is injected
//! through [`rng::Rng`] so tests can replay the exact draws recorded from the
//! TypeScript implementation.

pub mod primitives;
pub mod kem;
pub mod plaintext;
pub mod ratchet;
pub mod ratchet_reset;
pub mod session_set;
pub mod rng;

// Shared JS / tweetnacl semantics (one function per distinct behaviour) and
// the crypto.ts helpers several modules call.
pub mod compat;
pub mod crypto_ts;

// Stage-1 modules (one per golden-vector area; see docs/native/vectors).
pub mod legacy_box;
pub mod key_publish;
pub mod sealed_sender;
pub mod offline_seal;
pub mod sdp_signing;
pub mod files;
pub mod files_stream;
pub mod sender_keys;
pub mod group_chains;
pub mod x3dh;
pub mod mesh_envelope;
pub mod safety_numbers;
pub mod contact_pair;
pub mod identity_backup;
pub mod room_id;
// Contact discovery: RFC 9497 OPRF over ristretto255.
pub mod discovery;

// Wire level 2 (mr.enzo 1.1; wire-1.1.md).
pub mod strict_json;
pub mod caps;
pub mod nearby;
pub mod ptt;
pub mod reactions;
pub mod sticker;
pub mod push_hint;
pub mod mesh_v11;
