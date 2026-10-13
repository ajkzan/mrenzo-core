# mrenzo-core

> **Licence note.** This is published for review under the PolyForm Strict License 1.0.0 (see the root [LICENSE](../../LICENSE)): for non-commercial purposes you may read it and run `cargo test` unchanged; you may not distribute it, change it or build new works on it. The commands that write files (`GOLDEN_WRITE`) and the rules about changing code and vectors are the maintainer's working rules, kept as the record of how the code is developed. They are not an invitation to change anything.

The protocol core of mr.enzo, written in Rust: the cryptographic constructions, the wire formats and the pure protocol logic (no networking, no storage, no UI). The iOS app and a future Android app call it through a binding layer that is not part of this repository.

The core started as a **byte-compatible port** of the protocol layer of the earlier React Native client (builds up to 348, before the App Store version 1.0.0), and has since grown protocol v3 and wire level 2 (mr.enzo 1.1). The contract is the documents in [docs/native/protocol](../../docs/native/protocol). Conformance is shown by the golden vectors in [docs/native/vectors](../../docs/native/vectors) (index: [docs/native/vectors/README.md](../../docs/native/vectors/README.md)): the RN-era vectors were produced by the real TypeScript code of that React Native client (build 324); the v3 and level-2 vectors are produced by this crate itself from a deterministic PRNG, and the tests regenerate them and compare byte for byte.

Read this first if you came from the root README: references like `wire-1.1 §W9` in the sources and documents point to the internal design record of wire level 2, which is not published. The normative text for everything it specifies is in `03-crypto.md` (§V3.16–§V3.21) and `04-mesh.md` («Mesh at level 2»). Only `03-crypto.md` is part of this first publication; the other protocol documents (01, 02 and 04) will follow, and references to them are kept so that the text stays exact. Citations like `api.ts:123` or `MessagePipeline.swift:384` name files of the closed-source apps; they do not resolve here.

## Build and test

```bash
cd native/core
cargo test --locked          # the whole suite
cargo test --locked --release   # same tests, faster
```

`Cargo.lock` is committed. The crate declares `rust-version = "1.85"` (raised from 1.84 for the `libcrux-ml-kem` dependency tree); `.cargo/config.toml` enables the MSRV-aware resolver. The root README records the result of the last run and the Rust version it used.

## Wire level 2 (mr.enzo 1.1)

The normative text is in `03-crypto.md` (§V3.16–§V3.21) and `04-mesh.md` («Mesh at level 2»; not part of this first publication, it will follow). The 1.0.0 build (353) is the level-1 reference: nothing below may put a plaintext with a new `t` in front of a 1.0.0 ratchet.

| Module | What it adds | Vectors | Tests |
|---|---|---|---|
| `plaintext` | level-2 kinds (`react`, `nearby`, `ptt`), soft keys (`caps`, `alt`, `p`, `nearby`), `classify` — an authenticated plaintext this build does not understand is `Unsupported`, never a failure; the `ctl` and `ptt-start` frame builders | `typedV11.json` | `golden_typed_v11` |
| `ratchet`, `session_set` | `open` (authenticate first, classify after), `Stale`, the per-peer aux (retired ratchet keys, the lossy-run counter), the skip budget, `x.kem` / `xflag 2`, no demotion of a hybrid session | `unsupportedV11.json`, `ratchetV3Pq.json` | `golden_typed_v11`, `golden_pq`, `session_set_property` |
| `x3dh`, `kem` | hybrid session setup: ML-KEM-768 + X25519, signed KEM prekeys, the KDF info that binds algorithm, kind, id, key and ciphertext. `kem.rs` calls the formally verified PORTABLE instantiation of `libcrux-ml-kem` (pinned `=0.0.10`) on every target | `pqxdhV1.json`, `mlkem768Kat.json` | `golden_pq` |
| `caps` | the capability object and the signed statement | `capsV11.json` | `golden_typed_v11` |
| `nearby`, `ptt`, `reactions`, `sticker`, `push_hint` | the token-exchange object; the `P1` chunk and `PttReceiver`; the last-writer-wins register, the post reaction key and the padding that makes a reaction's length independent of its emoji; the `st` reference and the PNG pad chunk; the push hint for the Notification Service Extension | `pttV1.json`, `reactGroupV1.json`, `stickerV1.json`, `pushHintV1.json` | `golden_features_v11` |
| `mesh_v11` | the strict frame check, `seenKey`, the forward rule (a relay writes only `hops`), the seen set (relay and capsule upgrades; per lane — radio — it keeps the `hops` the node relayed with, for the node the verified capsule, and it builds every emission from them), named kinds `ptt` / `ctl`, the blind ACK, the courier capsule (signed by the sender, checked by every node and at every door of the 1.0.0-shaped API), the link hello and the per-link budgets | `meshV11.json`, `meshCourierV1.json` | `golden_mesh_v11` |
| `strict_json` | duplicate keys at any depth, exact integers, canonical base64 — for every NEW field | — | unit tests |

Extra test binaries for the level as a whole:

- `tests/compat_353.rs` + `tests/legacy353/` — the 1.0.0 core with everything it calls (`compat/`, `crypto_ts`, `files`), copied byte for byte from commit `712e1dcc` of the closed-source repository (the App Store build 353) and fed with what this core produces. `legacy353::frozen` checks every copied file against the SHA-256 of its `712e1dcc` blob and pins `primitives.rs` / `rng.rs`. Do not «fix» the copied files: they are the App Store build. If `primitives.rs` or `rng.rs` has to change, copy the 1.0.0 file first — `frozen` fails until then. (The script that made the copy needs the closed-source git history and is not part of this repository.)
- `tests/hostile_input.rs` — a deterministic mutation corpus over the parsers that file lists (41 526 cases on a 512 KB stack): no panic, no forgery. It found one real defect (a stack overflow in the sealed-sender JSON reader at nesting depth 512; the limit is 64 now). `seen_set_orderings` is exhaustive instead: every sequence of up to four copies of one mesh frame on one radio (22 620) and of up to three over two radios (112 944) through the seen set.
- `tests/independent_check.py` — not a cargo test: a second implementation of the level-2 constructions in Python (libsodium, `hashlib`, OpenSSL's ML-KEM-768) that recomputes the vectors from the formulas written in the documents. Run it by hand: `python3 tests/independent_check.py` (needs PyNaCl and OpenSSL ≥ 3.5; it reads the formulas from documents that include the unpublished `wire-1.1` and `04-mesh.md` (which will follow), so some of its comments point to files that are not here). It prints how many checks it ran and how many agree; the root README says whether it was part of the last recorded run.

Rules added with the level: no panic reachable from received bytes (no unchecked index, `unwrap` on data, wire-driven loop or `as` narrowing); new fields are strict, soft keys are lenient (malformed = absent); the existing vector files never change.

## Modules of level 1 and protocol v3

| Module | What it is |
|---|---|
| `primitives` | X25519 (raw unclamped private keys), XSalsa20-Poly1305 secretbox in the NaCl layout, HKDF-SHA256 with a zero salt, Ed25519, base64 — byte-compatible with tweetnacl as the RN client used it |
| `rng` | injectable randomness (`OsRng` in production) and the deterministic golden-vector stream |
| `x3dh`, `session_set`, `ratchet`, `ratchet_reset` | X3DH v2 prekeys and sessions, the per-peer session state machine, the 1:1 Double Ratchet of protocol v3 (MAC over AD ‖ header ‖ ct), the signed ratchet reset |
| `plaintext` | the typed plaintext inside the box — the only thing a receiver renders or acts on |
| `sealed_sender`, `offline_seal` | the sealed-sender envelope and server certificate; the server-sealed `OSB1:` offline blobs |
| `key_publish`, `legacy_box`, `crypto_ts` | the key-publish self-signature; the pre-ratchet static box (still live for stories); the shared `signPayload` / `verifyPayload` |
| `sender_keys`, `group_chains` | group Sender Keys: the build-324 primitives and the build-325 chain semantics |
| `sdp_signing` | call DTLS-fingerprint signing, payload v2 |
| `files`, `files_stream` | attachment encryption and the file envelope; the streaming variant, byte-identical |
| `mesh_envelope` | the offline-mesh envelope, wire v2 |
| `safety_numbers`, `contact_pair`, `discovery`, `room_id`, `identity_backup` | safety numbers v2; the pairing link and QR payload; contact discovery over an OPRF (RFC 9497) without uploading the address book; group-room ids; the sealed local identity backup slot |

## Compat layer

The ports need a handful of JavaScript and tweetnacl behaviours that the Rust ecosystem does not provide as-is. `src/compat` holds **one implementation per distinct behaviour**, and every module calls it instead of carrying a private copy. The engine contract is the one the RN app shipped: Hermes 0.14.1, tweetnacl 1.0.3, tweetnacl-util 0.15.1.

| Module | What it models |
|---|---|
| `compat::b64` | tweetnacl-util `decodeBase64`: the `validateBase64` regex, then `atob`, which **discards** non-zero trailing bits (`"AB=="` → `[0x00]`). UTF-8 and UTF-16 inputs. |
| `compat::ed25519` | `nacl.sign.detached.verify` (S used unreduced, so S + k·L verifies; size throws in tweetnacl's order), `nacl.sign.detached` (hashes the **stored** public half `sk[32..64]`), `keyPair.fromSecretKey`, S mod L. |
| `compat::js_number` | `Number::toString` (ties go to the even digit), its JSON form, `StringToNumber` (correctly rounded `0x`/`0o`/`0b`), the StrDecimalLiteral grammar, ToInt32, ToUint32, `BigInt(…)` stored as 64 bits. |
| `compat::js_string` | JS whitespace (= RegExp `\s`), `trim`, UTF-16 code-unit order. |
| `compat::js_value` | ToBoolean, ToString and ToNumber of a `JSON.parse` result, including the TypeError for an object with its own `toString` key. |
| `compat::json` | `QuoteJSONString` (UTF-8 and UTF-16), `[[OwnPropertyKeys]]` order, `JSON.stringify` of a parsed value, and Hermes' `JSON.parse` (strtod number lexer, throws once a value sits at depth 512, UTF-16 strings) as a top-level-object scanner. |
| `compat::utf8` | tweetnacl-util `encodeUTF8` (strict) and WHATWG `TextDecoder` (lossy, strips one BOM). |
| `crypto_ts` | `crypto.ts` `signPayload` / `verifyPayload`, shared by `key_publish`, `sdp_signing` and `mesh_envelope`. |

Rules of the layer:

- **Different behaviours stay different functions.** Some modules historically shipped an approximation that their tests pin. Each approximation is a separately named function documented as a divergence, never merged into the faithful one:
  - `number_to_string_ties_up` rounds an exact decimal tie up (`mesh_envelope`, `sender_keys`, `x3dh`).
  - `string_to_number_f64_radix` (`sealed_sender`) and `string_to_number_u128_radix` (`sender_keys`, `x3dh`) double-round long `0x…` literals.
  - `to_string_lenient*` does not model the own-`toString` TypeError (`sealed_sender`, `x3dh`, `sender_keys`).
  - `crypto_ts::sign_payload_rfc8032` re-derives the public half (`sdp_signing`, `mesh_envelope`).

  Switching a caller to the faithful function is a behaviour change: it needs its own failing test first. The V8-grammar JSON parsers in `sealed_sender`, `files` and `contact_pair`, and the serde parses in `offline_seal`, `sender_keys` and `x3dh`, are also documented divergences from Hermes.
- **The strict primitives are not RN behaviour.** `primitives::b64d`/`b64d32` (strict RFC 4648), `ed25519_verify` (rejects S ≥ L) and `ed25519_sign` (re-derives the public half) are for fixtures and for bytes this crate produced itself. A source lint (`compat::tests::strict_primitives_stay_out_of_production_code`) keeps `b64d` and `ed25519_verify` out of production code.
- **The ratchet receives what RN receives.** Base64 fields are decoded with `compat::b64`, `RatchetEnvelope::from_wire` is Hermes `JSON.parse` plus the message-pipeline gate of the RN client, and at-rest import uses JS truthiness and ToString. These were live divergences: a relay could flip the MAC-free trailing bits of `ct` or `dh` and make a native client drop a message RN shows.

## Rules of the code

The first two rules were written while the React Native client was in use. The App Store releases are native; the rules are kept because the frozen 1.0.0 core and data carried over from those builds must keep working.

- **Port quirks faithfully.** The RN client has protocol quirks, for example `initAsSender` ignores the sender's identity key and a failed decrypt still consumes randomness. They are reproduced on purpose, because fixing them here breaks interop with RN clients in the field. Protocol fixes ship later as an explicitly versioned protocol change.
- **Be as lenient as RN on receive.** A native client that rejects what RN accepts silently drops messages in the field. Use `compat`, never a stricter Rust default.
- **Randomness is injected** through `rng::Rng`. Production uses `OsRng`. Tests use `ReplayRng`, which replays the draws recorded from TypeScript and asserts the same sizes, in the same order, fully consumed.
- **Pure logic only.** No networking, storage or UI. The platform shell owns those.

## Language of the sources

Comments and documents are in English. Where Russian appears it is either the app's own interface text («Отправить позже», placeholders such as the undecryptable-message marker, which are protocol constants) or Unicode test data inside a vector (`привет`, `Привет 👋`). Both are part of what the tests pin; none of it is a note.
