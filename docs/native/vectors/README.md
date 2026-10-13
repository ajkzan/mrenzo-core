# Golden interop vectors

> **Licence note.** This is published for review under the PolyForm Strict License 1.0.0 (see the root [LICENSE](../../../LICENSE)): for non-commercial purposes you may read it and run `cargo test` unchanged; you may not distribute it, change it or build new works on it. The commands that write files (`GOLDEN_WRITE`) and the rules about changing code and vectors are the maintainer's working rules, kept as the record of how the code is developed. They are not an invitation to change anything.

> **In this repository.** `cargo test` in `native/core` replays these files, or regenerates them and compares byte for byte. Account names and ids inside the files are synthetic (`alice` 1001, `bob` 1002, `carol` 1003 in the Rust-generated files; `42` in the RN-era files) and every key comes from the golden PRNG below, from a public test vector (RFC 7748, RFC 8032, NaCl) or from a fixed fixture, so nothing in this folder belongs to a real account. Interface strings in Russian inside the files are test data or the app's own placeholders and are part of the vectors.

> **Protocol v3 (build 349).** The v3 vectors below are produced by the shared Rust core
> (`native/core/tests/golden_*.rs`, deterministic `StreamRng` = the [PRNG](#prng) stream under the recorded
> `rngLabel`) and are the contract for every client of build ≥ 349:
>
> ```bash
> cd native/core
> GOLDEN_WRITE=1 cargo test --test golden_ratchet_v3 --test golden_protocol_v3 --test golden_sealed_sender   # (re)write
> cargo test                                                                                                 # verify (default)
> ```
>
> | File | Construction |
> |---|---|
> | `x3dhV2.json` | X3DH v2: bundle → SK / AD / sid / RK0 with and without OPK, responder equality, low-order rejection, the `mrenzo-spk-v2` SPK signature (a v1-signed SPK is refused) |
> | `ratchetV3.json` | A→B→A transcript with typed plaintexts (chat with reply/fwd/expire, file, edit, hello), prekey messages, `x` dropped after the first inbound, MAC bytes, header bytes, state after each step |
> | `ratchetV3Negative.json` | `v:2`, missing `mac`, duplicate key, non-canonical base64, `x` stripped / added, flipped header / ciphertext — none opens, none moves the state |
> | `skippedCap.json` | 2001 skips → the oldest evicted; the 14-day TTL |
> | `ratchetReset.json` | the signed reset canonical string, signature, nonce replay, ts window, a `dh` that matches nothing |
> | `safetyNumbersV2.json` | the number over IK ‖ ED of both sides; the pair number with seeds |
> | `sdpSigningV2.json` | payload `fp\|ts\|nonce\|from\|to\|callId\|type\|2`, `rb`, every verification outcome (ok, archived-session ok, rb missing / no session / mismatch, callId / to / type / from mismatch, wrong or missing key, pv missing, ts skew, reflection) |
> | `meshV2.json` | binding over every routing field, outer JSON, ACK tag, rejected relay mutations and v1 |
> | `contactPairV2.json` | key-less link, signed scan payload, rejected forms |
> | `sealedSenderCert.json` | Only integer `uid` / `expires_at_ms` in [0, 2^53) verify |
> | `senderKeysV3.json` | SKDM v2 (`from`) over a v3 session, the `sk2` post over group + sender + counter, negatives |
> | `legacy347/fixtures.json` | wire of builds ≤ 348 that a 349 client MUST reject (v2 envelope, mesh v1, pair link v1, `sk1`, SKDM v1 / transport 2, call offer without `pv`/`rb`, typed and unsigned resets, unsigned publish) |
>
> Removed with the functions they pinned: `ratchet.json`, `sdpSigning.json`, `mesh.json`, `contactPair.json`,
> `safetyNumbers.json`, `senderKeys.json`, `senderKeysV2.json` (and `native/tools/vectors`). Kept as-is:
> `primitives.json`, `keyPublish.json`, `legacyBox.json`, `sealedSender.json`, `offlineSeal.json`, `files.json`,
> `x3dh.json` (the v1 generation helpers), `identityBackup.json`, `roomId.json`, `prng.json`. The sections below
> describe the RN-era generator and are historical for the removed files.

> **Wire level 2 (mr.enzo 1.1, build ≥ 354).** Contract: `wire-1.1.md`; normative text: `../protocol/03-crypto.md`
> (§V3.16–§V3.21 and the level-2 notes inside §V3.3–§V3.9) and `../protocol/04-mesh.md` («Mesh at level 2»; that document is not part of this first publication and will follow). Produced by
> the same Rust core with the same `StreamRng`; every v3 file above is UNCHANGED from build 353 and still verifies
> (in the closed-source repository the diff of these files against the App Store commit `712e1dcc`, build 353, is empty; the files below are new).
>
> ```bash
> cd native/core
> GOLDEN_WRITE=1 cargo test --test golden_typed_v11 --test golden_pq --test golden_features_v11 --test golden_mesh_v11   # (re)write
> cargo test                                                                                                              # verify (default)
> ```
>
> | File | Test | Construction |
> |---|---|---|
> | `typedV11.json` | `golden_typed_v11` | the `caps` object (canonical form, the lenient-parse table); every plaintext a level-2 client builds (`chat` with `caps` / `alt` / a nearby invite, `hello`, `react` — an emoji, a removal and the longest legal `e`, padded to ONE length (the padded size is that of the longest `e`, `wire-1.1.md` §W7.3) —, `nearby` accept / stop, `ptt`); the classification table — typed, soft keys malformed = absent, unknown `t` = `Unsupported` with `t` / `id` / `alt`, strict level-2 kinds; the outer-agreement tables (`ctl`, mesh `ctl`, `ptt`) |
> | `unsupportedV11.json` | `golden_typed_v11` | a ratchet transcript in which one side sends a kind this build does not know: `Unsupported`, the state after it, the next `chat` opens; `Stale` on the current chain and after a DH step WITH the aux, the same frame without the aux = `Failed`; the aux JSON; the skip budget (run of 256 lossy steps, the refusal, which kinds are lossy) |
> | `capsV11.json` | `golden_typed_v11` | the signed statement: canonical string `mrenzo-caps-v1\|uid\|v\|flags\|ts`, signature, JSON; 14 verification cases (another user, another key, replayed, future, a flag or the level changed after signing, non-canonical, duplicate key, over 1 KiB) |
> | `pqxdhV1.json` | `golden_pq` | hybrid session setup: KEM prekey generation (64 bytes drawn per key), the `mrenzo-kem-prekey-v1` signature, upload bodies; initiation with / without OPK × one-time / last-resort — draws, the 89-byte KDF info, SK / AD / sid / RK0, the first envelope with `x.kem`, header bytes with `xflag 2`; responder equality; same DHs ⇒ classical SK ≠ hybrid SK; 24 negatives (kind, key id, flipped key byte, SPK-label signature, server-substituted key, a key that fails the FIPS 203 modulus check, header without seed and seed without header, the 1.0.0 responder on a hybrid header, another seed, tampered / stripped / added `kem`, wrong lengths) |
> | `ratchetV3Pq.json` | `golden_pq` | a transcript over a hybrid session, with the state JSON (`pq`, `x.kem`) after each step |
> | `mlkem768Kat.json` | `golden_pq` | ML-KEM-768 as this build computes it: seed → `SHA-256(ek)`, `m` → `ct` / `ss`, decapsulation, implicit rejection. NOT the NIST ACVP files (they are not in the tree): it pins the pinned crate's output against silent change and is the cross-check file for Go `crypto/mlkem`. All four cases were reproduced with OpenSSL 3.6.1 (`genpkey -algorithm ML-KEM-768 -pkeyopt hexseed:…`, `pkeyutl -decap`, `pkeyutl -encap -pkeyopt hexikme:…`; commands in `wire-1.1.md` §W6.7) |
> | `pttV1.json` | `golden_features_v11` | push-to-talk: the key object, five `P1` chunks (recorded nonce, flags, padding to 256), 13 negatives, the `PttReceiver` transcript (per-sender state, dedupe only after authentication, a foreign frame naming a victim's `tx`) |
> | `reactGroupV1.json` | `golden_features_v11` | reactions in rooms: chain key → `mk` → `rk` → `k_u`, an add and a removal blob (`rx1:`) of one length, 10 negatives (re-attributed to another user / post / group), and the last-writer-wins register table (raw `(ts, id)`, no clamping, the 24 h bound) |
> | `stickerV1.json` | `golden_features_v11` | the `st` reference table (12 cases); a PNG, its padded wire form (`mrPd` chunk, 32 768 bucket), the canonical id; 10 malformed PNGs |
> | `pushHintV1.json` | `golden_features_v11` | the push hint `mz` for the Notification Service Extension: a direct and a channel hint sealed as `OSB1:`, 10 negatives |
> | `meshV11.json` | `golden_mesh_v11` | the strict frame check: 10 valid frames (1.0.0-built `msg` and ACK, blind ACK, `ptt`, `ctl`, an unknown name), 80 rejected ones with their reason, `seenKey`, the forward table, relay chains in which every hop's copy verifies, the blind ACK (seed, key, frame), a FORGED blind ACK that passes the check and matches no author, a `ptt` transmission, the link hello |
> | `meshCourierV1.json` | `golden_mesh_v11` | the courier capsule `c` (signed by the sender, checked by every node): the `csig` string, capsule bytes, the frame with and without it, the queue JSON, the object the server routes, 12 negatives — for each, whether a relay keeps the capsule and whether the server gets a recipient; the seen-set transcript (per row: the lane the copy came in on and whether that radio can relay; new / duplicate / upgrade; the exact frames emitted with their lanes — a copy with an inflated `hops` or a bystander's capsule, heard first, suppresses nothing) and its `orderings` — seven fresh nodes: the two unsigned levers used together, and the two-radio cases; in each the last emission on every lane carries the sender's capsule |
>
> **Compatibility with 1.0.0 is proved by running the 1.0.0 code**, not by vectors: `native/core/tests/legacy353/`
> holds `plaintext.rs`, `ratchet.rs`, `x3dh.rs`, `session_set.rs`, `mesh_envelope.rs`, `files.rs`, `crypto_ts.rs` and
> the whole `compat/` layer from `712e1dcc` (copied from the 1.0.0 commit `712e1dcc` of the closed-source repository; only `crate::` paths rewritten; each
> file checked against the SHA-256 of its `712e1dcc` blob by `legacy353::frozen`, which also pins the two modules
> still shared with the live crate, `primitives.rs` and `rng.rs`), and `native/core/tests/compat_353.rs` feeds
> level-2 output to them. Hostile input: `native/core/tests/hostile_input.rs` mutates valid inputs for the parsers it lists
> (built by the core's own builders or read from the vectors; 41 526 cases) and requires no panic and no forgery; its `seen_set_orderings` runs every short sequence of copies of one
> frame through the seen set (22 620 on one radio, 112 944 over two).
>
> **A second implementation:** `native/core/tests/independent_check.py` recomputes these files from the formulas
> written in the documents, with libsodium (PyNaCl), `hashlib` and OpenSSL's ML-KEM-768 instead of the Rust core
> (it prints how many checks agree; the last full run is not recorded in this publication; run by hand, it needs
> PyNaCl and OpenSSL ≥ 3.5: `python3 native/core/tests/independent_check.py`).
> It is a second, independent reading of the formulas in the documents.

Byte-exact test vectors produced by the **real production TypeScript code** of the React Native app (build 324). Every native implementation in the developer's own apps (Swift iOS, the shared core, a planned Kotlin Android app) must reproduce these outputs. If it does not, it cannot talk to the React Native clients still in the field.

Generator: `mobile/src/__tests__/goldenVectors.test.ts` (closed source; the RN-era files below are fixed and are only replayed here).

Exception: `discovery.json` (address-book discovery, build ≥ 349, no RN counterpart) is generated by the Go server, `DISCOVERY_VECTORS_WRITE=1 go test ./internal/discovery`, and carries the RFC 9497 Appendix A.1.1 vectors; contract `../protocol/01-rest-api.md` §9.3 (that document is not part of this first publication and will follow).

## Dual mode

> The RN-era generator is in the closed-source app and is not published; the commands below are kept as the record of how those files were made. In this repository, `cargo test` in `native/core` is the verification (all v3 and level-2 files are regenerated by the Rust tests and compared byte for byte; the RN-era files are replayed).

```bash
cd mobile
GOLDEN_WRITE=1 npx jest goldenVectors --forceExit --runInBand   # (re)write the JSON files
npx jest goldenVectors --forceExit --runInBand                  # verify (default, runs in CI with the suite)
```

Verify mode checks both directions:

- **Producer side.** The current code re-derives every output byte-for-byte from the recorded inputs.
- **Consumer side.** The production decoders still accept the committed ciphertexts and signatures, with the recorded random draws replayed.

A failure in verify mode means the wire or at-rest contract changed. That breaks every native client and every RN client in the field. **Never regenerate just to make the test pass.** Regenerate only for an intentional, versioned protocol change, and update `../protocol/*.md` in the same commit.

## File conventions

Every file has the same header: `area`, `schema` (currently 1), `generator`, `encodings`, `sources` (production file:line the vector exercises) and `notes` (the construction in prose, including the traps).

| Suffix | Encoding |
|---|---|
| `*B64` | RFC 4648 §4 standard base64 **with** `=` padding (tweetnacl-util) |
| `*Hex` | lowercase hex |
| `*Json`, `wire` | the exact UTF-8 string emitted by `JSON.stringify`. Key order matters wherever a signature covers it. |
| `rng.draws` | PRNG draws in call order, see [PRNG](#prng) |

## <a name="prng"></a>PRNG: deterministic randomness

Production uses the OS CSPRNG. The vectors replace tweetnacl's `randombytes` with a deterministic stream, so the "random" keys, nonces and ephemerals are reproducible.

```
D          = UTF-8("mrenzo-golden-prng-v1|" + label)
stream(D)  = SHA-256(D || be32(0)) || SHA-256(D || be32(1)) || SHA-256(D || be32(2)) || ...
```

Each `randombytes(x, n)` call consumes the **next n bytes** of the stream. Reads continue across calls and are never re-aligned to the 32-byte block boundary. `prng.json` is a self-test: label `selftest`, draw sizes 1, 31, 32, 36, 4, and the first 104 bytes of the stream.

A native harness has two options:

1. **Re-implement the stream** (about 20 lines of code) and call the same production-equivalent functions. The draw sizes and order must match what tweetnacl requests, listed below.
2. **Inject the recorded draws** from each vector's `rng.draws`, in order. This works even when the native code draws in a different order internally, as long as it can accept the injected values.

What tweetnacl draws:

| Call | Bytes drawn |
|---|---|
| `nacl.randomBytes(n)` | n |
| `nacl.box.keyPair()` | 32 (raw X25519 secret, **unclamped**; clamping happens inside scalar multiplication) |
| `nacl.sign.keyPair()` | 32 (Ed25519 seed) |
| Ed25519 sign, box, secretbox | 0 (deterministic) |

Clocks are fixed too: `T0 = 1758800000000` (2025-09-25T11:33:20.000Z), with per-vector offsets recorded in the file.

## Files

| File | Construction | Crosses devices? |
|---|---|---|
| `primitives.json` | Key generation and encodings. The Ed25519 private key is tweetnacl's 64-byte `seed‖pub`; CryptoKit and BouncyCastle take the 32-byte seed. | yes |
| `keyPublish.json` | `POST /api/keys/publish` body and its Ed25519 signature over `publicKey\|signingPublicKey\|uid\|ts` (base64 strings, `ts` is a decimal string) | yes |
| `legacyBox.json` | Pre-ratchet static `nacl.box` (HSalsa20 over X25519). **Still live for stories** and as a legacy decrypt attempt in chats. | yes |
| `ratchet.json` | 1:1 Double Ratchet: HKDF-SHA256 with a zero salt and ASCII info labels, KDF_RK and KDF_CK, header, message JSON, skipped keys, out-of-order delivery. Multi-step Alice↔Bob sequences. | yes |
| `sealedSender.json` | Server certificate (`be64(uid)‖be64(expiresMs)‖ASCII(sender_pub base64)`) and the sealed blob layout | yes |
| `offlineSeal.json` | `OSB1:` blobs sealed by the **server** for offline delivery. The ephemeral key comes first, the opposite of sealed sender. | yes (server→client) |
| `sdpSigning.json` | Call DTLS fingerprint signing: canonical `a=fingerprint:` lines, `fingerprints\|ts\|nonce\|fromUserId`, and the legacy 3-field form | yes |
| `files.json` | Attachments: per-file secretbox key (32 bytes, drawn before the 24-byte nonce), the envelope carried in the E2E message, raw ciphertext on the server | yes |
| `safetyNumbers.json` | SHA-512 over the sorted raw identity public keys, rendered as 6 blocks of 5 digits | yes (both sides must show the same number) |
| `mesh.json` | Mesh envelope: outer JSON, the byte-exact inner blob (u64 BE uids, flags 0x01/0x02/0x04/0x08), Ed25519 signature, padding buckets, `toIdx`, ACK | yes (iOS↔Android over BLE) |
| `senderKeys.json` | Group sender keys: SKDM distribution and the `sk1:` wrapper. `messageKey = HKDF(chainKey, info "mrenzo-sender-msg")`, `next = HMAC(chainKey, 0x02)` | yes |
| `senderKeysV2.json` | Build-325 group semantics: chain sets (`recv:`/`recvprev:`), SKDM ingest rules, walk bound 2000 + per-sender budget, 4000-byte refusal, `sender-v2:` tag. Generated from RN 325 by `native/tools/vectors/senderKeysV2.gen.test.ts` | yes |
| `x3dh.json` | X3DH prekeys. Signed prekey upload is **live**; the derive functions have **no production caller yet**. The vectors pin the construction ahead of use. | yes (future) |
| `contactPair.json` | Offline QR pairing: `mrenzo://pair/` + base64url JSON with no padding | yes |
| `identityBackup.json` | The sealed identity backup slot in MMKV | **no**: local only. Needed so the native iOS app can import it when it replaces the RN app in place. |
