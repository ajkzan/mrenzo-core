# 03 — Cryptography and message formats: interop contract

> **About this publication.** The documents 01 (HTTP API), 02 (WebSocket) and 04 (offline network) are not part of this first publication and are planned to follow. For a reader of this repository the normative text is this document together with the vectors; where a passage below names another document or the code of the closed apps and server as its source, that is the record of where the statement came from, not something this repository lets you check. References to them (for example «02 §7» or `04-mesh.md`) are kept as they are, so that the text stays exact.

**Status:** normative for the native iOS client (Swift) and the future Android client (Kotlin). **Build ≥ 349 speaks
protocol v3 only — see «Protocol v3 (build 349)» right after the contents; §3, §7, §9–§12 describe the ≤ 348 formats
that v3 rejects.** **mr.enzo 1.1 (build ≥ 354) is «wire level 2» of the same protocol v3:** additive, and safe against
the 1.0.0 clients in the field (build 353). Level 2 is marked «Level 2» inside §V3.3–§V3.14 and specified in
§V3.16–§V3.21; the single source of truth for what 1.1 adds — field tables, flows, the 1.0.0 ↔ 1.1 matrix, and the
lists «server must» / «iOS must» — is `wire-1.1.md` (the design record of wire level 2; it is not part of this repository — the normative text is §V3.16–§V3.21 below and 04-mesh.md «Mesh at level 2»).

**Source of truth:** the code of the closed-source RN client and server, build 324. Paths below are relative to the root of that tree, and every non-obvious claim cites `file:line` (the citations do not resolve inside this repository).

**Sibling specs:**
- `01-rest-api.md` covers HTTP endpoints in general.
- `04-mesh.md` covers mesh framing and routing.

This document owns every cryptographic construction and every encrypted-payload format.

**Conventions:**
- Keywords MUST / SHOULD / MAY follow RFC 2119.
- "RN" means the shipping React Native client. "Native" means the new Swift iOS app and the future Android app.
- **As-built** means what the code does today, bugs included. Native MUST reproduce as-built **wire** behaviour unless a section explicitly says a divergence is allowed, because RN peers stay in the field for months. (Historical: written while the React Native client was in use. The App Store releases are native, and builds ≥ 349 reject the ≤ 348 formats — see «Protocol v3» below.)
- **NOT INTEROP** marks device-local state: Keychain layout, MMKV blobs, backup slots. That state matters only when migrating an RN install to the native app on the same phone (§2.7).
- Notation:
  - `b64(x)` is standard base64 with padding (RFC 4648 §4); `b64dec` is its strict inverse (§1.3).
  - `‖` is byte concatenation.
  - `UTF8(s)` is the UTF-8 bytes of `s`.
  - `BE64(n)`, `BE32(n)` and `BE16(n)` are big-endian unsigned integers.
  - `ZERO32` is 32 bytes of `0x00`.

---

## Contents

V3. Protocol v3 (build 349) — normative; supersedes §3, §7, §9–§12
    V3.16–V3.21: wire level 2 (mr.enzo 1.1) — outcomes and capabilities, the control carrier, the hybrid
    post-quantum setup, push-to-talk media, stickers, the push hint
0. Summary for implementers
1. Primitives, libraries, encodings, constants
2. Identity keys and the key directory
3. The Double Ratchet (1:1 messages)
4. Legacy static box `{n,c}`
5. Sealed Sender (certificates, envelope, delivery tokens)
6. Server at-rest offline seal (`OSB1:`)
7. SDP / DTLS-fingerprint signing for calls
8. File and attachment encryption
9. Safety numbers
10. Group Sender Keys (as built, effectively non-functional)
11. X3DH prekeys (uploaded, never used; native ports the bootstrap)
12. Mesh crypto touchpoints
13. Apple-only vs cross-platform; Android equivalents
14. Known-answer test vectors
15. Interop hazards (checklist)
16. Open questions

---

## Protocol v3 (build 349) — normative

**Status:** this section is the protocol every client of build ≥ 349 speaks, and the only one it accepts. It
replaces §3 (Double Ratchet), §7 (SDP signing), §9 (safety numbers), §10 (Sender Keys), §11 (X3DH) and the
crypto parts of §12 (mesh) below, which stay as the reference of the ≤ 348 formats that a 349 client REJECTS
(§V3.14). There is no compatibility window: build 349 and the server ship together.

**Numbering:** code comments of build ≥ 349 cite «03 §N.M»; that is §V3.N.M here. Inside this section a bare
«§N.M» also means §V3.N.M. «AS-nn» tags name the security-review findings each rule closes.

**Wire level.** An integer that names a set of mandatory RECEIVE behaviours. Level 1 = build 349–353 (1.0.0; never
announced). Level 2 = mr.enzo 1.1, announced in `caps` (§V3.16). Three rules govern everything level 2 adds:
1. **Carrier rule.** A typed plaintext whose `t` did not exist in 1.0.0 travels ONLY in a field a 1.0.0 client never
   feeds to its ratchet (`p2p-message.data.ctl`, `ptt-start.data.wire`, a mesh frame of a named kind) — because a
   1.0.0 core counts an unknown `t` as a decrypt failure and three of those reset the session.
2. **Soft keys.** What a 1.0.0 peer must still receive in a meaningful form rides as an optional key that 1.0.0
   ignores (`caps`, `alt`, `p`, `nearby` on a `chat`, `silent` on a `chat` or a `file`, `st` in a `file` body); a
   malformed soft key is an absent one.
3. **From level 2 on, an authenticated plaintext is never a decrypt failure** (§V3.3.5, §V3.5.6).

**Implementation:** Rust core `native/core/src/{x3dh,ratchet,plaintext,session_set,ratchet_reset,safety_numbers,sdp_signing,mesh_envelope,contact_pair,sealed_sender,sender_keys,group_chains}.rs`;
level 2: `{kem,caps,nearby,ptt,reactions,sticker,push_hint,mesh_v11,strict_json}.rs`
(UniFFI: `native/ffi/src/lib.rs`, level 2 in `native/ffi/src/v11.rs`); Swift `MessageCrypto`, `PeerPins`, `SessionEstablisher`, `PrekeyStore`,
`MessagePipeline`, `EditIntake`, `DirectSend`, `SenderKeyService`, `SdpSigner`, `MeshService`, `OfflinePairing`,
`MigrationV3`; server `internal/auth/handlers.go` (bundles), `storage/app/routes_keys.py` (publish).
Golden vectors: `docs/native/vectors/*V2.json`, `*V3.json`, `ratchetReset.json`, `skippedCap.json`,
`sealedSenderCert.json`, `legacy347/fixtures.json`; level 2: `typedV11`, `unsupportedV11`, `capsV11`, `pqxdhV1`,
`ratchetV3Pq`, `mlkem768Kat`, `pttV1`, `reactGroupV1`, `stickerV1`, `pushHintV1`, `meshV11`, `meshCourierV1`
(see `vectors/README.md`). The 1.0.0 core is frozen under `native/core/tests/legacy353/` — with every helper it
calls, each file pinned by hash to `712e1dcc` — and `tests/compat_353.rs` runs level-2 output through it.

### V3.1 Threat model and goals

Adversaries: (1) a malicious or compromised server operator (routes, stamps `fromUserId`, controls the key directory, the prekey pool, the push text and the channel member lists); (2) any other authenticated user, including a group member; (3) a nearby radio on the mesh; (4) a relay of pigeon frames. Out of scope: a compromised endpoint, the Keychain, iOS itself, a person who physically presents a forged QR and is believed.

Goals:
- G1 Every 1:1 session is mutually authenticated to both parties' identity keys. The server can neither impersonate a user nor become a MITM without changing a safety number.
- G2 No unauthenticated path creates, replaces, promotes or deletes a session. Loss of a session is visible, never a silent swap.
- G3 Everything a receiver renders or acts on (text, target of an edit, quoted reply, forwarded-from name, expiry, story reference) is inside the authenticated box.
- G4 A group post is attributable to one identity in one group: the chain's signature covers the group and the sender, and the chain reached the receiver through an authenticated session.
- G5 Calls are bound to an authenticated session between exactly these two users and this call (`rb`).
- G6 Mesh frames and ACKs are acted on only when the signer is a pinned identity; relays cannot re-target, extend or re-flag a frame.
- G7 Safety numbers cover every key a peer signs or encrypts with.
- G8 The Share Extension steps existing sessions without any identity private key, never starts one and never writes trust state.

---

### V3.2 Keys and key storage

#### V3.2.1 Identity (unchanged material, preserved on update)
- `IK` X25519 identity key, 32 B. Keychain item K2 (`com.mrenzo.e2e`).
- `ED` Ed25519 signing key, 64 B secret (`seed ‖ pub`). Keychain item K3 (`com.mrenzo.e2e.sign`).
- Published together, self-signed (`POST /api/keys/publish`, canonical `publicKey|signingPublicKey|uid|ts`, unchanged). The server REJECTS unsigned or half publishes and keys already published by another uid (§8.2).
- The pair `(IK, ED)` is ONE identity. Any change to either half is a key change (§5.7).

#### V3.2.2 Prekeys (account DB, kv scope `x3dh`, sealed)
| Key | Value | Notes |
|---|---|---|
| `spk:current` | `{keyId, privKey, pubKey, signature, rotatedAt}` | `signature = Ed25519(ED, UTF8("mrenzo-spk-v2") ‖ raw 32 SPK bytes)`. The v1 raw-bytes signer survives only for the `x3dh.json` golden vectors |
| `spk:old:<keyId>` | `{keyId, privKey, pubKey, retiredAt}` | A retired SPK. Expires `retiredAt + 30 d`; at most 5 kept (oldest evicted). Inbound prekey messages may reference any of them |
| `opk:<id>` | b64 X25519 private | deleted when consumed |
| `nextKeyId` | decimal | one counter for SPK and OPK ids; NEVER reset |
| `opkRefillPending`, `opkPoolResetPending` | `"1"` | unchanged semantics |

Rotation: SPK every 7 days (unchanged): the old `spk:current` becomes `spk:old:<id>` in the same transaction that stores the new one (after the server accepted it, as today). OPK batch 100, refill under 20 (unchanged). A launch that finds an identity in the Keychain but NO `x3dh` rows other than `nextKeyId` (fresh DB, «Использовать этот iPhone», or the §10 switch) MUST set `opkPoolResetPending=1` and `opkRefillPending=1`.

#### V3.2.3 Peer pins (`peer_keys`, existing table, two new columns)
```
ALTER TABLE peer_keys ADD COLUMN source TEXT NOT NULL DEFAULT 'directory';   -- 'directory' | 'pair-scan'
ALTER TABLE peer_keys ADD COLUMN confirmed_at INTEGER;                        -- NULL = provisional
```
A row IS the pin (trust on first use against the directory). Rules:
- A row is written only with BOTH keys present and 32 bytes each. A row with an empty `signing_public_key` (pre-349 rows) is "no pin" for ED: nothing signed by that peer verifies until a directory fetch fills the row (this is the ordinary TOFU of a first fetch, documented; a verified peer in that state is handled by §10.4, never repaired silently).
- `confirmed_at` is set by a directory fetch (`GET /api/keys/{uid}`, row-identity check unchanged) that returned exactly the row's pair. Rows written from the directory are confirmed at write. `pair-scan` rows start provisional.
- A **provisional** row is honoured by the offline paths only: mesh receive (§9.2) and mesh ACKs (§9.4). (No session can be INITIATED under a provisional pin: X3DH needs the bundle, which is an online fetch. Level 2 adds one more offline use — a second, provisional capability record that gates mesh-only features, §V3.16.2.) Before ANY online use of that peer (bundle fetch, call, accepting a signed reset, sending over WS, opening the chat with network) the app MUST reconcile it: fetch the directory; equal → `confirmed_at = now`; different → §5.7; unreachable → the online action waits (`needs-session`, call fails `pin-unconfirmed`).
- Any source that presents a `(IK, ED)` differing from the row in EITHER half is a key-change event (§5.7). Nothing overwrites a row silently. Every write goes through `PeerPins.reconcile(tx, uid, ik, ed, source, now)` (new pin / confirm / unchanged / key change) or the §5.7 gate (`PeerPins.applyDirectoryChange`, `acceptNewKey`); there is no other writer.
- Sources: `directory`, `pair-scan`. A prekey header or a link is NEVER a source (it can only match or mismatch).

#### V3.2.4 Sessions (`sessions` table replaces `ratchet_sessions`)
```
CREATE TABLE sessions(
  peer_uid   INTEGER NOT NULL,
  sid_hash   TEXT    NOT NULL,          -- hex SHA-256 of the sid: the row key (the sealed session_id is randomised per write)
  session_id BLOB    NOT NULL,          -- sealed b64 sid, AAD "sessions.session_id|<peer>"
  peer_ek    TEXT,                      -- b64 initiator ephemeral (responder side only; NULL on our initiations)
  status     TEXT    NOT NULL CHECK(status IN ('initiating','active','archived')),
  state      BLOB    NOT NULL,          -- sealed JSON (§V3.3.7), AAD "sessions.state|<peer>|<sid_hash>"
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(peer_uid, sid_hash)
);
CREATE UNIQUE INDEX sessions_one_live ON sessions(peer_uid) WHERE status <> 'archived';
CREATE INDEX sessions_peer_ek ON sessions(peer_uid, peer_ek) WHERE peer_ek IS NOT NULL;
```
Invariants: at most one non-archived ("live") session per peer; at most 3 archived (oldest by `updated_at` deleted); archived sessions expire 30 days after `updated_at`. Archived sessions decrypt and can be promoted (§5.1); they never send.

#### V3.2.5 Verified records (`kv safety/verified:<uid>`, existing)
Shape `{safetyNumber, verifiedAt}` with the v2 number (§6). `verified` is written ONLY by a fresh number comparison (§6, §12.4). Migration in §10.4.

1.1 adds an optional, LOCAL `method` (never sent, not interop): `"qr"` — the peer's code scanned from their screen in the guided in-person flow («Проверить лично»); `"typed"` — the peer's first two blocks typed. Absent in every record made before 1.1 and in an RN import (unknown), and absent ≠ `"typed"`. A reader keeps a record whose `method` it does not know and treats it as an ordinary verification. Only `"qr"` earns the label «Проверен лично»; everything else reads «Подтверждено».

#### V3.2.6 Initiator-ephemeral seen-set (`kv x3dh-seen/<peer>:<b64 ek>` → `firstSeenMs`)
Every `ek` that ever created a responder session is recorded for 45 days (longer than any SPK can still be valid: 7 d current + 30 d retired ≤ 37 d). Pruned on write. A prekey header whose `ek` is in the set but matches no stored session is a replay of an evicted session → dropped `init.ekReplayed`, not counted, no reset, no receipt.

---

### V3.3 1:1 protocol v3

#### V3.3.1 X3DH (initiator A → responder B)
Inputs: A's `IK_A`, `ED_A`; B's pinned and confirmed `IK_B`, `ED_B` (§5.2); B's bundle `SPK_B` (id, pub, sig), optional `OPK_B` (id, pub).
```
verify Ed25519(ED_B, UTF8("mrenzo-spk-v2") ‖ SPK_B pub) == SPK_B.sig       else abort "spk-signature"
EK_A = fresh X25519 keypair
DH1 = X25519(IK_A.priv, SPK_B)
DH2 = X25519(EK_A.priv, IK_B)
DH3 = X25519(EK_A.priv, SPK_B)
DH4 = X25519(EK_A.priv, OPK_B)                                  when OPK present
abort if any DHi == 0^32 (low-order point)
SK  = HKDF-SHA256(salt = 0^32, ikm = 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], info = "mrenzo-x3dh-v2", L = 32)
AD  = "mrenzo-ad-v3" ‖ IK_A ‖ ED_A ‖ IK_B ‖ ED_B                (12 + 128 bytes; initiator first)
sid = HKDF-SHA256(0^32, SK, "mrenzo-ratchet-session-id-v3", 32)
RK0 = HKDF-SHA256(0^32, SK, "mrenzo-ratchet-init-v3", 32)
```
Responder (given header `x` and `fromUserId`): `DH1 = X25519(SPK.priv, x.ik)`, `DH2 = X25519(IK_B.priv, x.ek)`, `DH3 = X25519(SPK.priv, x.ek)`, `DH4 = X25519(OPK.priv, x.ek)`; same SK/AD/sid/RK0 with `IK_A = x.ik`, `ED_A = x.ed`, `SPK` = `spk:current` or the `spk:old:<x.spk>` it names. `x.ik`/`x.ed` MUST equal the pin for `fromUserId` (§5.2) BEFORE any DH is computed.

The Rust `x3dh.rs` keeps its RN functions for the golden `x3dh.json`; v3 adds strict `x3dh_v2_derive_{sender,recipient}` (typed 32-byte inputs, low-order rejection, new info label, v2 SPK signature label).

**Level 2 — the hybrid option (ML-KEM-768 + X25519; `x3dh_pq_initiate` / `x3dh_pq_respond`).** Chosen per session by
the initiator when B's bundle carries a KEM prekey (01 §6). The classical derivation above is unchanged byte for byte
(`x3dhV2.json`, `ratchetV3.json` verify without regeneration).
```
KEM prekey   = ML-KEM-768 (FIPS 203): ek 1184 B, ct 1088 B, shared secret 32 B; the device keeps the 64-byte seed d ‖ z
signed bytes = UTF8("mrenzo-kem-prekey-v1") ‖ BE64(keyId) ‖ kind ‖ 0x0A ‖ ek        kind: 0x01 last-resort, 0x02 one-time; 0x0A = ML-KEM-768
verify the SPK signature (as above), then Ed25519(ED_B, signed bytes) STRICTLY under the pinned ED        else abort "kem-signature"
verify ek by the FIPS 203 §7.2 modulus check                                                              else abort "kem-invalid"
EK_A = fresh X25519 keypair (32 bytes drawn);  m = 32 bytes drawn                    draw order: EK, then m
DH1..DH3 [DH4] as above, each ≠ 0^32
(ct, SS) = ML-KEM-768.Encaps(ek, m)
info = UTF8("mrenzo-pqxdh-v1") ‖ 0x0A ‖ kind ‖ BE64(keyId) ‖ SHA-256(ek) ‖ SHA-256(ct)                    89 bytes
SK   = HKDF-SHA256(0^32, 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] ‖ SS, info, 32)
AD, sid, RK0 exactly as above
```
The algorithm, the key kind, the key id, `ek` and `ct` are bound INTO `SK`, not only under the header MAC: two
parties that disagree on any of them derive different sessions whatever the KEM is. Responder: `SS = Decaps(seed, ct)`
with the seed of the KEM prekey `x.kem.id` names (one-time, then current last-resort, then retired last-resort) and the
KIND of the row it was found in; `ek` for the info is re-derived from the seed. ML-KEM rejects implicitly, so a
ciphertext not made for that key derives a session nobody holds and the envelope MAC fails (`init.macFailed`). A header
with `kem` and no seed, or a seed without `kem`, is `bad-key-id`. The core never falls back by itself: a KEM prekey
that does not verify is an ERROR, and the host applies §V3.17. The KEM runs through `libcrux-ml-kem` 0.0.10, always
its formally verified PORTABLE instantiation (`native/core/src/kem.rs`). Vectors: `pqxdhV1.json`, `mlkem768Kat.json`
(the latter reproduced with a second implementation, OpenSSL 3.6.1: same keys from the seed, same ciphertext from
the recorded randomness, same shared and implicit-rejection secrets).

#### V3.3.2 Initial ratchet state (same mechanics as today, new inputs)
Initiator: `root_key = RK0`, `my_dh = EK_A`, `peer_dh = SPK_B`, `(root_key, send_chain) = KDF_RK(RK0, DH3)`, counts 0, `x` = header (§3.4), `role = "init"`, `status = initiating`.
Responder: `root_key = RK0`, `my_dh = SPK keypair`, `peer_dh = 0^32`, chains none, `role = "resp"`, `peerEk = x.ek`, `status = active`. The first decrypt sees `env.dh = EK_A ≠ peer_dh` and runs the existing `dh_ratchet`, whose receive half is `KDF_RK(RK0, X25519(SPK.priv, EK_A)) = KDF_RK(RK0, DH3)` = the initiator's `(root, send_chain)`. `dh_ratchet`, `kdf_rk`, `kdf_ck`, `skip_recv_keys` are unchanged (info strings `mrenzo-ratchet-step-v1/chain-v1/msg-v1`).

The responder's session blob holds `SPK.priv`, never `IK_B.priv`.

#### V3.3.3 Per-message keys and MAC
```
(next_chain, mk) = KDF_CK(chain)                                 (unchanged)
(k_enc, k_mac)   = HKDF-SHA256(0^32, mk, "mrenzo-ratchet-msg-keys-v3", 64)   split 32/32
nonce            = random 24
ct               = nonce ‖ secretbox(UTF8(plaintext JSON §3.5), nonce, k_enc)
hdr              = 0x03 ‖ dh(32) ‖ BE64(pn) ‖ BE64(n) ‖ xflag(1)
                   ‖ [ ik(32) ‖ ed(32) ‖ ek(32) ‖ BE64(spk) ‖ BE64(opk, 0xFFFFFFFFFFFFFFFF when absent) ]   when xflag = 1 or 2
                   ‖ [ BE64(kem.id) ‖ kem.ct(1088) ]                                                         when xflag = 2 (level 2)
mac              = HMAC-SHA256(k_mac, AD ‖ hdr ‖ ct)               32 bytes
```
Decrypt derives `mk` exactly as today (skipped-key lookup → DH step → chain walk), verifies `mac` in constant time BEFORE `secretbox_open`. Skipped keys store `mk`.
- **Level 1 (build ≤ 353)** then parses the typed plaintext INSIDE the decrypt: a plaintext it cannot parse — an unknown `t` included — is the same `Ok(None)` as a MAC failure, the state is not saved, and the host counts it. This is the compatibility trap that the carrier rule exists for.
- **Level 2** stops at the box (`ratchet::open`). What the plaintext IS — a kind this build knows or not — is decided AFTER authentication (§V3.3.5); the ratchet step is consumed either way. `xflag = 2` when `x.kem` is present: the flag, the KEM key id and the ciphertext are under the MAC, so a relay can neither strip nor add `kem`.

#### V3.3.4 Wire envelope v3 (the `text` of `p2p-message`, `newText` of `message-edit`, the `skdm` field, the mesh payload, the group post body)
```json
{"v":3,"dh":"<b64 32>","pn":0,"n":0,"ct":"<b64 nonce‖box>","mac":"<b64 32>",
 "x":{"ik":"<b64 32>","ed":"<b64 32>","ek":"<b64 32>","spk":17,"opk":118}}
```
- `x` is present on every message the initiator sends while its session is `initiating`, absent afterwards. `opk` omitted when the bundle had none.
- **Level 2 — `x.kem`** (a hybrid session, §V3.3.1): `"x":{…,"spk":17,"opk":118,"kem":{"id":42,"ct":"<b64 of 1088 bytes>"}}`, `kem` the LAST key of `x`. Parse: `kem.id` an integer < 2^53, `kem.ct` canonical base64 of exactly 1088 bytes; anything else → `notEnvelope`. A level-1 client ignores unknown keys inside `x`, derives the classical secret and fails the MAC — one counted failure, no crash; the server therefore serves a KEM prekey only for a target whose last build is ≥ 354 (01 §6).
- **Level 2 — a newer envelope.** `{"v":N}` with an integer `N > 3` is `newer` (`envelope_classify_v11`): a notice row «Сообщение отправлено более новой версией mr.enzo. Обновите приложение.», never counted; the host KEEPS the raw envelope with the row and retries it after an app update. `N < 3` or a non-integer stays `rejectedLegacy`. A wire over 64 KiB is `notEnvelope`.
- Typed parse (serde): `v` must be the integer 3; `pn`, `n`, `spk`, `opk` non-negative integers < 2^53; every base64 field standard-padded and of the exact length; unknown keys ignored; a duplicate key or any other shape → `notEnvelope`. `RatchetEnvelope::from_wire` (v2/Hermes) is deleted with its leniency tests.
- `v:2` (or anything else) → `rejectedLegacy`: the pipeline inserts the placeholder «Сообщение отправлено старой версией приложения» (l10n `native.msg.legacyVersion`, 8 languages), never counts a failure, never sends a reset, sends the delivery receipt (a row was rendered).
- **Outer frame.** Removed from the wire: `replyTo`, `forwarded`, `forwardedFrom`, `autoDeleteSeconds`, `storyContent`. Kept as server-facing hints only: `toUserId`, `messageId`, `text`, `encrypted:true`, `type` (the server reads it for the push text; the receiver never renders from it), `action` (server routing), `storyId`/`storyType` (server story hooks). The receiver MUST check the hints against the inner plaintext (§3.5) and treat a mismatch as `notEnvelope`.

#### V3.3.5 Typed plaintext (inside the box; the only thing a receiver renders or acts on)
```json
{"t":"chat","id":"<messageId>","body":"<text>",
 "reply":{"id":"<messageId>","text":"<≤100 UTF-16 units>","name":"<sender name>"},   // optional
 "fwd":{"name":"<original sender name>"},                                            // optional
 "expire":86400,                                                                     // optional, seconds
 "story":{"id":"<storyId>","type":"<storyType>","action":"<action>","content":"…"}}  // optional
{"t":"file","id":"<messageId>","body":{…FileEnvelope JSON, unchanged 03 §8.3…},"reply":…,"fwd":…,"expire":…}
{"t":"edit","id":"<editId>","editOf":"<messageId>","body":"<text>"}
{"t":"skdm","id":"<messageId>","body":{…SKDM v2, §7.1…}}
{"t":"hello","id":"<messageId>"}
```
Receiver rules (all in the pipeline, before any row is written):
- `p2p-message` / mesh / sealed: outer `messageId` MUST equal inner `id`; outer `action` MUST agree with `t` (`sender-key-distribution` ↔ `skdm`, `session-hello` ↔ `hello`, a story action ↔ `t:"chat"` with `story` present and outer `storyId == story.id`); no outer `action` ↔ `chat`/`file`.
- `message-edit`: outer `messageId` MUST equal inner `editOf`, `t` MUST be `edit`. The edit applies to `editOf` only; the original-sender check (`target.from != "me"`) and the same-transaction apply stay.
- Group posts (§7): outer `messageId` MUST equal inner `id`; `edit` targets `editOf`.
- Mismatch → `notEnvelope` (not counted, no receipt). `reply.text` is a courtesy copy: when the receiver holds message `reply.id` locally it renders its own copy.
- `expire` replaces `autoDeleteSeconds` (same semantics, sender-chosen).

**Level 2 — the typed plaintext (`plaintext::classify`; vectors `typedV11.json`, `unsupportedV11.json`).**

Mandatory for every kind: UTF-8 text of at most 48 KiB that is a JSON object with no duplicate key at any depth, `"t"` a string, `"id"` a non-empty string. Three kinds are new; none of them ever travels in `text`, `newText`, `skdm`, a sealed blob or a mesh `msg`:
```json
{"t":"react","id":"rx-<uuid>","to":"<target messageId>","e":["❤️"],"ts":1790000000000}        carrier: ctl (§V3.16.3)
{"t":"nearby","id":"<messageId>","nearby":{"v":1,"op":"accept|token|stop",…}}                  carrier: ctl, mesh ctl (§V3.16.5)
{"t":"ptt","id":"<pttId>","ptt":{"v":1,"k":"<b64 32>","codec":"opus","sr":16000}}              carrier: ptt-start.wire, mesh ptt (§V3.18)
```
Optional on EVERY kind, parsed leniently (malformed = absent, never a failure):

| Key | Value | Use |
|---|---|---|
| `caps` | `{"v":<int 2..65535>,"f":[<token>,…]}` (§V3.16.1) | the sender's capabilities; a level-2 client attaches it to every plaintext of a 1:1 session |
| `alt` | string, 1..256 UTF-16 units | a plain-text fallback a receiver shows above the notice when it does not know `t` |
| `p` | string of U+0020 | padding, ignored |
| `nearby` (on `chat` only) | `{"v":1,"op":"invite","ns":…,"exp":…}` | a «Найти рядом» invite riding on a visible message (§V3.16.5) |
| `silent` (on `chat` and `file` only) | `true` (written only when chosen; anything else = absent) | «Отправить без звука»: the authenticated copy of the outer hint `silent` — the recipient's device posts its own notice of the message without a sound and its extension takes the sound off the alert (`wire-1.1.md` §W7.9). Not read on any other kind, and the builder refuses to write it there |

Serialization order: the kind's own keys (for a level-1 kind byte for byte what 1.0.0 writes), then `nearby`, `silent`, `alt`, `caps`, `p`. A level-2 kind MUST NOT carry `body`, `editOf`, `reply`, `fwd`, `expire` or `story`.

Everything else that authenticates is **`unsupported`**: an unknown `t`, a known `t` whose mandatory structure is not met, not an object, not UTF-8, over 48 KiB. It is an OUTCOME, not an error (§V3.5.6): the ratchet step is consumed, nothing is counted, and `t`, `id`, `alt`, `caps` are reported when they can be read. A later release may therefore send a new kind to any peer of level ≥ 2 — in `text` when a visible placeholder is wanted, in `ctl` when silence is.

Outer agreement at level 2 — one carrier per kind (`typedV11.json` `outer`): `chat` / `file` / `skdm` / `hello` by the rules above; `edit` in `message-edit`; `react` and `nearby` in `ctl` with outer `messageId == id`; `nearby` only in a mesh `ctl` frame; `ptt` in `ptt-start.wire` or the `w` of a mesh `ptt` frame with the transmission id `== id`. A kind in the wrong carrier is a mismatch (rolled back, `notEnvelope`, not counted).

#### V3.3.6 Session-level control messages
| outer `action` | inner `t` | purpose |
|---|---|---|
| `session-hello` | `hello` | establishes a session without a visible message (calls, prewarm). No row, no bubble, no receipt |
| `sender-key-distribution` | `skdm` | `skdmTransport: 3` |
| none | `chat` / `file` | ordinary messages |
| `ratchet-reset` | — (not ratchet-encrypted; signed control, §5.5) | |
| `session-hello` with the key **`ctl`** and NO `text` (level 2, §V3.16.3) | `react` / `nearby` | the control carrier. A 1.0.0 client drops a `p2p-message` without `text` before its ratchet; a 1.0.0 SERVER already treats `session-hello` as session control (stored offline, block-filtered, no push, no contact auto-add) |

#### V3.3.7 Session state JSON (native-only, sealed)
```json
{"v":3,"role":"init|resp","sid":"<b64>","ad":"<b64 140>",
 "rootKey":"…","myDHPub":"…","myDHPriv":"…","prevMyDHPub":"…|null","peerDH":"…","peerEk":"…|null",
 "sendChainKey":null,"sendCount":0,"recvChainKey":null,"recvCount":0,"prevSendCount":0,
 "skipped":[{"dh":"<b64>","n":5,"mk":"<b64>","at":1790000000000}],
 "x":{"ik":"…","ed":"…","ek":"…","spk":17,"opk":118},
 "peerIk":"<b64>","peerEd":"<b64>","createdAt":1790000000000,"confirmedAt":null}
```
`prevMyDHPub` is the send ratchet key before the last DH step (for §5.5). `ad` and `x` let the Share Extension encrypt on an `initiating` session without any identity key. `RatchetState::deserialise` (RN import) is deleted; `serialise/deserialise_v3` are strict.

**Level 2.** A hybrid session writes two more keys, each ONLY when present: `"pq":true` (top level, last) and `x.kem` `{"id","ct"}` (while initiating). A classical session's JSON is therefore byte for byte what 1.0.0 writes and reads (`compat_353.rs` proves it both ways); a 1.0.0 client, strict at rest, drops a hybrid row — after a rollback those sessions come back classical through the signed reset. `x.kem` without `pq` is not a state.

**The aux (level 2; NOT part of the session JSON).** One opaque string per peer, kept by the host beside the session rows and written in the same transaction:
```json
{"v":1,"s":{"<sid b64>":{"r":["<b64 8-byte prefix of a retired peer ratchet key>",…],"l":<lossy run>}}}
```
`r` = the last 64 peer ratchet keys the session moved past (§V3.5.4); `l` = lossy steps sent since the last universal one (§V3.16.3). An unreadable aux is an empty aux; entries of sessions no longer in the set are dropped on load; a host that passes none gets 1.0.0 behaviour. iOS: sealed kv scope `session-aux`, key `<peer uid>`. **Session rows and the aux MUST NOT be restorable from a backup or a device-to-device transfer** (iOS: `accounts/` is excluded; Android MUST exclude them in `dataExtractionRules`): a restored ratchet state silently sends on retired keys.

#### V3.3.8 Skipped keys
`MAX_SKIP_PER_MESSAGE = 1000` (unchanged); `MAX_SKIPPED_TOTAL = 2000`: inserting beyond it evicts the oldest; `SKIPPED_TTL_MS = 14 d`: older entries dropped on load and save. Keys `(dh, n)`, insertion order preserved.

#### V3.3.9 Session identifier
`sid` (32 B) is used for `rb` (§4) and the mesh ACK tag (§9.4). It is NOT used for dedupe.

---

### V3.4 Calls

#### V3.4.1 Precondition
A 1:1 call (caller and callee) MUST have a live session with the peer (`active` or `initiating`). Caller: before `call-start`, if none, run X3DH and send `session-hello`. Callee: `handleOffer` waits up to 5 s for the pending replay to deliver that hello if no session exists, then fails the call `no-session`. A provisional pin (§2.3) is reconciled first; a peer in `KeyChange` (§5.7) is refused.

#### V3.4.2 Signed payload v2 (byte-exact)
```
payload = fp + "|" + ts + "|" + nonce + "|" + fromUserId + "|" + toUserId + "|" + callId + "|" + type + "|2"
          type ∈ {"offer","answer"}
sig     = Ed25519(ED_signer, UTF8(payload))
rb      = b64(HKDF-SHA256(0^32, sid, UTF8("mrenzo-ratchet-bind-v2|" + payload), 32))
```
Wire fields on `call-offer` / `call-answer` `data`: `type, sdp, sig, ts, nonce, fromUserId, toUserId, callId, pv: 2, rb` (all required). `fp` as today (03 §7.1). `toUserId` and `type` kill reflection (a captured offer cannot be replayed to a third party or as an answer); `callId` binds it to this call.

#### V3.4.3 Verification (replaces the warn-only path)
Order: userId resolution and mismatch (unchanged) → required fields incl. `pv == 2`, `toUserId == me`, `type == frame type`, `callId == current call` → `|now − ts| ≤ 60 s` → fingerprint present → `sig` verifies with the **pinned, confirmed** ED for `fromUserId` (no network on the call path). A signature failure fails the call (`sig`) AND schedules an out-of-band directory reconcile for that uid (§5.7 runs if the directory differs; it is never silent) → `rb`: recomputed over the live session and then each archived session (≤ 4 total); the first match wins; `rb` absent / no session / no match → `ok = false` with `rb-missing` / `rb-no-session` / `rb-mismatch`. `SdpVerification.ok` is the only gate `CallEngine` reads.

Room (group) calls keep signature-only verification with `toUserId = roomId` in the payload; they have no 1:1 session (documented residual).

---

### V3.5 State machine and receive rules

#### V3.5.1 Per-peer states (Signal semantics)
`NoSession` → `Live(sid, initiating|active)` with `Archived[≤3]`; `KeyChange` overlay (§5.7).
- The most recently created or promoted session is live. There is NO tie-break.
- A successful decrypt of a fresh (non-spent) message under an archived session PROMOTES it: it becomes live (`active`), the previous live session becomes archived (`updated_at = now`). A promoted session that we initiated and that was still `initiating` becomes `active` (its `x` is dropped).
- A replay (message-id dedupe, spent `(dh, n)`, `ek` seen-set) never promotes.
- **Level 2 — no demotion.** A successful decrypt under an ARCHIVED session that is classical, while the live session is a hybrid one (§V3.3.1), does not promote it: the archived session's state is saved (it decrypted), the live session stays live, `promoted = false`. Without this an in-flight classical message would undo every lazy post-quantum upgrade. Promotion among sessions of the same kind is unchanged, and a hybrid archived session is promoted over a classical live one (property tests `session_set_property.rs`).
- Convergence: both sides always hold both racing sessions, so every message decrypts; after the race ends, the first message in either direction promotes the same session on both sides within one round trip (property test §16.2).

| Event | From | Action |
|---|---|---|
| Send, no live session | NoSession | Resolve and reconcile the peer pin (§5.2). `GET /api/x3dh/bundle/{peer}`; 404, or an SPK whose signature fails under the pinned ED → the message stays `sending` as outbox `needs-session`, retried with backoff (1 min → 1 h, 7 days), UI «собеседник ещё не обновил приложение». X3DH → `Live(initiating)`, message carries `x` |
| Send | Live | ratchet step; `x` attached iff `initiating` |
| Inbound v3 with `x` | any | §5.3 |
| Inbound v3 without `x` | any | try live, then archived newest first. Success under archived → promote. All fail → failure window (3 in 5 min) → §5.5. No session at all → §5.5 immediately |
| First inbound decrypt under `Live(initiating)` | initiating | → `active`, `x` removed, `confirmedAt` set |
| Signed `ratchet-reset` (§5.5) | any | archive the matching session; the next send re-initiates |
| Key change (§5.7) | any | archive the live session, `resetServed(peer)`, notice; a new session only after the gate passes |
| `peer-key-rotated` | any | fetch the directory now; same pair → ignore; different → §5.7 |
| Archived TTL / cap | — | delete |

#### V3.5.2 Resolving the peer identity (MUST precede every DH)
`fromUserId` (server-stamped, sealed-cert uid, or mesh `from.uid`) selects the `peer_keys` row.
1. Row with both keys → this is the identity. Online path + provisional row → reconcile first (§2.3). A header/directory value that differs → §5.7; the differing value is never used before the gate passes.
2. No row (or empty ED) → online: `GET /api/keys/{uid}`, both keys required, pin `directory`, confirmed. Offline (mesh, backlog without network): the frame goes to the held store (§9.3); nothing is decrypted.
Never take a peer's key from the X3DH bundle, from a Go `User` object, from a prekey header or from a link.

#### V3.5.3 Inbound prekey message (has `x`)
0. **Block filter.** `fromUserId` blocked locally → drop before anything else (no DH, no OPK, no row, no receipt).
1. `x.ik`/`x.ed` == pin (§5.2); differing pin → §5.7 with the message in the held store (§9.3); no pin → §5.2.
2. **Session match.** A live or archived session with `peer_ek == x.ek` → ordinary decrypt on it (the `x` fields stay MAC'd but drive no state); success under archived → promote (§5.1). No such session but `(peer, x.ek)` ∈ seen-set (§2.6) → drop `init.ekReplayed`.
3. `x.spk` ∈ {`spk:current`} ∪ {`spk:old:*`} else drop `init.spkUnknown` + signed reset bound to `env.dh` (§5.5, rate-limited), no receipt.
4. `x.opk` present: the private must exist, else drop `init.opkUnknown` + signed reset bound to `env.dh`, no receipt.
5. Derive SK/AD/sid/RK0; build the responder state; decrypt + MAC + typed parse. Failure → drop `init.macFailed`, counted as one failure. Success → ONE transaction: save the session as live (`active`), archive the previous live session (if any; `session.replaced` logged, shipped, no user notice — same pinned identity, so this is legitimate: a reinstall, a lost DB, or a simultaneous initiation), consume the OPK, add `(peer, x.ek)` to the seen-set, write the message row.
   Replacement now requires DH1 with the pinned `IK`, which only its holder can compute; the old `pn == 0` gate is gone.

#### V3.5.4 Dedupe and edits
Message-id dedupe before decrypt (unchanged). `isSpentPosition` keeps only the `(dh, n)` checks over live + archived sessions; the "fresh init lands on our sid" branch is gone. Edits: §3.5 (`editOf` inside the box).

**Level 2 — stale positions.** The level-1 spent test knows only the CURRENT receiving chain: a duplicate that arrives after one DH step is ratcheted, fails the MAC and is counted — fatal for carriers whose duplicates are normal (a control frame arrives through the WS replay AND the HTTP backlog). Two lines of defence:
1. the host dedupes by id before the ratchet — `(peer, messageId)` for messages (rows and tombstones) and for control frames (`ctl_seen`, 30 days). The key includes the PEER, so another contact cannot pre-empt somebody's id;
2. the core remembers, per session, the last 64 peer ratchet keys it retired (the aux, §V3.3.7). `open` order for one session: (a) `(dh, n)` in `skipped` → open with that key; (b) `dh == peer_dh` and `n < recv_count` → **stale**; (c) the 8-byte prefix of `dh` in the retired list → **stale**; (d) otherwise the chain walk or DH step, **failed** when the MAC does not verify. After a DH step every position of the retired chain that can still arrive is in `skipped` (the walk to `pn` ran first), so (c) can only hit a replay, a forgery, or a late message whose skipped key expired.

`is_stale(wire)` is the same test without touching the state (the guard before the ratchet on `ctl`, `ptt-start` and edits).

#### V3.5.5 Signed ratchet reset (replaces WS `ratchet-reset` / `peer-ratchet-reset`)
```json
{"type":"p2p-message","data":{"toUserId":P,"messageId":"rr-<uuid>","action":"ratchet-reset",
  "rr":{"v":2,"ts":1790000000000,"nonce":"<b64 16>","dh":"<b64 32>","sig":"<b64 64>"}}}
canonical = "mrenzo-ratchet-reset-v2|" + from + "|" + to + "|" + ts + "|" + nonce + "|" + dh
sig       = Ed25519(ED_from, UTF8(canonical))
```
`dh` = the `dh` of the envelope that could not be decrypted (the sender's ratchet public key at that moment).
Receiver: `from` = server-stamped `fromUserId`; pin required and confirmed (no pin / provisional → ignore); verify `sig`; `|now − ts| ≤ 10 min`; nonce not among the last 32 seen for that peer; then archive the LIVE session whose `myDHPub` or `prevMyDHPub` equals `dh` — any other value is a no-op (`reset.noMatch`, logged). The next send re-initiates through X3DH.
Sender rules: after 3 failures in 5 min under the live session, or when a v3 message arrives and there is no session at all, or on `init.spkUnknown` / `init.opkUnknown`; at most one per peer per 5 minutes; the sender also archives its own live session when the failing envelope came through it.
Why no loop: the peer's replacement session has a fresh `myDHPub`, so a second reset carrying the old `dh` matches nothing. The typed frame `peer-ratchet-reset` no longer exists on the server and is ignored by the client.

#### V3.5.6 Failure counting
Counted: a v3 envelope that fails the MAC under every candidate session, and `init.macFailed`. Not counted: `notEnvelope`, `rejectedLegacy`, throws, `init.spkUnknown`, `init.opkUnknown`, `init.ekReplayed`, replays, held frames. Threshold and window unchanged (3 / 5 min).

**Level 2 — the outcomes of `open`** (`PeerSessionSet.open` / `respond_and_open`; `unsupportedV11.json`). Precedence over the candidate sessions: typed / unsupported > stale > tooManySkipped > failed.

| Outcome | Meaning | Ratchet | Counted |
|---|---|---|---|
| `typed` | MAC valid; a kind this build knows | advanced | — |
| `unsupported {raw, t, id, alt, caps}` | MAC valid, box opened, but not a typed plaintext this build understands | advanced, exactly as for `typed` (a responder session is installed, the OPK and the KEM one-time key are consumed) | **never** |
| `stale` | a position this set already used, or a ratchet key it retired (§V3.5.4) | unchanged | **never** — except by the unknown-id rule below |
| `failed` | MAC failure under every candidate session | unchanged | yes: the ONLY counted outcome |
| `noSession`, `needsResponder`, `tooManySkipped` | as in level 1 | unchanged | no |
| `internal` | the core caught a panic of its own (§V3.21) | unchanged | **never**; never buffered |

What the host does, by carrier:

| Outcome | `text` (also sealed, mesh `msg`, backlog) | `skdm`, `message-edit.newText` | `ctl`, `ptt-start.wire`, mesh `ptt` / `ctl` |
|---|---|---|---|
| `typed`, outer agrees | as level 1 | as level 1 | apply |
| `typed`, outer disagrees | roll back, `notEnvelope` | same | same |
| `unsupported`, `id` equals the outer id | commit the step; ONE notice row under that id, state `unsupported`: «Сообщение не поддерживается этой версией mr.enzo. Обновите приложение.» (`alt` above it when present); STORE `raw` with the row, sealed like a message body; `message-delivered` / the mesh ACK; record `caps` | commit the step; show and change nothing | commit the step; mark the frame id seen; show nothing |
| `unsupported`, `id` missing or different | roll back, `notEnvelope` | same | same |
| `stale` | drop: no row, no placeholder, no buffer | drop | drop |
| `failed` | as level 1 (counted, pending-decrypt buffer) | as level 1 | drop, log; **not counted, no reset, no buffer** |
| `noSession` | as level 1: drop, and the signed reset bound to `env.dh` (§V3.5.5) | as level 1 | the same — drop, and the signed reset. Not a count: no duplicate and no reordering produces «no session at all», and a reset naming a retired key is a no-op for the peer. Without it a peer that lost its sessions stays unreachable for reactions and push-to-talk until an ordinary message arrives |
| `internal` | drop, log the frame id | same | same |

- **The notice is not a dead end.** The step is spent, so the sender cannot be asked again; the plaintext survives on the receiver. On the first launch after the app version changed the host runs `typed_plaintext_classify(raw)` over its `unsupported` rows and replaces, in place, every row that is `typed` now (same id, same position). For a `newer` envelope (§V3.3.4) it kept the wire and retries `open`. Retention follows the chat (deleted with it, tombstoned on delete-for-everyone, the disappearing timer applies), at most 90 days.
- **The unknown-id rule.** A true duplicate always carries an id the host knows. A `stale` result in `text` whose outer `messageId` is known NOWHERE (no row, no tombstone, no `ctl_seen` entry) marks a peer whose session state went backwards: three DISTINCT such ids from one peer within 5 minutes archive the live session and send the signed reset (§V3.5.5), under the one-per-5-minutes limit.
- **Why control carriers never count:** every control kind is redundant state (a reaction register is re-sent on its next change, a transmission is over, a nearby exchange times out) and its delivery paths legitimately duplicate and reorder. A really broken session shows itself on the next ordinary message.

#### V3.5.7 Key change gate (unmissable)
Trigger: for a peer with a pinned `(IK, ED)`, any source (directory fetch on send or call, `peer-key-rotated` refetch, prekey header, scan payload, the §2.3 reconcile of a provisional or migrated pin) presents a different pair.
1. Confirm against the directory with a NETWORK fetch made now (a header or a QR alone never changes a pin). Offline → hold (held store), no change.
2. Directory agrees with the new pair: archive the live session, `GroupSendCore.resetServed(peer)` + rotate our group chains where that peer is a member (§7.4), invalidate `PeerKeyCache`, insert the system row «Код безопасности изменился · Проверить» (existing `KeyRotationNotice`, debounced), show a persistent banner in the chat header (not a toast), and:
   - peer verified (`safety/verified:<uid>` exists): status `changed`. Sending, calling and answering are BLOCKED until the user taps «Принять новый ключ» on the banner or the safety-number screen. Accepting DELETES the verified record (the peer becomes unverified), pins the directory pair, clears the banner and resumes sends on a fresh X3DH session. `verified` is regained only by a fresh number comparison (§6). One tap never verifies.
     1.1, «Проверить лично снова»: the one other way out of the block, and the only one that keeps the peer verified. The user scans the peer's safety-number QR in person; then, in ONE transaction: re-read the pending directory pair (absent or not blocking → nothing); compute the §6 number over our pair and THAT pair; if the scanned 30 digits are not that number → nothing is written, the gate stays; if they are → exactly the «Принять новый ключ» writes (pin the pair, drop sessions of the old identity, clear the gate, clear what was learned about the old identity — capabilities and sticky `pq` included) and the verified record `{safetyNumber: the new number, verifiedAt, method: "qr"}`. The comparison is made against the pair read inside the transaction, never against a number computed earlier, so a second directory change in between cannot pin a pair nobody compared. No wire element: it works against a 1.0.0 peer, whose QR is the same 30 digits.
   - peer unverified: pin the new pair immediately (source `directory`, confirmed), banner stays in the chat header until the user taps «Понятно» or opens the safety-number screen; sends continue on a fresh X3DH session (TOFU by design, documented).
3. Directory disagrees with the presented pair (a header or QR the directory does not confirm): drop the message / refuse the pairing, log `keys.presentedMismatch` (shipped). Nothing changes.
The Share Extension never runs this gate (§11): anything that is not a plain ratchet step becomes `needs-session`.

#### V3.5.8 Multi-device, reinstall, takeover
- One device per account (takeover model, 03 §2.8) — unchanged; no session fan-out.
- Reinstall with the Keychain identity kept: sessions and prekeys are gone. §2.2 resets the pool and mints an SPK. Peers' messages arrive without `x` and find no session → signed reset bound to their `dh` → they re-initiate. Their pins of us are unchanged, no notice anywhere.
- Takeover / new identity: `key-rotated` → peers run §5.7 (verified peers block). Our device starts with an empty `sessions` table.
- Restore from backup on a new phone: identity from the backup (03 identity_backup); stale sessions resolve through §5.5.

---

### V3.6 Safety numbers v2
```
K_me   = IK_me(32) ‖ ED_me(32);  K_peer = IK_peer(32) ‖ ED_peer(32)
(x, y) = bytewise sort of (K_me, K_peer)
d      = SHA-512(UTF8("mrenzo-safety-v2") ‖ x ‖ y)
blocks = for i in 0..6: zero-pad(BE_uint40(d[5i..5i+5]) mod 100000, 5); number = join(" ")
```
Same 30-digit rendering and QR as today. Pair safety number (offline pairing) = the same construction with `x, y` followed by the two sorted 32-byte seeds. `verified` is written only when the user has compared this number with the peer (typed the peer's first two blocks → `method: "typed"`, or scanned the peer's QR back in the in-person flow → `method: "qr"`, §V3.2.5). Each phone marks from its own comparison only; nothing tells the peer. The number changes for everybody on update; §10.4 migrates verified records.

---

### V3.7 Groups (Sender Keys v2)

#### V3.7.1 SKDM v2
Inner plaintext `t:"skdm"`, `body = {"v":2,"groupId":"<id>","chainKey":"<b64>","signingPub":"<b64>","startCounter":N,"from":<uid>}`. Transport `{"type":"p2p-message","data":{"toUserId":M,"messageId":"skdm-…","action":"sender-key-distribution","skdmTransport":3,"skdm":"<v3 ratchet wire>"}}`. `skdmTransport ≠ 3` or `v ≠ 2` → rejected, not counted.
Receive: decrypted under the sessions with `fromUserId` (§5.1); `body.from == fromUserId`; the chain is stored under `recv2:<g>:<fromUserId>`. A `signingPub` already stored under ANOTHER sender of that group → reject `skdm.dupSigningPub` (defence in depth: without the private it could never post, but it must not shadow the real owner).

#### V3.7.2 `sk2` post envelope
```
envelope       = {"v":2,"ctr":N,"n":"<b64 24>","ct":"<b64>","sig":"<b64 64>"}
signed payload = UTF8("mrenzo-sk2|" + groupId + "|" + senderUid + "|") ‖ BE64(ctr) ‖ ct
```
`senderUid` = the server-stamped sender of the `channel-message`; `groupId` = the channel the post arrived in. The receiver rebuilds the payload from those two values, never from the envelope. `sk1` (`v:1`) is rejected, not counted. Plaintext = what the sender's `GroupSendCore.seal` is given: the raw message text, or the FileEnvelope JSON of §8.3 for an attachment — NOT the typed plaintext of §3.5 (an earlier revision of this section said so; no build ever sealed one, and the outer `messageId` of a post is assigned by the server after sealing).
Attribution chain: `sk2` signature (over group + sender) → chain `signingPub` → SKDM → authenticated session → pinned `IK`. A re-posted post under another sender or in another group fails the signature and shows the "undecryptable" placeholder, never a wrong name.

#### V3.7.3 Send
Members with no live session get one through X3DH with the SKDM riding on the prekey message. Members whose bundle is 404 or whose pin is provisional/unconfirmed are skipped for this post and retried by `distributePending` (existing). A member in `KeyChange` (verified, unaccepted) is skipped and the post shows «не доставлено: N».

#### V3.7.4 Chain rotation
The sender keeps `members:<g>` = the member set it last distributed to. Before every post: fetch the list; if any member LEFT (set shrank) or any member's pin changed since (§5.7) → mint a new chain (new `chainKey`, new signing keypair), `resetServed(g)`, distribute to the current members before the post. A member added by the server is served on the next post as today (residual: the server can add a reader; it is visible in the member list).
Chain KDFs, previous-chain sets and walk budgets unchanged. (Level 2: the chain walk of ONE envelope is bounded at 2000 steps inside the primitive too — it used to rely on its callers, and a counter at 2^53, where `i + 1 == i`, would have spun for ever.)

#### V3.7.5 Posts of a newer build (level 2)
A channel message whose text starts with `sk<N>:` where `N` is 1..9 decimal digits without a leading zero and `N > 2` comes from a newer build: the host shows «Сообщение отправлено более новой версией mr.enzo. Обновите приложение.» and keeps the raw text for a retry after an update — never plaintext, never «не удалось расшифровать» (`sender_key_receive_batch_v11` → `NewerVersion`). `sk1:` and unprefixed text stay what they are in level 1 (the undecryptable placeholder).

#### V3.7.6 Reactions in rooms and channels (level 2; `reactions.rs`, `reactGroupV1.json`)
A reaction on the reactor's own Sender-Keys chain would make every reacting subscriber a sender to every other subscriber (an SKDM fan-out per reaction, and a chain every 1.0.0 member would have to walk). Instead a reaction is sealed under a key bound to the POST, derived from material every reader of the post already has:
```
mk   = HKDF(ck_ctr, "mrenzo-sender-msg")                     the post's existing message key
rk   = HKDF(mk, "mrenzo-sender-rx-v1")                        post reaction key
k_u  = HKDF(rk, UTF8("mrenzo-grx-v1|" + groupId + "|" + postId + "|" + reactorUid))
blob = "rx1:" + b64( nonce(24, random) ‖ secretbox(k_u, nonce, UTF8(react JSON)) )        ≤ 1024 bytes
react JSON = {"t":"react","id":"rx-<uuid>","to":"<postId>","e":[…],"ts":…,"p":"…"}        the rules and the padding of §V3.16.4, no caps
```
- `rk` is derived when a level-2 client SEALS a post (from the chain key it is about to use: `sender_key_post_reaction_key`) or OPENS one (from the message key, also one taken from the skipped-key store) and is stored sealed beside the post's cached plaintext; it is deleted with it (delete-for-everyone, leaving the room, account wipe). Posts cached before the update have no `rk` and cannot carry reactions.
- Cost O(1): no SKDM, no member fetch, no chain step. A 1.0.0 member never calls the reaction routes and ignores the `channel-reaction` frame; ITS posts can be reacted to (every reader holds their `mk`).
- Receiver: the row `(channelId, messageId, userId, blob)` → `k_u` from the row's `userId` → open → strict `react` parse → `to == messageId` → last-writer-wins per `(room, post, user)` (§V3.16.4). A removal is a blob whose `e` is empty — the server cannot tell it from an add, nor one emoji from another or from three: by the padding rule of §V3.16.4 every blob one user writes for one post has ONE length (it varies only with the length of the ids). A row re-attributed to another user, post or group does not open. Rows are fetched BY POST when posts are opened without local reaction rows (`GET /api/channels/{id}/reactions?messageIds=`), so a new device or an old page still gets them.
- **Attribution, stated plainly:** it rests on the server-stamped `userId` and on possession of `rk`. A malicious server alone can only withhold or replay a user's own older blob. A malicious server TOGETHER with a member can forge another member's reaction on posts that member can read. That is weaker than the `sk2` signature of a post and is accepted for emoji; signing with identity keys would need every subscriber to pin every other one.

---

### V3.8 Server API changes (minimal)

#### V3.8.1 Go
| Endpoint | Change |
|---|---|
| `GET /api/x3dh/bundle/{uid}` | Response `{"userId":N,"signedPreKey":{"keyId","pubKey","signature"},"oneTimePreKey"?:{"keyId","pubKey"}}`. `identityKey`/`signingKey` REMOVED. `Cache-Control: no-store`. **Hand-out budget:** per target ≤ 30 OPKs per hour across all requesters — above it the bundle is served WITHOUT an OPK (nothing is popped); per (requester, target) pair 3 per hour → 429; per requester 60 per minute unchanged. Self-fetch exempt |
| `POST /api/x3dh/otps` | `INSERT … ON CONFLICT(user_id, key_id) DO UPDATE SET pub_key = excluded.pub_key`. Pool cap 500 per user → 413 above |
| `POST /api/x3dh/spk`, `DELETE /api/x3dh/otps`, `GET /api/x3dh/otp-count` | unchanged (the SPK signature is opaque to the server) |
| WS `p2p-message` with `action ∈ {ratchet-reset, sender-key-distribution, session-hello}` | routed and stored offline like any p2p-message, NO APNs alert, not counted as a chat for contacts auto-add. `ratchet-reset` and `session-hello` are subject to the block filter like ordinary messages (only `sender-key-distribution` keeps its group exemption) |
| WS `{"type":"ratchet-reset"}` → `peer-ratchet-reset` | removed |
| `call-offer` / `call-answer` | relayed unchanged; the server does not validate `pv`/`rb` |

#### V3.8.2 Python storage
| Endpoint | Change |
|---|---|
| `POST /api/keys/publish` | `publicKey`, `signingPublicKey`, `signature`, `ts` all REQUIRED; both keys strict base64 → 32 bytes; `\|now − ts\| ≤ 5 min`; signature must verify → else 400/401. Unsigned and X25519-only branches deleted. **Uniqueness:** a `publicKey` or `signingPublicKey` already published by a different uid → 409 `key-in-use` (unique indexes on both columns; a uid re-publishing its own pair is fine) |
| `GET /api/keys/{uid}` | unchanged |

No server-side session state; nothing to migrate on deploy. Pending offline `v:2` envelopes become `rejectedLegacy` placeholders on updated clients.

---

### V3.9 Mesh v2

The frame, its routing and the level-2 receive pipeline are specified in `04-mesh.md` («Mesh v2» and «Mesh at level 2»). This section owns the cryptography.

#### V3.9.1 Frame and binding
Outer `{"v":2,"id","ttl","hops","L"?,"mode","ts","b"}` (level 2: plus the optional `c`, §V3.9.5); inner blob layout unchanged. Binding v2 (signed with `ED_from`, verified against the embedded `sig_pub`, which MUST then equal the pinned ED):
```
"mrenzo-mesh-v2|" + id + "|" + ts + "|" + from.uid + "|" + to + "|" + (toIdx or "-") + "|" + ttl + "|" + (L or "-") + "|" + mode + "|" + kind + "|" + payload
kind ∈ {msg, ack}                  level 2: or the NAME of a named kind (flags bit 0x80: payload = BE8(nlen) ‖ name ‖ body, name ^[a-z0-9]{1,8}$)
payload in the binding = the ACK text; for every other kind the canonical base64 of ALL payload bytes
```
`ttl`, `L`, `mode`, `toIdx` are set by the originator and MUST NOT be changed by relays (only `hops` is mutable and stays outside the binding; a relay counts its hop budget in `hops`, 04 «Mesh at level 2». Builds 349–353 rewrote `ttl` / `L` when relaying and so broke every copy they re-emitted). `to` is always 0 on the air. `v:1` frames are dropped at unpack. Message payload = padded v3 ratchet wire (the prekey header travels inside it).

**Level 2 — the names `msg` and `ack` are reserved.** A named frame called `msg` would produce exactly the level-1 binding string, so a 1.0.0 client would VERIFY it and hand its payload to the pipeline; a named frame called `ack` over payload `P` carries a signature that is also valid for a real ACK whose text is `base64(P)` (`compat_353.rs` shows both). Every builder and the frame check reject them. With that, a 1.0.0 client fails the signature of every named frame.

**Level 2 — the signature is verified STRICTLY** (RFC 8032: canonical `S`, no small-order key), on the one canonical encoding of the frame: no duplicate JSON key, integers that are integers, canonical base64, flags exactly `0x03` (`msg`), `0x08` (`ack`), `0x80` / `0x82` (named), no byte after the signature. Level 1 verified like tweetnacl (a re-encoded `S` passes) and ignored trailing bytes, which let anyone mint a second encoding of somebody's signed frame. Every frame a level-1 client originates is canonical.

#### V3.9.2 Receive (act-paths: messages addressed to me, ACKs)
1. The strict frame check (`mesh_frame_check`): canonical form, the profile of the kind, the signature over the v2 binding, the replay window (25 h / +5 min). NOTHING is recorded as seen for a frame that fails it; the duplicate key of a valid frame is `b64(SHA-256(inner blob)[0..16])`, not its id.
2. «Addressed to me» = `toIdx` equals the tag computed with the cached identity key OF `from.uid` (04 §8) — sender-bound, not «any key I know». A sender whose identity key this device has not cached cannot address it at all: there is nothing to hold, and first contact over the mesh needs an in-person scan or one online lookup of that uid.
3. Sender binding: `peer_keys[from.uid].signing_public_key` MUST exist (confirmed or provisional) and equal `sig_pub`. Different → drop `recv.sigPubMismatch`. Missing while the identity key IS cached (a row without a signing key) → §9.3 for `msg`, drop for everything else.
4. `msg` for me: unpad ALWAYS, hand to the pipeline; §5.2 then requires the pinned `IK` for `from.uid` (a first-contact prekey header must match it), so a nearby radio can only deliver under an identity it holds.
5. Relayed (not for me) pigeon frames: stored regardless of pins — except that a `from.uid` this device HAS pinned must carry the pinned `sig_pub`.

#### V3.9.3 Held store (one store for every "cannot act yet" frame)
kv scope `held`, key `<uid>:<frameId>`, value = the raw frame + `reason ∈ {no-pin, key-change, offline}` + `receivedAt`. Per-uid cap 8, total 128 (oldest evicted per uid first, then globally), TTL 7 days. Sources: a mesh `msg` addressed to me from a uid whose row has no signing key (§9.2 step 3); a WS/backlog frame from an unpinned uid while offline; a prekey message whose header mismatches the pin while §5.7 is unresolved. A named frame (`ptt`, `ctl`) is never held.
Release: when a confirmed pin for that uid appears (directory fetch, in-person pairing) or the §5.7 gate resolves, every held frame of that uid is re-run through §9.2 / §5.3 in `receivedAt` order.

#### V3.9.4 ACK
**The tagged ACK (level 1; still sent to a level-1 author).** Payload = `id + "." + b64(HMAC-SHA256(k_ack, UTF8(id)))[..16]` with `k_ack = HKDF-SHA256(0^32, sid, "mrenzo-mesh-ack-v2", 32)` of the session the message was decrypted under; `from.uid` = the recipient, signed with its identity key.
- Original sender: the delivered tick flips only when `ack.from.uid == message.peer`, the signer is pinned (§9.2), and the tag verifies under one of its own sessions with that peer (live, then archived). Own pigeon copy pruned on that same condition.

**The blind ACK (level 2).** The tagged ACK puts the recipient's uid, its signing key and the acked id on the air, which re-links sender and recipient. The blind form carries none of them:
```
seed    = HKDF-SHA256(0^32, sid, UTF8("mrenzo-mesh-ack-v3|" + id), 32)        sid = the session the message was decrypted under
(sk,pk) = the Ed25519 key pair of seed
frame   = kind ack, flags 0x08, from.uid = 0, sig_pub = pk, payload = b64(SHA-256(UTF8(id))[0..16]),
          ttl 4, mode realtime, no L, a fresh UUID as the outer id, signed with sk over the ordinary v2 binding
```
- **Which form — decided per message:** blind iff the acknowledged PLAINTEXT itself carried `caps.v ≥ 2` (authenticated in the same decrypt; it needs no record, works under a provisional pin, and is right again the moment the author goes back to build 353). A push-to-talk transmission is always acknowledged blind.
- **The form and its 32 bytes are stored with the message** at the first decrypt (the `seed`, or the `sid` for the tagged form) and a duplicate is re-ACKed from those — never from the live session, whose `sid` may be another one by then.
- **Author:** it computes `pk` for `(sid, id)` when it encrypts a message for the mesh and keeps it with the entry; a verified ACK with `from.uid == 0` whose `sig_pub` equals an expected `pk` is the delivery proof — only a holder of `sid` can make it. A level-2 author accepts both forms.
- **A level-1 client hearing a blind ACK** verifies it, finds no pin for uid 0 and does nothing.

**An ACK means something only to the author.** The payload of a blind ACK is a hash of an id that is in clear in the message frame and its key is self-made: anyone in range can produce one that passes the frame check and is indistinguishable from the recipient's to every node but the author (`meshV11.json` `forgedBlindAck`). On a node that is not the author an ACK of either form MUST NOT remove, skip or delay past its expiry any relay-store or courier-store entry. (An earlier revision of this section let a relay prune a copy whose envelope carried `to` in clear; no such frame exists since build 349 and no build ever pruned.)

#### V3.9.5 Courier capsule `c` (level 2; `meshCourierV1.json`)
A `msg` frame may carry one outer key OUTSIDE the binding (a level-1 node must still verify the frame), so that a stranger's phone that reaches the internet can hand the still-encrypted frame to the server without learning the recipient:
```
c     = b64( 0x01 ‖ kid ‖ eph_pub[32] ‖ box[25] ‖ csig[64] )                   123 bytes → 164 characters
box   = crypto_box( pt, nonce, courier_pub, eph_priv )                         X25519 + XSalsa20-Poly1305, as OSB1 (§6)
pt    = 0x01 ‖ BE64(to)                                                         9 bytes; 25 with the tag
nonce = SHA-256( UTF8("mrenzo-courier-nonce-v1") ‖ eph_pub ‖ courier_pub )[0..24]         the ephemeral key is used once
csig  = Ed25519( ED_from, UTF8("mrenzo-courier-v1|" + id + "|" + ts + "|" + from + "|" + kid + "|"
                               + b64(SHA-256(inner blob bytes)) + "|" + b64(SHA-256(eph_pub ‖ box))) )
```
- **`csig` is outside the box and EVERY node checks it** — strictly, under the frame's own `sig_pub`; no secret is needed. A `c` that is not canonical base64 of exactly these 123 bytes with the version byte `0x01`, or whose `csig` does not verify, is ABSENT: the frame stays valid (a relay that mangles `c` cannot stop the radio delivery), but the capsule is neither stored nor relayed. **Reason:** `c` is outside the binding, so without a signature of its own anybody in range could attach a capsule to somebody's valid frame; a courier that had stored that one first would hold the junk in place of the sender's, and the server would reject the upload — one nearby device could switch off courier delivery of every message it hears.
- **The check runs at every door of the core, and a verified capsule belongs to its frame.** Not only `mesh_frame_check` applies it: the 1.0.0-shaped unpack returns a capsule only when `csig` verifies, a stored queue entry is read back the same way, and the pack and queue-write functions drop a `courier` that is not the signer's capsule for exactly that frame — so no path, old or new, takes a capsule that is merely of the right shape from the air into a store or back onto the air. And a relay remembers the capsule it verified (04 L2.3): once known, every copy of the frame it emits carries it, also when the copy that triggers the emission came without one (a 1.0.0 re-flush, a stripped copy).
- `csig` is also what stops re-addressing: the courier key is public, so anyone can seal a recipient, but only the sender can sign the sealed bytes together with the hash of the inner blob. The recipient uid itself is inside the box; the signed string names nothing an observer does not already see.
- The server, in this order: the strict frame check (which includes `csig`) → kind `msg` → `kid` known → the box opens → `to` in `[1, 2^53)` → freshness → `sig_pub` is the directory key of `from` → claim `H(from|id)`; then it routes `{"toUserId","messageId","text":<the unpadded envelope>,"encrypted":true,"transport":"mesh-courier"}` as if `from` had sent it (no `type`, no `action`).
- A level-1 node does not see `c`.

---

### V3.10 One-time switch on update (build 349 first launch)
DB `user_version` step, one transaction, before any network:
1. `DROP TABLE ratchet_sessions`; `CREATE TABLE sessions` (§2.4); `ALTER TABLE peer_keys` (§2.3). The RN ratchet-session importer is deleted (`RNSessionImport` for auth stays).
2. Group state: delete kv `sender:*`, `sender-v2:*`, `recv:*`, `recvprev:*`, `recvskip:*`, `served:*`, `skdmbase:*`, `ptpending:*`, `ptfail:*`. KEEP `pt:*` and `ptidx:*` (decrypted group history).
3. Outbox: every `p2p-message` / `p2p-sealed` / `message-edit` row is deleted and replaced by one `needs-session` row per `(conversation, messageId)` built from the message row: text → typed plaintext; media → `FileEnvelope` from `fileInfo`, `fileKey`, `fileNonce`, `mimeType`, `fileName`, `fileSize`, `duration`; edits → `t:"edit"` with the row's current text. Rows stay `sending`; the app re-encrypts on the first socket open after establishing sessions.
4. **Pins and verified records.** Every existing `peer_keys` row gets `source='directory'`, `confirmed_at = NULL` (provisional: it must be reconciled with the directory before online use, §2.3 — one fetch per peer on first online use, verified peers first, in the background on the first socket open). Verified records: row with both keys → rewrite `safetyNumber` as the v2 number from the cached pair (the first reconcile fires §5.7 in its blocking form if the directory disagrees); row with an empty ED → delete the verified record and insert the system row «Подтвердите код безопасности заново» (l10n `native.safety.reverify`) — never repaired silently. Log `safety.migrated {kept, dropped}`.
5. Mesh pigeon queue and `ackedIds` cleared.
6. `x3dh`: delete EVERY row except `nextKeyId`; set `opkPoolResetPending=1`, `opkRefillPending=1`; a fresh SPK (v2 signature) is minted on the first run.
7. `rotation-seen/*` kept.
Untouched: Keychain identity, `conversations`, `messages`, `drafts`, `channel_meta`, blocks, Избранное (`SavedMessages`), `peer_keys` key columns.

---

### V3.11 Share Extension (G8)
- Reads: the session DB (via the DB key from the Keychain, as today), `peer_keys`, `sessions`. Never K2/K3, never `x3dh`.
- Writes: message rows, outbox rows, session `state`/`updated_at` of the session it stepped (under the file lock). NEVER `peer_keys`, NEVER session `status`, NEVER `safety/*`, NEVER the held store.
- Send on a peer with a live session (`initiating` or `active`) and a confirmed pin: `DirectSend.commitText` / `ratchetStep` under the file lock; AD and, for `initiating`, the `x` header come from the state (§3.7).
- Anything else (no live session, archived-only peer, provisional or missing pin, pending key change): the extension writes the message row (`sending`) and an outbox row `type = 'needs-session'`, `transport = 'ws'`, frame = sealed JSON `{peer, messageId, kind, plaintext | fileEnvelope}`; media are still encrypted and uploaded by the extension (file keys are per-file). Outcome `.pending`. The app drains `needs-session` rows on socket open: reconcile pin → X3DH → ratchet step → real frame → send.
- `acceptVerifiedChange` in the extension is removed.
- Group posts: unchanged, except members without a live session are left for `distributePending`.

---

### V3.12 Pairing

#### V3.12.1 Links carry no keys
`mrenzo://pair/<base64url({"v":2,"uid":N,"username":"…"?})>`. Opening a link → online lookup (`GET /api/users/{uid}` for the profile, `GET /api/keys/{uid}` for the pin, source `directory`, confirmed) → the ordinary "add contact" sheet. Offline → «Нужна сеть, чтобы добавить контакт по ссылке». A link never pins, never verifies, never overwrites. `v:1` links → invalid.

#### V3.12.2 Scan payload v2 (QR only)
`{"v":2,"uid","username"?,"displayName"?,"ipk","spk","seed","ts","sig"}`, `sig = Ed25519(spk-secret, UTF8("mrenzo-pair-v2|" + uid + "|" + ipk + "|" + spk + "|" + seed + "|" + ts))`. `v:1` → invalid. Validation: shapes as today plus the signature.

#### V3.12.3 Confirm (scan)
1. Existing `peer_keys` row with a different pair → refuse: «Сохранённый ключ этого контакта отличается», button to the key-change screen (§5.7 with the directory when online). Never overwrite.
2. Online → `GET /api/keys/{uid}` must equal the payload pair; mismatch → refuse (`pair.directoryMismatch`); equal → pin `directory`, confirmed.
3. Offline, no row → pin `source = pair-scan`, `confirmed_at = NULL` (provisional, §2.3): usable for the offline-pair conversation and mesh; reconciled with the directory before any online use.

#### V3.12.4 Verified
`markVerified` only when the user entered the peer's first two 5-digit blocks of the mutual pair number (or scanned the peer's QR back, which carries the mutual number). It may be set while the pin is still provisional — the in-person comparison IS the verification; a later directory mismatch then fires §5.7 in its blocking form.

#### V3.12.5 UI
A provisional contact shows the badge «ключ не подтверждён сервером» in the chat header and on the profile until `confirmed_at` is set.

---

### V3.13 Sealed sender
`verify_cert`: `uid` and `expires_at_ms` MUST be JSON integers in `[0, 2^53)`; parse each once as `i64`; the same values feed `now_ms > expires_at_ms` and the signed payload `BE64(uid) ‖ BE64(exp) ‖ ASCII(sender_pub)`. Any other JSON shape → `false`. The Go issuer is unchanged.

---

### V3.14 Downgrade surface (must all be rejected, each with a test)
`v:2` envelope · envelope without `mac` · `x` stripped or added by a relay (MAC covers `xflag`) · outer `messageId` ≠ inner `id` / `editOf` · outer `action` disagreeing with inner `t` · prekey header `spk` outside {current} ∪ {old} · `opk` unknown · `ek` replay (seen-set) · identity taken from a bundle / header / link / Go user object · unsigned or half `keys/publish` · a key already published by another uid · `pv`, `rb`, `toUserId`, `type` or `callId` missing on `call-offer`/`call-answer` · `rb` matching no session · `skdmTransport ≠ 3` / SKDM `v ≠ 2` · `sk1` / `sk2` with wrong group or sender · duplicate `signingPub` across senders · mesh `v:1` · mesh frame from an unpinned signer · mesh frame with a relay-modified `toIdx`/`ttl`/`L`/`mode` · ACK without a valid tag · pair link with keys or `v:1` · scan payload with a bad `sig` · typed `peer-ratchet-reset` · unsigned `ratchet-reset` · `ratchet-reset` whose `dh` matches no live session (no-op) · `session-hello` / prekey message from a blocked uid · legacy `initAsRecipient(identityPriv, …)` (deleted).

**Level 2, additionally:** `x.kem` stripped or added by a relay (the MAC covers `xflag 2`, the id and the ciphertext) · a KEM prekey signed under another label, kind or id, by another identity, or failing the modulus check · a hybrid header answered without its seed, or with the seed of another key or kind (another session: the MAC fails) · a classical bundle served for a peer that is sticky-`pq` (refused and retried, §V3.17) · a level-2 kind in `text`, `newText`, `skdm`, a sealed blob or a mesh `msg` (mismatch; and the API cannot build it) · a message kind in `ctl` · a `caps` statement that is replayed (older `ts`), post-dated, re-attributed or edited · a duplicate JSON key anywhere in a typed plaintext or a mesh frame · a mesh frame with a number that is not an exact integer, non-canonical base64 or flags, bytes after the signature, a re-encoded `S`, a kind outside its profile, a reserved name · a capsule moved to another frame, re-addressed, or sealed for another `kid` · a PTT chunk under another key, with a reserved flag, non-zero padding or a framing that does not tile · a group reaction row re-attributed to another user, post or group · a push hint that is not sealed to this device.

---

### V3.15 Failure and edge cases
| Case | Behaviour |
|---|---|
| Peer has no SPK / SPK signature fails under the pin | `needs-session` retry with backoff up to 7 days; UI hint |
| OPK pool empty or target budget exhausted | 3-DH init, `x.opk` absent, log `x3dh.noOpk` (shipped); the recipient refills on next foreground |
| OPK consumed / unknown | drop + signed reset bound to `env.dh` (≤ 1 per peer / 5 min); the initiator re-fetches and re-initiates |
| Initiator's 2nd… messages carry the same `x` | matched by `ek` (§5.3.2), decrypted through skipped keys if reordered |
| SPK rotated between bundle fetch and first message | `spk:old:<id>` (30 d) still decrypts |
| Server serves a stale SPK (> 30 d) | `init.spkUnknown` → signed reset → re-fetch; a server that keeps doing it produces «не доставлено», never a session (DoS residual) |
| Simultaneous initiation / server reordering | both sessions kept; promotion on decrypt; converges within one round trip |
| Peer reinstalled (kept identity) | new prekey session becomes live; no notice |
| We reinstalled | pool reset; inbound non-prekey → signed reset bound to its `dh` |
| Verified peer key change | blocked until accepted; accept → unverified; calls refused meanwhile |
| Unverified peer key change | notice row + persistent header banner; sends continue |
| Directory unreachable, no pin | held store; nothing decrypted |
| Directory serves a different ED but same IK | key change (§5.7): SPK signatures, SDP, resets, mesh all fail closed until resolved |
| Server substitutes SPK in the bundle | DH1 mismatch on the responder → init MAC fails → session never forms; «не доставлено», never a MITM |
| Server relabels a frame | MAC fails under the selected peer's sessions; never misattributed |
| Server moves an edit / rewrites a quote | inner `editOf` / `reply` are authenticated; outer mismatch → `notEnvelope` |
| Member re-posts another member's group post | `sk2` signature over group + sender fails → placeholder |
| Member removed from a group | chain rotated before the next post |
| Mesh first contact | held until pinned (§9.3) |
| Relay re-targets a hidden-recipient frame | `toIdx` inside the binding → signature fails |
| Prekey message replay | `ek` matches a session → decrypt-only/promote by spent checks; `ek` in seen-set → drop; `spk` unknown after 30 d → drop |
| Old pending offline message (`v:2`) | `rejectedLegacy` placeholder |
| Outbox after update | rebuilt from message rows (§10.3) |
| Share Extension, no session / provisional pin | `needs-session` → app |
| Skipped-key flood | ≤ 2000 keys / 14 d |
| Migrated pin written by a vulnerable pre-349 path | provisional until the first directory reconcile; verified + mismatch → blocking gate |
| **Level 2.** An authenticated plaintext of a kind this build does not know | `unsupported`: the step is consumed, a notice row that keeps the raw text (re-read after an update), nothing counted (§5.6) |
| A duplicate control frame after a DH step (WS replay + HTTP backlog) | dropped by `ctl_seen`; else `stale` by the retired-key memory; never counted |
| 256 lossy steps in a row (reactions to a peer that went back to 1.0.0, transmissions nobody heard) | `skip-budget`: one `session-hello` with `text` first, then retry (§V3.16.3) |
| The peer restored an old session state (a backup) | its messages are `stale` with ids we never saw: three in 5 min → signed reset |
| A KEM prekey in the bundle does not verify | error `kem-signature` / `kem-invalid`; sticky-`pq` peer → refuse and retry; other peer → classical session, `pq.kemInvalid` shipped |
| A classical prekey message from a sticky-`pq` peer | installed as live (it may really have reinstalled); own PQ re-initiation scheduled; 5 refusals in 24 h → the chat's security row says so (§V3.17) |
| A classical message in flight during a lazy upgrade | opens under the archived classical session; the hybrid one stays live (§5.1) |
| The core panics on a frame | `internal`: dropped, logged, never counted; the session object is dead and still reads back its last committed state (§V3.21) |

---

### V3.16 Capabilities and the control carrier (wire level 2)

#### V3.16.1 The `caps` object
```json
{"v":2,"f":["pq","ptt"]}
```
- `v` — the wire level, an integer in `[2, 65535]`. Level 2 means the sender implements, as a RECEIVER: §V3.5.6 (unsupported and stale are never failures), the control carrier and the kinds `react` and `nearby` (act or ignore), these `caps` rules, both mesh ACK forms, the named mesh kinds and the strict mesh receive pipeline.
- `f` — feature tokens, each `^[a-z0-9][a-z0-9-]{0,15}$`, serialized sorted (byte order), omitted when empty. Level 2 defines `pq` (KEM prekeys are published and confirmed by the server) and `ptt` («Рация» is on and transmissions are accepted).
- Lenient parse: not an object, `v` missing / not an integer / out of range → `caps` absent. Entries of `f` that are not tokens are skipped, duplicates collapse, at most 32 are kept, unknown keys are ignored. `caps` never fails a plaintext. (`typedV11.json` `caps`.)

#### V3.16.2 Where a peer learns it, and what may lower it
1. **In band, authenticated by the session.** A level-2 client attaches `caps` to EVERY typed plaintext it encrypts in a 1:1 session. A 1.0.0 receiver ignores it.
2. **A published statement, authenticated by the pinned identity key** — an optimisation for a peer that has not written since it updated:
   ```json
   {"v":1,"uid":1001,"caps":{"v":2,"f":["pq"]},"ts":1790000000000,"sig":"<b64 64>"}
   canonical = "mrenzo-caps-v1|" + uid + "|" + caps.v + "|" + join(",", caps.f) + "|" + ts
   sig       = Ed25519(ED_uid, UTF8(canonical))          verified STRICTLY under the PINNED ED of uid
   ```
   It carries device and protocol capabilities only (`pq`), never a user setting. Accepted when: canonical shape (≤ 1 KiB, no duplicate key, `caps` sorted and unique), `uid` is the expected peer, `ts ≤ now + 5 min`, `ts` not older than the newest statement already accepted under this pin, and the signature verifies (`capsV11.json`). The server stores it opaque and serves it as one extra field of a response a client already requests — the X3DH bundle (01 §2.5, §6): the answer never depends on who asks, and a client never asks per chat open. (The key directory is served by the storage service, which 1.1 does not change; a client that ever finds the field there verifies it the same way.)
3. **The bounded hello — a MUST, because a server can withhold the statement.** Before its FIRST clear `message-reaction` to a peer whose level it does not know under the current pin, a level-2 client sends ONE plain `session-hello` (ordinary `text` carrier; it carries `caps` like every plaintext). A level-2 client that learns a peer's level for the first time under a pin and has not yet sent that peer a `caps`-bearing plaintext answers with ONE `session-hello`. At most one per side per pin: it cannot loop, and a 1.0.0 peer consumes it silently.

The per-peer record (`peer-caps/<uid>` = `{v, f, at, pinTag, stmtTs, helloSent}`) is written ONLY from those sources, inside the transaction that authenticated them, under a CONFIRMED pin, and is cleared when a key change is accepted:
- `v` is monotonic: the stored level only rises (a peer that really went back to 1.0.0 stays safe by the carrier rule);
- `pq` is sticky until the pin changes (§V3.17); every other flag is «last authenticated wins»;
- the server can withhold a statement and replay an old one — both only delay learning; it cannot forge a level or a flag.

**Provisional record.** A decrypt under a provisional scan pin writes a second record, `peer-caps-prov/<uid>` = `{v, f, at, keyTag}`. It may gate ONLY mesh features (mesh `ptt`, mesh `ctl`), never `pq` stickiness and nothing sent through the server; it is merged when the directory confirms the same key and deleted when it does not.

#### V3.16.3 The control carrier `ctl`
```json
{"type":"p2p-message","data":{"toUserId":1002,"messageId":"rx-9f1c…","action":"session-hello","ctl":"<v3 envelope JSON>"}}
```
- No `text`, no `encrypted`, no `type`. `ctl` = the v3 envelope (§V3.3.4) of a `react` or `nearby` plaintext, at most 8192 bytes; `messageId` equals the inner `id` and is 1–128 characters of `[A-Za-z0-9_-]` (what the server's duplicate claim can key; `encrypt_ctl` refuses any other id). **`text` and `ctl` never travel together:** a level-2 receiver that finds a non-empty `text` treats the frame as a 1.0.0 hello and ignores `ctl`.
- Sender: one transaction — the ratchet step (`encrypt_ctl`), the feature's state row, the outbox frame; a retry re-sends the SAME bytes. Never sealed (`p2p-sealed` has no action field), never from the Share Extension, never in a mesh `msg`.
- Receiver, in this order: block filter → `(fromUserId, messageId)` in `ctl_seen` → drop → not a v3 envelope (`legacy`, `newer`, `notEnvelope`) → drop, no notice row → `is_stale(wire)` → drop → `open` (with a prekey header: the whole of §V3.5.3; where that would put a message into the held store — no pin offline, a pending key-change gate — a WebSocket `ctl` frame is held and released the same way; a mesh `ctl` frame never is):
  `typed` and the outer agreement holds → apply, and insert into `ctl_seen` in the SAME transaction that saves the session; `typed` of a message kind → roll back, drop; `unsupported` with a matching `id` → save the session, mark seen, nothing else; anything else → drop and log. Never counted, never buffered, never a placeholder; a signed reset ONLY where no state is in doubt — `noSession` (this device holds no session with the peer at all) and the unknown-prekey drops of §V3.5.3 — exactly as for a message (§V3.5.6). No `message-delivered`, no row, no unread, no notification.
- **Skip budget.** A receiver walks at most 1000 positions per message. `react`, `nearby`, `ptt` and `edit` are **lossy** (the peer may never decrypt them: a 1.0.0 peer drops `ctl` unread, a transmission nobody heard, an edit the server dropped); `chat`, `file`, `skdm`, `hello` are **universal**. With an aux in use the core counts consecutive lossy steps per session and refuses the 257th with `skip-budget`; the host then sends one `session-hello` with `text` and retries. A universal step resets the run. A `chat` / `file` handed to the server to be sent later («Отправить позже», wire-1.1 §W7.10) is taken through `encrypt_held` and counts as lossy: until its time — or for ever, if it is edited or cancelled — the peer has not got it.
- **Repair.** When a NEW session is installed with a peer, or its level record first appears under a pin, the client re-sends the CURRENT state of every reaction register of that conversation that changed in the last 30 days (one frame each, a fresh `id`, the stored `ts`).

#### V3.16.4 Reactions, 1:1
```json
{"t":"react","id":"rx-<uuid>","to":"<target messageId>","e":["❤️"],"ts":1790000000000,"caps":{…},"p":"   "}
```
- `to` non-empty, ≤ 128 bytes. `e` = the sender's FULL set for that message: 0..3 distinct strings, each 1..64 UTF-8 bytes without control characters, without `"` and without `\`; empty = removed. Whether a string is an emoji the receiver can draw is the host's check against its own table. `ts` = the sender's clock, an integer in `[1, 2^53)`. (`"` and `\` are the characters JSON escapes: without them the JSON text of an entry is exactly its bytes between two quotes, and the length of `e` on the wire is a function of the byte lengths alone. A `react` that breaks any of these rules is `Unsupported`.)
- **Padding: the length does not depend on `e`.** `p` is always written, as the last key, by the builder (`plaintext::build`, `reactions::pad_reserve`). The plaintext is padded as if `e` had its longest legal JSON text, `E_max` = 202 bytes (`["…","…","…"]`, three entries of 64 bytes):
  ```
  len    = UTF-8 length of the plaintext without p
  target = ceil( (len − len(JSON of e) + 202 + 7) / 64 ) × 64          7 = the bytes of ,"p":""
  p      = (target − len − 7) spaces                                   possibly none
  ```
  So an emoji, three long ones and a removal have ONE length for given ids, `ts` and `caps`. Padding to the next multiple of 64 does NOT give that — a sender's base length is constant, so whether a given emoji crosses the 64-byte boundary is deterministic (a ZWJ sequence did, `❤️` did not) — and is not what this level does. A receiver never reads `p`.
- **Register:** last-writer-wins per `(conversation, to, sender)`, ordered by `(ts, id)` with `id` compared as bytes. A receiver applies a state only when it is greater than the stored one, and it compares and stores the sender's RAW values — no clamping (a clamp at receive time would give the later-arriving of two reordered states of a fast clock the larger value). One bound: a state with `ts > now + 24 h` is ignored and not stored. The sender stamps `max(now, its last ts for that register + 1)`. (`react_register_decide`; `reactGroupV1.json` `register`.)
- To a peer of level 1 or unknown level a level-2 client sends the 1.0.0 clear `message-reaction` frames (after the one hello of §V3.16.2). Once a peer has sent one authenticated `react`, its clear frames are ignored until its pin changes.

#### V3.16.5 «Найти рядом» (`nearby.rs`)
| `op` | Fields (strict; `v` is 1) | Carrier |
|---|---|---|
| `invite` | `v, op, ns, exp` | the soft key `nearby` on a visible `t:"chat"` |
| `accept` | `v, op, ns, exp, tok` | `t:"nearby"` in `ctl`, or in a mesh `ctl` frame when there is no socket |
| `token` | `v, op, ns, exp, tok` | same |
| `stop` | `v, op, ns, why?` | same |

`ns` = canonical base64 of 16 random bytes; `exp` = Unix ms in `[1, 2^53)`; `tok` = canonical base64 of 1..2048 bytes (opaque to the core); `why` = `^[a-z][a-z-]{0,15}$`. A field another op owns makes the object invalid; unknown keys are ignored. On a `chat` an invalid `nearby` is absent (the row is plain text); in `t:"nearby"` it makes the plaintext `unsupported`. Proximity is never a verification factor: «проверен лично» is set only by a successful comparison of the safety number (§V3.6).

---

### V3.17 Hybrid sessions: host rules and residuals (wire level 2)
- **Sticky `pq`.** Once a peer is known to speak the hybrid setup under the current pin — from `caps`, a statement, a valid signed KEM prekey in its bundle, or a hybrid prekey message that authenticated — the initiator REFUSES a bundle without a valid KEM prekey for that peer (`pq.bundleStripped`, outbox `needs-session`, the ordinary backoff). For any other peer an invalid KEM prekey is treated as absent (a classical session; `pq.kemInvalid` shipped).
- **Lazy upgrade** of a live classical session = an initiation on a set that already has a live session (the previous one is archived): at most once per peer per 24 h, only with a verified KEM prekey, never during a call. §V3.5.1 «no demotion» keeps in-flight classical messages from undoing it.
- **A classical PREKEY message from a sticky peer is still installed as live** — the peer may really have reinstalled. The host logs `pq.downgradeObserved` and schedules its own PQ re-initiation.
- **What «no silent downgrade» does NOT cover.** Stickiness lives on a device. If one side loses its record (a reinstall with identity restore, an accepted key change), the server can strip the KEM key from both bundles: the side without the record initiates classically, and the side that still holds it installs that message as live. While a peer is sticky-`pq` and the live session with it is classical, the host keeps retrying the PQ re-initiation; after 5 refusals within 24 h it ships `pq.downgradePersisting` and marks the chat's security row. No blocking in 1.1.
- Residuals: first contact is trust-on-first-use for the post-quantum part (a server that withholds the KEM key keeps a first session classical); a last-resort KEM key has no forward secrecy for its post-quantum part until rotated; calls, sealed-sender metadata, OSB1 and the DH ratchet steps stay classical; a group chain distributed to a 1.0.0 member is classically protected.

---

### V3.18 Push-to-talk media (wire level 2; `ptt.rs`, `pttV1.json`)
One transmission = one random 32-byte key `K`, delivered once inside the 1:1 ratchet as `{"t":"ptt","id":"<pttId>","ptt":{"v":1,"k":"<b64 32>","codec":"opus","sr":16000}}` (`pttId` a lowercase UUIDv4; `codec` `^[a-z0-9-]{1,16}$`; `sr` in `[8000, 48000]`; unknown keys of the object ignored), and a run of chunks sealed under it — the same bytes online (`ptt-chunk.data`) and on the mesh (a `ptt` frame, 04):
```
chunk   = nonce(24, random) ‖ secretbox(K, nonce, pt)
pt      = 0x50 0x31 ‖ flags(1) ‖ BE32(seq) ‖ BE16(padLen) ‖ packets ‖ 0x00^padLen           "P1"
packets = ( BE16(len) ‖ packet[len] )*        1 ≤ len ≤ 4096, at most 512 packets; none only with LAST
flags   : bit0 LAST; every other bit 0        len(pt) a multiple of 256, ≤ 16 384; padLen ≤ 255; seq < 4096
```
- `open` rejects everything but that one framing. `K` binds a chunk to its transmission; `seq` inside the box stops reordering and splicing.
- **The end is authenticated.** A transmission is COMPLETE only after a chunk with LAST opened (online: and `ptt-end.lastSeq`, a clear hint, names the same `seq`); anything else is «прервано». The mesh body's LAST bit is a copy that must agree.
- **Sizes say nothing about the speech:** every chunk is padded to a multiple of 256 bytes inside the box.
- **Receiver state** (`PttReceiver`): keys and played sequence numbers are held per `(sender uid, transmission)` — never per bare transmission id, which is in clear on the air — and a number is recorded only AFTER its chunk opened under `K`. The end is final from both sides: after a LAST chunk opened, a higher `seq` or a second LAST is rejected, and a LAST below a number already played is rejected — a complete transmission is exactly `0..=lastSeq`. At most 8 transmissions per sender, 32 in total. The key envelope is opened through the control path (§V3.16.3: `(sender, pttId)` in `ctl_seen`, never counted); after the decrypt the session's peer MUST be the `fromUserId` of the frame.

---

### V3.19 Stickers (wire level 2; `sticker.rs`, `stickerV1.json`)
A sticker is an ordinary encrypted image attachment — `t:"file"`, `kind:"image"`, `image/png` — whose body carries the soft key
```json
"st":{"v":1,"id":"<64 lowercase hex>","pack":"<24 lowercase hex>","e":"😀","w":512,"h":512}
```
`id` = SHA-256 of the canonical PNG bytes; `pack` (optional) names a public pack; `e` optional, 1..64 bytes, no control character; `w`, `h` integers in `[1, 512]`. Any violation → `st` absent → a plain photo. The body around it is the level-1 one unchanged — the FileEnvelope JSON of §8.3 plus `kind`: `{"p":"📎","id":"<fileId>","k":…,"n":…,"m":"image/png","s":…,"kind":"image","st":{…}}` (in a room: the FileEnvelope JSON of the post, with `st` beside its keys). 1.0.0 ignores `st` and shows the photo; a sticker is never sent as a reference without the blob. `pack` is a CLAIM bound to nothing: a receiver shows the pack link only after the user's own tap fetched the manifest and it contains `id`.

So that the server cannot tell WHICH public sticker a blob is by its exact size, the wire copy may carry one private ancillary PNG chunk `mrPd` of zero bytes immediately before `IEND`: padded size = the smallest multiple of 32 768 ≥ canonical size + 12; canonical bytes = the PNG without that chunk. The core walks chunks only (signature, IHDR first, lengths inside the buffer, an empty IEND last, at most one `mrPd` with a correct CRC, ≤ 1 MiB); a receiver verifies `st.id` against the canonical bytes before using a hash-keyed store and checks the decoded size itself.

---

### V3.20 The push hint for the Notification Service Extension (wire level 2; `push_hint.rs`, `pushHintV1.json`)
Hidden chats require «Скрывать отправителя», and such pushes carry no ids. For a push token registered with `"nse":1` the server adds `"mutable-content":1` and, when it knows the sender, one payload key:
```
mz   = "OSB1:" + b64( eph_pub[32] ‖ nonce[24] ‖ crypto_box(hint, nonce, IK_recipient, eph_priv) )        the offline seal of §6
hint = {"from":<uid>[,"mid":"<messageId>"]}  |  {"ch":"<channelId>"[,"mid":"<messageId>"]}
```
Exactly one of `from` / `ch`; a duplicate key, another shape or more than 512 bytes → no hint. A sealed-sender frame carries none. The extension opens `mz` with the identity private key and rewrites the notification. **It MUST NOT read or write session rows or the aux and MUST NOT step a ratchet** (a second process advancing sessions desyncs them); the only core functions it links are stateless: `push_hint_open`, `open_sealed_offline`, `core_version`.

---

### V3.21 Hostile input (wire level 2)
- **No panic is reachable from received bytes** in the core: no slicing without a length check, no `unwrap` on data, no loop or allocation driven by a wire number, no narrowing cast of a wire number, no unchecked arithmetic on a wire integer (`sdp_signing` and `ratchet_reset` computed `(now − ts).abs()` on an `i64` from JSON: an overflow, and in release a wrapped negative that PASSED the window — both are `abs_diff` now). Recursion is bounded so that the deepest accepted nesting fits a 512 KB stack (the sealed-sender JSON parser accepted 512 levels and needed more than that in a debug build: 64 now — one rule for both directions: `seal_envelope` refuses an inner object `open_envelope` would refuse, so a certificate nests at most 63 levels inside the sealed `{cert, ratchet}`; the server's nests one). Measured at the caps on the host (aarch64): the serde-based readers at 128 levels need under 96 KB in a release build and under 320 KB in a debug build; the file-envelope reader under 48 KB / 192 KB. Code that relied on an earlier validator (`expect("validated")`, indexing into a document another function had checked — `compat::json`, `compat::js_number`, `legacy_box`) returns `None` or a total fallback instead; the behaviour on every input the validator admits is unchanged.
- **A stored mesh frame is read as strictly as a received one where numbers are concerned:** `mesh_envelope_from_json` (the pigeon queue, and the RN queue at import) returns nothing when `ts`, `ttl`, `hops`, `from.uid`, `to` or `L` is not an exact integer in `[0, 2^53)`. The record's integer fields would otherwise truncate `7.9` and saturate `-1e300` to the minimum integer, and a queue holds frames relayed from strangers (finding M42).
- **At the FFI every entry point that takes received bytes runs inside `catch_unwind`**, because the generated Swift calls every non-throwing function through `try!` and the server replays a stored frame at every launch. A caught panic becomes: the function's rejection value where nobody counts a rejection; `CoreError.Internal` in a throwing function; the outcome `internal` from `open` / `respond_and_open` — NEVER `failed`, which is counted (that would be a reset loop in place of the crash loop). `panic = "abort"` MUST NOT be set for the FFI crate.
- **A session set cannot be saved half-mutated.** Every mutating call runs on a copy of the state and commits it only when it returned; after a caught panic the object is dead (every later mutating call reports `internal`) while `rows()` and `aux_json()` keep returning the last committed state — never an empty list a host would persist as «delete every session».
- Limits, each enforced before the work they bound: envelope wire 64 KiB; typed plaintext 48 KiB; `ctl` 8192 B; mesh frame 131 072 B; mesh payload 65 535 B; PTT chunk plaintext 16 384 B; `tok` 2048 B; sticker PNG 1 MiB; caps statement 1 KiB; push hint 512 B; JSON nesting 128 (serde) / 64 (sealed sender).
- `native/core/tests/hostile_input.rs` drives every parser with a deterministic mutation corpus (41 000 cases: truncation at every length, bit flips, insertions, duplicated keys, number extremes, type swaps, lone surrogates, deep nesting, megabyte strings, invalid UTF-8) on a 512 KB stack, and asserts both «no panic» and «no mutation of an authenticated field verifies».

---

## 0. Summary for implementers

1. **The crypto stack is NaCl plus HKDF/HMAC.**
   - RN uses tweetnacl for X25519, XSalsa20-Poly1305 (`box`/`secretbox`), Ed25519 and SHA-512, and `@noble/hashes` for HKDF-SHA256 and HMAC-SHA256.
   - **CryptoKit cannot do XSalsa20-Poly1305 or HSalsa20.** Both platforms therefore need libsodium: swift-sodium on iOS, lazysodium or libsodium-jni on Android.
   - CryptoKit remains fine for X25519, Ed25519 verification, SHA-2, HMAC and HKDF (§1.2).
2. **Binary data inside JSON is always standard, padded base64.** RN's decoder throws on the URL-safe alphabet, on missing padding and on whitespace (§1.3).
3. **1:1 text and media** use a Double Ratchet envelope with `v=2`. The envelope is serialised as a JSON *string* and placed in `p2p-message.data.text`, with `data.encrypted: true` (§3.10).
4. **Sealed Sender** wraps that same JSON string, together with a server-signed certificate, in a `crypto_box` addressed to the recipient's identity key. It is sent as `p2p-sealed` with an HMAC delivery token (§5).
5. **Calls** sign the SDP's DTLS fingerprints with the Ed25519 signing key. A ratchet-derived MAC, `rb`, is attached, but a mismatch only logs a warning (§7).
6. **Attachments** use `secretbox` with a random key and nonce per file. The key and nonce travel inside the ratchet-encrypted *file envelope* JSON (§8).
7. **The key directory** is the Python storage service at `/api/keys/*`. It is the **only** authoritative source of peer keys; the Go `users.public_key` column is stale (§2.3).
8. **Three receive-side behaviours keep a mixed RN/native fleet stable.** Getting any of them wrong makes RN peers wipe their sessions (§3.11):
   - deduplicate by `messageId` *before* touching the ratchet;
   - the `pn == 0` fresh-init recovery;
   - the "3 failures in 5 minutes" `ratchet-reset`.
9. **Several RN paths are broken as built:**
   - forwarding sends plaintext;
   - story reactions use the legacy box;
   - RN cannot decrypt ratchet-encrypted edits (it does display legacy-box edits; §3.10.1);
   - group Sender Keys are never distributed.

   See §15 and §16 for what native should do about each.

---

## 1. Primitives, libraries, encodings, constants

### 1.1 Libraries in the field

| Component | Library and version | Where |
|---|---|---|
| RN client | `tweetnacl` ^1.0.3 (1.0.3 installed), `tweetnacl-util` ^0.15.1, `@noble/hashes` ^1.7.1 | `mobile/package.json` |
| Go server | `golang.org/x/crypto/nacl/box`, stdlib `crypto/ed25519`, `crypto/hmac`, `crypto/sha256` | `internal/server/seal.go:9`, `internal/sealedsender/*.go` |
| Python storage | `pynacl==1.5.0` (`nacl.signing.VerifyKey`) | `storage/requirements.txt`, `storage/app/routes_keys.py:7` |

The iOS project contains no native crypto *constructions* (ObjC or Swift). Two native touchpoints exist:

- **CSPRNG.** `MrEnzoRandom.getRandomBase64(n)` in `mobile/ios/MrEnzo/AppDelegate.mm:32-48` wraps `SecRandomCopyBytes` (max 65 536 bytes per call). `mobile/src/polyfills/getRandomValues.ts` installs it as `global.crypto.getRandomValues`, and `mobile/index.js:9` imports that polyfill first, so every `nacl.randomBytes` (keys, nonces, ephemerals) in RN is backed by `SecRandomCopyBytes`.
- **Transport.** `mobile/ios/MrEnzo/MeshModule.m:194` only sets `MCEncryptionRequired` on the Multipeer transport.

### 1.2 Primitive map

| Primitive | tweetnacl call | Exact semantics | libsodium (both platforms) | Apple CryptoKit | Android without libsodium |
|---|---|---|---|---|---|
| X25519 keypair | `nacl.box.keyPair()` | `sk` = 32 random bytes, stored **unclamped**. `pk = X25519(sk, 9)`; clamping happens inside the multiply. | `crypto_box_keypair`; `pk = crypto_scalarmult_base(sk)` | `Curve25519.KeyAgreement.PrivateKey(rawRepresentation: sk)` (32 B). Its `publicKey.rawRepresentation` equals `pk`. | JCA `XDH` (API 33+) is awkward with raw keys. Use libsodium. |
| X25519 raw DH | `nacl.scalarMult(sk, pk)` | Raw 32-byte X25519 output, **not hashed**. tweetnacl never rejects low-order points or an all-zero result. | `crypto_scalarmult` (returns −1 on an all-zero result; tweetnacl returns zeros) | `sharedSecretFromKeyAgreement(with:)`, then take the **raw bytes** through `withUnsafeBytes`. Never use `hkdfDerivedSymmetricKey` or `x963DerivedSymmetricKey`. May throw on degenerate peer keys. | BouncyCastle `X25519Agreement`, or libsodium |
| NaCl beforenm | `nacl.box.before(pk, sk)` | `HSalsa20(key = X25519(sk, pk), input = 16 zero bytes)` → 32-byte key | `crypto_box_beforenm` | **No equivalent.** CryptoKit has no HSalsa20; use libsodium. | libsodium |
| NaCl box | `nacl.box(m, n24, pk, sk)`, `nacl.box.open` | `secretbox(m, n, beforenm(pk, sk))`; output is `tag16 ‖ ciphertext` | `crypto_box_easy`, `crypto_box_open_easy` | **No equivalent** | libsodium |
| NaCl box with precomputed key | `nacl.box.after(m, n, k)`, `nacl.box.open.after` | `secretbox` keyed with the beforenm key | `crypto_box_easy_afternm`, `crypto_box_open_easy_afternm` | **No equivalent** | libsodium |
| XSalsa20-Poly1305 | `nacl.secretbox(m, n24, k32)`, `.open` | Output is `tag16 ‖ ciphertext` (the 16 NaCl "boxzero" bytes are stripped) | `crypto_secretbox_easy`, `crypto_secretbox_open_easy` | **No equivalent.** `ChaChaPoly` is IETF ChaCha20 with a 12-byte nonce and is **not** compatible. | libsodium |
| Ed25519 keypair | `nacl.sign.keyPair()`, `.fromSeed(seed32)`, `.fromSecretKey(sk64)` | Secret key is **64 bytes: `seed32 ‖ pk32`** | `crypto_sign_seed_keypair` (same 64-byte layout) | `Curve25519.Signing.PrivateKey(rawRepresentation: sk64[0..<32])` | BouncyCastle `Ed25519PrivateKeyParameters(seed)`; JCA `Ed25519` on API 33+ |
| Ed25519 sign | `nacl.sign.detached(m, sk64)` | RFC 8032, deterministic, 64-byte signature | `crypto_sign_detached` (deterministic) | `signature(for:)` is **randomised**: its bytes differ from tweetnacl's, but they verify | BouncyCastle `Ed25519Signer` (deterministic) |
| Ed25519 verify | `nacl.sign.detached.verify` | Standard | `crypto_sign_verify_detached` | `isValidSignature` (stricter on non-canonical `S`; irrelevant for honest peers) | BouncyCastle or JCA |
| SHA-512 | `nacl.hash(m)` | 64-byte digest | `crypto_hash_sha512` | `SHA512.hash` | `MessageDigest("SHA-512")` |
| SHA-256 | `@noble/hashes/sha256` | — | `crypto_hash_sha256` | `SHA256` | `MessageDigest("SHA-256")` |
| HMAC-SHA256 | `hmac(sha256, key, msg)` | RFC 2104 | `crypto_auth_hmacsha256` | `HMAC<SHA256>` | `Mac("HmacSHA256")` |
| HKDF-SHA256 | `hkdf(sha256, ikm, salt, info, L)` | RFC 5869. A string `info` is UTF-8 encoded; `salt === undefined` means 32 zero bytes. | manual (HMAC), or `crypto_kdf_hkdf_sha256_*` (libsodium ≥ 1.0.19) | `HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` (iOS 14+) | Tink `Hkdf.computeHkdf("HMACSHA256", …)` or BouncyCastle `HKDFBytesGenerator` |
| CSPRNG | `nacl.randomBytes(n)` | platform CSPRNG | `randombytes_buf` | `SecRandomCopyBytes` | `SecureRandom` |

**HKDF salt equivalence.** An HKDF salt of `ZERO32` produces byte-for-byte the same output as an empty salt, because HMAC zero-pads short keys to the block size. So any "no salt" API gives identical results. Native SHOULD still pass `ZERO32` explicitly.

**Ed25519 signatures are only ever verified.** No protocol step compares signature bytes, so CryptoKit's randomised signatures interoperate. The signature vectors in §14 can only be *verified*, unless you use libsodium or BouncyCastle, both of which are deterministic.

### 1.3 Encodings

**Base64.** RN uses `tweetnacl-util` everywhere.

- `encodeBase64` emits the standard alphabet (`A–Z a–z 0–9 + /`) with `=` padding and no line breaks.
- `decodeBase64` first validates its input against the regex below, and throws `TypeError('invalid encoding')` on a mismatch:

  ```
  /^(?:[A-Za-z0-9+\/]{2}[A-Za-z0-9+\/]{2})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/
  ```

- This was verified by running the library: `"abc"` (unpadded), `"ab-_"` (URL-safe) and `"YQ==\n"` (trailing newline) all throw, and `""` decodes to 0 bytes.

Rules:

- Native MUST emit canonical, padded, standard base64 for every binary field in this document.
- Native decoders SHOULD be equally strict.
- The Go server uses `base64.StdEncoding`, which is the same alphabet. Python's `base64.b64decode` is lenient.

RN compares several values **as base64 strings**, not as bytes, so a non-canonical encoding silently breaks all of these:

- skipped-key map keys (`mobile/src/utils/ratchet.ts:279`, `:317-321`);
- `peerDH` equality (`ratchet.ts:335`);
- the shared-identity tripwire (`mobile/src/store/auth.ts:1175-1176`);
- mesh `toIdx` matching (`mobile/src/services/mesh.ts:1155`);
- the `rb` comparison (`mobile/src/services/webrtc.ts:2270`).

**Hex.** Always lowercase. Used for:

- delivery tokens (Go `hex.EncodeToString`);
- the device id (`mobile/src/utils/crypto.ts:518-519`);
- the MMKV key (`mobile/src/services/secureStorage.ts:118-121`).

**UTF-8.** The `tweetnacl-util` function names are inverted:

- `decodeUTF8(string) → bytes` is `unescape(encodeURIComponent(s))` and **throws `URIError` on lone surrogates**.
- `encodeUTF8(bytes) → string` is `decodeURIComponent(escape(…))` and **throws `URIError` on invalid UTF-8**.

Both behaviours were verified by execution. The consequence: when an RN receiver opens a ratchet, secretbox or box payload whose plaintext is not valid UTF-8, it records a *decrypt failure* (`ratchet.ts:290-301` catches the throw and returns `null`). Native senders MUST encrypt only valid UTF-8. In Kotlin, never encode a `String` that contains unpaired surrogates.

**Integers.**

- Binary integers are big-endian.
- JSON integers are JSON **numbers**, never strings, unless a section says otherwise. Several RN checks use `typeof x === 'number'` (§15 H6).

**Decimal formatting inside signed strings.** Several signed or MACed strings interpolate integers:

- SDP `ts` and `fromUserId`;
- the key-publish `uid` and `ts`;
- mesh `id|ts|uid|to`.

RN formats them with JavaScript's `Number → String`, which yields plain decimal: no sign, no leading zeros, no exponent. This holds for integers below 1e21, and every value here is below 2^53.

Native MUST format these integers identically, for example with `String(Int64)` in Swift or `Long.toString()` in Kotlin. It MUST send them as JSON integers, never as floats such as `1.7e12` or `1767225600000.0`.

### 1.4 Wire and version constants

**Double Ratchet (1:1)**

| Constant | Value | Where |
|---|---|---|
| Envelope version | `v: 2` (JSON number) | `ratchet.ts:90`, `:262` |
| HKDF info: init | `"mrenzo-ratchet-init-v1"` | `ratchet.ts:44` |
| HKDF info: DH step | `"mrenzo-ratchet-step-v1"` | `ratchet.ts:45` |
| HKDF info: chain | `"mrenzo-ratchet-chain-v1"` | `ratchet.ts:46` |
| HKDF info: message key | `"mrenzo-ratchet-msg-v1"` | `ratchet.ts:47` |
| HKDF info: session id | `"mrenzo-ratchet-session-id-v1"` | `ratchet.ts:53` |
| HKDF info: binding MAC | `"mrenzo-ratchet-bind-v1"`, followed by `"\|" + payload` | `ratchet.ts:57`, `:426` |
| HKDF salt | `ZERO32` | `ratchet.ts:58` |
| Max keys skipped per skip call | 1000 | `ratchet.ts:64`, `:309` |
| Auto-recovery threshold / window | 3 failures within 5 min | `mobile/src/services/messagePipeline.ts:52-53` |
| Pending-decrypt buffer TTL / cap | 8000 ms / 5 envelopes per peer | `messagePipeline.ts:86-87` |

**Legacy box and offline seal**

| Constant | Value | Where |
|---|---|---|
| Legacy box envelope | `{"n": b64(24), "c": b64(box)}` | `crypto.ts:32-35`, `:659-670` |
| Offline seal marker | `"OSB1:"` | `crypto.ts:300`; `internal/server/seal.go:28` |

**Sealed Sender**

| Constant | Value | Where |
|---|---|---|
| Certificate validity | 24 h | `internal/sealedsender/sealedsender.go:54` |
| Certificate early refresh (client) | 1 h before expiry | `mobile/src/services/sealedSender.ts:82` |
| Server verifying key soft TTL (client) | 24 h | `sealedSender.ts:81` |
| Delivery-token validity | 6 h | `internal/sealedsender/token.go:60` |
| Delivery-token early refresh (client) | 5 min before expiry | `sealedSender.ts:192` |
| Delivery-token HMAC label | ASCII `"token"` | `token.go:74` |

**Calls, key publishing, files, safety numbers**

| Constant | Value | Where |
|---|---|---|
| SDP signature freshness window | ±60 000 ms | `webrtc.ts:2219-2220` |
| SDP nonce | 16 random bytes, base64 (24 chars) | `webrtc.ts:442` |
| Key-publish signature freshness window | ±300 000 ms | `storage/app/routes_keys.py:16`, `:71` |
| File key / nonce | 32 B / 24 B, random | `crypto.ts:709-710` |
| Safety number | SHA-512 → first 30 bytes → 6 blocks of 5 bytes → `mod 100000` → 5 digits each | `mobile/src/utils/safetyNumbers.ts:32-34`, `:49-72` |

**Groups and X3DH**

| Constant | Value | Where |
|---|---|---|
| Sender Keys wire prefix / version | `"sk1:"` / `v: 1` | `mobile/src/services/senderKeyChannel.ts:41`; `mobile/src/utils/senderKeys.ts:58` |
| Sender Keys message-key HKDF info | `"mrenzo-sender-msg"` (salt `ZERO32`) | `senderKeys.ts:74`, `:135` |
| Sender Keys chain step | `HMAC-SHA256(key=CK, msg=0x02)` | `senderKeys.ts:125` |
| SKDM version | `v: 1` | `mobile/src/services/senderKeyStore.ts:148` |
| X3DH HKDF info | `"mr.enzo.x3dh.v1"` (note the dots) | `mobile/src/utils/x3dh.ts:151` |

**Mesh**

| Constant | Value | Where |
|---|---|---|
| Wire version | `v: 1` | `mobile/src/services/meshCrypto.ts:381` |
| `toIdx` | 8 bytes, hourly epoch (3 600 000 ms) | `meshCrypto.ts:62-63` |
| Padding buckets | 256 / 512 / 1024 / 2048, then multiples of 2048 | `meshCrypto.ts:339-349` |

**Device-local**

| Constant | Value | Where |
|---|---|---|
| Identity backup context (NOT INTEROP) | `"mrenzo-identity-backup-v1"` | `crypto.ts:267` |

### 1.5 Which backend serves which crypto-relevant path

Every client request goes to `https://mrenzo.com`. Caddy splits the traffic by path (`Caddyfile`). Paths that are not listed below fall through to the Go server. Do not rely on the comment in `api.ts:7-11`; it still names a former storage host.

| Path | Backend | Notes |
|---|---|---|
| `/api/keys/*` | Python storage service | Key directory (§2.2, §2.3). Needs a Bearer JWT. |
| `/api/offline/*` | Python storage | Offline copy of buffered messages, which may be OSB1-sealed (§6). |
| `/api/files/*` (except `/api/files/avatars/*`) | Python storage | Not used for chat attachments. |
| `/api/chat-files/*` | **Go** | Encrypted attachments (§8.2). |
| `/api/sealed-sender/*` | **Go** | Certificates, server key and delivery tokens (§5). |
| `/api/x3dh/*` | **Go** | Prekeys (§11). |
| `/ws` | **Go** | Every WS frame in this document. |

---

## 2. Identity keys and the key directory

### 2.1 Key types

Every account has **two independent keypairs**. They are generated separately and neither is derived from the other (`crypto.ts:47-53`, `:418-424`).

**Identity key (X25519)**

- Private key: 32 raw bytes, stored as base64. Public key: 32 bytes, published as `publicKey`.
- Used as:
  - the recipient-side static DH key of the Double Ratchet (§3.4);
  - the Sealed Sender outer-box recipient key (§5.4);
  - the `OSB1` recipient key (§6);
  - the legacy static box key (§4);
  - the mesh `toIdx` input (§12);
  - the safety-number input (§9).

**Signing key (Ed25519)**

- Secret key: 64 bytes (`seed32 ‖ pk32`), stored as base64. Public key: 32 bytes, published as `signingPublicKey`.
- Used for:
  - SDP fingerprint signatures (§7);
  - the key-publish self-signature (§2.2);
  - mesh envelope signatures (§12);
  - the X3DH signed-prekey signature (§11).
- **Not** used by the ratchet or by Sealed Sender.

Public keys are derived as follows:

- `derivePublicKey(priv) = nacl.box.keyPair.fromSecretKey(priv).publicKey` (`crypto.ts:64-68`).
- `deriveSigningPublicKey(sk64)`, which amounts to `sk64[32..64]` (`crypto.ts:435-439`).

### 2.2 Publish: `POST https://mrenzo.com/api/keys/publish`

Caddy routes `/api/keys/*` to the Python storage service (`Caddyfile`; see §1.5). Authentication is `Authorization: Bearer <access JWT>`.

**Request body** (`api.ts:714-745`):

```json
{
  "publicKey":        "<b64 X25519 pub, 32 B>",
  "signingPublicKey": "<b64 Ed25519 pub, 32 B>",
  "ts":               "1767225600000",
  "signature":        "<b64 Ed25519 detached signature, 64 B>"
}
```

Field notes:

- `publicKey` is required. The server does not reject an empty string here.
- `ts` is the current time in milliseconds. RN sends it as a **decimal string** (`api.ts:734`), as in the example above. The server field is `Optional[int]` (`routes_keys.py:28`), so pydantic coerces the string (see Q9). **Native SHOULD send `ts` as a JSON integer** (for example `"ts": 1767225600000`), per §1.3. An integer needs no coercion and does not depend on Q9. The server interpolates the parsed int into `canonical` (`routes_keys.py:73`), so either form verifies against the same decimal string.
- RN includes `ts` and `signature` only when the signing private key, `signingPublicKey` and the uid are all available (`api.ts:731`).

**Signature** (`api.ts:733-735`):

```
canonical = publicKey + "|" + signingPublicKey + "|" + decimal(uid) + "|" + decimal(ts)
signature = b64( Ed25519.sign(UTF8(canonical), signingSecret64) )
```

The server substitutes the uid from the **JWT**, not from the request body (`routes_keys.py:73`). A vector is in §14.8.

**Server rules** (`storage/app/routes_keys.py`):

1. **Size limit.** If `len(publicKey)` or `len(signingPublicKey)` exceeds 4096 characters, return 413 (`:42-45`). **Neither the base64 validity nor the 32-byte length is checked.**
2. **No half identities.** If `signingPublicKey` is absent or empty, **and** either no row exists yet or the stored row has no signing key, return 400 `"signing key required"` (`:55-62`).
3. **Signature check.** If `signature` is present and `signingPublicKey` is non-empty:
   - `ts` must be present with `|now_ms − ts| ≤ 300000`, otherwise 400 `"stale publish signature"`;
   - the signature is verified against the key **being published**; failure returns 401 `"key publish signature invalid"` (`:70-79`).

   **Unsigned publishes are still accepted** (rollout grace).
4. **Upsert** (`:81-103`):
   - if the `signingPublicKey` field is **present**, both columns are replaced. The test is `is not None`, so an **empty string counts as present**. `"signingPublicKey": ""` sent over a row that already holds a signing key passes rule 2, skips rule 3 (the value is falsy), and then **overwrites the stored signing key with `""`**. Every later call to that user fails with `peer-signing-key-unavailable`.
   - if the field is absent (`null` or omitted), only `public_key` is replaced and the stored signing key is kept (the legacy path).
5. **Response:** `{"status":"published"}`.

**Native MUST** always send all four fields, and `signingPublicKey` MUST be a non-empty key (never `""`; see rule 4). It MUST publish only keys whose private halves are already durably stored and verified (§2.4, invariant I1).

### 2.3 Fetch: `GET https://mrenzo.com/api/keys/{userId}`

**Response** (`routes_keys.py:108-153`):

```json
{"userId": 42, "publicKey": "<b64>", "signingPublicKey": "<b64 or \"\">", "updatedAt": "YYYY-MM-DD HH:MM:SS"}
```

- The request needs `Authorization: Bearer <access JWT>` (`require_auth`). Any authenticated user may fetch any user's row.
- `updatedAt` is SQLite `datetime('now')`: UTC with no zone suffix.
- If you fetch **your own** id and no row exists, the server returns **200** with `publicKey:""`, `signingPublicKey:""` and `updatedAt:null` (`:139-145`).
- For any other missing id it returns **404** `{"detail":"public key not found"}` (`:146`).

**RN client behaviour** (`api.ts:747-810`):

- **Network first.** A successful response is written through to a persistent, encrypted cache that **never expires** (`mobile/src/services/peerKeyCache.ts:45-60`).
- **Fallback.** On a network error or a 404, RN returns the cached copy. If nothing is cached, the error propagates and the UI shows "encryption not ready".
- **Row-identity check.** If `response.userId` is present and differs from the requested id, the response is neither cached nor fed to the heal tripwire. It **is still returned to the caller**, though (`api.ts:777-785`; see Q13).
- **Heal tripwire.** Every successful fetch of *another* user's row runs `maybeHealSharedIdentity(userId, publicKey, signingPublicKey)` (`api.ts:790-797`; see §2.6).
- **Readback.** `fetchPublishedKeys` (`api.ts:817-821`) bypasses the cache and is used to verify our own publish.

**Only the storage service is authoritative.** The Go server's `users.public_key` column goes **stale** after a re-key: `UpdatePublicKey` is never called on the publish path (`server.go:562-567`). Despite that, the stale value still appears in:

- Go `User` JSON (`internal/db/db.go:809-810`);
- the X3DH bundle (`internal/auth/handlers.go:2363`).

The same goes for the Go `users.signing_public_key` column: `UpdatePublicKey` and `UpdateSigningPublicKey` (`internal/db/db.go:960-976`) have no callers. The X3DH bundle returns that stale column as `signingKey`.

**Native MUST NOT use `publicKey` (or `signingKey`/`signingPublicKey`) from any Go API response as a peer's encryption or verification key.** The Go server itself fetches from storage when it seals offline blobs (`server.go:568-609`).

### 2.4 Publication invariants

These come from `ensureKeyPair`, `ensureKeysPublished`, `reconcileSigningKeyWithServer` and `retryPendingKeyUpload` in `mobile/src/store/auth.ts`. Native MUST keep them. How native tracks them locally is its own business.

- **I1 — never publish an unbacked key.** The private key must be stored and read back from secure storage before its public half is published (`crypto.ts:231-245`, `:452-455`; `auth.ts:584`, `:666-672`).
- **I2 — never publish half an identity.** Always publish X25519 and Ed25519 together (`auth.ts:719-737`). The server enforces this for rows that have no signing key yet (§2.2, rule 2).
- **I3 — confirm the publish by readback.**
  - At login, block until `GET /api/keys/{me}` (bypassing the cache) returns the public keys derived from the local private keys. Retry up to 3 times with a backoff of `700 × attempt` ms, within a 10 s budget (`auth.ts:100-130`, `:820-913`).
  - If that fails, set the `keys_publish_incomplete` flag and repair at the next launch: 2 attempts, starting 1.5 s after launch (`auth.ts:330-336`).
  - While the flag is set, outgoing calls are blocked (`isKeySetupIncomplete`, `auth.ts:954-956`).
- **I4 — reconcile against the server.** On every WS connect and every foreground (`App.tsx:545`, `:1433`), compare the server row with the derived public keys and republish if either differs or the row is missing (`auth.ts:982-1085`).
  - **Native (both platforms) narrows this** (§2.8, Q16 settled): republish silently only when the row is **empty**, a **legacy half row** (no signing key; no native build writes one), or carries **our own X25519 key** with another signing key (I6 drift). A **complete row with another X25519 key** is another device's takeover: stop (`foreign`), never republish on your own, and offer the explicit takeover of §2.8. RN builds in the field still republish.
- **I5 — announce changes.** After a publish that changed or repaired the server row, send `{"type":"key-rotated"}` over the WS. If the WS is down, persist a pending flag and send on the next connect (`auth.ts:752-768`, `:1095-1106`).
- **I6 — republish when the signing key drifts** (build 210). Republish whenever `derive(signingPriv)` differs from the last signing public key published successfully (stored as `signing_pub_published`; `auth.ts:686-713`).

### 2.5 `key-rotated` and `peer-key-rotated`

**Client → server:** `{"type":"key-rotated"}`. Any data is ignored.

**Server** (`internal/server/server.go:2205-2240`):

1. Requires an authenticated connection.
2. Persists `users.key_rotated_at`.
3. Broadcasts `{"type":"peer-key-rotated","data":{"userId":<int>}}` to **every connected user except the sender**, not only to contacts. *(Historical: this is the first release. Since server 1.1 the audience is limited, see Q12 in §16 and 02 §6.1.)*
4. On a contact's later (re)connect, replays `peer-key-rotated` for each contact whose `key_rotated_at` is later than that user's `last_seen`, **before** pending messages are replayed (`server.go:287-301`).

**Receiver obligations** (`mobile/src/App.tsx:585-630`). Native MUST do all of the following, exactly as RN does:

1. Drop every cached X25519 public key for `userId`, both in memory and in the persistent cache.
2. Drop the cached Ed25519 signing key used for SDP verification.
3. **Delete the whole ratchet session with `userId`** (`resetRatchet`, `App.tsx:597`).
4. Drop prewarm freshness.
5. If the peer was verified in Safety Numbers, show "changed" the next time (`App.tsx:612-627`).

**Exception: a replay of a rotation the client already acted on** (native). The send path also detects a re-key: before encrypting it fetches the peer's key and compares it with the cached one. A different key drops the session and writes the notice, and the send starts a fresh session on the new key (`DirectSend.reconcilePeerKey`). This is the only way the Share Extension (HTTP only, no socket) learns of a re-key, and the app does the same when it sends before its socket opens. Neither moves `users.last_seen`, so the server still replays `peer-key-rotated` for that rotation on the app's next connect (step 4 above), and the peer may already be answering on the new session. Resetting it then makes every one of those answers undecryptable. The native client therefore records the observed rotation `{key, at}` (kv `rotation-seen/<uid>`), binds it to the session it next starts on that key (SHA-256 of the session id), and absorbs **one** `peer-key-rotated` for that peer, skipping obligations 1–5 (the send path already did them), only when all of the following hold:

- the record is bound to the **current** session;
- the record is younger than 14 days;
- a **network** fetch of `/api/keys/{userId}` made now returns that same key.

Otherwise, including when the fetch fails or only the cached row answers, the reset happens as in obligations 1–5. A rotation that kept the same key (for example, a restore on a new phone) is never observed by a send, so its event always resets. A session the peer started carries no key to check and is not covered.

**Hazard: RN over-sends `key-rotated`.** RN also emits it after publishes that did **not** change the X25519 key:

- a signing-key-only republish;
- a retry of an identical bundle;
- a reconcile repair (`auth.ts:763`, `:894`, `:942`, `:1078`).

Every such message makes every peer reset its ratchet with that user. Native SHOULD emit `key-rotated` only when a published value actually changed on the server.

### 2.6 Shared-identity heal (generic rule; both platforms MUST implement it)

**Background.** Build 276 let iCloud Keychain sync one identity across two accounts. Build 319 added detection and repair. The rule is generic: it is not tied to particular uids.

Sources: `auth.ts:1151-1352`; trigger in `api.ts:790-797`.

**Trigger:** every successful key fetch for **another** user `P` that passed the row-identity check.

**Detection:**

```
myPub     = derivePub(myX25519Priv)         (fallback: stored user.publicKey)
mySignPub = deriveSignPub(mySigningSecret)  (fallback: "")
encShared  = myPub != ""     && P.publicKey == myPub                          // compared as base64 strings
signShared = mySignPub != "" && P.signingPublicKey != "" && P.signingPublicKey == mySignPub
if !encShared && !signShared: return
```

**Tie-breaker: the lower uid keeps the key, the higher uid re-keys.**

- If `myUid < P.uid`, you are the **keeper**. Only log, at most once per peer per 5 minutes (`auth.ts:1179-1188`).
- Otherwise you are the **re-keyer**. Proceed only if all of these hold:
  1. No heal is already in flight.
  2. The call lifecycle is `idle`. If it is not, defer **without** arming the throttle (`:1195-1200`).
  3. At least 10 minutes have passed since the last attempt (`:1203`).
  4. **Corroboration:** a fresh `GET /api/keys/{P}` that bypasses the cache still shows **at least one** shared half (`:1212-1222`). It may be either half, not necessarily the one that tripped detection. Any error, or neither half matching, aborts. The 10-minute throttle is armed **before** this fetch, so a failed corroboration also waits 10 minutes before retrying.

**Re-key sequence** (order matters; `auth.ts:1230-1340`):

1. Set the durable degraded flag `keys_publish_incomplete`.
2. Invalidate every in-flight key operation (epoch bump) and block new ones.
3. Wipe every copy of the old identity:
   - the backup slot and its uid binding;
   - `retireLegacyIdentity()` (Apple-only; see §2.7);
   - both Keychain keys;
   - the publish bookkeeping flags.
4. **Verify the wipe.** If any old key still loads, abort.
5. Run `resetAllRatchets()` and clear the mesh pigeon queue.
6. Mint new keys and publish them with a readback (§2.4, I1–I3).
7. Check that the new public key differs from the old one.
8. Send `key-rotated`, or persist the pending flag if the WS is down.

**Cross-platform requirement.** iOS native, Android and RN MUST all use the same uid tie-breaker. Otherwise two twin accounts on different platforms would both re-key, or neither would.

### 2.7 Device-local key storage, and migrating RN → native on the same device (NOT INTEROP)

A native iOS build installed over the RN app (same bundle id, same team) can read RN's Keychain items. **The identity MUST be preserved across that upgrade.** If it is not, the upgrade becomes a re-key: peers reset their sessions, and server-sealed offline blobs addressed to the old key (`OSB1`, §6) can no longer be opened.

**Keychain items written by RN.** All are `kSecClassGenericPassword`; the value is the UTF-8 encoding of the stored string.

| service | account | value | notes |
|---|---|---|---|
| `com.mrenzo.e2e` | `e2e-private-key` | base64 of the 32-byte X25519 private key | AfterFirstUnlock (`crypto.ts:227-230`) |
| `com.mrenzo.e2e.sign` | `e2e-sign-key` | base64 of the 64-byte Ed25519 secret key | AfterFirstUnlock (`crypto.ts:448-451`) |
| `com.mrenzo.idowner` | `mrenzo-idowner` | owner uid, decimal | `crypto.ts:174-189` |
| `com.mrenzo.idretired.v319` | `mrenzo-idretired` | `"1"` | `crypto.ts:102`, `:128-136` |
| `com.mrenzo.idlocal.v319.<service>` | `mrenzo-idlocal` | `"1"` (partition-migration flag) | `crypto.ts:147-162` |
| `com.mrenzo.idmig.v281` | `mrenzo-idmig` | `"1"` | `crypto.ts:478-498` |
| `com.mrenzo.deviceid` | `mrenzo-device-id` | 32 lowercase hex characters (16 random bytes) | `crypto.ts:509-530` |
| `com.mrenzo.mmkv.key` | `mrenzo-mmkv-key` | 32 hex characters: the MMKV encryption key | `mobile/src/services/secureStorage.ts:74`, `:174-185` |

**Apple-only partition quirk** (`crypto.ts:74-101`). react-native-keychain 10 treats the mere *presence* of the `cloudSync` option as `kSecAttrSynchronizable=true`. As a result, identity keys may live in the **synchronizable** partition. RN loads them with this rule (`crypto.ts:354-388`):

```
if flag(com.mrenzo.idlocal.v319.<service>) == "1" or flag(com.mrenzo.idretired.v319) == "1":
    return local(service)                                          // synchronizable = false
legacy = synced(service)                                           // synchronizable = true
if legacy: copy legacy -> local, verify, set the idlocal flag; return legacy     // legacy is never deleted
return local(service)
```

Native iOS MUST:

- replicate this lookup, querying both values of `kSecAttrSynchronizable`;
- never delete the synchronizable item, because the deletion would propagate over iCloud to the twin device;
- write new items with `synchronizable = false`.

This attribute layout is inferred from react-native-keychain 8.2.0, the only copy vendored locally; production ships 10.x. See Q8.

**MMKV** (`secureStorage.ts:85-99`). The sensitive MMKV instances are encrypted with the key above. Ratchet sessions live in instance `mrenzo-ratchet` under the key `ratchet:<peerUserId>`, in the JSON format of §3.12 (`mobile/src/services/ratchetStore.ts:27-28`).

If native cannot read RN's MMKV (Q7), every session resets on upgrade. Peers then recover through §3.11:

- if we send first, our fresh `pn=0` session triggers their fresh-init recovery;
- if they send first, our failures lead to a `ratchet-reset`.

Messages in flight during the switch are lost.

**Sealed identity backup (NOT INTEROP)** (`crypto.ts:251-331`; `auth.ts:35-52`). RN keeps a second copy of the identity private key in default-namespace MMKV:

```
subkey = SHA-512( UTF8("mrenzo-identity-backup-v1" + mmkvKeyHex) )[0..32]        // secureStorage.ts:346-352
value  = b64( nonce24 ‖ secretbox(UTF8(b64PrivKey), nonce24, subkey) )
stored under 'identity_key_backup_v1'; the owning uid is stored under 'identity_key_backup_uid'
```

Native MAY read this slot during migration. It is not a wire format.

**Android equivalent.**

- Keep the raw 32-byte and 64-byte keys encrypted under an AES-GCM key held in the Android Keystore (Tink `AndroidKeysetManager` or `EncryptedSharedPreferences`).
- Exclude them from Auto Backup.
- Reproduce the guard that refuses to regenerate a key when encrypted data already exists (`secureStorage.ts:145-169`).
- Reproduce the uid owner gate (`auth.ts:396-432`).
- Android has nothing like the synchronizable partition.

### 2.8 Moving an account to this device: the confirmed takeover (both platforms MUST implement it)

**Why.** Identity private keys never leave the device: iOS keeps them in Keychain items that do not migrate to a new phone (and are lost on a restore without the Keychain), Android excludes them from Auto Backup (§2.7). A device that signs in to an account whose key row belongs to another device therefore has no usable identity. RN minted a fresh identity and published it over the row automatically (`auth.ts` `ensureKeyPair` → `ensureKeysPublished`), and an RN device that still held its keys took the row back on its next reconcile (I4). Native moves an account **only after the user confirms it**, because that ends messaging on the other device and resets every peer's session with the account, and a device the account was moved away from **never takes it back by itself**.

Typical cases: a new phone, a phone restored without its Keychain, a second account on a phone that holds another account's keys, and the old phone of any of these.

**Two kinds of offer.** Both are the same button, **Use This iPhone**.
- **New device** (`newDevice`): this device holds **no X25519 identity key for the account**. Confirming mints a fresh identity.
- **Moved away** (`movedAway`): this device holds the account's own X25519 key (a complete identity, or a lone X25519 half), and the row is **another device's complete identity**: a different X25519 key with a signing key (I4 as narrowed above). Messaging stops here: the socket stays down, the composer is off, and an offline start is not "ready-unverified" any more (drop the last-verified marker). Confirming publishes **this device's own keys** back (no mint; a lone X25519 half gets its signing half minted, §2.4), so peers see the security code this device had before.

**When it is offered.** All of these hold:

1. The Keychain resolution (§2.7) finished. A read error is not "absent" (touch nothing, offer nothing).
2. The restore from the sealed backup slot (§2.7; `05` §8.7) has run and adopted nothing. A slot or K1 read/write error there stops the resolution instead, and nothing is offered.
3. An uncached readback of the own row succeeded, and the row is non-empty (another device's identity), or empty while the Go `users.public_key` column is non-empty (the storage-loss tripwire D3 of `09` §2.2; new-device offer only).
4. **The row proof** found nothing (new-device offer only). A key this device holds back — an X25519 key refused by the owner gate, or a backup slot that opened but was not adopted (unproven legacy slot, or bound to another uid) — whose public key **equals the row's key** (or the Go column's, for D3) is the account's current identity, and minting over it would destroy the only copy:
   - nothing claims it for another account (an **unstamped** key refused only by RN's `auth_user.publicKey` check; an **unbound** legacy slot): **adopt it** (stamp the owner, or restore the slot with the row's key as the proof), then resolve normally. After D3 the adopted key goes back up into the empty row.
   - something does (the owner stamp or the slot's binding names another uid): **withhold the offer** and log it. Stay `foreign`.
5. The client's key policy allows it. The production app always allows it. The iOS dev shell allows it only for its allow-listed test accounts.

**Another account's keys on this device** (new-device offer only). The identity items are one set per device. When they hold another account's keys — the owner stamp names another uid, the RN owner gate refused them, or a lone signing half is stamped for another uid — a fresh mint **overwrites them**, and that account must take its own account over again the next time it signs in here (resetting its peers). The offer says so and names the account when it can (`GET /api/users/{uid}/profile` → `@username`), and confirming needs a **second, explicit confirmation** (an alert: "Delete the other account's keys?" → destructive "Delete and Continue"). The client also refuses a confirmation that did not include it (the offer the user saw is passed along and compared).

**UX.**
- A sheet opens once per app session when an offer appears. It is re-requested until it has really been on screen (a request made while another sheet is up is dropped by the system).
  - New device: title "This account was used on another device", question "Make this iPhone your main device?", consequences "Chats on the old device will stop working." and "Your contacts will see that your security code has changed.", plus the other-account warning when it applies.
  - Moved away: title "This account is now used on another device", body "Messages and calls are off on this iPhone.", question "Move the account back to this iPhone?", consequences "Chats on the other device will stop working.", the security-code line, and "Didn't sign in on another device? Move the account back to this iPhone."
  - Buttons: **Use This iPhone** (confirm) and **Not Now**.
- After "Not Now" the chat composer's status line (same title as the sheet) and the Settings screen keep a **Use This iPhone** entry that reopens the sheet. Nothing else about the account works until then. A foreground re-resolution of a keyless account (`resolving` → `absent` → readback → `foreign`) keeps the offer on screen; it does not blink.
- A failure before the point of no return (step 3 below) shows the reason with **Retry** and **Not Now**. After it, the takeover finishes by itself (Resume), so the sheet says "The move has started and will finish automatically." and offers **Retry** and **Close**, not "Not Now". **Retry** always works: when the offer fell away meanwhile (network, Keychain), it re-resolves and, if the same offer comes back, carries on with the user's confirmation.

**Sequence on confirm.** Order matters:

1. Resolve the Keychain again. A new-device offer where an identity key appeared meanwhile, or a moved-away offer whose key went, is not this takeover: resolve normally. Another account's keys that appeared meanwhile: resolve again, so the offer shows the warning.
2. Read the own row again, bypassing any cache. If that fails, stop: **nothing has been touched**, and the offer stands. If the row is now empty, carries this device's X25519 key, or (new device) is a key this device holds back (step 4 of eligibility), this is not a takeover: resolve normally.
3. **Point of no return.** Delete every local ratchet session and the failure window (§3.11.3). Delete the stored signed prekey (§11), because its signature belongs to the old signing key (or the SPK on the server is now the other device's). Mark the one-time prekey pool for a reset (§11): the pool on the server is the other device's, whose privates this device does not have, and its key ids may collide with this device's. Move the key-id counter to a random base in `[2^24, 2^30]` (never lower it) and force a refill.
4. Persist the *replaced row* (its X25519 public key) and a *pending takeover* marker holding the X25519 public key to publish. New device: generate a **fresh identity, both halves** (no leftover half is kept) and store both with verified writes and the owner stamp (I1). Moved away: this device's own identity (a lone X25519 half gets its signing half minted and stored).
5. Publish both keys, signed (§2.2), and confirm by readback (I2, I3).
6. The row changed, so send `{"type":"key-rotated"}` (I5), through the persisted outbox that flushes when the socket opens. Peers then do everything in §2.5: drop their session with the account, drop the cached keys, and show the safety number / security code as changed.
7. Clear the pending marker and the replaced row. The identity is ready and the socket may connect. Reseal the backup slot with the key (§2.7). The next X3DH bootstrap drops the server pool (`DELETE /api/x3dh/otps`; a server without the endpoint answers 404/405: go on with the fresh ids and the forced refill), signs a new SPK and uploads a fresh batch.

**Resume.** A takeover that does not reach step 7 is finished later, never restarted. It is resumed by **Retry**, by the chat gate's retry, by the next launch, and by every pre-connect check and recheck.
- While the pending marker equals the local X25519 public key and the row differs, every resolution, pre-connect check and recheck publishes the local keys (step 5), even under a policy that would otherwise refuse the row — **but only over the row the takeover replaced** (or an empty or half row, or one carrying the local X25519 key). A complete row that a **third** device wrote since supersedes the takeover: drop the marker and treat the row like any other device's (moved away; only the button publishes again). This is what keeps two devices from taking the row back from each other.
- A publish can land while its readback fails (step 5 ends in "incomplete"). The first later readback that matches the local keys while the pending marker equals the local X25519 public key is the confirmation: send `key-rotated` then (step 6), and clear the marker.
- **Exactly one announcement.** Whoever clears the marker announces, and checking and clearing it happen with no suspension in between. A publish of the same keys already in flight is awaited, not repeated. A publish that finds the marker already cleared by another path does not announce.
- A Keychain write that stopped after the X25519 half leaves a lone X25519 key that equals the marker. The next resolution mints the missing signing half and publishes both (the lone-half rule of §2.4).
- A `stale publish signature` answer (clock skew) keeps the marker. The user fixes the clock; the next resolution or Retry finishes it.

**What is lost.** Offline messages the server holds for the replaced key (`OSB1`, §6, and pending ratchet frames) cannot be opened on the device that took over, and the other device's sessions are dead. RN's automatic mint had the same effect. The device the account was moved away from keeps its keys (it may take the account back).

**Security note.** Email OTP is the only sign-in factor, so a phished code lets an attacker take the account over with one confirmation. What this design guarantees: the device that loses the row is told ("This account is now used on another device", with the "didn't sign in" line), it never takes the row back silently (so the attacker cannot hide the move by letting it flip back), and its explicit takeover restores the previous security code for peers. What it does not do: sign the attacker out (needs the logout-all of the credential-change revocation) or notify the account by email on every key-row replacement (server work). Both are not yet in the released server; planned with the privacy release (1.2.3). A fresh-OTP gate on the button would not help here: the attacker's code is fresh when the sheet opens.

**Android.** Implement the same eligibility (both kinds, the row proof, the other-account confirmation), the same order of steps, the same pending-marker and replaced-row semantics, the prekey pool reset, and the same UX (strings in all eight app languages).
- Keep the pending marker and the replaced row next to the other key-publication flags; they are not secrets.
- Log each step under the tag `KEYS`, event `identity.takeover`. Ship these lines. The `step` values are `offered` (with `source`: `auto`, `chatGate`, `settings`, and `kind`), `declined`, `closedPending` (closed after the point of no return), `confirmed`, `aborted` (with `reason`), `withheld` (with `reason`: `residueOfAnotherUid`, `slotOfAnotherUid`), `minted`, `reclaimed`, `publishPending`, `resume`, `superseded`, `done` and `failed`. Also `identity.residueAdoptedByRow`, `identity.backup.restored` with `provenByRow`, and `X3DH x3dh.otp.poolReset` (`result`: `dropped`, `unsupported`, `failed`).

---

## 3. The Double Ratchet (1:1 messages)

> **Superseded by protocol v3 (build 349), §V3.3.** Kept as the reference of the ≤ 348 format, which a 349 client rejects.



### 3.1 How this ratchet differs from Signal

The design is Signal-style but simplified (`ratchet.ts:1-37`).

- **The initial agreement is a single DH:** `SK = X25519(alice_eph_priv, bob_identity_pub)`. `initAsSender` **ignores the sender's own identity key**: its `myIdentityPriv` parameter is unused (`ratchet.ts:140-150`).
- **Consequence: the ratchet provides no cryptographic sender authentication.** Anyone who knows Bob's public identity key can start a session that Bob will decrypt. Who sent a message is decided entirely by the transport:
  - the `fromUserId` the server stamps from the JWT (`server.go:1825-1837`);
  - the server-signed sealed-certificate uid (§5);
  - the mesh Ed25519 signature plus sender pinning (§12).
- There are no one-time prekeys, no associated data and no header encryption. The X3DH module exists but is not wired in (§11).
- `KDF_RK` runs HKDF over the concatenation `rootKey ‖ dh`. Signal instead uses the root key as the HKDF salt.
- `KDF_CK` is two separate HKDF calls, where Signal uses HMAC with constants.
- The AEAD is XSalsa20-Poly1305 `secretbox`, with a **random** 24-byte nonce per message.
- A stable per-session `sessionId` is derived from `SK`. It feeds the call binding MAC (§7).

### 3.2 KDFs

```
HKDF(ikm, info, L) := HKDF-SHA256(salt = ZERO32, IKM = ikm, info = UTF8(info), L)      // RFC 5869
DH(priv, pub)      := raw X25519(priv, pub)                                             // 32 bytes, not hashed

INIT(sk)       := HKDF(sk, "mrenzo-ratchet-init-v1", 32)                  ratchet.ts:149, :180
SESSION_ID(sk) := HKDF(sk, "mrenzo-ratchet-session-id-v1", 32)            ratchet.ts:153, :183
KDF_RK(rk, dh) := okm = HKDF(rk ‖ dh, "mrenzo-ratchet-step-v1", 64)        ratchet.ts:99-121
                  return (newRoot = okm[0..32], newChain = okm[32..64])
KDF_CK(ck)     := nextChain  = HKDF(ck, "mrenzo-ratchet-chain-v1", 32)    ratchet.ts:124-128
                  messageKey = HKDF(ck, "mrenzo-ratchet-msg-v1",   32)
```

### 3.3 State

Defined in `ratchet.ts:71-87`.

| Field | Type | Meaning |
|---|---|---|
| `rootKey` | 32 B | current root key |
| `myDH` | X25519 keypair | our current ratchet keypair. It starts as Alice's ephemeral key, or as Bob's **identity** key. |
| `peerDH` | 32 B | the peer's current ratchet public key. On Bob's side it starts as `ZERO32`, meaning "not set yet". |
| `sendChainKey` (CKs) | 32 B or null | sending chain key |
| `sendCount` (Ns) | int | messages sent in the current sending chain |
| `recvChainKey` (CKr) | 32 B or null | receiving chain key |
| `recvCount` (Nr) | int | messages received in the current receiving chain |
| `prevSendCount` (PN) | int | length of our previous sending chain |
| `skippedKeys` | map `"<b64 peerDH>:<n>" → b64(messageKey)` | cached keys for out-of-order messages |
| `sessionId` | 32 B or null | `SESSION_ID(SK)`. It is `null` for state persisted by build 81 or earlier. |

### 3.4 Initialisation

**Sender with no state** (`initAsSender`, `ratchet.ts:140-166`):

```
eph       = fresh X25519 keypair
sk        = DH(eph.priv, peerIdentityPub)          // peerIdentityPub = the peer's published X25519 key
(RK, CKs) = KDF_RK(INIT(sk), sk)                   // sk is BOTH the HKDF input and the DH term
state     = { rootKey: RK, myDH: eph, peerDH: peerIdentityPub,
              CKs, Ns: 0, CKr: null, Nr: 0, PN: 0, skipped: {}, sessionId: SESSION_ID(sk) }
```

This runs lazily on the first encrypt to that peer: `encryptForPeerB64` loads the stored state or calls `initAsSender` (`ratchetStore.ts:136-154`). The peer key is whichever key was last fetched from `/api/keys` (`ChatScreen.tsx:288-306`).

**Recipient with no state, on the first envelope `E`** (`initAsRecipient`, `ratchet.ts:168-204`):

```
sk    = DH(myIdentityPriv, b64dec(E.dh))
state = { rootKey: INIT(sk), myDH: { pub: X25519_base(myIdentityPriv), priv: myIdentityPriv },
          peerDH: ZERO32, CKs: null, Ns: 0, CKr: null, Nr: 0, PN: 0, skipped: {}, sessionId: SESSION_ID(sk) }
then ratchetDecrypt(state, E)        // the DH branch fires, because E.dh != ZERO32
```

The new state is persisted **only if** that decrypt succeeds (`messagePipeline.ts:444-446`, `:513`).

**Why both sides agree:** Bob's first DH step computes `KDF_RK(INIT(sk), DH(bobId, eph)) = KDF_RK(INIT(sk), sk)`, which is exactly Alice's `(RK, CKs)`. The §14 vector checks this: `bob CKr == alice CKs0`.

### 3.5 DH ratchet step

`ratchet.ts:212-237`:

```
dhRatchet(s, newPeerPub):
    (rk1, CKr) = KDF_RK(s.rootKey, DH(s.myDH.priv, newPeerPub))
    PN         = s.Ns
    newDH      = fresh X25519 keypair
    (rk2, CKs) = KDF_RK(rk1, DH(newDH.priv, newPeerPub))
    return s with { rootKey: rk2, peerDH: newPeerPub, CKr, Nr: 0, PN, myDH: newDH, CKs, Ns: 0 }
    // skippedKeys and sessionId are carried over unchanged
```

### 3.6 Encrypt

`ratchet.ts:241-274`; persistence in `ratchetStore.ts:136-154`.

```
if s.CKs == null: s = dhRatchet(s, s.peerDH)        // defensive; unreachable for persisted states
(ck', mk) = KDF_CK(s.CKs)
nonce     = random(24)
sealed    = secretbox(UTF8(plaintext), nonce, mk)   // tag16 ‖ ct
env       = { "v": 2, "dh": b64(s.myDH.pub), "pn": s.PN, "n": s.Ns, "ct": b64(nonce ‖ sealed) }
s.CKs = ck';  s.Ns += 1
persist s                                           // BEFORE the wire text is handed out
wireText  = JSON.stringify(env)                     // compact; RN key order is v, dh, pn, n, ct
```

- **One logical message consumes exactly one chain step.** The state is saved before any transport sees the envelope, and every fallback path reuses the same wire text. Native MUST NOT re-encrypt when it falls back to another transport. The fallback paths are:
  - sealed → legacy `p2p-message` (§5.6);
  - pigeon queue → WS drain (`mesh.ts:700-745`). This drain unpads the stored mesh payload and sends that same wire text as `{"type":"p2p-message","data":{"toUserId","messageId":<mesh envelope id>,"text":<wireText>,"encrypted":true}}`. The mesh envelope id is the chat message id, so the receiver's `messageId` dedup (§3.11.1) collapses any mesh + WS double delivery.

  The WS-down → mesh choice is made in `ChatScreen.tsx` *before* anything is encrypted. The mesh path then encrypts exactly once, inside `buildMeshEnvelope` (`meshCrypto.ts:499-509`), and the WS path is skipped for that message.
- **A failed save is counted, not rethrown** (`ratchetStore.ts:53-78`). RN deliberately keeps **no** backup copy of chain keys, because restoring a stale state would reuse (key, nonce) pairs.

### 3.7 Decrypt

`ratchet.ts:278-354`:

```
ratchetDecrypt(s, E):          // pure: returns (s', pt) or null; never mutates s
  // 1. fast path: a previously skipped key
  k = E.dh + ":" + decimal(E.n)                     // E.dh exactly as received (a string)
  if k in s.skipped:
      pt = OPEN(b64dec(s.skipped[k]), E.ct)
      if pt != null: return (s with skipped - {k}, pt)
      // if pt == null, fall through
  // 2. the peer rolled its DH key: ratchet
  envDh = b64dec(E.dh)
  if b64(envDh) != b64(s.peerDH):
      s = SKIP(s, E.pn)                             // stash the rest of the OLD receiving chain
      s = dhRatchet(s, envDh)
  // 3. skip ahead inside the current chain
  s = SKIP(s, E.n)
  // 4. decrypt this message
  (ck', mk) = KDF_CK(s.CKr)
  pt = OPEN(mk, E.ct);  if pt == null: return null
  return (s with { CKr: ck', Nr: s.Nr + 1 }, pt)

SKIP(s, until):
  if s.CKr == null: return s
  if until - s.Nr > 1000: THROW "ratchet: too many skipped keys"
  while s.Nr < until:
      (ck', mk) = KDF_CK(s.CKr)
      s.skipped[b64(s.peerDH) + ":" + decimal(s.Nr)] = b64(mk)
      s.CKr = ck';  s.Nr += 1
  return s

OPEN(mk, ctB64):
  p = b64dec(ctB64);  if len(p) < 24: return null
  m = secretbox_open(p[24..], p[0..24], mk);  if m == null: return null
  return UTF8-decode(m)                             // invalid UTF-8 → null
```

Behaviour native MUST reproduce:

- **Throwing is not the same as failing.** These conditions **throw** instead of returning `null`:
  - `SKIP` exceeding its 1000-key limit;
  - malformed base64 **in `dh`** (`ratchet.ts:334` calls `decodeBase64` outside any `try`);
  - a `dh` of the wrong length (tweetnacl `scalarMult` throws `bad p size`).

  The pipeline catches the throw (`messagePipeline.ts:516-522`) and treats the message as undecryptable. But a throw **does not count toward auto-recovery**, and it **skips the `pn == 0` recovery**, which sits inside the same `try` block.

  A malformed or truncated **`ct`** does **not** throw. `decryptWithKey` (`ratchet.ts:290-302`) catches the base64 error and returns `null`, so the message is a clean failure: it **is** counted toward auto-recovery, and it does get the `pn == 0` retry.
- **Duplicates fail.** An old or duplicate envelope (`E.n < Nr` in the current chain, with no skipped key stored) runs `KDF_CK` on the current chain, gets the wrong key and returns `null`. That is why duplicates must be removed first (§3.11.1).
- **Skipped keys are unbounded.** The 1000-key limit applies per `SKIP` call only. The skipped map itself has **no total cap and no expiry** (hazard H18).
- **One session per peer.** A new session replaces the old one.

### 3.8 The v=2 envelope

| Field | JSON type | Content |
|---|---|---|
| `v` | number | exactly `2` |
| `dh` | string | `b64` of the sender's current 32-byte ratchet public key. In Alice's first chain this is her ephemeral key. |
| `pn` | number | the sender's previous sending-chain length |
| `n` | number | index within the current sending chain, starting at 0 |
| `ct` | string | `b64( nonce24 ‖ tag16 ‖ ciphertext )` |

**What an RN receiver accepts** (`messagePipeline.ts:422-441`):

- the text must parse as JSON; and
- `parsed.v === 2` (the number); and
- `dh` and `ct` must be strings; and
- `n` and `pn` must be numbers.

Anything else is treated as undecryptable: it goes to the pending buffer and then becomes the placeholder. It is **not** counted as a failure.

Extra fields are ignored, which makes them a safe, forward-compatible extension point. A future `v: 3` would show up on RN as the placeholder.

Note that `pn == 0` does not mean "fresh session": the responder's first reply chain also has `pn == 0` (see `msg3` in §14).

### 3.9 What the ratchet carries

| Use | Plaintext | Source |
|---|---|---|
| Text message | the text (UTF-8) | `ChatScreen.tsx:843` |
| Text message with a link preview (build ≥ 349) | U+0000, then the structured-text JSON below | native `LinkPreviewEnvelope` |
| Edit | the new text, sent as `message-edit.data.newText` | `ChatScreen.tsx:722-730` |
| Image, video, voice, file | file-envelope JSON (§8.3) | `ChatScreen.tsx:1161-1169`, `:1266-1274` |
| Retry | re-encrypts the **original** text or file envelope, using a new chain step, and resends it under the **same `messageId`** as the original (`messageId: item.id`). If the original did reach the receiver, §3.11.1 dedup drops the retry, and the retry's chain step later becomes a harmless skipped key. Native MUST reuse the original `messageId` on retry. `[build 361]` On native iOS an **automatic** re-send — every new connection, the silence timer (02 §5.1, §5.3) — is the **same bytes** and spends no chain step. A new step under the same `messageId` is taken only: by the user's «Повторить»; when the session or the signing key of an offline-queue entry is gone (04 L2.10); when a `p2p-sealed` frame's delivery token has run out or the seal was refused; and when the bytes are older than 6 days (the recipient may no longer remember the id of a message it deleted, and would count the copy as a failed decrypt, §3.11.3). The delivery receipt for an undecryptable frame (§3.11) is unchanged. | `ChatScreen.tsx:1008-1058`; native `DBTx.requeueFresh`, `MessagingService.retry` |
| Prewarm | the empty string `""`. The envelope is **thrown away**, never sent, so it burns one chain step. As a result the first real message may arrive with `n ≥ 1`. | `mobile/src/services/peerPrewarm.ts:128-140` |
| Mesh | the message text is ratchet-encrypted once inside `buildMeshEnvelope`, and the resulting v=2 wire text is bucket-padded (§12) | `meshCrypto.ts:499-509` |

**Receive side:** if a `text`-type message decrypts to an empty or whitespace-only string, RN drops it silently. Nothing is stored and **no delivery ack** is sent (`messagePipeline.ts:900-941`).

**Structured text: the link preview inside the message (build ≥ 349).** The preview of a text's first link is made by the **sender's** device and travels in the ratchet plaintext; a recipient renders it and never contacts the server or the linked host for it (`GET /api/link-preview` is not used by native ≥ 349, 01 §15). The plaintext of such a `text` message is the character U+0000 followed by UTF-8 JSON:

```
"\u0000" + {"v":1,"text":"<the message text>","preview":{"url":"<https URL>","title":"…","description":"…","image":"<std base64 JPEG or empty>"}}
```

- A plaintext that does not start with U+0000 is the text itself, exactly as before. The outer `p2p-message` / `p2p-sealed` frame is unchanged (no `type` field), so the server cannot tell a message with a preview from one without.
- Sender limits: the whole plaintext ≤ 30 000 UTF-8 bytes (fits the 64 KiB WS frame through the sealed-sender layer and the mesh payload); the thumbnail ≤ 12 KiB decoded and a JPEG (starts `FF D8 FF`); `title` ≤ 200 and `description` ≤ 300 characters. When the whole does not fit, the thumbnail is dropped; when it still does not, the message is sent as plain text with no preview. Keys are emitted sorted; key order carries no meaning.
- `preview.url` MUST be the text's first link (`https?://[^\s]+`, trailing `.,;:!?"'»”’]}>` and an unbalanced `)` trimmed). A receiver drops a preview whose `url` is not the text's first link, a thumbnail that is not a JPEG within the limit, and clips `title`/`description`; the card opens and names the domain of the text's link, never anything else from the preview.
- A plaintext that starts with U+0000 but is not a valid `v:1` object is shown as the characters after U+0000, with no preview.
- The sender makes the preview on its own device only for https pages (≤ 1 MiB of HTML, 5 s; `og:title` else `<title>`, `og:description` else the `description` meta, `og:image` ≤ 5 MiB as a ≤ 320 px JPEG), over an ephemeral session with no cookies. The page is untrusted input: it is read in one linear pass (a `<meta>` tag or `<title>` text that does not close within 4 KiB is skipped), never with backtracking patterns. A draft's link is fetched once typing pauses (0.7 s), not per keystroke; a send that finds no preview yet starts it and waits at most 2 s. Edits and forwards carry no preview; a retry carries the stored one again. Group messages carry no preview.

### 3.10 What goes over the wire (`p2p-message`)

**Client → server** (`ChatScreen.tsx:881-895`, `:1197-1207`, `:1296-1306`):

```json
{"type":"p2p-message","data":{
  "toUserId": 42,
  "messageId": "<client id string>",
  "text": "<wireText: the v=2 envelope JSON, as a STRING>",
  "encrypted": true,
  "type": "image",
  "replyTo": {"id":"…","text":"<≤100 chars, PLAINTEXT quote>","senderName":"…"},
  "autoDeleteSeconds": 30
}}
```

- `type` is omitted for plain text. For media it is one of `image`, `video`, `voice` or `file`.
- `replyTo` and `autoDeleteSeconds` are optional.

**Server:** it copies `data` verbatim, assigns a `messageId` if one is missing, and stamps `fromUserId`, `fromUsername` and `fromDisplayName` (`server.go:1768-1830`). It never inspects `text`.

**Receiver rules** (`messagePipeline.ts:757-807`):

- The ratchet is tried **only** when all three hold: `data.encrypted` is truthy, `text` is non-empty, and the local private key is loaded.
- **If `encrypted` is false or absent, `text` is shown verbatim.** Native senders MUST therefore set `"encrypted": true`.
- If the private key is not loaded, the message text becomes `"⚠️ Ключ шифрования не готов"`.
- On a decrypt failure the receiver still sends `message-delivered` immediately (`:797-802`).

**`replyTo.text` is plaintext and visible to the server** (`ChatScreen.tsx:736-738`). RN renders it straight from `data.replyTo`, so native MUST send it in the same form to stay compatible. Treat it as a known privacy leak (H11).

**`message-edit`** (`ChatScreen.tsx:726-729`):

```json
{"type":"message-edit","data":{"toUserId":42,"messageId":"<id>","newText":"<wireText>","encrypted":true}}
```

**The RN receiver is broken.** It tries the *legacy static box* on `newText` (`ChatScreen.tsx:541-545`). That always fails for a v=2 envelope, and RN then stores the raw envelope JSON as the edited text. RN therefore displays everyone's edits as ciphertext JSON.

That is true of **ratchet** edits only. The same receiver *does* open a legacy-box `{n,c}` string in `newText` and displays the plaintext, so a legacy-box edit is the one encoding RN can show. See §3.10.1 for that encoding, its failure cases and what it gives up.

The sender still used up a ratchet step for the edit. The receiver later skips that key, which is harmless.

**Delivery is live-only.** The server relays `message-edit` with `BroadcastToUsers` (`server.go:2157-2167`, `:763-777`), stamping `fromUserId`. It has no offline store, pending row or push. An edit sent while the peer is offline is lost. RN handles `message-edit` only inside a mounted `ChatScreen` for that peer (`ChatScreen.tsx:534-547`); no global handler exists. A native receiver must therefore tolerate:

- edits that never arrive (the chain step becomes a skipped key);
- edits whose envelope uses a chain position that it has already skipped past.

What native should do:

- **As a receiver:** decrypt `newText` with the ratchet. First deduplicate by `(messageId, edit)`, then run `ratchetDecrypt`. If native adopts the §3.10.1 option, also accept a `{n,c}` `newText` (§3.10.1, receiver rules).
- **As a sender to RN peers:** undecided; see Q3. A ratchet edit is never readable on RN; the only encoding RN displays is the legacy box of §3.10.1.

#### 3.10.1 Legacy-box edits: the encoding RN can display

RN's only `message-edit` receiver (`ChatScreen.tsx:534-547`) opens `newText` with the legacy static box of §4, never with the ratchet:

```
if data.fromUserId != peerId: ignore                          // :534, handler of the mounted screen for that peer
if the target message exists and is from 'me': ignore         // :539-540
newText = data.newText || ""                                  // :541
if data.encrypted is truthy and sharedKeyRef != null and newText != "":     // :542
    dec = decryptMessage(newText, sharedKeyRef)               // :543; crypto.ts:676-688
    if dec != null: newText = dec                             // :544
editMessage(conversationId, messageId, newText)               // :546; stored whether or not decrypt succeeded
```

`decryptMessage` is `JSON.parse` → `b64dec(n)`, `b64dec(c)` → `nacl.box.open.after(c, n, k)` → UTF-8 decode. Any throw or a failed MAC returns `null` (`crypto.ts:676-688`).

`sharedKeyRef` is filled when the chat screen mounts (`ChatScreen.tsx:288-308`; assignment at `:292-294`):

```
peerX25519Pub = getPublicKey(peerId).publicKey               // GET /api/keys/{peerId}, §2.3 (api.ts:747-811)
sharedKeyRef  = computeSharedKey(myX25519Priv, peerX25519Pub, peerId)
              = beforenm(peerX25519Pub, myX25519Priv)         // crypto.ts:620-633 (nacl.box.before)
```

`beforenm` gives both parties the same `k` (§4). A native sender computing `k = crypto_box_beforenm(rnPeerX25519Pub, myX25519Priv)`, with the peer's `publicKey` from `/api/keys/{id}` (H20), therefore produces a `newText` RN opens.

**Consequence for native.** A native sender that puts a legacy-box `{"n","c"}` string into `newText` has its edit displayed correctly by RN. A native sender that puts a ratchet envelope there, as the §3.10 receiver rule assumes, has its edit shown as raw envelope JSON on every RN peer, and it also burns a sender chain step (§3.10).

**Wire frame** (byte construction exactly as §4; known-answer vector in §14.7):

```json
{"type":"message-edit","data":{"toUserId":42,"messageId":"<id of the original message>","newText":"{\"n\":\"<b64, 24 B>\",\"c\":\"<b64, tag16 ‖ ct>\"}","encrypted":true}}
```

- `k = crypto_box_beforenm(peerX25519Pub, myX25519Priv)` = HSalsa20(X25519(myPriv, peerPub), 0^16). Raw X25519 fails silently (H4).
- `n` is 24 fresh random bytes. `c = crypto_box_afternm(UTF8(editedText), n, k)` (= `crypto_secretbox_easy` under `k`), laid out `tag16 ‖ ct` (H3).
- `newText = JSON.stringify({"n": b64(n), "c": b64(c)})` (`crypto.ts:659-670`): standard padded base64 (§1.3), key order `n` then `c`. RN only needs `n` and `c` to be base64 strings; it ignores other keys.
- The plaintext is the complete edited text, valid UTF-8 (H8), with no wrapper.
- `"encrypted": true` is REQUIRED. When it is false or absent, RN shows `newText` verbatim (`ChatScreen.tsx:542`).
- `messageId` is the id of the message being edited; `toUserId` is a JSON number (H6).
- The edit does not touch the ratchet: no chain step is burned, no skipped key is created, and nothing counts toward §3.11.3.

**When RN still shows the raw `{n,c}` JSON.** Whenever the decrypt is skipped or fails, RN stores `newText` unchanged and persists it to `msgs:<conversationId>` (`messages.ts:544-551`). The garbled text therefore survives a restart, until a later edit to the same message decrypts. This happens when:

1. **No `ChatScreen` for the sender is mounted.** The edit is not handled at all and is lost (§3.10, delivery is live-only).
2. **`sharedKeyRef` is still `null`.** The screen has just mounted and `getPublicKey` has not resolved yet, or it failed with no cached key (`ChatScreen.tsx:288-299`).
3. **RN holds a stale `k` after the native peer re-keys.** This case needs care:
   - `sharedKeyCache` is a module-level `Map` keyed only by the numeric `peerId` (`crypto.ts:40`). `computeSharedKey` returns the cached entry without looking at the keys it was given (`crypto.ts:625-626`).
   - `clearSharedKey(peerId)` (`crypto.ts:639-641`) has **no caller**. `clearAllSharedKeys` (`crypto.ts:649-651`) is called only from tests.
   - The only production clear is inside `deletePrivateKey` (`crypto.ts:400`). It runs only when RN drops its **own** identity (`auth.ts:411`, `:425`, `:1275`); logout does not call it (`auth.ts:160-169`).
   - RN's `peer-key-rotated` handler resets the ratchet and the peer-key caches, but not `sharedKeyCache` (`App.tsx:585-612`). The chat screen's invalidation listener then nulls `peerPubB64Ref` and bumps `pubFetchEpoch` (`ChatScreen.tsx:321-324`). The refetch calls `computeSharedKey` with the new `publicKey` (`:294`) and gets the **old** `k` back from the cache.
   - Result: after the native peer re-keys, every legacy-box edit it sends to that RN peer fails to open and is persisted as raw JSON. This lasts until the RN process restarts, which empties the in-memory cache, or until RN drops its own identity. Native cannot detect this window. Ratchet messages are unaffected, because `peer-key-rotated` resets the session (§2.5).

**What a legacy-box edit gives up**, compared with a ratchet edit:

- **No forward secrecy and no post-compromise security.** `k` depends only on the two static X25519 identity keys. Anyone who records the frame (the server relays `newText` verbatim, `server.go:2157-2167`) and later obtains **either** party's identity private key can open every legacy-box edit that pair has exchanged, past and future. This is the same exposure as RN's story reactions (§4).
- **No replay protection and no binding to `messageId`.** The ciphertext covers only the edited text. A party able to inject `message-edit` frames stamped `fromUserId = X` (the relay) can replay an old edit, or move its `newText` onto another of X's messages. RN applies it, because its only check is that the target is not `from === 'me'` (`ChatScreen.tsx:539-540`). A ratchet edit cannot be replayed, since its message key is single-use.
- **Still confidential and unforgeable to third parties, including the server.** Only the two holders of the identity keys can derive `k`. As with the ratchet (§3.1), either of them could produce a ciphertext in the other's name.

**Native rules if this option is adopted** (whether to adopt it is Q3):

- **Sender.** There is no client-version signal, so the encoding cannot be chosen per peer. A native sender that adopts legacy-box edits sends them to every peer, native peers included.
- **Receiver.** Accept both encodings in `newText`:
  - if it parses as a v=2 envelope (§3.8), deduplicate and use the ratchet (§3.10). RN senders always send v=2 edits (`ChatScreen.tsx:722-729`);
  - otherwise, if it parses as `{"n","c"}`, open it with `beforenm(peerX25519Pub, myX25519Priv)`. A failure here MUST NOT count toward §3.11.3 auto-recovery, and MUST NOT be stored as the message text.
- **Cache.** Derive `k` from the peer's **current** `publicKey`. Unlike RN, native MUST drop its cached `k` for a peer on `peer-key-rotated` from that peer, and all cached `k` on its own re-key. The Rust core exposes both operations (`native/core/src/legacy_box.rs:105-113`, `clear_shared_key` / `clear_all_shared_keys`).

### 3.11 Recovery layer

Native MUST reproduce these behaviours, because they change what the *peer* experiences.

#### 3.11.1 Deduplicate before decrypting

If a message with the same `messageId` is already in the conversation, return without touching the ratchet (`messagePipeline.ts:728-754`). For mesh transports, re-send the mesh ACK (`:746-751`).

Without this, duplicates — WS plus offline replay, or WS plus mesh — fail to decrypt. The failures count toward auto-recovery and can fire a spurious `ratchet-reset`, which wipes the peer's session.

#### 3.11.2 `pn == 0` fresh-init recovery

`messagePipeline.ts:464-488`:

```
if decrypt(existingState, E) == null and existingState != null and E.pn == 0:
    fresh = initAsRecipient(myIdentityPriv, E)
    r = ratchetDecrypt(fresh, E)
    if r:
        persist r.state          // REPLACES the existing session
        clear the failure window
        return r.plaintext
```

This recovers when the peer reinstalled, logged out, re-keyed or reset. `E.n` may be greater than 0; the intervening keys are cached as skipped. On a responder's `pn=0` reply chain the attempt simply fails, which is harmless.

**Security note.** Combined with §3.1 (no sender authentication), any party that can get an envelope attributed to `fromUserId = X` can replace our session with X. Transport attribution is the only protection.

#### 3.11.3 Failure counting and auto-recovery

Client side (`messagePipeline.ts:377-402`, `:490-511`):

- The first failure opens a 5-minute window per peer, with `count = 1`.
- Every further clean `null` failure inside the window adds 1.
- When `count ≥ 3`:
  1. `resetRatchet(peer)` locally;
  2. clear the window;
  3. send `{"type":"ratchet-reset","data":{"peerUserId":<int>}}`.
- A successful decrypt clears the window.
- Throws (§3.7) and texts that are not v=2 are **not** counted.
- Replays of buffered envelopes **are** counted, because they go through the same function.

**Server** (`server.go:2298-2330`): forwards `{"type":"peer-ratchet-reset","data":{"userId":<sender int>}}` to **every registered connection** of the target (`userConns`). There is **no** `IsAlive` liveness filter, so a half-open socket can swallow the message. There is no persistence either: the message is live-only and lost if the target is offline. Requests with `peerUserId` 0, a non-number `peerUserId`, or a `peerUserId` equal to the sender are ignored.

**Receiver** (`App.tsx:641-656`): calls `resetRatchet(userId)`, then retries every buffered envelope from that peer.

#### 3.11.4 Pending-decrypt buffer

This is local UI behaviour, but it affects timing (`messagePipeline.ts:86-345`).

- A failed envelope is buffered for 8 s. There is one timer per peer, and later failures do **not** extend it.
- At most 5 envelopes per peer are kept, first-in first-out.
- The buffer is retried after any successful decrypt from the same peer (`:779`), and after a `peer-ratchet-reset`.
- When the timer expires, buffered messages become the placeholder `"⚠️ Не удалось расшифровать"` (`:246`).

#### 3.11.5 Other events that delete sessions

| Event | Sessions deleted | Source |
|---|---|---|
| Logout | all | `auth.ts:190` |
| One-time identity localisation (build 281) | all | `auth.ts:460` |
| Shared-identity heal | all | `auth.ts:1296` |
| `peer-key-rotated` received | that peer's | `App.tsx:597` |
| Stored session fails to deserialise | that peer's | `ratchetStore.ts:35-40` |

#### 3.11.6 Simultaneous initiation (as-built weakness)

Suppose both sides have no state and both send before either receives:

1. Each side receives a `pn=0` envelope that fails under its own sender state.
2. Each side then replaces its state through fresh-init, adopting the *other* side's session.
3. Each side's pending replies are encrypted in the session the other side just dropped, so they fail until auto-recovery kicks in.

Native cannot fix this on its own side without breaking RN. Reproduce the algorithm exactly; do not "improve" only one end.

### 3.12 Persisted session JSON (NOT INTEROP; only needed for the §2.7 migration)

`ratchet.ts:362-410`:

```json
{"rootKey":"<b64>","myDHPub":"<b64>","myDHPriv":"<b64>","peerDH":"<b64>",
 "sendChainKey":"<b64>|null","sendCount":0,"recvChainKey":"<b64>|null","recvCount":0,
 "prevSendCount":0,"skippedKeys":{"<b64 dh>:<n>":"<b64 mk>"},"sessionId":"<b64>|null"}
```

---

## 4. Legacy static box `{n,c}`

Construction (`crypto.ts:620-688`):

```
k    = beforenm(peerX25519Pub, myX25519Priv)    // HSalsa20(X25519(my, peer), 0^16); both parties get the same k
n    = random(24)
text = JSON.stringify({ "n": b64(n), "c": b64( secretbox(UTF8(plaintext), n, k) ) })
```

**Status: RN still sends it, but no RN receive path can read it** — except `message-edit.newText`, which RN opens with this box and displays (§3.10.1).

- **RN still emits it for story reactions** (`StoriesScreen.tsx:243-262`). The message is a `p2p-message` with `encrypted:true`, `action: "story-like"` or `"story-comment"`, `storyId`, `storyType`, and `storyContent` in **plaintext**.
- The RN inbox pipeline has **not** decrypted this format since build 88 (`messagePipeline.ts:410-441`). RN recipients see the reaction as undecryptable, and then as the placeholder.
- The only RN code that still attempts to open it is the broken edit path (§3.10). That path is broken only for ratchet edits; for a `{n,c}` `newText` it works, subject to the stale-key caveat in §3.10.1.

**Native guidance:**

- Native MAY decrypt `{n,c}` on receive, for example to show story reactions from RN. This is interop-safe.
- Native MUST NOT *send* `{n,c}`, because RN recipients cannot read it.
  - **Exception:** `message-edit.newText`. There `{n,c}` is the only encoding RN can display, at the cost of forward secrecy (§3.10.1). Whether to use it is Q3. Everywhere else the MUST NOT stands.
- For story reactions, native SHOULD send a v=2 ratchet envelope carrying the same `action`, `storyId`, `storyType` and `storyContent` fields. The RN pipeline decrypts it and keeps those fields (`messagePipeline.ts:852-881`).

---

## 5. Sealed Sender

Sealed Sender hides who sent a message from the WS routing layer. Only `toUserId` stays visible to the server.

### 5.1 Server signing key (server only)

The server loads its Ed25519 signing key from the first source that exists (`internal/sealedsender/sealedsender.go:82-128`; `main.go:226-236`):

1. the environment variable `SEALED_SENDER_SIGNING_KEY`: standard base64 of a 64-byte Ed25519 private key or of a 32-byte seed;
2. the file at `SEALED_SENDER_KEY_PATH` (default: a file in the server's data directory): raw 64 or 32 bytes;
3. otherwise a newly generated key, persisted as 64 raw bytes with mode 0600.

If the key rotates, every outstanding certificate stops verifying. Clients recover by refetching the verifying key (§5.3).

### 5.2 Certificate

**Wire JSON** (Go struct, `sealedsender.go:59-64`):

```json
{"uid": 42, "expires_at_ms": 1893456000000, "sender_pub": "<b64 X25519 pub>", "sig": "<b64 Ed25519, 64 B>"}
```

**Signed payload** (`sealedsender.go:194-203`; mirrored in `mobile/src/services/sealedEnvelope.ts:119-127`):

```
payload = BE64(uid) ‖ BE64(expires_at_ms) ‖ ASCII(sender_pub)     // the base64 TEXT, not the decoded 32 bytes
sig     = Ed25519.sign(payload, serverKey)
```

- Both integers are written as two's-complement int64. Both are positive.
- The payload is `16 + len(sender_pub)` bytes: 60 bytes when `sender_pub` is the canonical 44-character base64 of a 32-byte key. The server signs whatever non-empty string the client sent (see Issuance below), so a verifier MUST NOT hard-code 60.
- The certificate is valid for 24 h from issuance (`sealedsender.go:155`).

**Issuance:** `POST https://mrenzo.com/api/sealed-sender/cert`, authenticated with a Bearer JWT (`internal/sealedsender/handlers.go:65-106`).

- Request body: `{"senderPub":"<b64>"}`, at most 4096 bytes.
- Response: `{"cert":{...},"publicKey":"<b64 server Ed25519 pub>"}`.
- **The server does not validate `senderPub`.** It only checks that it is non-empty; it does not compare it with the caller's published key.

**Client cache** (`sealedSender.ts:133-180`). A cached certificate is reused only if all of these hold:

- `cert.uid == me.id`;
- `cert.sender_pub == <my current public key>`;
- `expires_at_ms − now > 1 h`.

Otherwise the client requests a new one. After a 401 it refreshes the JWT and retries once (`:43-65`). `senderPub` is taken from the auth store's `user.publicKey` (`ChatScreen.tsx:899`).

**Verification** (client `sealedEnvelope.ts:107-117`; server `sealedsender.go:173-188`):

```
reject if now_ms > expires_at_ms
Ed25519.verify(payload, b64dec(sig), serverPub)
```

**RN never checks `cert.sender_pub` against anything**, including the uid's published key, and never checks `cert.uid` beyond the signature (see Q6).

### 5.3 Server verifying key

`GET https://mrenzo.com/api/sealed-sender/server-key` needs **no authentication**. It returns `{"publicKey":"<b64 32 B>"}` with `Cache-Control: public, max-age=3600` (`handlers.go:36-49`).

**Client caching** (`sealedSender.ts:102-124`):

- The key is cached with a soft 24 h TTL.
- If a refresh fails on the network, the stale cached value is used.
- The certificate-issuance response also refreshes the cache (`:167-170`).

**Verify with refresh** (`sealedSender.ts:252-272`):

1. Verify with the cached key.
2. On failure, force a refetch.
3. Retry verification only if the refetched key differs from the cached one.

Native SHOULD reproduce this. Otherwise a server key rotation drops all sealed traffic until the cached key expires.

### 5.4 The sealed envelope blob

`sealedEnvelope.ts:46-68`:

```
inner = UTF8( JSON.stringify({ "cert": <the certificate object exactly as issued>, "ratchet": <wireText string> }) )
eph   = fresh X25519 keypair
nonce = random(24)
boxed = crypto_box(inner, nonce, recipientIdentityPub, eph.priv)     // tag16 ‖ ct
blob  = b64( nonce(24) ‖ eph.pub(32) ‖ boxed )
```

- **Byte order: the nonce comes first, then the ephemeral public key.** `OSB1` (§6) uses the opposite order.
- This is **not** libsodium's `crypto_box_seal`, which derives its nonce with BLAKE2b. It is a hand-rolled ephemeral-sender box.
- The recipient key must decode to exactly 32 bytes, or sealing fails (`:52-53`).
- `ratchet` holds the v=2 envelope's **JSON text**. It is not base64, even though the parameter is named `ratchetCiphertextB64` (`ChatScreen.tsx:915`).

**Open** (`sealedEnvelope.ts:76-100`):

```
raw = b64dec(blob); require len(raw) >= 24 + 32 + 16
inner = crypto_box_open(raw[56..], raw[0..24], raw[24..56], myIdentityPriv)
parse JSON; require typeof inner.ratchet == "string" && inner.cert present
```

RN ignores unknown keys inside `inner`. That gives native-to-native traffic a safe place for extensions; RN simply ignores them.

### 5.5 Delivery tokens

**Pair secret (server only).** Stored in the table `sealed_delivery_secrets(recipient_id, sender_id, pair_secret)` (`internal/db/db.go:702-748`):

- 64 lowercase hex characters, i.e. 32 random bytes;
- created lazily on the first token request, or on the first `p2p-sealed` verification (`GetOrCreateDeliverySecret`);
- **never rotated as built.** `RotateDeliverySecret` exists (`db.go:739-750`) and its comments describe rotating the secret when the recipient blocks the sender. Nothing calls it, so blocking a sender does **not** invalidate that sender's delivery tokens, and a blocked sender can keep sending sealed messages.

**Token** (`internal/sealedsender/token.go:65-79`):

```
K     = hexdecode(pair_secret)                 // the 32 raw bytes are the HMAC key
exp   = issue_time_ms + 6h
mac   = HMAC-SHA256(K, ASCII("token") ‖ BE64(exp))
token = lowerhex(mac) + ":" + lowerhex(BE64(exp))     // always 64 + 1 + 16 = 81 characters
```

**Endpoint:** `GET https://mrenzo.com/api/sealed-sender/delivery-token/{recipientId}`, with a Bearer JWT (`handlers.go:120-160`).

- Returns `{"token":"…","expiresAtMs":<int>}`.
- Returns 400 if `recipientId` is the caller, 500 if the secret is unavailable.

**Client cache** (`sealedSender.ts:206-232`):

- cached per recipient in the MMKV key `delivery_token:<id>` as `{token, expiresAtMs}`;
- refetched when less than 5 minutes remain;
- clients treat the token as opaque.

**Server verification** (`token.go:85-118`; called from `server.go:2027-2053`):

- the token is exactly 81 characters, with `':'` at index 64;
- `exp ≥ now`;
- the MAC matches, compared in constant time.

### 5.6 Sending a sealed message

Source: `ChatScreen.tsx:843-968`.

1. **Encrypt once** to get `wireText`.
2. **Check the local setting `push_hide_sender`.** If it is **false** (the default), send the legacy `p2p-message` (§3.10) and stop. Sealed Sender is used **only** when the user turned on "hide name in notifications" (`:865-895`), because the server can only put the sender's name in the push for legacy frames.
3. **Otherwise build the sealed envelope**, in this order:
   1. obtain a certificate (§5.2);
   2. warm the server verifying key without waiting for it;
   3. `blob = seal(cert, wireText, peerIdentityPub)`;
   4. obtain a delivery token. It is **required**: if it cannot be obtained, fall back to the legacy frame.
4. **Send:**

   ```json
   {"type":"p2p-sealed","data":{"toUserId":42,"messageId":"<id>","blob":"<b64>","deliveryToken":"<token>"}}
   ```

5. **If any client-side step fails**, send the legacy `p2p-message` with the **same** `wireText` (`:940-957`).

**Server-side rejections are not retried.** The server replies with a frame whose `data` is a **plain string**, `{"type":"error","data":"<reason>"}`. The reason is one of `"missing delivery token"`, `"invalid delivery token"`, `"secret unavailable"`, `"server misconfigured"` or `"rate limit"` (`server.go:1981-2053`). The error carries no `messageId`, so it cannot be correlated with the message. On success the server sends `message-ack {messageId, status:"sent"}` (`server.go:2105-2108`).

RN neither falls back to legacy nor retries in that case. On a healthy WS, `markSentOptimistic` has already set the message to `sent`. The 10 s timeout fails only messages still `sending` (`ChatScreen.tsx:974-1002`), and the store refuses to downgrade `sent` to `failed` (`store/messages.ts:233-253`). So the rejected message **silently stays at a single tick and is never delivered**. Native SHOULD treat an `error` frame that arrives right after a `p2p-sealed` as a failure, and resend the same `wireText` as a legacy `p2p-message`.

**Limits of the sealed path:**

- **It carries only brand-new plain-text messages.** Media, edits, retries (`:1051-1057`), story reactions and mesh drains always go as `p2p-message`.
- **It drops metadata:** the sealed frame carries only the blob, so `replyTo`, `autoDeleteSeconds`, `forwarded` and `type` are lost.

### 5.7 Receiving a sealed message

**Server → client:**

```json
{"type":"p2p-sealed","from":"server","data":{"toUserId":42,"blob":"<b64>","messageId":"<id>","ts":<ms>}}
```

The server delivers this only to connections that have sent a frame recently (`IsAlive(wsLivenessWindow)`). If there is no such connection, it stores the blob in the sender-less table `sealed_pending_messages` and sends a generic push. On reconnect it replays the frame with the same `data` shape, but **without** the `"from":"server"` field, and with `ts` set to the time the blob was stored (`server.go:2059-2104`, `:340-362`). Receivers MUST NOT require `from`.

**Client** (`App.tsx:1039-1110`):

```
inner = open(blob)                         ; null  → drop (logs sealed.openFailed); no ack
verifyCertWithRefresh(inner.cert)          ; false → drop (logs sealed.certInvalid); no ack
inject p2p-message { fromUserId: cert.uid, fromUsername: "", fromDisplayName: "",
                     messageId, type: "text", text: inner.ratchet, encrypted: true, transport: "sealed", ts }
```

From there the normal pipeline runs: dedup, ratchet decrypt, and **`message-delivered` sent to `cert.uid`**. That ack reveals the sender/recipient pair to the server, which partly defeats Sealed Sender (H12).

**`type` is forced to `"text"`.** RN only unwraps file envelopes for non-text types (`messagePipeline.ts:810-829`), so a file sent over `p2p-sealed` would show up on RN as raw file-envelope JSON. Native senders MUST NOT send media over `p2p-sealed` to RN peers.

**Expiry hazard.** A sender may use a certificate with as little as 1 h of validity left (23 h after issuance), and receivers check expiry against *now*. A recipient that stays offline longer than the certificate's remaining lifetime **silently loses** the message (H13, Q5).

---

## 6. Server at-rest offline seal (`OSB1:`)

When the server buffers a message for an offline user, it seals the whole JSON data map it would otherwise have forwarded. That map includes `fromUserId`, the E2E `text`, receipts and `__type`. The seal targets the recipient's **current** X25519 key, which the server fetches from storage.

**Seal** (`internal/server/seal.go:53-76`):

```
eph, nonce = fresh X25519 keypair, random(24)
ct  = box.Seal(blobJSONBytes, nonce, recipientPub, eph.priv)     // tag16 ‖ ct
out = "OSB1:" + StdBase64( eph.pub(32) ‖ nonce(24) ‖ ct )        // eph FIRST: the opposite of §5.4
```

**Open** (client, `crypto.ts:301-315`):

- A string without the `"OSB1:"` prefix is legacy plaintext and is returned unchanged.
- Otherwise require at least 32 + 24 + 16 bytes, run `crypto_box_open(ct, nonce, ephPub, myIdentityPriv)`, and decode the result as UTF-8 JSON.

Sealing is idempotent: the server never seals an already-sealed string (`seal.go:37-39`).

**Recipient key cache.** `fetchRecipientPubKey` caches each recipient's `/api/keys` answer for **5 minutes** (`server.go:568-609`). For up to 5 minutes after a re-key, the server can therefore still seal OSB1 blobs to the **old** X25519 key. The new identity cannot open those blobs; the client acks and skips them (see below). Native MUST treat an OSB1 blob that fails to open as "skip", not as a fatal error.

**Where OSB1 shows up:**

1. **The storage service copy.** `GET /api/offline/fetch` returns items `{id, fromUserId, encryptedPayload, ...}`, where `encryptedPayload` is either OSB1 or plaintext JSON (`server.go:614-640`; `storage/app/routes_offline.py:69-95`; client `App.tsx:1615-1655`).
   - The server **always** tries to seal, and falls back to plaintext if the recipient key is unavailable.
   - A payload the client cannot open is acked and skipped.
   - The outer `id` is the **storage row id** (a uuid hex), not the chat `messageId`. It is what goes into `POST /api/offline/ack {"messageIds":[<id>…]}` (`routes_offline.py:96-116`).
   - The outer `fromUserId` is **plaintext in the storage row**, taken from the Go service token (`routes_offline.py:57-62`). OSB1 therefore hides the payload and the inner metadata, but not the sender→recipient pair, from the storage host.
   - The client uses the **inner** `fromUserId`, and falls back to the outer one only if the inner map lacks it (`App.tsx:1642`). It processes every item with `sendDeliveryAck: false`.
2. **The Go DB pending copy**, only when the environment variable `SEAL_PENDING=1` is set; it is off by default (`server.go:713-735`). Such rows are replayed as `{"type":"p2p-pending-sealed","data":{"toUserId","blob","messageId","ts"}}`.
   - The server chooses the replay type by checking for the OSB1 marker (`seal.go:46-51`).
   - The client unseals the blob. If `inner.__type` is present and is not `p2p-message`, the client strips it and re-dispatches the message as that type; otherwise it dispatches a `p2p-message` (`App.tsx:1125-1148`).

---

## 7. SDP / DTLS-fingerprint signing for calls

> **Superseded by protocol v3 (build 349), §V3.4.** Kept as the reference of the ≤ 348 format, which a 349 client rejects.



### 7.1 Fingerprint canonicalisation

`crypto.ts:598-612`:

```
lines = split(sdp, /\r?\n/)
fps   = [ lowercase(trim(l)) for l in lines if l startsWith "a=fingerprint:" ]
        // the prefix test is case-SENSITIVE and runs on the untrimmed line
if fps is empty → "" (the SDP cannot be signed; the caller aborts)
fp    = join( sort( unique(fps) ), "|" )
        // JS default sort = UTF-16 code-unit order, which is byte order for ASCII
```

The whole line is kept and lowercased, including the `a=fingerprint:` prefix and the hash name, for example `a=fingerprint:sha-256 ab:cd:ef:01`.

### 7.2 Signed payload

Signing is in `webrtc.ts:431-467`; the verifier's payload construction is in `:2221-2229`.

```
payload = fp + "|" + decimal(ts) + "|" + nonce + "|" + decimal(fromUserId)      // modern form
payload = fp + "|" + decimal(ts) + "|" + nonce                                  // legacy (builds 35/36); used only when fromUserId is absent or 0 (room path only; see §7.3)
sig     = b64( Ed25519.sign(UTF8(payload), mySigningSecret64) )
rb      = b64( HKDF(sessionId, "mrenzo-ratchet-bind-v1|" + payload, 32) )        // only if a ratchet session with a sessionId exists for this peer
```

- `ts` is the signer's `Date.now()` in milliseconds.
- `nonce` is `b64(random(16))`: 24 characters ending in `==`.
- `fromUserId` is the signer's own uid.

**`rb` shortcut.** Because `rb` needs only one HKDF output block, it equals:

```
HMAC-SHA256( HMAC-SHA256(ZERO32, sessionId), UTF8("mrenzo-ratchet-bind-v1|" + payload) ‖ 0x01 )
```

This is noted in `ratchet.ts:421-429` and verified in §14.

### 7.3 Wire fields

Every offer and answer, including ICE-restart and renegotiation offers, carries these fields (`webrtc.ts:2095-2105`, `:2478-2486`, `:3127-3135`):

```json
{"type":"offer","sdp":"<exact SDP string>","sig":"<b64>","ts":1767225600000,"nonce":"<b64, 16 B>","fromUserId":42,"rb":"<b64>|null"}
```

How they travel (`webrtc.ts:1073-1106`):

- **1:1 calls:** WS message `call-offer` or `call-answer`, with `data = {...fields, callId}`.
  - **The server overwrites `data.fromUserId`** with the JWT-authenticated sender uid before relaying (`handleCallSignal`, `internal/server/call.go:617-619`). It relays only between the call's caller and callee.
  - Consequently the receiver always sees `fromUserId` and always builds the **modern** payload. The legacy payload (§7.2) cannot occur on the 1:1 path.
  - A signer that put a different uid into its signed payload fails verification. Native MUST sign with its own JWT uid.
- **Rooms:** WS message `offer` or `answer`, with `to` set to the peer id and `data` set to the fields. The room relay (`forward`, `server.go:2497+`) does **not** stamp `fromUserId`; it forwards the client's value. Only there can a missing `fromUserId` select the legacy payload.

**Not signed:** ICE candidates (`call-ice`, `candidate`), `call-start`, `call-accept` and the other call-control messages.

### 7.4 Verification

`verifyRemoteSDP`, `webrtc.ts:2194-2292`. The checks run in this order:

1. **Resolve the user.** `userId = Number(fromUserId)`, or the room-mapped id. If both exist and differ, fail with `userId-mismatch`.
2. **Check fields.** `sdp` and `sig` must be present. `ts` must be a number (else `no-ts`). `nonce` must be a string.
3. **Check freshness.** `|now − ts| ≤ 60000` ms, else `ts-skew:<ms>`.
4. **Compute `fp`** from the **received** `sdp` string. It must be non-empty.
5. **Verify the signature.** Build the payload (the modern form when `fromUserId` is present) and verify `sig` against the peer's `signingPublicKey` from `/api/keys/{userId}`, which is cached per call session.

   **Recover once on failure:** drop the cached peer key, trigger a republish of our **own** keys (`reconcileSigningKeyWithServer`), refetch the peer key, and verify again.
6. **Check `rb` (warning only).** If `rb` is a non-empty string **and** we hold a `sessionId` for the peer, compare the base64 strings. A mismatch is only logged (`webrtc.ts:2265-2290`); it was downgraded from a hard reject in build 86.

**On failure** the call is aborted through `onVerificationFailure`. Exception: if the peer connection is already connected, the failure is absorbed. The unverified SDP is not applied and the call continues (`webrtc.ts:237-250`).

**Native MUST:**

- send `ts` as a JSON integer and `nonce` as a string;
- always include `fromUserId` (the modern payload);
- send `rb` whenever it holds a session with a `sessionId`;
- treat an `rb` mismatch as a warning only, because RN computes `rb` from a session that may have desynced;
- verify with the modern and legacy payload rules exactly as above.

### 7.5 Replay protection and duplicates

There is **no persistent nonce cache.** Replay protection consists of two parts (`webrtc.ts:193-229`):

- the ±60 s freshness window;
- a per-peer, in-memory seen-set keyed by `"<offer|answer>:<ts>:<nonce>"`. If `ts` or `nonce` is missing, the raw SDP string is used as the key instead.

The entry is added **synchronously, before** the asynchronous verification, so a resend is ignored while the first copy is still being verified. It is removed again on a "soft" failure, so a later resend can be processed. An offer or answer with a new `ts`/`nonce` pair is never treated as a duplicate.

---

## 8. File and attachment encryption

### 8.1 Content encryption

`crypto.ts:707-738`:

```
key   = random(32); nonce = random(24)          // new for every file, never reused
blob  = secretbox(fileBytes, nonce, key)        // tag16 ‖ ct; this is exactly what gets uploaded
decrypt: require len(key) == 32 && len(nonce) == 24; then secretbox_open(blob, nonce, key)
```

### 8.2 Transport

**Upload:** `POST https://mrenzo.com/api/chat-files/upload`, multipart, with a Bearer JWT (`api.ts:1108-1197`). The **Go** server handles it (`main.go:381`, `internal/files/handler.go:51-165`), not storage.

- The `file` part carries the ciphertext bytes, with content type `application/octet-stream`. The request body is capped at 100 MB.
- **An addressee is required.** Send `recipientId` (the peer's uid, as a decimal string) for 1:1 chats, or `channelId` for group chats; the uploader must be a channel member. Without either (and without `kind=story`), the upload fails with 400 `"missing channelId or recipientId"`.
- **The addressee is also the download ACL** (`canAccessFile`, `handler.go:167-193`). Only the uploader, the named `recipientId`, or a member of `channelId` may download. Anyone else gets **404**. A native sender that addresses the file to the wrong uid makes the attachment undownloadable for the peer, even though the ratchet envelope decrypts.
- The response is the file record `{"id":"<fileId>","name":…,"size":<int>,"mimeType":…,"uploaderId":…,"recipientId":…,"createdAt":…}`. Clients use `id` and `size`.
- RN names the multipart file `dbg-pt<N>-ct<N>-tmp<N>-<originalFileName>.enc` (`api.ts:1168`). That **leaks the plaintext file name and sizes to the server** (H14). Native SHOULD send an opaque name; the server works with the returned id, not the name.

**Download:** `GET https://mrenzo.com/api/chat-files/{fileId}` with a Bearer JWT returns the raw ciphertext. RN strips whitespace from its own base64 of the body before decrypting (`api.ts:1199-1257`).

### 8.3 File envelope (the ratchet plaintext for media)

`crypto.ts:747-789`:

```json
{"p":"<placeholder text>","id":"<fileId>","k":"<b64 key, 32 B>","n":"<b64 nonce, 24 B>","m":"<mime>","fn":"<fileName>","s":12345,"d":4.2}
```

- `fn`, `s` and `d` are omitted when undefined.
- `d` is the duration, used for voice messages. RN sends voice as `m: "audio/m4a"` (`ChatScreen.tsx:1229`), with `fn` and `d` but no `s`.
- **`s` is the ciphertext size as built:** for image, video and file, RN puts `enc.size || fileSize` (`ChatScreen.tsx:1168`). `enc.size` is the server-reported stored size (`api.ts:1191`), which is plaintext + 16. Native receivers MUST treat `s` as advisory, display-only data and never use it to validate the decrypted length.

**Parsing rules** (`crypto.ts:771-789`):

- `id`, `k` and `n` must be truthy.
- `id` is coerced with `String()`.
- `m` defaults to `application/octet-stream`.
- `s` and `d` must be numbers; `fn` must be a string.
- The envelope is parsed only when `p2p-message.data.type` is neither `text` nor `system` (`messagePipeline.ts:810-829`).
- `p` becomes the text shown in the chat bubble.

### 8.4 Legacy plaintext fallback (as built)

If the sender does not have the peer's key yet, RN uploads the file **unencrypted** (`uploadChatFile`) and sends:

```json
{"text":"<placeholder>","type":"...","fileUrl":"...","fileName":"...","fileSize":...,"encrypted":false}
```

Source: `ChatScreen.tsx:1210-1215`. Native SHOULD NOT send this form, but MUST render it when received, using `fileUrl`, `fileName` and `fileSize`.

---

## 9. Safety numbers

> **Superseded by protocol v3 (build 349), §V3.6.** Kept as the reference of the ≤ 348 format, which a 349 client rejects.



`safetyNumbers.ts:49-72`:

```
a, b   = b64dec(myX25519Pub), b64dec(peerX25519Pub)
(x, y) = (a, b) if bytewise_compare(a, b) <= 0 else (b, a)     // lexicographic on bytes, then by length
d      = SHA-512(x ‖ y)
for i in 0..5: v_i = BE_uint40(d[5i .. 5i+5]) mod 100000; block_i = zero-pad(v_i, 5)
number = join(blocks, " ")        // e.g. "08876 19738 10135 62818 13302 34562"
```

- **Inputs are the published X25519 identity keys:** our own from the auth store's `user.publicKey`, the peer's from `getPublicKey` (`SafetyNumbersScreen.tsx:80-105`).
- **The order of the two keys does not matter**; they are sorted first.
- **Only X25519 goes in, not Ed25519.** A signing-key-only change does **not** change the safety number.
- **"Verified" status is stored on the device.** The MMKV store `mrenzo-safety` maps `verified:<peerId>` to `{safetyNumber, verifiedAt}`. The status becomes "changed" when the stored string differs from the recomputed one (`safetyNumbersStore.ts:16-67`).

Two native clients and an RN client all show the same number for the same pair of keys.

---

## 10. Group Sender Keys (as built, effectively non-functional)

> **Superseded by protocol v3 (build 349), §V3.7.** Kept as the reference of the ≤ 348 format, which a 349 client rejects.



This code is live in `GroupChatScreen` and `ChannelChatScreen`.

**Primitives** (`senderKeys.ts`):

```
state    = { chainKey: 32 B, signingPub: 32 B, signingPriv: 64 B (sender) or empty (recipient), counter }
MK(ck)   = HKDF-SHA256(salt = ZERO32, ck, "mrenzo-sender-msg", 32)
NEXT(ck) = HMAC-SHA256(key = ck, msg = 0x02)          // the comment at :10 says "next"; the code uses 0x02

encrypt:
  nonce  = random(24)
  ct     = secretbox(UTF8(pt), nonce, MK(ck))
  sig    = Ed25519.sign(BE64(counter) ‖ ct, signingPriv)     // ct is tag16 ‖ ciphertext, WITHOUT the nonce
  env    = {"v":1,"ct":b64(ct),"n":b64(nonce),"ctr":counter,"sig":b64(sig)}
  state' = {chainKey: NEXT(ck), counter: counter + 1}

wire     = "sk1:" + JSON.stringify(env)       // sent as the channel message text via the REST call sendChannelMessage

decrypt:
  verify sig
  reject if ctr < state.counter
  apply NEXT() from state.counter up to ctr, then open
  state' = {chainKey: NEXT(ck_ctr), counter: ctr + 1}
```

- The signing keypair is a fresh Ed25519 key per group, not the identity signing key (`senderKeys.ts:84-93`).
- The constant `RATCHET_INFO = "mrenzo-sender-chain"` (`:73`) is **never used**.

**SKDM (Sender Key Distribution Message)** (`senderKeyStore.ts:147-179`):

```json
{"v":1,"groupId":"<channelId>","chainKey":"<b64, 32 B>","signingPub":"<b64, 32 B>","startCounter":<int>}
```

It is sent as `{"type":"p2p-message","data":{"toUserId":<member>,"action":"sender-key-distribution","payload":<SKDM>}}`.

**Why this is non-functional:**

- **The SKDM is sent in PLAINTEXT.** No ratchet step is applied, despite a comment saying otherwise (`senderKeyChannel.ts:260-271`). The server can therefore read every group chain key.
- **No receive path ever calls `handleIncomingSKDM`** (searched across `mobile/src`). The pipeline discards the frame as an empty decode, so recipients never get state and always show `"🔒 (ожидание ключа)"` ("waiting for key").
- **Decryption runs inside a render `useMemo` and saves the advanced state** (`GroupChatScreen.tsx:215-229`, `ChannelChatScreen.tsx:323-329`). Re-rendering a message that was already decrypted would then fail the counter check.

**Consequence for native:** there is no working group E2E to interoperate with. RN displays group messages without the `sk1:` prefix as plain text. See Q1 for the decision this needs.

### 10.1 Build 325 — the semantics native implements

The primitives, the `sk1:` envelope and the SKDM JSON above are unchanged. What 325 adds (core: `native/core/src/group_chains.rs`, FFI `sender_key_*`, vectors `senderKeysV2.json`):

- **SKDM transport v2.** The SKDM JSON is the plaintext of a 1:1 Double Ratchet v=2 envelope carried in `data.skdm`: `{"type":"p2p-message","data":{"toUserId":M,"messageId":"skdm-…","action":"sender-key-distribution","skdmTransport":2,"skdm":"<ratchet wire>"}}`. v1 plaintext `payload` SKDMs are rejected. The SKDM is a snapshot at the counter of the message being sent.
- **Incoming chain sets.** `recv:<g>:<sender>` = current chain; `recvprev:<g>:<sender>` = `JSON.stringify` array of up to 3 previous chain blobs, newest first. A missing/corrupt current means no chains at all.
- **Ingest** (validation: `v === 1`; non-empty string `groupId`/`chainKey`/`signingPub`; `startCounter ?? 0` a non-negative safe integer; 32-byte keys). Chains are identified by `signingPub`: an SKDM for a previous chain is ignored; for the current chain the receiver's copy is kept unless `startCounter > counter + 2000` or the key does not match the copy walked forward (then replaced); a new chain becomes current and the old current is prepended to previous.
- **Decrypt.** The envelope must be an object with `Number.isSafeInteger(ctr) && ctr >= 0`; chains are tried current first; a chain with `ctr − counter > 2000` (`MAX_CHAIN_WALK`) is skipped; wrong-size `sig`/`n` are failures, not throws. In a batch each sender's envelopes are opened in `(senderId, ctr, index)` order; walks over 32 steps are charged to a 4000-step per-sender budget only after the signature verifies; a verified walk that still fails is memoised under the chain-set fingerprint (`signingPub`s joined by `,`).
- **Encrypt.** A wire over 4000 bytes is refused (`GROUP_MESSAGE_TOO_LONG`) before the chain advances. The outgoing chain `sender:<g>` is only used when `sender-v2:<g>` equals `hex(SHA-256(blob))[0..32]`; otherwise a fresh chain is minted (≤324 builds leaked theirs in plaintext SKDMs). No path returns the plaintext as the group wire.
- **Distribution (native: `Groups/SenderKeyService.swift`).** Member list fetched per send (empty/failed → the send fails, never plaintext); each member ≠ self gets the SKDM once per chain per process, served only on the server `message-ack` of the frame within 30 s, else left alone 2 min; ≤ 50 SKDM frames/min; waits ≤ 30 s for an open socket and never uses the outbox or memory queue; the send waits ≤ 3 s for the fan-out. A rotation (kick) re-checks the chain before every send, so an old-chain SKDM never leaves after the new one.
- **Receipt (native: `MessagePipeline.receiveSKDM`).** Routed before the call sink and the chat path (live, pending-sealed and offline backlog alike); v1 or non-v2 frames ignored; dedup on `messageId` in the persisted `skdmseen` list (last 1000, kv scope `sender-keys`) and the pending buffer before the ratchet; the ratchet advance, `skdmseen` mark and ingested chain commit in ONE transaction; an undecryptable SKDM waits in the per-peer pending buffer (replayed on the next envelope / `peer-ratchet-reset`, silently dropped on expiry). No message row, conversation or `message-delivered`. Sender Keys live in the sealed `kv` table under scope `sender-keys` with the RN key names.

---

## 11. X3DH prekeys (uploaded, never used; native ports the bootstrap)

> **Superseded by protocol v3 (build 349), §V3.3.1, §V3.2.2.** Kept as the reference of the ≤ 348 format, which a 349 client rejects.



RN runs an X3DH prekey bootstrap at launch (`mobile/src/services/x3dhBootstrap.ts`; `App.tsx:300-315`).

- **Signed prekey (SPK).** A fresh X25519 keypair, rotated every 7 days. Its signature is `Ed25519.sign(the raw 32-byte SPK public key, identitySigningSecret)` (`x3dh.ts:216-229`).
  - Uploaded with `POST /api/x3dh/spk`, body `{keyId: int > 0, pubKey: b64, signature: b64}` (Go, `handlers.go:2206-2244`).
- **One-time prekeys (OPKs).** Uploaded with `POST /api/x3dh/otps`, body `{keys:[{keyId, pubKey}]}`, 1 to 200 keys per request.
  - RN checks `GET /api/x3dh/otp-count` (→ `{count}`) and uploads a batch of 100 when the count is below 20.
- **Bundle fetch.** `GET /api/x3dh/bundle/{userId}` hands out one OPK and removes it from the pool. It is rate-limited to 10 per minute per (requester, target) pair and 60 per minute per requester (`handlers.go:2295-2371`).
- **The derivation is dead code.** `deriveSharedSecretAsSender` and `deriveSharedSecretAsRecipient` compute

  ```
  HKDF-SHA256(salt = ZERO32, 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], "mr.enzo.x3dh.v1", 32)
  ```

  but nothing calls them. The ratchet initialises as described in §3.4 instead.

~~Native MAY skip prekey uploads entirely, since nothing consumes them (Q10).~~ Superseded 2026-09-27: the native app **ports the bootstrap for parity**, so the Go server keeps a valid SPK and OPK pool for every migrated or new account, and the X3DH first-message path can be switched on later without another client release.

- **Where.** `X3DHService` (`native/ios/MrEnzo/MrEnzo/Data/X3DHService.swift`), kicked by `MessagingRuntime` when the identity reaches `ready` (server-confirmed; RN: after auth once the signing key is loaded) and on every foreground. It runs detached and never blocks the UI or the socket. Concurrent kicks share one run.
- **Same policy as RN.** The SPK is rotated when `spk:current` is missing, unparsable or older than 7 days (`rotatedAt`, JS coercion). The OPK pool is refilled with 100 keys when `otp-count` < 20 **or** `opkRefillPending` is set. A failing count fetch skips the refill. A failed SPK upload stores nothing. A failed OPK upload sets `opkRefillPending = "1"`, and the next run retries.
- **Same bytes.** Generation, the stored-SPK JSON and both upload bodies come from the Rust core through the FFI (`x3dh_generate_signed_pre_key`, `x3dh_generate_one_time_pre_keys`, `x3dh_spk_needs_new`, `x3dh_stored_spk_json`, `x3dh_spk_upload_body`, `x3dh_otps_upload_body`, `x3dh_constants`). They are checked against `vectors/x3dh.json`.
- **Same storage.** Account DB `kv(x3dh, …)`, sealed, using exactly the keys the RN importer writes from `mrenzo-x3dh`: `spk:current` (RN JSON), `opk:<id>` (b64 private), `nextKeyId` and `spkRotatedAt` (decimal strings), and `opkRefillPending` (`"1"`/`"0"`). An imported account therefore continues its SPK, its OPK privates and its id counter; nothing is regenerated.
- **Deliberate local deviations.** Nothing visible to the server or to peers changes.
  - An OPK batch reserves its whole id range (`nextKeyId = start + 100`) before the upload. RN reserved only one id, so a retry after a failed upload overlapped `start+1…start+99`. If the "failed" request had in fact landed, `INSERT OR IGNORE` kept the first batch's pubs while the device held the second batch's privates for the same ids.
  - OPK privates are stored before the upload. A definite HTTP rejection deletes them again (the Go insert is one transaction). An ambiguous network failure keeps them, in case the request landed.
- **After an identity takeover (§2.8).** The takeover deletes `spk:current`, sets `opkRefillPending`, moves `nextKeyId` to a random base in `[2^24, 2^30]` (never lower) and sets the native-only `opkPoolResetPending = "1"`. The next run first sends `DELETE /api/x3dh/otps` (drops the caller's whole pool; 01 §6), then signs a new SPK and uploads a fresh batch. A 404/405 (a server without the endpoint) clears the mark and goes on; the other device's stale pubs then drain as bundles are fetched. A network or server error keeps the mark and skips the refill until the next run.

---

## 12. Mesh crypto touchpoints

> **Superseded by protocol v3 (build 349), §V3.9.** Kept as the reference of the ≤ 348 format, which a 349 client rejects.



Mesh framing, relaying, the pigeon queue and the transports are specified in `04-mesh.md`. This section covers only the crypto that has to match §3 (`meshCrypto.ts`, `mesh.ts`).

**Payload padding** (`meshCrypto.ts:339-379`):

```
padded = b64( BE32(len) ‖ UTF8(wireText) ‖ random fill up to the bucket size )
```

- `wireText` is the ratchet wire text from §3.
- The bucket is the smallest of 256 / 512 / 1024 / 2048 bytes that fits `len + 4`. Beyond that, the next multiple of 2048 is used.
- On unpad, lengths above 1 MiB are rejected.

**Recipient index `toIdx`** (`meshCrypto.ts:296-315`):

```
toIdx = b64( SHA-512( beforenm(peerPub, myPriv) ‖ BE32(floor(ts_ms / 3600000)) )[0..8] )
```

- `beforenm` is the **HSalsa20-over-X25519** key, not raw X25519.
- A receiver tries `toIdx` against every cached peer public key, then falls back to the plaintext `to` field (`mesh.ts:1146-1175`).

**Signature** (`meshCrypto.ts:521-522`, `:569-570`, `:594-599`):

```
binding = id + "|" + decimal(ts) + "|" + decimal(from.uid) + "|" + decimal(to) + "|" + payload
sig     = Ed25519.sign(UTF8(binding), identitySigningSecret)
```

For messages, `payload` is the padded base64 string. For ACKs it is the raw ID of the acknowledged message.

**Inner blob** (`meshCrypto.ts:131-187`):

```
flags(1) ‖ sig_pub(32) ‖ BE64(from_uid) ‖ [BE64(to) if flags & 0x04] ‖ [toIdx(8) if flags & 0x02] ‖ BE16(payloadLen) ‖ payload ‖ sig(64)
```

- Flag bits: `0x01` padded, `0x02` has `toIdx`, `0x04` has `to`, `0x08` is an ACK.
- The payload bytes are `b64dec(padded)` for messages and the UTF-8 ID for ACKs.
- The outer JSON is `{v:1, id, ttl, hops, L, mode, ts, b: b64(inner)}`.

**Receiver checks** (`mesh.ts:1029-1080`, `:1188-1217`):

1. Verify the signature against the embedded `sig_pub`.
2. Replay window: reject if the envelope is older than 24 h + 1 h, or more than 5 minutes in the future.
3. **Sender pinning.** On act-paths (ACKs, and messages addressed to us), drop the frame if we have a cached `signingPublicKey` for `from.uid` and it differs from `sig_pub`.

The mesh ACK is sent only after the message has been decrypted and persisted successfully (`messagePipeline.ts:966-978`).

---

## 13. Apple-only vs cross-platform; Android equivalents

**Cross-platform (on the wire).** Every construction in §§2.2–2.6 and 3–12 is platform-neutral. It MUST be byte-identical on native iOS, Android and RN.

**Apple-only items and their Android counterparts:**

| Item | Apple mechanism | Android equivalent |
|---|---|---|
| Identity key storage | Keychain, AfterFirstUnlock, `synchronizable=false`; legacy synchronizable-partition quirk (§2.7) | AES-GCM over raw key bytes, key wrapped by Keystore; no cloud sync; excluded from Auto Backup |
| Local database encryption | MMKV with a 16-byte AES key held in the Keychain (`com.mrenzo.mmkv.key`; ThisDeviceOnly for new installs, `secureStorage.ts:174-185`) | SQLCipher or Tink AEAD with a Keystore master key |
| Excluding encrypted stores from backups | `NSURLIsExcludedFromBackupKey` (`AppDelegate.mm:794-815`) | `android:allowBackup="false"` or `dataExtractionRules` |
| Crypto primitives | CryptoKit (X25519, Ed25519, SHA, HMAC, HKDF) **plus libsodium** (secretbox, box, beforenm) | libsodium (lazysodium) for everything; optionally Tink or BouncyCastle for HKDF and Ed25519 |
| Mesh link encryption | MultipeerConnectivity `MCEncryptionRequired` (transport only). The BLE transport added in build 321 (`BleMeshModule.m`, `MeshFrameCore.m`) has **no** link encryption. | None. MultipeerConnectivity is Apple-only and cannot talk to Android, so any iOS↔Android mesh link must use the BLE transport, which is unencrypted at the link layer on iOS too. The mesh envelope is already signed and E2E-encrypted by the ratchet, so the app layer is sufficient. |
| Calls | CallKit / PushKit (no crypto involved) | ConnectionService / FCM; SDP signing is identical |

---

## 14. Known-answer test vectors

> **Level 2 (mr.enzo 1.1).** The vectors of wire level 2 are generated by the Rust core from the golden PRNG and live
> in `docs/native/vectors` (format and regeneration: `vectors/README.md`):
>
> | File | Pins |
> |---|---|
> | `typedV11.json` | `caps` (canonical and lenient), the builders of every kind with soft keys and padding, the classification table (typed / unsupported), one carrier per kind |
> | `unsupportedV11.json` | an authenticated unknown kind → `unsupported` with the state after; stale on the current chain and across a DH step; the aux; the same replay without an aux = failed; the skip budget |
> | `capsV11.json` | the statement's canonical string and signature; every verification outcome |
> | `pqxdhV1.json` | signed KEM prekeys; the hybrid derivation with / without OPK × one-time / last-resort; the `xflag 2` header and wire; initiator, responder and envelope negatives |
> | `ratchetV3Pq.json` | a transcript over a hybrid session, with its at-rest JSON (`pq`, `x.kem`) |
> | `mlkem768Kat.json` | seed → `ek`, `m` → `ct` / `ss`, an implicit rejection; the cross-check file for Go `crypto/mlkem` |
> | `pttV1.json` | chunks with recorded nonces, every framing negative, the receiver script (a truncated stream, a second sender reusing the id, the authenticated end) |
> | `reactGroupV1.json` | `mk` → `rk` → `k_u`, an add and a removal blob of one length, negatives, the register table |
> | `stickerV1.json` | the `st` table; a PNG, its padded form and its id; malformed PNGs |
> | `pushHintV1.json` | the two hints sealed and opened; negatives |
> | `meshV11.json`, `meshCourierV1.json` | 04 §20 |
>
> The 1.0.0 vectors (`x3dhV2`, `ratchetV3`, `ratchetV3Negative`, `skippedCap`, `senderKeysV3`, `meshV2`, …) are
> unchanged and verified by the same test run; `tests/compat_353.rs` runs level-2 output through the frozen 1.0.0 core.

**How they were produced.** The **unmodified production modules** below were run under Node 22 with the real tweetnacl 1.0.3 and tweetnacl-util 0.15.1:

- `mobile/src/utils/ratchet.ts`
- `mobile/src/utils/safetyNumbers.ts`
- `mobile/src/services/sealedEnvelope.ts`
- `mobile/src/utils/senderKeys.ts`

`@noble/hashes` was replaced by a shim over Node's `crypto` module (RFC 5869 HKDF, HMAC, SHA-2). Randomness came from a deterministic PRNG installed with `nacl.setPRNG`; every random value consumed is listed below.

**How they were checked:**

- Every value was re-derived independently with PyNaCl 1.5 (libsodium) and a hand-written RFC 5869 HKDF built on `hmac`/`hashlib`. All 40 checks passed.
- The certificate and delivery-token vectors were also checked with the **real Go** `internal/sealedsender` code: `Verify` returns nil, and `IssueDeliveryToken` produces the identical token.

**Ed25519 signatures** below are deterministic (tweetnacl and libsodium agree). With CryptoKit, **verify** them; do not try to reproduce the bytes.

**Sanity anchors against published test vectors:**

- The X25519 shared secret `4a5d9d5b…1742` is the RFC 7748 §6.1 test vector.
- `beforenm` = `1b275564…8389` is the classic NaCl "firstkey" test vector.
- The file vector reuses NaCl's firstkey and nonce as its key and nonce.

### 14.1 Identities

```
alice_x25519_priv  = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
alice_x25519_pub   = hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=   (8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a)
bob_x25519_priv    = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
bob_x25519_pub     = 3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=   (de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f)
alice_ed25519_seed = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
alice_ed25519_sk64 = nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGg==
alice_ed25519_pub  = 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
```

### 14.2 Double Ratchet transcript

The sequence is: Alice → Bob twice, Bob → Alice, then Alice → Bob.

```
alice_eph_priv            = eda8d97f846bbb25459614d2698e2be477e3f79f0975e89ccc58d34457f52da0
alice_eph_pub             = mm9+fjLXhmVHl0Gg29NK37rNT9sGxnqgG0ZzrCASawM=
SK = DH(eph, bob_pub)     = 200228549dd485e5d673123d2e5230f156be82c47a6ec72ff74f1761b307fb45
INIT(SK)                  = 527d41abea17a946e65da473056fb64eed5df1660434fd00aeaa406573c7d994
RK = KDF_RK(INIT,SK).root = fc0eaa5a31ab796c5be9dc0a5c3835b303a7ccd48c1d57520e9822f84fdc73c5
CKs0                      = e2ea535c2e3fcceb2ba6bf341d6db6f665251e59fa39724365bcecf563e16c05
sessionId                 = e75160f00e895a52594e63f0b279637249ffc75d40d298d2d28d4f6ce9a47b21
MK(n=0) = KDF_CK(CKs0).mk = b9507447d07c2970865e62165a36664115c7b25b98c6d9b30ec3123a9290770a
CKs1                      = bcc096b18bd7406aa98f9752b18943355a765d0652707be301e63b9bf29d3fe8

msg1 plaintext "Привет, Bob! 👋"  (UTF-8 d09fd180d0b8d0b2d0b5d1822c20426f622120f09f918b)
     nonce c1871b6f441f4bdee54523fabf170d55df3a4170126e40a1
     wire  {"v":2,"dh":"mm9+fjLXhmVHl0Gg29NK37rNT9sGxnqgG0ZzrCASawM=","pn":0,"n":0,"ct":"wYcbb0QfS97lRSP6vxcNVd86QXASbkChGTsgJhLzcPrU+QcnPShkA7qDWtQBmfFlepWEcM2iJ1Sg3v3IyyPc"}
msg2 plaintext "second"   nonce b4190daac869e5dc01d11270a95dce6a3c45a57c44fa7a7f
     wire  {"v":2,"dh":"mm9+fjLXhmVHl0Gg29NK37rNT9sGxnqgG0ZzrCASawM=","pn":0,"n":1,"ct":"tBkNqshp5dwB0RJwqV3OajxFpXxE+np/jDZT5FD8p06vqd4tm+Lq9hp8CQI6Qg=="}

Bob, initAsRecipient(bob_priv, msg1): rootKey = INIT(SK) = 527d41ab…d994
  Bob's new ratchet DH priv = 9685704d7ceb79bef206044f65c030060c34cdaa101cc8144043442380ad55d3
  Bob's new ratchet DH pub  = aMiKizHAXFRpQ5FxOnQKeMYj+UeG9A7wEjOlBtvd2gY=
  after decrypting msg1:
    rootKey = a1e2a803e72c723c67adb65c2c8ada9928773b70de319783a04ecbd5a16549da
    CKr     = bcc096b18bd7406aa98f9752b18943355a765d0652707be301e63b9bf29d3fe8   (= Alice's CKs1)
    CKs     = b14f97917d4c8d798d2302c86ea5547ddac9391b6fa054b1688a224448bead6a
    Nr=1  Ns=0  PN=0      ; then decrypts msg2 → "second"

msg3 Bob → Alice "reply from Bob"   nonce 2a20b2c87a467c0a4dbd7c785677dede2b4c945f5d3d8ded
     wire  {"v":2,"dh":"aMiKizHAXFRpQ5FxOnQKeMYj+UeG9A7wEjOlBtvd2gY=","pn":0,"n":0,"ct":"KiCyyHpGfApNvXx4Vnfe3itMlF9dPY3tK+UBQuQew1DY+DkhbGOjtY+OJVsBrbpY0Yj9Dbva"}
Alice after decrypting msg3:
    new DH priv = 1f1a0c3f9effe46035b6c383672dbd9f6b238fbde0929507b930032d8d7a203d
    new DH pub  = CeYQHJUaZxgdJrvBxFHrfvA039GBAbm9tP/mrgp58A4=
    rootKey     = 2ba2cd1419054f314ec7c7fc3e6cca5201a408d76233304dd674372483b736bb
    CKs         = 32d31b9fd786d17f8ab3ad59505f1fc94f93aaa39f23a78ef008d27d420d29a2      PN=2
msg4 Alice → Bob "alice again"   nonce 96ab743174492fb10a3070e31d926b3356e733dae966af2f
     wire  {"v":2,"dh":"CeYQHJUaZxgdJrvBxFHrfvA039GBAbm9tP/mrgp58A4=","pn":2,"n":0,"ct":"lqt0MXRJL7EKMHDjHZJrM1bnM9rpZq8vVF4FK0i6wtfPWaTHYUCqKgxpq/1cbaSiTNB1"}

binding MAC:
  payload "a=fingerprint:sha-256 ab:cd|1767225600000|AAAAAAAAAAAAAAAAAAAAAA==|42"
  rb = iToLxcKLRNuNfni6Lk9YfMgt/4TZ5BgX5W4dhvVDhW4=   (Alice and Bob compute the same value)
```

### 14.3 Safety number

```
alice_x25519_pub + bob_x25519_pub  →  "08876 19738 10135 62818 13302 34562"   (same result with the arguments swapped)
```

### 14.4 Sealed Sender

**Server key and certificate:**

```
server_seed        = 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
server_pub         = PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=
cert payload (hex) = 000000000000002a 000001b8dac5b400 6853447743596b777031523069333363744437335767322f4f67306d4f427230363653706a717162546d6f3d
                     = BE64 uid=42 ‖ BE64 exp=1893456000000 ‖ ASCII "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
cert JSON          = {"uid":42,"expires_at_ms":1893456000000,"sender_pub":"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=","sig":"nWGe7m+vVHYhyF7QXyu8i63WN3p0236Dh5CuzrrgFdtu5tgbSq7y24jX+DlbyfMkeFwnI3kdg3Rj0gCyACqJDQ=="}
```

**Sealing msg1 (§14.2) to Bob:**

```
eph_priv   = 127a413d21dc11541ae8b8ab9f6f2077870a021000d7bd5c6fbe28de5b932065
nonce      = 9b4863e73b37905a3f67c96288b2888fa4aea0158aad9e3b
recipient  = bob_x25519_pub ; inner.ratchet = msg1 wire text
inner JSON = {"cert":{"uid":42,"expires_at_ms":1893456000000,"sender_pub":"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=","sig":"nWGe7m+vVHYhyF7QXyu8i63WN3p0236Dh5CuzrrgFdtu5tgbSq7y24jX+DlbyfMkeFwnI3kdg3Rj0gCyACqJDQ=="},"ratchet":"{\"v\":2,\"dh\":\"mm9+fjLXhmVHl0Gg29NK37rNT9sGxnqgG0ZzrCASawM=\",\"pn\":0,\"n\":0,\"ct\":\"wYcbb0QfS97lRSP6vxcNVd86QXASbkChGTsgJhLzcPrU+QcnPShkA7qDWtQBmfFlepWEcM2iJ1Sg3v3IyyPc\"}"}
blob       = m0hj5zs3kFo/Z8liiLKIj6SuoBWKrZ47eDuMolA7Lj2x5YeWPrJGwKKhaKffuPm+dOCoQ/EWR2Hjfau670ty7fI+zo0u3SdoVjgTpJr3FgRsNhEOVBMkpl6yT/g5XNtvWXRfnWw6dMgzuHReKuDiwkB50/+nBlHwvPe+IuABftB0zjk/pMsPcOYQaVktC9eCrZKK9Mxl47QX+Q5mCweoGX+BRxdM3x4LxLMGsbrsXXfMLFu8Uk02GhhyIzN/dPXM955Sai+Qu2KWc1JSmUXxrHWLldracs0oJwKBEu9+TIO8EUmqQP+tSh4q42h/HfVxd29n6gg0L5AGX0DW2E4whJTNyJBY1G01CSWAIIwpm4yn3DCbHlrruZU3zUP8o96wpsM0nc2rdLMc5tpbnENAES7jezW8rl2STGUymnpFepPsEyYDRrkFh5C/71jtN7CasbaGDzqdDlf1pMMlYKQXx3Kiah4orrfk0BWluiWF86ZJeHUYkr5QJYeqGRO8aoRR9+kCnFL4cHWV71/ankBTkeTvfyOISEJHgo8zC4BBV8yxFpOQHCJ5GgexZpJnMkTAqZa//XoCStRvc+0K30NgXRmYfwZk5HmBLVfybT3DjzKdSFEWZQ==
```

**Delivery token:**

```
pair_secret = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f (hex)
exp         = 1767225600000
token       = 4129198223253ab577dd065747ad50956cf86612904421c2c6f2d57083da9616:0000019b76daa800
```

**Note on the blob.** The exact bytes of the inner JSON depend on the serialiser; for example, Swift escapes `/` as `\/` by default. Opening parses JSON, so what is fixed is *this blob's decryption output*. A native sealer does not need to reproduce the blob bytes.

The seeds and ephemeral keys in this worked example (`server_seed`, `eph_priv`, `pair_secret`) are throwaway test values; they belong to no account and to no service.

### 14.5 OSB1

```
eph_priv = d3e861716894b30a96fefcef23b8512b3ee37834d3907cf8336a60bb84c6c3b2
eph_pub  = 69fd6dcc85f1317c64f362fd9a626447fa97c49a5b88bd1be70a0e6d879c9c34
nonce    = 6f5eda643d47bd038369079feb68923a14a3b56ddca91de9      recipient = bob_x25519_pub
inner    = {"fromUserId":42,"messageId":"m1","text":"x","encrypted":true}
sealed   = OSB1:af1tzIXxMXxk82L9mmJkR/qXxJpbiL0b5woObYecnDRvXtpkPUe9A4NpB5/raJI6FKO1bdypHemkACm+st83ptOusCAGjSV42RJWUx5/w4ajm9b1pM6F3hm/psmvEo1yP0Q+mNcA3BDj6rWTcbyGz4eIPpl/G+TmmvVhA1j9dl8l0FCn7lg=
```

### 14.6 File secretbox

```
key    = GydVZHPphdRizVEZeppGx2AJVJ6sZHTyBsTuCET2g4k=
nonce  = aWlu6VW2K3PNYr2odfxz1oIZ4ANregs3
plain  = 89504e470d0a1a0a00ff
cipher = PTcuux4g52t9BwZND5JtOrnOKh154/qsDX0=
       = 3d372ebb1e20e76b7d07064d0f926d3a (tag, 16 B) ‖ b9ce2a1d79e3faac0d7d (ciphertext, 10 B)
```

### 14.7 Raw DH, beforenm, legacy box, mesh `toIdx`

```
X25519(alice_priv, bob_pub)    = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
beforenm(bob_pub, alice_priv)  = 1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389
legacy {n,c} of "❤️", nonce 000102030405060708090a0b0c0d0e0f1011121314151617:
    {"n":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYX","c":"L1kv4Se+wAB9uGuKHiNyGefT9Eqj+Q=="}
toIdx(alice_priv, bob_pub, ts=1767225600000 → epoch 490896) = RkKYDTGd1VM=
```

### 14.8 SDP and key-publish signatures

**SDP.** The input SDP, CRLF line endings:

```
v=0
o=- 1 2 IN IP4 127.0.0.1
a=group:BUNDLE 0 1
m=audio 9 UDP/TLS/RTP/SAVPF 111
a=fingerprint:sha-256 AB:CD:EF:01
m=video 9 UDP/TLS/RTP/SAVPF 96
a=fingerprint:sha-256 AB:CD:EF:01
```

```
fp      = a=fingerprint:sha-256 ab:cd:ef:01
payload = a=fingerprint:sha-256 ab:cd:ef:01|1767225600000|AAECAwQFBgcICQoLDA0ODw==|42
sig     = NKgLlEqLc0/D+Oh0F4Ej8e7bLchtEM0hEP2LNwihZ/BnCFqfXNljW4Lr0Cu+0s3g+RLtzN1haoZ6a/oxQlLDDw==   (signed by alice_ed25519)
```

**Key publish:**

```
canonical = hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=|11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=|42|1767225600000
signature = 98ZDvd3kkgmD9BRESEDvofBOS5bSZPzG47wRODDRH6zucHbdWpF/jiDMZEqxvfCDYk0tBdh/yk+KFoHxoNZVBA==
```

### 14.9 Sender Keys

```
chainKey = a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
plain    = "group hello"   (UTF-8)
signing  = alice_ed25519 ; counter 0 ; nonce 1068185b4ad4c8ff63022f6a89e9df21206e590ef62884e4
signed   = BE64(0) ‖ b64dec(ct)   (8 + 27 bytes)
MK       = 19b4bca3873f89bfd65f44e99825eda229c11738873ffae4f632f5da09179335
NEXT     = 1b3a7fbd4ff6ca9b98298bca6f7ea1007dc763968aa0862450438e935bc0e37a
wire     = sk1:{"v":1,"ct":"JqprfSnxyAm7zSSas1A1MhtxnmB4l9X4razG","n":"EGgYW0rUyP9jAi9qienfISBuWQ72KITk","ctr":0,"sig":"omVWFrGg7qbXEZ8NB9Y2yxDQdO9CUCb0YZ2qZzW5dMXfW6vx94HLLNaXwpnKZ9SCAEd3IS8KH3iAk/pogMG2Dw=="}
```

---

## 15. Interop hazards (checklist)

Each item says what breaks if it is got wrong.

**Primitives and byte layouts**

- **H1. Use libsodium for secretbox, box and beforenm.** CryptoKit's `ChaChaPoly` and `AES.GCM` are **not** compatible. Do not use `crypto_box_seal` either: build the ephemeral boxes by hand, with the exact byte orders below.
- **H2. The two sealed formats use opposite byte orders.** Sealed Sender is `nonce ‖ ephPub ‖ box` (§5.4). `OSB1` is `ephPub ‖ nonce ‖ box` (§6).
- **H3. The tag comes first.** Output is always `tag16 ‖ ciphertext`, never the reverse. The ratchet `ct` field additionally prepends the nonce: `nonce ‖ tag ‖ ct`.
- **H4. Raw X25519 vs beforenm.** The ratchet uses raw X25519 (`scalarMult`). The legacy box and mesh `toIdx` use **beforenm** (HSalsa20 over X25519). Swapping them causes silent decrypt failures.
- **H24. The Ed25519 secret key is `seed ‖ pub`** (64 bytes). CryptoKit wants only the first 32 bytes.

**Encoding and JSON typing**

- **H5. Base64 must be standard and padded everywhere.** Skipped-key maps and `peerDH` comparisons work on base64 strings.
- **H6. JSON types must match exactly.** A string in any of these places makes RN fail silently:
  - ratchet `v` must be the number `2`; `n` and `pn` must be numbers;
  - SDP `ts` must be a number and `nonce` a string;
  - certificate `uid` and `expires_at_ms` must be numbers;
  - `toUserId` must be a number. Here the **server** does the silent dropping: `extractToUserID` accepts only a JSON number (`server.go:1056-1060`), and it drops `p2p-message` and `p2p-sealed` frames whose `toUserId` is a string, with no error sent back;
  - `ratchet-reset.data.peerUserId` must be a number (`server.go:2311-2312`);
  - `messageId` must be a string. The server replaces a non-string `messageId` with a server-generated one (`server.go:1805-1809`, `:1997-2000`), which breaks the sender's ack correlation and the receiver's dedup.
- **H8. Plaintexts must be valid UTF-8.** RN counts invalid UTF-8 as a decrypt failure.
- **H21. The certificate signs the base64 text of `sender_pub`,** not the raw 32 bytes.
- **H22. SDP fingerprint canonicalisation.** The `a=fingerprint:` prefix match is case-sensitive, and lines are lowercased only *after* matching. Deduplicate, sort by code unit (byte order), then join.
- **H23. Integers inside signed strings are plain decimal.** Never serialise a timestamp as a float.

**Message handling**

- **H7. Set `p2p-message.data.encrypted` to `true`.** Otherwise RN displays the envelope JSON as plaintext.
- **H9. Deduplicate by `messageId` before decrypting.** Duplicates otherwise count as failures, trigger `ratchet-reset`, and wipe the peer's session.
- **H10. Never re-encrypt when falling back to another transport; reuse the same wire text.** A second encryption makes the receiver skip one key. That is harmless once, but it breaks the mesh/WS dedup assumptions and burns chain steps.
- **H18. Skipped keys accumulate forever.** They are never pruned and never expire, and every prewarm burns one. A single gap of more than 1000 throws, and that failure is not counted toward auto-recovery.
- **H25. Media must go over `p2p-message`, never `p2p-sealed`.** RN forces `type: "text"` when it receives a sealed message.
- **H33. Size limits sit under every encrypted payload.** Native MUST cap the plaintext; RN caps chat input at 4096 UTF-16 units (`ChatScreen.tsx:2142`).
  - **WS frame: 64 KB.** `conn.SetReadLimit(64*1024)` (`server.go:51`, `:1583`). A larger frame makes gorilla close the **whole connection**; the frame is not merely dropped.
    - A `p2p-message` grows about 1.37× over the UTF-8 plaintext: base64 of `nonce ‖ tag ‖ ct`, inside JSON.
    - A `p2p-sealed` grows about 1.9×: base64 of a box around JSON that contains that base64.
  - **Room SDP: 32 KB** per offer or answer (`server.go:2560-2565`).
  - **Offline storage copy: 64 KB.** `encryptedPayload` (the OSB1 string) is capped at 64 KB. Above that, storage returns 413 and the storage copy is dropped; the Go-DB copy remains (`routes_offline.py:13`, `:40-41`).
  - **Mesh: 65 535 bytes.** The inner blob carries the padded payload length as `BE16` (`meshCrypto.ts:182`). Above 65 535 bytes, `setUint16` wraps the length field modulo 2^16 while the full payload is still written. The receiver then mis-parses the blob, the signature check fails, and the envelope is dropped. A large message therefore cannot go over the mesh.
- **H26. `pn == 0` fresh-init replaces the session, and the ratchet does not authenticate senders.** Native MUST apply the same transport-attribution checks RN applies:
  - the server-stamped `fromUserId`;
  - the verified certificate `uid`;
  - the mesh signature, replay window and sender pinning.

**Keys and identity**

- **H19. `peer-key-rotated` MUST reset the ratchet with that peer.** The one exception is a replay of a rotation the send path already acted on, when the current session was started on the new key and a network fetch confirms that key (§2.5, "Exception"). Native SHOULD NOT emit `key-rotated` unless a published value actually changed.
- **H20. Get peer keys only from `/api/keys/{id}` (storage).** Never use Go's `User.publicKey`, nor the X3DH bundle's `identityKey`/`signingKey`. Both Go columns are stale (§2.3).
- **H27. Shared-identity heal: "lower uid keeps the key."** Every platform MUST agree on this tie-breaker.
- **H28. The key-publish `ts` must be within ±5 min of server time.** With a skewed device clock the server returns 400 `stale publish signature` and the key is not published.
- **H30. Never publish `"signingPublicKey": ""`.** The storage server treats an empty string as "present", so it replaces the stored Ed25519 key with `""`. Every peer's SDP verification of your calls then fails (§2.2, rule 4).
- **H31. Address every attachment upload.** `recipientId` or `channelId` is required, and it is also the download ACL. A wrong or missing addressee makes the peer's download return 404 (§8.2).

**Calls**

- **H29. The SDP `ts` must be within ±60 s of the verifier's clock.** A wrong device clock breaks call setup. Failures on already-connected calls are absorbed.
- **H32. On 1:1 calls the server stamps `fromUserId` into `call-offer`/`call-answer`** (`call.go:619`). Always sign the modern payload with your own JWT uid.

**Privacy leaks in RN's current behaviour**

- **H11. Plaintext beside the ciphertext.** *Historical: this describes the React Native builds up to 348, before App Store 1.0.0. Fixed in protocol v3, which removes `replyTo` and `storyContent` from the wire (§V3.3.4, «Outer frame»).* `replyTo.text` (up to 100 characters) and `storyContent` travel unencrypted next to the ciphertext. Native must send them the same way for RN compatibility, but it is a privacy leak.
- **H12. Delivery acks unmask Sealed Sender.** On the sealed receive path RN sends `message-delivered` to `cert.uid` over the WS, revealing the sender/recipient pair to the server.
- **H14. The upload file name leaks.** RN's multipart file name contains the original file name and sizes (§8.2).

**RN paths that are broken as built**

- **H13. Sealed certificates can expire before an offline recipient reconnects.** The message is then **silently dropped** (§5.7).
- **H15. Forwarding sends plaintext.** The forward path (`ChatScreen.tsx:2260-2286`) sends **plaintext** `text` with `encrypted: true` and no `messageId`, so RN receivers fail and show the placeholder.
  - Native forwards SHOULD re-encrypt with the ratchet; RN decrypts those fine.
  - Native receivers will see RN forwards as undecryptable (Q2).
- **H16. Story reactions use the legacy box** (§4). RN recipients cannot decrypt them.
- **H17. RN cannot decrypt `message-edit`** (§3.10) when it carries a ratchet envelope. RN does display a legacy-box `{n,c}` `newText`. That option has no forward secrecy, and after the native peer re-keys it fails on RN until RN restarts, because RN never invalidates its per-peer `beforenm` cache (§3.10.1).

---

## 16. Open questions

These cannot be settled from the code. Each one needs a product decision or a check against the running system.

**Product decisions**

- **Q1. Group E2E.** *Historical: this describes the React Native builds up to 348, before App Store 1.0.0. Fixed in protocol v3: Sender Keys v2, with the SKDMs carried inside the 1:1 ratchet (§V3.7).* Group Sender Keys are broken end to end: SKDMs go out in plaintext, nobody ingests them, and decrypting during render advances state (§10). Native has three options:
  - implement the as-built `sk1:` format — it still would not interoperate, because RN never ingests SKDMs;
  - send plaintext group messages, which is what RN effectively does today;
  - wait for a redesigned v2 group protocol shipped on both platforms.
- **Q2. Forwards from RN.** They arrive as plaintext `text` marked `encrypted: true`. Should native display them (the server has already seen the text) or show RN's placeholder?
- **Q3. Edits sent to RN peers.** Every RN build shows edits as ciphertext JSON. There is no client-version signal in this code. Should native stop sending edits to peers suspected to be on RN, or should RN be fixed first?
  - A third option exists: send edits as a legacy-box `{n,c}` in `newText`, which every RN build displays (§3.10.1). The costs are no forward secrecy or post-compromise security, no replay protection, and raw JSON on RN peers that have not restarted since the native side re-keyed. Because there is no version signal, a sender that adopts it uses it for all peers, and native receivers must then accept both encodings.
- **Q4. Story reactions.** Native senders could switch to v=2 ratchet envelopes, which RN can decrypt. Is that acceptable, given that RN senders will keep emitting the undecryptable legacy box?
- **Q5. Certificate expiry for offline recipients.** Should native check certificate expiry against the relay `ts` in the `p2p-sealed` frame instead of the current time, so long-offline messages are not dropped silently? The only divergence from RN would be accepting more messages.
- **Q6. Checking `cert.sender_pub`.** Should native require `cert.sender_pub` to equal the published `publicKey` of `cert.uid`? Arguments against a strict check:
  - RN never performs it;
  - the server does not validate `senderPub` at issuance;
  - RN takes `senderPub` from `user.publicKey`, which can be stale, so a strict check could reject legitimate RN traffic.

  Logging mismatches without rejecting is the safe default.
- **Q10. Prekey uploads.** Should native keep uploading SPKs and OPKs? Nothing consumes them; they only fill server storage and cost RN battery. **Resolved 2026-09-27:** yes, native keeps uploading them for parity (§11).
- **Q11. Enforcing `rb`.** The ratchet binding MAC has been warn-only since build 86. Enforcing it would need a coordinated flag day, because RN derives `rb` from a session that can desync.
- **Q12. `key-rotated` fan-out.** *Historical: this describes the first release. Fixed on the server side (server 1.1): the broadcast now goes only to the users who can hold key or session state for the sender (its contacts in either direction, its sealed-sender pairs, the co-members of its groups and the posters of its broadcast channels), no longer to every connected user (02 §6.1).* The broadcast went to every connected user, not just contacts (`server.go:2226-2238`), which leaks rotation events. Is that intended?
- **Q13. Row-id mismatches.** `getPublicKey` returns a row whose `userId` does not match the request to its caller (`api.ts:777-785`), and the caller may encrypt to it. Should native treat a mismatch as a hard error? Recommended; it does not affect interop.
- **Q14. Resets after signing-key-only rotations.** Should a `peer-key-rotated` caused by a signing-key-only republish really wipe ratchet sessions? No server field distinguishes the two cases today, so native must keep resetting until the server adds one.
- **Q15. Duplicate delivery acks.** With the chat screen open, RN can send **two** `message-delivered` acks for one sealed message: one from the pipeline and one from `ChatScreen.tsx:524-529`. Does the receipts spec tolerate duplicates? This matters for native clients receiving RN acks.
- **Q16. Two devices that both hold the account's keys (§2.8). SETTLED (build 339): stop.** A native client that holds its own identity and finds a *different, complete* row (another X25519 key with a signing key) treats it as another device's takeover: `foreign`, messaging off, the "moved away" offer, never a silent republish. I4 republishing stays for an empty row, a legacy half row, and our own X25519 key with another signing key (I6). A row lost or corrupted on the server into another complete identity is healed by the same explicit button. RN builds in the field keep republishing; they are not supported against native devices.

**Runtime verification needed**

- **Q7. Can native read RN's MMKV?** The MMKV key is a 32-character hex string, but MMKV's AES uses 16 bytes (`secureStorage.ts:115-121` says longer keys are "silently truncated"). Which exact key bytes does react-native-mmkv v4 use, and can a native MMKV reader open `mrenzo-ratchet`? The answer decides whether sessions survive the RN → native upgrade.
- **Q8. react-native-keychain 10.x attributes.** Only version **8.2.0** is vendored locally; production ships **10.x**. Confirm exactly what v10 writes, because the native migration depends on it:
  - the access group;
  - the presence semantics of `kSecAttrSynchronizable`;
  - the accessibility class;
  - any `kSecAttrAccessControl`.
- **Q9. Deployed pydantic version.** Confirm that the deployed pydantic accepts `ts` in `/api/keys/publish` both as a string and as an integer. `requirements.txt` does not pin pydantic.
