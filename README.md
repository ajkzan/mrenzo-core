# mr.enzo: the protocol and the cryptographic core

## What this repository is

This is the first publication of the part of **mr.enzo** on which its encryption claims rest: the Rust core that implements the cryptographic constructions and the wire formats, the written description of the cryptography, and the golden test vectors. It lets a reader check the constructions and the formats. It cannot show how the closed apps and the server use them (see «What is not here»).

The repository is **source-available for review**. You can read it, build it unchanged, run the tests and check the vectors against the documents. The licence is the PolyForm Strict License 1.0.0 (see «Licence»): it allows that for non-commercial purposes and nothing more. It does not let you distribute the code, change it or build on it.

**What is here:** the primitives, the key agreement (X3DH v2, with a hybrid ML-KEM-768 variant), the Double Ratchet, sealed sender, group sender keys, the signed mesh frames, the document that specifies the cryptographic constructions and the encrypted-payload formats (`03-crypto.md`; the frames of the offline network are specified in a document that is not published yet), and the vectors that pin them byte for byte.

**What is not here:** the iOS app, the server, the Swift binding layer that exposes the core to the app (there is no Android app or binding yet), build and deploy scripts, and the internal planning documents. The apps also contain protocol-related logic of their own (for example when a key is distributed and what happens when a send fails); it is not published, so this repository cannot show that the apps use the core correctly. Three of the four protocol documents (01 HTTP API, 02 WebSocket, 04 offline network) are not part of this first publication; a second publication is planned, with no date. Because the apps and the server are not here, you cannot check from this repository that the apps call the core exactly as documented, how keys are stored on the phone, or what the server does.

## What mr.enzo is

mr.enzo is a private messenger for iPhone, made by one developer who signs as **ajkzan**. Status: version 1.1.4, in the App Store since 15 October 2026 (<https://apps.apple.com/app/id6761927514>, site <https://mrenzo.com>). It is free. You sign in with an e-mail address. Chats and calls are end-to-end encrypted; story photos are not. It also has Push to Talk (a walkie-talkie) on Apple's PushToTalk framework, an offline mode that sends text messages of one-to-one chats between nearby iPhones over Bluetooth and Wi-Fi, and eight interface languages.

What has been seen on real phones, and what has not. Seen: text between two iPhones with no connection (once, on the version of 9 October, between people who had already written to each other over the internet); Push to Talk through the internet; and, by the developer's own check, Push to Talk directly between two open apps nearby. Not seen: relaying a message through a third phone, and courier phones. Both are specified and tested in code, but not yet seen working on real phones.

Limits without the internet. Push to Talk works only while mr.enzo is open on both phones and the screen is on; it does not wake a locked phone; the voice arrives a few seconds late and reaches only the phone next to you — phones do not pass it on. Only text messages of one-to-one chats go from phone to phone. No range is promised: walls, floors and shelves differ.

## What is in this repository

The layout mirrors the developer's private repository. References to things that are not published here (the binding layer, the three other protocol documents, the internal design record, files of the apps and the server) are kept as they are and do not resolve in this repository.

```
native/core/                 the Rust crate `mrenzo-core`
  src/                       the protocol modules (see native/core/README.md)
  tests/                     golden-vector tests, compatibility tests, hostile-input tests
  tests/legacy353/           the 1.0.0 core, frozen byte for byte and pinned by SHA-256
  tests/independent_check.py a second implementation in Python (not run by cargo)
  Cargo.toml, Cargo.lock
docs/native/protocol/        03-crypto.md (01, 02 and 04 are planned to follow)
docs/native/vectors/         the golden test vectors (JSON) and their README (the index)
SECURITY.md                  how to report a security problem
LICENSE                      PolyForm Strict License 1.0.0 (see «Licence»)
```

### The protocol document and its status

| Document | What it specifies | Status |
|---|---|---|
| [`docs/native/protocol/03-crypto.md`](docs/native/protocol/03-crypto.md) | the cryptographic constructions and encrypted-payload formats: keys, X3DH v2, the ratchet, sealed sender, groups, files, call signing, safety numbers, protocol v3 and wire level 2 | Normative for protocol v3 and wire level 2, except the offline-network part of level 2, which is specified in `04-mesh.md` (not published yet). Sections for formats up to build 348 are kept as history and say so; three findings about earlier versions (H11 in §15, Q1 and Q12 in §16) carry a «historical» mark because they were fixed later. Contains worked examples (§14) built from public test vectors and from throwaway test values. |

The documents 01 (HTTP API), 02 (WebSocket) and 04 (offline network) are not part of this first publication; they are planned to follow, with no date. `03-crypto.md` refers to them in many places; the references are kept so that the text stays exact.

## Build and run the tests

You need a Rust toolchain (the crate declares `rust-version = "1.85"`). Cargo downloads the dependencies pinned in `Cargo.lock` the first time; the tests themselves make no network requests.

```bash
cd native/core
cargo test --locked
```

`cargo test --release --locked` runs the same tests faster. The golden vectors in `docs/native/vectors` are the contract: the Rust tests replay them, or, for the files that the Rust tests themselves produce, regenerate them and compare **byte for byte**. A change to a construction that a vector covers therefore shows up as a change to the committed vector. The suite also runs the 1.0.0 core, frozen, against the current core (`tests/compat_353.rs`), and a deterministic mutation corpus over the parsers listed in `tests/hostile_input.rs`.

`tests/independent_check.py` is a second implementation of the level-2 constructions, written from the formulas in the design documents (some of which are not published). It needs PyNaCl and OpenSSL 3.5 or newer and is run by hand: `python3 native/core/tests/independent_check.py`.

**Result of the last run** (platform, Rust version, date; the cargo result and the result of the Python check):

```
date:      13 October 2026
platform:  macOS 26.5, arm64
rust:      rustc 1.98.1 (48a229cea 2026-09-01), cargo 1.98.1
command:   cd native/core && cargo test --locked --offline
result:    351 passed; 0 failed; 0 ignored (24 test binaries, 0 compiler warnings)
python:    tests/independent_check.py was not part of this run
```

## Reading the documents

- `file:line` citations (`api.ts:867-869`, `server.go:1056-1060`, `internal/files/handler.go:51-165`) name files of the closed-source apps and server. They are the evidence trail of each statement; they do not resolve in this repository.
- `wire-1.1` (`wire-1.1 §W9`, `wire-1.1.md`) is the internal design record of wire level 2. It is not published. The normative text for everything it specifies is in `03-crypto.md` (§V3.16–§V3.21) and `04-mesh.md` («Mesh at level 2»; 04 is not published yet). References to it in comments and documents are left as they are.
- Tags such as `[build 361]` mark which revision of the app or the server introduced a rule. Labels such as `H11`, `Q1` and `I4` are numbered items inside the same document (interop hazards, open questions, invariants).
- «Text in guillemets», and any Russian, is the interface text of the app or a Unicode test string inside a vector. These strings are part of the behaviour the documents pin.
- Account names and ids in examples are synthetic: `alice` 1001, `bob` 1002, `carol` 1003; the RN-era vectors use `42` and `2002`. The keys in this repository are test values: they come from the deterministic golden PRNG, from public test vectors (RFC 7748, RFC 8032, NaCl), from fixed fixtures or from throwaway values made for a worked example.
- `712e1dcc` and `781eee60` are commits of the closed-source repository: the client and the server of the App Store release 1.0.0 (build 353). The files in `native/core/tests/legacy353/` are byte-identical copies, checked by SHA-256 on every test run.
- The server host `mrenzo.com` appears because it is the documented API host of the protocol (`https://mrenzo.com/api/...` in `03-crypto.md`).

## Known limitations and what is being done

| Limitation | What is being done |
|---|---|
| No outside security audit. | None is scheduled. This is the reason the code is published: so that people outside the project can read and check it. The licence lets anyone read, build, run and test this code, unchanged, for non-commercial purposes (see LICENSE). If you are not sure that your review is one, ask first by opening an issue. |
| The apps and the server are closed. | Only the core, the vectors and the cryptography document are published here. |
| The incoming-call notification shows the caller's name even when «hide the name in notifications» is on. | Fix planned for 1.2.1, mid-November 2026. |
| The server keeps the member list of a group, so it can add a member. The new member is visible in the member list but is not announced in the chat. | An in-chat notice is planned for 1.2.1; member-signed membership later. |
| Group (room) calls are authenticated by signature against the server's key directory only. | A documented residual; no date. |
| «Online» follows any open connection, so an incoming call makes the callee look online. | Fix planned for 1.2.0, 9 November 2026. |
| After an account takeover, the attacker's sessions are not signed out by a credential change, and the victim gets no e-mail about a key replacement. | Planned with the privacy release (1.2.3, December 2026). |
| Relaying through a third phone and couriers are specified and tested in code but unverified on phones. | A three-phone test is planned for 1.2.2. |

Dates are plans, not promises.

## Release history

| Version | Date in the App Store | What changed |
|---|---|---|
| 1.0.0 | 4 October 2026 | first release |
| 1.1.0 | 9 October 2026 | Push to Talk (walkie-talkie) |
| 1.1.1 | between 1.1.0 and 1.1.2 | fixes and small additions |
| 1.1.2 | 10 October 2026 | fixes and small additions |
| 1.1.3 | 12 October 2026 | delivery ticks and call states changed to say what actually happened |
| 1.1.4 | 15 October 2026 | reconnects by itself every few seconds; links from YouTube and other apps are saved and sent; an honest «No connection to the server» |

Six versions in the first twelve days: the table shows how often updates ship.

## How this was built

mr.enzo was written by AI coding agents under the direction of one developer. What this repository lets a reader check:

- The golden vectors are the contract, and the Rust tests replay or regenerate them byte for byte.
- The current core is run against the frozen 1.0.0 core, the first App Store release (`tests/compat_353.rs`, `tests/legacy353/`, pinned by SHA-256).
- The parsers listed in `tests/hostile_input.rs` are run against a deterministic mutation corpus.
- A second implementation in Python (`tests/independent_check.py`), which shares no code with the core, recomputes the vectors of the level-2 constructions from the formulas in the documents (some of which are not published).

None of that replaces an independent audit, which has not happened. The reviews so far were done by AI coding agents under the developer's direction, not by independent security experts.

## Reporting a security problem

The only channel is GitHub's private vulnerability reporting (the **Security** tab of this repository, **Report a vulnerability**). Details and scope are in [SECURITY.md](SECURITY.md).

## Licence

This repository is licensed under the **PolyForm Strict License 1.0.0**; the full text is in [LICENSE](LICENSE) (<https://polyformproject.org/licenses/strict/1.0.0>). In plain words: for non-commercial purposes you may read this code and build and run it, with its tests, unchanged. You may not distribute it, change it or build new works on it. Use for a commercial purpose is not covered. The text of the licence governs; this paragraph is only a summary.

By publishing here the developer also accepts GitHub's Terms of Service, under which GitHub users may view a public repository and fork it within GitHub. Beyond that and beyond the licence above, no right to copy, distribute, change or build on this material is granted.

Copyright (c) 2026 ajkzan

The licence covers the code, the document and the vectors alike. Third-party crates keep their own licences. The apps, the server, the name «mr.enzo» and the logo are not covered by this licence.

Issues are welcome for questions and for mistakes in the text; a vulnerability goes through the private channel described in SECURITY.md, not into an issue. Pull requests are not accepted. For anything the licence does not allow, open an issue.
