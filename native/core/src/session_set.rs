//! The per-peer session state machine of protocol v3 (03-crypto §5.1–§5.5),
//! pure and storage-free: the host loads a peer's session rows, runs one
//! operation here, and writes back what changed (`rows()`).
//!
//! Signal semantics, no tie-break:
//! - at most one LIVE session (`initiating` or `active`); up to
//!   [`MAX_ARCHIVED`] archived ones, deleted [`ARCHIVE_TTL_MS`] after their
//!   last use;
//! - the most recently created or promoted session is live;
//! - a successful decrypt of a fresh message under an archived session
//!   PROMOTES it (the live one is archived); a replay cannot promote, because
//!   a spent position never decrypts;
//! - a prekey message (`x` present) is matched to an existing session only by
//!   the initiator ephemeral (`peer_ek == x.ek`); otherwise the host must build
//!   a responder session ([`PeerSessions::respond_and_decrypt`]) after its own
//!   checks (block list, pin, `ek` seen-set, SPK/OPK lookup).
//!
//! Every session is authenticated to the peer's identity at creation (X3DH
//! DH1/DH2), so the host drops sessions whose identity is no longer the pin
//! ([`PeerSessions::retain_identity`]) when a key change is accepted.
//!
//! Wire level 2 (wire-1.1 §W3, §W6.5):
//! - [`PeerSessions::open`] returns an OUTCOME, and an authenticated
//!   plaintext is never a failure: it is [`SetOpen::Typed`] or
//!   [`SetOpen::Unsupported`]; a position already used is [`SetOpen::Stale`];
//!   only a MAC failure is [`SetOpen::Failed`] (the one the host counts);
//! - the **aux** ([`SessionAux`], kept by the host beside the rows): the peer
//!   ratchet keys each session retired — so a duplicate that arrives after a
//!   DH step is `Stale`, not a counted failure — and the run of «lossy»
//!   steps, bounded so that a receiver is never asked to skip past its limit;
//! - no demotion: an archived classical session that decrypts while the live
//!   one is hybrid stays archived (an in-flight classical message must not
//!   undo a post-quantum upgrade).
//!
//! [`PeerSessions::decrypt`] / [`PeerSessions::respond_and_decrypt`] keep the
//! 1.0.0 signatures on top of that.

use crate::kem;
use crate::plaintext::{classify_bytes, Classified, Parsed, Unsupported, MAX_PLAINTEXT_BYTES};
use crate::primitives::{b64, KeyPair};
use crate::ratchet::{self, b64_strict32, Envelope, EnvelopeError, Open, RatchetError, Role, Session, MAX_RETIRED_KEYS};
use crate::rng::Rng;
use crate::strict_json;
use crate::x3dh::{x3dh_pq_initiate, x3dh_pq_respond, x3dh_v2_initiate, BundleV2, KemKind, KemPreKeyPublic, X3dhV2Error};

pub const MAX_ARCHIVED: usize = 3;
pub const ARCHIVE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Consecutive lossy steps one session may send (wire-1.1 §W3.5). A receiver
/// walks at most 1000 positions per message; this keeps it well inside.
pub const LOSSY_RUN_MAX: u32 = 256;
pub const AUX_VERSION: u64 = 1;

/// What the host keeps per session BESIDE the session JSON (which must stay
/// byte-identical to 1.0.0 for classical sessions).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionAux {
    /// 8-byte prefixes of the peer ratchet keys this session moved past,
    /// oldest first, at most [`MAX_RETIRED_KEYS`].
    pub retired: Vec<[u8; 8]>,
    /// Lossy steps sent since the last universal one.
    pub lossy: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Initiating,
    Active,
    Archived,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Initiating => "initiating",
            Status::Active => "active",
            Status::Archived => "archived",
        }
    }

    pub fn parse(s: &str) -> Option<Status> {
        match s {
            "initiating" => Some(Status::Initiating),
            "active" => Some(Status::Active),
            "archived" => Some(Status::Archived),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub session: Session,
    pub status: Status,
    pub updated_at: i64,
    pub aux: SessionAux,
}

impl Entry {
    fn live_status(session: &Session) -> Status {
        if session.role == Role::Init && session.x.is_some() {
            Status::Initiating
        } else {
            Status::Active
        }
    }
}

/// What a decrypt did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetDecrypt {
    /// `sid` = the session that opened it; `promoted` = it was archived and
    /// is live now; `created` = a responder session was just built for it.
    Opened { plaintext: String, sid: [u8; 32], promoted: bool, created: bool },
    /// No session at all for this peer (non-prekey message): signed reset.
    NoSession,
    /// Every candidate failed authentication (counted).
    Failed,
    /// A prekey message that matches no stored session: the host checks the
    /// seen-set, the SPK/OPK and the pin, then calls `respond_and_decrypt`.
    NeedsResponder,
    /// A message asking for too many skipped keys (not counted).
    TooManySkipped,
}

/// Which session authenticated an envelope, and what that did to the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenedBy {
    pub sid: [u8; 32],
    /// It was archived and is live now.
    pub promoted: bool,
    /// A responder session was just built for it.
    pub created: bool,
    /// It is a hybrid (post-quantum) session.
    pub pq: bool,
}

/// The outcome of [`PeerSessions::open`] (wire-1.1 §W3.1).
// Built once per call and consumed at once: the size difference between the cases costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum SetOpen {
    /// Authenticated, and a kind this core knows. `plaintext` = the exact text.
    Typed { plaintext: String, parsed: Parsed, by: OpenedBy },
    /// Authenticated, but not a typed plaintext this core understands. The
    /// ratchet step is consumed exactly as for `Typed`. `raw` = the
    /// authenticated text for the host to keep (absent when it is not UTF-8
    /// or over 48 KiB). NEVER counted.
    Unsupported { raw: Option<String>, what: Unsupported, by: OpenedBy },
    /// A position this set already used or a ratchet key it retired. Never counted.
    Stale,
    NoSession,
    /// MAC failure under every candidate session (the one outcome a host counts).
    Failed,
    NeedsResponder,
    TooManySkipped,
}

/// An envelope after authentication, before classification.
enum RawOpen {
    Authenticated { plaintext: Vec<u8>, by: OpenedBy },
    Stale,
    NoSession,
    Failed,
    NeedsResponder,
    TooManySkipped,
}

impl RawOpen {
    fn classified(self) -> SetOpen {
        match self {
            RawOpen::Authenticated { plaintext, by } => {
                let class = classify_bytes(&plaintext);
                match (class, String::from_utf8(plaintext)) {
                    (Classified::Typed(parsed), Ok(text)) => SetOpen::Typed { plaintext: text, parsed, by },
                    (Classified::Unsupported(what), text) => {
                        SetOpen::Unsupported { raw: text.ok().filter(|t| t.len() <= MAX_PLAINTEXT_BYTES), what, by }
                    }
                    // `classify_bytes` is `Typed` only for valid UTF-8.
                    (Classified::Typed(_), Err(_)) => SetOpen::Unsupported { raw: None, what: Unsupported::default(), by },
                }
            }
            RawOpen::Stale => SetOpen::Stale,
            RawOpen::NoSession => SetOpen::NoSession,
            RawOpen::Failed => SetOpen::Failed,
            RawOpen::NeedsResponder => SetOpen::NeedsResponder,
            RawOpen::TooManySkipped => SetOpen::TooManySkipped,
        }
    }

    /// The 1.0.0 shape: an authenticated plaintext is `Opened` with its text
    /// whatever it is (the old call site then fails its own typed parse and
    /// rolls back, uncounted); a stale position is `Failed`, as it was.
    fn legacy(self) -> SetDecrypt {
        match self {
            RawOpen::Authenticated { plaintext, by } => SetDecrypt::Opened {
                plaintext: String::from_utf8_lossy(&plaintext).into_owned(),
                sid: by.sid,
                promoted: by.promoted,
                created: by.created,
            },
            RawOpen::Stale | RawOpen::Failed => SetDecrypt::Failed,
            RawOpen::NoSession => SetDecrypt::NoSession,
            RawOpen::NeedsResponder => SetDecrypt::NeedsResponder,
            RawOpen::TooManySkipped => SetDecrypt::TooManySkipped,
        }
    }
}

/// Why [`PeerSessions::encrypt_counted`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetEncryptError {
    /// No live session with a sending chain.
    NoSendChain,
    /// [`LOSSY_RUN_MAX`] lossy steps in a row: send one universal message
    /// (a `session-hello` with `text`) first, then retry.
    SkipBudget,
}

impl std::fmt::Display for SetEncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SetEncryptError::NoSendChain => "ratchet: no sending chain",
            SetEncryptError::SkipBudget => "skip-budget",
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSessions {
    pub entries: Vec<Entry>,
    /// The host keeps an aux for this peer ([`PeerSessions::from_rows_aux`]).
    /// Without one the set behaves as in 1.0.0: no retired-key memory (a
    /// cross-chain replay is `Failed`) and no lossy budget.
    pub aux_enabled: bool,
}

impl PeerSessions {
    /// Normalises loaded rows: one live session at most (the newest wins),
    /// archived ones capped and aged out.
    pub fn new(mut entries: Vec<Entry>, now_ms: i64) -> PeerSessions {
        entries.sort_by_key(|e| std::cmp::Reverse(e.updated_at));
        let mut seen_live = false;
        for e in entries.iter_mut() {
            if e.status != Status::Archived {
                if seen_live {
                    e.status = Status::Archived;
                } else {
                    seen_live = true;
                    e.status = Entry::live_status(&e.session);
                }
            }
        }
        let mut set = PeerSessions { entries, aux_enabled: false };
        set.prune(now_ms);
        set
    }

    pub fn live_index(&self) -> Option<usize> {
        self.entries.iter().position(|e| e.status != Status::Archived)
    }

    pub fn live(&self) -> Option<&Entry> {
        self.live_index().map(|i| &self.entries[i])
    }

    /// Live first, then archived newest first.
    fn candidate_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = self.live_index().into_iter().collect();
        let mut archived: Vec<usize> = (0..self.entries.len()).filter(|&i| self.entries[i].status == Status::Archived).collect();
        archived.sort_by(|&a, &b| self.entries[b].updated_at.cmp(&self.entries[a].updated_at));
        order.extend(archived);
        order
    }

    /// Session ids, live first (the `rb` candidates, 03 §4.3).
    pub fn sids_live_first(&self) -> Vec<[u8; 32]> {
        self.candidate_order().into_iter().map(|i| self.entries[i].session.sid).collect()
    }

    fn prune(&mut self, now_ms: i64) {
        self.entries.retain(|e| e.status != Status::Archived || now_ms.saturating_sub(e.updated_at) <= ARCHIVE_TTL_MS);
        let mut archived: Vec<(usize, i64)> =
            self.entries.iter().enumerate().filter(|(_, e)| e.status == Status::Archived).map(|(i, e)| (i, e.updated_at)).collect();
        if archived.len() > MAX_ARCHIVED {
            archived.sort_by_key(|a| std::cmp::Reverse(a.1));
            let drop: Vec<usize> = archived[MAX_ARCHIVED..].iter().map(|(i, _)| *i).collect();
            let mut i = 0;
            self.entries.retain(|_| {
                let keep = !drop.contains(&i);
                i += 1;
                keep
            });
        }
    }

    fn archive_live(&mut self, now_ms: i64) {
        if let Some(i) = self.live_index() {
            self.entries[i].status = Status::Archived;
            self.entries[i].updated_at = now_ms;
        }
    }

    /// Makes `session` the live one (the previous live one is archived).
    fn install(&mut self, session: Session, now_ms: i64) {
        self.archive_live(now_ms);
        let status = Entry::live_status(&session);
        self.entries.retain(|e| e.session.sid != session.sid);
        self.entries.insert(0, Entry { session, status, updated_at: now_ms, aux: SessionAux::default() });
        self.prune(now_ms);
    }

    /// Our X3DH initiation to the peer's PINNED identity with its bundle.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate(
        &mut self,
        my_ik: &KeyPair,
        my_ed_pub: &[u8; 32],
        peer_ik: &[u8; 32],
        peer_ed: &[u8; 32],
        bundle: &BundleV2,
        now_ms: i64,
        rng: &mut dyn Rng,
    ) -> Result<[u8; 32], X3dhV2Error> {
        let init = x3dh_v2_initiate(my_ik, my_ed_pub, peer_ik, peer_ed, bundle, rng)?;
        let session = ratchet::initiate(&init, peer_ik, peer_ed, now_ms);
        let sid = session.sid;
        self.install(session, now_ms);
        Ok(sid)
    }

    /// The hybrid initiation (wire-1.1 §W6.2): X3DH v2 plus ML-KEM-768 to the
    /// peer's KEM prekey. Called on a set that already has a live classical
    /// session this is the lazy upgrade: the previous live session is archived.
    /// Errors `kem-signature` / `kem-invalid` leave the set untouched; the
    /// host decides whether a classical initiation is allowed instead.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_pq(
        &mut self,
        my_ik: &KeyPair,
        my_ed_pub: &[u8; 32],
        peer_ik: &[u8; 32],
        peer_ed: &[u8; 32],
        bundle: &BundleV2,
        kem_key: &KemPreKeyPublic,
        now_ms: i64,
        rng: &mut dyn Rng,
    ) -> Result<[u8; 32], X3dhV2Error> {
        let init = x3dh_pq_initiate(my_ik, my_ed_pub, peer_ik, peer_ed, bundle, kem_key, rng)?;
        let session = ratchet::initiate(&init, peer_ik, peer_ed, now_ms);
        let sid = session.sid;
        self.install(session, now_ms);
        Ok(sid)
    }

    /// The live session is a hybrid one.
    pub fn live_is_pq(&self) -> bool {
        self.live().is_some_and(|e| e.session.pq)
    }

    /// One ratchet step on the live session (no lossy accounting: the 1.0.0
    /// entry point, also what tests and vectors drive directly).
    pub fn encrypt(&mut self, plaintext: &str, now_ms: i64, rng: &mut dyn Rng) -> Result<Envelope, RatchetError> {
        let i = self.live_index().ok_or(RatchetError::NoSendChain)?;
        let (next, env) = ratchet::encrypt(&self.entries[i].session, plaintext, now_ms, rng)?;
        self.entries[i].session = next;
        self.entries[i].updated_at = now_ms;
        Ok(env)
    }

    /// [`Self::encrypt`] with the skip budget of wire-1.1 §W3.5. `lossy` =
    /// the peer may never decrypt this step (`TypedPlaintext::is_lossy`).
    /// With an aux in use, the 257th lossy step in a row is refused before
    /// anything is drawn or advanced; a universal step resets the run.
    pub fn encrypt_counted(&mut self, plaintext: &str, lossy: bool, now_ms: i64, rng: &mut dyn Rng) -> Result<Envelope, SetEncryptError> {
        let i = self.live_index().ok_or(SetEncryptError::NoSendChain)?;
        if self.aux_enabled && lossy && self.entries[i].aux.lossy >= LOSSY_RUN_MAX {
            return Err(SetEncryptError::SkipBudget);
        }
        let env = self.encrypt(plaintext, now_ms, rng).map_err(|_| SetEncryptError::NoSendChain)?;
        if self.aux_enabled {
            let run = &mut self.entries[i].aux.lossy;
            *run = if lossy { *run + 1 } else { 0 };
        }
        Ok(env)
    }

    /// The peer provably caught up with session `sid` (an authenticated mesh
    /// ACK for a transmission sent under it): the lossy run starts over.
    pub fn note_peer_progress(&mut self, sid: &[u8; 32]) -> bool {
        match self.entries.iter_mut().find(|e| e.session.sid == *sid) {
            Some(e) => {
                e.aux.lossy = 0;
                true
            }
            None => false,
        }
    }

    /// Stores what a session became after it authenticated an envelope.
    fn commit(&mut self, i: usize, next: Session, retired: Option<[u8; 8]>, now_ms: i64) -> OpenedBy {
        let (sid, pq) = (next.sid, next.pq);
        let was_archived = self.entries[i].status == Status::Archived;
        // No demotion (wire-1.1 §W6.5): a classical session that was archived
        // by a hybrid one decrypts its late messages and stays archived.
        let stays_archived = was_archived && !pq && self.live_is_pq();
        let promoted = was_archived && !stays_archived;
        if promoted {
            self.archive_live(now_ms);
        }
        let status = if stays_archived { Status::Archived } else { Entry::live_status(&next) };
        let mut aux = std::mem::take(&mut self.entries[i].aux);
        if let (true, Some(prefix)) = (self.aux_enabled, retired) {
            aux.retired.retain(|p| *p != prefix);
            aux.retired.push(prefix);
            if aux.retired.len() > MAX_RETIRED_KEYS {
                let excess = aux.retired.len() - MAX_RETIRED_KEYS;
                aux.retired.drain(..excess);
            }
        }
        self.entries[i] = Entry { session: next, status, updated_at: now_ms, aux };
        self.prune(now_ms);
        OpenedBy { sid, promoted, created: false, pq }
    }

    fn open_raw(&mut self, env: &Envelope, now_ms: i64, rng: &mut dyn Rng) -> RawOpen {
        let candidates: Vec<usize> = match &env.x {
            Some(x) => {
                let hits: Vec<usize> = (0..self.entries.len()).filter(|&i| self.entries[i].session.peer_ek == Some(x.ek)).collect();
                if hits.is_empty() {
                    return RawOpen::NeedsResponder;
                }
                hits
            }
            None => self.candidate_order(),
        };
        if candidates.is_empty() {
            return RawOpen::NoSession;
        }
        // Precedence over the candidates: opened > stale > too many skipped > failed.
        let (mut stale, mut too_many) = (false, false);
        for i in candidates {
            let retired: &[[u8; 8]] = if self.aux_enabled { &self.entries[i].aux.retired } else { &[] };
            match ratchet::open(&self.entries[i].session, retired, env, now_ms, rng) {
                Ok(Open::Opened { next, plaintext, retired }) => {
                    let by = self.commit(i, next, retired, now_ms);
                    return RawOpen::Authenticated { plaintext, by };
                }
                Ok(Open::Stale) => stale = true,
                Ok(Open::Failed) => {}
                Err(RatchetError::TooManySkippedKeys) => too_many = true,
                Err(RatchetError::NoSendChain) => {}
            }
        }
        if stale {
            RawOpen::Stale
        } else if too_many {
            RawOpen::TooManySkipped
        } else {
            RawOpen::Failed
        }
    }

    /// Opens `env` under the stored sessions and classifies what it carried
    /// (wire-1.1 §W3.1). The set changes only for `Typed` and `Unsupported`.
    pub fn open(&mut self, env: &Envelope, now_ms: i64, rng: &mut dyn Rng) -> SetOpen {
        self.open_raw(env, now_ms, rng).classified()
    }

    /// Decrypts under the stored sessions (§5.1 table, §5.3 step 2) — the
    /// 1.0.0 shape of [`Self::open`].
    pub fn decrypt(&mut self, env: &Envelope, now_ms: i64, rng: &mut dyn Rng) -> SetDecrypt {
        self.open_raw(env, now_ms, rng).legacy()
    }

    /// §5.3 step 5: a responder session from the prekey header, decrypted at
    /// once; installed as live only when the message authenticates.
    #[allow(clippy::too_many_arguments)]
    pub fn respond_and_decrypt(
        &mut self,
        env: &Envelope,
        my_ik: &KeyPair,
        my_ed_pub: &[u8; 32],
        spk: &KeyPair,
        opk_priv: Option<&[u8; 32]>,
        pinned_ik: &[u8; 32],
        pinned_ed: &[u8; 32],
        now_ms: i64,
        rng: &mut dyn Rng,
    ) -> Result<SetDecrypt, X3dhV2Error> {
        Ok(self.respond_raw(env, my_ik, my_ed_pub, spk, opk_priv, None, pinned_ik, pinned_ed, now_ms, rng)?.legacy())
    }

    /// [`Self::respond_and_decrypt`] with the level-2 outcome and the hybrid
    /// option: `kem_seed` = the seed (and the kind) of the KEM prekey
    /// `x.kem.id` names, present exactly when the header carries `kem`
    /// (`bad-key-id` otherwise). The responder session is installed for
    /// `Unsupported` exactly as for `Typed`: the prekeys were used either way.
    #[allow(clippy::too_many_arguments)]
    pub fn respond_and_open(
        &mut self,
        env: &Envelope,
        my_ik: &KeyPair,
        my_ed_pub: &[u8; 32],
        spk: &KeyPair,
        opk_priv: Option<&[u8; 32]>,
        kem_seed: Option<(&[u8; kem::SEED_LEN], KemKind)>,
        pinned_ik: &[u8; 32],
        pinned_ed: &[u8; 32],
        now_ms: i64,
        rng: &mut dyn Rng,
    ) -> Result<SetOpen, X3dhV2Error> {
        Ok(self.respond_raw(env, my_ik, my_ed_pub, spk, opk_priv, kem_seed, pinned_ik, pinned_ed, now_ms, rng)?.classified())
    }

    #[allow(clippy::too_many_arguments)]
    fn respond_raw(
        &mut self,
        env: &Envelope,
        my_ik: &KeyPair,
        my_ed_pub: &[u8; 32],
        spk: &KeyPair,
        opk_priv: Option<&[u8; 32]>,
        kem_seed: Option<(&[u8; kem::SEED_LEN], KemKind)>,
        pinned_ik: &[u8; 32],
        pinned_ed: &[u8; 32],
        now_ms: i64,
        rng: &mut dyn Rng,
    ) -> Result<RawOpen, X3dhV2Error> {
        let Some(x) = env.x else { return Ok(RawOpen::Failed) };
        let secret = x3dh_pq_respond(my_ik, my_ed_pub, spk, opk_priv, kem_seed, &x, pinned_ik, pinned_ed)?;
        let fresh = ratchet::respond(&secret, spk, &x, now_ms);
        Ok(match ratchet::open(&fresh, &[], env, now_ms, rng) {
            Ok(Open::Opened { next, plaintext, .. }) => {
                let by = OpenedBy { sid: next.sid, promoted: false, created: true, pq: next.pq };
                self.install(next, now_ms);
                RawOpen::Authenticated { plaintext, by }
            }
            Ok(Open::Stale) | Ok(Open::Failed) => RawOpen::Failed,
            Err(_) => RawOpen::TooManySkipped,
        })
    }

    /// A signed reset naming `dh`: archive the LIVE session whose current or
    /// previous sending ratchet key is `dh` (§5.5). Anything else is a no-op.
    pub fn archive_matching_dh(&mut self, dh: &[u8; 32], now_ms: i64) -> bool {
        let Some(i) = self.live_index() else { return false };
        let s = &self.entries[i].session;
        if s.my_dh.public == *dh || s.prev_my_dh_pub == Some(*dh) {
            self.archive_live(now_ms);
            self.prune(now_ms);
            true
        } else {
            false
        }
    }

    /// Our own give-up (failure window) or an accepted key change: archive live.
    pub fn archive(&mut self, now_ms: i64) {
        self.archive_live(now_ms);
        self.prune(now_ms);
    }

    /// Drops every session not authenticated to `(ik, ed)` (key change, §5.7).
    pub fn retain_identity(&mut self, ik: &[u8; 32], ed: &[u8; 32]) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.session.peer_ik == *ik && e.session.peer_ed == *ed);
        before - self.entries.len()
    }

    /// True when `env` names a position one of our sessions already used.
    pub fn is_spent(&self, env: &Envelope) -> bool {
        self.entries.iter().any(|e| ratchet::is_spent_position(&e.session, env))
    }

    /// [`Self::is_spent`] that also recognises the chains our sessions
    /// retired (needs the aux): the guard before the ratchet on `ctl`,
    /// `ptt-start` and edits.
    pub fn is_stale(&self, env: &Envelope) -> bool {
        self.entries.iter().any(|e| {
            let retired: &[[u8; 8]] = if self.aux_enabled { &e.aux.retired } else { &[] };
            ratchet::is_stale_position(&e.session, retired, env)
        })
    }

    /// The seed of the blind mesh ACK key for a message decrypted (or sent)
    /// under session `sid` — `None` when the set does not hold that session.
    pub fn ack_seed(&self, sid: &[u8; 32], message_id: &str) -> Option<[u8; 32]> {
        self.entries.iter().any(|e| e.session.sid == *sid).then(|| ratchet::mesh_ack_seed(sid, message_id))
    }

    /// The mesh ACK payload for a message decrypted under session `sid`.
    pub fn ack_payload(&self, sid: &[u8; 32], message_id: &str) -> Option<String> {
        self.entries.iter().any(|e| e.session.sid == *sid).then(|| ratchet::mesh_ack_payload(sid, message_id))
    }

    /// The acked id when `payload` carries a valid tag under one of our sessions.
    pub fn ack_matches(&self, payload: &str) -> Option<String> {
        self.candidate_order().into_iter().find_map(|i| ratchet::mesh_ack_matches(&self.entries[i].session.sid, payload))
    }
}

/// An aux string longer than this is not read (4 sessions × 64 prefixes is
/// under 4 KB).
pub const AUX_MAX_BYTES: usize = 16 * 1024;

/// One stored row, as the host keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub sid_b64: String,
    pub peer_ek_b64: Option<String>,
    pub status: Status,
    pub state_json: String,
    pub updated_at: i64,
}

impl PeerSessions {
    /// Rows whose state no longer parses are skipped (the host deletes them).
    pub fn from_rows(rows: &[Row], now_ms: i64) -> PeerSessions {
        let entries = rows
            .iter()
            .filter_map(|r| {
                let session = Session::from_json(&r.state_json, now_ms)?;
                (b64(&session.sid) == r.sid_b64).then_some(Entry {
                    session,
                    status: r.status,
                    updated_at: r.updated_at,
                    aux: SessionAux::default(),
                })
            })
            .collect();
        PeerSessions::new(entries, now_ms)
    }

    /// [`Self::from_rows`] for a host that keeps the aux (wire-1.1 §W3.4):
    /// `aux_json` = the string [`Self::aux_json`] returned last time, `None`
    /// before the first one. An unreadable aux is an empty aux; entries of
    /// sessions that are no longer in the set are dropped.
    pub fn from_rows_aux(rows: &[Row], aux_json: Option<&str>, now_ms: i64) -> PeerSessions {
        let mut set = PeerSessions::from_rows(rows, now_ms);
        set.aux_enabled = true;
        let Some(parsed) = aux_json.filter(|a| a.len() <= AUX_MAX_BYTES).and_then(strict_json::parse_object) else { return set };
        if parsed.get("v").and_then(strict_json::uint) != Some(AUX_VERSION) {
            return set;
        }
        let Some(sessions) = parsed.get("s").and_then(|s| s.as_object()) else { return set };
        for e in set.entries.iter_mut() {
            let Some(a) = sessions.get(&b64(&e.session.sid)).and_then(|a| a.as_object()) else { continue };
            if let Some(list) = a.get("r").and_then(|r| r.as_array()) {
                let mut retired: Vec<[u8; 8]> = list.iter().filter_map(|p| strict_json::b64_n::<8>(p.as_str()?)).collect();
                if retired.len() > MAX_RETIRED_KEYS {
                    let excess = retired.len() - MAX_RETIRED_KEYS;
                    retired.drain(..excess);
                }
                e.aux.retired = retired;
            }
            // A run above the limit can only come from a damaged aux: clamp it.
            e.aux.lossy = a.get("l").and_then(strict_json::uint).map_or(0, |l| l.min(LOSSY_RUN_MAX as u64) as u32);
        }
        set
    }

    /// `{"v":1,"s":{"<sid b64>":{"r":["<b64 8 bytes>",…],"l":<run>}}}` — one
    /// entry per session that has something to remember. The host writes it
    /// in the same transaction as [`Self::rows`].
    pub fn aux_json(&self) -> String {
        let entries: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.aux != SessionAux::default())
            .map(|e| {
                let r: Vec<String> = e.aux.retired.iter().map(|p| format!("\"{}\"", b64(p))).collect();
                format!("\"{}\":{{\"r\":[{}],\"l\":{}}}", b64(&e.session.sid), r.join(","), e.aux.lossy)
            })
            .collect();
        format!("{{\"v\":{AUX_VERSION},\"s\":{{{}}}}}", entries.join(","))
    }

    pub fn rows(&self) -> Vec<Row> {
        self.entries
            .iter()
            .map(|e| Row {
                sid_b64: b64(&e.session.sid),
                peer_ek_b64: e.session.peer_ek.map(|k| b64(&k)),
                status: e.status,
                state_json: e.session.to_json(),
                updated_at: e.updated_at,
            })
            .collect()
    }
}

/// `Envelope::parse` for hosts that only need the classification.
pub fn classify(wire: &str) -> Result<Envelope, EnvelopeError> {
    Envelope::parse(wire)
}

/// base64 helper for hosts.
pub fn key32(s: &str) -> Option<[u8; 32]> {
    b64_strict32(s)
}
