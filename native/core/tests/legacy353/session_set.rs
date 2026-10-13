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

use mrenzo_core::primitives::{b64, KeyPair};
use crate::legacy353::ratchet::{self, b64_strict32, Envelope, EnvelopeError, RatchetError, Role, Session};
use mrenzo_core::rng::Rng;
use crate::legacy353::x3dh::{x3dh_v2_initiate, x3dh_v2_respond, BundleV2, X3dhV2Error};

pub const MAX_ARCHIVED: usize = 3;
pub const ARCHIVE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSessions {
    pub entries: Vec<Entry>,
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
        let mut set = PeerSessions { entries };
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
        self.entries.insert(0, Entry { session, status, updated_at: now_ms });
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

    /// One ratchet step on the live session.
    pub fn encrypt(&mut self, plaintext: &str, now_ms: i64, rng: &mut dyn Rng) -> Result<Envelope, RatchetError> {
        let i = self.live_index().ok_or(RatchetError::NoSendChain)?;
        let (next, env) = ratchet::encrypt(&self.entries[i].session, plaintext, now_ms, rng)?;
        self.entries[i].session = next;
        self.entries[i].updated_at = now_ms;
        Ok(env)
    }

    fn opened(&mut self, i: usize, next: Session, plaintext: String, now_ms: i64, created: bool) -> SetDecrypt {
        let sid = next.sid;
        let promoted = self.entries[i].status == Status::Archived;
        if promoted {
            self.archive_live(now_ms);
        }
        let status = Entry::live_status(&next);
        self.entries[i] = Entry { session: next, status, updated_at: now_ms };
        self.prune(now_ms);
        SetDecrypt::Opened { plaintext, sid, promoted, created }
    }

    /// Decrypts under the stored sessions (§5.1 table, §5.3 step 2).
    pub fn decrypt(&mut self, env: &Envelope, now_ms: i64, rng: &mut dyn Rng) -> SetDecrypt {
        let candidates: Vec<usize> = match &env.x {
            Some(x) => {
                let hits: Vec<usize> = (0..self.entries.len()).filter(|&i| self.entries[i].session.peer_ek == Some(x.ek)).collect();
                if hits.is_empty() {
                    return SetDecrypt::NeedsResponder;
                }
                hits
            }
            None => self.candidate_order(),
        };
        if candidates.is_empty() {
            return SetDecrypt::NoSession;
        }
        let mut too_many = false;
        for i in candidates {
            match ratchet::decrypt(&self.entries[i].session, env, now_ms, rng) {
                Ok(Some((next, pt))) => return self.opened(i, next, pt, now_ms, false),
                Ok(None) => {}
                Err(RatchetError::TooManySkippedKeys) => too_many = true,
                Err(RatchetError::NoSendChain) => {}
            }
        }
        if too_many {
            SetDecrypt::TooManySkipped
        } else {
            SetDecrypt::Failed
        }
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
        let Some(x) = env.x else { return Ok(SetDecrypt::Failed) };
        let secret = x3dh_v2_respond(my_ik, my_ed_pub, spk, opk_priv, &x, pinned_ik, pinned_ed)?;
        let fresh = ratchet::respond(&secret, spk, &x, now_ms);
        Ok(match ratchet::decrypt(&fresh, env, now_ms, rng) {
            Ok(Some((next, pt))) => {
                let sid = next.sid;
                self.install(next, now_ms);
                SetDecrypt::Opened { plaintext: pt, sid, promoted: false, created: true }
            }
            Ok(None) => SetDecrypt::Failed,
            Err(_) => SetDecrypt::TooManySkipped,
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

    /// The mesh ACK payload for a message decrypted under session `sid`.
    pub fn ack_payload(&self, sid: &[u8; 32], message_id: &str) -> Option<String> {
        self.entries.iter().any(|e| e.session.sid == *sid).then(|| ratchet::mesh_ack_payload(sid, message_id))
    }

    /// The acked id when `payload` carries a valid tag under one of our sessions.
    pub fn ack_matches(&self, payload: &str) -> Option<String> {
        self.candidate_order().into_iter().find_map(|i| ratchet::mesh_ack_matches(&self.entries[i].session.sid, payload))
    }
}

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
                (b64(&session.sid) == r.sid_b64).then_some(Entry { session, status: r.status, updated_at: r.updated_at })
            })
            .collect();
        PeerSessions::new(entries, now_ms)
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
