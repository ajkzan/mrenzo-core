//! Injectable randomness. Production: [`OsRng`]. Tests: [`ReplayRng`], which
//! feeds the draws recorded from the TypeScript implementation and asserts the
//! code asks for exactly the same sizes in exactly the same order — the same
//! contract tweetnacl's `randombytes` has in the RN client.

pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// OS CSPRNG (what tweetnacl uses in production).
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("OS randomness unavailable");
    }
}

/// Replays recorded draws; panics on any size/order/count mismatch.
pub struct ReplayRng {
    draws: Vec<Vec<u8>>,
    next: usize,
    label: String,
}

impl ReplayRng {
    pub fn new(label: impl Into<String>, draws: Vec<Vec<u8>>) -> Self {
        Self { draws, next: 0, label: label.into() }
    }

    /// All recorded draws must be consumed — an implementation that draws
    /// LESS than the reference is just as divergent as one that draws more.
    pub fn assert_exhausted(&self) {
        assert_eq!(
            self.next,
            self.draws.len(),
            "replay {}: consumed {}/{} recorded draws",
            self.label,
            self.next,
            self.draws.len()
        );
    }
}

impl Rng for ReplayRng {
    fn fill(&mut self, buf: &mut [u8]) {
        let d = self.draws.get(self.next).unwrap_or_else(|| {
            panic!("replay {}: unexpected extra draw #{} of {} bytes", self.label, self.next + 1, buf.len())
        });
        assert_eq!(
            d.len(),
            buf.len(),
            "replay {}: draw #{} asked {} bytes, recorded {}",
            self.label,
            self.next + 1,
            buf.len(),
            d.len()
        );
        buf.copy_from_slice(d);
        self.next += 1;
    }
}

/// The golden-vector PRNG of docs/native/vectors/README.md#prng:
/// `stream(D) = SHA-256(D ‖ be32(0)) ‖ SHA-256(D ‖ be32(1)) ‖ …` with
/// `D = UTF-8("mrenzo-golden-prng-v1|" + label)`; each draw takes the next
/// bytes. Test and vector generation only — never production.
pub struct StreamRng {
    domain: Vec<u8>,
    block: u32,
    buf: Vec<u8>,
}

impl StreamRng {
    pub fn new(label: &str) -> Self {
        Self { domain: format!("mrenzo-golden-prng-v1|{label}").into_bytes(), block: 0, buf: Vec::new() }
    }
}

impl Rng for StreamRng {
    fn fill(&mut self, out: &mut [u8]) {
        while self.buf.len() < out.len() {
            let mut input = self.domain.clone();
            input.extend_from_slice(&self.block.to_be_bytes());
            self.buf.extend_from_slice(&crate::primitives::sha256(&input));
            self.block += 1;
        }
        out.copy_from_slice(&self.buf[..out.len()]);
        self.buf.drain(..out.len());
    }
}
