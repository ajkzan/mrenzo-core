//! Streaming (path-based) attachment encryption, byte-identical to
//! [`crate::files::encrypt_file`] / `nacl.secretbox` for every size, so a
//! 100 MiB attachment is never held in memory (or copied across the FFI).
//!
//! `nacl.secretbox(m, n, k)` = XSalsa20 keystream over `0^32 ‖ m`; the first
//! 32 keystream bytes are the one-time Poly1305 key, the rest encrypts `m`;
//! the box is `poly1305(ct) ‖ ct`. Here the keystream is generated
//! incrementally in 64 KiB chunks, Poly1305 is fed the ciphertext as it is
//! produced, a 16-byte placeholder is written first and the tag is patched in
//! with a seek at the end.
//!
//! Decryption verifies the tag in a FIRST pass before any plaintext is
//! written; the second pass decrypts and re-authenticates what it read (the
//! input could change between passes), deleting the output on any failure.
//! Like the RN download path (`decrypt_downloaded_file`), an empty plaintext
//! counts as a failure.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use poly1305::universal_hash::{KeyInit, UniversalHash};
use poly1305::{Block, Poly1305};
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::XSalsa20;

use crate::compat::b64::tweetnacl_util_decode_base64;
use crate::files::{FILE_KEY_LEN, FILE_NONCE_LEN};
use crate::rng::Rng;

/// Chunk size (a multiple of 16 and 64 so blocks line up).
pub const CHUNK: usize = 64 * 1024;
const TAG_LEN: usize = 16;

/// Result of [`encrypt_file_path`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamedFileKeys {
    pub key: [u8; FILE_KEY_LEN],
    pub nonce: [u8; FILE_NONCE_LEN],
    /// Bytes written to the output (tag 16 + plaintext length).
    pub ciphertext_len: u64,
}

#[derive(Debug)]
pub enum StreamError {
    Io(io::Error),
    /// Bad key/nonce encoding or length, box shorter than 16 bytes,
    /// authentication failure or empty plaintext.
    DecryptionFailed,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Io(e) => write!(f, "io: {e}"),
            StreamError::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<io::Error> for StreamError {
    fn from(e: io::Error) -> Self {
        StreamError::Io(e)
    }
}

/// Reads until `buf` is full or EOF; returns the number of bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// XSalsa20 positioned after the 32 Poly1305-key bytes, plus the MAC.
fn start(key: &[u8; FILE_KEY_LEN], nonce: &[u8; FILE_NONCE_LEN]) -> (XSalsa20, Poly1305) {
    let mut cipher = XSalsa20::new(key.into(), nonce.into());
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);
    let mac = Poly1305::new((&poly_key).into());
    poly_key.fill(0);
    (cipher, mac)
}

/// Incremental Poly1305 over a byte stream (full blocks via `update`, the
/// unpadded tail at the end — exactly `compute_unpadded` over the whole).
struct Mac {
    mac: Poly1305,
    tail: Vec<u8>,
}

impl Mac {
    fn new(mac: Poly1305) -> Self {
        Self { mac, tail: Vec::with_capacity(TAG_LEN) }
    }

    fn update(&mut self, mut data: &[u8]) {
        if !self.tail.is_empty() {
            let need = TAG_LEN - self.tail.len();
            let take = need.min(data.len());
            self.tail.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.tail.len() < TAG_LEN {
                return;
            }
            self.mac.update(&[*Block::from_slice(&self.tail)]);
            self.tail.clear();
        }
        let full = data.len() / TAG_LEN * TAG_LEN;
        if full > 0 {
            let blocks: Vec<Block> = data[..full].chunks_exact(TAG_LEN).map(|c| *Block::from_slice(c)).collect();
            self.mac.update(&blocks);
        }
        self.tail.extend_from_slice(&data[full..]);
    }

    fn finish(self) -> [u8; TAG_LEN] {
        self.mac.compute_unpadded(&self.tail).into()
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Streaming `encryptFileBase64`: draws key (32) THEN nonce (24) like RN and
/// writes `tag16 ‖ ciphertext` to `out_path` (created/truncated). On error the
/// output is removed.
pub fn encrypt_file_path(in_path: &Path, out_path: &Path, rng: &mut dyn Rng) -> Result<StreamedFileKeys, StreamError> {
    let mut key = [0u8; FILE_KEY_LEN];
    rng.fill(&mut key);
    let mut nonce = [0u8; FILE_NONCE_LEN];
    rng.fill(&mut nonce);
    match encrypt_inner(in_path, out_path, &key, &nonce) {
        Ok(len) => Ok(StreamedFileKeys { key, nonce, ciphertext_len: len }),
        Err(e) => {
            let _ = fs::remove_file(out_path);
            Err(e)
        }
    }
}

/// Deterministic core (tests): seal `in_path` with the given key/nonce.
pub fn encrypt_inner(in_path: &Path, out_path: &Path, key: &[u8; FILE_KEY_LEN], nonce: &[u8; FILE_NONCE_LEN]) -> Result<u64, StreamError> {
    let mut input = File::open(in_path)?;
    let mut out = OpenOptions::new().write(true).create(true).truncate(true).open(out_path)?;
    let (mut cipher, mac) = start(key, nonce);
    let mut mac = Mac::new(mac);
    out.write_all(&[0u8; TAG_LEN])?;
    let mut buf = vec![0u8; CHUNK];
    let mut total: u64 = TAG_LEN as u64;
    loop {
        let n = read_full(&mut input, &mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        cipher.apply_keystream(chunk);
        mac.update(chunk);
        out.write_all(chunk)?;
        total += n as u64;
        if n < CHUNK {
            break;
        }
    }
    let tag = mac.finish();
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&tag)?;
    out.sync_all()?;
    buf.fill(0);
    Ok(total)
}

fn decode_key_nonce(key_b64: &str, nonce_b64: &str) -> Option<([u8; FILE_KEY_LEN], [u8; FILE_NONCE_LEN])> {
    let key: [u8; FILE_KEY_LEN] = tweetnacl_util_decode_base64(key_b64)?.try_into().ok()?;
    let nonce: [u8; FILE_NONCE_LEN] = tweetnacl_util_decode_base64(nonce_b64)?.try_into().ok()?;
    Some((key, nonce))
}

/// Streaming `downloadDecryptedChatFile` tail: verifies, then writes the
/// plaintext to `out_path`. Returns the plaintext length. Any failure removes
/// `out_path` and yields `DecryptionFailed` (or `Io` for I/O errors).
pub fn decrypt_file_path(in_path: &Path, out_path: &Path, key_b64: &str, nonce_b64: &str) -> Result<u64, StreamError> {
    let (key, nonce) = decode_key_nonce(key_b64, nonce_b64).ok_or(StreamError::DecryptionFailed)?;
    let r = decrypt_inner(in_path, out_path, &key, &nonce);
    if r.is_err() {
        let _ = fs::remove_file(out_path);
    }
    r
}

fn decrypt_inner(in_path: &Path, out_path: &Path, key: &[u8; FILE_KEY_LEN], nonce: &[u8; FILE_NONCE_LEN]) -> Result<u64, StreamError> {
    let mut buf = vec![0u8; CHUNK];
    // Pass 1: authenticate only.
    let mut input = File::open(in_path)?;
    let mut tag = [0u8; TAG_LEN];
    if read_full(&mut input, &mut tag)? < TAG_LEN {
        return Err(StreamError::DecryptionFailed);
    }
    let (_, mac) = start(key, nonce);
    let mut mac = Mac::new(mac);
    let mut pt_len: u64 = 0;
    loop {
        let n = read_full(&mut input, &mut buf)?;
        if n == 0 {
            break;
        }
        mac.update(&buf[..n]);
        pt_len += n as u64;
        if n < CHUNK {
            break;
        }
    }
    if !ct_eq(&mac.finish(), &tag) || pt_len == 0 {
        return Err(StreamError::DecryptionFailed);
    }
    // Pass 2: decrypt, re-authenticating the bytes actually decrypted.
    input.seek(SeekFrom::Start(TAG_LEN as u64))?;
    let mut out = OpenOptions::new().write(true).create(true).truncate(true).open(out_path)?;
    let (mut cipher, mac) = start(key, nonce);
    let mut mac = Mac::new(mac);
    let mut written: u64 = 0;
    loop {
        let n = read_full(&mut input, &mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        mac.update(chunk);
        cipher.apply_keystream(chunk);
        out.write_all(chunk)?;
        written += n as u64;
        if n < CHUNK {
            break;
        }
    }
    buf.fill(0);
    if !ct_eq(&mac.finish(), &tag) || written != pt_len {
        return Err(StreamError::DecryptionFailed);
    }
    out.sync_all()?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{secretbox_open, secretbox_seal};

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("mrenzo_fs_{}_{}", std::process::id(), name));
        p
    }

    struct Seq(u8);
    impl Rng for Seq {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_mul(31).wrapping_add(7);
            }
        }
    }

    #[test]
    fn streamed_equals_secretbox_for_every_boundary_size() {
        for &size in &[0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 65535, 65536, 65537, 131072 + 5, 5 * 1024 * 1024 + 3] {
            let plain: Vec<u8> = (0..size).map(|i| (i * 7 + size) as u8).collect();
            let pin = tmp(&format!("in_{size}"));
            let pout = tmp(&format!("out_{size}"));
            let pdec = tmp(&format!("dec_{size}"));
            fs::write(&pin, &plain).unwrap();
            let keys = encrypt_file_path(&pin, &pout, &mut Seq(size as u8)).unwrap();
            let mut rng = Seq(size as u8);
            let expected = crate::files::encrypt_file(&plain, &mut rng);
            assert_eq!(keys.key, expected.key);
            assert_eq!(keys.nonce, expected.nonce);
            let got = fs::read(&pout).unwrap();
            assert_eq!(got, secretbox_seal(&plain, &keys.nonce, &keys.key), "size {size}");
            assert_eq!(keys.ciphertext_len, (size + 16) as u64);
            assert_eq!(secretbox_open(&got, &keys.nonce, &keys.key).unwrap(), plain);

            let kb = crate::primitives::b64(&keys.key);
            let nb = crate::primitives::b64(&keys.nonce);
            let r = decrypt_file_path(&pout, &pdec, &kb, &nb);
            if size == 0 {
                assert!(matches!(r, Err(StreamError::DecryptionFailed)), "empty plaintext is a failure (RN parity)");
                assert!(!pdec.exists());
            } else {
                assert_eq!(r.unwrap(), size as u64);
                assert_eq!(fs::read(&pdec).unwrap(), plain);
            }
            // Flipped ciphertext byte → failure, no output file.
            if size > 0 {
                let mut bad = got.clone();
                let i = 16 + size / 2;
                bad[i] ^= 1;
                fs::write(&pout, &bad).unwrap();
                assert!(matches!(decrypt_file_path(&pout, &pdec, &kb, &nb), Err(StreamError::DecryptionFailed)));
                assert!(!pdec.exists());
            }
            for p in [&pin, &pout, &pdec] {
                let _ = fs::remove_file(p);
            }
        }
    }

    #[test]
    fn short_box_and_bad_keys_fail() {
        let pin = tmp("short");
        let pout = tmp("short_out");
        fs::write(&pin, [1u8; 10]).unwrap();
        let k = crate::primitives::b64(&[0u8; 32]);
        let n = crate::primitives::b64(&[0u8; 24]);
        assert!(matches!(decrypt_file_path(&pin, &pout, &k, &n), Err(StreamError::DecryptionFailed)));
        assert!(matches!(decrypt_file_path(&pin, &pout, "AAAA", &n), Err(StreamError::DecryptionFailed)));
        assert!(matches!(decrypt_file_path(&pin, &pout, &k, "not base64!"), Err(StreamError::DecryptionFailed)));
        assert!(!pout.exists());
        let _ = fs::remove_file(&pin);
    }
}
