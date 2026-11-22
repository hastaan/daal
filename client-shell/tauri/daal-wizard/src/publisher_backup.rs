//! Publisher backup and restore: one file holding everything a
//! publisher needs to carry on from another phone, encrypted under
//! twelve recovery words the app generates and the person writes down.
//!
//! # Why
//!
//! Everything a publisher needs to keep serving their family lives in
//! this app's private storage on one phone: the relays, each relay's
//! signing key and hosting key, the people, their files and the setup
//! journals; and the account keys kept apart from any relay (the
//! Accounts page's hosting key and Cloudflare key), when there are any. The keys are wrapped under the phone's own key store
//! (`device_custody`), so they cannot leave the phone as they are. A
//! backup re-wraps them under a secret the person holds, and a restore
//! wraps them again under the new phone's key store.
//!
//! # The secret
//!
//! 128 bits from the OS, encoded exactly like a 12-word BIP-39 mnemonic
//! (entropy, then the first 4 bits of SHA-256(entropy), in 11-bit
//! groups). The BIP-39 seed step (PBKDF2) is NOT used: the KDF input is
//! the 16 raw entropy bytes. The word list (`backup_words.txt`) is the
//! canonical BIP-39 English list, taken from filippo.io/age v1.1.1
//! (`cmd/age/wordlist.go`, BSD-3-Clause), already a dependency of
//! `core/go.mod`. Its SHA-256 is pinned by a test.
//!
//! # The file (`.daalbackup`, big-endian)
//!
//! ```text
//! off  len  field
//! 0    8    magic          = b"DAALBKUP"
//! 8    2    format_version = 1
//! 10   1    kdf_id         = 1  (Argon2id v0x13)
//! 11   1    aead_id        = 1  (AES-256-GCM)
//! 12   4    m_kib          = 65536
//! 16   4    t_cost         = 3
//! 20   4    p_lanes        = 1
//! 24   16   salt
//! 40   12   nonce
//! 52   16   check
//! 68   8    ct_len
//! 76   ct_len ciphertext (incl. 16-byte tag), aad = header[0..76]
//! ```
//!
//! `ikm = Argon2id(entropy, salt, m, t, p, 32)`, `key = HKDF(ikm,
//! "daal.backup.v1.key")`, `check = HKDF(ikm, "daal.backup.v1.check")`.
//! The check is what separates "wrong words" from "damaged file". The
//! header holds no relay, person, address, provider or time.
//!
//! KDF parameters: 64 MiB / t=3 / p=1, the same memory the custody
//! passphrase path uses; the `argon2` crate is single-threaded, so p=1.
//! Expected 1-3 s on a mid-range phone (NOT measured on a phone). The
//! words already carry 128 bits, so the KDF is defence in depth.
//!
//! # Plaintext
//!
//! The payload is built and parsed in memory only, in `Zeroizing`
//! buffers; no plaintext temp file is ever written, and the only file
//! a backup writes is the ciphertext. Known limit: the JSON tree that
//! `serde_json` builds and parses holds copies of the base64 secrets in
//! ordinary `String`s that are freed without being wiped.
//!
//! # Restore
//!
//! Validates everything first (including a dry-run insert that is
//! rolled back), then: writes every secret and file into a
//! custody-wrapped pending blob; commits all rows plus a pending marker
//! in ONE transaction (the commit point); then rolls forward (files,
//! keys, forgets, words, marker cleared). Every roll-forward step is
//! idempotent and runs again from `list_operators`, `custody_status`,
//! `backup_status` and `custody_get`, so a kill leaves either the old
//! state or the new one, never a mix that an operation could act on.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::commands::{
    coded, map_custody_err, probe_custody, Result, WizardCtx, WizardError, E_BACKUP_DAMAGED,
    E_BACKUP_NEWER, E_BACKUP_NOTHING, E_BACKUP_NOT_A_BACKUP, E_BACKUP_NO_WORDS,
    E_BACKUP_SAVE_FAILED, E_BACKUP_SECRET_UNREADABLE, E_BACKUP_WORDS_INVALID,
    E_BACKUP_WORDS_MISMATCH, E_BACKUP_WRONG_WORDS, E_CUSTODY_BACKEND, E_CUSTODY_LOCKED,
    E_BACKUP_READ_FAILED, E_HOSTING_KEY_REJECTED, E_HOSTING_KEY_WRONG_ACCOUNT,
    E_LEGACY_PIN_REQUIRED, E_RESTORE_FAILED, E_RESTORE_STATE_CHANGED,
    E_RESTORE_UNFINISHED, E_RESTORE_WOULD_REPLACE, E_SETUP_RUNNING,
};
use crate::device_custody::CustodyError;

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

pub const MAGIC: &[u8; 8] = b"DAALBKUP";
pub const FORMAT_VERSION: u16 = 1;
pub const KDF_ARGON2ID: u8 = 1;
pub const AEAD_AES256GCM: u8 = 1;
/// Production Argon2id memory, KiB. Pinned by a test.
pub const KDF_M_KIB: u32 = 65536;
/// Production Argon2id passes. Pinned by a test.
pub const KDF_T_COST: u32 = 3;
/// Production Argon2id lanes. Pinned by a test.
pub const KDF_P_LANES: u32 = 1;
pub const HEADER_LEN: usize = 76;
/// The largest ciphertext a reader accepts.
pub const MAX_CIPHERTEXT: u64 = 64 * 1024 * 1024;
pub const PAYLOAD_KIND: &str = "daal.publisher-backup";
pub const PAYLOAD_VERSION: i64 = 1;
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The confirmed recovery words' entropy (16 bytes).
pub const WORDS_ALIAS: &str = "daal.backup.words";
/// Words shown but not yet confirmed.
pub const WORDS_PENDING_ALIAS: &str = "daal.backup.words.pending";
/// `daal.restore.pending.<nonce>`: what a committed restore still has to write.
pub const RESTORE_PENDING_PREFIX: &str = "daal.restore.pending.";

const KEY_INFO: &[u8] = b"daal.backup.v1.key";
const CHECK_INFO: &[u8] = b"daal.backup.v1.check";
const DIGEST_DOMAIN: &[u8] = b"daal.backup.state.v1\0";

/// Tables a backup carries, in insert order (delete in reverse).
pub const INCLUDED_TABLES: &[&str] = &[
    "operators",
    "signed_sbps",
    "subkeys",
    "cdn_fronts",
    "cells",
    "operator_cell_membership",
    "cell_revocations",
    "recipients",
    "recipient_name_counters",
    "relay_identity",
    "freshness_endpoints",
    // V019: the add-on ledger. A new phone must know what still bills
    // and how to take it down; each add-on's secret comes along through
    // `ALIAS_COLUMNS`.
    "relay_addons",
];

/// INCLUDED tables added after backups were already being made, with
/// the schema version that added each. A backup from before that
/// version has no such table and restores as if it were empty; and the
/// table counts in the staleness digest only once it has rows, so a
/// phone that never used it keeps the digest (and the up-to-date
/// backup) it had before the table existed.
pub const LATER_TABLES: &[(&str, i64)] = &[("relay_addons", 19)];

fn later_table_since(t: &str) -> Option<i64> {
    LATER_TABLES.iter().find(|(n, _)| *n == t).map(|(_, v)| *v)
}

/// Tables a backup deliberately leaves out: this phone's own recipient
/// identity, its audit and bookkeeping, and the per-device backup meta.
pub const EXCLUDED_TABLES: &[&str] = &[
    "pin_attempts",
    "recipient_identity",
    "recipient_identity_history",
    "custody_events",
    "schema_migrations",
    "publisher_backup_meta",
    // V018: per device, written by the restore itself (`restore_settle`).
    "restore_unsettled",
];

/// Columns holding a file path. Carried as a path relative to the
/// staging dir and rewritten to the new phone's staging dir.
pub const PATH_COLUMNS: &[(&str, &str)] = &[
    ("signed_sbps", "sbp_path"),
    ("subkeys", "subkey_pub_path"),
    ("subkeys", "subkey_priv_path"),
    ("subkeys", "subkey_cert_path"),
    ("cdn_fronts", "origin_ca_cert_path"),
    ("cdn_fronts", "origin_ca_priv_path"),
    ("cdn_fronts", "aop_client_cert_path"),
];

/// Columns ending in `_path` that are URL paths, not files.
pub const NOT_FILE_PATH_COLUMNS: &[(&str, &str)] = &[
    ("cdn_fronts", "public_path"),
    ("cdn_fronts", "origin_path"),
    ("recipients", "ws_path"),
];

/// Values describing the old phone or an old moment: reset on restore
/// and left out of the staleness digest.
const RESET_COLUMNS: &[(&str, &str)] = &[
    ("operators", "helper_ip"),
    ("operators", "helper_ip_source"),
    ("operators", "helper_ip_at_unix"),
    ("operators", "last_health_json"),
    ("operators", "last_health_at_unix"),
];

/// Restored as they are, but left out of the staleness digest.
const VOLATILE_COLUMNS: &[(&str, &str)] = &[
    ("relay_identity", "learned_at_unix"),
    ("freshness_endpoints", "last_publish_at_unix"),
    ("freshness_endpoints", "last_publish_ok"),
    ("freshness_endpoints", "last_publish_status"),
    ("freshness_endpoints", "last_publish_detail"),
    ("freshness_endpoints", "last_published_url"),
];

/// Columns naming a custody alias.
const ALIAS_COLUMNS: &[(&str, &str)] = &[
    ("operators", "publisher_priv_keystore_alias"),
    ("operators", "cloud_token_keystore_alias"),
    ("freshness_endpoints", "secret_alias"),
    ("relay_addons", "secret_alias"),
    ("cells", "bundle_signer_priv_alias"),
    ("cells", "admin_priv_alias"),
];

/// Alias prefixes a backup may never write (compared after the same
/// sanitising `FileCustody` applies to file names).
const FORBIDDEN_ALIAS_PREFIXES: &[&str] = &[
    "recipient_priv_x25519",
    "daal.backup.",
    "daal.restore.",
    "daal.custody.",
];

// ---------------------------------------------------------------------
// Recovery words
// ---------------------------------------------------------------------

const WORDS_TXT: &str = include_str!("backup_words.txt");

fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| WORDS_TXT.lines().collect())
}

/// Why typed words did not parse. Never carries a typed word: command
/// failures are logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordsError {
    /// Not exactly 12 words.
    Count(usize),
    /// Word at this 1-based position is not a list word.
    NotAWord(usize),
    /// Twelve list words, but the checksum does not hold.
    Checksum,
}

impl std::fmt::Display for WordsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WordsError::Count(n) => write!(f, "expected 12 words, got {n}"),
            WordsError::NotAWord(i) => write!(f, "word {i} is not one of the recovery words"),
            WordsError::Checksum => write!(f, "the words do not fit together; one may be wrong"),
        }
    }
}

fn entropy_bit(e: &[u8; 16], cs: u8, i: usize) -> u16 {
    if i < 128 {
        ((e[i / 8] >> (7 - (i % 8))) & 1) as u16
    } else {
        ((cs >> (3 - (i - 128))) & 1) as u16
    }
}

/// The 12 words for `entropy`, BIP-39 style.
pub fn words_from_entropy(entropy: &[u8; 16]) -> Vec<&'static str> {
    let cs = Sha256::digest(entropy)[0] >> 4;
    let list = wordlist();
    (0..12)
        .map(|w| {
            let mut idx: u16 = 0;
            for b in 0..11 {
                idx = (idx << 1) | entropy_bit(entropy, cs, w * 11 + b);
            }
            list[idx as usize]
        })
        .collect()
}

/// Map one typed character (§1 of the wave contract): the standard
/// Persian keyboard layout to the Latin letter on the same key,
/// Persian / Arabic-Indic digits to ASCII, fullwidth Latin to ASCII,
/// ASCII to lowercase. Everything else passes through (and is then a
/// separator unless it is a-z).
fn map_char(c: char) -> char {
    let mapped = match c {
        'ض' => 'q',
        'ص' => 'w',
        'ث' => 'e',
        'ق' => 'r',
        'ف' => 't',
        'غ' => 'y',
        'ع' => 'u',
        'ه' => 'i',
        'خ' => 'o',
        'ح' => 'p',
        'ش' => 'a',
        'س' => 's',
        'ی' | 'ي' | 'ى' => 'd',
        'ب' => 'f',
        'ل' => 'g',
        'ا' | 'آ' => 'h',
        'ت' => 'j',
        'ن' => 'k',
        'م' => 'l',
        'ظ' => 'z',
        'ط' => 'x',
        'ز' => 'c',
        'ر' => 'v',
        'ذ' => 'b',
        'د' => 'n',
        'پ' => 'm',
        '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (c as u32 - 0x06F0) as u8),
        '\u{0660}'..='\u{0669}' => char::from(b'0' + (c as u32 - 0x0660) as u8),
        '\u{FF21}'..='\u{FF3A}' => char::from(b'a' + (c as u32 - 0xFF21) as u8),
        '\u{FF41}'..='\u{FF5A}' => char::from(b'a' + (c as u32 - 0xFF41) as u8),
        '\u{FF10}'..='\u{FF19}' => char::from(b'0' + (c as u32 - 0xFF10) as u8),
        other => other,
    };
    mapped.to_ascii_lowercase()
}

/// Split typed text into maximal a-z runs after mapping.
fn typed_runs(text: &str) -> Vec<Zeroizing<String>> {
    let mut out = Vec::new();
    let mut cur = Zeroizing::new(String::new());
    for c in text.chars() {
        let m = map_char(c);
        if m.is_ascii_lowercase() {
            cur.push(m);
        } else if !cur.is_empty() {
            out.push(std::mem::replace(&mut cur, Zeroizing::new(String::new())));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A typed word's list index: an exact match, or a prefix of at least
/// four letters that names exactly one word.
fn resolve_word(w: &str) -> Option<u16> {
    let list = wordlist();
    if let Ok(i) = list.binary_search(&w) {
        return Some(i as u16);
    }
    if w.len() < 4 {
        return None;
    }
    let mut found = None;
    for (i, cand) in list.iter().enumerate() {
        if cand.starts_with(w) {
            if found.is_some() {
                return None;
            }
            found = Some(i as u16);
        }
    }
    found
}

/// Parse what the person typed into the 16 entropy bytes.
pub fn parse_words(text: &str) -> std::result::Result<Zeroizing<[u8; 16]>, WordsError> {
    let runs = typed_runs(text);
    if runs.len() != 12 {
        return Err(WordsError::Count(runs.len()));
    }
    let mut idx = [0u16; 12];
    for (i, r) in runs.iter().enumerate() {
        idx[i] = resolve_word(r).ok_or(WordsError::NotAWord(i + 1))?;
    }
    let mut bits = [0u8; 17]; // 132 bits, MSB first
    for (w, &v) in idx.iter().enumerate() {
        for b in 0..11 {
            let bit = (v >> (10 - b)) & 1;
            let pos = w * 11 + b;
            if bit == 1 {
                bits[pos / 8] |= 1 << (7 - (pos % 8));
            }
        }
    }
    let mut e = Zeroizing::new([0u8; 16]);
    e.copy_from_slice(&bits[..16]);
    let cs = bits[16] >> 4;
    bits.iter_mut().for_each(|b| *b = 0);
    if Sha256::digest(&e[..])[0] >> 4 != cs {
        return Err(WordsError::Checksum);
    }
    Ok(e)
}

fn words_err(e: WordsError) -> WizardError {
    coded(E_BACKUP_WORDS_INVALID, e)
}

// ---------------------------------------------------------------------
// KDF + AEAD + header
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_lanes: u32,
}

impl KdfParams {
    pub const PRODUCTION: KdfParams = KdfParams {
        m_kib: KDF_M_KIB,
        t_cost: KDF_T_COST,
        p_lanes: KDF_P_LANES,
    };

    fn in_bounds(&self) -> bool {
        (8192..=262_144).contains(&self.m_kib)
            && (1..=10).contains(&self.t_cost)
            && (1..=8).contains(&self.p_lanes)
    }
}

#[cfg(test)]
thread_local! {
    /// Tests write cheap files (the header carries the parameters).
    static MAKE_PARAMS: std::cell::Cell<KdfParams> =
        const { std::cell::Cell::new(KdfParams { m_kib: 8192, t_cost: 1, p_lanes: 1 }) };
}

fn make_params() -> KdfParams {
    #[cfg(test)]
    {
        MAKE_PARAMS.with(|p| p.get())
    }
    #[cfg(not(test))]
    {
        KdfParams::PRODUCTION
    }
}

struct Derived {
    key: Zeroizing<[u8; 32]>,
    check: [u8; 16],
}

fn derive(entropy: &[u8; 16], salt: &[u8; 16], p: KdfParams) -> Result<Derived> {
    let params = Params::new(p.m_kib, p.t_cost, p.p_lanes, Some(32))
        .map_err(|e| coded(E_BACKUP_DAMAGED, format!("kdf parameters: {e}")))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut ikm = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(entropy, salt, &mut ikm[..])
        .map_err(|e| coded(E_BACKUP_DAMAGED, format!("kdf: {e}")))?;
    let hk = Hkdf::<Sha256>::new(None, &ikm[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(KEY_INFO, &mut key[..])
        .map_err(|_| coded(E_CUSTODY_BACKEND, "hkdf expand"))?;
    let mut check = [0u8; 16];
    hk.expand(CHECK_INFO, &mut check)
        .map_err(|_| coded(E_CUSTODY_BACKEND, "hkdf expand"))?;
    Ok(Derived { key, check })
}

#[derive(Debug, Clone)]
struct Header {
    params: KdfParams,
    salt: [u8; 16],
    nonce: [u8; 12],
    check: [u8; 16],
    ct_len: u64,
}

fn header_bytes(h: &Header) -> [u8; HEADER_LEN] {
    let mut b = [0u8; HEADER_LEN];
    b[0..8].copy_from_slice(MAGIC);
    b[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    b[10] = KDF_ARGON2ID;
    b[11] = AEAD_AES256GCM;
    b[12..16].copy_from_slice(&h.params.m_kib.to_be_bytes());
    b[16..20].copy_from_slice(&h.params.t_cost.to_be_bytes());
    b[20..24].copy_from_slice(&h.params.p_lanes.to_be_bytes());
    b[24..40].copy_from_slice(&h.salt);
    b[40..52].copy_from_slice(&h.nonce);
    b[52..68].copy_from_slice(&h.check);
    b[68..76].copy_from_slice(&h.ct_len.to_be_bytes());
    b
}

/// Encrypt `payload` under `entropy` into a complete backup file.
pub(crate) fn seal(entropy: &[u8; 16], payload: &[u8], p: KdfParams) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let d = derive(entropy, &salt, p)?;
    let h = Header {
        params: p,
        salt,
        nonce,
        check: d.check,
        ct_len: payload.len() as u64 + 16,
    };
    let hb = header_bytes(&h);
    let cipher =
        Aes256Gcm::new_from_slice(&d.key[..]).map_err(|_| coded(E_CUSTODY_BACKEND, "aead key"))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &hb,
            },
        )
        .map_err(|_| coded(E_CUSTODY_BACKEND, "aead seal"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&hb);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Read order steps 1-3: magic, version/ids, structure.
fn parse_header(bytes: &[u8]) -> Result<Header> {
    if bytes.len() < 8 || &bytes[0..8] != MAGIC {
        return Err(coded(
            E_BACKUP_NOT_A_BACKUP,
            "the file does not start like a Daal backup",
        ));
    }
    if bytes.len() < 12 {
        return Err(coded(E_BACKUP_DAMAGED, "the file ends inside its header"));
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != FORMAT_VERSION || bytes[10] != KDF_ARGON2ID || bytes[11] != AEAD_AES256GCM {
        return Err(coded(
            E_BACKUP_NEWER,
            format!("format {version}, kdf {}, cipher {}", bytes[10], bytes[11]),
        ));
    }
    if bytes.len() < HEADER_LEN {
        return Err(coded(E_BACKUP_DAMAGED, "the file ends inside its header"));
    }
    let u32_at = |o: usize| u32::from_be_bytes(bytes[o..o + 4].try_into().unwrap());
    let params = KdfParams {
        m_kib: u32_at(12),
        t_cost: u32_at(16),
        p_lanes: u32_at(20),
    };
    let ct_len = u64::from_be_bytes(bytes[68..76].try_into().unwrap());
    if (bytes.len() as u64) > MAX_CIPHERTEXT + HEADER_LEN as u64
        || ct_len < 16
        || ct_len > MAX_CIPHERTEXT
        || bytes.len() as u64 != HEADER_LEN as u64 + ct_len
    {
        return Err(coded(
            E_BACKUP_DAMAGED,
            "the file length does not match its header",
        ));
    }
    if !params.in_bounds() {
        return Err(coded(
            E_BACKUP_DAMAGED,
            "the key parameters are out of range",
        ));
    }
    let mut h = Header {
        params,
        salt: [0; 16],
        nonce: [0; 12],
        check: [0; 16],
        ct_len,
    };
    h.salt.copy_from_slice(&bytes[24..40]);
    h.nonce.copy_from_slice(&bytes[40..52]);
    h.check.copy_from_slice(&bytes[52..68]);
    Ok(h)
}

/// Read a file the person picked. The magic is checked before any size
/// cap, so a large photo is "not a backup", not "damaged".
fn read_backup_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;
    // Could not be opened or read: say that, not "not a backup" — the
    // file may be a good backup this phone cannot reach right now.
    let read_failed = |what: &str, e: std::io::Error| {
        coded(E_BACKUP_READ_FAILED, format!("{what}: {}", e.kind()))
    };
    let mut f = std::fs::File::open(path).map_err(|e| read_failed("cannot open the file", e))?;
    if f.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return Err(coded(E_BACKUP_READ_FAILED, "this is a folder, not a file"));
    }
    let mut magic = [0u8; 8];
    let mut got = 0;
    while got < 8 {
        match f.read(&mut magic[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(read_failed("cannot read the file", e)),
        }
    }
    if got < 8 || &magic != MAGIC {
        return Err(coded(
            E_BACKUP_NOT_A_BACKUP,
            "the file does not start like a Daal backup",
        ));
    }
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len > MAX_CIPHERTEXT + HEADER_LEN as u64 {
        return Err(coded(
            E_BACKUP_DAMAGED,
            "the file is larger than any backup",
        ));
    }
    let mut bytes = magic.to_vec();
    f.take(MAX_CIPHERTEXT + HEADER_LEN as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| read_failed("cannot read the file", e))?;
    Ok(bytes)
}

/// Steps 4-6: words, check, AEAD. Returns the plaintext payload.
fn decrypt(bytes: &[u8], words: &str) -> Result<Zeroizing<Vec<u8>>> {
    let h = parse_header(bytes)?;
    let entropy = parse_words(words).map_err(words_err)?;
    decrypt_with(bytes, &h, &entropy)
}

fn decrypt_with(bytes: &[u8], h: &Header, entropy: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>> {
    let d = derive(entropy, &h.salt, h.params)?;
    if !bool::from(d.check.ct_eq(&h.check)) {
        return Err(coded(
            E_BACKUP_WRONG_WORDS,
            "these words do not open this backup",
        ));
    }
    let cipher =
        Aes256Gcm::new_from_slice(&d.key[..]).map_err(|_| coded(E_CUSTODY_BACKEND, "aead key"))?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&h.nonce),
            Payload {
                msg: &bytes[HEADER_LEN..],
                aad: &bytes[..HEADER_LEN],
            },
        )
        .map_err(|_| coded(E_BACKUP_DAMAGED, "the contents do not match their seal"))?;
    Ok(Zeroizing::new(pt))
}

// ---------------------------------------------------------------------
// State snapshot (shared by make, digest and restore)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
    /// A path column, relative to the staging dir.
    Path(String),
}

impl Cell {
    fn to_json(&self) -> Value {
        match self {
            Cell::Null => Value::Null,
            Cell::Int(i) => json!(i),
            Cell::Real(f) => json!({ "real": f }),
            Cell::Text(s) => Value::String(s.clone()),
            Cell::Blob(b) => json!({ "b64": B64.encode(b) }),
            Cell::Path(r) => json!({ "staging_rel": r }),
        }
    }
    fn as_str(&self) -> &str {
        match self {
            Cell::Text(s) => s,
            _ => "",
        }
    }
    fn as_i64(&self) -> i64 {
        match self {
            Cell::Int(i) => *i,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct TableDump {
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

impl TableDump {
    fn col(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c == name)
    }
    fn get<'a>(&'a self, row: &'a [Cell], name: &str) -> &'a Cell {
        static NULL: Cell = Cell::Null;
        self.col(name).map(|i| &row[i]).unwrap_or(&NULL)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Area {
    Staging,
    Journal,
}

impl Area {
    fn as_str(self) -> &'static str {
        match self {
            Area::Staging => "staging",
            Area::Journal => "journal",
        }
    }
    fn parse(s: &str) -> Option<Area> {
        match s {
            "staging" => Some(Area::Staging),
            "journal" => Some(Area::Journal),
            _ => None,
        }
    }
}

struct FileEntry {
    area: Area,
    rel: String,
    bytes: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct Snapshot {
    tables: BTreeMap<String, TableDump>,
    /// Sorted by alias.
    secrets: Vec<(String, Zeroizing<Vec<u8>>)>,
    missing: Vec<String>,
    files: Vec<FileEntry>,
}

impl Snapshot {
    fn table(&self, name: &str) -> &TableDump {
        static EMPTY: OnceLock<TableDump> = OnceLock::new();
        self.tables
            .get(name)
            .unwrap_or_else(|| EMPTY.get_or_init(TableDump::default))
    }
    fn operator_ids(&self) -> Vec<i64> {
        let t = self.table("operators");
        t.rows.iter().map(|r| t.get(r, "id").as_i64()).collect()
    }
    fn secret(&self, alias: &str) -> Option<&Zeroizing<Vec<u8>>> {
        self.secrets
            .iter()
            .find(|(a, _)| a == alias)
            .map(|(_, v)| v)
    }
}

fn is_listed(list: &[(&str, &str)], table: &str, col: &str) -> bool {
    list.iter().any(|(t, c)| *t == table && *c == col)
}

fn db_err(e: rusqlite::Error) -> WizardError {
    WizardError::Db(crate::operator_db::DbError::Sqlite(e))
}

fn table_columns(conn: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let cols = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(cols)
}

fn all_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let v = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(v)
}

/// A relative path as a backup carries it: relative, no `..`, no empty
/// component, every component `[A-Za-z0-9._-]+`.
pub(crate) fn valid_rel(rel: &str) -> bool {
    !rel.is_empty()
        && rel.len() <= 512
        && rel.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && c.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
        })
}

fn safe_component(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let out = out.trim_matches('.').to_string();
    if out.is_empty() {
        "file".into()
    } else {
        out
    }
}

fn rel_for_path(staging: &Path, table: &str, rowid: i64, col: &str, path: &str) -> String {
    let p = Path::new(path);
    if let Ok(r) = p.strip_prefix(staging) {
        let s = r.to_string_lossy().replace('\\', "/");
        if valid_rel(&s) {
            return s;
        }
    }
    let base = p
        .file_name()
        .map(|b| b.to_string_lossy().to_string())
        .unwrap_or_default();
    format!("outside/{table}-{rowid}-{col}-{}", safe_component(&base))
}

/// Dump the INCLUDED tables. Path columns become staging-relative.
fn dump_tables(
    conn: &Connection,
    staging: &Path,
) -> rusqlite::Result<(BTreeMap<String, TableDump>, Vec<(String, PathBuf)>)> {
    let mut tables = BTreeMap::new();
    let mut path_files: Vec<(String, PathBuf)> = Vec::new();
    for &t in INCLUDED_TABLES {
        let columns = table_columns(conn, t)?;
        let sel = columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut stmt = conn.prepare(&format!("SELECT rowid, {sel} FROM \"{t}\" ORDER BY rowid"))?;
        let mut rows_out = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let rowid: i64 = r.get(0)?;
            let mut row = Vec::with_capacity(columns.len());
            for (i, c) in columns.iter().enumerate() {
                let cell = match r.get_ref(i + 1)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(v) => Cell::Int(v),
                    ValueRef::Real(v) => Cell::Real(v),
                    ValueRef::Text(b) => {
                        let s = String::from_utf8_lossy(b).to_string();
                        if is_listed(PATH_COLUMNS, t, c) && !s.is_empty() {
                            let rel = rel_for_path(staging, t, rowid, c, &s);
                            path_files.push((rel.clone(), PathBuf::from(&s)));
                            Cell::Path(rel)
                        } else {
                            Cell::Text(s)
                        }
                    }
                    ValueRef::Blob(b) => Cell::Blob(b.to_vec()),
                };
                row.push(cell);
            }
            rows_out.push(row);
        }
        tables.insert(
            t.to_string(),
            TableDump {
                columns,
                rows: rows_out,
            },
        );
    }
    Ok((tables, path_files))
}

/// The conventional staging names a relay owns.
fn conventional_staging(staging: &Path, id: i64) -> Vec<String> {
    let mut v = vec![
        format!("{id}.sbp"),
        format!("{id}.shared.sbp"),
        format!("{id}.pre-provision.json"),
        format!("freshness.{id}.json"),
    ];
    let prefix = format!("{id}.");
    if let Ok(rd) = std::fs::read_dir(staging) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with(&prefix)
                && name.ends_with(".sbpx")
                && name.len() > prefix.len() + 5
                && valid_rel(&name)
                && e.file_type().map(|t| t.is_file()).unwrap_or(false)
            {
                v.push(name);
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Every file the state names: (area, rel, absolute path).
fn file_inventory(
    ctx: &WizardCtx,
    ids: &[i64],
    path_files: &[(String, PathBuf)],
) -> Vec<(Area, String, PathBuf)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |area: Area, rel: String, abs: PathBuf| {
        if seen.insert((area, rel.clone())) {
            out.push((area, rel, abs));
        }
    };
    for &id in ids {
        for rel in conventional_staging(&ctx.staging_dir, id) {
            let abs = ctx.staging_dir.join(&rel);
            push(Area::Staging, rel, abs);
        }
        let j = crate::provision_journal::journal_path(&ctx.journal_dir, id);
        push(Area::Journal, format!("{id}.jsonl"), j);
    }
    for (rel, abs) in path_files {
        push(Area::Staging, rel.clone(), abs.clone());
    }
    out
}

/// How strictly to read secrets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretMode {
    /// For a backup: an unreadable live signing key refuses; a locked
    /// or broken key store refuses.
    Strict,
    /// For digests: anything unreadable but a locked store is "missing".
    Lenient,
}

/// Aliases the state references: column values plus the computed
/// Cloudflare alias. `(alias, signing_key_of_live_relay_id)`.
fn referenced_aliases(tables: &BTreeMap<String, TableDump>) -> Vec<(String, Option<i64>)> {
    let mut out: Vec<(String, Option<i64>)> = Vec::new();
    let mut seen = BTreeSet::new();
    let empty = TableDump::default();
    for &(t, c) in ALIAS_COLUMNS {
        let td = tables.get(t).unwrap_or(&empty);
        for r in &td.rows {
            let a = td.get(r, c).as_str().to_string();
            if a.is_empty() {
                continue;
            }
            let live_signing = if t == "operators" && c == "publisher_priv_keystore_alias" {
                let st = td.get(r, "status").as_str();
                if st != "decommissioned" {
                    Some(td.get(r, "id").as_i64())
                } else {
                    None
                }
            } else {
                None
            };
            if seen.insert(a.clone()) {
                out.push((a, live_signing));
            } else if live_signing.is_some() {
                if let Some(e) = out.iter_mut().find(|(x, _)| *x == a) {
                    e.1 = live_signing;
                }
            }
        }
    }
    let ops = tables.get("operators").unwrap_or(&empty);
    for r in &ops.rows {
        let a = crate::commands::cloudflare_alias(ops.get(r, "id").as_i64());
        if seen.insert(a.clone()) {
            out.push((a, None));
        }
    }
    out
}

/// The network-test report aliases every relay in `tables` may have
/// (`crate::report_key`). Not columns: present only once made.
fn report_aliases(tables: &BTreeMap<String, TableDump>) -> Vec<String> {
    let empty = TableDump::default();
    let ops = tables.get("operators").unwrap_or(&empty);
    ops.rows
        .iter()
        .flat_map(|r| {
            let id = ops.get(r, "id").as_i64();
            crate::report_key::optional_aliases(id)
                .into_iter()
                .chain([crate::addon_standby::update_state_alias(id)])
        })
        .collect()
}

/// The account keys a phone may hold apart from any relay (the Accounts
/// page): each hosting company's key, the Cloudflare key with its zone
/// and what it can do beyond the five, and the Google account's write key with its script's
/// address. Not columns, so carried only when present: a phone
/// with no account keeps the same digest (and the same backup) as
/// before they existed, and a backup made before them restores as is.
fn account_aliases() -> Vec<String> {
    let mut out = crate::hosting_account::all_account_aliases();
    out.push(crate::addon_cdn::ACCOUNT_ALIAS.to_string());
    out.push(crate::addon_cdn::ACCOUNT_ZONE_ALIAS.to_string());
    out.push(crate::addon_cdn::ACCOUNT_EXTRA_ALIAS.to_string());
    out.extend(crate::addon_google::ACCOUNT_ALIASES.iter().map(|a| a.to_string()));
    // The update root the people's secrets derive from (no relay of its
    // own). Without it a restore makes a new root and codes go plain.
    out.push(crate::addon_standby::UPDATE_ROOT_ALIAS.to_string());
    out
}

fn collect_state(ctx: &WizardCtx, mode: SecretMode) -> Result<Snapshot> {
    let staging = ctx.staging_dir.clone();
    let (tables, path_files) = ctx
        .db
        .with_conn(|c| dump_tables(c, &staging))
        .map_err(db_err)?;
    let mut snap = Snapshot {
        tables,
        ..Default::default()
    };

    for (alias, live_signing) in referenced_aliases(&snap.tables) {
        match ctx.custody.get(&alias) {
            Ok(v) => snap.secrets.push((alias, Zeroizing::new(v))),
            Err(CustodyError::Locked) => {
                return Err(coded(
                    E_CUSTODY_LOCKED,
                    "unlock this device's key store to continue",
                ))
            }
            Err(CustodyError::NotFound(_)) if live_signing.is_none() => snap.missing.push(alias),
            Err(e) => {
                if mode == SecretMode::Lenient {
                    snap.missing.push(alias);
                } else if let Some(id) = live_signing {
                    let _ = e;
                    return Err(coded(
                        E_BACKUP_SECRET_UNREADABLE,
                        format!("the signing key of relay {id} cannot be read"),
                    ));
                } else if matches!(e, CustodyError::NotFound(_)) {
                    snap.missing.push(alias);
                } else {
                    return Err(coded(E_CUSTODY_BACKEND, e));
                }
            }
        }
    }
    // Network-test report keys and the account keys: in the backup
    // when they exist, and only then, so a publisher who never made one
    // keeps the same digest (and the same backup) as before they existed.
    let optional = snap
        .operator_ids()
        .into_iter()
        .flat_map(|id| {
            crate::report_key::optional_aliases(id)
                .into_iter()
                .chain([crate::addon_standby::update_state_alias(id)])
        })
        .chain(account_aliases())
        .collect::<Vec<_>>();
    for alias in optional {
        if snap.secrets.iter().any(|(a, _)| *a == alias) {
            continue;
        }
        match ctx.custody.get(&alias) {
            Ok(v) => snap.secrets.push((alias, Zeroizing::new(v))),
            Err(CustodyError::NotFound(_)) => {}
            Err(CustodyError::Locked) => {
                return Err(coded(
                    E_CUSTODY_LOCKED,
                    "unlock this device's key store to continue",
                ))
            }
            Err(e) => {
                if mode == SecretMode::Lenient {
                    snap.missing.push(alias);
                } else {
                    return Err(coded(E_CUSTODY_BACKEND, e));
                }
            }
        }
    }
    snap.secrets.sort_by(|a, b| a.0.cmp(&b.0));
    snap.missing.sort();

    let ids = snap.operator_ids();
    for (area, rel, abs) in file_inventory(ctx, &ids, &path_files) {
        match std::fs::read(&abs) {
            Ok(b) => snap.files.push(FileEntry {
                area,
                rel,
                bytes: Zeroizing::new(b),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) if abs.is_dir() => {}
            Err(e) => {
                return Err(coded(
                    E_BACKUP_SAVE_FAILED,
                    format!("cannot read a relay file: {}", e.kind()),
                ))
            }
        }
    }
    snap.files
        .sort_by(|a, b| (a.area, &a.rel).cmp(&(b.area, &b.rel)));
    Ok(snap)
}

#[derive(Serialize)]
struct CanonTable {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

#[derive(Serialize)]
struct Canon {
    tables: BTreeMap<String, CanonTable>,
    secrets: Vec<(String, String)>,
    missing: Vec<String>,
    files: Vec<(String, String, String)>,
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The staleness / replace digest of a snapshot.
fn digest_of(s: &Snapshot) -> String {
    let mut tables = BTreeMap::new();
    for (name, t) in &s.tables {
        if t.rows.is_empty() && later_table_since(name).is_some() {
            continue;
        }
        let keep: Vec<usize> = (0..t.columns.len())
            .filter(|&i| {
                !is_listed(RESET_COLUMNS, name, &t.columns[i])
                    && !is_listed(VOLATILE_COLUMNS, name, &t.columns[i])
            })
            .collect();
        tables.insert(
            name.clone(),
            CanonTable {
                columns: keep.iter().map(|&i| t.columns[i].clone()).collect(),
                rows: t
                    .rows
                    .iter()
                    .map(|r| keep.iter().map(|&i| r[i].to_json()).collect())
                    .collect(),
            },
        );
    }
    let canon = Canon {
        tables,
        secrets: s
            .secrets
            .iter()
            .map(|(a, v)| (a.clone(), sha_hex(v)))
            .collect(),
        missing: s.missing.clone(),
        files: s
            .files
            .iter()
            .map(|f| {
                (
                    f.area.as_str().to_string(),
                    f.rel.clone(),
                    sha_hex(&f.bytes),
                )
            })
            .collect(),
    };
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(serde_json::to_vec(&canon).unwrap_or_default());
    hex::encode(h.finalize())
}

/// The digest of this phone's publisher state right now.
pub fn state_digest(ctx: &WizardCtx) -> Result<String> {
    Ok(digest_of(&collect_state(ctx, SecretMode::Lenient)?))
}

fn payload_bytes(s: &Snapshot, created_at: i64) -> Zeroizing<Vec<u8>> {
    let mut tables = serde_json::Map::new();
    for &t in INCLUDED_TABLES {
        let td = s.table(t);
        tables.insert(
            t.to_string(),
            json!({
                "columns": td.columns,
                "rows": td.rows.iter().map(|r| r.iter().map(Cell::to_json).collect::<Vec<_>>()).collect::<Vec<_>>(),
            }),
        );
    }
    let secrets: Vec<Value> = s
        .secrets
        .iter()
        .map(|(a, v)| json!({ "alias": a, "b64": B64.encode(&v[..]) }))
        .collect();
    let files: Vec<Value> = s
        .files
        .iter()
        .map(|f| json!({ "area": f.area.as_str(), "rel": f.rel, "b64": B64.encode(&f.bytes[..]) }))
        .collect();
    let doc = json!({
        "kind": PAYLOAD_KIND,
        "payload_version": PAYLOAD_VERSION,
        "created_at_unix": created_at,
        "app_version": APP_VERSION,
        "db_schema_version": crate::operator_db::current_schema_version(),
        "tables": tables,
        "secrets": secrets,
        "missing_secrets": s.missing,
        "files": files,
    });
    Zeroizing::new(serde_json::to_vec(&doc).unwrap_or_default())
}

// ---------------------------------------------------------------------
// Payload validation (restore side)
// ---------------------------------------------------------------------

fn damaged(why: impl std::fmt::Display) -> WizardError {
    coded(E_BACKUP_DAMAGED, why)
}

struct Parsed {
    created_at: i64,
    app_version: String,
    snap: Snapshot,
}

/// A future data-rewriting migration adds a step here that turns an
/// older payload's tables into the current shape. v1 has none: no
/// backup older than V017 can exist, and V018 added only a table a
/// backup never carries.
fn upgrade_payload(from: i64, _tables: &mut BTreeMap<String, TableDump>) -> Result<()> {
    let _ = from;
    Ok(())
}

fn sanitize_alias(a: &str) -> String {
    a.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn alias_forbidden(a: &str, recipient_aliases: &BTreeSet<String>) -> bool {
    let s = sanitize_alias(a);
    a.is_empty()
        || a.len() > 200
        || FORBIDDEN_ALIAS_PREFIXES
            .iter()
            .any(|p| s.starts_with(&sanitize_alias(p)))
        || recipient_aliases.iter().any(|r| sanitize_alias(r) == s)
}

fn recipient_aliases(conn: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for t in ["recipient_identity", "recipient_identity_history"] {
        let mut stmt = conn.prepare(&format!("SELECT keystore_alias FROM \"{t}\""))?;
        for a in stmt.query_map([], |r| r.get::<_, String>(0))? {
            out.insert(a?);
        }
    }
    Ok(out)
}

fn parse_cell(v: &Value, is_path: bool) -> Result<Cell> {
    Ok(match v {
        Value::Null => Cell::Null,
        Value::String(s) => Cell::Text(s.clone()),
        Value::Number(n) => Cell::Int(
            n.as_i64()
                .ok_or_else(|| damaged("a number is not an integer"))?,
        ),
        Value::Object(o) if o.len() == 1 => {
            if let Some(Value::String(b)) = o.get("b64") {
                Cell::Blob(
                    B64.decode(b)
                        .map_err(|_| damaged("a value is not base64"))?,
                )
            } else if let Some(Value::String(r)) = o.get("staging_rel") {
                if !is_path || !valid_rel(r) {
                    return Err(damaged("a file path is not valid"));
                }
                Cell::Path(r.clone())
            } else if let Some(f) = o.get("real").and_then(Value::as_f64) {
                Cell::Real(f)
            } else {
                return Err(damaged("a value has an unknown shape"));
            }
        }
        _ => return Err(damaged("a value has an unknown shape")),
    })
}

fn parse_payload(ctx: &WizardCtx, pt: &[u8]) -> Result<Parsed> {
    let doc: Value =
        serde_json::from_slice(pt).map_err(|_| damaged("the contents are not readable"))?;
    let o = doc
        .as_object()
        .ok_or_else(|| damaged("the contents are not readable"))?;
    if o.get("kind").and_then(Value::as_str) != Some(PAYLOAD_KIND) {
        return Err(damaged("the contents are not a publisher backup"));
    }
    match o.get("payload_version").and_then(Value::as_i64) {
        Some(PAYLOAD_VERSION) => {}
        Some(v) => return Err(coded(E_BACKUP_NEWER, format!("contents version {v}"))),
        None => return Err(damaged("the contents have no version")),
    }
    let schema = o
        .get("db_schema_version")
        .and_then(Value::as_i64)
        .ok_or_else(|| damaged("the contents have no database version"))?;
    let current = crate::operator_db::current_schema_version();
    if schema > current {
        return Err(coded(E_BACKUP_NEWER, format!("database version {schema}")));
    }
    let created_at = o
        .get("created_at_unix")
        .and_then(Value::as_i64)
        .ok_or_else(|| damaged("the contents have no date"))?;
    let app_version = o
        .get("app_version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let (db_tables, db_cols, rec_aliases) = ctx
        .db
        .with_conn(|c| -> rusqlite::Result<_> {
            let names = all_tables(c)?;
            let mut cols = BTreeMap::new();
            for n in &names {
                cols.insert(n.clone(), table_columns(c, n)?);
            }
            Ok((names, cols, recipient_aliases(c)?))
        })
        .map_err(db_err)?;

    let tables_v = o
        .get("tables")
        .and_then(Value::as_object)
        .ok_or_else(|| damaged("the contents have no tables"))?;
    let mut tables = BTreeMap::new();
    for (name, tv) in tables_v {
        if !db_tables.contains(name) {
            return Err(coded(E_BACKUP_NEWER, "a table this version does not have"));
        }
        if !INCLUDED_TABLES.contains(&name.as_str()) {
            return Err(damaged("a table a backup never carries"));
        }
        let cols: Vec<String> = tv
            .get("columns")
            .and_then(Value::as_array)
            .ok_or_else(|| damaged("a table has no columns"))?
            .iter()
            .map(|c| {
                c.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| damaged("a column name is not text"))
            })
            .collect::<Result<_>>()?;
        let have = &db_cols[name];
        let mut uniq = BTreeSet::new();
        for c in &cols {
            if !have.contains(c) {
                return Err(coded(E_BACKUP_NEWER, "a column this version does not have"));
            }
            if !uniq.insert(c.clone()) {
                return Err(damaged("a column appears twice"));
            }
        }
        let mut rows = Vec::new();
        for rv in tv
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| damaged("a table has no rows"))?
        {
            let ra = rv
                .as_array()
                .ok_or_else(|| damaged("a row is not a list"))?;
            if ra.len() != cols.len() {
                return Err(damaged("a row has the wrong length"));
            }
            let row = ra
                .iter()
                .zip(&cols)
                .map(|(v, c)| parse_cell(v, is_listed(PATH_COLUMNS, name, c)))
                .collect::<Result<Vec<_>>>()?;
            rows.push(row);
        }
        tables.insert(
            name.clone(),
            TableDump {
                columns: cols,
                rows,
            },
        );
    }
    for &t in INCLUDED_TABLES {
        if !tables.contains_key(t) {
            // A table this backup is older than is not missing: it did
            // not exist yet, and restores as empty.
            match later_table_since(t) {
                Some(since) if schema < since => continue,
                _ => return Err(damaged("a table is missing")),
            }
        }
    }
    if schema < current {
        upgrade_payload(schema, &mut tables)?;
    }

    // Aliases: every column value and every secret must be a publisher
    // alias, and every secret must be referenced by the rows.
    let referenced = referenced_aliases(&tables);
    // A relay's network-test report keys may be there too (only when
    // they were made; see collect_state). So may the account keys (only when this phone had them).
    let optional: Vec<String> = report_aliases(&tables)
        .into_iter()
        .chain(account_aliases())
        .collect();
    let mut referenced_set: BTreeSet<&str> = referenced.iter().map(|(a, _)| a.as_str()).collect();
    referenced_set.extend(optional.iter().map(String::as_str));
    for (a, _) in &referenced {
        if alias_forbidden(a, &rec_aliases) {
            return Err(damaged("the contents name a key a backup may not hold"));
        }
    }
    let mut secrets = Vec::new();
    let mut seen = BTreeSet::new();
    for sv in o
        .get("secrets")
        .and_then(Value::as_array)
        .ok_or_else(|| damaged("no key list"))?
    {
        let alias = sv
            .get("alias")
            .and_then(Value::as_str)
            .ok_or_else(|| damaged("a key has no name"))?
            .to_string();
        if !referenced_set.contains(alias.as_str()) || alias_forbidden(&alias, &rec_aliases) {
            return Err(damaged("the contents hold a key a backup may not hold"));
        }
        if !seen.insert(alias.clone()) {
            return Err(damaged("a key appears twice"));
        }
        let b64 = Zeroizing::new(
            sv.get("b64")
                .and_then(Value::as_str)
                .ok_or_else(|| damaged("a key has no value"))?
                .to_string(),
        );
        let v = Zeroizing::new(
            B64.decode(b64.as_bytes())
                .map_err(|_| damaged("a key is not base64"))?,
        );
        secrets.push((alias, v));
    }
    secrets.sort_by(|a, b| a.0.cmp(&b.0));
    let missing: Vec<String> = o
        .get("missing_secrets")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mut files = Vec::new();
    let mut seen_f = BTreeSet::new();
    for fv in o
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| damaged("no file list"))?
    {
        let area = fv
            .get("area")
            .and_then(Value::as_str)
            .and_then(Area::parse)
            .ok_or_else(|| damaged("a file has an unknown place"))?;
        let rel = fv
            .get("rel")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !valid_rel(&rel) {
            return Err(damaged("a file name is not valid"));
        }
        if area == Area::Journal
            && !(rel.ends_with(".jsonl")
                && !rel.contains('/')
                && rel.trim_end_matches(".jsonl").parse::<i64>().is_ok())
        {
            return Err(damaged("a setup journal name is not valid"));
        }
        if !seen_f.insert((area, rel.clone())) {
            return Err(damaged("a file appears twice"));
        }
        let b = fv
            .get("b64")
            .and_then(Value::as_str)
            .ok_or_else(|| damaged("a file has no contents"))?;
        let bytes = Zeroizing::new(B64.decode(b).map_err(|_| damaged("a file is not base64"))?);
        files.push(FileEntry { area, rel, bytes });
    }
    files.sort_by(|a, b| (a.area, &a.rel).cmp(&(b.area, &b.rel)));

    let snap = Snapshot {
        tables,
        secrets,
        missing,
        files,
    };

    // Every live relay's signing key is there and matches its public key.
    let ops = snap.table("operators");
    for r in &ops.rows {
        let alias = ops.get(r, "publisher_priv_keystore_alias").as_str();
        if alias.is_empty() {
            continue;
        }
        let live = ops.get(r, "status").as_str() != "decommissioned";
        match snap.secret(alias) {
            Some(k) => {
                let key = crate::publisher_key::import(k)
                    .map_err(|_| damaged("a signing key is not valid"))?;
                let want = ops
                    .get(r, "publisher_pub_hex")
                    .as_str()
                    .to_ascii_lowercase();
                if hex::encode(key.pub_bytes) != want {
                    return Err(damaged("a signing key does not match its relay"));
                }
            }
            None if live => return Err(damaged("a relay's signing key is missing")),
            None => {}
        }
    }

    // A dry run of the commit, rolled back: whatever the database would
    // refuse is refused now, before anything is written.
    let staging = ctx.staging_dir.clone();
    ctx.db
        .with_conn(|c| -> rusqlite::Result<()> {
            let tx = c.transaction()?;
            replace_tables(&tx, &snap, &staging)?;
            tx.rollback()
        })
        .map_err(commit_err)?;

    Ok(Parsed {
        created_at,
        app_version,
        snap,
    })
}

/// A database refusal of the backup's own rows (a constraint, a type)
/// means the contents do not fit together; anything else (disk full,
/// busy, I/O) is this phone's database failing, and says so.
fn commit_err(e: rusqlite::Error) -> WizardError {
    use rusqlite::ffi::ErrorCode;
    match &e {
        rusqlite::Error::SqliteFailure(f, _)
            if matches!(f.code, ErrorCode::ConstraintViolation | ErrorCode::TypeMismatch) =>
        {
            damaged("the contents do not fit together")
        }
        rusqlite::Error::SqliteFailure(f, _) => coded(
            E_RESTORE_FAILED,
            format!("this phone's database refused the write: {:?}", f.code),
        ),
        rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::InvalidParameterCount(..)
        | rusqlite::Error::InvalidColumnName(..) => damaged("the contents do not fit together"),
        _ => coded(E_RESTORE_FAILED, "this phone's database refused the write"),
    }
}

/// Delete every INCLUDED row and insert the snapshot's, rewriting path
/// columns to this phone's staging dir and resetting old-phone columns.
fn replace_tables(
    tx: &rusqlite::Transaction<'_>,
    s: &Snapshot,
    staging: &Path,
) -> rusqlite::Result<()> {
    for &t in INCLUDED_TABLES.iter().rev() {
        tx.execute(&format!("DELETE FROM \"{t}\""), [])?;
    }
    for &t in INCLUDED_TABLES {
        let td = s.table(t);
        if td.columns.is_empty() {
            continue;
        }
        let cols = td
            .columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let qs = (1..=td.columns.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut stmt = tx.prepare(&format!("INSERT INTO \"{t}\" ({cols}) VALUES ({qs})"))?;
        for r in &td.rows {
            let vals: Vec<SqlValue> = r
                .iter()
                .map(|c| match c {
                    Cell::Null => SqlValue::Null,
                    Cell::Int(i) => SqlValue::Integer(*i),
                    Cell::Real(f) => SqlValue::Real(*f),
                    Cell::Text(s) => SqlValue::Text(s.clone()),
                    Cell::Blob(b) => SqlValue::Blob(b.clone()),
                    Cell::Path(rel) => {
                        SqlValue::Text(staging.join(rel).to_string_lossy().to_string())
                    }
                })
                .collect();
            stmt.execute(rusqlite::params_from_iter(vals))?;
        }
    }
    tx.execute(
        "UPDATE operators SET helper_ip = '', helper_ip_source = '', helper_ip_at_unix = 0,
                              last_health_json = '', last_health_at_unix = 0",
        [],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------
// Meta (V017, per device)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Meta {
    last_backup_at_unix: i64,
    last_backup_digest: String,
    restore_pending_nonce: String,
    restored_at_unix: i64,
    restored_backup_made_at_unix: i64,
    restore_notice_dismissed: bool,
    words_changed_at_unix: i64,
    share_unconfirmed_at_unix: i64,
    share_unconfirmed_digest: String,
}

fn read_meta(ctx: &WizardCtx) -> Result<Meta> {
    ctx.db
        .with_conn(|c| {
            c.query_row(
                "SELECT last_backup_at_unix, last_backup_digest, restore_pending_nonce,
                        restored_at_unix, restored_backup_made_at_unix, restore_notice_dismissed,
                        words_changed_at_unix, share_unconfirmed_at_unix, share_unconfirmed_digest
                 FROM publisher_backup_meta WHERE id = 1",
                [],
                |r| {
                    Ok(Meta {
                        last_backup_at_unix: r.get(0)?,
                        last_backup_digest: r.get(1)?,
                        restore_pending_nonce: r.get(2)?,
                        restored_at_unix: r.get(3)?,
                        restored_backup_made_at_unix: r.get(4)?,
                        restore_notice_dismissed: r.get::<_, i64>(5)? != 0,
                        words_changed_at_unix: r.get(6)?,
                        share_unconfirmed_at_unix: r.get(7)?,
                        share_unconfirmed_digest: r.get(8)?,
                    })
                },
            )
        })
        .map_err(db_err)
}

// ---------------------------------------------------------------------
// What the screens show
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RelayLine {
    pub id: i64,
    pub nickname: String,
    pub public_ip: String,
    pub status: String,
    pub provider: String,
    pub people: i64,
    pub removed_people: i64,
    pub has_hosting_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackupContents {
    pub relays: Vec<RelayLine>,
    pub people_total: i64,
    pub files: i64,
    pub includes_hosting_key: bool,
    pub unfinished_setups: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RestoreNotice {
    pub restored_at_unix: i64,
    pub backup_made_at_unix: i64,
    pub relays: Vec<RelayLine>,
    pub has_refresh_keys: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackupStatus {
    pub has_publisher_data: bool,
    pub words_set: bool,
    pub last_backup_at_unix: i64,
    pub stale: bool,
    pub contents: BackupContents,
    /// `''` | `setup_running` | `secret_unreadable` | `custody_locked` |
    /// `legacy_pending` | `custody_backend`.
    pub blocked: String,
    /// Raw text for a Details fold only.
    pub blocked_detail: String,
    pub restore_pending: bool,
    pub restore_notice: Option<RestoreNotice>,
    /// New recovery words were made and never confirmed: backups still
    /// use the confirmed (old) words.
    #[serde(default)]
    pub words_pending: bool,
    /// New words were confirmed after the last backup: that file opens
    /// only with the old words. Implies `stale`.
    #[serde(default)]
    pub words_changed: bool,
    /// A backup was handed to another app and the person has not said
    /// it arrived (0 = none waiting). It is not the last backup yet.
    #[serde(default)]
    pub share_unconfirmed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ExistingData {
    pub relays: Vec<RelayLine>,
    pub people_total: i64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackupInspect {
    pub existing: Option<ExistingData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ReplaceInfo {
    pub this_phone: Vec<RelayLine>,
    pub only_on_this_phone: Vec<RelayLine>,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackupPreview {
    pub made_at_unix: i64,
    pub app_version: String,
    pub contents: BackupContents,
    pub replace: Option<ReplaceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RestoreResult {
    pub contents: BackupContents,
    pub notice: RestoreNotice,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WordsNew {
    pub words: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WordAnswer {
    pub index: u32,
    pub word: String,
}

/// What `publisher_backup_make` reports once the file was handed over.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MadeBackup {
    pub file_name: String,
    pub made_at_unix: i64,
    pub contents: BackupContents,
    /// `downloads` | `share`.
    pub destination: String,
    /// Saved to Downloads: recorded as the last backup. Handed to
    /// another app: waits for [`backup_confirm_shared`].
    #[serde(default)]
    pub confirmed: bool,
}

/// A backup file written and not yet handed over.
#[derive(Debug, Clone)]
pub struct MadeBackupFile {
    pub path: PathBuf,
    pub file_name: String,
    pub made_at_unix: i64,
    pub contents: BackupContents,
    digest: String,
}

fn relay_lines(s: &Snapshot) -> Vec<RelayLine> {
    let ops = s.table("operators");
    let rec = s.table("recipients");
    ops.rows
        .iter()
        .map(|r| {
            let id = ops.get(r, "id").as_i64();
            let record: Value = serde_json::from_str(ops.get(r, "operator_record_json").as_str())
                .unwrap_or(Value::Null);
            let mut people = 0;
            let mut removed = 0;
            for p in &rec.rows {
                if rec.get(p, "operator_id").as_i64() == id {
                    if rec.get(p, "revoked_at_unix").as_i64() == 0 {
                        people += 1;
                    } else {
                        removed += 1;
                    }
                }
            }
            let token_alias = ops.get(r, "cloud_token_keystore_alias").as_str();
            // The column is what every key and account call uses; the
            // record's copy is only a fallback for an old row.
            let col = ops.get(r, "cloud_provider").as_str();
            let provider = if !col.is_empty() {
                col.to_string()
            } else {
                record
                    .get("provider")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            RelayLine {
                id,
                nickname: ops.get(r, "nickname").as_str().to_string(),
                public_ip: record
                    .get("public_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                status: ops.get(r, "status").as_str().to_string(),
                provider,
                people,
                removed_people: removed,
                has_hosting_key: !token_alias.is_empty() && s.secret(token_alias).is_some(),
            }
        })
        .collect()
}

fn contents_of(s: &Snapshot) -> BackupContents {
    let relays = relay_lines(s);
    let ops = s.table("operators");
    let journals: BTreeSet<&str> = s
        .files
        .iter()
        .filter(|f| f.area == Area::Journal)
        .map(|f| f.rel.as_str())
        .collect();
    let unfinished = ops
        .rows
        .iter()
        .filter(|r| {
            ops.get(r, "status").as_str() == "pre-provision"
                && journals.contains(format!("{}.jsonl", ops.get(r, "id").as_i64()).as_str())
        })
        .count() as i64;
    BackupContents {
        people_total: relays.iter().map(|r| r.people).sum(),
        includes_hosting_key: relays.iter().any(|r| r.has_hosting_key)
            || crate::hosting_account::all_account_aliases()
                .iter()
                .any(|a| s.secret(a).is_some()),
        files: s.files.len() as i64,
        unfinished_setups: unfinished,
        relays,
    }
}

fn has_refresh_keys(s: &Snapshot) -> bool {
    let f = s.table("freshness_endpoints");
    f.rows
        .iter()
        .any(|r| !f.get(r, "secret_alias").as_str().is_empty())
}

fn any_journal_locked(ctx: &WizardCtx) -> bool {
    let Ok(rd) = std::fs::read_dir(&ctx.journal_dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        e.file_name().to_string_lossy().ends_with(".jsonl")
            && crate::provision_journal::is_locked(&e.path())
    })
}

fn setup_running_err() -> WizardError {
    coded(
        E_SETUP_RUNNING,
        "a setup is still running; wait for it to finish, then try again",
    )
}

fn now(ctx: &WizardCtx) -> i64 {
    (ctx.clock)()
}

fn custody_err(e: CustodyError) -> WizardError {
    match e {
        CustodyError::Locked => coded(
            E_CUSTODY_LOCKED,
            "unlock this device's key store to continue",
        ),
        other => coded(E_CUSTODY_BACKEND, other),
    }
}

fn read_entropy(ctx: &WizardCtx, alias: &str) -> Result<Option<Zeroizing<[u8; 16]>>> {
    match ctx.custody.get(alias) {
        Ok(v) => {
            let v = Zeroizing::new(v);
            if v.len() != 16 {
                return Err(coded(
                    E_CUSTODY_BACKEND,
                    "stored recovery words are not valid",
                ));
            }
            let mut e = Zeroizing::new([0u8; 16]);
            e.copy_from_slice(&v);
            Ok(Some(e))
        }
        Err(CustodyError::NotFound(_)) => Ok(None),
        Err(e) => Err(custody_err(e)),
    }
}

fn code_of(e: &WizardError) -> String {
    let s = e.to_string();
    s.split(':').next().unwrap_or("").to_string()
}

// ---------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------

/// `publisher_backup_status`.
pub fn backup_status(ctx: &WizardCtx) -> Result<BackupStatus> {
    let finish = finish_pending_restore(ctx);
    let meta = read_meta(ctx)?;
    let mut st = BackupStatus {
        last_backup_at_unix: meta.last_backup_at_unix,
        restore_pending: !meta.restore_pending_nonce.is_empty(),
        words_changed: meta.last_backup_at_unix > 0 && meta.words_changed_at_unix > 0,
        share_unconfirmed_at_unix: meta.share_unconfirmed_at_unix,
        ..Default::default()
    };
    if let Err(e) = &finish {
        st.blocked_detail = e.to_string();
    }
    let block = |st: &mut BackupStatus, b: &str, d: String| {
        if st.blocked.is_empty() {
            st.blocked = b.to_string();
            st.blocked_detail = d;
        }
    };
    let staging = ctx.staging_dir.clone();
    let (tables, _) = ctx
        .db
        .with_conn(|c| dump_tables(c, &staging))
        .map_err(db_err)?;
    st.has_publisher_data = !tables
        .get("operators")
        .map(|t| t.rows.is_empty())
        .unwrap_or(true);

    let custody = crate::commands::custody_status(ctx)?;
    if custody.legacy_pending {
        block(&mut st, "legacy_pending", String::new());
    } else if !custody.ok {
        let b = if custody.error.starts_with(E_CUSTODY_LOCKED) {
            "custody_locked"
        } else {
            "custody_backend"
        };
        block(&mut st, b, custody.error.clone());
    }
    if st.blocked.is_empty() {
        st.words_set = matches!(read_entropy(ctx, WORDS_ALIAS), Ok(Some(_)));
        st.words_pending = matches!(read_entropy(ctx, WORDS_PENDING_ALIAS), Ok(Some(_)));
    }
    if any_journal_locked(ctx) {
        block(&mut st, "setup_running", String::new());
    }

    let snap = if st.blocked.is_empty() || st.blocked == "setup_running" {
        match collect_state(ctx, SecretMode::Strict) {
            Ok(s) => Some(s),
            Err(e) => {
                let b = match code_of(&e).as_str() {
                    E_BACKUP_SECRET_UNREADABLE => "secret_unreadable",
                    E_CUSTODY_LOCKED => "custody_locked",
                    _ => "custody_backend",
                };
                block(&mut st, b, e.to_string());
                None
            }
        }
    } else {
        None
    };
    match snap {
        Some(s) => {
            st.contents = contents_of(&s);
            st.stale = meta.last_backup_at_unix > 0
                && (st.words_changed || digest_of(&s) != meta.last_backup_digest);
            if meta.restored_at_unix > 0 && !meta.restore_notice_dismissed {
                st.restore_notice = Some(RestoreNotice {
                    restored_at_unix: meta.restored_at_unix,
                    backup_made_at_unix: meta.restored_backup_made_at_unix,
                    relays: relay_lines(&s),
                    has_refresh_keys: has_refresh_keys(&s),
                });
            }
        }
        None => {
            // Without the keys: what the rows say, so the screen can
            // still name the relays.
            let s = Snapshot {
                tables,
                ..Default::default()
            };
            st.contents = contents_of(&s);
            if meta.restored_at_unix > 0 && !meta.restore_notice_dismissed {
                st.restore_notice = Some(RestoreNotice {
                    restored_at_unix: meta.restored_at_unix,
                    backup_made_at_unix: meta.restored_backup_made_at_unix,
                    relays: relay_lines(&s),
                    has_refresh_keys: has_refresh_keys(&s),
                });
            }
        }
    }
    Ok(st)
}

/// `publisher_backup_words_new`: twelve new words, kept as pending
/// until confirmed (replacing any earlier pending words).
pub fn words_new(ctx: &WizardCtx) -> Result<WordsNew> {
    let mut e = Zeroizing::new([0u8; 16]);
    OsRng.fill_bytes(&mut e[..]);
    ctx.custody
        .put(WORDS_PENDING_ALIAS, &e[..])
        .map_err(custody_err)?;
    Ok(WordsNew {
        words: words_from_entropy(&e)
            .into_iter()
            .map(str::to_string)
            .collect(),
    })
}

/// `publisher_backup_words_confirm`: at least three distinct positions
/// typed back correctly move the pending words to the confirmed slot.
pub fn words_confirm(ctx: &WizardCtx, answers: &[WordAnswer]) -> Result<()> {
    let distinct: BTreeSet<u32> = answers.iter().map(|a| a.index).collect();
    if distinct.len() < 3 || answers.iter().any(|a| a.index >= 12) {
        return Err(WizardError::Validation(
            "type back at least three different words".into(),
        ));
    }
    let Some(pending) = read_entropy(ctx, WORDS_PENDING_ALIAS)? else {
        return Err(coded(
            E_BACKUP_NO_WORDS,
            "no new recovery words are waiting to be confirmed",
        ));
    };
    let list = wordlist();
    let words = words_from_entropy(&pending);
    for a in answers {
        let runs = typed_runs(&a.word);
        let ok = runs.len() == 1
            && resolve_word(&runs[0]).map(|i| list[i as usize]) == Some(words[a.index as usize]);
        if !ok {
            return Err(coded(
                E_BACKUP_WORDS_MISMATCH,
                format!("word number {} does not match", a.index + 1),
            ));
        }
    }
    // Replacing confirmed words: every backup made so far opens only
    // with the old ones, so it stops counting as current, and a file
    // handed to another app under the old words is no longer waiting
    // to be confirmed. Recorded before the words change, so a kill in
    // between errs on "out of date".
    let replacing = match read_entropy(ctx, WORDS_ALIAS)? {
        Some(old) => !bool::from(old[..].ct_eq(&pending[..])),
        None => false,
    };
    if replacing {
        let at = now(ctx).max(1);
        ctx.db
            .with_conn(|c| {
                c.execute(
                    "UPDATE publisher_backup_meta SET words_changed_at_unix = ?1,
                            share_unconfirmed_at_unix = 0, share_unconfirmed_digest = ''
                     WHERE id = 1",
                    params![at],
                )
            })
            .map_err(db_err)?;
    }
    ctx.custody
        .put(WORDS_ALIAS, &pending[..])
        .map_err(custody_err)?;
    let _ = ctx.custody.forget(WORDS_PENDING_ALIAS);
    Ok(())
}

/// `publisher_backup_words_check`: are these the stored words?
pub fn words_check(ctx: &WizardCtx, words: &str) -> Result<bool> {
    let Some(stored) = read_entropy(ctx, WORDS_ALIAS)? else {
        return Err(coded(E_BACKUP_NO_WORDS, "no recovery words on this phone"));
    };
    Ok(match parse_words(words) {
        Ok(e) => bool::from(e[..].ct_eq(&stored[..])),
        Err(_) => false,
    })
}

fn default_file_name(at: i64) -> String {
    let d =
        time::OffsetDateTime::from_unix_timestamp(at).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    // Hour and minute too: a second backup the same day gets its own
    // name, so "Saved as {file}" names the file just made and never an
    // older one beside it.
    format!(
        "daal-backup-{:04}-{:02}-{:02}-{:02}{:02}.daalbackup",
        d.year(),
        u8::from(d.month()),
        d.day(),
        d.hour(),
        d.minute()
    )
}

fn clean_file_name(name: Option<&str>, at: i64) -> String {
    let n = name.map(safe_component).unwrap_or_default();
    if n.is_empty() || n == "file" {
        return default_file_name(at);
    }
    if n.ends_with(".daalbackup") {
        n
    } else {
        format!("{n}.daalbackup")
    }
}

/// Write `bytes` durably with mode 0600: tmp, fsync, rename, fsync dir.
fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default()
    ));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Backup files handed to another app are kept for it to read; sweep
/// the ones older than a day.
fn sweep_backup_out(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let day = std::time::Duration::from_secs(24 * 3600);
    for e in rd.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|age| age > day)
            .unwrap_or(false);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

pub fn backup_out_dir(ctx: &WizardCtx) -> PathBuf {
    ctx.staging_dir.join("backup-out")
}

/// First half of `publisher_backup_make`: build, encrypt in memory and
/// write only the ciphertext to `<staging>/backup-out/<name>`. Nothing
/// is recorded until [`backup_mark_made`] after the hand-over worked.
pub fn backup_make_file(ctx: &WizardCtx, file_name: Option<&str>) -> Result<MadeBackupFile> {
    ensure_restore_finished(ctx)?;
    let custody = crate::commands::custody_status(ctx)?;
    if custody.legacy_pending {
        return Err(coded(
            E_LEGACY_PIN_REQUIRED,
            "keys are still sealed under the old PIN",
        ));
    }
    if !custody.ok {
        return Err(WizardError::Coded(custody.error));
    }
    if any_journal_locked(ctx) {
        return Err(setup_running_err());
    }
    let snap = collect_state(ctx, SecretMode::Strict)?;
    if snap.table("operators").rows.is_empty() {
        return Err(coded(
            E_BACKUP_NOTHING,
            "this phone has no relays to back up",
        ));
    }
    let Some(entropy) = read_entropy(ctx, WORDS_ALIAS)? else {
        return Err(coded(E_BACKUP_NO_WORDS, "create the recovery words first"));
    };
    let at = now(ctx);
    let payload = payload_bytes(&snap, at);
    if payload.len() as u64 + 16 > MAX_CIPHERTEXT {
        return Err(coded(E_BACKUP_SAVE_FAILED, "the backup would be too large"));
    }
    let file = seal(&entropy, &payload, make_params())?;
    drop(payload);
    let dir = backup_out_dir(ctx);
    sweep_backup_out(&dir);
    let name = clean_file_name(file_name, at);
    let path = dir.join(&name);
    write_durably(&path, &file).map_err(|e| {
        coded(
            E_BACKUP_SAVE_FAILED,
            format!("cannot write the backup: {}", e.kind()),
        )
    })?;
    Ok(MadeBackupFile {
        path,
        file_name: name,
        made_at_unix: at,
        contents: contents_of(&snap),
        digest: digest_of(&snap),
    })
}

/// Second half: the file reached Downloads. It is made under the
/// current words, so any earlier words change is settled.
pub fn backup_mark_made(ctx: &WizardCtx, made: &MadeBackupFile) -> Result<()> {
    record_last_backup(ctx, made.made_at_unix, &made.digest)
}

fn record_last_backup(ctx: &WizardCtx, at: i64, digest: &str) -> Result<()> {
    ctx.db
        .with_conn(|c| {
            c.execute(
                "UPDATE publisher_backup_meta SET last_backup_at_unix = ?1, last_backup_digest = ?2,
                        words_changed_at_unix = 0,
                        share_unconfirmed_at_unix = 0, share_unconfirmed_digest = ''
                 WHERE id = 1",
                params![at, digest],
            )
        })
        .map_err(db_err)?;
    Ok(())
}

/// The file was handed to another app. A share chooser that opened
/// proves nothing (the person may close it, the app may drop the file),
/// so it is held as "waiting" until the person says it arrived.
pub fn backup_note_shared(ctx: &WizardCtx, made: &MadeBackupFile) -> Result<()> {
    ctx.db
        .with_conn(|c| {
            c.execute(
                "UPDATE publisher_backup_meta SET share_unconfirmed_at_unix = ?1,
                        share_unconfirmed_digest = ?2 WHERE id = 1",
                params![made.made_at_unix.max(1), made.digest],
            )
        })
        .map_err(db_err)?;
    Ok(())
}

/// `publisher_backup_confirm_shared`: the person says whether the file
/// handed to another app arrived. Yes makes it the last backup; no
/// forgets it. Returns whether a backup was recorded.
pub fn backup_confirm_shared(ctx: &WizardCtx, arrived: bool) -> Result<bool> {
    let meta = read_meta(ctx)?;
    if meta.share_unconfirmed_at_unix <= 0 {
        return Ok(false);
    }
    if arrived {
        record_last_backup(
            ctx,
            meta.share_unconfirmed_at_unix,
            &meta.share_unconfirmed_digest,
        )?;
        return Ok(true);
    }
    ctx.db
        .with_conn(|c| {
            c.execute(
                "UPDATE publisher_backup_meta SET share_unconfirmed_at_unix = 0,
                        share_unconfirmed_digest = '' WHERE id = 1",
                [],
            )
        })
        .map_err(db_err)?;
    Ok(false)
}

fn existing(ctx: &WizardCtx) -> Result<Option<(Snapshot, String)>> {
    let snap = collect_state(ctx, SecretMode::Lenient)?;
    if snap.table("operators").rows.is_empty() {
        return Ok(None);
    }
    let d = digest_of(&snap);
    Ok(Some((snap, d)))
}

/// `publisher_backup_inspect`: the header only, and this phone's data.
pub fn backup_inspect(ctx: &WizardCtx, path: &Path) -> Result<BackupInspect> {
    let bytes = read_backup_file(path)?;
    parse_header(&bytes)?;
    let existing = existing(ctx)?.map(|(s, digest)| {
        let relays = relay_lines(&s);
        ExistingData {
            people_total: relays.iter().map(|r| r.people).sum(),
            relays,
            digest,
        }
    });
    Ok(BackupInspect { existing })
}

fn open_parsed(ctx: &WizardCtx, path: &Path, words: &str) -> Result<Parsed> {
    let bytes = read_backup_file(path)?;
    let pt = decrypt(&bytes, words)?;
    parse_payload(ctx, &pt)
}

fn replace_info(ctx: &WizardCtx, backup: &Snapshot) -> Result<Option<ReplaceInfo>> {
    let Some((cur, digest)) = existing(ctx)? else {
        return Ok(None);
    };
    let bops = backup.table("operators");
    let backup_keys: BTreeSet<String> = bops
        .rows
        .iter()
        .map(|r| {
            bops.get(r, "publisher_pub_hex")
                .as_str()
                .to_ascii_lowercase()
        })
        .collect();
    let cops = cur.table("operators");
    let this_phone = relay_lines(&cur);
    let only = this_phone
        .iter()
        .zip(&cops.rows)
        .filter(|(_, r)| {
            let k = cops
                .get(r, "publisher_pub_hex")
                .as_str()
                .to_ascii_lowercase();
            k.is_empty() || !backup_keys.contains(&k)
        })
        .map(|(l, _)| l.clone())
        .collect();
    Ok(Some(ReplaceInfo {
        this_phone,
        only_on_this_phone: only,
        digest,
    }))
}

/// `publisher_backup_open`: decrypt and validate; writes nothing.
pub fn backup_open(ctx: &WizardCtx, path: &Path, words: &str) -> Result<BackupPreview> {
    let p = open_parsed(ctx, path, words)?;
    Ok(BackupPreview {
        made_at_unix: p.created_at,
        app_version: p.app_version.clone(),
        contents: contents_of(&p.snap),
        replace: replace_info(ctx, &p.snap)?,
    })
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreFault {
    BeforeCommit,
    AfterCommit,
    AfterNPuts(usize),
    /// The commit transaction fails as a full disk would.
    CommitError,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Option<RestoreFault>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_fault(f: Option<RestoreFault>) {
    FAULT.with(|c| c.set(f));
}

/// A simulated kill at `at`. Consumed when it fires.
#[allow(unused_variables)]
fn fault(at: &str, puts: usize) -> bool {
    #[cfg(test)]
    {
        let hit = FAULT.with(|c| match c.get() {
            Some(RestoreFault::BeforeCommit) => at == "before_commit",
            Some(RestoreFault::AfterCommit) => at == "after_commit",
            Some(RestoreFault::AfterNPuts(k)) => at == "put" && puts == k,
            Some(RestoreFault::CommitError) => at == "commit_error",
            None => false,
        });
        if hit {
            FAULT.with(|c| c.set(None));
        }
        hit
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn killed() -> WizardError {
    coded(E_RESTORE_UNFINISHED, "simulated stop")
}

#[derive(Serialize, Deserialize)]
struct PendingSecret {
    alias: String,
    b64: String,
}

#[derive(Serialize, Deserialize)]
struct PendingFile {
    area: String,
    rel: String,
    #[serde(default)]
    b64: String,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    secrets: Vec<PendingSecret>,
    files: Vec<PendingFile>,
    words_hex: String,
    forget_aliases: Vec<String>,
    old_ids: Vec<i64>,
    old_files: Vec<PendingFile>,
}

fn pending_alias(nonce: &str) -> String {
    format!("{RESTORE_PENDING_PREFIX}{nonce}")
}

/// `publisher_backup_restore`.
pub fn backup_restore(
    ctx: &WizardCtx,
    path: &Path,
    words: &str,
    replace_digest: Option<&str>,
) -> Result<RestoreResult> {
    // 1. The file.
    let bytes = read_backup_file(path)?;
    let h = parse_header(&bytes)?;
    let entropy = parse_words(words).map_err(words_err)?;
    let pt = decrypt_with(&bytes, &h, &entropy)?;
    let parsed = parse_payload(ctx, &pt)?;
    drop(pt);
    // 2. Custody works.
    probe_custody(ctx).map_err(|e| map_custody_err(ctx, "daal.custody.probe", e))?;
    // From here to the end one restore runs at a time, and nothing
    // sweeps the pending blob between its write and the commit.
    let _guard = restore_lock();
    // A previous restore still pending must finish before another.
    if !read_meta(ctx)?.restore_pending_nonce.is_empty() {
        finish_locked(ctx)?;
    }
    // 3. No setup running.
    if any_journal_locked(ctx) {
        return Err(setup_running_err());
    }
    // 4. Replace rule.
    let current = collect_state(ctx, SecretMode::Lenient)?;
    if !current.table("operators").rows.is_empty() {
        match replace_digest {
            None => {
                return Err(coded(
                    E_RESTORE_WOULD_REPLACE,
                    "this phone already has relays; confirm replacing them",
                ))
            }
            Some(d) if d != digest_of(&current) => {
                return Err(coded(
                    E_RESTORE_STATE_CHANGED,
                    "this phone's relays changed; look again",
                ))
            }
            Some(_) => {}
        }
    }

    // A. Everything the roll-forward needs, wrapped under this phone's
    // custody (no plaintext on disk).
    let backup_aliases: BTreeSet<&str> = parsed
        .snap
        .secrets
        .iter()
        .map(|(a, _)| a.as_str())
        .collect();
    let mut forget: BTreeSet<String> = referenced_aliases(&current.tables)
        .into_iter()
        .map(|(a, _)| a)
        .chain(report_aliases(&current.tables))
        .filter(|a| !backup_aliases.contains(a.as_str()))
        .collect();
    for a in ctx.db.list_all_keystore_aliases().unwrap_or_default() {
        if !backup_aliases.contains(a.as_str()) {
            forget.insert(a);
        }
    }
    let rec_aliases = ctx.db.with_conn(|c| recipient_aliases(c)).map_err(db_err)?;
    forget.retain(|a| !alias_forbidden(a, &rec_aliases));
    let old_files: Vec<PendingFile> = {
        let staging = ctx.staging_dir.clone();
        let (_, path_files) = ctx
            .db
            .with_conn(|c| dump_tables(c, &staging))
            .map_err(db_err)?;
        file_inventory(ctx, &current.operator_ids(), &path_files)
            .into_iter()
            .map(|(a, rel, _)| PendingFile {
                area: a.as_str().into(),
                rel,
                b64: String::new(),
            })
            .collect()
    };
    let pending = Pending {
        secrets: parsed
            .snap
            .secrets
            .iter()
            .map(|(a, v)| PendingSecret {
                alias: a.clone(),
                b64: B64.encode(&v[..]),
            })
            .collect(),
        files: parsed
            .snap
            .files
            .iter()
            .map(|f| PendingFile {
                area: f.area.as_str().into(),
                rel: f.rel.clone(),
                b64: B64.encode(&f.bytes[..]),
            })
            .collect(),
        words_hex: hex::encode(&entropy[..]),
        forget_aliases: forget.into_iter().collect(),
        old_ids: current.operator_ids(),
        old_files,
    };
    let blob = Zeroizing::new(serde_json::to_vec(&pending).unwrap_or_default());
    drop(pending);
    let mut nb = [0u8; 16];
    OsRng.fill_bytes(&mut nb);
    let nonce = hex::encode(nb);
    ctx.custody
        .put(&pending_alias(&nonce), &blob)
        .map_err(custody_err)?;
    drop(blob);
    if fault("before_commit", 0) {
        return Err(killed());
    }

    // B. The commit point.
    let staging = ctx.staging_dir.clone();
    let at = now(ctx);
    let committed = ctx.db.with_conn(|c| -> rusqlite::Result<()> {
        if fault("commit_error", 0) {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
                None,
            ));
        }
        let tx = c.transaction()?;
        replace_tables(&tx, &parsed.snap, &staging)?;
        // PB-1: in the same transaction, everyone not removed is
        // "restored, not yet settled" until a relay check says the relay
        // knows them or the person answers for them.
        crate::restore_settle::mark_restored(&tx)?;
        tx.execute(
            "UPDATE publisher_backup_meta SET restore_pending_nonce = ?1, restored_at_unix = ?2,
                    restored_backup_made_at_unix = ?3, restore_notice_dismissed = 0 WHERE id = 1",
            params![nonce, at, parsed.created_at],
        )?;
        tx.commit()
    });
    if let Err(e) = committed {
        let _ = ctx.custody.forget(&pending_alias(&nonce));
        return Err(commit_err(e));
    }
    if fault("after_commit", 0) {
        return Err(killed());
    }

    // C. Roll forward.
    finish_locked(ctx)?;
    let cur = collect_state(ctx, SecretMode::Lenient)?;
    Ok(RestoreResult {
        contents: contents_of(&parsed.snap),
        notice: RestoreNotice {
            restored_at_unix: at,
            backup_made_at_unix: parsed.created_at,
            relays: relay_lines(&cur),
            has_refresh_keys: has_refresh_keys(&cur),
        },
    })
}

fn area_dir(ctx: &WizardCtx, area: &str) -> Option<PathBuf> {
    match Area::parse(area)? {
        Area::Staging => Some(ctx.staging_dir.clone()),
        Area::Journal => Some(ctx.journal_dir.clone()),
    }
}

static RESTORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn restore_lock() -> std::sync::MutexGuard<'static, ()> {
    RESTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Finish a committed restore. Every step is idempotent; with no
/// restore pending it only removes orphan pending blobs.
pub fn finish_pending_restore(ctx: &WizardCtx) -> Result<()> {
    let _guard = restore_lock();
    finish_locked(ctx)
}

fn finish_locked(ctx: &WizardCtx) -> Result<()> {
    let meta = read_meta(ctx)?;
    if meta.restore_pending_nonce.is_empty() {
        let _ = ctx.custody.forget_prefix(RESTORE_PENDING_PREFIX);
        return Ok(());
    }
    let alias = pending_alias(&meta.restore_pending_nonce);
    let blob = match ctx.custody.get(&alias) {
        Ok(b) => Zeroizing::new(b),
        Err(CustodyError::Locked) => {
            return Err(coded(
                E_CUSTODY_LOCKED,
                "unlock this device's key store to finish the restore",
            ))
        }
        Err(_) => {
            return Err(coded(
                E_RESTORE_UNFINISHED,
                "what the restore still had to write is gone",
            ))
        }
    };
    let pending: Pending = serde_json::from_slice(&blob).map_err(|_| {
        coded(
            E_RESTORE_UNFINISHED,
            "what the restore still had to write is unreadable",
        )
    })?;
    drop(blob);
    let unfinished = |what: &str, e: std::io::Error| {
        coded(E_RESTORE_UNFINISHED, format!("{what}: {}", e.kind()))
    };

    // 1. Remove the old phone state's files and every relay's
    // conventional files.
    let new_ids: Vec<i64> = ctx
        .db
        .with_conn(|c| -> rusqlite::Result<Vec<i64>> {
            let mut s = c.prepare("SELECT id FROM operators")?;
            let v = s
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<i64>>>()?;
            Ok(v)
        })
        .map_err(db_err)?;
    let mut ids: BTreeSet<i64> = pending.old_ids.iter().copied().collect();
    ids.extend(new_ids);
    for id in ids {
        for rel in conventional_staging(&ctx.staging_dir, id) {
            let _ = std::fs::remove_file(ctx.staging_dir.join(rel));
        }
        crate::provision_journal::remove(&ctx.journal_dir, id);
    }
    for f in &pending.old_files {
        if valid_rel(&f.rel) {
            if let Some(d) = area_dir(ctx, &f.area) {
                let _ = std::fs::remove_file(d.join(&f.rel));
            }
        }
    }
    // 2. Files, 0600, durably.
    for f in &pending.files {
        let d = area_dir(ctx, &f.area).filter(|_| valid_rel(&f.rel));
        let Some(d) = d else {
            return Err(coded(E_RESTORE_UNFINISHED, "a file name is not valid"));
        };
        let bytes = Zeroizing::new(
            B64.decode(&f.b64)
                .map_err(|_| coded(E_RESTORE_UNFINISHED, "a file is unreadable"))?,
        );
        write_durably(&d.join(&f.rel), &bytes).map_err(|e| unfinished("cannot write a file", e))?;
    }
    // 3. Keys, re-wrapped under this phone's custody.
    for (n, s) in pending.secrets.iter().enumerate() {
        if fault("put", n) {
            return Err(killed());
        }
        let v = Zeroizing::new(
            B64.decode(&s.b64)
                .map_err(|_| coded(E_RESTORE_UNFINISHED, "a key is unreadable"))?,
        );
        ctx.custody.put(&s.alias, &v).map_err(custody_err)?;
    }
    // 4. Keys of the replaced state that the backup does not have.
    for a in &pending.forget_aliases {
        let _ = ctx.custody.forget(a);
    }
    // 5. The words that opened this backup are this phone's words now.
    let mut e = Zeroizing::new([0u8; 16]);
    hex::decode_to_slice(&pending.words_hex, &mut e[..])
        .map_err(|_| coded(E_RESTORE_UNFINISHED, "the stored words are unreadable"))?;
    ctx.custody.put(WORDS_ALIAS, &e[..]).map_err(custody_err)?;
    drop(pending);
    // 6. Done: the backup it came from is the last backup.
    let digest = state_digest(ctx)?;
    ctx.db
        .with_conn(|c| {
            c.execute(
                "UPDATE publisher_backup_meta SET restore_pending_nonce = '',
                        last_backup_at_unix = restored_backup_made_at_unix, last_backup_digest = ?1,
                        words_changed_at_unix = 0,
                        share_unconfirmed_at_unix = 0, share_unconfirmed_digest = ''
                 WHERE id = 1",
                params![digest],
            )
        })
        .map_err(db_err)?;
    // 7.
    let _ = ctx.custody.forget(&alias);
    Ok(())
}

/// Used by `custody_get`: no publisher operation runs on a restore that
/// committed and did not finish.
pub(crate) fn ensure_restore_finished(ctx: &WizardCtx) -> Result<()> {
    let pending = read_meta(ctx)
        .map(|m| !m.restore_pending_nonce.is_empty())
        .unwrap_or(false);
    if !pending {
        return Ok(());
    }
    finish_pending_restore(ctx).map_err(|e| {
        if code_of(&e) == E_RESTORE_UNFINISHED {
            e
        } else {
            coded(E_RESTORE_UNFINISHED, e)
        }
    })
}

/// `publisher_backup_finish_restore`.
pub fn finish_restore(ctx: &WizardCtx) -> Result<()> {
    finish_pending_restore(ctx)
}

/// `publisher_replace_hosting_key`: the old-phone remedy. The person
/// made a new key at the hosting company; it replaces the stored one for
/// `operator_ids` only after one read-only call shows it works and opens
/// the account that holds these relays' servers. A refused or mistyped
/// key, or one for another account, changes nothing: the key this phone
/// had stays in use. Returns the relays whose key was replaced.
pub fn replace_hosting_key(
    ctx: &WizardCtx,
    provider: &str,
    token: &str,
    operator_ids: &[i64],
) -> Result<Vec<i64>> {
    let token = token.trim();
    if token.is_empty() {
        return Err(WizardError::EmptyToken);
    }
    ensure_restore_finished(ctx)?;
    let mut rows = Vec::new();
    for &id in operator_ids {
        let row = ctx.db.get(id)?;
        if row.cloud_provider != provider {
            return Err(WizardError::Validation(format!(
                "relay {id} is not at {provider}"
            )));
        }
        rows.push(row);
    }
    let servers = ctx.cli.run_list_servers(provider, token).map_err(|e| {
        // The provider's own words, for Details; never the key.
        let text = e.to_string().replace(token, "[key]");
        coded(
            E_HOSTING_KEY_REJECTED,
            format!("the hosting company did not accept this key: {text}"),
        )
    })?;
    for row in &rows {
        if row.status != "provisioned" {
            continue;
        }
        let server_id = serde_json::from_str::<Value>(&row.operator_record_json)
            .ok()
            .and_then(|v| v.get("server_id").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        if !server_id.is_empty() && !servers.iter().any(|s| s.id == server_id) {
            return Err(coded(
                E_HOSTING_KEY_WRONG_ACCOUNT,
                format!(
                    "relay {}: its server is not in the account this key opens",
                    row.id
                ),
            ));
        }
    }
    let mut done = Vec::new();
    for row in &rows {
        crate::commands::store_cloud_token(ctx, provider, token, Some(row.id))?;
        done.push(row.id);
    }
    Ok(done)
}

/// `publisher_backup_dismiss_notice`.
pub fn dismiss_notice(ctx: &WizardCtx) -> Result<()> {
    ctx.db
        .with_conn(|c| {
            c.execute(
                "UPDATE publisher_backup_meta SET restore_notice_dismissed = 1 WHERE id = 1",
                [],
            )
        })
        .map_err(db_err)?;
    Ok(())
}

#[cfg(test)]
#[path = "publisher_backup_tests.rs"]
mod tests;
