//! Wave 4 Step 11 — make a route travel as TEXT.
//!
//! The one offline path that works today ships a high-entropy binary
//! blob over a channel that bans executables and watches entropy and
//! packet size. A base64 paste travels as a chat message instead.
//!
//! This module is the *decoder half* of that path. It is deliberately
//! split in two halves with opposite postures:
//!
//!   • **Liberal in what it accepts.** A human is pasting out of a
//!     messenger. The text arrives hard-wrapped, space-padded, quoted,
//!     bidi-marked (Farsi chats insert RLM/LRM all over a latin blob),
//!     prefixed with something someone typed (`daal:`), in the
//!     standard *or* URL-safe alphabet, with padding stripped or
//!     doubled, and often with a sentence in front of it. Every one of
//!     those must still yield the same bytes. A blob that fails only
//!     because a chat client inserted line breaks is a route the
//!     family did not get.
//!
//!   • **Strict about everything else.** These bytes are untrusted
//!     input from a hostile channel. The decoded size is bounded
//!     *before* the decode buffer is allocated; the container magic
//!     must match; and the bytes then go through the SAME verifier the
//!     file path uses — `.sbp` to `commands::import_sbp` (engine
//!     signature + revocation + expiry), `.sbpx` to
//!     [`crate::recipient_sbpx::import_sbpx`] (recipient identity +
//!     device custody) and only then to the importer. There is no
//!     bypass in this file, and there must never be one: it decides
//!     *which* verified path the bytes take, never *whether* they are
//!     verified.
//!
//! Recovery strategy: rather than trying to enumerate every wrapper a
//! messenger might add, we scan the text for the base64 spelling of
//! the container magic and start there. `.sbp` is a zip
//! (`PK\x03\x04` → `UEsDB…`); `.sbpx` is the envelope
//! (`DSBP\x00\x01` → `RFNCUAAB…`). Both magics land on a base64 group
//! boundary because they start the file, so the encoding of the first
//! bytes is fixed and searchable. Anything before it is discarded as
//! chatter. This is safe because finding the magic is not a trust
//! decision — signature verification downstream is.

use std::path::{Path, PathBuf};

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, Engine as _};
use rand::RngCore;
use thiserror::Error;

use crate::recipient_sbpx::SBPX_MAGIC;

/// Zip local-file-header magic. Every `.sbp` is a zip archive
/// (`bundle/go/bundle/sbp.go`), so this is its first four bytes.
pub const SBP_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

/// base64 of the leading bytes of each container. Fixed strings: the
/// magic starts at offset 0, so it always encodes onto a group
/// boundary. `paste_magic_prefixes_are_what_base64_produces` pins
/// both against a real encoder so a typo here cannot ship.
const SBP_B64_PREFIX: &str = "UEsDB";
const SBPX_B64_PREFIX: &str = "RFNCUAAB";

/// Hard ceiling on the decoded bundle. A real `.sbp` is a couple of
/// KB; a fat multi-relay pack is tens of KB. 1 MiB is ~700x the
/// realistic size and still far below anything a messenger would
/// carry as a text message — it exists so a hostile paste cannot make
/// us allocate.
pub const MAX_DECODED_BYTES: usize = 1024 * 1024;

/// Ceiling on the *input* text, checked before we walk it. Allows a
/// 4/3 base64 expansion plus 3x of surrounding junk/whitespace.
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// Anything shorter than this cannot be a container — a zip with a
/// single entry is already hundreds of bytes. Catches half-copied
/// text early, with an error that tells the user to copy it all.
const MIN_DECODED_BYTES: usize = 64;

/// Decoder tuned for human-pasted text: padding may be absent,
/// present, or wrong (we strip `=` before it ever gets here, so the
/// mode is Indifferent), and non-canonical trailing bits are
/// tolerated rather than rejected.
const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Which container the pasted text turned out to hold. This picks the
/// downstream *verification* path, never whether there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PastedKind {
    /// Plain signed bundle → the engine importer.
    Sbp,
    /// Sealed envelope → recipient identity + device custody first.
    Sbpx,
}

impl PastedKind {
    pub fn extension(self) -> &'static str {
        match self {
            PastedKind::Sbp => "sbp",
            PastedKind::Sbpx => "sbpx",
        }
    }
}

#[derive(Debug)]
pub struct DecodedPaste {
    pub kind: PastedKind,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct StagedPaste {
    /// Absolute path of the mode-0600 file we wrote the bytes to.
    /// The caller hands this to the same verifier the file picker
    /// uses, then deletes it.
    pub path: PathBuf,
    pub kind: PastedKind,
}

#[derive(Debug, Error)]
pub enum PasteError {
    #[error("this text does not contain a Daal bundle or envelope")]
    NotDaalText,
    #[error("the pasted text is incomplete")]
    Truncated,
    #[error("the pasted text is too large to be a Daal bundle")]
    TooLarge,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

impl PasteError {
    /// Stable machine code, in the same shape `bundle_rs::Error::code`
    /// emits (`ErrFoo`). The Tauri layer prefixes the message with it
    /// and `AddSheet.friendlyError` swaps in the `add.err.<code>`
    /// copy, so these strings are load-bearing: they must match the
    /// i18n keys in `client-shared/i18n/d2-extra.*.json`.
    pub fn code(&self) -> &'static str {
        match self {
            PasteError::NotDaalText => "ErrNotDaalText",
            PasteError::Truncated => "ErrPasteTruncated",
            PasteError::TooLarge => "ErrPasteTooLarge",
            PasteError::Io(_) => "ErrIo",
        }
    }
}

/// Characters that are *dropped without breaking the blob*. These are
/// the artefacts of transport, not of content:
///
///   • any whitespace — the hard-wrap a messenger inserts, and the
///     spaces a user's keyboard adds. This is the single most common
///     reason a paste fails today.
///   • `=` — stripped so that missing, partial or doubled padding all
///     normalise to the same thing and we re-derive it at decode.
///   • soft hyphen, zero-width space/non-joiner/joiner, BOM, and the
///     bidi control marks (LRM/RLM/LRE..RLO/LRI..PDI). An RTL chat
///     app sprinkles these around a latin-script blob as a matter of
///     course, and they are invisible in the paste box.
fn is_joiner(ch: char) -> bool {
    if ch.is_whitespace() {
        return true;
    }
    matches!(ch,
        '='
        | '\u{00ad}'                 // soft hyphen
        | '\u{200b}'..='\u{200f}'    // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202a}'..='\u{202e}'    // LRE, RLE, PDF, LRO, RLO
        | '\u{2060}'..='\u{2064}'    // word joiner + invisible operators
        | '\u{2066}'..='\u{2069}'    // LRI, RLI, FSI, PDI
        | '\u{feff}'                 // BOM / ZWNBSP
    )
}

/// Map one character onto the standard base64 alphabet, accepting the
/// URL-safe alphabet too (`-` → `+`, `_` → `/`). Returns `None` for
/// anything that is not a base64 symbol; the caller treats that as a
/// run boundary.
fn map_b64(ch: char) -> Option<char> {
    match ch {
        'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' => Some(ch),
        '-' => Some('+'),
        '_' => Some('/'),
        _ => None,
    }
}

/// Decode human-pasted text into container bytes.
///
/// See the module docs for the acceptance posture. The bound on
/// [`MAX_DECODED_BYTES`] is enforced three times — on the input length,
/// on the candidate's encoded length before `decode` allocates, and on
/// the decoded buffer — because the cheap check is the one that has to
/// hold when the input is hostile.
pub fn decode_pasted(text: &str) -> Result<DecodedPaste, PasteError> {
    if text.len() > MAX_INPUT_BYTES {
        return Err(PasteError::TooLarge);
    }
    // Encoded length that could still decode within the ceiling.
    let max_encoded = (MAX_DECODED_BYTES / 3 + 1) * 4;

    // Split into runs of base64 symbols. Joiners are skipped WITHOUT
    // ending the current run — that is what makes a hard-wrapped
    // paste survive. Everything else (punctuation, Farsi or Latin
    // prose, emoji) ends the run.
    let mut runs: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if is_joiner(ch) {
            continue;
        }
        match map_b64(ch) {
            Some(c) => {
                if cur.len() >= max_encoded {
                    return Err(PasteError::TooLarge);
                }
                cur.push(c);
            }
            None => {
                if !cur.is_empty() {
                    runs.push(std::mem::take(&mut cur));
                }
            }
        }
    }
    if !cur.is_empty() {
        runs.push(cur);
    }

    // Find the container magic. Anything ahead of it — "salam, ino
    // bezan:", a typed `daal:` prefix, a data: URI header — is
    // chatter and is dropped. Longest candidate wins so a stray
    // "UEsDB" inside prose cannot beat the real payload.
    let mut best: Option<(&str, PastedKind)> = None;
    for run in &runs {
        for (prefix, kind) in [
            (SBPX_B64_PREFIX, PastedKind::Sbpx),
            (SBP_B64_PREFIX, PastedKind::Sbp),
        ] {
            if let Some(i) = run.find(prefix) {
                let cand = &run[i..];
                if best.map_or(true, |(b, _)| cand.len() > b.len()) {
                    best = Some((cand, kind));
                }
            }
        }
    }
    let (cand, prefix_kind) = best.ok_or(PasteError::NotDaalText)?;

    // A base64 quad is 2-4 symbols; a trailing lone symbol means the
    // copy stopped mid-character.
    if cand.len() % 4 == 1 {
        return Err(PasteError::Truncated);
    }
    if cand.len() / 4 * 3 > MAX_DECODED_BYTES {
        return Err(PasteError::TooLarge);
    }

    let bytes = B64.decode(cand).map_err(|e| match e {
        base64::DecodeError::InvalidLength(_) => PasteError::Truncated,
        _ => PasteError::NotDaalText,
    })?;

    if bytes.len() > MAX_DECODED_BYTES {
        return Err(PasteError::TooLarge);
    }
    if bytes.len() < MIN_DECODED_BYTES {
        return Err(PasteError::Truncated);
    }

    // The decoded bytes are the authority on the kind, not the
    // prefix we matched on.
    let kind = if bytes.starts_with(&SBPX_MAGIC) {
        PastedKind::Sbpx
    } else if bytes.starts_with(&SBP_MAGIC) {
        PastedKind::Sbp
    } else {
        return Err(PasteError::NotDaalText);
    };
    debug_assert_eq!(kind, prefix_kind);

    Ok(DecodedPaste { kind, bytes })
}

/// Decode the text and write it to a private file under
/// `<staging>/paste/`, because every verifier we own takes a path.
/// The file is created with `create_new` (never follows an existing
/// name or symlink) and mode 0600 on unix. The caller deletes it as
/// soon as the importer has run; `sweep_stale_pastes` reaps anything
/// a crash left behind.
pub fn stage_pasted_text(staging_dir: &Path, text: &str) -> Result<StagedPaste, PasteError> {
    let decoded = decode_pasted(text)?;
    let dir = staging_dir.join("paste");
    std::fs::create_dir_all(&dir)?;

    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..8 {
        let mut tag = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut tag);
        let path = dir.join(format!("{}.{}", hex::encode(tag), decoded.kind.extension()));
        match write_private(&path, &decoded.bytes) {
            Ok(()) => {
                return Ok(StagedPaste {
                    path,
                    kind: decoded.kind,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(PasteError::Io(e)),
        }
    }
    Err(PasteError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::Other, "could not stage pasted bundle")
    })))
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Reap `<staging>/paste/` leftovers older than `older_than_secs`.
/// Mirrors `recipient_sbpx::sweep_stale`; called at launch.
pub fn sweep_stale_pastes(staging_dir: &Path, now_unix: i64, older_than_secs: i64) -> usize {
    let dir = staging_dir.join("paste");
    if !dir.exists() {
        return 0;
    }
    let cutoff = now_unix - older_than_secs;
    let mut removed = 0usize;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let mtime = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
        if let Some(d) = mtime {
            if (d.as_secs() as i64) < cutoff {
                let _ = std::fs::remove_file(entry.path());
                removed += 1;
            }
        }
    }
    removed
}

/// The reverse direction: bytes → text a human can paste into a chat.
///
/// Standard alphabet, padded, hard-wrapped at 76 columns so the
/// receiving app's own wrapping cannot make it worse (and so the blob
/// reads as a block of text rather than one enormous line). Wrapping
/// is free on the way back in because newlines are joiners.
///
/// This is the one-line counterpart a publisher "Copy as text" action
/// calls; see the Step 11 report for where that button goes.
pub fn encode_pasteable(bytes: &[u8]) -> String {
    let raw = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = String::with_capacity(raw.len() + raw.len() / 76 + 1);
    for (i, ch) in raw.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};

    // ---- fixtures ---------------------------------------------------

    /// Smallest thing that satisfies the decoder's structural gate: a
    /// zip magic plus enough filler to clear MIN_DECODED_BYTES. The
    /// decoder is not a zip parser — `bundle_rs::parse_sbp` and the
    /// engine are, and the `paste_bytes_still_face_the_verifier`
    /// tests below feed them real signed fixtures.
    fn fake_sbp() -> Vec<u8> {
        let mut v = SBP_MAGIC.to_vec();
        v.extend(std::iter::repeat(b'z').take(200));
        v
    }

    fn fake_sbpx() -> Vec<u8> {
        let mut v = SBPX_MAGIC.to_vec();
        v.extend(std::iter::repeat(b'q').take(200));
        v
    }

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // ---- the magic prefixes are real --------------------------------

    #[test]
    fn paste_magic_prefixes_are_what_base64_produces() {
        assert!(STANDARD.encode(fake_sbp()).starts_with(SBP_B64_PREFIX));
        assert!(STANDARD.encode(fake_sbpx()).starts_with(SBPX_B64_PREFIX));
        // And they cannot be confused for each other.
        assert!(!STANDARD.encode(fake_sbp()).starts_with(SBPX_B64_PREFIX));
        assert!(!STANDARD.encode(fake_sbpx()).starts_with(SBP_B64_PREFIX));
    }

    // ---- the messy-input table --------------------------------------
    //
    // Every row is the SAME bundle, mangled the way a real messenger
    // or a real human mangles it. All must decode to identical bytes.

    #[test]
    fn accepts_the_messy_input_table() {
        let want = fake_sbp();
        let clean = STANDARD.encode(&want);
        let urlsafe = URL_SAFE.encode(&want);
        let unpadded = clean.trim_end_matches('=').to_string();

        let wrapped_40 = clean
            .as_bytes()
            .chunks(40)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let wrapped_crlf = clean
            .as_bytes()
            .chunks(33)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        let spaced = clean
            .as_bytes()
            .chunks(8)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect::<Vec<_>>()
            .join(" ");

        let cases: Vec<(&str, String)> = vec![
            ("clean", clean.clone()),
            ("leading/trailing whitespace", format!("\n\n  {clean}  \n")),
            ("hard-wrapped at 40", wrapped_40),
            ("hard-wrapped with CRLF", wrapped_crlf),
            ("spaces every 8 chars", spaced),
            ("url-safe alphabet", urlsafe.clone()),
            ("url-safe, unpadded", urlsafe.trim_end_matches('=').to_string()),
            ("padding stripped", unpadded.clone()),
            ("padding doubled", format!("{unpadded}====")),
            ("double quotes added by the app", format!("\"{clean}\"")),
            ("smart quotes", format!("\u{201c}{clean}\u{201d}")),
            ("guillemets", format!("\u{00ab}{clean}\u{00bb}")),
            ("backtick code span", format!("`{clean}`")),
            ("markdown code fence", format!("```\n{clean}\n```")),
            ("typed daal: prefix", format!("daal:{clean}")),
            ("typed daal:// prefix", format!("daal://{clean}")),
            ("typed sbp: prefix", format!("sbp:{clean}")),
            ("data: URI header", format!("data:application/octet-stream;base64,{clean}")),
            ("english sentence in front", format!("here you go, paste this: {clean}")),
            ("farsi sentence in front", format!("سلام، این را بچسبان: {clean}")),
            ("farsi sentence after", format!("{clean} \u{200f}موفق باشی")),
            (
                "bidi marks sprinkled through",
                format!("\u{200f}{}\u{200e}{}\u{200f}", &clean[..20], &clean[20..]),
            ),
            (
                "zero-width space mid-blob",
                format!("{}\u{200b}{}", &clean[..31], &clean[31..]),
            ),
            (
                "soft hyphen mid-blob",
                format!("{}\u{00ad}{}", &clean[..17], &clean[17..]),
            ),
            ("BOM in front", format!("\u{feff}{clean}")),
            (
                "wrapped AND quoted AND prefixed AND url-safe",
                format!(
                    "  \"daal:{}\"  ",
                    urlsafe
                        .trim_end_matches('=')
                        .as_bytes()
                        .chunks(50)
                        .map(|c| String::from_utf8(c.to_vec()).unwrap())
                        .collect::<Vec<_>>()
                        .join("\n   ")
                ),
            ),
            ("our own encode_pasteable output", encode_pasteable(&want)),
        ];

        for (name, input) in cases {
            let got = decode_pasted(&input)
                .unwrap_or_else(|e| panic!("case {name:?} should decode, got {e}"));
            assert_eq!(got.bytes, want, "case {name:?} decoded to the wrong bytes");
            assert_eq!(got.kind, PastedKind::Sbp, "case {name:?} wrong kind");
        }
    }

    #[test]
    fn sealed_envelope_is_recognised_as_sbpx_however_mangled() {
        let want = fake_sbpx();
        let clean = STANDARD.encode(&want);
        for input in [
            clean.clone(),
            format!("\"daal:{clean}\""),
            clean
                .as_bytes()
                .chunks(29)
                .map(|c| String::from_utf8(c.to_vec()).unwrap())
                .collect::<Vec<_>>()
                .join("\n"),
            URL_SAFE.encode(&want).trim_end_matches('=').to_string(),
        ] {
            let got = decode_pasted(&input).expect("sbpx should decode");
            assert_eq!(got.kind, PastedKind::Sbpx);
            assert_eq!(got.bytes, want);
        }
    }

    // ---- refusals ---------------------------------------------------

    #[test]
    fn refuses_text_that_is_not_a_daal_container() {
        for input in [
            "",
            "   \n  ",
            "hello there",
            "https://example.invalid/sub",
            "vless://uuid@host:443?security=reality#name",
            // Valid base64 of the right length, wrong magic.
            &STANDARD.encode(vec![0u8; 300]),
            // The zip magic in the middle of a payload, not at the
            // start — we only ever anchor on offset 0.
            &STANDARD.encode({
                let mut v = vec![0u8; 8];
                v.extend_from_slice(&SBP_MAGIC);
                v.extend(std::iter::repeat(b'z').take(200));
                v
            }),
        ] {
            let err = decode_pasted(input).unwrap_err();
            assert!(
                matches!(err, PasteError::NotDaalText),
                "input {input:?} should be NotDaalText, got {err:?}"
            );
            assert_eq!(err.code(), "ErrNotDaalText");
        }
    }

    #[test]
    fn refuses_a_half_copied_blob() {
        let clean = STANDARD.encode(fake_sbp());
        // Cut mid-quad: a lone trailing symbol.
        let cut = &clean[..clean.len() - 6];
        let cut = &cut[..cut.len() - (cut.len() % 4) + 1];
        let err = decode_pasted(cut).unwrap_err();
        assert!(matches!(err, PasteError::Truncated), "got {err:?}");
        assert_eq!(err.code(), "ErrPasteTruncated");

        // Only the magic came across.
        let err = decode_pasted(&clean[..8]).unwrap_err();
        assert!(matches!(err, PasteError::Truncated), "got {err:?}");
    }

    #[test]
    fn refuses_input_over_the_size_bound() {
        // Oversized *input* — rejected before we walk a single char.
        let huge = "A".repeat(MAX_INPUT_BYTES + 1);
        assert!(matches!(
            decode_pasted(&huge).unwrap_err(),
            PasteError::TooLarge
        ));

        // Oversized *payload* — a real magic followed by more base64
        // than MAX_DECODED_BYTES allows. Must be refused while
        // walking, i.e. before any decode buffer is allocated.
        let over = format!(
            "{}{}",
            SBP_B64_PREFIX,
            "A".repeat((MAX_DECODED_BYTES / 3 + 1) * 4)
        );
        let err = decode_pasted(&over).unwrap_err();
        assert!(matches!(err, PasteError::TooLarge), "got {err:?}");
        assert_eq!(err.code(), "ErrPasteTooLarge");

        // And a payload that is just inside the bound is not refused
        // for size (it fails later, on the magic/structure).
        let ok_len = format!("{}{}", SBP_B64_PREFIX, "A".repeat(1024));
        assert!(!matches!(
            decode_pasted(&ok_len).unwrap_err(),
            PasteError::TooLarge
        ));
    }

    #[test]
    fn a_tampered_blob_decodes_to_tampered_bytes_not_to_the_original() {
        // The decoder must not "helpfully" repair anything. One
        // flipped base64 symbol must come out as different bytes, so
        // the signature check downstream sees the tampering.
        let want = fake_sbp();
        let clean = STANDARD.encode(&want);
        let mut chars: Vec<char> = clean.chars().collect();
        let i = chars.len() / 2;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        let got = decode_pasted(&tampered).expect("still structurally decodable");
        assert_ne!(got.bytes, want, "tampering must survive the decoder");
    }

    // ---- staging ----------------------------------------------------

    #[test]
    fn stage_writes_a_private_file_with_the_right_extension() {
        let dir = tmpdir();
        let text = encode_pasteable(&fake_sbp());
        let staged = stage_pasted_text(dir.path(), &text).expect("stage");
        assert_eq!(staged.kind, PastedKind::Sbp);
        assert_eq!(staged.path.extension().unwrap(), "sbp");
        assert_eq!(std::fs::read(&staged.path).unwrap(), fake_sbp());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&staged.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "staged paste must be 0600");
        }

        let staged2 = stage_pasted_text(dir.path(), &STANDARD.encode(fake_sbpx())).expect("stage");
        assert_eq!(staged2.kind, PastedKind::Sbpx);
        assert_eq!(staged2.path.extension().unwrap(), "sbpx");
        assert_ne!(staged.path, staged2.path, "staging names must not collide");
    }

    #[test]
    fn stage_refuses_junk_without_writing_anything() {
        let dir = tmpdir();
        let err = stage_pasted_text(dir.path(), "not a bundle").unwrap_err();
        assert!(matches!(err, PasteError::NotDaalText));
        let paste_dir = dir.path().join("paste");
        let count = std::fs::read_dir(&paste_dir).map(|d| d.count()).unwrap_or(0);
        assert_eq!(count, 0, "a refused paste must leave nothing on disk");
    }

    #[test]
    fn sweep_removes_stale_pastes_only() {
        let dir = tmpdir();
        let staged = stage_pasted_text(dir.path(), &STANDARD.encode(fake_sbp())).expect("stage");
        // now == epoch-ish → nothing is older than the cutoff.
        assert_eq!(sweep_stale_pastes(dir.path(), 0, 600), 0);
        assert!(staged.path.exists());
        // now == far future → everything is stale.
        assert_eq!(sweep_stale_pastes(dir.path(), i64::MAX / 2, 600), 1);
        assert!(!staged.path.exists());
    }

    #[test]
    fn round_trips_through_encode_pasteable() {
        for want in [fake_sbp(), fake_sbpx()] {
            let text = encode_pasteable(&want);
            assert!(text.contains('\n'), "long blobs should be wrapped");
            assert_eq!(decode_pasted(&text).unwrap().bytes, want);
        }
    }
}
