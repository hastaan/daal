//! Wave 4 Step 11 — the pasted-text path takes the SAME verification
//! the file path takes.
//!
//! `recipient_paste`'s unit tests prove the decoder is liberal about
//! transport damage. This file proves the other half: being liberal
//! about newlines buys the user nothing extra in trust. The bytes that
//! come out of a paste are fed to the very same verifiers a picked
//! file is fed to, and a bundle that is tampered with, expired, or
//! sealed for someone else is REFUSED.
//!
//! Two verifiers are in play, and both are exercised here:
//!
//!   * `bundle_rs::{parse_sbp, verify_bundle}` — the local verifier
//!     `daal_desktop_core::commands::preview_bundle` runs, i.e. the
//!     one behind the Tauri `preview_sbp_bytes` command. Signed
//!     fixtures come from `bundle-rs/tests/fixtures/`, the corpus the
//!     Go implementation and bundle-rs are held to parity on.
//!   * `recipient_sbpx::import_sbpx` — recipient identity + device
//!     custody, the gate a `.sbpx` must clear before any importer sees
//!     plaintext.
//!
//! The third verifier, the Go engine importer behind `import_sbp`,
//! cannot run here (it needs the c-shared engine). It does not need a
//! separate test: the Tauri command hands it a path produced by
//! `stage_pasted_text` and calls `cmd::import_sbp` — literally the
//! same call the file picker makes, on a file with the same bytes.

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine as _;

use daal_wizard::cli_bridge::{MockRunner, Pricing};
use daal_wizard::commands::WizardCtx;
use daal_wizard::device_custody::FileCustody;
use daal_wizard::keystore::Keystore;
use daal_wizard::operator_db::OperatorDb;
use daal_wizard::recipient_paste::{decode_pasted, stage_pasted_text, PasteError, PastedKind};
use daal_wizard::recipient_sbpx::{import_sbpx, SbpxImportError, SBPX_MAGIC};

fn fixture(name: &str) -> Vec<u8> {
    // The signed corpus lives with bundle-rs, which owns the
    // verifier. We read it rather than copy it so there is exactly
    // one set of vectors in the repo.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("bundle-rs/tests/fixtures");
    p.push(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read fixture {}: {e}", p.display()))
}

/// The worst-case realistic paste: someone typed a prefix, the app
/// added quotes, the channel used the URL-safe alphabet and dropped
/// the padding, and the message was hard-wrapped with a Farsi
/// sentence and its bidi mark in front.
fn mangle(bytes: &[u8]) -> String {
    let b64 = URL_SAFE.encode(bytes);
    let wrapped = b64
        .trim_end_matches('=')
        .as_bytes()
        .chunks(37)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n  ");
    format!("\u{200f}سلام، این را بچسبان:\n\"daal:{wrapped}\"\n")
}

/// The instant the Go fixture generator pinned. `bundle-rs`'s own
/// parity suite verifies at the same instant, because the corpus's
/// `valid-*` vectors carry a fixed 3-day validity window that wall
/// clock has since walked past. Expiry itself is tested against the
/// REAL clock in `expiry_is_enforced_on_the_production_clock`.
fn fixture_clock() -> time::OffsetDateTime {
    time::macros::datetime!(2026-04-26 12:00:00 UTC)
}

fn verify_pasted(text: &str) -> Result<(), String> {
    let decoded = decode_pasted(text).map_err(|e| e.code().to_string())?;
    assert_eq!(decoded.kind, PastedKind::Sbp);
    let sbp = bundle_rs::parse_sbp(&decoded.bytes).map_err(|e| e.code().to_string())?;
    bundle_rs::verify_bundle_at(&sbp, fixture_clock()).map_err(|e| e.code().to_string())
}

#[test]
fn a_valid_bundle_survives_the_worst_realistic_mangling() {
    let raw = fixture("valid-v2.sbp");
    let text = mangle(&raw);

    // Byte-identical to the file the publisher exported...
    let decoded = decode_pasted(&text).expect("decode");
    assert_eq!(decoded.bytes, raw, "paste must reproduce the file exactly");

    // ...and it verifies.
    verify_pasted(&text).expect("valid-v2 pasted as text must verify");
}

#[test]
fn a_tampered_bundle_is_refused() {
    // The corpus's own tampered vector: signature no longer matches.
    let err = verify_pasted(&mangle(&fixture("invalid-signature.sbp"))).unwrap_err();
    assert_eq!(err, "ErrInvalidSignature");

    // And tampering applied to the TEXT in transit — one flipped
    // base64 symbol inside the payload — must also be refused. It
    // must never come back as "imported".
    let raw = fixture("valid-v2.sbp");
    let b64 = STANDARD.encode(&raw);
    let mut chars: Vec<char> = b64.chars().collect();
    let mid = chars.len() / 2;
    chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert!(
        verify_pasted(&tampered).is_err(),
        "a text-tampered blob must be refused, never imported"
    );
}

#[test]
fn an_expired_bundle_is_refused() {
    let err = verify_pasted(&mangle(&fixture("expired-bundle.sbp"))).unwrap_err();
    assert_eq!(err, "ErrExpiredBundle");
}

/// `preview_bundle` (and therefore `preview_sbp_bytes`) calls
/// `verify_bundle`, which reads the real clock. Pin that: a bundle
/// whose window closed is refused with no clock injected anywhere.
#[test]
fn expiry_is_enforced_on_the_production_clock() {
    let decoded = decode_pasted(&mangle(&fixture("expired-bundle.sbp"))).expect("decode");
    let sbp = bundle_rs::parse_sbp(&decoded.bytes).expect("parse");
    let err = bundle_rs::verify_bundle(&sbp).expect_err("must refuse");
    assert_eq!(err.code(), "ErrExpiredBundle");
}

#[test]
fn other_corpus_refusals_survive_the_paste_path() {
    // Nothing about arriving as text softens any other check.
    for (vector, want) in [
        ("fingerprint-mismatch.sbp", "ErrFingerprintMismatch"),
        ("invalid-spec-v6.sbp", "ErrUnsupportedSpec"),
        ("expired-route.sbp", "ErrExpiredRoute"),
        ("missing-profile.sbp", "ErrMissingProfile"),
        ("unknown-scarcity.sbp", "ErrInvalidEnum"),
        ("unknown-transport.sbp", "ErrInvalidEnum"),
    ] {
        let got = verify_pasted(&mangle(&fixture(vector))).unwrap_err();
        assert_eq!(got, want, "vector {vector}");
    }
}

#[test]
fn a_truncated_paste_of_a_real_bundle_is_refused() {
    // The user copied most of the message. Either the decoder calls
    // it truncated or the verifier calls it a broken zip — what must
    // never happen is a successful import.
    let b64 = STANDARD.encode(fixture("valid-v2.sbp"));
    let cut = &b64[..b64.len() / 2];
    assert!(verify_pasted(cut).is_err(), "half a bundle must be refused");
}

// ---- sealed envelopes ----------------------------------------------

fn make_ctx() -> WizardCtx {
    let db = OperatorDb::open_in_memory().expect("open_in_memory");
    let tmp = tempfile::tempdir().expect("tempdir");
    let ks = Keystore::new_in_memory(tmp.path());
    let custody = FileCustody::static_test(tmp.path()).expect("custody");
    let staging_dir = tmp.path().to_path_buf();
    // The tempdir must outlive the ctx; the process is a test binary.
    let _ = Box::leak(Box::new(tmp));
    WizardCtx {
        db: Arc::new(db),
        keystore: Arc::new(ks),
        staging_dir,
        cli: Arc::new(MockRunner::new(Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.0,
            monthly_eur: 0.0,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        })),
        clock: Arc::new(|| 1_700_000_000),
        custody: Arc::new(custody),
    }
}

/// A sealed envelope pasted as text still needs the recipient
/// identity. This is the whole point of `.sbpx`: it is addressed to
/// one phone. Arriving as a chat message must not change that.
#[test]
fn a_sealed_paste_without_an_identity_is_refused() {
    let ctx = make_ctx();

    let mut sealed = SBPX_MAGIC.to_vec();
    sealed.extend(std::iter::repeat(b'x').take(200));
    let text = mangle_sbpx(&sealed);

    let staged = stage_pasted_text(&ctx.staging_dir, &text).expect("stage");
    assert_eq!(
        staged.kind,
        PastedKind::Sbpx,
        "a sealed paste must be routed to the identity gate, never to the plain importer"
    );

    // No identity on this device → refused, with the error the UI
    // turns into "create your Daal address first".
    let err = import_sbpx(&ctx, &staged.path).unwrap_err();
    assert!(
        matches!(err, SbpxImportError::IdentityMissing),
        "got {err:?}"
    );
}

/// Same envelope, same device, once an identity exists: the sealed
/// paste opens. (The mock unpack strips the magic; what is being
/// tested is that a pasted `.sbpx` reaches `import_sbpx` at all, with
/// bytes intact.)
#[test]
fn a_sealed_paste_with_an_identity_reaches_the_unwrapper() {
    let ctx = make_ctx();
    daal_wizard::recipient_identity::get_or_create(&ctx).expect("identity");

    // Long enough to clear the decoder's minimum-size floor, which
    // exists to catch half-copied messages.
    let mut plaintext = b"---DAAL SBP v1---\npasted envelope body\n".to_vec();
    plaintext.extend(std::iter::repeat(b'.').take(64));
    let mut sealed = SBPX_MAGIC.to_vec();
    sealed.extend_from_slice(&plaintext);

    let staged = stage_pasted_text(&ctx.staging_dir, &mangle_sbpx(&sealed)).expect("stage");
    assert_eq!(std::fs::read(&staged.path).unwrap(), sealed);

    let out = import_sbpx(&ctx, &staged.path).expect("import_sbpx");
    assert_eq!(std::fs::read(&out).unwrap(), plaintext);
}

/// Mangling for envelopes: same treatment, but without the `daal:`
/// prefix so both prefix-present and prefix-absent shapes are
/// covered across this file.
fn mangle_sbpx(bytes: &[u8]) -> String {
    let b64 = STANDARD.encode(bytes);
    let wrapped = b64
        .as_bytes()
        .chunks(31)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!("  \u{feff}{wrapped}  \n")
}

#[test]
fn junk_never_becomes_a_bundle() {
    let ctx = make_ctx();
    for junk in [
        "سلام، حالت چطوره؟",
        "https://example.invalid/subscription",
        "vless://0000@example.invalid:443#x",
        &STANDARD.encode(vec![7u8; 4096]),
    ] {
        let err = stage_pasted_text(&ctx.staging_dir, junk).unwrap_err();
        assert!(matches!(err, PasteError::NotDaalText), "junk {junk:?}");
    }
}

// ---- the lane, both halves ------------------------------------------

/// The base64-paste lane is only a capability if BOTH halves exist. The
/// receiving half (`decode_pasted` / `stage_pasted_text`) shipped first;
/// `encode_pasteable` had no non-test caller anywhere, so the publisher
/// could not produce the text its own recipient app was waiting for.
/// `commands::copy_pasteable` is that caller.
///
/// This drives the real function over a real signed fixture and feeds
/// its output straight into the real receiver, so the two halves are
/// proven to fit rather than assumed to.
/// Insert a real operator row and mark it as having a signed SBP, so
/// `copy_pasteable`'s preconditions are genuinely satisfied. Without
/// this the call refuses with "operator not found" and any test around
/// it passes for the wrong reason.
fn seed_signed_operator(ctx: &WizardCtx) -> i64 {
    let id = ctx
        .db
        .insert_pre_provision("{}", "ab", "k1", "hetzner", "t1", 1)
        .expect("insert operator");
    ctx.db
        .record_signed_sbp(id, "sha-test", "rp-test", 1_700_000_000)
        .expect("mark signed");
    id
}

#[test]
fn copy_pasteable_output_is_exactly_what_the_paste_lane_accepts() {
    use daal_wizard::commands::copy_pasteable;

    let ctx = make_ctx();
    let want = fixture("valid-v2.sbp");
    let operator_id = seed_signed_operator(&ctx);

    // Stage the artifact where copy_pasteable looks for the "shared"
    // (connectable) pack, matching produce_shared_sbp's convention.
    std::fs::write(
        ctx.staging_dir.join(format!("{operator_id}.shared.sbp")),
        &want,
    )
    .expect("stage shared sbp");

    let text = copy_pasteable(&ctx, operator_id, "shared").expect("copy_pasteable");

    // What a messenger will actually carry: wrapped lines, not one
    // enormous one.
    assert!(
        text.lines().count() > 1,
        "pasteable text should be hard-wrapped, got one line of {}",
        text.len()
    );
    assert!(
        text.lines().all(|l| l.len() <= 76),
        "a line exceeded the 76-column wrap"
    );

    // And the receiving half accepts it, byte for byte.
    let got = decode_pasted(&text).expect("copy_pasteable output must decode");
    assert_eq!(got.bytes, want, "round-trip changed the bundle");
    assert_eq!(got.kind, PastedKind::Sbp);

    // Finally the real staging path the Tauri command uses, so the whole
    // receive lane is exercised and not just the decoder.
    let staged = stage_pasted_text(&ctx.staging_dir, &text).expect("stage");
    assert_eq!(staged.kind, PastedKind::Sbp);
    assert_eq!(std::fs::read(&staged.path).expect("read staged"), want);
}

/// The text must survive the trip a real chat message puts it through.
/// This is the whole reason the lane exists, so it is asserted on the
/// PUBLISHER's actual output rather than on a hand-built string.
#[test]
fn copy_pasteable_output_survives_a_messenger() {
    use daal_wizard::commands::copy_pasteable;

    let ctx = make_ctx();
    let want = fixture("valid-v2.sbp");
    let operator_id = seed_signed_operator(&ctx);
    std::fs::write(
        ctx.staging_dir.join(format!("{operator_id}.shared.sbp")),
        &want,
    )
    .expect("stage");

    let text = copy_pasteable(&ctx, operator_id, "shared").expect("copy_pasteable");

    // Surrounding prose, and the bidi marks an RTL client sprinkles
    // around a latin blob — the realistic shape of "I pasted the whole
    // message the sender sent me".
    let mangled = format!("\u{200f}سلام، این را بگیر:\u{200e}\n\n{text}\n\nمرسی");
    let got = decode_pasted(&mangled).expect("a real chat message must still decode");
    assert_eq!(got.bytes, want);
    assert_eq!(got.kind, PastedKind::Sbp);
}

/// Email-style `>` quoting breaks every line into its own run, so the
/// longest-run heuristic sees one 76-character line rather than the
/// bundle. That must REFUSE, not import the fragment it can see: a
/// partial bundle that parsed would be the worst outcome available.
///
/// This is a property of the decoder worth pinning down rather than a
/// gap to close — the safe answer to ambiguous input is no answer.
#[test]
fn a_quote_prefixed_paste_is_refused_rather_than_half_imported() {
    use daal_wizard::commands::copy_pasteable;

    let ctx = make_ctx();
    let want = fixture("valid-v2.sbp");
    let operator_id = seed_signed_operator(&ctx);
    std::fs::write(
        ctx.staging_dir.join(format!("{operator_id}.shared.sbp")),
        &want,
    )
    .expect("stage");

    let text = copy_pasteable(&ctx, operator_id, "shared").expect("copy_pasteable");
    let quoted = text
        .lines()
        .map(|l| format!("> {l}"))
        .collect::<Vec<_>>()
        .join("\n");

    match decode_pasted(&quoted) {
        Err(_) => {} // the only acceptable outcome
        Ok(got) => panic!(
            "a quote-prefixed paste decoded to {} bytes instead of being refused",
            got.bytes.len()
        ),
    }
}

/// `copy_pasteable` must refuse an artifact name it does not know rather
/// than guessing. The two artifacts differ in exactly the way that
/// matters — "shared" carries credentials and can connect, "raw" cannot
/// — so a silent default would either leak credentials or hand out a
/// pack the receiver can never use, with no visible difference.
#[test]
fn copy_pasteable_refuses_an_unknown_artifact() {
    use daal_wizard::commands::copy_pasteable;

    let ctx = make_ctx();
    let operator_id = seed_signed_operator(&ctx);
    std::fs::write(
        ctx.staging_dir.join(format!("{operator_id}.shared.sbp")),
        fixture("valid-v2.sbp"),
    )
    .expect("stage");

    let err = copy_pasteable(&ctx, operator_id, "everything")
        .expect_err("an unknown artifact name must be refused, not defaulted");
    assert!(
        format!("{err}").contains("everything"),
        "the refusal should name the artifact it rejected, got: {err}"
    );

    // And "raw" — a real name — must resolve to a DIFFERENT file, not
    // silently fall back to the shared one.
    assert!(
        copy_pasteable(&ctx, operator_id, "raw").is_err(),
        "raw must resolve to <id>.sbp, which was never staged here"
    );
}
