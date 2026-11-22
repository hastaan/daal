//! Network test, the publisher's half (specs/field-probe-v2.md,
//! specs/sealed-report-v1.md).
//!
//! A relay becomes the **Test relay** when its pack is signed with the
//! publisher's report address (`bind-and-sign --report-to daal1…`):
//! every route then carries `_report_to`, and a person who runs the
//! network test seals the result to that address. Only the publisher
//! who holds the matching key can open it.
//!
//! The key is made on this phone by the publisher library
//! (`daal-deploy report-keygen --out -`, so it never touches a file) and
//! kept in device custody beside the relay's other secrets:
//!
//!   * `daal.report.<id>.key`     — the 32-byte X25519 private key while
//!     the relay IS the Test relay. Its presence is the switch: the next
//!     signature of this relay's pack carries the address.
//!   * `daal.report.<id>.retired` — the same key after "Stop using as
//!     test relay": reports made before still open, and turning it on
//!     again brings back the same address.
//!
//! The address is never stored: it is derived from the key each time,
//! and the address the library printed is checked against it once.
//!
//! Both aliases are in the publisher backup when they exist
//! ([`optional_aliases`]), and only then — a publisher who never made a
//! report key keeps the same backup digest.
//!
//! Reports are UNTRUSTED INPUT (age says nothing about who sealed one;
//! anyone holding the address can make one). The opener validates each
//! against schema v2 before anything is shown.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli_bridge::{verb_unknown, BridgeError};
use crate::commands::{coded, Result, WizardCtx, WizardError, E_CUSTODY_BACKEND, E_CUSTODY_LOCKED, E_DEPLOY_TOO_OLD};
use crate::device_custody::CustodyError;

/// The file is not a sealed network-test report.
pub const E_REPORT_NOT_A_REPORT: &str = "E_REPORT_NOT_A_REPORT";
/// No report key on this phone opens it (sealed to another publisher,
/// or to a key this phone never had).
pub const E_REPORT_NOT_OURS: &str = "E_REPORT_NOT_OURS";
/// This phone has never made a report key.
pub const E_REPORT_NO_KEY: &str = "E_REPORT_NO_KEY";
/// The file could not be read.
pub const E_REPORT_READ_FAILED: &str = "E_REPORT_READ_FAILED";
/// "Use as test relay" on a relay people connect with (someone not
/// removed, or an everyone file), without the second confirmation. The
/// test makes unusual connections to the relay's address, so it must be
/// a relay of its own (specs/relaypack-v1.md, the separate-address rule).
pub const E_TEST_RELAY_IN_USE: &str = "E_TEST_RELAY_IN_USE";

/// `DSBR 0x00 0x01` (specs/sealed-report-v1.md): never a pack.
const REPORT_MAGIC: &[u8] = b"DSBR\x00\x01";
/// A sealed report is a 16 KiB-padded JSON plus age overhead; anything
/// far larger is not one.
const MAX_REPORT_BYTES: u64 = 256 * 1024;

pub fn key_alias(operator_id: i64) -> String {
    format!("daal.report.{operator_id}.key")
}

pub fn retired_alias(operator_id: i64) -> String {
    format!("daal.report.{operator_id}.retired")
}

/// The report aliases a relay MAY have. Included in a backup only when
/// present; accepted in a backup for any relay it names.
pub(crate) fn optional_aliases(operator_id: i64) -> [String; 2] {
    [key_alias(operator_id), retired_alias(operator_id)]
}

/// The `daal1…` address of a stored 32-byte key.
fn address_of(key: &[u8]) -> Result<String> {
    if key.len() != 32 {
        return Err(coded(E_CUSTODY_BACKEND, "the stored report key is not valid"));
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    raw.copy_from_slice(key);
    let secret = x25519_dalek::StaticSecret::from(*raw);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(daal_recipient_addr::encode(&public.to_bytes()))
}

fn custody_err(e: CustodyError) -> WizardError {
    match e {
        CustodyError::Locked => coded(E_CUSTODY_LOCKED, "unlock this device's key store to continue"),
        other => coded(E_CUSTODY_BACKEND, other),
    }
}

/// The key under `alias`, `None` when there is none.
fn read(ctx: &WizardCtx, alias: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match ctx.custody.get(alias) {
        Ok(v) => Ok(Some(Zeroizing::new(v))),
        Err(CustodyError::NotFound(_)) => Ok(None),
        Err(e) => Err(custody_err(e)),
    }
}

/// What the next signature of this relay's pack carries as
/// `--report-to`: the address of its live report key, or `None`.
pub(crate) fn report_to_for_signing(ctx: &WizardCtx, operator_id: i64) -> Result<Option<String>> {
    match read(ctx, &key_alias(operator_id))? {
        Some(k) => address_of(&k).map(Some),
        None => Ok(None),
    }
}

/// Is this relay the Test relay, as far as its signed pack goes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TestRelayStatus {
    pub operator_id: i64,
    /// The live key exists: the pack is (or, after a failed signature,
    /// will next be) signed with the report address.
    pub is_test_relay: bool,
    /// A key was made for this relay at some point (live or retired).
    pub has_key: bool,
    /// People on this relay who are not removed. More than none means
    /// people connect with it: the sheet says so before anything runs.
    pub people_on_relay: usize,
    /// An everyone file was made for this relay.
    pub everyone_file: bool,
}

/// Who connects with this relay: people not removed, and whether an
/// everyone file exists.
fn in_use(ctx: &WizardCtx, operator_id: i64) -> Result<(usize, bool)> {
    let people = ctx
        .db
        .list_recipients(operator_id)
        .map_err(WizardError::Db)?
        .iter()
        .filter(|r| r.revoked_at_unix == 0)
        .count();
    let everyone = ctx.staging_dir.join(format!("{operator_id}.shared.sbp")).exists();
    Ok((people, everyone))
}

pub fn status(ctx: &WizardCtx, operator_id: i64) -> Result<TestRelayStatus> {
    let live = read(ctx, &key_alias(operator_id))?.is_some();
    let retired = !live && read(ctx, &retired_alias(operator_id))?.is_some();
    let (people_on_relay, everyone_file) = in_use(ctx, operator_id)?;
    Ok(TestRelayStatus {
        operator_id,
        is_test_relay: live,
        has_key: live || retired,
        people_on_relay,
        everyone_file,
    })
}

/// What "Use as test relay" / "Stop using as test relay" did.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TestRelaySet {
    pub operator_id: i64,
    pub is_test_relay: bool,
    /// A new key was made (false when an earlier one was brought back).
    pub key_made: bool,
    /// People on this relay who hold a file made before this change and
    /// need a new one (not counting removed people).
    pub people_to_send: usize,
    /// An everyone file exists and was left exactly as it was: it keeps
    /// working and does not offer the test. It is never made again here
    /// — making it again gives the shared user new keys, and every phone
    /// on the old everyone file would stop connecting.
    pub everyone_file_kept: bool,
    /// The refresh note naming the new pack was accepted (people whose
    /// apps can refresh get it without a new file).
    pub refresh_note_published: bool,
}

/// Move a key between the two aliases.
fn move_key(ctx: &WizardCtx, from: &str, to: &str) -> Result<()> {
    let Some(k) = read(ctx, from)? else { return Ok(()) };
    ctx.custody.put(to, &k).map_err(custody_err)?;
    ctx.custody.forget(from).map_err(custody_err)?;
    Ok(())
}

fn map_keygen_err(e: BridgeError) -> WizardError {
    if verb_unknown(&e) {
        return coded(E_DEPLOY_TOO_OLD, "the setup helper bundled with this app cannot make a report key");
    }
    WizardError::Pricing(e.to_string())
}

/// Make the live key exist: the live one, else the retired one brought
/// back, else a new one from the publisher library. Returns whether a
/// new key was made.
fn ensure_live_key(ctx: &WizardCtx, operator_id: i64) -> Result<bool> {
    let live = key_alias(operator_id);
    if read(ctx, &live)?.is_some() {
        return Ok(false);
    }
    let retired = retired_alias(operator_id);
    if read(ctx, &retired)?.is_some() {
        move_key(ctx, &retired, &live)?;
        return Ok(false);
    }
    let made = ctx.cli.run_report_keygen().map_err(map_keygen_err)?;
    let hex_key = made.private_key_hex.trim();
    let mut raw = Zeroizing::new([0u8; 32]);
    if hex_key.len() != 64 || hex::decode_to_slice(hex_key, &mut raw[..]).is_err() {
        return Err(WizardError::Pricing("report-keygen printed a key that is not 64 hex".into()));
    }
    // The library's address and the key's own must be the same: a
    // mismatch would seal every report to a key nobody holds.
    if address_of(&raw[..])? != made.report_to.trim() {
        return Err(WizardError::Pricing("report-keygen printed an address that is not its key's".into()));
    }
    ctx.custody.put(&live, &raw[..]).map_err(custody_err)?;
    Ok(true)
}

/// "Use as test relay" (`on`) or "Stop using as test relay".
///
/// Signs the relay's pack again — with `_report_to` on every route, or
/// without — through the same path every re-sign takes
/// ([`crate::relay_identity::resign_and_republish`]: the relay is asked
/// who it is first, and the refresh note is published when the pack has
/// refresh addresses). Nothing on the relay changes: no user is added,
/// removed or given new keys, so every file already handed out (each
/// person's and the everyone file) keeps working exactly as before; it
/// just does not offer the test. The result counts who needs a new file.
///
/// Turning it ON for a relay people connect with (anyone not removed, or
/// an everyone file) is refused with [`E_TEST_RELAY_IN_USE`] unless
/// `confirm_in_use`: the test makes unusual connections to the relay's
/// address, and the sheet has to have said so, with the count, first.
/// Turning it off is never refused.
///
/// A signature that fails before anything was recorded puts the switch
/// back, so the key's place says what the signed pack carries.
pub fn set_test_relay(ctx: &WizardCtx, operator_id: i64, on: bool, confirm_in_use: bool) -> Result<TestRelaySet> {
    // A restore that is not finished: no publisher operation runs.
    crate::publisher_backup::ensure_restore_finished(ctx)?;
    let before = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let (people, everyone) = in_use(ctx, operator_id)?;
    if on && !confirm_in_use && (people > 0 || everyone) {
        return Err(coded(
            E_TEST_RELAY_IN_USE,
            format!(
                "{people} people connect with this relay{}; use a separate relay for testing",
                if everyone { " and it has an everyone file" } else { "" }
            ),
        ));
    }
    let live = key_alias(operator_id);
    let retired = retired_alias(operator_id);
    // Already in the asked state: still signed again, so a pack that
    // missed an earlier signature is made right.
    let was_live = read(ctx, &live)?.is_some();
    let mut key_made = false;
    if on {
        key_made = ensure_live_key(ctx, operator_id)?;
    } else {
        move_key(ctx, &live, &retired)?;
    }

    let resigned = match crate::relay_identity::resign_and_republish(
        ctx,
        operator_id,
        crate::relay_identity::Freshness::Fresh,
        &mut |_| {},
    ) {
        Ok(r) => r,
        Err(e) => {
            // Put the switch back where the signed pack is — unless the
            // new signature was already recorded (a later step failed):
            // then the pack carries the new state, and so must the key's
            // place, or the next re-sign would silently undo it.
            let recorded = ctx
                .db
                .get(operator_id)
                .map(|after| after.signed_sbp_sha256 != before.signed_sbp_sha256)
                .unwrap_or(false);
            if !recorded {
                if on && !was_live {
                    let _ = move_key(ctx, &live, &retired);
                } else if !on && was_live {
                    let _ = move_key(ctx, &retired, &live);
                }
            }
            return Err(e);
        }
    };

    Ok(TestRelaySet {
        operator_id,
        is_test_relay: on,
        key_made,
        people_to_send: people,
        everyone_file_kept: everyone,
        refresh_note_published: resigned.refresh_note_published,
    })
}

/// `open_report`: decrypt one received report with whichever report key
/// on this phone opens it (every relay's, live or retired) and return
/// the validated v2 JSON exactly as the publisher library printed it.
pub fn open_report(ctx: &WizardCtx, path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    let meta = std::fs::metadata(path).map_err(|e| coded(E_REPORT_READ_FAILED, e))?;
    if meta.len() > MAX_REPORT_BYTES {
        return Err(coded(E_REPORT_NOT_A_REPORT, "the file is too large to be a network test report"));
    }
    let mut head = [0u8; 6];
    let mut f = std::fs::File::open(path).map_err(|e| coded(E_REPORT_READ_FAILED, e))?;
    if f.read_exact(&mut head).is_err() || &head[..] != REPORT_MAGIC {
        return Err(coded(E_REPORT_NOT_A_REPORT, "the file is not a network test report"));
    }
    drop(f);

    let mut keys: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for op in ctx.db.list().map_err(WizardError::Db)? {
        for alias in optional_aliases(op.id) {
            if let Some(k) = read(ctx, &alias)? {
                keys.push(k);
            }
        }
    }
    if keys.is_empty() {
        return Err(coded(E_REPORT_NO_KEY, "this phone has no report key"));
    }
    let mut last = String::new();
    for k in &keys {
        if k.len() != 32 {
            continue;
        }
        let hex_key = Zeroizing::new(hex::encode(&k[..]));
        match ctx.cli.run_report_open(path, &hex_key) {
            Ok(json) => {
                // The opener validated it; a second, shallow look here so
                // nothing that is not one JSON object reaches the page.
                let v: serde_json::Value = serde_json::from_str(&json)
                    .map_err(|_| coded(E_REPORT_NOT_A_REPORT, "the opener printed something that is not a report"))?;
                if !v.is_object() {
                    return Err(coded(E_REPORT_NOT_A_REPORT, "the opener printed something that is not a report"));
                }
                return Ok(v.to_string());
            }
            Err(e) if verb_unknown(&e) => {
                return Err(coded(E_DEPLOY_TOO_OLD, "the setup helper bundled with this app cannot open reports"));
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(coded(E_REPORT_NOT_OURS, if last.is_empty() { "no key on this phone opens it".to_string() } else { last }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_is_the_keys_own() {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        let want = daal_recipient_addr::encode(&public.to_bytes());
        assert_eq!(address_of(&secret.to_bytes()).unwrap(), want);
        assert!(address_of(&[1u8; 31]).is_err());
    }

    #[test]
    fn keygen_output_parses_and_debug_leaves_the_key_out() {
        let r = crate::cli_bridge::ReportKeygenResult::from_json(
            br#"{"report_to":"daal1qqq","private_key_hex":"5ec7e7"}"#,
        )
        .unwrap();
        assert_eq!(r.report_to, "daal1qqq");
        assert_eq!(r.private_key_hex.as_str(), "5ec7e7");
        assert!(!format!("{r:?}").contains("5ec7e7"));
    }

    #[test]
    fn aliases_are_per_relay_and_never_a_signing_key() {
        assert_eq!(key_alias(3), "daal.report.3.key");
        assert_eq!(retired_alias(3), "daal.report.3.retired");
        for a in optional_aliases(7) {
            assert!(!a.starts_with("daal.publisher."));
        }
    }
}
