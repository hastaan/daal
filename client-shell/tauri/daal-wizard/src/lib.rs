//! FRP-5 desktop-wizard backend.
//!
//! The wizard walks a Diaspora Helper through:
//!
//!   1. Cloud-provider token paste + live pricing lookup.
//!   2. Region / server-type / toolbox-profile choice + relay name.
//!   3. Build: publisher keygen, provision, sign, produce the
//!      shareable pack. Then hand off to the relay-detail screen,
//!      which is the permanent home for sharing and recipients.
//!
//! There is no PIN anywhere in that flow. Publisher secrets live
//! under `device_custody` (hardware-backed where the platform has a
//! keystore); `keystore` survives only as the legacy reader for the
//! one-time migration. See the headers of both modules.
//!
//! This crate is workspace-resident so it can be unit-tested
//! without the GTK/webkit toolchain pulled in by Tauri 2. The
//! Tauri shell (`tauri/src-tauri/`) imports this crate for its
//! `#[tauri::command]` glue; FRP-5 commit 3/5 wires the bindings.
//!
//! There is NO `Provider.Provision`, `BindAndSign`, or QR call site
//! anywhere in this module tree — phase doc invariants 25 + 28.
//! The OPSEC test (`tests/key_opsec_test.rs`) greps for either
//! symbol and fails the build if found.

// Optional add-ons (docs/optional-addons-plan.md): the shared ledger
// and plumbing, and one module per add-on. The three per-kind modules
// are stubs that answer E_NOT_BUILT until their lanes land.
pub mod addon_cdn;
pub mod addon_google;
// The update notes: the GitHub account, and the two per-relay carriers
// (through GitHub, through DNS).
pub mod addon_notes;
pub mod addon_standby;
pub mod addons;
pub mod cli_bridge;
pub mod commands;
pub mod device_custody;
// Wave 3 Step 8: the freshness upload — SigV4 + the two static-host
// backends. It is the ONE place this crate opens a socket; everything
// else reaches the network through the `daal-deploy` subprocess.
pub mod freshness;
pub mod hosting_account;
pub mod keystore;
// `modifiers_i18n` is gone. It guarded 11 `wizard.modifiers.*` keys in
// `tauri/src/wizard/i18n/wizard.{en,fa}.json` for
// `tauri/src/wizard/screens/Screen6Handoff.tsx` — a tree that no longer
// exists (the wizard frontend moved to client-ui/, which has neither the
// bundle nor the keys nor a consumer). Its two tests could only ever
// report "skipped", so they were counted as green while asserting
// nothing: a guard that cannot fire is worse than no guard, because it
// makes the suite look like it still covers a surface it does not.
pub mod operator_db;
pub mod phase;
// Publisher-alone wave: what a setup journalled, finishing or deleting
// an interrupted setup and checking the hosting account, the health
// check, and renewing everyone's files after a rebuild.
pub mod provision_journal;
// Backup and restore of everything a publisher needs to carry on from
// another phone: one file, encrypted under twelve recovery words.
pub mod publisher_backup;
pub mod publisher_key;
pub mod recipient_book;
pub mod recipient_identity;
// Wave 4 Step 11: the offline path that survives a channel which bans
// executables and watches entropy — a bundle pasted as text. Sits
// beside `recipient_sbpx` because it hands sealed pastes straight to
// it, and takes the same verification afterwards.
pub mod recipient_paste;
pub mod recipient_sbpx;
// What the relay says it is, and keeping the signed pack true to it:
// the relay is asked before every signature, and a reply that no longer
// matches what the pack commits to signs again.
pub mod relay_health;
pub mod relay_identity;
// Network test: the Test relay's report key, and opening reports.
pub mod report_key;
pub mod relay_rotation;
pub mod renew;
// "New files for everyone" after a removal: the standby code wraps again.
pub mod refile;
pub mod restore_settle;
pub mod setup_recovery;
// "Links for other apps": share links for one person.
pub mod share_links;
#[cfg(test)]
mod publisher_alone_tests;
pub mod staging;

/// Whether `dir` exists (or can be made) and a file can be created in
/// it. The shell uses it to choose a state and a temp directory on
/// devices that give the app no usable HOME or TMPDIR.
pub fn dir_is_writable(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".daal-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// The file that marks a directory as this install's state home. Written
/// once a state directory has been chosen, so a later start never adopts
/// an older directory over one that is in use.
pub const STATE_HOME_MARKER: &str = ".daal-state-home";

/// What [`adopt_earlier_state`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adopted {
    /// `chosen` is already this install's state home, or nothing earlier
    /// holds state: nothing moved.
    Nothing,
    /// An earlier directory was moved into place. A directory that stood
    /// at `chosen` (made by a build that did not look for earlier state)
    /// was kept beside it under `set_aside`.
    Moved { from: std::path::PathBuf, set_aside: Option<std::path::PathBuf> },
    /// An earlier directory holds state but could not be moved: use it
    /// where it is, rather than start empty.
    UseInPlace(std::path::PathBuf),
}

/// Only a directory with the operator database counts: a cache directory
/// that holds nothing but staged temporary files (as on a phone that never
/// kept its state there) must never replace real state.
fn holds_state(dir: &std::path::Path) -> bool {
    dir.join("wizard.db").is_file()
}

/// Bring an earlier install's state to `chosen`.
///
/// Earlier Android builds chose their state directory from $HOME, then
/// the platform data directory, then $TMPDIR. On some phones that last
/// one won: Android points $TMPDIR at the app's CACHE directory, so a
/// Samsung kept its relay keys and operator database in a directory the
/// system may empty when storage runs low. The fix for phones without
/// $HOME (2026-11-19) chose the app's files directory instead, and the
/// Samsung opened empty (seen 2026-11-20). Nothing was lost; this moves
/// it back.
///
/// Rules: if `chosen` carries [`STATE_HOME_MARKER`], it is in use and
/// nothing moves. Otherwise the most recently changed `earlier`
/// directory that holds state is renamed into place; a directory that
/// already stood at `chosen` is renamed aside, never deleted. If the
/// rename fails, the earlier directory is used where it is.
pub fn adopt_earlier_state(chosen: &std::path::Path, earlier: &[std::path::PathBuf], now_unix: u64) -> Adopted {
    if chosen.join(STATE_HOME_MARKER).is_file() {
        return Adopted::Nothing;
    }
    let mtime = |d: &std::path::Path| {
        let db = d.join("wizard.db");
        std::fs::metadata(if db.is_file() { db } else { d.to_path_buf() })
            .and_then(|m| m.modified())
            .ok()
    };
    let best = earlier
        .iter()
        .filter(|d| d.as_path() != chosen && d.is_dir() && holds_state(d))
        .max_by_key(|d| mtime(d));
    let Some(from) = best else { return Adopted::Nothing };
    let mut set_aside = None;
    if chosen.exists() {
        let aside = chosen.with_file_name(format!(
            "{}.superseded-{now_unix}",
            chosen.file_name().and_then(|n| n.to_str()).unwrap_or("daal")
        ));
        if std::fs::rename(chosen, &aside).is_err() {
            return Adopted::UseInPlace(from.clone());
        }
        set_aside = Some(aside);
    }
    if let Some(parent) = chosen.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::rename(from, chosen) {
        Ok(()) => Adopted::Moved { from: from.clone(), set_aside },
        Err(_) => {
            // Put back what was set aside, and run from the earlier place.
            if let Some(a) = &set_aside {
                let _ = std::fs::rename(a, chosen);
            }
            Adopted::UseInPlace(from.clone())
        }
    }
}

/// Mark `dir` as this install's state home (see [`STATE_HOME_MARKER`]).
pub fn mark_state_home(dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join(STATE_HOME_MARKER), b"daal state home\n");
}

#[cfg(test)]
mod adopt_tests {
    use super::*;

    fn with_db(d: &std::path::Path, body: &[u8]) {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("wizard.db"), body).unwrap();
    }

    #[test]
    fn state_left_in_the_cache_directory_is_moved_into_place_and_the_empty_one_kept_aside() {
        let t = tempfile::tempdir().unwrap();
        let chosen = t.path().join("files").join("daal");
        let cache = t.path().join("cache").join("daal");
        with_db(&cache, b"the relay");
        with_db(&chosen, b"empty, made by the build that did not look");
        let r = adopt_earlier_state(&chosen, &[cache.clone()], 42);
        let aside = t.path().join("files").join("daal.superseded-42");
        assert_eq!(r, Adopted::Moved { from: cache.clone(), set_aside: Some(aside.clone()) });
        assert_eq!(std::fs::read(chosen.join("wizard.db")).unwrap(), b"the relay");
        assert_eq!(std::fs::read(aside.join("wizard.db")).unwrap(), b"empty, made by the build that did not look");
        assert!(!cache.exists());
    }

    #[test]
    fn a_state_home_in_use_is_never_replaced() {
        let t = tempfile::tempdir().unwrap();
        let chosen = t.path().join("files").join("daal");
        let cache = t.path().join("cache").join("daal");
        with_db(&cache, b"old");
        with_db(&chosen, b"current");
        mark_state_home(&chosen);
        assert_eq!(adopt_earlier_state(&chosen, &[cache.clone()], 1), Adopted::Nothing);
        assert_eq!(std::fs::read(chosen.join("wizard.db")).unwrap(), b"current");
        assert!(cache.join("wizard.db").is_file());
    }

    #[test]
    fn a_cache_directory_with_only_staged_files_never_replaces_state() {
        let t = tempfile::tempdir().unwrap();
        let chosen = t.path().join("files").join("daal");
        with_db(&chosen, b"the phone's state");
        let cache = t.path().join("cache").join("daal");
        std::fs::create_dir_all(cache.join("staging")).unwrap();
        std::fs::write(cache.join("staging").join("picked.bin"), b"x").unwrap();
        assert_eq!(adopt_earlier_state(&chosen, &[cache], 1), Adopted::Nothing);
        assert_eq!(std::fs::read(chosen.join("wizard.db")).unwrap(), b"the phone's state");
    }

    #[test]
    fn nothing_earlier_means_nothing_moves() {
        let t = tempfile::tempdir().unwrap();
        let chosen = t.path().join("files").join("daal");
        let empty = t.path().join("cache").join("daal");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(adopt_earlier_state(&chosen, &[empty, t.path().join("missing")], 1), Adopted::Nothing);
        assert_eq!(adopt_earlier_state(&chosen, &[chosen.clone()], 1), Adopted::Nothing);
    }

    #[test]
    fn with_no_directory_at_the_chosen_place_the_earlier_one_simply_moves() {
        let t = tempfile::tempdir().unwrap();
        let chosen = t.path().join("files").join("daal");
        let old = t.path().join("tmp").join("daal");
        with_db(&old, b"x");
        assert_eq!(adopt_earlier_state(&chosen, &[old.clone()], 1), Adopted::Moved { from: old, set_aside: None });
        assert!(chosen.join("wizard.db").is_file());
    }
}

#[cfg(test)]
mod writable_dir_tests {
    use super::dir_is_writable;

    #[test]
    fn a_directory_that_can_be_made_and_written_counts_and_leaves_nothing_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("a").join("b");
        assert!(dir_is_writable(&d));
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
    }

    #[test]
    fn a_place_that_cannot_hold_a_directory_does_not_count() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("plain-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(!dir_is_writable(&file.join("daal")));
    }
}

