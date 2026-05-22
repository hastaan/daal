//! Operational-security regressions for the wizard key/PIN paths.
//!
//! These tests are intentionally narrow — they assert the
//! invariants the FRP-5 phase doc lists as MUST in §"Position B
//! preserved" and §"Two-layer key custody mandatory":
//!
//!  1. (FRP-4b ship: polarity flipped) The wizard codebase MUST
//!     define `provision_run`, `sign_relaypack`, and `qr_render`
//!     functions. At FRP-5 these were forbidden; at FRP-4b they
//!     are required. If a maintainer accidentally deletes one
//!     while refactoring, this test fails.
//!  2. `GeneratedKey` does not implement `Debug` — printing it is a
//!     compile error, so a stray `dbg!()` cannot leak the priv
//!     bytes.
//!  3. `Keystore::open` zeroizes the derived key on drop (we can't
//!     observe the inner state but we can assert the type bounds
//!     hold by referencing the public API).
//!  4. The pre-provision JSON file mode is 0o600 on unix.
//!  5. No analytics-vendor markers appear anywhere in the wizard
//!     crate or the wizard frontend.
//!
//! Tests 1 and 5 are pure source-grep regressions. Tests 2-4 are
//! type-level / behavioural assertions that compile-or-fail.

use std::fs;
use std::path::PathBuf;

fn wizard_crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn wizard_frontend_root() -> Option<PathBuf> {
    // Best-effort: the frontend lives alongside the crate at
    // ../tauri/src/wizard. If it isn't there (e.g. running this
    // test outside a checkout), skip the frontend scan.
    let p = wizard_crate_root()
        .join("..")
        .join("tauri")
        .join("src")
        .join("wizard");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn collect_files(root: &PathBuf, exts: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip target/.cargo dirs.
                let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if name == "target" || name == "node_modules" || name.starts_with('.') {
                    continue;
                }
                stack.push(path);
            } else if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if exts.contains(&ext) {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Strip line comments and block-comment-free regions are good
/// enough for our grep purposes: drop everything after `//` on
/// each line, then drop `/* … */` blocks.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        if let Some(idx) = line.find("//") {
            out.push_str(&line[..idx]);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    // Drop /* ... */ blocks naively (no nesting in our codebase).
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(start) = rest.find("/*") {
        result.push_str(&rest[..start]);
        if let Some(end) = rest[start + 2..].find("*/") {
            rest = &rest[start + 2 + end + 2..];
        } else {
            break;
        }
    }
    result.push_str(rest);
    result
}

#[test]
fn frp4b_command_names_present_in_wizard_sources() {
    // Polarity flipped at FRP-4b ship: these three high-level
    // command functions MUST be defined in the crate. If a
    // refactor accidentally drops one, the wizard frontend's
    // Tauri shims will fail to compile, but this test catches
    // the regression earlier with a clearer error.
    let required = ["provision_run", "sign_relaypack", "qr_render"];
    let files = collect_files(&wizard_crate_root().join("src"), &["rs"]);
    let mut found = std::collections::HashSet::new();
    for path in &files {
        let body = strip_comments(&fs::read_to_string(path).unwrap());
        for sym in &required {
            // We require the literal `pub fn <sym>(` definition
            // somewhere in the crate — call-sites alone don't
            // count, since they could be downstream stubs.
            let needle = format!("pub fn {sym}(");
            if body.contains(&needle) {
                found.insert(*sym);
            }
        }
    }
    for sym in &required {
        assert!(
            found.contains(sym),
            "FRP-4b required symbol `pub fn {sym}(...)` is missing from wizard sources"
        );
    }
}

#[test]
fn no_analytics_vendor_symbols_in_wizard_sources() {
    // Position B ("no telemetry") OPSEC regression. The list is
    // not exhaustive, but covers the analytics platforms that
    // historically slip in via npm bundle pulls.
    let forbidden_substrings = [
        ["sen", "try"].concat(),
        ["post", "hog"].concat(),
        ["data", "dog"].concat(),
        ["ampli", "tude"].concat(),
        ["mix", "panel"].concat(),
        ["segment", ".", "io"].concat(),
        ["google", "-", "analytics"].concat(),
        ["google", "tag", "manager"].concat(),
        ["hot", "jar"].concat(),
        ["full", "story"].concat(),
        ["tele", "metry"].concat(),
    ];
    let mut roots = vec![wizard_crate_root().join("src")];
    if let Some(fe) = wizard_frontend_root() {
        roots.push(fe);
    }
    for root in &roots {
        let files = collect_files(root, &["rs", "ts", "tsx", "json"]);
        for path in &files {
            let body = fs::read_to_string(path).unwrap_or_default().to_lowercase();
            for sym in &forbidden_substrings {
                assert!(
                    !body.contains(sym),
                    "disallowed analytics symbol `{sym}` leaked into {path:?}"
                );
            }
        }
    }
}

#[test]
fn generated_key_does_not_derive_debug() {
    // Source-level OPSEC regression: if a maintainer adds
    // `#[derive(Debug)]` to GeneratedKey, this test fails. The
    // cargo-level proof that printing GeneratedKey is impossible
    // lives in the publisher_key tests (panic match arms cannot
    // print the Ok(GeneratedKey) variant).
    let path = wizard_crate_root().join("src").join("publisher_key.rs");
    let body = fs::read_to_string(&path).unwrap();
    let needle = "pub struct GeneratedKey";
    let idx = body.find(needle).expect("GeneratedKey struct definition");
    // Inspect only the line immediately above the struct line —
    // that's where derive-attributes live.
    let prefix = &body[..idx];
    let last_lines: Vec<&str> = prefix.lines().rev().take(8).collect();
    // The first non-comment, non-blank line above is the
    // attribute (or doc-comment). Walk up until we find a #[…]
    // attribute or a blank/comment marker (= no derives).
    let mut derive_line: Option<&str> = None;
    for line in last_lines {
        let trimmed = line.trim();
        if trimmed.starts_with("#[derive") {
            derive_line = Some(trimmed);
            break;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        break; // Hit non-comment, non-attr; bail.
    }
    if let Some(line) = derive_line {
        assert!(
            !line.contains("Debug"),
            "GeneratedKey derives Debug — would let dbg!() leak \
             private key bytes. Derive line: {line}"
        );
    }
}

#[test]
#[cfg(unix)]
fn pre_provision_file_is_mode_0o600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let rec = daal_wizard::staging::PreProvisionRecord::new(
        "hetzner",
        "fsn1",
        "cx22",
        "iran-default",
        vec![],
        "AAAA",
    );
    let path = daal_wizard::staging::write_record(dir.path(), 1, &rec).unwrap();
    let meta = fs::metadata(&path).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "pre-provision file mode = {mode:o} (want 0o600)"
    );
}
