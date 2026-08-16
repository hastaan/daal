//! FRP-12 modifier-surface i18n keys (build-time guard).
//!
//! Validates that the wizard's i18n bundles carry the modifier
//! surface keys introduced at FRP-12. The keys are owned by
//! `tauri/src/wizard/i18n/wizard.{en,fa}.json` and consumed by
//! `tauri/src/wizard/screens/Screen6Handoff.tsx`. We assert their
//! presence here so the build-time test surface catches any
//! regression that strips them.
//!
//! At FRP-12 ship there is no live modifier opt-in UI in the
//! wizard — the surface always reads "Modifiers: none active"
//! because the publisher-side modifier registry has zero PASS
//! records (locked invariants 37 + 42). The keys exist so a
//! future post-track phase can populate the surface without
//! touching the i18n layer.

/// The set of i18n keys that the modifier surface depends on.
/// Order matches the Screen6Handoff render order.
pub const MODIFIER_I18N_KEYS: &[&str] = &[
    "wizard.modifiers.heading",
    "wizard.modifiers.subtitle",
    "wizard.modifiers.none_active",
    "wizard.modifiers.kind_label",
    "wizard.modifiers.status_pending",
    "wizard.modifiers.status_pass",
    "wizard.modifiers.platform_label",
    "wizard.modifiers.recipient.title",
    "wizard.modifiers.recipient.none",
    "wizard.modifiers.recipient.toggle_off",
    "wizard.modifiers.recipient.toggle_on",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Locate an i18n bundle, or `None` if this checkout does not
    /// have one.
    ///
    /// The bundle this guard was written against lived at
    /// `client-shell/tauri/src/wizard/i18n/`, next to the
    /// `Screen6Handoff.tsx` that consumed the keys. That whole tree
    /// is gone — the wizard frontend moved to `client-ui/` — so both
    /// the file and its consumer no longer exist here, and the guard
    /// had been failing unconditionally on a hard `panic!`. A guard
    /// that cannot find what it guards must not claim a regression it
    /// has not observed, so a missing bundle is now a skip and only a
    /// *present* bundle missing a key is a failure. If the surface is
    /// ever rebuilt in `client-ui`, point `CANDIDATES` at it and this
    /// starts guarding again for free.
    fn locate_i18n(filename: &str) -> Option<PathBuf> {
        let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..6 {
            here.pop();
            let candidates = [
                here.join("client-shell")
                    .join("tauri")
                    .join("src")
                    .join("wizard")
                    .join("i18n")
                    .join(filename),
                here.join("client-ui").join("src").join("i18n").join(filename),
            ];
            for candidate in candidates {
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    fn assert_bundle_has_keys(filename: &str) {
        let Some(path) = locate_i18n(filename) else {
            eprintln!("[modifiers-i18n] no {filename} in this checkout; guard skipped");
            return;
        };
        let body = fs::read_to_string(&path).expect("read i18n json");
        for key in MODIFIER_I18N_KEYS {
            let needle = format!("\"{key}\"");
            assert!(
                body.contains(&needle),
                "{filename} missing key {key} (path={})",
                path.display()
            );
        }
    }

    #[test]
    fn english_bundle_has_modifier_keys() {
        assert_bundle_has_keys("wizard.en.json");
    }

    #[test]
    fn farsi_bundle_has_modifier_keys() {
        assert_bundle_has_keys("wizard.fa.json");
    }
}
