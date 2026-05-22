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

    fn locate_i18n(filename: &str) -> PathBuf {
        // tests run from client-shell/tauri/daal-wizard/ — walk up to
        // the repo root and resolve the tauri side.
        let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..6 {
            here.pop();
            let candidate = here
                .join("client-shell")
                .join("tauri")
                .join("src")
                .join("wizard")
                .join("i18n")
                .join(filename);
            if candidate.exists() {
                return candidate;
            }
        }
        panic!("could not locate {filename}");
    }

    #[test]
    fn english_bundle_has_modifier_keys() {
        let path = locate_i18n("wizard.en.json");
        let body = fs::read_to_string(&path).expect("read en json");
        for key in MODIFIER_I18N_KEYS {
            let needle = format!("\"{key}\"");
            assert!(
                body.contains(&needle),
                "wizard.en.json missing key {key} (path={})",
                path.display()
            );
        }
    }

    #[test]
    fn farsi_bundle_has_modifier_keys() {
        let path = locate_i18n("wizard.fa.json");
        let body = fs::read_to_string(&path).expect("read fa json");
        for key in MODIFIER_I18N_KEYS {
            let needle = format!("\"{key}\"");
            assert!(
                body.contains(&needle),
                "wizard.fa.json missing key {key} (path={})",
                path.display()
            );
        }
    }
}
