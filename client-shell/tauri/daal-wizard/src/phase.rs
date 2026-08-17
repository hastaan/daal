//! The RelayPack phase, Rust side.
//!
//! There is exactly one phase value in this repo and it is declared in
//! Go, at `bundle/go/phase/phase.go` (`const Current`). Everything that
//! signs, validates, or explains a RelayPack reads it.
//!
//! This crate cannot import that constant — it shells out to
//! `daal-deploy bind-and-sign` over a `--phase` flag, which is a string
//! on the wire. So the value is restated here ONCE, and a test asserts
//! byte-equality against the Go source. That is what stops the drift
//! this module exists to prevent: before it, `commands.rs` re-signed
//! rotations at `"V1.5"` while `PublisherWizard.tsx` signed the initial
//! pack at `"V1.6"`, so a rotation silently downgraded the pack's phase
//! and re-closed the two gates FRP-8 had opened.
//!
//! If you change the Go constant, this test fails until you change this
//! line too — which is the whole design.

/// The phase every `bind-and-sign` invocation from this crate passes.
/// Mirrors `daal/bundle-go/phase.Current`; kept honest by
/// `tests::rust_phase_matches_go_constant` below.
pub const RELAYPACK_PHASE: &str = "V1.6";

#[cfg(test)]
mod tests {
    use super::RELAYPACK_PHASE;

    /// The Go source is the authority. We parse it at test-compile
    /// time rather than at runtime so this cannot be skipped by a
    /// missing-file branch that quietly passes.
    const GO_PHASE_SRC: &str = include_str!("../../../../bundle/go/phase/phase.go");

    /// Extract the string literal a `NAME Phase = "…"` line binds.
    fn go_const(name: &str) -> String {
        for line in GO_PHASE_SRC.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix(name) {
                let rest = rest.trim_start();
                if !rest.starts_with("Phase =") {
                    continue;
                }
                if let Some(open) = rest.find('"') {
                    if let Some(close) = rest[open + 1..].find('"') {
                        return rest[open + 1..open + 1 + close].to_string();
                    }
                }
            }
        }
        panic!("no `{name} Phase = \"…\"` line in bundle/go/phase/phase.go");
    }

    /// `const Current = V16` — resolve the alias to its literal.
    fn go_current() -> String {
        let alias = GO_PHASE_SRC
            .lines()
            .find_map(|l| l.trim().strip_prefix("const Current = "))
            .map(|s| s.trim().to_string())
            .expect("no `const Current = …` line in bundle/go/phase/phase.go");
        go_const(&alias)
    }

    #[test]
    fn rust_phase_matches_go_constant() {
        let want = go_current();
        assert_eq!(
            RELAYPACK_PHASE, want,
            "RELAYPACK_PHASE drifted from bundle/go/phase.Current — \
             update client-shell/tauri/daal-wizard/src/phase.rs (and the \
             TS mirror in client-ui/src/publisher/phase.ts)"
        );
    }
}
