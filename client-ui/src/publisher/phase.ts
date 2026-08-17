/**
 * The RelayPack phase, TS side.
 *
 * One value, declared once in Go at `bundle/go/phase/phase.go`
 * (`const Current`), restated in Rust at
 * `client-shell/tauri/daal-wizard/src/phase.rs`, and restated here.
 * Three restatements is two too many, but the value crosses two
 * process boundaries as a plain string (`wizard_sign_relaypack`'s
 * `phase` argument → `daal-deploy bind-and-sign --phase`), so there is
 * no shared symbol to import.
 *
 * `tools/check-phase.sh` compares all three at build time and fails the
 * push if they disagree. It also forbids a phase literal anywhere else,
 * which is what let the wizard sign at V1.6 while a rotation re-signed
 * at V1.5 and the on-device importer validated at V1.5 — three
 * different answers to one question.
 *
 * Every call site that needs a phase imports THIS constant.
 */
export const RELAYPACK_PHASE = 'V1.6';
