//! FRP-5 desktop-wizard backend.
//!
//! The wizard walks a Diaspora Helper through:
//!
//!   0. Welcome.
//!   1. Cloud-provider token paste + PIN set + live pricing lookup.
//!   2. Region / server-type / toolbox-profile choice.
//!   3. Publisher key creation (or import) + fingerprint reveal.
//!   4. Provisioning shell      — DISABLED at FRP-5; wired live at FRP-4b.
//!   5. RelayPack signing shell — DISABLED at FRP-5; wired live at FRP-4b.
//!   6. RelayPack handoff shell — DISABLED at FRP-5; wired live at FRP-4b.
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

pub mod cli_bridge;
pub mod commands;
pub mod device_custody;
pub mod keystore;
pub mod modifiers_i18n;
pub mod operator_db;
pub mod pin_lockout;
pub mod publisher_key;
pub mod recipient_book;
pub mod recipient_identity;
pub mod recipient_sbpx;
pub mod staging;
