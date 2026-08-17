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

pub mod cli_bridge;
pub mod commands;
pub mod device_custody;
// Wave 3 Step 8: the freshness upload — SigV4 + the two static-host
// backends. It is the ONE place this crate opens a socket; everything
// else reaches the network through the `daal-deploy` subprocess.
pub mod freshness;
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
pub mod publisher_key;
pub mod recipient_book;
pub mod recipient_identity;
pub mod recipient_sbpx;
pub mod relay_rotation;
pub mod staging;
