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
pub mod keystore;
pub mod modifiers_i18n;
pub mod operator_db;
pub mod publisher_key;
pub mod recipient_book;
pub mod recipient_identity;
pub mod recipient_sbpx;
pub mod staging;
