// Daal — Tauri 2 desktop entrypoint.
//
// All logic lives in `lib.rs`; this file is the thin platform shim.
// The cargo bin name is `daal-desktop` (set in Cargo.toml).
//
// The cfg attribute hides the console window on Windows in release.
//
// Mobile builds (Android/iOS) do NOT run main(); Tauri's
// `mobile_entry_point` macro on `lib::run` generates the JNI / Swift
// bridge entry. This file is desktop-only.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

#[cfg(desktop)]
fn main() {
    daal_desktop_tauri_lib::run()
}

#[cfg(mobile)]
fn main() {}
