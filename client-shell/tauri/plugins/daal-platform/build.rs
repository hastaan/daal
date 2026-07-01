// build.rs — runs tauri-plugin's build helper to:
//   1. discover the commands declared below (vpn_start / vpn_stop /
//      vpn_status),
//   2. emit the JSON-schema for permissions/default.toml,
//   3. pick up the Android Gradle module under ./android/ when the
//      target is Android.

const COMMANDS: &[&str] = &["vpn_start", "vpn_stop", "vpn_status"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .build();
}
