# daal-platform — Tauri Mobile plugin (planned)

This directory holds the platform-native code that the WebView UI
cannot do itself: Android `VpnService` lifecycle + tun fd ownership,
iOS `NetworkExtension` packet-tunnel provider, biometric unlock, app
group / shared keychain.

## Status

**Source preservation only.** The Kotlin / Swift files here are
copied from the retired `client-android/` and `client-ios/` trees so
their hard-won implementations are not lost. They are not yet wired
into a Tauri Mobile plugin (no `Cargo.toml`, no `tauri-build`
plugin manifest yet).

When mobile ships, this directory grows into:

```
plugins/daal-platform/
├── Cargo.toml                # Rust plugin crate
├── src/
│   ├── lib.rs                # tauri::plugin::Builder
│   ├── commands.rs           # #[tauri::command] surfaces
│   └── models.rs
├── android/
│   ├── build.gradle.kts
│   ├── src/main/java/
│   │   └── DaalVpnService.kt
│   └── src/main/AndroidManifest.xml
├── ios/
│   ├── Package.swift
│   └── Sources/
│       └── PacketTunnelProvider.swift
└── permissions/
    └── default.toml          # capability manifest for the plugin
```

See `https://v2.tauri.app/develop/plugins/develop-mobile/` for the
Tauri Mobile plugin authoring guide.

## Files currently preserved

| Path                                         | Origin                                                                            |
|----------------------------------------------|-----------------------------------------------------------------------------------|
| `android/DaalVpnService.kt`                  | `client-android/app/src/main/java/ai/daal/app/vpn/DaalVpnService.kt`              |
| `ios/PacketTunnelProvider.swift`             | `client-ios/DaalTunnel/Sources/PacketTunnelProvider.swift`                        |

Additional preservation candidates (TBD when the plugin lands):
- iOS biometrics + keychain helpers
- Android intent / share / QR receivers
- Android permission flows
