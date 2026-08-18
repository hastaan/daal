# tauri-plugin-daal-platform

**Status: active plugin (Phase 45).**

Daal's mobile-only platform glue. On Android the plugin owns the
`VpnService` lifecycle and the Kotlin → JNI → engine ABI bridge that
hands the TUN file descriptor to libdaalcore's in-process sing-box
driver. On desktop the plugin's command surface is a deterministic
no-op so the same frontend bindings work everywhere.

**Desktop has no data plane.** The `daal-tun-helper` SCM_RIGHTS path is
built but has no caller (`daal_desktop_core::commands::deliver_tun_fd`
is dead code — `tools/check-plumbing.mjs` reports it), and every desktop
`libdaalcore` is compiled `-tags cshared` with no `singbox`, so the
linked driver is `engine.Stub`. Since this wave the engine refuses
`engine_set_route` on such a build (`core/abi/dataplane.go`) rather than
letting the Stub publish a "Connected" event nothing produced. See
`docs/platform-reality.md`.

## File layout

```
plugins/daal-platform/
├── Cargo.toml                # Rust plugin crate (path-dep from src-tauri)
├── build.rs                  # tauri-plugin's command-discovery shim
├── src/
│   ├── lib.rs                # plugin init + PlatformHandle facade
│   ├── commands.rs           # #[tauri::command] surface (vpn_*)
│   ├── error.rs              # Error / Result types
│   ├── mobile.rs             # Tauri Mobile registration (Android)
│   └── models.rs             # request/response shapes
├── permissions/
│   └── default.toml          # default capability set
├── android/
│   ├── build.gradle.kts      # Android lib module
│   ├── proguard-rules.pro    # internal R8 rules
│   ├── consumer-rules.pro    # forwarded to host app's R8
│   ├── settings.gradle       # pulls :tauri-android via .tauri/
│   └── src/main/
│       ├── AndroidManifest.xml          # merges VPN <service> + perms into host
│       └── java/org/daal/desktop/
│           ├── platform/
│           │   ├── DaalPlatformPlugin.kt   # @TauriPlugin entry point
│           │   └── DaalCoreBridge.kt       # JNI surface → libdaalcore.so
│           └── vpn/
│               └── DaalVpnService.kt       # VpnService lifecycle
└── ios/
    └── PacketTunnelProvider.swift          # preserved from client-ios; not yet wired
```

## How the lifecycle flows

1. UI invokes `plugin:daal-platform|vpn_start` with the chosen
   `route_id`.
2. `DaalPlatformPlugin.vpnStart` calls `VpnService.prepare(activity)`;
   if a consent Activity is required, the plugin starts it via
   `startActivityForResult` and resumes from `@ActivityCallback
   vpnConsentResult` once the user accepts.
3. After consent, the plugin starts `DaalVpnService` as a foreground
   service.
4. `DaalVpnService` registers the protect callback (so the engine's
   upstream sockets escape the TUN), then calls `Builder.establish()`
   and hands the resulting fd to the engine via
   `DaalCoreBridge.setTunFd` — which JNIs into the Rust shim that
   forwards to `engine_set_tun_fd`.
5. `DaalCoreBridge.setRoute(routeId)` activates the route on the
   in-process driver.
6. `vpn_stop` (or the system's `onRevoke`) tears down in reverse:
   `clearRoute → clearTunFd → stopForeground`.

## Manifest merging

`android/src/main/AndroidManifest.xml` is the source of truth for
the VPN-related permissions + service registration. It merges into
the app's regenerated `gen/android/.../AndroidManifest.xml` at
Gradle build time. This indirection is required because `gen/android/`
is `.gitignore`'d.

## Native symbols

The plugin's JNI bridge declares the following external methods on
`org.daal.desktop.platform.DaalCoreBridge`:

| Kotlin method                        | JNI symbol (implemented in src-tauri lib.rs)                                    | Engine ABI |
|--------------------------------------|----------------------------------------------------------------------------------|------------|
| `setTunFd(fd: Int)`                  | `Java_org_daal_desktop_platform_DaalCoreBridge_setTunFd`                         | `engine_set_tun_fd`             |
| `clearTunFd()`                       | `Java_org_daal_desktop_platform_DaalCoreBridge_clearTunFd`                       | `engine_clear_tun_fd`           |
| `registerProtectCallback()`          | `Java_org_daal_desktop_platform_DaalCoreBridge_registerProtectCallback`          | `engine_register_protect_callback` |
| `setRoute(routeId: String)`          | `Java_org_daal_desktop_platform_DaalCoreBridge_setRoute`                         | `engine_set_route`              |
| `clearRoute()`                       | `Java_org_daal_desktop_platform_DaalCoreBridge_clearRoute`                       | `engine_clear_route`            |

The protect callback uses a Rust C trampoline (`protect_trampoline` in
`src-tauri/src/lib.rs`) that the engine driver invokes with each fresh
upstream socket; the trampoline JNIs into
`DaalCoreBridge.invokeProtect(fd)` which delegates to
`VpnService.protect(fd)` via the closure DaalVpnService stored before
the first dial.
