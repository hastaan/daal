# D-2 desktop tray + tunnel wiring (engineering spec)

This document is the engineering plan for D-2 §3.2 / §4.6 desktop
tray behavior and the wiring between `tun-helper/` and the
Connection screen. It defers the actual native code changes to the
implementation phase but locks down call-site boundaries so the new
React UI (already merged) and the existing Rust desktop core can be
glued together without engine-ABI churn.

## Tray menu

Implemented via `tauri-plugin-tray` in `src-tauri/src/main.rs`.
Menu items, in order:

1. Status indicator (read-only): `Connected via {family}` /
   `Not connected`. Color follows the connection state; no
   localization fallback to the OS.
2. `Connect` / `Disconnect` (mutually exclusive).
3. `Current route: {name}` (read-only).
4. `Mode` ▶ (submenu) Lifeline / Normal / Bulk.
5. `Show Daal` (raises the window).
6. `Quit Daal` (with the §"Quit while connected" confirm flow).

Strings are read from the existing i18n catalog; no hard-coded
strings in `main.rs`.

### Close-to-tray default

- On `WindowEvent::CloseRequested`, intercept and hide the window
  rather than terminate. First time only: emit a tray notification
  (or a one-time toast) with `tray.first_close` copy. Persist the
  "explained" flag in platform-side preferences.

### Quit-while-connected confirm

- `Quit Daal` from the tray, or the OS `Cmd+Q` shortcut, while the
  engine state is `Connected`, opens a confirm modal in the React
  shell. The Tauri side calls a `quit_request` event which the
  React side handles via the existing diagnostics polling loop.

### Sleep/wake reconnect

- Subscribe to `tao::event::Event::Suspended` / `Resumed` (or the
  per-platform sleep notifier on Linux/Windows/macOS) and emit a
  `system_resumed` event. The React shell shows a 2-second
  `conn.reconnecting` banner and the engine's heartbeat loop does
  the actual reconnect.

### Autostart

- Use `tauri-plugin-autostart`. Toggle in Settings → General. On
  first enable, write the platform-native autostart entry:
  - Windows: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
  - Linux: `~/.config/autostart/daal.desktop`
  - macOS: `~/Library/LaunchAgents/org.daal.desktop.plist`

## tun-helper wiring on Connect

`client-desktop/tun-helper/` is the existing Rust crate that opens
`/dev/net/tun` (Linux) or `WinTUN` (Windows) or `utun` (macOS), and
hands the fd back to the unprivileged GUI over an abstract Unix
socket via `SCM_RIGHTS`.

D-2 wires it into the `connect()` Tauri command:

```rust
// src-tauri/src/main.rs (sketch)
#[tauri::command]
async fn connect(route_id: String) -> Result<(), String> {
    // 1. Spawn (or reuse) tun-helper. polkit prompt happens here on
    //    Linux; UAC on Windows; system-extension permission on
    //    macOS.
    let helper = tun_helper::spawn_or_attach()?;

    // 2. Ask the helper for a TUN fd configured for this route.
    let fd = helper.bring_up(&route_id)?;

    // 3. Hand the fd to the engine.
    daal_desktop_core::engine_set_route_with_fd(&route_id, fd).await
        .map_err(|e| e.to_string())?;

    Ok(())
}
```

Per-platform fallbacks (D-2 §4.6.1):

- **Linux:** the `polkit` rule shipped in
  `client-desktop/packaging/` is reused as-is.
- **Windows:** WinTUN is bundled into the NSIS installer; the
  helper does the install / driver-binding on first run.
- **macOS:** if the system-extension flow is not finished by the
  D-2 internal milestone, `connect()` falls back to engine-only
  tunnel and the React shell shows a "macOS: engine-only tunnel"
  banner. This path is acceptable for the internal milestone; D-3
  decides whether it is acceptable for the public release.

## Disconnect and clean-up

- `disconnect()` calls `engine_clear_route` and then asks the
  helper to bring the TUN down. The helper drops the fd; on Linux,
  routes are restored from a snapshot taken at `bring_up` time.

## Concurrency

- The helper is a single-instance daemon per logged-in user. The
  Tauri side spawns it once and keeps the socket open for the
  process lifetime. Reconnects after `Resumed` reuse the existing
  helper.

## Tests

- `tun-helper/tests/integration.rs` already exercises bring-up and
  bring-down on Linux. D-2 adds a smoke that verifies
  `engine_set_route_with_fd` returns a successful heartbeat within
  10 s.
- The `tun-helper` integration test runs only on `linux-x86_64`
  CI; Windows and macOS get a pinned binary smoke test in the
  manual test plan instead.
