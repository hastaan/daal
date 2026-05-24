# Packaging

Phase 1.5B ships four artifact families:

| Target | Artifact | Driver |
|---|---|---|
| Linux AppImage | `Daal-x86_64.AppImage` | Tauri's built-in AppImage bundler (`--bundles appimage`) |
| Linux Debian | `daal_0.1.0_amd64.deb` | Tauri's `deb` bundler + postinst that chowns `daal-tun-helper` setuid |
| Windows NSIS | `Daal_0.1.0_x64-setup.exe` | Tauri's NSIS bundler |
| Windows portable ZIP | `Daal-portable-x64.zip` | `packaging/windows/portable/zip.ps1` |

Macos is built green in CI but not user-tested in 1.5B.

## Layout

```
packaging/
├── README.md                    (this file)
├── linux/
│   ├── deb/
│   │   ├── postinst             (sets setuid on tun-helper)
│   │   └── prerm                (clean removal)
│   └── appimage/
│       └── AppRun               (sets DAAL_ENGINE_LIB then exec's GUI)
└── windows/
    ├── nsis/
    │   └── installer.nsi.tmpl   (template; Tauri merges in product info)
    └── portable/
        └── zip.ps1              (PowerShell driver for portable ZIP)
```
