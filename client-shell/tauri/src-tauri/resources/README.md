This directory is intentionally tracked so Tauri's `resources/*` bundle
glob always resolves during local builds.

Packaged desktop builds may place `libdaalcore.so` here after building
the Go c-shared engine.
