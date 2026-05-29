# zip.ps1 — assemble a portable Windows ZIP for Daal.
#
# This is intentionally minimal: a portable build is identical to the
# NSIS install layout, just without the installer. Run from the
# repository root after `cargo tauri build`.

param(
    [string]$Source = "client-shell\tauri\src-tauri\target\release",
    [string]$EngineLib = "client-shell\tauri\src-tauri\resources\libdaalcore.dll",
    [string]$Singbox = "client-shell\tauri\src-tauri\resources\sing-box.exe",
    [string]$Out = "Daal-portable-x64.zip"
)

$ErrorActionPreference = "Stop"

$Stage = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP "daal-portable")
Remove-Item -Recurse -Force $Stage
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

Copy-Item (Join-Path $Source "daal-desktop.exe") (Join-Path $Stage "Daal.exe")
if (Test-Path $EngineLib) {
    Copy-Item $EngineLib (Join-Path $Stage "libdaalcore.dll")
}
if (Test-Path $Singbox) {
    Copy-Item $Singbox (Join-Path $Stage "sing-box.exe")
}
Copy-Item "client-shell\tauri\README.md" (Join-Path $Stage "README.txt")

Compress-Archive -Path "$Stage\*" -DestinationPath $Out -Force
Write-Host "wrote $Out"
