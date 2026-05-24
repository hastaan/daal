// landing/src/downloads.ts — catalog of release artifacts.
//
// Version comes from the repo-root VERSION file (injected by vite.config.ts
// as __APP_VERSION__). File sizes also come from vite.config.ts as
// __RELEASE_SIZES__, populated from one of two sources at build time:
//   1. local `dist-release/v<VERSION>/<filename>` (Linux/Android artifacts
//      we built on the dev machine)
//   2. `gh release view v<VERSION>` (Win/Mac/iOS artifacts uploaded by
//      AppVeyor)
//
// We resolve sizes at BUILD time (not runtime) so the deployed landing
// page never reaches a GitHub API endpoint — important because the API
// is blocked in some of the network environments Daal targets.
//
// Bumping a release: edit the repo-root `VERSION` file. The landing
// page picks up the new version + new sizes on the next `npm run build`.

declare const __APP_VERSION__: string;
declare const __RELEASE_SIZES__: Record<string, string>;

const SIZES = __RELEASE_SIZES__;
/** Look up the build-time size for a filename. Empty string → omit pill. */
function s(filename: string): string {
  return SIZES[filename] ?? '';
}

export const RELEASE_VERSION = __APP_VERSION__;
export const RELEASE_BASE_URL = `https://github.com/hastaan/daal/releases/download/v${RELEASE_VERSION}`;
export const RELEASE_PAGE_URL = `https://github.com/hastaan/daal/releases/tag/v${RELEASE_VERSION}`;
export const REPO_URL = 'https://github.com/hastaan/daal';

export interface DownloadFile {
  /** Filename as it appears on the GitHub release page. */
  filename: string;
  /** Human-readable label shown below the filename, e.g. "Debian / Ubuntu". */
  label: string;
  /** Approximate uncompressed size for visual weight, e.g. "13 MB". */
  size: string;
  /** Set true while the artifact for this version hasn't been uploaded yet. */
  unavailable?: boolean;
}

export interface Platform {
  /** Stable identifier used in URLs / analytics-free anchor links. */
  id: string;
  /** Display name shown in the card header. */
  name: string;
  /** Short tagline under the name. */
  meta: string;
  /** SVG path string for the platform glyph. Rendered inside a 24×24 viewBox. */
  iconPath: string;
  /** Files available for download on this platform. */
  files: DownloadFile[];
  /** Footnote shown beneath the file list. */
  notes?: string;
}

/**
 * Inline platform glyphs (24×24 viewBox). Kept terse so we ship one
 * SVG path each rather than five extra image requests. Strokes use
 * currentColor so the icon adopts the gold accent.
 */
const ICON = {
  windows:
    'M3 5.5l8-1.1v7.2H3V5.5zm0 13L11 19.6V12.5H3v6zM12 4.3l9-1.3v8.6h-9V4.3zm0 16.4l9 1.3V12.5h-9v8.2z',
  apple:
    'M16.5 13.5c0-2 1.6-3 1.7-3.1-0.9-1.4-2.4-1.6-2.9-1.6-1.3-0.1-2.4 0.7-3 0.7s-1.6-0.7-2.7-0.7c-1.4 0-2.7 0.8-3.4 2-1.5 2.5-0.4 6.3 1 8.4 0.7 1 1.6 2.2 2.7 2.1 1.1-0.1 1.5-0.7 2.8-0.7 1.3 0 1.7 0.7 2.8 0.7 1.2 0 1.9-1 2.6-2 0.8-1.2 1.2-2.3 1.2-2.4-0.1-0.1-2.3-0.9-2.3-3.4zm-2.2-6c0.6-0.7 1-1.7 0.9-2.7-0.9 0.1-1.9 0.6-2.5 1.3-0.6 0.6-1.1 1.7-0.9 2.6 1 0.1 2-0.5 2.5-1.2z',
  linux:
    'M12 2c-2 0-3.5 1.6-3.5 3.5 0 1.7 1.1 3 1.7 3.5-0.5 0.3-2 1.4-2.7 2.8-1.2 2.3-2.5 4.5-2.5 6 0 1 0.5 1.5 1 1.8 0.2 0.6 0.6 1.2 1.5 1.4 0.5 0.7 1.4 1 2.5 1h4c1.1 0 2-0.3 2.5-1 0.9-0.2 1.3-0.8 1.5-1.4 0.5-0.3 1-0.8 1-1.8 0-1.5-1.3-3.7-2.5-6-0.7-1.4-2.2-2.5-2.7-2.8 0.6-0.5 1.7-1.8 1.7-3.5C15.5 3.6 14 2 12 2zm-1.2 4.3c0.4 0 0.7 0.5 0.7 1 0 0.3-0.1 0.6-0.3 0.8-0.1 0-0.2 0-0.4 0-0.3-0.1-0.5-0.5-0.5-0.9 0-0.5 0.3-0.9 0.5-0.9zm2.4 0c0.2 0 0.5 0.4 0.5 0.9 0 0.4-0.2 0.8-0.5 0.9-0.2 0-0.3 0-0.4 0-0.2-0.2-0.3-0.5-0.3-0.8 0-0.5 0.3-1 0.7-1z',
  android:
    'M5.4 8.6L4 9.4l1.4 2.4c-0.7 0.6-1.1 1.3-1.4 2.2H20c-0.3-0.9-0.7-1.6-1.4-2.2L20 9.4l-1.4-0.8-1.4 2.4C16.1 10.5 14.6 10 13 10h-2c-1.6 0-3.1 0.5-4.2 1zm3.6 0.6c-0.4 0-0.7-0.3-0.7-0.7s0.3-0.7 0.7-0.7 0.7 0.3 0.7 0.7-0.3 0.7-0.7 0.7zm6 0c-0.4 0-0.7-0.3-0.7-0.7s0.3-0.7 0.7-0.7 0.7 0.3 0.7 0.7-0.3 0.7-0.7 0.7zM4 15v5c0 0.6 0.4 1 1 1h1v2.5h2V21h8v2.5h2V21h1c0.6 0 1-0.4 1-1v-5H4zm-1.5 0c-0.8 0-1.5 0.7-1.5 1.5v4c0 0.8 0.7 1.5 1.5 1.5s1.5-0.7 1.5-1.5v-4c0-0.8-0.7-1.5-1.5-1.5zm19 0c-0.8 0-1.5 0.7-1.5 1.5v4c0 0.8 0.7 1.5 1.5 1.5s1.5-0.7 1.5-1.5v-4c0-0.8-0.7-1.5-1.5-1.5z',
  ios:
    'M16.5 13.5c0-2 1.6-3 1.7-3.1-0.9-1.4-2.4-1.6-2.9-1.6-1.3-0.1-2.4 0.7-3 0.7s-1.6-0.7-2.7-0.7c-1.4 0-2.7 0.8-3.4 2-1.5 2.5-0.4 6.3 1 8.4 0.7 1 1.6 2.2 2.7 2.1 1.1-0.1 1.5-0.7 2.8-0.7 1.3 0 1.7 0.7 2.8 0.7 1.2 0 1.9-1 2.6-2 0.8-1.2 1.2-2.3 1.2-2.4-0.1-0.1-2.3-0.9-2.3-3.4z',
};

export const PLATFORMS: Platform[] = [
  {
    id: 'linux',
    name: 'Linux',
    meta: 'x86_64 · GTK / WebKit2',
    iconPath: ICON.linux,
    files: [
      {
        filename: `Daal_${RELEASE_VERSION}_amd64.deb`,
        label: 'Debian / Ubuntu',
        size: s(`Daal_${RELEASE_VERSION}_amd64.deb`),
      },
      {
        filename: `Daal-${RELEASE_VERSION}-1.x86_64.rpm`,
        label: 'Fedora / openSUSE / RHEL',
        size: s(`Daal-${RELEASE_VERSION}-1.x86_64.rpm`),
      },
      {
        filename: `Daal_${RELEASE_VERSION}_amd64.AppImage`,
        label: 'AppImage (portable)',
        size: s(`Daal_${RELEASE_VERSION}_amd64.AppImage`),
      },
    ],
    notes: 'Tested on Debian 12 + Fedora 41. AppImage needs `chmod +x` before launch.',
  },
  {
    id: 'macos',
    name: 'macOS',
    meta: 'aarch64 (Apple Silicon)',
    iconPath: ICON.apple,
    files: [
      {
        filename: `Daal_${RELEASE_VERSION}_aarch64.dmg`,
        label: 'Disk image',
        size: s(`Daal_${RELEASE_VERSION}_aarch64.dmg`),
      },
      {
        filename: `Daal_${RELEASE_VERSION}_aarch64.app.zip`,
        label: '.app bundle (zipped)',
        size: s(`Daal_${RELEASE_VERSION}_aarch64.app.zip`),
      },
    ],
    notes: 'Unsigned builds — right-click → Open the first time to bypass Gatekeeper.',
  },
  {
    id: 'windows',
    name: 'Windows',
    meta: 'x86_64 · WebView2',
    iconPath: ICON.windows,
    files: [
      {
        filename: `Daal_${RELEASE_VERSION}_x64-setup.exe`,
        label: 'NSIS installer',
        size: s(`Daal_${RELEASE_VERSION}_x64-setup.exe`),
      },
      {
        filename: `Daal_${RELEASE_VERSION}_x64.msi`,
        label: 'MSI package',
        size: s(`Daal_${RELEASE_VERSION}_x64.msi`),
      },
    ],
    notes: 'SmartScreen may warn — unsigned. Click "More info" → "Run anyway".',
  },
  {
    id: 'android',
    name: 'Android',
    meta: 'arm64-v8a · armeabi-v7a · x86_64',
    iconPath: ICON.android,
    files: [
      {
        filename: `Daal_${RELEASE_VERSION}_arm64-v8a.apk`,
        label: 'Modern devices (arm64)',
        size: s(`Daal_${RELEASE_VERSION}_arm64-v8a.apk`),
      },
      {
        filename: `Daal_${RELEASE_VERSION}_armeabi-v7a.apk`,
        label: 'Older 32-bit devices',
        size: s(`Daal_${RELEASE_VERSION}_armeabi-v7a.apk`),
      },
      {
        filename: `Daal_${RELEASE_VERSION}_x86_64.apk`,
        label: 'x86_64 emulators',
        size: s(`Daal_${RELEASE_VERSION}_x86_64.apk`),
      },
    ],
    notes:
      'Enable "Install unknown apps" for your browser/file manager. Pick the APK matching your device CPU — almost all phones use arm64. v7a is for older 32-bit devices; x86_64 is for emulators only.',
  },
  {
    id: 'ios',
    name: 'iOS / iPadOS',
    meta: 'arm64 device · unsigned',
    iconPath: ICON.ios,
    files: [
      {
        filename: `Daal_${RELEASE_VERSION}_unsigned.ipa`,
        label: 'Unsigned IPA (re-sign locally)',
        size: s(`Daal_${RELEASE_VERSION}_unsigned.ipa`),
      },
    ],
    notes:
      'Re-sign with Sideloadly using your free Apple ID, then deploy to your device. Re-sign weekly (7-day free-account limit).',
  },
];
