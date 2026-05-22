/// <reference types="vite/client" />

// Build-time constants injected by vite.config.ts. See that file for
// where the values come from.
declare const __APP_VERSION__: string;
declare const __RELEASE_SIZES__: Record<string, string>;

// Brand assets imported via the @branding alias. Vite resolves these
// at build time; TS needs explicit module declarations so the alias
// is type-safe.
declare module '@branding/sources/daal-eagle.svg?url' {
  const url: string;
  export default url;
}
declare module '@branding/sources/daal-eagle-transparent.png' {
  const url: string;
  export default url;
}
