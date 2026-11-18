// Vite's `?raw` import: the file's text as a string. Used by tests that
// hold a wiring fact at the source level (extraFamilies.test.tsx).
declare module '*?raw' {
    const source: string;
    export default source;
}
