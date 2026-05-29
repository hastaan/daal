// Asset module declarations for non-TS imports (Vite resolves these at
// runtime to URL strings; TypeScript needs the type ambient declaration
// to allow `import x from './foo.svg'`).

declare module '*.svg' {
    const url: string;
    export default url;
}
declare module '*.svg?url' {
    const url: string;
    export default url;
}
declare module '*.png' {
    const url: string;
    export default url;
}
declare module '*.png?url' {
    const url: string;
    export default url;
}
declare module '*.jpg' {
    const url: string;
    export default url;
}
declare module '*.jpg?url' {
    const url: string;
    export default url;
}
