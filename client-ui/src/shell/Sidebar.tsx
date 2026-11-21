// Sidebar.tsx — the section vocabulary the pages navigate with.
//
// The old desktop sidebar component that lived here was never rendered
// (DesktopShell uses the SidebarFull primitive); only this type was
// imported, by ConnectionPage. Its members stay exactly as they were.

export type SectionId =
    | 'connection'
    | 'network'
    | 'status'
    | 'settings'
    | 'publisher';
