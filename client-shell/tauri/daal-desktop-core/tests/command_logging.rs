//! Reads the GUI shell's command surface (src-tauri/src/lib.rs) as
//! text: the shell itself cannot be compiled without the GTK/webkit
//! toolchain, and this rule must hold on every machine that runs
//! `cargo test`.

/// Every `#[tauri::command]` in the GUI shell that returns a `Result`
/// goes through `daal_desktop_core::cmdlog`. Reads the source, so a command added
/// without the wrapper fails here rather than on a phone.
#[test]
fn every_result_command_is_logged() {
    let src = include_str!("../../src-tauri/src/lib.rs");
    let mut missing = Vec::new();
    let mut seen = 0;
    let mut rest = src;
    while let Some(i) = rest.find("#[tauri::command]\n") {
        let after = &rest[i + "#[tauri::command]\n".len()..];
        // Signature: up to the line that opens the body.
        let open = after.find("{\n").expect("command body");
        let sig = &after[..open];
        let end = after.find("\n}\n").expect("command end");
        let body = &after[open..end];
        rest = &after[end..];
        let name = sig
            .split("fn ")
            .nth(1)
            .and_then(|s| s.split(['(', '<']).next())
            .unwrap_or("?")
            .trim()
            .to_string();
        let returns_result = sig
            .rsplit_once("->")
            .map(|(_, r)| r.trim_start().starts_with("Result<"))
            .unwrap_or(false);
        if !returns_result {
            continue;
        }
        seen += 1;
        let want_a = format!("cmdlog::logged(\"{name}\",");
        let want_b = format!("cmdlog::result(\"{name}\",");
        let want_c = format!("cmdlog::result(\n        \"{name}\",");
        if !(body.contains(&want_a) || body.contains(&want_b) || body.contains(&want_c)) {
            missing.push(name);
        }
    }
    assert!(seen >= 100, "only {seen} commands found — the scan is broken");
    assert!(
        missing.is_empty(),
        "commands that can fail without a log line: {missing:?}"
    );
}
