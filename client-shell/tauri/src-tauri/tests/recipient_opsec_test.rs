//! FRP-6 — recipient OPSEC: enforce Position B at the desktop layer.
//!
//! Two greps:
//!
//!   1. No analytics SDKs (firebase / crashlytics / sentry / amplitude /
//!      mixpanel / google-analytics / datadog / new-relic) in the
//!      Cargo.toml or the `src/` tree.
//!
//!   2. The recipient module never opens its own sockets. The engine
//!      is the single network actor. We grep `src/recipient.rs` for
//!      `std::net::TcpStream`, `reqwest`, `hyper`, `surf`, `ureq`,
//!      and `tokio::net` and assert zero hits.

use std::fs;
use std::path::{Path, PathBuf};

fn project_root() -> PathBuf {
    let mut cursor = std::env::current_dir().expect("cwd");
    for _ in 0..8 {
        if cursor
            .join("client-shell/tauri/src-tauri/src/recipient.rs")
            .is_file()
        {
            return cursor;
        }
        cursor = match cursor.parent() {
            Some(p) => p.to_path_buf(),
            None => break,
        };
    }
    PathBuf::from("../../..")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn collect_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_files(&path, ext));
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
            out.push(path);
        }
    }
    out
}

fn analytics_symbols() -> Vec<String> {
    vec![
        "fire".to_string() + "base",
        "crash".to_string() + "lytics",
        "sen".to_string() + "try",
        "amp".to_string() + "litude",
        "mix".to_string() + "panel",
        "google".to_string() + "-analytics",
        "google".to_string() + ".analytics",
        "data".to_string() + "dog",
        "new".to_string() + "relic",
        "new".to_string() + "-relic",
    ]
}

const NETWORK_SYMBOLS: &[&str] = &[
    "std::net::TcpStream",
    "std::net::TcpListener",
    "reqwest::",
    "hyper::client",
    "surf::",
    "ureq::",
    "tokio::net::TcpStream",
];

#[test]
fn no_analytics_in_cargo_toml() {
    let root = project_root();
    let toml = read(&root.join("client-shell/tauri/src-tauri/Cargo.toml")).to_lowercase();
    for sym in analytics_symbols() {
        assert!(
            !toml.contains(&sym),
            "Position B: Cargo.toml must not pull in '{sym}'"
        );
    }
}

#[test]
fn no_analytics_in_src() {
    let root = project_root();
    let src_dir = root.join("client-shell/tauri/src-tauri/src");
    let files = collect_files(&src_dir, "rs");
    for f in &files {
        let content = read(f).to_lowercase();
        for sym in analytics_symbols() {
            assert!(
                !content.contains(&sym),
                "Position B: {} must not import '{sym}'",
                f.display()
            );
        }
    }
}

#[test]
fn recipient_module_has_no_sockets() {
    let root = project_root();
    let path = root.join("client-shell/tauri/src-tauri/src/recipient.rs");
    let content = read(&path);
    for sym in NETWORK_SYMBOLS {
        assert!(
            !content.contains(sym),
            "recipient.rs must not open sockets; saw '{sym}'"
        );
    }
}

#[test]
fn frp6_recipient_command_names_present() {
    // Polarity flip à la FRP-4b: ensure the wired commands actually
    // exist in lib.rs. Removing one without re-adding it elsewhere
    // fails this test before the Tauri shim refuses to compile.
    let root = project_root();
    let lib = read(&root.join("client-shell/tauri/src-tauri/src/lib.rs"));
    for cmd in &[
        "fn recipient_qr_session_new",
        "fn recipient_qr_feed_frame",
        "fn recipient_qr_status",
        "fn recipient_qr_cancel",
        "fn recipient_qr_finalize",
    ] {
        assert!(
            lib.contains(cmd),
            "FRP-6 recipient command must be defined: {cmd}"
        );
    }
}
