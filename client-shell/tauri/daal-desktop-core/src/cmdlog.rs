//! One log line for every command that fails.
//!
//! The first real-phone pass ended with a red banner and an empty
//! logcat: each `#[tauri::command]` turned its error into a string for
//! the webview (`map_err(|e| e.to_string())`) and nothing else ever saw
//! it. Every command that returns a `Result` now runs its body through
//! [`logged`] (or hands its result to [`result`], for the async ones),
//! so a rejection the page receives is also one `warn` line —
//! `command <name> failed: <text>` — in logcat (tag from
//! `android_logger`) or on stderr.
//!
//! The value returned to JS is NOT changed: it is still the plain
//! string it always was.
//!
//! What goes to the log is passed through [`scrub`] first. An error
//! text is written for a person to read, but it is built from whatever
//! the failing layer had in hand — a cloud API's response, a path, a
//! URL — so anything shaped like a secret is cut out before it is
//! logged, and the line is bounded.
//!
//! This module lives in `daal-desktop-core` rather than next to the
//! commands so that it can be tested on a machine without the GUI
//! toolchain. `tests/command_logging.rs` reads the shell's lib.rs and
//! keeps the rule true for commands added later.

use std::fmt::Display;

/// Longest error text written to the log, in characters.
const MAX_LOG_CHARS: usize = 400;

/// A run of this many "token characters" or more that mixes letters
/// and digits is treated as a credential (API tokens, keys, base64
/// blobs, long hex) and replaced. Route ids, error codes and ordinary
/// words are shorter; a file path is long but its components rarely
/// carry digits, and one that does is cut too — losing part of a path
/// in a log line is the cheap side of that trade.
const SECRET_RUN: usize = 24;

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// One bounded line with nothing secret-shaped in it.
///
/// The same passes, in the same order, as the engine's own scrubber
/// (`core/engine/log.go` `Scrub`): URLs, credential-looking
/// `key=value` pairs, IP addresses (with or without a port), host
/// names, and long token-like runs. A publisher command's error can
/// carry a subprocess's stderr — "dial tcp 203.0.113.5:8443:
/// connection refused" — and the relay's address must not reach logcat
/// on the publisher's own phone. It errs toward removing too much.
pub fn scrub(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let out = scrub_blobs(&scrub_addresses(&scrub_words(&flat)));
    let trimmed = out.trim();
    if trimmed.chars().count() > MAX_LOG_CHARS {
        let mut s: String = trimmed.chars().take(MAX_LOG_CHARS).collect();
        s.push('…');
        s
    } else {
        trimmed.to_string()
    }
}

/// Names whose value is a credential whatever it looks like. Matched
/// against the END of the key, so `hcloud_token` and `x-auth-token`
/// count too.
const SECRET_KEYS: &[&str] = &[
    "password", "passwd", "passphrase", "pass", "pin", "secret", "token", "uuid", "key", "psk",
    "short_id", "short-id", "shortid", "auth", "authorization", "credential", "credentials",
    "username", "user",
];

fn is_secret_key(key: &str) -> bool {
    let k = key
        .trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .to_ascii_lowercase();
    !k.is_empty() && SECRET_KEYS.iter().any(|s| k.ends_with(s))
}

/// Word-level passes: a word holding `scheme://` becomes `<url>`, and
/// the value of a credential-looking `key=value` / `key: value` becomes
/// `[redacted]` however short it is.
fn scrub_words(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    // How many following words are a credential's value ("token: abc",
    // "Authorization: Bearer abc").
    let mut redact_next = 0u8;
    for (n, word) in text.split(' ').enumerate() {
        if n > 0 {
            out.push(' ');
        }
        if word.is_empty() {
            continue;
        }
        if redact_next > 0 {
            redact_next -= 1;
            if word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic") {
                redact_next = 1;
            }
            out.push_str("[redacted]");
            continue;
        }
        if let Some(i) = word.find("://") {
            // Keep what precedes the scheme's letters: an opening
            // bracket or quote.
            let scheme_start = word[..i]
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')))
                .map(|p| p + word[p..].chars().next().map_or(1, char::len_utf8))
                .unwrap_or(0);
            if scheme_start < i {
                out.push_str(&word[..scheme_start]);
                out.push_str("<url>");
                continue;
            }
        }
        if let Some(i) = word.find(|c| c == '=' || c == ':') {
            if is_secret_key(&word[..i]) {
                out.push_str(&word[..=i]);
                if word[i + 1..].trim_matches(|c| c == '"' || c == '\'').is_empty() {
                    redact_next = 1;
                } else {
                    out.push_str("[redacted]");
                }
                continue;
            }
        }
        out.push_str(word);
    }
    out
}

/// Names with a dot in them that are files and identifiers, not hosts.
const KEEP_SUFFIX: &[&str] = &[
    ".json", ".db", ".key", ".sbp", ".sbpx", ".go", ".so", ".share", ".wasm", ".rs", ".toml",
    ".kt", ".apk", ".jks", ".txt", ".log", ".pem", ".yaml", ".yml", ".sh", ".tmp", ".lock",
    ".sqlite",
];

fn is_addr_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '%')
}

fn is_ipv4(s: &str) -> bool {
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (s, None),
    };
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Hex groups with at least two colons between them, `::` included. It
/// also takes a clock time like 12:34:56, which is no loss.
fn is_ipv6(s: &str) -> bool {
    s.matches(':').count() >= 2
        && s.chars().any(|c| c.is_ascii_hexdigit())
        && s.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '%'))
}

/// `name.name[.name…][:port]`.
fn is_host(s: &str) -> bool {
    let host = match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => h,
        Some(_) => return false,
        None => s,
    };
    let lower = host.to_ascii_lowercase();
    if KEEP_SUFFIX.iter().any(|sfx| lower.ends_with(sfx)) {
        return false;
    }
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |l: &&str| {
        !l.is_empty()
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    let tld = labels[labels.len() - 1];
    labels.iter().all(label_ok)
        && (2..=24).contains(&tld.len())
        && tld.as_bytes()[0].is_ascii_alphabetic()
}

/// IP addresses and host names, with or without a port.
fn scrub_addresses(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let mut before_run: Option<char> = None;
    let mut prev: Option<char> = None;
    let flush = |run: &mut String, before: Option<char>, out: &mut String| {
        if run.is_empty() {
            return;
        }
        // Sentence punctuation around the candidate is not part of it:
        // "…203.0.113.5:8443: connection refused", "see example.org."
        let lead = run.len() - run.trim_start_matches(|c| c == ':' || c == '.' || c == '-').len();
        let core_end = run.trim_end_matches(|c| c == ':' || c == '.' || c == '-').len();
        if lead >= core_end {
            out.push_str(run);
            run.clear();
            return;
        }
        let core = &run[lead..core_end];
        let replacement = if is_ipv4(core) || is_ipv6(core) {
            Some("<addr>")
        } else if is_host(core) && !(before == Some('/') && !core.contains(':')) {
            // A dotted name right after a '/' is a path component
            // ("/data/user/0/org.daal.desktop/files"), unless it
            // carries a port.
            Some("<host>")
        } else {
            None
        };
        match replacement {
            Some(r) => {
                out.push_str(&run[..lead]);
                out.push_str(r);
                out.push_str(&run[core_end..]);
            }
            None => out.push_str(run),
        }
        run.clear();
    };
    for c in text.chars() {
        if is_addr_char(c) {
            if run.is_empty() {
                before_run = prev;
            }
            run.push(c);
        } else {
            flush(&mut run, before_run, &mut out);
            out.push(c);
        }
        prev = Some(c);
    }
    flush(&mut run, before_run, &mut out);
    out
}

/// Long token-like runs: API tokens, keys, base64 blobs, long hex,
/// UUIDs.
fn scrub_blobs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        let mixed = run.chars().any(|c| c.is_ascii_digit())
            && run.chars().any(|c| c.is_ascii_alphabetic());
        if mixed && run.chars().count() >= SECRET_RUN {
            out.push_str("[redacted]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if is_token_char(c) {
            run.push(c);
            continue;
        }
        flush(&mut run, &mut out);
        out.push(c);
    }
    flush(&mut run, &mut out);
    out
}

/// The line itself; separate from [`result`] so a test can read it.
pub fn failure_line<E: Display>(command: &str, err: &E) -> String {
    format!("command {command} failed: {}", scrub(&err.to_string()))
}

/// Logs `r`'s error, if it is one, and hands `r` back untouched.
pub fn result<T, E: Display>(command: &'static str, r: Result<T, E>) -> Result<T, E> {
    if let Err(e) = &r {
        log::warn!("{}", failure_line(command, e));
    }
    r
}

/// Runs a command body and logs its error. Every way out of the body —
/// `?`, an early `return Err(..)`, the tail expression — goes through
/// the one log line, which is why the bodies are wrapped whole instead
/// of each `map_err` being taught to log.
pub fn logged<T, E: Display>(
    command: &'static str,
    body: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    result(command, body())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_error_text_is_kept() {
        let e = "engine call returned -1: subscription_list: database is locked";
        assert_eq!(
            failure_line("subscription_list", &e),
            "command subscription_list failed: engine call returned -1: \
             subscription_list: database is locked"
        );
        assert_eq!(scrub("route r1 is cooling down"), "route r1 is cooling down");
        assert_eq!(
            scrub("io: /data/user/0/org.daal.desktop/files/daal/wizard.db: no such file"),
            "io: /data/user/0/org.daal.desktop/files/daal/wizard.db: no such file"
        );
    }

    #[test]
    fn secret_shaped_runs_are_cut() {
        let token = "hcloud_AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789";
        let got = scrub(&format!("provider said 401 for token {token} (retry)"));
        assert_eq!(got, "provider said 401 for token [redacted] (retry)");
        let b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
        assert!(!scrub(&format!("key={b64}")).contains("QUJD"));
        let hex = "3fa9c1d2".repeat(8);
        assert!(!scrub(&format!("fp {hex}")).contains(&hex));
    }

    #[test]
    fn addresses_never_reach_the_log() {
        // What a publisher command's error looks like when it carries a
        // subprocess's stderr (daal-wizard recipient_sbpx: "[alias] stderr").
        assert_eq!(
            scrub("[relay1] dial tcp 203.0.113.5:8443: connection refused"),
            "[relay1] dial tcp <addr>: connection refused"
        );
        assert_eq!(scrub("no route to 198.51.100.7"), "no route to <addr>");
        assert_eq!(
            scrub("dial tcp [2001:db8::1]:443: i/o timeout"),
            "dial tcp [<addr>]:443: i/o timeout"
        );
        assert_eq!(scrub("lookup relay.example.org: no such host"), "lookup <host>: no such host");
        assert_eq!(scrub("tls: bad cert for cdn.example.com:8443."), "tls: bad cert for <host>.");
    }

    #[test]
    fn urls_and_short_credentials_are_cut() {
        let got = scrub("GET https://api.example.net/v1/servers?token=abc123 returned 401");
        assert_eq!(got, "GET <url> returned 401");
        assert_eq!(scrub("fetch (http://10.0.0.1/x) failed"), "fetch (<url> failed");
        // Too short and too plain for the long-run rule.
        assert_eq!(scrub("login failed: password=hunter2 rejected"), "login failed: password=[redacted] rejected");
        assert_eq!(scrub("bad hcloud_token=abc"), "bad hcloud_token=[redacted]");
        assert_eq!(scrub(r#"body {"uuid":"x1","n":3}"#), r#"body {"uuid":[redacted]"#);
        assert_eq!(scrub("token: abc rejected"), "token: [redacted] rejected");
        assert_eq!(
            scrub("sent Authorization: Bearer abcdef got 403"),
            "sent Authorization: [redacted] [redacted] got 403"
        );
    }

    #[test]
    fn files_versions_and_identifiers_are_not_hosts() {
        for keep in [
            "open wizard.db: permission denied",
            "relay-v1.5.1 is too old",
            "src/lib.rs:42 panicked",
            "std::io::Error: broken pipe",
            "route r1 failed after 3 tries",
        ] {
            assert_eq!(scrub(keep), keep);
        }
    }

    #[test]
    fn one_bounded_line() {
        let got = scrub(&format!("a\nb\r\n{}", "word ".repeat(500)));
        assert!(!got.contains('\n') && !got.contains('\r'));
        assert!(got.chars().count() <= MAX_LOG_CHARS + 1);
        assert!(got.starts_with("a b"));
    }

    #[test]
    fn result_and_logged_hand_the_value_back_unchanged() {
        assert_eq!(result::<i32, String>("x", Ok(7)), Ok(7));
        assert_eq!(
            result::<i32, String>("x", Err("boom".into())),
            Err("boom".to_string())
        );
        assert_eq!(logged("x", || Ok::<_, String>(1)), Ok(1));
        let r: Result<(), String> = logged("x", || {
            Err::<(), String>("early".into())?;
            Ok(())
        });
        assert_eq!(r, Err("early".to_string()));
    }
}
