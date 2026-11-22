//! Reading the setup journal a `daal-deploy provision` child leaves.
//!
//! WHY THIS EXISTS. A setup is a child process that rents a server, and
//! on Android the child dies with the app (it is in the app's process
//! group, and its next progress write to a closed pipe is SIGPIPE). The
//! app used to write down what was created only when the whole setup
//! succeeded, so a setup killed after the server was rented left a
//! billing server the app had no record of at all.
//!
//! The child now journals every cloud object BEFORE it asks for it
//! (`intent`) and as soon as the provider answers (`created`), one
//! fsynced JSON line each, holding an exclusive lock on the file for its
//! whole life (`provision --journal`). This module is the reading half:
//! a pure [`summarize`] that turns the text into what the recovery card
//! needs, and [`is_locked`] that tells a running setup from a dead one.
//!
//! The journal is evidence, not the only backstop: Daal's labels and
//! derived names, read through `account-audit`, still find everything if
//! a line is missing.
//!
//! Nothing secret is ever in it (the child's opsec test pins that); this
//! reader still never logs a line verbatim.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The `begin` line of the last run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JournalBegin {
    /// `create` | `adopt` | `rebuild_yours`.
    pub mode: String,
    pub provider: String,
    pub region: String,
    pub relay_name: String,
    pub existing_server_id: String,
    /// RFC3339, as written.
    pub ts: String,
}

/// Something created and not (yet) seen deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveObject {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub public_ip: String,
    /// For servers, how this one came into the journal:
    /// `created` (a `created kind=server` line: Daal rented it),
    /// `adopt` (a rebuild intent in an `adopt` run: Daal's own labelled
    /// server, re-imaged), or `yours` (a rebuild intent in a
    /// `rebuild_yours` run: the person's OWN server, which carries no
    /// Daal label and must never be deleted without them saying so).
    #[serde(default)]
    pub origin: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct JournalSummary {
    pub last_begin: Option<JournalBegin>,
    /// Server ids created (or re-imaged) and not deleted, newest first.
    pub servers: Vec<LiveObject>,
    /// The OperatorRecord of the last `done` after the last `begin`.
    pub done_record: Option<serde_json::Value>,
    pub last_failed_code: Option<String>,
    /// Every non-server object created and not deleted, in order.
    pub other_live: Vec<LiveObject>,
    /// The last run asked the provider for a server (`intent
    /// kind=server`) and never wrote down the answer: a server may exist
    /// under the derived name that no `created` line names.
    pub unanswered_server_intent: bool,
}

impl JournalSummary {
    /// The newest live server id, if any (whatever its origin).
    pub fn server_id(&self) -> Option<&str> {
        self.servers.first().map(|s| s.id.as_str())
    }

    /// The newest live server that came from the person's own server
    /// (`rebuild_yours`), if any.
    pub fn own_server(&self) -> Option<&LiveObject> {
        self.servers.iter().find(|s| s.origin == "yours")
    }

    /// The server id a teardown may fill into a record that has none.
    ///
    /// Two rules, both about not trusting the journal alone:
    /// - a server that is the person's own (`yours`) is returned only
    ///   when `include_own` — they said "delete my server";
    /// - when the last run sent a server create whose answer never made
    ///   it into the journal, no id is returned for a Daal server at
    ///   all: an older `created` id may be stale while the new server
    ///   bills under the derived name, and only an empty id makes
    ///   `decommission` look the server up by that name.
    pub fn teardown_server_id(&self, include_own: bool) -> Option<&str> {
        if include_own {
            if let Some(own) = self.own_server() {
                return Some(own.id.as_str());
            }
        }
        if self.unanswered_server_intent {
            return None;
        }
        self.servers
            .iter()
            .find(|s| s.origin != "yours")
            .map(|s| s.id.as_str())
    }
}

fn s(v: &serde_json::Value, k: &str) -> String {
    match v.get(k) {
        Some(serde_json::Value::String(x)) => x.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Summarise a journal's text.
///
/// Tolerant by design, because it is read after a crash: a torn last
/// line (the child died mid-write) is ignored, and so is any line that
/// does not parse, has an unknown `ev`, or a version newer than 1.
/// Objects are tracked across every `begin` segment — a server rented by
/// the first, killed run is still live during the second — while
/// `done_record` and `last_failed_code` belong to the last run only.
pub fn summarize(text: &str) -> JournalSummary {
    let mut out = JournalSummary::default();
    // (kind, id) -> object, insertion-ordered.
    let mut live: Vec<LiveObject> = Vec::new();
    // The mode of the segment being read (from its `begin`).
    let mut mode = String::new();
    for line in text.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let ver = v.get("v").and_then(|x| x.as_i64()).unwrap_or(0);
        if ver != 1 {
            continue;
        }
        match v.get("ev").and_then(|x| x.as_str()).unwrap_or("") {
            "begin" => {
                out.last_begin = Some(JournalBegin {
                    mode: s(&v, "mode"),
                    provider: s(&v, "provider"),
                    region: s(&v, "region"),
                    relay_name: s(&v, "relay_name"),
                    existing_server_id: s(&v, "existing_server_id"),
                    ts: s(&v, "ts"),
                });
                out.done_record = None;
                out.last_failed_code = None;
                out.unanswered_server_intent = false;
                mode = s(&v, "mode");
            }
            "intent" => {
                match s(&v, "kind").as_str() {
                    // A rebuild names the server it is about to re-image:
                    // that server is to be accounted for from this moment
                    // on — as the person's own when this run is setting
                    // up a server they brought.
                    "rebuild" => {
                        let id = s(&v, "id");
                        if !id.is_empty()
                            && !live.iter().any(|o| o.kind == "server" && o.id == id)
                        {
                            live.push(LiveObject {
                                kind: "server".into(),
                                id,
                                name: s(&v, "name"),
                                public_ip: String::new(),
                                origin: rebuild_origin(&mode).into(),
                            });
                        }
                    }
                    "server" => out.unanswered_server_intent = true,
                    _ => {}
                }
            }
            "created" => {
                let kind = s(&v, "kind");
                let id = s(&v, "id");
                if kind.is_empty() || id.is_empty() {
                    continue;
                }
                if kind == "rebuild" {
                    // The re-image answered: the same server, now with
                    // its address. Not a second object.
                    let name = s(&v, "name");
                    let ip = s(&v, "public_ip");
                    match live.iter_mut().find(|o| o.kind == "server" && o.id == id) {
                        Some(o) => {
                            if !name.is_empty() {
                                o.name = name;
                            }
                            if !ip.is_empty() {
                                o.public_ip = ip;
                            }
                        }
                        None => live.push(LiveObject {
                            kind: "server".into(),
                            id,
                            name,
                            public_ip: ip,
                            origin: rebuild_origin(&mode).into(),
                        }),
                    }
                    continue;
                }
                if kind == "server" {
                    out.unanswered_server_intent = false;
                }
                live.retain(|o| !(o.kind == kind && o.id == id));
                live.push(LiveObject {
                    origin: if kind == "server" { "created".into() } else { String::new() },
                    kind,
                    id,
                    name: s(&v, "name"),
                    public_ip: s(&v, "public_ip"),
                });
            }
            "deleted" => {
                let mut kind = s(&v, "kind");
                if kind == "rebuild" {
                    kind = "server".into();
                }
                let id = s(&v, "id");
                live.retain(|o| !(o.kind == kind && o.id == id));
            }
            "done" => {
                if let Some(r) = v.get("record").filter(|r| r.is_object()) {
                    out.done_record = Some(r.clone());
                }
            }
            "failed" => {
                out.last_failed_code = Some(s(&v, "code"));
            }
            _ => {}
        }
    }
    for o in live {
        if o.kind == "server" {
            out.servers.push(o);
        } else {
            out.other_live.push(o);
        }
    }
    out.servers.reverse();
    out
}

fn rebuild_origin(mode: &str) -> &'static str {
    if mode == "rebuild_yours" {
        "yours"
    } else {
        "adopt"
    }
}

/// Where the journal for one relay lives.
pub fn journal_path(journal_dir: &Path, operator_id: i64) -> PathBuf {
    journal_dir.join(format!("{operator_id}.jsonl"))
}

/// The file whose presence asks a running `provision` for this relay to
/// stop (`daal-deploy provision --cancel-file`).
pub fn cancel_path(journal_dir: &Path, operator_id: i64) -> PathBuf {
    journal_dir.join(format!("{operator_id}.cancel"))
}

/// Read and summarise a journal; `None` when there is none.
pub fn read(journal_dir: &Path, operator_id: i64) -> Option<JournalSummary> {
    let text = std::fs::read_to_string(journal_path(journal_dir, operator_id)).ok()?;
    Some(summarize(&text))
}

/// Make the directory (0700) and return the path to hand the child.
pub fn prepare(journal_dir: &Path, operator_id: i64) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(journal_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(journal_dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(journal_path(journal_dir, operator_id))
}

/// Forget a relay's journal. Only ever after the outcome it recorded is
/// safely somewhere else (the record is in the database, or the cloud
/// side is gone). Never on a failure.
pub fn remove(journal_dir: &Path, operator_id: i64) {
    let _ = std::fs::remove_file(journal_path(journal_dir, operator_id));
}

/// Is a setup still running against this journal?
///
/// The child holds an EXCLUSIVE lock for its whole life and the kernel
/// drops it when the child dies, however it dies. So a shared lock that
/// cannot be taken means a live child. A missing file is not locked.
#[cfg(unix)]
#[allow(clippy::incompatible_msrv)]
pub fn is_locked(path: &Path) -> bool {
    let Ok(f) = std::fs::File::open(path) else {
        return false;
    };
    match f.try_lock_shared() {
        Ok(()) => {
            let _ = f.unlock();
            false
        }
        Err(std::fs::TryLockError::WouldBlock) => true,
        Err(std::fs::TryLockError::Error(_)) => false,
    }
}

#[cfg(not(unix))]
pub fn is_locked(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN1: &str = r#"{"v":1,"ev":"begin","seq":1,"ts":"2026-11-19T10:00:00Z","pid":4242,"provider":"hetzner","region":"fsn1","relay_name":"daal-fsn1-0011223344556677","mgmt_port":23456,"existing_server_id":"","mode":"create"}
{"v":1,"ev":"intent","seq":2,"ts":"x","kind":"ssh-key","name":"daal-fsn1-0011223344556677-ephemeral-ab12cd34"}
{"v":1,"ev":"created","seq":3,"ts":"x","kind":"ssh-key","id":"901","name":"daal-fsn1-0011223344556677-ephemeral-ab12cd34"}
{"v":1,"ev":"intent","seq":4,"ts":"x","kind":"server","name":"daal-fsn1-0011223344556677"}
{"v":1,"ev":"created","seq":5,"ts":"x","kind":"server","id":"123","name":"daal-fsn1-0011223344556677","public_ip":"203.0.113.7"}
{"v":1,"ev":"intent","seq":6,"ts":"x","kind":"firewall","name":"daal-relay-123"}
{"v":1,"ev":"created","seq":7,"ts":"x","kind":"firewall","id":"55","name":"daal-relay-123"}
{"v":1,"ev":"phase","seq":8,"ts":"x","step":"health_wait"}
"#;

    #[test]
    fn a_killed_run_leaves_its_server_and_leftovers_and_a_torn_line_is_ignored() {
        let text = format!("{RUN1}{{\"v\":1,\"ev\":\"created\",\"seq\":9,\"kind\":\"floa");
        let sum = summarize(&text);
        assert_eq!(sum.server_id(), Some("123"));
        assert_eq!(sum.servers[0].public_ip, "203.0.113.7");
        let kinds: Vec<_> = sum.other_live.iter().map(|o| o.kind.as_str()).collect();
        assert_eq!(kinds, vec!["ssh-key", "firewall"]);
        assert!(sum.done_record.is_none());
        assert_eq!(sum.last_begin.as_ref().unwrap().mode, "create");
    }

    #[test]
    fn objects_carry_across_runs_but_done_and_failed_belong_to_the_last() {
        let run2 = r#"{"v":1,"ev":"begin","seq":1,"ts":"2026-11-19T10:05:00Z","provider":"hetzner","region":"fsn1","relay_name":"daal-fsn1-0011223344556677","existing_server_id":"123","mode":"adopt"}
{"v":1,"ev":"deleted","seq":2,"ts":"x","kind":"ssh-key","id":"901"}
{"v":1,"ev":"intent","seq":3,"ts":"x","kind":"rebuild","name":"daal-fsn1-0011223344556677","id":"123"}
{"v":2,"ev":"created","seq":4,"kind":"server","id":"999"}
{"v":1,"ev":"teleported","seq":5}
{"v":1,"ev":"done","seq":6,"ts":"x","record":{"server_id":"123","mgmt_port":23456}}
"#;
        let first_failed = format!(
            "{RUN1}{}\n",
            r#"{"v":1,"ev":"failed","seq":9,"ts":"x","code":"health_timeout","rolled_back":false}"#
        );
        let one = summarize(&first_failed);
        assert_eq!(one.last_failed_code.as_deref(), Some("health_timeout"));

        let sum = summarize(&format!("{first_failed}{run2}"));
        // The failure belonged to run 1; run 2 finished.
        assert_eq!(sum.last_failed_code, None);
        assert_eq!(sum.done_record.as_ref().unwrap()["server_id"], "123");
        // v=2 and unknown events are ignored: no server 999.
        assert_eq!(sum.servers.len(), 1);
        assert_eq!(sum.server_id(), Some("123"));
        // The key was swept by run 2; the firewall from run 1 is still live.
        let kinds: Vec<_> = sum.other_live.iter().map(|o| o.kind.as_str()).collect();
        assert_eq!(kinds, vec!["firewall"]);
        assert_eq!(sum.last_begin.unwrap().mode, "adopt");
    }

    #[test]
    fn a_done_from_an_earlier_run_does_not_count() {
        let text = r#"{"v":1,"ev":"begin","mode":"create"}
{"v":1,"ev":"done","record":{"server_id":"1"}}
{"v":1,"ev":"begin","mode":"create"}
"#;
        assert!(summarize(text).done_record.is_none());
    }

    #[test]
    fn a_rebuild_intent_with_an_id_counts_as_a_server() {
        let text = r#"{"v":1,"ev":"begin","mode":"rebuild_yours","existing_server_id":"77"}
{"v":1,"ev":"intent","kind":"rebuild","id":"77","name":"mine"}
"#;
        let sum = summarize(text);
        assert_eq!(sum.server_id(), Some("77"));
    }

    #[test]
    fn the_persons_own_server_is_never_a_teardown_target_unless_asked() {
        // Run 1: their own server 77, health wait failed (no rollback on
        // a server they own). Run 2: they switched to renting; the new
        // server was created and rolled back.
        let text = r#"{"v":1,"ev":"begin","mode":"rebuild_yours","existing_server_id":"77"}
{"v":1,"ev":"intent","kind":"rebuild","id":"77","name":"mine"}
{"v":1,"ev":"created","kind":"rebuild","id":"77","name":"mine","public_ip":"192.0.2.77"}
{"v":1,"ev":"failed","code":"health_timeout","rolled_back":false}
{"v":1,"ev":"begin","mode":"create","existing_server_id":""}
{"v":1,"ev":"intent","kind":"server","name":"daal-fsn1-00"}
{"v":1,"ev":"created","kind":"server","id":"456","name":"daal-fsn1-00","public_ip":"203.0.113.9"}
{"v":1,"ev":"deleted","kind":"server","id":"456"}
"#;
        let sum = summarize(text);
        assert_eq!(sum.last_begin.as_ref().unwrap().mode, "create");
        assert_eq!(sum.own_server().map(|s| s.id.as_str()), Some("77"));
        assert_eq!(sum.own_server().unwrap().public_ip, "192.0.2.77");
        assert_eq!(sum.teardown_server_id(false), None, "never the person's own server");
        assert_eq!(sum.teardown_server_id(true), Some("77"));
        // The rebuild answer is not a second object.
        assert!(sum.other_live.is_empty(), "{:?}", sum.other_live);
    }

    #[test]
    fn a_server_create_with_no_answer_hides_an_older_id() {
        // Run 1 created 123 (since deleted outside the journal's view);
        // run 2 asked for a server and was killed before the answer.
        let text = format!(
            "{RUN1}{}\n{}\n{}\n",
            r#"{"v":1,"ev":"begin","mode":"create"}"#,
            r#"{"v":1,"ev":"intent","kind":"ssh-key","name":"k"}"#,
            r#"{"v":1,"ev":"intent","kind":"server","name":"daal-fsn1-0011223344556677"}"#,
        );
        let sum = summarize(&text);
        assert!(sum.unanswered_server_intent);
        assert_eq!(sum.server_id(), Some("123"));
        assert_eq!(sum.teardown_server_id(false), None, "let decommission look up the name");
        // Once a server create is answered, its id is trusted again.
        assert_eq!(summarize(RUN1).teardown_server_id(false), Some("123"));
    }

    #[test]
    fn an_adopted_server_keeps_one_entry_with_its_address_and_a_rollback_clears_it() {
        let text = r#"{"v":1,"ev":"begin","mode":"adopt","existing_server_id":"123"}
{"v":1,"ev":"intent","kind":"rebuild","id":"123","name":"daal-fsn1-00"}
{"v":1,"ev":"created","kind":"rebuild","id":"123","name":"daal-fsn1-00","public_ip":"203.0.113.7"}
"#;
        let sum = summarize(text);
        assert_eq!(sum.servers.len(), 1);
        assert_eq!(sum.servers[0].public_ip, "203.0.113.7");
        assert_eq!(sum.servers[0].origin, "adopt");
        assert!(sum.other_live.is_empty(), "no phantom 'rebuild' object");
        assert_eq!(sum.teardown_server_id(false), Some("123"));
        let rolled = format!("{text}{}\n", r#"{"v":1,"ev":"deleted","kind":"server","id":"123"}"#);
        let sum = summarize(&rolled);
        assert!(sum.servers.is_empty() && sum.other_live.is_empty());
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::incompatible_msrv)]
    fn an_exclusive_lock_reads_as_running_and_its_release_as_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = prepare(dir.path(), 4).unwrap();
        assert!(!is_locked(&path), "no file is not a running setup");
        std::fs::write(&path, RUN1).unwrap();
        assert!(!is_locked(&path));
        let holder = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        holder.lock().unwrap();
        assert!(is_locked(&path));
        drop(holder);
        assert!(!is_locked(&path));
    }
}
