//! Publisher-alone wave, end to end: the app's own command functions,
//! the REAL `daal-deploy` built from this tree (through the production
//! `SubprocessRunner`), and a fake hosting company whose servers run a
//! management service in-process (`publisher/deploy/e2e/fakeworld`).
//!
//! Nothing here reaches a real cloud: the child is pointed at the fake
//! with `HTTPS_PROXY` + `SSL_CERT_FILE` by a two-line wrapper script
//! (the production runner clears the environment), and the fake's
//! proxy tunnels to nothing but itself.
//!
//! Binaries: `DAAL_E2E_DEPLOY_BIN` and `DAAL_E2E_FAKEWORLD_BIN` when
//! set (`./daal test` builds both from this tree); otherwise they are
//! built here with `go build`. Without Go and without those variables
//! the tests FAIL, unless `DAAL_E2E_SKIP=1` says out loud that they
//! did not run.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;

use daal_wizard::cli_bridge::{CliRunner, SubprocessRunner};
use daal_wizard::commands::{
    copy_pasteable, list_operators, provision_run, publisher_keygen, qr_render, relay_destroy,
    rotate_execute, select_profile, set_helper_ip, sign_relaypack, store_cloud_token,
    RotateExecuteInput, WizardCtx,
};
use daal_wizard::device_custody::FileCustody;
use daal_wizard::keystore::Keystore;
use daal_wizard::operator_db::OperatorDb;
use daal_wizard::recipient_book::{recipient_provision, recipient_revoke};
use daal_wizard::recipient_paste::{stage_pasted_text, stage_sealed_b64, PastedKind};
use daal_wizard::recipient_sbpx::import_sbpx;
use daal_wizard::setup_recovery::{setup_recovery, setup_remove_server};

const TOKEN: &str = "fakeworld-account-token-0001";
/// Families a test process can serve: TCP, above 1024 (relayports:
/// anytls = 8447, shadowsocks = 8446). 443 would need privileges.
const FAMILY: &str = "anytls";
/// Two ways, because a relay pack needs at least two direct routes.
const FAMILIES: [&str; 2] = ["anytls", "shadowsocks"];

// ---------------------------------------------------------------- bins

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn go_build(dir: &Path, pkg: &str, out: &Path) {
    let st = Command::new("go")
        .current_dir(dir)
        .args(["build", "-o"])
        .arg(out)
        .arg(pkg)
        .status()
        .unwrap_or_else(|e| panic!("`go build {pkg}` could not start ({e}); set DAAL_E2E_DEPLOY_BIN/DAAL_E2E_FAKEWORLD_BIN or DAAL_E2E_SKIP=1"));
    assert!(st.success(), "go build {pkg} failed");
}

/// `None` = skipped on purpose (DAAL_E2E_SKIP=1).
fn bins() -> Option<&'static (PathBuf, PathBuf)> {
    static B: OnceLock<Option<(PathBuf, PathBuf)>> = OnceLock::new();
    B.get_or_init(|| {
        if std::env::var("DAAL_E2E_SKIP").as_deref() == Ok("1") {
            eprintln!("publisher_alone_e2e: SKIPPED by DAAL_E2E_SKIP=1 — nothing was tested end to end");
            return None;
        }
        if let (Ok(d), Ok(f)) = (std::env::var("DAAL_E2E_DEPLOY_BIN"), std::env::var("DAAL_E2E_FAKEWORLD_BIN")) {
            return Some((PathBuf::from(d), PathBuf::from(f)));
        }
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("publisher-e2e-bin");
        std::fs::create_dir_all(&out).unwrap();
        let root = repo_root();
        go_build(&root.join("cmd/daal-deploy"), ".", &out.join("daal-deploy"));
        go_build(&root.join("publisher"), "./deploy/e2e/fakeworld/cmd/fakeworld", &out.join("fakeworld"));
        Some((out.join("daal-deploy"), out.join("fakeworld")))
    })
    .as_ref()
}

// --------------------------------------------------------------- world

/// One fake hosting account and the app state of one phone.
struct World {
    _child: Child,
    _stdin: ChildStdin,
    control: String,
    wrapper: PathBuf,
    pidfile: PathBuf,
    dir: tempfile::TempDir,
}

impl World {
    fn start() -> Option<World> {
        let (deploy, fakeworld) = bins()?;
        let dir = tempfile::tempdir().unwrap();
        let tok = dir.path().join("account.token");
        std::fs::write(&tok, TOKEN).unwrap();
        let mut child = Command::new(fakeworld)
            .arg("-dir")
            .arg(dir.path())
            .arg("-token-file")
            .arg(&tok)
            .arg("-families")
            .arg(FAMILIES.join(","))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start fakeworld");
        let stdin = child.stdin.take().unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let ep: Value = serde_json::from_str(&line).expect("fakeworld endpoints");
        let pidfile = dir.path().join("provision.pid");
        let wrapper = dir.path().join("daal-deploy");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\n[ \"$1\" = provision ] && echo $$ > '{pid}'\nexport HTTPS_PROXY='{proxy}' SSL_CERT_FILE='{ca}'\nexec '{bin}' \"$@\"\n",
                pid = pidfile.display(),
                proxy = ep["proxy"].as_str().unwrap(),
                ca = ep["ca_file"].as_str().unwrap(),
                bin = deploy.display(),
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Some(World {
            _child: child,
            _stdin: stdin,
            control: ep["control"].as_str().unwrap().trim_start_matches("http://").to_string(),
            wrapper,
            pidfile,
            dir,
        })
    }

    /// A phone: its own database, custody and staging, the real runner.
    fn phone(&self, name: &str) -> WizardCtx {
        let root = self.dir.path().join(name);
        std::fs::create_dir_all(root.join("staging")).unwrap();
        let cli: Arc<dyn CliRunner> = Arc::new(SubprocessRunner::new(Some(self.wrapper.clone())));
        WizardCtx {
            db: Arc::new(OperatorDb::open_in_memory().unwrap()),
            keystore: Arc::new(Keystore::new_in_memory(&root)),
            staging_dir: root.join("staging"),
            journal_dir: root.join("state").join("provision-journal"),
            cli,
            clock: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
            }),
            custody: Arc::new(FileCustody::static_test(&root).unwrap()),
        }
    }

    fn http(&self, method: &str, path: &str, body: &str) -> Value {
        let mut s = TcpStream::connect(&self.control).unwrap();
        write!(
            s,
            "{method} {path} HTTP/1.0\r\nHost: control\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        let (head, body) = resp.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200"), "{method} {path}: {head}\n{body}");
        serde_json::from_str(body).unwrap()
    }

    fn state(&self) -> Value {
        self.http("GET", "/state", "")
    }

    fn wait_for(&self, what: &str, f: impl Fn(&Value) -> bool) -> Value {
        let t0 = Instant::now();
        loop {
            let st = self.state();
            if f(&st) {
                return st;
            }
            assert!(t0.elapsed() < Duration::from_secs(60), "timed out waiting for {what}: {st:#}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The app is killed: the setup helper dies between two
    /// instructions (Android kills the whole process group).
    fn kill_setup_helper(&self) {
        let pid = std::fs::read_to_string(&self.pidfile).unwrap();
        let st = Command::new("kill").args(["-9", pid.trim()]).status().unwrap();
        assert!(st.success());
    }
}

fn len(v: &Value, k: &str) -> usize {
    v[k].as_array().map(|a| a.len()).unwrap_or(0)
}

/// A relay row taken up to "ready to build", as the wizard does.
fn ready_to_build(ctx: &WizardCtx) -> i64 {
    let id = store_cloud_token(ctx, "hetzner", TOKEN, None).unwrap();
    select_profile(ctx, id, "fsn1", "cx22", "iran-default", FAMILIES.iter().map(|f| f.to_string()).collect()).unwrap();
    publisher_keygen(ctx, id).unwrap();
    set_helper_ip(ctx, id, "127.0.0.1", "manual").unwrap();
    id
}

/// Start a setup, let it rent the server and its firewall, then kill
/// the helper before the server is ready. Returns the server id.
fn killed_setup(w: &World, ctx: &WizardCtx, id: i64) -> String {
    w.http("POST", "/hold-health?on=1", "");
    let c2 = ctx.clone();
    let t = std::thread::spawn(move || provision_run(&c2, id, "", &mut |_| {}));
    let st = w.wait_for("a server and its firewall", |s| len(s, "servers") == 1 && len(s, "firewalls") == 1);
    // The firewall exists, so its `created` line is on disk: the child
    // writes it before its next cloud call. Give the child a moment to
    // get into the health wait, then kill it.
    std::thread::sleep(Duration::from_millis(300));
    w.kill_setup_helper();
    let res = t.join().unwrap();
    assert!(res.is_err(), "a killed setup must not report success");
    w.http("POST", "/hold-health?on=0", "");
    assert_eq!(ctx.db.get(id).unwrap().status, "pre-provision", "nothing was saved");
    st["servers"][0]["id"].as_i64().unwrap().to_string()
}

fn provisioned(w: &World, ctx: &WizardCtx) -> i64 {
    let _ = w;
    let id = ready_to_build(ctx);
    provision_run(ctx, id, "", &mut |_| {}).expect("provision against the fake");
    let out = ctx.staging_dir.clone();
    sign_relaypack(ctx, id, daal_wizard::phase::RELAYPACK_PHASE, &out, "", &mut |_| {})
        .expect("sign the relay's file");
    id
}

// ------------------------------------------------------------------ D1

#[test]
fn d1_a_killed_setup_is_finished_on_the_server_that_already_exists() {
    let Some(w) = World::start() else { return };
    let ctx = w.phone("publisher");
    let id = ready_to_build(&ctx);
    let server_id = killed_setup(&w, &ctx, id);

    // The app comes back: the card says what is there, from the journal
    // and the account, and nothing is rented by asking.
    let r = setup_recovery(&ctx, id).unwrap();
    assert_eq!(r.state, "server_running", "{r:?}");
    assert!(r.can_finish_here, "{r:?}");
    assert_eq!(r.server_id, server_id);
    assert_eq!(r.billing, "yes");
    assert_eq!(r.server_origin, "created");
    assert!(r.leftovers.iter().any(|l| l.kind == "server" && l.id == server_id), "{r:?}");

    // "Finish setting up on this server".
    provision_run(&ctx, id, &r.server_id, &mut |_| {}).expect("finish on the same server");

    let st = w.state();
    assert_eq!(st["servers_created"], 1, "exactly one server was ever rented: {st:#}");
    assert_eq!(st["rebuilds"], 1, "it was re-imaged in place");
    assert_eq!(len(&st, "servers"), 1);
    assert_eq!(st["servers"][0]["id"].as_i64().unwrap().to_string(), server_id);
    assert_eq!(len(&st, "ssh_keys"), 0, "the killed run's one-shot key was swept: {st:#}");
    let row = ctx.db.get(id).unwrap();
    assert_eq!(row.status, "provisioned");
    assert_eq!(row.mgmt_tls_fingerprint, st["servers"][0]["mgmt_fp"].as_str().unwrap(), "pinned to the re-imaged box");
    let rec: Value = serde_json::from_str(&row.operator_record_json).unwrap();
    assert_eq!(rec["server_id"].as_str().unwrap(), server_id);
    assert!(
        !daal_wizard::provision_journal::journal_path(&ctx.journal_dir, id).exists(),
        "a saved setup leaves no journal"
    );
    assert_eq!(len(&st, "unmodelled"), 0, "{st:#}");
}

#[test]
fn d1_a_killed_setup_is_deleted_with_everything_it_made() {
    let Some(w) = World::start() else { return };
    let ctx = w.phone("publisher");
    let id = ready_to_build(&ctx);
    let server_id = killed_setup(&w, &ctx, id);
    let st = w.state();
    let relay = st["servers"][0]["name"].as_str().unwrap().to_string();
    // An address reserved for this relay (as an address change would).
    let sid: i64 = server_id.parse().unwrap();
    w.http(
        "POST",
        "/reserve-address",
        &serde_json::json!({"labels":{"managed-by":"daal-deploy","daal-relay":relay},"server":sid}).to_string(),
    );
    assert!(len(&st, "ssh_keys") >= 1, "the killed run left its one-shot key: {st:#}");

    let r = setup_recovery(&ctx, id).unwrap();
    assert_eq!(r.state, "server_running", "{r:?}");

    // "Delete this server".
    let rep = setup_remove_server(&ctx, id).expect("delete what the setup made");
    assert!(rep.server_deleted, "{rep:?}");
    assert!(!rep.retry_needed, "{rep:?}");
    assert!(rep.addresses.iter().any(|a| a.code == "released"), "{rep:?}");

    let st = w.state();
    assert_eq!(len(&st, "servers"), 0, "{st:#}");
    assert_eq!(len(&st, "firewalls"), 0, "{st:#}");
    assert_eq!(len(&st, "ssh_keys"), 0, "{st:#}");
    assert_eq!(len(&st, "floating_ips"), 0, "{st:#}");
    let row = ctx.db.get(id).unwrap();
    assert_eq!(row.status, "pre-provision", "the relay stays, ready to start again");
    assert!(!row.cloud_token_keystore_alias.is_empty());
    assert_eq!(setup_recovery(&ctx, id).unwrap().state, "nothing_billing");
    assert_eq!(len(&st, "unmodelled"), 0, "{st:#}");
}

// ------------------------------------------------------------------ D2

/// A person's phone: a recipient identity of its own.
fn person(w: &World, name: &str) -> (WizardCtx, String) {
    let ctx = w.phone(name);
    let id = daal_wizard::recipient_identity::get_or_create(&ctx).expect("recipient identity");
    (ctx, id.address)
}

fn server_of(st: &Value) -> &Value {
    assert_eq!(len(st, "servers"), 1, "{st:#}");
    &st["servers"][0]
}

#[test]
fn d2_after_a_rebuild_one_press_renews_everyone_and_a_second_press_changes_nothing() {
    let Some(w) = World::start() else { return };
    let ctx = w.phone("publisher");
    let op = provisioned(&w, &ctx);
    let mut rids = Vec::new();
    for n in ["Bahar", "Dara", "Sima"] {
        let (_phone, addr) = person(&w, n);
        rids.push(recipient_provision(&ctx, op, &addr, n).expect("add a person").id);
    }
    let removed = recipient_revoke(&ctx, op, rids[1]).expect("remove Dara");
    let st = w.state();
    assert_eq!(server_of(&st)["users"].as_array().unwrap().len(), 2, "{st:#}");

    // The relay is rebuilt on a new server (the L4 rung: another
    // datacenter). Its roster is empty there.
    rotate_execute(
        &ctx,
        op,
        RotateExecuteInput {
            level: "L4".into(),
            reason: "e2e".into(),
            helper_ip: Some("127.0.0.1".into()),
            new_region: Some("hel1".into()),
            ..Default::default()
        },
        &mut |_| {},
    )
    .expect("rebuild the relay");
    let st = w.state();
    let box_ = server_of(&st);
    assert_eq!(box_["users"].as_array().unwrap().len(), 0, "a new server knows nobody: {st:#}");
    let new_fp = box_["mgmt_fp"].as_str().unwrap().to_string();
    assert_eq!(ctx.db.get(op).unwrap().mgmt_tls_fingerprint, new_fp, "the rebuild pinned the new box");
    let summary = list_operators(&ctx).unwrap().into_iter().find(|s| s.id == op).unwrap();
    assert_eq!(summary.people_needing_renewal, 2, "the two people not removed need new files");

    // "Renew everyone's files".
    let rep = daal_wizard::renew::renew_everyone(&ctx, op, &mut |_| {}).expect("renew");
    assert!(rep.all_done, "{rep:#?}");
    let live: Vec<_> = rep.items.iter().filter(|i| i.recipient_id != Some(removed.id)).collect();
    assert_eq!(live.len(), 2, "{rep:#?}");
    for it in &live {
        assert_eq!(it.status, "done", "{it:?}");
        assert!(Path::new(&it.sbpx_path).exists(), "{it:?}");
    }
    assert!(
        rep.items.iter().all(|i| i.recipient_id != Some(removed.id) || i.status == "removed_from_server"),
        "a removed person is never given a file: {rep:#?}"
    );
    let st = w.state();
    let box_ = server_of(&st);
    let mut users: Vec<String> = box_["users"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    users.sort();
    let mut want = vec![
        ctx.db.get_recipient(op, rids[0]).unwrap().unwrap().name,
        ctx.db.get_recipient(op, rids[2]).unwrap().unwrap().name,
    ];
    want.sort();
    assert_eq!(users, want, "exactly the people not removed are on the new server");
    assert!(!users.contains(&removed.name), "the removed person was NOT re-created");
    let writes_after_first = box_["mgmt_writes"].clone();
    assert_eq!(list_operators(&ctx).unwrap().into_iter().find(|s| s.id == op).unwrap().people_needing_renewal, 0);

    // Pressed again: nothing on the server changes.
    let rep2 = daal_wizard::renew::renew_everyone(&ctx, op, &mut |_| {}).expect("renew again");
    assert!(rep2.all_done, "{rep2:#?}");
    for it in rep2.items.iter().filter(|i| i.recipient_id != Some(removed.id)) {
        assert_eq!(it.status, "already_done", "{it:?}");
    }
    let st = w.state();
    assert_eq!(server_of(&st)["mgmt_writes"], writes_after_first, "a second press wrote nothing to the box");
    assert_eq!(len(&st, "unmodelled"), 0, "{st:#}");
}

// ------------------------------------------------------------------ D3

#[test]
fn d3_health_says_working_stopped_and_management_silent_from_the_real_checks() {
    let Some(w) = World::start() else { return };
    let ctx = w.phone("publisher");
    let op = provisioned(&w, &ctx);
    let sid = server_of(&w.state())["id"].as_i64().unwrap();

    let h = daal_wizard::relay_health::relay_health(&ctx, op, true).expect("health");
    assert_eq!(h.overall, "working", "{h:#?}");
    assert_eq!(h.server, "running");
    assert_eq!(h.management, "answers");
    assert_eq!(h.keys_match, Some(true), "{h:#?}");
    assert_eq!(h.people_missing, Some(0));
    assert!(h.ways.iter().any(|w| w.family == FAMILY && w.state == "answers"), "{h:#?}");
    let cached = daal_wizard::relay_health::relay_health(&ctx, op, false).unwrap();
    assert!(cached.from_cache, "opening the page again does not re-check");

    // The management port stops answering; the way still answers.
    w.http("POST", &format!("/servers/{sid}/stop-management"), "");
    let h = daal_wizard::relay_health::relay_health(&ctx, op, true).expect("health");
    assert_eq!(h.management, "no_answer", "{h:#?}");
    assert_ne!(h.overall, "working", "{h:#?}");
    assert!(h.ways.iter().any(|w| w.family == FAMILY && w.state == "answers"), "{h:#?}");

    // The server is switched off at the hosting company.
    w.http("POST", &format!("/servers/{sid}/status?s=off"), "");
    let h = daal_wizard::relay_health::relay_health(&ctx, op, true).expect("health");
    assert_eq!(h.server, "stopped", "{h:#?}");
    assert_eq!(h.overall, "not_working", "{h:#?}");
    assert_eq!(h.management, "not_checked", "no window is opened on a stopped server");
    assert_eq!(len(&w.state(), "unmodelled"), 0);
}

// ------------------------------------------------------------------ D4

#[test]
fn d4_deleting_a_relay_releases_its_address_and_a_failed_release_is_retried() {
    let Some(w) = World::start() else { return };
    let ctx = w.phone("publisher");
    let op = provisioned(&w, &ctx);
    let st = w.state();
    let srv = server_of(&st);
    let fip = w.http(
        "POST",
        "/reserve-address",
        &serde_json::json!({"labels":{"managed-by":"daal-deploy","daal-relay":srv["name"]},"server":srv["id"]}).to_string(),
    );
    let ip = fip["ip"].as_str().unwrap().to_string();
    w.http("POST", "/fail-fip-deletes?n=1", "");

    let rep = relay_destroy(&ctx, op, true).expect("delete the relay");
    assert!(rep.server_deleted, "{rep:?}");
    assert!(rep.retry_needed && !rep.local_removed, "{rep:?}");
    assert!(rep.addresses.iter().any(|a| a.ip == ip && a.code == "release_failed"), "{rep:?}");
    assert!(
        rep.warnings.iter().all(|x| !x.contains("daal-deploy ")),
        "no command line for the person to type: {rep:?}"
    );
    let s = list_operators(&ctx).unwrap().into_iter().find(|s| s.id == op).expect("row kept");
    assert_eq!(s.status, "decommissioned");
    assert_eq!(s.unreleased_addresses, vec![ip.clone()]);
    let st = w.state();
    assert_eq!(len(&st, "servers"), 0);
    assert_eq!(len(&st, "floating_ips"), 1, "it still bills");

    // "Try again".
    let rep = relay_destroy(&ctx, op, true).expect("try again");
    assert!(!rep.retry_needed && rep.local_removed, "{rep:?}");
    assert!(rep.addresses.iter().any(|a| a.ip == ip && a.code == "released"), "{rep:?}");
    let st = w.state();
    assert_eq!(len(&st, "floating_ips"), 0, "{st:#}");
    assert_eq!(len(&st, "firewalls"), 0, "{st:#}");
    assert!(list_operators(&ctx).unwrap().iter().all(|s| s.id != op));
    assert_eq!(len(&st, "unmodelled"), 0, "{st:#}");
}

// ------------------------------------------------------------------ D5

fn verify_plain(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    let sbp = bundle_rs::parse_sbp(&bytes).expect("a bundle");
    bundle_rs::verify_bundle_at(&sbp, time::OffsetDateTime::now_utc()).expect("signature, revocation and expiry hold");
}

#[test]
fn d5_one_persons_file_survives_copy_as_text_and_the_qr_code_and_still_verifies() {
    let Some(w) = World::start() else { return };
    let (_, fakeworld) = bins().unwrap();
    let ctx = w.phone("publisher");
    let op = provisioned(&w, &ctx);
    let (phone, addr) = person(&w, "bahar-phone");
    let rid = recipient_provision(&ctx, op, &addr, "Bahar").expect("add Bahar").id;
    let artifact = format!("recipient:{rid}");

    // Copy as text → pasted on Bahar's phone.
    let text = copy_pasteable(&ctx, op, &artifact).expect("copy as text");
    let staged = stage_pasted_text(&phone.staging_dir, &text).expect("paste");
    assert_eq!(staged.kind, PastedKind::Sbpx);
    verify_plain(&import_sbpx(&phone, &staged.path).expect("only Bahar's phone opens it"));

    // Show as QR code → scanned on Bahar's phone (the engine's decoder
    // hands the shell `sealed_b64`).
    let mut frames = String::new();
    qr_render(&ctx, op, &artifact, 96, 4000, 7, &mut |f| {
        frames.push_str(&f.frame_b64);
        frames.push('\n');
        true
    })
    .expect("QR frames");
    let mut dec = Command::new(fakeworld)
        .arg("fountain-decode")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // The decoder stops reading once it has the whole file.
    let _ = dec.stdin.take().unwrap().write_all(frames.as_bytes());
    let out = dec.wait_with_output().unwrap();
    assert!(out.status.success(), "the frames decode to a whole file");
    let sealed_b64 = String::from_utf8(out.stdout).unwrap();
    let file = ctx.staging_dir.join(format!("{op}.{}.sbpx", ctx.db.get_recipient(op, rid).unwrap().unwrap().name));
    assert_eq!(STANDARD.decode(sealed_b64.trim()).unwrap(), std::fs::read(&file).unwrap(), "bytes identical");
    let staged = stage_sealed_b64(&phone.staging_dir, sealed_b64.trim()).expect("stage");
    verify_plain(&import_sbpx(&phone, &staged.path).expect("unseal"));

    // Someone else's phone cannot open it.
    let (other, _) = person(&w, "someone-else");
    let staged = stage_pasted_text(&other.staging_dir, &text).expect("paste");
    assert!(import_sbpx(&other, &staged.path).is_err(), "sealed to Bahar only");

    // A removed person's file is not handed out.
    recipient_revoke(&ctx, op, rid).unwrap();
    assert!(copy_pasteable(&ctx, op, &artifact).is_err());
}

/// D1, the account check: a server another phone stranded is found by
/// Daal's own labels, offered for deletion, and deleted with what was
/// made with it — and nothing unlabelled is ever touched.
#[test]
fn d1_the_account_check_finds_and_deletes_a_server_another_phone_stranded() {
    let Some(w) = World::start() else { return };
    let a = w.phone("phone-a");
    let id_a = ready_to_build(&a);
    let server_id = killed_setup(&w, &a, id_a);
    let relay = server_of(&w.state())["name"].as_str().unwrap().to_string();
    let sid: i64 = server_id.parse().unwrap();
    w.http(
        "POST",
        "/reserve-address",
        &serde_json::json!({"labels":{"managed-by":"daal-deploy","daal-relay":relay},"server":sid}).to_string(),
    );
    // Something in the account Daal did not make.
    let theirs = w.http("POST", "/reserve-address", &serde_json::json!({"labels":{},"server":0}).to_string());

    // Phone B holds a token for the same account and no record of it.
    let b = w.phone("phone-b");
    let _ = ready_to_build(&b);
    let chk = daal_wizard::setup_recovery::account_check(&b).expect("account check");
    assert_eq!(chk.accounts.len(), 1, "{chk:#?}");
    let acc = &chk.accounts[0];
    assert!(acc.complete && acc.error_code.is_empty(), "{acc:#?}");
    let srv = acc.items.iter().find(|i| i.kind == "server" && i.id == server_id).expect("the stranded server is listed");
    assert_eq!(srv.finding, "not_on_this_phone", "{srv:?}");
    assert!(srv.can_delete && srv.billing, "{srv:?}");
    assert!(
        acc.items.iter().all(|i| i.id != theirs["id"].as_i64().unwrap().to_string() || !i.can_delete),
        "an address Daal did not label is never offered: {acc:#?}"
    );
    let text = serde_json::to_string(&chk).unwrap();
    assert!(!text.contains(TOKEN), "the token never leaves Rust");

    let picked: Vec<_> = acc.items.iter().filter(|i| i.can_delete).map(|i| daal_wizard::cli_bridge::ResourceRef { kind: i.kind.clone(), id: i.id.clone() }).collect();
    let rep = daal_wizard::setup_recovery::account_cleanup(&b, &acc.account_key, &picked).expect("cleanup");
    assert!(rep.outcomes.iter().any(|o| o.kind == "server" && o.id == server_id && o.code == "deleted"), "{rep:#?}");

    let st = w.state();
    assert_eq!(len(&st, "servers"), 0, "{st:#}");
    assert_eq!(len(&st, "firewalls"), 0, "{st:#}");
    assert_eq!(len(&st, "ssh_keys"), 0, "{st:#}");
    let fips = st["floating_ips"].as_array().unwrap();
    assert_eq!(fips.len(), 1, "only the address Daal did not make is left: {st:#}");
    assert_eq!(fips[0]["id"], theirs["id"]);
    assert_eq!(len(&st, "unmodelled"), 0, "{st:#}");
}
