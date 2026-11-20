//! Backup and restore, driven through the real command functions with
//! two tempdirs as two phones (each `FileCustody::static_test` has its
//! own binding salt) and `MockRunner`. Nothing reaches a cloud or relay.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use super::*;
use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
use crate::commands::{
    list_operators, provision_run, publisher_keygen, select_profile, set_helper_ip,
    set_operator_nickname, store_cloud_token, WizardCtx,
};
use crate::device_custody::{DeviceCustody, FileCustody};
use crate::keystore::Keystore;
use crate::operator_db::OperatorDb;
use crate::recipient_book::{produce_shared_sbp, recipient_provision, recipient_revoke};

const FP_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "hcloud_TESTTOKEN_do_not_leak_0001";
const NICK: &str = "Bahar-Relay";
const IP: &str = "203.0.113.7";
const PERSON: &str = "Maman";
const GH_PAT: &str = "github_pat_TESTPAT_do_not_leak_42";

struct Phone {
    ctx: WizardCtx,
    mock: Arc<MockRunner>,
    #[allow(dead_code)]
    clock: Arc<AtomicI64>,
    dir: tempfile::TempDir,
}

fn record(server_id: &str, fp: &str) -> String {
    serde_json::json!({
        "provider":"hetzner","server_id":server_id,"region":"fsn1",
        "server_type":"cx22","public_ip":IP,
        "toolbox_profile":"iran-default",
        "enabled_families":["vless-reality"],
        "publisher_pub_key":"ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8=",
        "mgmt_port":42424,
        "mgmt_tls_fingerprint":fp,
        "candidates":[{"family":"vless-reality"}],
        "provisioned_at":"2026-11-19T10:00:00Z",
        "freshness_url":""
    })
    .to_string()
}

fn phone() -> Phone {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(OperatorDb::open_in_memory().unwrap());
    let ks = Arc::new(Keystore::new_in_memory(dir.path()));
    let staging_dir = dir.path().join("staging");
    std::fs::create_dir_all(&staging_dir).unwrap();
    let mock = Arc::new(
        MockRunner::new(Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        })
        .with_provision_record(record("123", FP_A)),
    );
    let cli: Arc<dyn CliRunner> = mock.clone();
    let clock = Arc::new(AtomicI64::new(1_800_000_000));
    let c2 = clock.clone();
    let custody: Arc<dyn DeviceCustody> = Arc::new(FileCustody::static_test(dir.path()).unwrap());
    let ctx = WizardCtx {
        db,
        keystore: ks,
        journal_dir: dir.path().join("state").join("provision-journal"),
        staging_dir,
        cli,
        clock: Arc::new(move || c2.load(Ordering::SeqCst)),
        custody,
    };
    Phone {
        ctx,
        mock,
        clock,
        dir,
    }
}

fn address(byte: u8) -> String {
    daal_recipient_addr::encode(&[byte; 32])
}

const JOURNAL: &str = r#"{"v":1,"ev":"begin","seq":1,"ts":"2026-11-19T10:00:00Z","provider":"hetzner","region":"fsn1","relay_name":"daal-fsn1-0011223344556677","existing_server_id":"","mode":"create"}
"#;

struct Populated {
    live: i64,
    unfinished: i64,
    maman: i64,
}

/// Two relays (one finished with three people, one removed; one setup
/// stopped with a journal), the files, the tokens, a refresh address
/// with its key and a sub-key row with one path outside staging.
fn populate(p: &Phone) -> Populated {
    let live = store_cloud_token(&p.ctx, "hetzner", TOKEN, None).unwrap();
    select_profile(
        &p.ctx,
        live,
        "fsn1",
        "cx22",
        "iran-default",
        vec!["vless-reality".into()],
    )
    .unwrap();
    publisher_keygen(&p.ctx, live).unwrap();
    set_helper_ip(&p.ctx, live, "198.51.100.1", "manual").unwrap();
    provision_run(&p.ctx, live, "", &mut |_| {}).unwrap();
    std::fs::write(
        p.ctx.staging_dir.join(format!("{live}.sbp")),
        b"signed-bundle",
    )
    .unwrap();
    p.ctx
        .db
        .record_signed_sbp(live, "sha-test", "rp-test", 1_800_000_000)
        .unwrap();
    set_operator_nickname(&p.ctx, live, NICK).unwrap();
    let maman = recipient_provision(&p.ctx, live, &address(1), PERSON).unwrap();
    recipient_provision(&p.ctx, live, &address(2), "Bob").unwrap();
    let carol = recipient_provision(&p.ctx, live, &address(3), "Carol").unwrap();
    recipient_revoke(&p.ctx, live, carol.id).unwrap();
    {
        let mut users = p.mock.box_users.lock().unwrap();
        users.insert("r1".into());
        users.insert("r2".into());
    }
    produce_shared_sbp(&p.ctx, live).unwrap();
    crate::freshness::add_endpoint(
        &p.ctx,
        live,
        crate::freshness::FreshnessEndpointInput {
            kind: "ghpages".into(),
            public_url: "https://example.github.io/f.json".into(),
            gh_owner: "o".into(),
            gh_repo: "r".into(),
            gh_path: "f.json".into(),
            gh_branch: "main".into(),
            gh_pat: GH_PAT.into(),
            ..Default::default()
        },
    )
    .unwrap();
    let sk = p.ctx.staging_dir.join("subkeys").join(live.to_string());
    std::fs::create_dir_all(&sk).unwrap();
    std::fs::write(sk.join("subkey.priv"), b"sub-priv-bytes").unwrap();
    std::fs::write(sk.join("subkey.pub"), b"sub-pub-bytes").unwrap();
    let outside = p.dir.path().join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("cert.json"), b"sub-cert").unwrap();
    p.ctx
        .db
        .insert_subkey_rotation(
            live,
            "fp",
            &sk.join("subkey.pub").to_string_lossy(),
            &sk.join("subkey.priv").to_string_lossy(),
            &outside.join("cert.json").to_string_lossy(),
            "{}",
            "l",
            1,
            2,
            3,
        )
        .unwrap();

    let unfinished =
        store_cloud_token(&p.ctx, "hetzner", "hcloud_SECOND_token_0002", None).unwrap();
    select_profile(
        &p.ctx,
        unfinished,
        "fsn1",
        "cx22",
        "iran-default",
        vec!["vless-reality".into()],
    )
    .unwrap();
    publisher_keygen(&p.ctx, unfinished).unwrap();
    let j = crate::provision_journal::prepare(&p.ctx.journal_dir, unfinished).unwrap();
    std::fs::write(j, JOURNAL).unwrap();
    Populated {
        live,
        unfinished,
        maman: maman.id,
    }
}

/// Create and confirm words; returns them as typed text.
fn set_words(p: &Phone) -> String {
    let w = words_new(&p.ctx).unwrap().words;
    words_confirm(
        &p.ctx,
        &[0, 5, 11].map(|i| WordAnswer {
            index: i,
            word: w[i as usize].clone(),
        }),
    )
    .unwrap();
    w.join(" ")
}

fn make(p: &Phone) -> PathBuf {
    let m = backup_make_file(&p.ctx, None).unwrap();
    backup_mark_made(&p.ctx, &m).unwrap();
    m.path
}

/// Copy a backup somewhere the restoring phone reads it from.
fn carry(file: &Path, to: &Phone) -> PathBuf {
    let dst = to.dir.path().join("picked.daalbackup");
    std::fs::copy(file, &dst).unwrap();
    dst
}

fn entropy(p: &Phone) -> [u8; 16] {
    let e = read_entropy(&p.ctx, WORDS_ALIAS).unwrap().unwrap();
    *e
}

/// Every table, every row, plus every file under the phone's dir.
fn fingerprint(p: &Phone, skip: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    p.ctx.db.with_conn(|c| {
        for t in all_tables(c).unwrap() {
            let cols = table_columns(c, &t).unwrap();
            let sel = cols
                .iter()
                .map(|c| format!("quote(\"{c}\")"))
                .collect::<Vec<_>>()
                .join("||'|'||");
            let mut s = c
                .prepare(&format!("SELECT {sel} FROM \"{t}\" ORDER BY rowid"))
                .unwrap();
            let rows: Vec<String> = s
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            out.insert(format!("db:{t}"), rows.join("\n"));
        }
    });
    fn walk(d: &Path, skip: &Path, out: &mut BTreeMap<String, String>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let path = e.path();
            if path == skip {
                continue;
            }
            if path.is_dir() {
                walk(&path, skip, out);
            } else {
                out.insert(
                    path.to_string_lossy().to_string(),
                    sha_hex(&std::fs::read(&path).unwrap()),
                );
            }
        }
    }
    walk(p.dir.path(), skip, &mut out);
    out
}

fn code(e: WizardError) -> String {
    code_of(&e)
}

// ------------------------------------------------------------ words

#[test]
fn the_word_list_is_the_canonical_bip39_english_list() {
    assert_eq!(
        sha_hex(WORDS_TXT.as_bytes()),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
    assert_eq!(wordlist().len(), 2048);
    let mut sorted = wordlist().to_vec();
    sorted.sort();
    assert_eq!(sorted, wordlist(), "binary search needs the list sorted");
}

#[test]
fn bip39_vectors() {
    let v = |b: u8| words_from_entropy(&[b; 16]).join(" ");
    assert_eq!(v(0x00), format!("{}about", "abandon ".repeat(11)));
    assert_eq!(
        v(0x7f),
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    );
    assert_eq!(
        v(0x80),
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
    );
    assert_eq!(v(0xff), format!("{}wrong", "zoo ".repeat(11)));
    for b in [0x00u8, 0x7f, 0x80, 0xff] {
        assert_eq!(*parse_words(&v(b)).unwrap(), [b; 16]);
    }
    let mut r = [0u8; 16];
    OsRng.fill_bytes(&mut r);
    assert_eq!(*parse_words(&words_from_entropy(&r).join(" ")).unwrap(), r);
}

#[test]
fn typed_words_are_normalised() {
    // "abandon" typed on a Persian keyboard.
    let fa: String = "شذشدیخد".into();
    let phrase = format!("{} about", vec![fa.as_str(); 11].join(" "));
    assert_eq!(*parse_words(&phrase).unwrap(), [0u8; 16]);
    // Mixed case, commas, numbering, ZWNJ, Persian digits, newlines,
    // fullwidth letters and four-letter prefixes.
    let messy = "1. Legal, 2. WINNER،\n۳. thank\u{200C} 4-year 5.wave 6 sausage 7 worth \
                 8 usef 9 ＬＥＧＡＬ 10 winn 11 thank 12 yell";
    assert_eq!(*parse_words(messy).unwrap(), [0x7f; 16]);
    assert_eq!(parse_words("abandon abandon"), Err(WordsError::Count(2)));
    // A three-letter fragment is not a prefix match.
    let bad = format!("{}aba about", "abandon ".repeat(10));
    assert_eq!(parse_words(&bad), Err(WordsError::NotAWord(11)));
    // Swapped word: all valid list words, wrong checksum.
    let swapped = format!("{}abandon", "abandon ".repeat(11));
    assert_eq!(parse_words(&swapped), Err(WordsError::Checksum));
}

#[test]
fn production_kdf_constants_are_pinned() {
    assert_eq!((KDF_M_KIB, KDF_T_COST, KDF_P_LANES), (65536, 3, 1));
    assert_eq!(
        KdfParams::PRODUCTION,
        KdfParams {
            m_kib: 65536,
            t_cost: 3,
            p_lanes: 1
        }
    );
    assert!(KdfParams::PRODUCTION.in_bounds());
    assert_eq!(HEADER_LEN, 76);
}

#[test]
fn every_table_and_path_column_is_classified() {
    let p = phone();
    p.ctx.db.with_conn(|c| {
        for t in all_tables(c).unwrap() {
            let inc = INCLUDED_TABLES.contains(&t.as_str());
            let exc = EXCLUDED_TABLES.contains(&t.as_str());
            assert!(
                inc ^ exc,
                "table {t} must be in exactly one of INCLUDED / EXCLUDED"
            );
            for col in table_columns(c, &t).unwrap() {
                if col.ends_with("_path") {
                    let file = is_listed(PATH_COLUMNS, &t, &col);
                    let url = is_listed(NOT_FILE_PATH_COLUMNS, &t, &col);
                    assert!(
                        file ^ url,
                        "{t}.{col} must be classified as a file path or not"
                    );
                    assert!(!file || inc);
                }
            }
        }
        for t in INCLUDED_TABLES.iter().chain(EXCLUDED_TABLES) {
            assert!(
                all_tables(c).unwrap().contains(&t.to_string()),
                "{t} listed but absent"
            );
        }
    });
}

#[test]
fn words_confirm_and_check() {
    let p = phone();
    assert_eq!(
        code(words_check(&p.ctx, "x").unwrap_err()),
        E_BACKUP_NO_WORDS
    );
    assert_eq!(
        code(
            words_confirm(
                &p.ctx,
                &[0, 1, 2].map(|i| WordAnswer {
                    index: i,
                    word: "abandon".into()
                })
            )
            .unwrap_err()
        ),
        E_BACKUP_NO_WORDS
    );
    let w = words_new(&p.ctx).unwrap().words;
    assert_eq!(w.len(), 12);
    // Two positions are not enough.
    assert!(words_confirm(
        &p.ctx,
        &[0, 1].map(|i| WordAnswer {
            index: i,
            word: w[i as usize].clone()
        })
    )
    .is_err());
    let wrong = if w[4] == "zoo" { "abandon" } else { "zoo" };
    let e = words_confirm(
        &p.ctx,
        &[
            WordAnswer {
                index: 0,
                word: w[0].clone(),
            },
            WordAnswer {
                index: 4,
                word: wrong.into(),
            },
            WordAnswer {
                index: 9,
                word: w[9].clone(),
            },
        ],
    )
    .unwrap_err()
    .to_string();
    assert!(e.starts_with(E_BACKUP_WORDS_MISMATCH), "{e}");
    assert!(e.contains("word number 5") && !e.contains(wrong), "{e}");
    assert!(
        !read_entropy(&p.ctx, WORDS_ALIAS).unwrap().is_some(),
        "nothing confirmed yet"
    );
    // A typed answer is normalised the same way.
    words_confirm(
        &p.ctx,
        &[0, 4, 9].map(|i| WordAnswer {
            index: i,
            word: format!(" {}. ", w[i as usize].to_uppercase()),
        }),
    )
    .unwrap();
    assert!(words_check(&p.ctx, &w.join(" ")).unwrap());
    assert!(!words_check(&p.ctx, &words_from_entropy(&[0; 16]).join(" ")).unwrap());
    assert!(!words_check(&p.ctx, "not words").unwrap());
    assert!(read_entropy(&p.ctx, WORDS_PENDING_ALIAS).unwrap().is_none());
}

// ------------------------------------------------------------ round trip

#[test]
fn round_trip_into_an_empty_phone_and_the_keys_still_sign() {
    let a = phone();
    let pop = populate(&a);
    let words = set_words(&a);
    let file = make(&a);
    let a_snap = collect_state(&a.ctx, SecretMode::Strict).unwrap();

    let b = phone();
    let b_ident = crate::recipient_identity::get_or_create(&b.ctx).unwrap();
    let b_ident_priv = b
        .ctx
        .custody
        .get(crate::recipient_identity::RECIPIENT_PRIV_ALIAS)
        .unwrap();
    let path = carry(&file, &b);
    let insp = backup_inspect(&b.ctx, &path).unwrap();
    assert!(insp.existing.is_none());
    let prev = backup_open(&b.ctx, &path, &words).unwrap();
    assert_eq!(prev.contents.relays.len(), 2);
    assert_eq!(prev.contents.people_total, 2);
    assert!(prev.contents.includes_hosting_key);
    assert_eq!(prev.contents.unfinished_setups, 1);
    assert!(prev.replace.is_none());
    let res = backup_restore(&b.ctx, &path, &words, None).unwrap();
    assert_eq!(res.notice.relays.len(), 2);
    assert!(res.notice.has_refresh_keys);

    // Rows equal (apart from reset columns), keys and files equal.
    let b_snap = collect_state(&b.ctx, SecretMode::Strict).unwrap();
    assert_eq!(digest_of(&a_snap), digest_of(&b_snap));
    for t in INCLUDED_TABLES {
        assert_eq!(
            a_snap.table(t).rows.len(),
            b_snap.table(t).rows.len(),
            "{t}"
        );
    }
    let row = b.ctx.db.get(pop.live).unwrap();
    assert_eq!(row.helper_ip, "", "the new phone detects its own address");
    assert_eq!(row.nickname, NICK);
    for (alias, v) in &a_snap.secrets {
        assert_eq!(&b.ctx.custody.get(alias).unwrap(), &v[..], "{alias}");
    }
    assert!(a_snap
        .secrets
        .iter()
        .any(|(a, _)| a.starts_with("daal.freshness.")));
    for f in &a_snap.files {
        let dir = if f.area == Area::Journal {
            &b.ctx.journal_dir
        } else {
            &b.ctx.staging_dir
        };
        assert_eq!(
            std::fs::read(dir.join(&f.rel)).unwrap(),
            &f.bytes[..],
            "{}",
            f.rel
        );
    }
    assert!(crate::provision_journal::journal_path(&b.ctx.journal_dir, pop.unfinished).exists());
    // The sub-key paths point into B's staging, the outside file too.
    let sk = b.ctx.db.with_conn(|c| {
        c.query_row(
            "SELECT subkey_priv_path, subkey_cert_path FROM subkeys",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .unwrap()
    });
    assert!(Path::new(&sk.0).starts_with(&b.ctx.staging_dir) && Path::new(&sk.0).exists());
    assert!(Path::new(&sk.1).starts_with(b.ctx.staging_dir.join("outside")));
    assert_eq!(std::fs::read(&sk.1).unwrap(), b"sub-cert");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&sk.0).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600);
    }

    // Re-wrapped: A's raw blob does not open on B.
    let raw_a = std::fs::read(
        a.dir
            .path()
            .join("custody/aliases/daal_publisher_1_priv.blob"),
    )
    .unwrap();
    std::fs::write(
        b.dir.path().join("custody/aliases/copied_from_a.blob"),
        raw_a,
    )
    .unwrap();
    assert!(b.ctx.custody.get("copied.from.a").is_err());

    // B's own recipient identity is untouched.
    assert_eq!(
        crate::recipient_identity::get_or_create(&b.ctx)
            .unwrap()
            .address,
        b_ident.address
    );
    assert_eq!(
        b.ctx
            .custody
            .get(crate::recipient_identity::RECIPIENT_PRIV_ALIAS)
            .unwrap(),
        b_ident_priv
    );

    // The restored key signs, and A's public key verifies it.
    let k = crate::publisher_key::import(
        &b.ctx
            .custody
            .get(&format!("daal.publisher.{}.priv", pop.live))
            .unwrap(),
    )
    .unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&k.priv_bytes[..32].try_into().unwrap());
    use ed25519_dalek::{Signer, Verifier};
    let sig = sk.sign(b"a file for the family");
    let a_pub = hex::decode(&a.ctx.db.get(pop.live).unwrap().publisher_pub_hex).unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&a_pub.try_into().unwrap())
        .unwrap()
        .verify(b"a file for the family", &sig)
        .unwrap();

    // The words that opened it are B's words; not stale; notice shown.
    assert!(words_check(&b.ctx, &words).unwrap());
    let st = backup_status(&b.ctx).unwrap();
    assert!(
        !st.stale && st.last_backup_at_unix > 0 && !st.restore_pending,
        "{st:?}"
    );
    assert!(st.restore_notice.is_some());
    dismiss_notice(&b.ctx).unwrap();
    assert!(backup_status(&b.ctx).unwrap().restore_notice.is_none());

    // And on B the relay is usable: health, add, remove, renew.
    *b.mock.box_users.lock().unwrap() = a.mock.box_users.lock().unwrap().clone();
    set_helper_ip(&b.ctx, pop.live, "198.51.100.9", "auto").unwrap();
    let h = crate::relay_health::relay_health(&b.ctx, pop.live, true).unwrap();
    // The mock box's own "everyone" user is mock state, not restored
    // state; what matters is that management answered with B's keys.
    assert_eq!(
        (h.management.as_str(), h.people_missing),
        ("answers", Some(0)),
        "{h:?}"
    );
    let new = recipient_provision(&b.ctx, pop.live, &address(9), "Dina").unwrap();
    assert_eq!(new.name, "r4", "the name counter came along");
    recipient_revoke(&b.ctx, pop.live, pop.maman).unwrap();
    crate::renew::renew_everyone(&b.ctx, pop.live, &mut |_| {}).unwrap();
    assert!(
        backup_status(&b.ctx).unwrap().stale,
        "changes since the restore"
    );
}

// ------------------------------------------------------------ refusals

struct Refusal {
    phone: Phone,
    file: Vec<u8>,
    words: String,
    entropy: [u8; 16],
}

/// A backup from phone A, and a phone B that already has a relay and a
/// recipient identity, to be refused onto.
fn refusal_rig() -> (Phone, Refusal) {
    let a = phone();
    populate(&a);
    let words = set_words(&a);
    let file = std::fs::read(make(&a)).unwrap();
    let e = entropy(&a);
    let b = phone();
    crate::recipient_identity::get_or_create(&b.ctx).unwrap();
    let id = store_cloud_token(&b.ctx, "hetzner", "hcloud_B_token", None).unwrap();
    publisher_keygen(&b.ctx, id).unwrap();
    (
        a,
        Refusal {
            phone: b,
            file,
            words,
            entropy: e,
        },
    )
}

fn reseal(r: &Refusal, f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let h = parse_header(&r.file).unwrap();
    let pt = decrypt_with(&r.file, &h, &r.entropy).unwrap();
    let mut v: Value = serde_json::from_slice(&pt).unwrap();
    f(&mut v);
    seal(&r.entropy, &serde_json::to_vec(&v).unwrap(), make_params()).unwrap()
}

fn refuse(r: &Refusal, bytes: &[u8], words: &str) -> String {
    let path = r.phone.dir.path().join("candidate.daalbackup");
    std::fs::write(&path, bytes).unwrap();
    let before = fingerprint(&r.phone, &path);
    let open = backup_open(&r.phone.ctx, &path, words)
        .map(|_| ())
        .unwrap_err()
        .to_string();
    let rest = backup_restore(&r.phone.ctx, &path, words, Some("whatever"))
        .map(|_| ())
        .unwrap_err()
        .to_string();
    let replace_ok = backup_restore(
        &r.phone.ctx,
        &path,
        words,
        Some(&state_digest(&r.phone.ctx).unwrap()),
    )
    .map(|_| ())
    .unwrap_err()
    .to_string();
    assert_eq!(
        code_of(&WizardError::Coded(open.clone())),
        code_of(&WizardError::Coded(rest.clone()))
    );
    assert_eq!(
        code_of(&WizardError::Coded(open.clone())),
        code_of(&WizardError::Coded(replace_ok))
    );
    assert_eq!(
        before,
        fingerprint(&r.phone, &path),
        "a refusal changed something: {open}"
    );
    std::fs::remove_file(&path).unwrap();
    code_of(&WizardError::Coded(open))
}

#[test]
fn every_refusal_is_distinct_and_changes_nothing() {
    let (_a, r) = refusal_rig();
    let good = r.words.clone();
    let other = words_from_entropy(&[7u8; 16]).join(" ");
    assert_eq!(refuse(&r, &r.file, &other), E_BACKUP_WRONG_WORDS);

    let mut w: Vec<&str> = good.split(' ').collect();
    let swapped_in = if w[3] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    w[3] = swapped_in;
    let swapped = w.join(" ");
    if parse_words(&swapped).is_err() {
        let path = r.phone.dir.path().join("x.daalbackup");
        std::fs::write(&path, &r.file).unwrap();
        let e = backup_open(&r.phone.ctx, &path, &swapped)
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with(E_BACKUP_WORDS_INVALID) && !e.contains(swapped_in),
            "{e}"
        );
        std::fs::remove_file(path).unwrap();
        assert_eq!(refuse(&r, &r.file, &swapped), E_BACKUP_WORDS_INVALID);
    }
    let eleven = good.split(' ').take(11).collect::<Vec<_>>().join(" ");
    assert_eq!(refuse(&r, &r.file, &eleven), E_BACKUP_WORDS_INVALID);
    let typo = good.replacen(good.split(' ').next().unwrap(), "qqqqqq", 1);
    let path = r.phone.dir.path().join("x.daalbackup");
    std::fs::write(&path, &r.file).unwrap();
    let e = backup_open(&r.phone.ctx, &path, &typo)
        .unwrap_err()
        .to_string();
    assert!(
        e.starts_with(E_BACKUP_WORDS_INVALID) && e.contains("word 1") && !e.contains("qqqqqq"),
        "{e}"
    );
    std::fs::remove_file(path).unwrap();

    // One flipped byte in each region.
    let flip = |at: usize| {
        let mut f = r.file.clone();
        f[at] ^= 0x01;
        f
    };
    assert_eq!(refuse(&r, &flip(30), &good), E_BACKUP_WRONG_WORDS, "salt");
    assert_eq!(refuse(&r, &flip(45), &good), E_BACKUP_DAMAGED, "nonce");
    assert_eq!(refuse(&r, &flip(60), &good), E_BACKUP_WRONG_WORDS, "check");
    assert_eq!(
        refuse(&r, &flip(15), &good),
        E_BACKUP_WRONG_WORDS,
        "kdf memory, in bounds"
    );
    assert_eq!(
        refuse(&r, &flip(HEADER_LEN + 3), &good),
        E_BACKUP_DAMAGED,
        "ciphertext"
    );
    assert_eq!(
        refuse(&r, &flip(r.file.len() - 1), &good),
        E_BACKUP_DAMAGED,
        "tag"
    );
    assert_eq!(refuse(&r, &flip(70), &good), E_BACKUP_DAMAGED, "length");
    assert_eq!(refuse(&r, &flip(2), &good), E_BACKUP_NOT_A_BACKUP, "magic");

    assert_eq!(refuse(&r, &r.file[..5], &good), E_BACKUP_NOT_A_BACKUP);
    assert_eq!(refuse(&r, &r.file[..40], &good), E_BACKUP_DAMAGED);
    assert_eq!(
        refuse(&r, &r.file[..r.file.len() - 1], &good),
        E_BACKUP_DAMAGED
    );
    let mut longer = r.file.clone();
    longer.push(0);
    assert_eq!(refuse(&r, &longer, &good), E_BACKUP_DAMAGED);

    let mut v2 = r.file.clone();
    v2[9] = 2;
    assert_eq!(refuse(&r, &v2, &good), E_BACKUP_NEWER);
    let mut aead = r.file.clone();
    aead[11] = 9;
    assert_eq!(refuse(&r, &aead, &good), E_BACKUP_NEWER);
    let mut kdf_oob = r.file.clone();
    kdf_oob[16..20].copy_from_slice(&11u32.to_be_bytes());
    assert_eq!(refuse(&r, &kdf_oob, &good), E_BACKUP_DAMAGED);
    let mut mem_oob = r.file.clone();
    mem_oob[12..16].copy_from_slice(&1024u32.to_be_bytes());
    assert_eq!(refuse(&r, &mem_oob, &good), E_BACKUP_DAMAGED);

    // Not a backup at all.
    let sbp = std::fs::read(_a.ctx.staging_dir.join("1.sbp")).unwrap();
    assert_eq!(refuse(&r, &sbp, &good), E_BACKUP_NOT_A_BACKUP);
    let mut rnd = vec![0u8; 4096];
    OsRng.fill_bytes(&mut rnd);
    assert_eq!(refuse(&r, &rnd, &good), E_BACKUP_NOT_A_BACKUP);

    // Crafted payloads, sealed under the right words.
    let cur = crate::operator_db::current_schema_version();
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| v["db_schema_version"] = json!(cur + 1)),
            &good
        ),
        E_BACKUP_NEWER
    );
    assert_eq!(
        refuse(&r, &reseal(&r, |v| v["payload_version"] = json!(2)), &good),
        E_BACKUP_NEWER
    );
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| {
                let t = &mut v["tables"]["operators"];
                t["columns"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("from_the_future"));
                for row in t["rows"].as_array_mut().unwrap() {
                    row.as_array_mut().unwrap().push(json!(1));
                }
            }),
            &good
        ),
        E_BACKUP_NEWER
    );
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| v["kind"] = json!("something.else")),
            &good
        ),
        E_BACKUP_DAMAGED
    );
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| {
                v["secrets"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"alias":"recipient_priv_x25519","b64":"AAAA"}))
            }),
            &good
        ),
        E_BACKUP_DAMAGED,
        "an alias outside the whitelist"
    );
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| {
                let t = &mut v["tables"]["operators"];
                let i = t["columns"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|c| c == "cloud_token_keystore_alias")
                    .unwrap();
                t["rows"][0][i] = json!("recipient_priv_x25519");
                // ...and the key under that name, so only the whitelist
                // stands between this file and B's own identity key.
                for sec in v["secrets"].as_array_mut().unwrap() {
                    if sec["alias"] == "daal.cloud.1.token" {
                        sec["alias"] = json!("recipient_priv_x25519");
                    }
                }
            }),
            &good
        ),
        E_BACKUP_DAMAGED,
        "a row naming the recipient key, with the key"
    );
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| {
                let t = &mut v["tables"]["operators"];
                let i = t["columns"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|c| c == "cloud_token_keystore_alias")
                    .unwrap();
                t["rows"][0][i] = json!("daal_backup_words");
                for sec in v["secrets"].as_array_mut().unwrap() {
                    if sec["alias"] == "daal.cloud.1.token" {
                        sec["alias"] = json!("daal_backup_words");
                    }
                }
            }),
            &good
        ),
        E_BACKUP_DAMAGED,
        "an alias that lands on the same custody file as the words"
    );
    let other_key = B64.encode(&crate::publisher_key::generate().priv_bytes[..]);
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| {
                for s in v["secrets"].as_array_mut().unwrap() {
                    if s["alias"] == "daal.publisher.1.priv" {
                        s["b64"] = json!(other_key);
                    }
                }
            }),
            &good
        ),
        E_BACKUP_DAMAGED,
        "a key that does not match publisher_pub_hex"
    );
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| v["files"][0]["rel"] = json!("../../escape")),
            &good
        ),
        E_BACKUP_DAMAGED
    );
    assert_eq!(
        refuse(
            &r,
            &reseal(&r, |v| {
                v["tables"]["recipients"]["rows"][0][1] = json!(999);
            }),
            &good
        ),
        E_BACKUP_DAMAGED,
        "a row the database refuses (foreign key)"
    );
}

#[test]
fn inspect_reads_only_the_header() {
    let (_a, r) = refusal_rig();
    let path = r.phone.dir.path().join("i.daalbackup");
    std::fs::write(&path, &r.file).unwrap();
    let i = backup_inspect(&r.phone.ctx, &path).unwrap();
    let ex = i.existing.unwrap();
    assert_eq!(ex.relays.len(), 1);
    assert_eq!(ex.digest, state_digest(&r.phone.ctx).unwrap());
    std::fs::write(&path, b"DAALBK").unwrap();
    assert_eq!(
        code(backup_inspect(&r.phone.ctx, &path).unwrap_err()),
        E_BACKUP_NOT_A_BACKUP
    );
    let mut v = r.file.clone();
    v[9] = 3;
    std::fs::write(&path, &v).unwrap();
    assert_eq!(
        code(backup_inspect(&r.phone.ctx, &path).unwrap_err()),
        E_BACKUP_NEWER
    );
    std::fs::write(&path, &r.file[..60]).unwrap();
    assert_eq!(
        code(backup_inspect(&r.phone.ctx, &path).unwrap_err()),
        E_BACKUP_DAMAGED
    );
}

// ------------------------------------------------------------ opsec

#[test]
fn nothing_in_the_file_or_the_errors_reads_in_clear() {
    let a = phone();
    let pop = populate(&a);
    let words = set_words(&a);
    let tmp_before: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    let m = backup_make_file(&a.ctx, Some("my backup")).unwrap();
    assert_eq!(m.file_name, "my_backup.daalbackup");
    let file = std::fs::read(&m.path).unwrap();
    let pub_hex = a.ctx.db.get(pop.live).unwrap().publisher_pub_hex;
    let key = a
        .ctx
        .custody
        .get(&format!("daal.publisher.{}.priv", pop.live))
        .unwrap();
    let needles: Vec<Vec<u8>> = vec![
        NICK.into(),
        IP.into(),
        "hetzner".into(),
        PERSON.into(),
        TOKEN.into(),
        GH_PAT.into(),
        pub_hex.clone().into_bytes(),
        key[..32].to_vec(),
        b"signed-bundle".to_vec(),
        b"fsn1".to_vec(),
    ];
    let contains = |hay: &[u8], n: &[u8]| hay.windows(n.len()).any(|w| w == n);
    for n in &needles {
        assert!(
            !contains(&file[..HEADER_LEN], n),
            "header holds {:?}",
            String::from_utf8_lossy(n)
        );
        assert!(
            !contains(&file, n),
            "file holds {:?}",
            String::from_utf8_lossy(n)
        );
    }
    // backup-out holds only this ciphertext; no new temp file; no file
    // outside custody/aliases holds the token or the key.
    let out: Vec<_> = std::fs::read_dir(backup_out_dir(&a.ctx))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(out.len(), 1);
    let tmp_after: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    for p in &tmp_after {
        if !tmp_before.contains(p) && p.is_file() {
            // The temp dir is shared with tests running in parallel,
            // and some of them hand the same test token to a fake
            // helper through a short-lived file. A leak from the backup
            // would stay; theirs is gone within moments.
            let leaks = |p: &Path| {
                let b = std::fs::read(p).unwrap_or_default();
                contains(&b, TOKEN.as_bytes()) || contains(&b, &key[..32])
            };
            let mut leaked = leaks(p);
            for _ in 0..20 {
                if !leaked {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                leaked = p.is_file() && leaks(p);
            }
            assert!(!leaked, "{p:?}");
        }
    }
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            if e.path().is_dir() {
                walk(&e.path(), out)
            } else {
                out.push(e.path())
            }
        }
    }
    let mut all = Vec::new();
    walk(a.dir.path(), &mut all);
    for p in all
        .iter()
        .filter(|p| !p.starts_with(a.dir.path().join("custody")))
    {
        let b = std::fs::read(p).unwrap();
        assert!(!contains(&b, TOKEN.as_bytes()), "{p:?} holds the token");
        assert!(!contains(&b, &key[..32]), "{p:?} holds the signing key");
        assert!(!contains(&b, words.as_bytes()), "{p:?} holds the words");
    }

    // Error text (which is logged) never carries the words, a token or
    // a name, on any refusal path.
    let b = phone();
    let path = carry(&m.path, &b);
    let mut errs = vec![
        backup_open(&b.ctx, &path, "hello world")
            .unwrap_err()
            .to_string(),
        backup_open(&b.ctx, &path, &words.replace(' ', "x"))
            .unwrap_err()
            .to_string(),
        backup_open(&b.ctx, &path, &words_from_entropy(&[3; 16]).join(" "))
            .unwrap_err()
            .to_string(),
    ];
    std::fs::write(&path, &file[..100]).unwrap();
    errs.push(backup_open(&b.ctx, &path, &words).unwrap_err().to_string());
    for e in &errs {
        for n in [TOKEN, NICK, PERSON, IP, "hello", &pub_hex] {
            assert!(!e.contains(n), "{e}");
        }
        for w in words.split(' ') {
            assert!(
                !e.split(|c: char| !c.is_ascii_alphabetic()).any(|t| t == w),
                "{e} names a word"
            );
        }
    }
}

// ------------------------------------------------------------ atomicity

fn restore_rig() -> (Phone, Phone, PathBuf, String) {
    let a = phone();
    populate(&a);
    let words = set_words(&a);
    let file = make(&a);
    let b = phone();
    crate::recipient_identity::get_or_create(&b.ctx).unwrap();
    let path = carry(&file, &b);
    (a, b, path, words)
}

fn pending_blobs(p: &Phone) -> usize {
    std::fs::read_dir(p.dir.path().join("custody/aliases"))
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("daal_restore_pending_")
        })
        .count()
}

#[test]
fn a_kill_before_the_commit_leaves_the_old_state() {
    let (_a, b, path, words) = restore_rig();
    let before = fingerprint(&b, &path);
    set_fault(Some(RestoreFault::BeforeCommit));
    assert!(backup_restore(&b.ctx, &path, &words, None).is_err());
    assert_eq!(pending_blobs(&b), 1, "the kill left the pending blob");
    assert!(list_operators(&b.ctx).unwrap().is_empty(), "old state");
    assert_eq!(pending_blobs(&b), 0, "the orphan is swept");
    let mut after = fingerprint(&b, &path);
    let mut before = before;
    // The probe left nothing; only the swept blob dir is compared.
    after.retain(|k, _| !k.contains("daal_custody_probe"));
    before.retain(|k, _| !k.contains("daal_custody_probe"));
    assert_eq!(before, after);
}

#[test]
fn a_kill_after_the_commit_is_finished_by_the_next_call() {
    let (a, b, path, words) = restore_rig();
    set_fault(Some(RestoreFault::AfterCommit));
    assert!(backup_restore(&b.ctx, &path, &words, None).is_err());
    assert!(backup_status(&b.ctx).is_ok());
    assert!(
        read_meta(&b.ctx).unwrap().restore_pending_nonce.is_empty(),
        "status finished it"
    );
    assert_eq!(
        digest_of(&collect_state(&a.ctx, SecretMode::Strict).unwrap()),
        state_digest(&b.ctx).unwrap()
    );

    // The same through list_operators, and through a kill mid-puts.
    for k in [0usize, 2] {
        let (a, b, path, words) = restore_rig();
        set_fault(Some(RestoreFault::AfterNPuts(k)));
        assert!(backup_restore(&b.ctx, &path, &words, None).is_err());
        assert!(!read_meta(&b.ctx).unwrap().restore_pending_nonce.is_empty());
        assert_eq!(list_operators(&b.ctx).unwrap().len(), 2);
        assert!(read_meta(&b.ctx).unwrap().restore_pending_nonce.is_empty());
        assert_eq!(pending_blobs(&b), 0);
        assert_eq!(
            digest_of(&collect_state(&a.ctx, SecretMode::Strict).unwrap()),
            state_digest(&b.ctx).unwrap()
        );
    }
}

#[test]
fn a_key_read_while_a_restore_is_pending_finishes_it_or_refuses() {
    let (_a, b, path, words) = restore_rig();
    set_fault(Some(RestoreFault::AfterNPuts(1)));
    assert!(backup_restore(&b.ctx, &path, &words, None).is_err());
    let k = crate::commands::custody_get(&b.ctx, "daal.publisher.1.priv").unwrap();
    assert_eq!(k.len(), 64);

    let (_a, b, path, words) = restore_rig();
    set_fault(Some(RestoreFault::AfterCommit));
    assert!(backup_restore(&b.ctx, &path, &words, None).is_err());
    // The pending blob is lost: nothing may run on half-written state.
    b.ctx.custody.forget_prefix(RESTORE_PENDING_PREFIX).unwrap();
    let e = crate::commands::custody_get(&b.ctx, "daal.publisher.1.priv").unwrap_err();
    assert_eq!(code(e), E_RESTORE_UNFINISHED);
    assert!(list_operators(&b.ctx).is_ok(), "the list still renders");
    assert!(backup_status(&b.ctx).unwrap().restore_pending);
}

// ------------------------------------------------------------ replace

#[test]
fn restore_over_existing_data_needs_the_named_confirmation() {
    let a = phone();
    populate(&a);
    let words = set_words(&a);
    let file = make(&a);

    let b = phone();
    crate::recipient_identity::get_or_create(&b.ctx).unwrap();
    let ident = b
        .ctx
        .custody
        .get(crate::recipient_identity::RECIPIENT_PRIV_ALIAS)
        .unwrap();
    // B has three relays of its own; id 3 exists only here.
    for t in ["hcloud_B1", "hcloud_B2", "hcloud_B3"] {
        let id = store_cloud_token(&b.ctx, "hetzner", t, None).unwrap();
        publisher_keygen(&b.ctx, id).unwrap();
        std::fs::write(
            b.ctx.staging_dir.join(format!("{id}.pre-provision.json")),
            b"{}",
        )
        .unwrap();
        std::fs::write(b.ctx.staging_dir.join(format!("{id}.r1.sbpx")), b"old").unwrap();
    }
    let j = crate::provision_journal::prepare(&b.ctx.journal_dir, 3).unwrap();
    std::fs::write(&j, JOURNAL).unwrap();
    let path = carry(&file, &b);
    let before = fingerprint(&b, &path);

    assert_eq!(
        code(backup_restore(&b.ctx, &path, &words, None).unwrap_err()),
        E_RESTORE_WOULD_REPLACE
    );
    assert_eq!(
        code(backup_restore(&b.ctx, &path, &words, Some("stale")).unwrap_err()),
        E_RESTORE_STATE_CHANGED
    );
    assert_eq!(before, fingerprint(&b, &path));

    let prev = backup_open(&b.ctx, &path, &words).unwrap();
    let rep = prev.replace.unwrap();
    assert_eq!(rep.this_phone.len(), 3);
    assert_eq!(
        rep.only_on_this_phone.len(),
        3,
        "different keys: none of B's relays is in the backup"
    );
    // Something changes after the preview: the digest no longer holds.
    set_operator_nickname(&b.ctx, 1, "changed").unwrap();
    assert_eq!(
        code(backup_restore(&b.ctx, &path, &words, Some(&rep.digest)).unwrap_err()),
        E_RESTORE_STATE_CHANGED
    );
    let digest = backup_open(&b.ctx, &path, &words)
        .unwrap()
        .replace
        .unwrap()
        .digest;
    backup_restore(&b.ctx, &path, &words, Some(&digest)).unwrap();

    assert_eq!(list_operators(&b.ctx).unwrap().len(), 2);
    assert!(matches!(
        b.ctx.custody.get("daal.publisher.3.priv"),
        Err(CustodyError::NotFound(_))
    ));
    assert!(matches!(
        b.ctx.custody.get("daal.cloud.3.token"),
        Err(CustodyError::NotFound(_))
    ));
    assert_eq!(
        &*crate::commands::custody_get_string(&b.ctx, "daal.cloud.1.token").unwrap(),
        TOKEN
    );
    assert!(!b.ctx.staging_dir.join("3.pre-provision.json").exists());
    assert!(!b.ctx.staging_dir.join("3.r1.sbpx").exists());
    assert!(
        !b.ctx.staging_dir.join("2.r1.sbpx").exists(),
        "a file of the replaced relay 2"
    );
    assert!(!j.exists(), "the replaced relay's journal");
    assert_eq!(
        b.ctx
            .custody
            .get(crate::recipient_identity::RECIPIENT_PRIV_ALIAS)
            .unwrap(),
        ident
    );
    assert!(b.ctx.db.get_recipient_identity().unwrap().is_some());
}

// ------------------------------------------------------------ staleness

#[test]
fn staleness_follows_people_files_and_keys_not_health() {
    let a = phone();
    let pop = populate(&a);
    set_words(&a);
    assert!(
        !backup_status(&a.ctx).unwrap().stale,
        "never backed up is not stale"
    );
    make(&a);
    assert!(!backup_status(&a.ctx).unwrap().stale);

    crate::relay_health::relay_health(&a.ctx, pop.live, true).unwrap();
    a.ctx
        .db
        .with_conn(|c| {
            c.execute(
                "UPDATE relay_identity SET learned_at_unix = learned_at_unix + 5",
                [],
            )
        })
        .unwrap();
    set_helper_ip(&a.ctx, pop.live, "198.51.100.77", "auto").unwrap();
    assert!(
        !backup_status(&a.ctx).unwrap().stale,
        "health and address are not changes"
    );

    recipient_provision(&a.ctx, pop.live, &address(7), "New").unwrap();
    assert!(backup_status(&a.ctx).unwrap().stale, "added a person");
    make(&a);
    recipient_revoke(&a.ctx, pop.live, pop.maman).unwrap();
    assert!(backup_status(&a.ctx).unwrap().stale, "removed a person");
    make(&a);
    a.ctx
        .db
        .record_mgmt_plane(
            pop.live,
            42424,
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )
        .unwrap();
    make(&a);
    a.mock.box_users.lock().unwrap().clear();
    crate::renew::renew_everyone(&a.ctx, pop.live, &mut |_| {}).unwrap();
    assert!(backup_status(&a.ctx).unwrap().stale, "renewed everyone");
    make(&a);
    store_cloud_token(&a.ctx, "hetzner", "hcloud_REPLACED", Some(pop.live)).unwrap();
    assert!(
        backup_status(&a.ctx).unwrap().stale,
        "replaced the hosting key"
    );
}

// ------------------------------------------------------------ blocked

#[test]
fn blocked_states_and_their_codes() {
    let p = phone();
    set_words(&p);
    assert_eq!(
        code(backup_make_file(&p.ctx, None).unwrap_err()),
        E_BACKUP_NOTHING
    );
    let st = backup_status(&p.ctx).unwrap();
    assert!(
        !st.has_publisher_data && st.words_set && st.blocked.is_empty(),
        "{st:?}"
    );

    let q = phone();
    let pop = populate(&q);
    assert_eq!(
        code(backup_make_file(&q.ctx, None).unwrap_err()),
        E_BACKUP_NO_WORDS
    );
    assert!(!backup_status(&q.ctx).unwrap().words_set);
    set_words(&q);

    #[cfg(unix)]
    {
        let j = crate::provision_journal::journal_path(&q.ctx.journal_dir, pop.unfinished);
        let holder = std::fs::OpenOptions::new().append(true).open(&j).unwrap();
        #[allow(clippy::incompatible_msrv)]
        holder.lock().unwrap();
        assert_eq!(
            code(backup_make_file(&q.ctx, None).unwrap_err()),
            E_SETUP_RUNNING
        );
        assert_eq!(backup_status(&q.ctx).unwrap().blocked, "setup_running");
        drop(holder);
    }

    q.ctx
        .custody
        .forget(&format!("daal.publisher.{}.priv", pop.live))
        .unwrap();
    let e = backup_make_file(&q.ctx, None).unwrap_err().to_string();
    assert!(
        e.starts_with(E_BACKUP_SECRET_UNREADABLE) && e.contains(&format!("relay {}", pop.live)),
        "{e}"
    );
    let st = backup_status(&q.ctx).unwrap();
    assert_eq!(st.blocked, "secret_unreadable");
    assert_eq!(
        st.contents.relays.len(),
        2,
        "the screen can still name the relays"
    );
    assert!(backup_out_dir(&q.ctx)
        .read_dir()
        .map(|mut d| d.next().is_none())
        .unwrap_or(true));
}

#[test]
fn default_name_and_sweep() {
    assert_eq!(
        default_file_name(1_800_000_000),
        "daal-backup-2027-01-15-0800.daalbackup"
    );
    assert_ne!(
        default_file_name(1_800_000_000),
        default_file_name(1_800_000_060),
        "a second backup the same day gets its own name"
    );
    assert_eq!(clean_file_name(Some("../../x"), 0), "_.._x.daalbackup");
    assert_eq!(clean_file_name(Some("a.daalbackup"), 0), "a.daalbackup");
    assert_eq!(
        clean_file_name(None, 0),
        "daal-backup-1970-01-01-0000.daalbackup"
    );
}

// ------------------------------------------------------------ repair wave

#[test]
fn new_words_make_the_last_backup_out_of_date_until_a_new_one() {
    let a = phone();
    populate(&a);
    set_words(&a);
    make(&a);
    let st = backup_status(&a.ctx).unwrap();
    assert!(!st.stale && !st.words_changed && !st.words_pending, "{st:?}");

    // Started new words and walked away: the old words still rule.
    words_new(&a.ctx).unwrap();
    let st = backup_status(&a.ctx).unwrap();
    assert!(st.words_pending, "unconfirmed new words are reported");
    assert!(!st.stale && !st.words_changed);

    // Confirmed them: the file on hand opens only with the old words.
    set_words(&a);
    let st = backup_status(&a.ctx).unwrap();
    assert!(st.words_changed, "{st:?}");
    assert!(st.stale, "a backup under the old words is out of date");
    assert!(!st.words_pending);

    make(&a);
    let st = backup_status(&a.ctx).unwrap();
    assert!(!st.stale && !st.words_changed, "{st:?}");
}

#[test]
fn a_backup_handed_to_another_app_counts_only_once_it_arrived() {
    let a = phone();
    populate(&a);
    set_words(&a);
    let m = backup_make_file(&a.ctx, None).unwrap();
    backup_note_shared(&a.ctx, &m).unwrap();
    let st = backup_status(&a.ctx).unwrap();
    assert_eq!(st.last_backup_at_unix, 0, "a chooser that opened is not a backup");
    assert_eq!(st.share_unconfirmed_at_unix, m.made_at_unix);

    // "No, it did not arrive": forgotten, still never backed up.
    assert!(!backup_confirm_shared(&a.ctx, false).unwrap());
    let st = backup_status(&a.ctx).unwrap();
    assert_eq!((st.last_backup_at_unix, st.share_unconfirmed_at_unix), (0, 0));

    // "Yes, I have it": the last backup, not stale.
    backup_note_shared(&a.ctx, &m).unwrap();
    assert!(backup_confirm_shared(&a.ctx, true).unwrap());
    let st = backup_status(&a.ctx).unwrap();
    assert_eq!(st.last_backup_at_unix, m.made_at_unix);
    assert!(!st.stale && st.share_unconfirmed_at_unix == 0, "{st:?}");
    assert!(!backup_confirm_shared(&a.ctx, true).unwrap(), "nothing waits now");

    // New words while a shared file waits: that file is under the old
    // words, so it no longer waits to be confirmed.
    backup_note_shared(&a.ctx, &m).unwrap();
    set_words(&a);
    assert_eq!(backup_status(&a.ctx).unwrap().share_unconfirmed_at_unix, 0);
}

#[test]
fn a_file_that_cannot_be_read_is_not_called_foreign_or_damaged() {
    let p = phone();
    let gone = p.dir.path().join("swept.daalbackup");
    let e = backup_inspect(&p.ctx, &gone).unwrap_err();
    assert_eq!(code(e), E_BACKUP_READ_FAILED);
    let e = backup_inspect(&p.ctx, p.dir.path()).unwrap_err();
    assert_eq!(code(e), E_BACKUP_READ_FAILED, "a directory");
}

#[test]
fn a_database_failure_at_the_commit_is_not_called_damaged() {
    let (a, b, file, words) = restore_rig();
    let _ = &a;
    let before = fingerprint(&b, &file);
    set_fault(Some(RestoreFault::CommitError));
    let e = backup_restore(&b.ctx, &file, &words, None).unwrap_err();
    set_fault(None);
    assert_eq!(code(e), E_RESTORE_FAILED);
    finish_pending_restore(&b.ctx).unwrap();
    assert_eq!(before, fingerprint(&b, &file), "nothing changed");
}

fn stored_token(p: &Phone, id: i64) -> String {
    crate::commands::custody_get_string(&p.ctx, &format!("daal.cloud.{id}.token"))
        .unwrap()
        .to_string()
}

#[test]
fn a_new_hosting_key_replaces_the_old_only_once_it_opens_the_right_account() {
    use crate::cli_bridge::ExistingServer;
    let a = phone();
    let pop = populate(&a);
    let server = |id: &str| ExistingServer {
        id: id.into(),
        name: "x".into(),
        status: "running".into(),
        server_type: "cx22".into(),
        region: "fsn1".into(),
        public_ip: IP.into(),
        public_ipv6: String::new(),
    };
    const NEW: &str = "hcloud_NEWKEY_0003";

    *a.mock.list_servers_result.lock().unwrap() = Some(Err(format!("401 unauthorized {NEW}")));
    let e = replace_hosting_key(&a.ctx, "hetzner", NEW, &[pop.live]).unwrap_err().to_string();
    assert!(e.starts_with(E_HOSTING_KEY_REJECTED), "{e}");
    assert!(!e.contains(NEW), "the key never appears in the error: {e}");
    assert_eq!(stored_token(&a, pop.live), TOKEN, "a refused key changes nothing");

    *a.mock.list_servers_result.lock().unwrap() = Some(Ok(vec![server("999")]));
    let e = replace_hosting_key(&a.ctx, "hetzner", NEW, &[pop.live]).unwrap_err().to_string();
    assert!(e.starts_with(E_HOSTING_KEY_WRONG_ACCOUNT), "{e}");
    assert_eq!(stored_token(&a, pop.live), TOKEN, "a key for another account changes nothing");

    *a.mock.list_servers_result.lock().unwrap() = Some(Ok(vec![server("123")]));
    assert_eq!(
        replace_hosting_key(&a.ctx, "hetzner", NEW, &[pop.live]).unwrap(),
        vec![pop.live]
    );
    assert_eq!(stored_token(&a, pop.live), NEW);
}

#[test]
fn a_relays_key_cannot_move_to_another_company_and_keep_a_truncated_record() {
    let a = phone();
    let pop = populate(&a);
    let before = a.ctx.db.get(pop.live).unwrap();
    assert_eq!(before.status, "provisioned");
    assert!(store_cloud_token(&a.ctx, "vultr", "vultr_KEY", Some(pop.live)).is_err());
    let after = a.ctx.db.get(pop.live).unwrap();
    assert_eq!(after.operator_record_json, before.operator_record_json);
    assert_eq!(after.cloud_provider, "hetzner");
    assert_eq!(stored_token(&a, pop.live), TOKEN);
    // An unfinished setup may still change company.
    store_cloud_token(&a.ctx, "vultr", "vultr_KEY", Some(pop.unfinished)).unwrap();
    assert_eq!(a.ctx.db.get(pop.unfinished).unwrap().cloud_provider, "vultr");
}

#[test]
fn after_restoring_an_older_backup_people_added_later_are_seen_and_their_names_skipped() {
    let (a, b, file, words) = restore_rig();
    let pop_live = list_operators(&a.ctx)
        .unwrap()
        .into_iter()
        .find(|o| o.status == "provisioned")
        .unwrap()
        .id;
    backup_restore(&b.ctx, &file, &words, None).unwrap();
    // On the old phone, after the backup: r4 was added. The relay has it;
    // the restored book does not.
    {
        let mut u = b.mock.box_users.lock().unwrap();
        u.clear();
        for n in ["r1", "r2", "r4"] {
            u.insert(n.into());
        }
    }
    set_helper_ip(&b.ctx, pop_live, "198.51.100.9", "manual").unwrap();
    let h = crate::relay_health::relay_health(&b.ctx, pop_live, true).unwrap();
    assert_eq!(h.people_unknown, Some(1), "{h:?}");
    assert!(h.details.iter().any(|d| d.contains("r4")));
    // The names come with the count, from the same read, and the cached
    // answer carries them without reaching the relay again (the relay
    // page lists them under People from here, RG review finding 1).
    assert_eq!(h.relay_only, Some(vec!["r4".to_string()]), "{h:?}");
    let lists = *b.mock.users_list_calls.lock().unwrap();
    let checks = b.mock.relay_health_calls.lock().unwrap().len();
    let cached = crate::relay_health::relay_health(&b.ctx, pop_live, false).unwrap();
    assert!(cached.from_cache);
    assert_eq!(cached.relay_only, Some(vec!["r4".to_string()]));
    assert_eq!(*b.mock.users_list_calls.lock().unwrap(), lists, "no second read");
    assert_eq!(b.mock.relay_health_calls.lock().unwrap().len(), checks, "no second check");
    let next = recipient_provision(&b.ctx, pop_live, &address(9), "Later").unwrap();
    assert_eq!(next.name, "r5", "the name the relay already has is skipped");
}

// ------------------------------------------------- after a restore (PB-1/2)

struct Restored {
    b: Phone,
    op: i64,
    maman: i64,
    bob: i64,
}

/// The backup has Maman (r1), Bob (r2) and Carol (r3, removed). On the
/// old phone, after the backup, Maman was removed: the relay now has only
/// Bob. The new phone restores the backup and knows its address.
fn restored_after_maman_left() -> Restored {
    let (a, b, file, words) = restore_rig();
    let op = list_operators(&a.ctx)
        .unwrap()
        .into_iter()
        .find(|o| o.status == "provisioned")
        .unwrap()
        .id;
    let rows = a.ctx.db.list_recipients(op).unwrap();
    let id_of = |n: &str| rows.iter().find(|r| r.display_name == n).unwrap().id;
    let (maman, bob) = (id_of(PERSON), id_of("Bob"));
    backup_restore(&b.ctx, &file, &words, None).unwrap();
    {
        let mut u = b.mock.box_users.lock().unwrap();
        u.clear();
        u.insert("r2".into());
    }
    set_helper_ip(&b.ctx, op, "198.51.100.9", "manual").unwrap();
    Restored { b, op, maman, bob }
}

fn states(p: &Phone, op: i64) -> Vec<(i64, String)> {
    p.ctx.db.with_conn(|c| {
        let mut s = c
            .prepare(
                "SELECT recipient_id, state FROM restore_unsettled WHERE operator_id = ?1
                 ORDER BY recipient_id",
            )
            .unwrap();
        let v = s
            .query_map([op], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        v
    })
}

fn renew(p: &Phone, op: i64) -> crate::renew::RenewReport {
    crate::renew::renew_everyone(&p.ctx, op, &mut |_| {}).unwrap()
}

fn provisioned(p: &Phone, name: &str) -> bool {
    p.mock
        .renew_box_writes
        .lock()
        .unwrap()
        .iter()
        .any(|w| w == &format!("provision {name}"))
}

#[test]
fn a_person_removed_after_the_backup_is_not_created_again_before_an_answer() {
    let r = restored_after_maman_left();
    let b = &r.b;
    assert_eq!(
        states(b, r.op),
        vec![(r.maman, "unchecked".into()), (r.bob, "unchecked".into())],
        "the restore marks everyone not removed"
    );

    // Renew before anyone was asked: the relay is read first, Maman is
    // skipped with a reason, and nothing about her reaches the relay.
    let report = renew(b, r.op);
    let by = |rep: &crate::renew::RenewReport, id: i64| {
        rep.items.iter().find(|i| i.recipient_id == Some(id)).unwrap().clone()
    };
    assert_eq!(by(&report, r.maman).status, "needs_answer");
    assert_eq!(by(&report, r.maman).reason, "restore_unanswered");
    assert_eq!(by(&report, r.bob).status, "already_done");
    assert!(!report.all_done, "{report:?}");
    let call = b.mock.users_renew_calls.lock().unwrap()[0].clone();
    for list in [&call.ensure, &call.replace, &call.revoke] {
        assert!(!list.contains(&"r1".to_string()), "{call:?}");
    }
    assert!(!provisioned(b, "r1"));
    assert_eq!(
        states(b, r.op),
        vec![(r.maman, "ask".into())],
        "Bob is on the relay: nothing to settle"
    );

    // Pressing it again changes nothing for her.
    let again = renew(b, r.op);
    assert_eq!(by(&again, r.maman).status, "needs_answer");
    assert!(!again.all_done);
    assert!(!provisioned(b, "r1"));

    // Asked by name.
    let q = crate::restore_settle::restore_unsettled(&b.ctx, r.op).unwrap();
    assert!(q.checked && q.check_error.is_none());
    assert_eq!(q.people.len(), 1);
    assert_eq!(q.people[0].recipient_id, r.maman);
    assert_eq!(q.people[0].name, PERSON);
    assert_eq!(
        list_operators(&b.ctx)
            .unwrap()
            .iter()
            .find(|o| o.id == r.op)
            .unwrap()
            .people_needing_answer,
        1
    );

    // "Still should have access": only now is she created, with a file.
    crate::restore_settle::restore_answer(&b.ctx, r.op, r.maman, true).unwrap();
    let after = renew(b, r.op);
    assert_eq!(by(&after, r.maman).status, "done", "{after:?}");
    assert!(provisioned(b, "r1"));
    assert!(after.all_done, "{after:?}");
    assert!(crate::restore_settle::restore_unsettled(&b.ctx, r.op)
        .unwrap()
        .people
        .is_empty());
    // Asked once: the same answer again is fine, the other one is not.
    crate::restore_settle::restore_answer(&b.ctx, r.op, r.maman, true).unwrap();
    let e = crate::restore_settle::restore_answer(&b.ctx, r.op, r.maman, false).unwrap_err();
    assert_eq!(code(e), crate::commands::E_RESTORE_ALREADY_ANSWERED);
    // Bob was never a question.
    let e = crate::restore_settle::restore_answer(&b.ctx, r.op, r.bob, true).unwrap_err();
    assert_eq!(code(e), crate::commands::E_RESTORE_NOT_ASKED);
}

#[test]
fn a_person_answered_as_removed_is_marked_removed_and_never_created() {
    let r = restored_after_maman_left();
    let b = &r.b;
    let q = crate::restore_settle::restore_unsettled(&b.ctx, r.op).unwrap();
    assert_eq!(q.people.len(), 1);
    let file = b.ctx.staging_dir.join(format!("{}.r1.sbpx", r.op));
    assert!(file.exists(), "her file came with the backup");
    let before = backup_status(&b.ctx).unwrap();

    crate::restore_settle::restore_answer(&b.ctx, r.op, r.maman, false).unwrap();
    let row = b.ctx.db.get_recipient(r.op, r.maman).unwrap().unwrap();
    assert_ne!(row.revoked_at_unix, 0, "marked removed on this phone");
    assert!(!file.exists(), "her dead file is not kept to hand out");
    assert_ne!(
        backup_status(&b.ctx).unwrap(),
        before,
        "a person removed makes the backup out of date"
    );

    for _ in 0..2 {
        let report = renew(b, r.op);
        assert!(report.all_done, "{report:?}");
        assert!(report.items.iter().all(|i| i.recipient_id != Some(r.maman)));
        assert!(!provisioned(b, "r1"));
    }
    let calls = b.mock.users_renew_calls.lock().unwrap().clone();
    assert!(calls.iter().all(|c| c.revoke.contains(&"r1".to_string())
        && !c.ensure.contains(&"r1".to_string())
        && !c.replace.contains(&"r1".to_string())));
    assert!(crate::recipient_book::recipient_repack_sbpx(&b.ctx, r.op, r.maman).is_err());
    assert!(!b
        .mock
        .users_provision_calls
        .lock()
        .unwrap()
        .contains(&"r1".to_string()));
}

#[test]
fn an_unreachable_relay_after_a_restore_assumes_nothing() {
    let r = restored_after_maman_left();
    let b = &r.b;
    *b.mock.users_list_error.lock().unwrap() = Some((1, "users/list: mgmt answered 502".into()));

    let q = crate::restore_settle::restore_unsettled(&b.ctx, r.op).unwrap();
    assert!(!q.checked);
    assert!(q.people.is_empty(), "nobody is called removed or kept");
    assert!(q
        .check_error
        .as_deref()
        .unwrap()
        .starts_with(crate::commands::E_RELAY_UNREACHABLE));

    let e = crate::renew::renew_everyone(&b.ctx, r.op, &mut |_| {}).unwrap_err();
    assert_eq!(code(e), crate::commands::E_RELAY_UNREACHABLE);
    assert!(b.mock.users_renew_calls.lock().unwrap().is_empty(), "nothing sent");
    assert!(crate::recipient_book::recipient_repack_sbpx(&b.ctx, r.op, r.maman).is_err());
    assert!(crate::relay_rotation::rotate_credentials(&b.ctx, r.op, "r1").is_err());
    assert!(b.mock.users_provision_calls.lock().unwrap().is_empty());
    assert!(b.mock.rotate_credentials_calls.lock().unwrap().is_empty());
    let o = crate::restore_settle::relay_only_users(&b.ctx, r.op).unwrap();
    assert!(!o.checked && o.users.is_empty() && o.check_error.is_some());
    assert_eq!(
        states(b, r.op),
        vec![(r.maman, "unchecked".into()), (r.bob, "unchecked".into())],
        "still unsettled, still nothing assumed"
    );

    // Reachable again: the check runs and asks about Maman.
    *b.mock.users_list_error.lock().unwrap() = None;
    let q = crate::restore_settle::restore_unsettled(&b.ctx, r.op).unwrap();
    assert!(q.checked);
    assert_eq!(q.people.iter().map(|p| p.recipient_id).collect::<Vec<_>>(), vec![r.maman]);
}

#[test]
fn the_health_check_settles_who_the_relay_knows_and_does_not_count_the_question_as_missing() {
    let r = restored_after_maman_left();
    let b = &r.b;
    let h = crate::relay_health::relay_health(&b.ctx, r.op, true).unwrap();
    assert_eq!(h.people_needing_answer, 1, "{h:?}");
    assert_eq!(h.people_missing, Some(0), "her renew must wait for the answer");
    assert_eq!(states(b, r.op), vec![(r.maman, "ask".into())]);
    // The repack of the one person waiting refuses without a round trip;
    // Bob's goes ahead.
    let lists = *b.mock.users_list_calls.lock().unwrap();
    let e = crate::recipient_book::recipient_repack_sbpx(&b.ctx, r.op, r.maman).unwrap_err();
    assert_eq!(code(e), crate::commands::E_RESTORE_UNANSWERED);
    let e = crate::relay_rotation::rotate_credentials(&b.ctx, r.op, "r1").unwrap_err();
    assert_eq!(code(e), crate::commands::E_RESTORE_UNANSWERED);
    assert_eq!(*b.mock.users_list_calls.lock().unwrap(), lists);
    assert!(!b.mock.users_provision_calls.lock().unwrap().contains(&"r1".to_string()));
    crate::recipient_book::recipient_repack_sbpx(&b.ctx, r.op, r.bob).unwrap();
}

#[test]
fn a_person_added_after_the_restore_is_not_a_question() {
    let r = restored_after_maman_left();
    let b = &r.b;
    let kian = recipient_provision(&b.ctx, r.op, &address(9), "Kian").unwrap();
    // Kian is not on the mock box yet; renew creates him as anyone else.
    let report = renew(b, r.op);
    let k = report.items.iter().find(|i| i.recipient_id == Some(kian.id)).unwrap();
    assert_ne!(k.status, "needs_answer", "{report:?}");
    assert!(states(b, r.op).iter().all(|(id, _)| *id != kian.id));
    let q = crate::restore_settle::restore_unsettled(&b.ctx, r.op).unwrap();
    assert_eq!(q.people.iter().map(|p| p.recipient_id).collect::<Vec<_>>(), vec![r.maman]);
}

#[test]
fn a_kill_between_the_restore_commit_and_the_settling_keeps_the_marker() {
    // Killed before the commit: no marker.
    let (_a, b, path, words) = restore_rig();
    set_fault(Some(RestoreFault::BeforeCommit));
    assert!(backup_restore(&b.ctx, &path, &words, None).is_err());
    list_operators(&b.ctx).unwrap();
    assert_eq!(
        b.ctx
            .db
            .with_conn(|c| c.query_row("SELECT COUNT(*) FROM restore_unsettled", [], |r| r
                .get::<_, i64>(0)))
            .unwrap(),
        0
    );

    // Killed right after the commit: the marker was in the commit's own
    // transaction, and the roll-forward on the next start keeps it.
    let (a, b, path, words) = restore_rig();
    set_fault(Some(RestoreFault::AfterCommit));
    assert!(backup_restore(&b.ctx, &path, &words, None).is_err());
    let op = list_operators(&a.ctx)
        .unwrap()
        .into_iter()
        .find(|o| o.status == "provisioned")
        .unwrap()
        .id;
    let marked = states(&b, op);
    assert_eq!(marked.len(), 2, "{marked:?}");
    assert!(marked.iter().all(|(_, s)| s == "unchecked"));
    list_operators(&b.ctx).unwrap();
    assert!(read_meta(&b.ctx).unwrap().restore_pending_nonce.is_empty(), "finished");
    assert_eq!(states(&b, op), marked, "the roll-forward did not settle anyone");
    // And it still stops a renew from creating an unknown person.
    b.mock.box_users.lock().unwrap().clear();
    set_helper_ip(&b.ctx, op, "198.51.100.9", "manual").unwrap();
    let report = renew(&b, op);
    assert!(report.items.iter().all(|i| i.status == "needs_answer"), "{report:?}");
    assert!(b.mock.renew_box_writes.lock().unwrap().iter().all(|w| !w.starts_with("provision r")
        || w == "provision r0"));
}

#[test]
fn a_relay_only_person_is_removed_by_name_and_a_listed_one_never() {
    let r = restored_after_maman_left();
    let b = &r.b;
    {
        let mut u = b.mock.box_users.lock().unwrap();
        u.insert("r1".into());
        u.insert("r4".into());
        u.insert("r0".into());
    }
    let o = crate::restore_settle::relay_only_users(&b.ctx, r.op).unwrap();
    assert!(o.checked && o.check_error.is_none());
    assert_eq!(o.users, vec!["r4".to_string()]);
    assert!(states(b, r.op).is_empty(), "that read settled the restore too");

    for (name, want) in [
        ("r1", crate::commands::E_RELAY_USER_IN_LIST),
        ("r2", crate::commands::E_RELAY_USER_IN_LIST),
        ("r3", crate::commands::E_RELAY_USER_IN_LIST), // Carol, removed, still in the list
        ("r0", crate::commands::E_RELAY_USER_INVALID),
        ("r04", crate::commands::E_RELAY_USER_INVALID),
        ("bob", crate::commands::E_RELAY_USER_INVALID),
        ("", crate::commands::E_RELAY_USER_INVALID),
    ] {
        let e = crate::restore_settle::relay_only_revoke(&b.ctx, r.op, name).unwrap_err();
        assert_eq!(code(e), want, "{name:?}");
    }
    assert!(b.mock.users_revoke_calls.lock().unwrap().is_empty(), "nothing sent");

    crate::restore_settle::relay_only_revoke(&b.ctx, r.op, "r4").unwrap();
    assert_eq!(*b.mock.users_revoke_calls.lock().unwrap(), vec!["r4".to_string()]);
    let rows = b.ctx.db.list_recipients(r.op).unwrap();
    assert!(rows.iter().all(|x| x.name != "r4"), "no row is invented for them");
    assert!(rows.iter().filter(|x| x.revoked_at_unix == 0).count() == 2);
}

// ------------------------------------------------------ network test

/// "Use as test relay": a report key made by the publisher library, the
/// relay's pack signed again with its address, the key in the backup
/// and back on a restored phone; "Stop" keeps the key (reports made
/// before still open) and the next signature carries no address.
#[test]
fn a_test_relays_report_key_is_signed_in_backed_up_and_kept_when_stopped() {
    use crate::report_key::{key_alias, retired_alias, set_test_relay, status};
    let a = phone();
    let pop = populate(&a);
    let words = set_words(&a);
    make(&a);
    assert!(!status(&a.ctx, pop.live).unwrap().has_key);

    // Maman and Bob connect with it (Carol was removed), and it has an
    // everyone file: confirmed by the person with that count shown.
    let on = set_test_relay(&a.ctx, pop.live, true, true).unwrap();
    assert!(on.is_test_relay && on.key_made);
    assert!(on.everyone_file_kept, "the everyone file is left as it was");
    assert_eq!(on.people_to_send, 2, "Maman and Bob; Carol was removed");
    assert_eq!(*a.mock.report_keygen_calls.lock().unwrap(), 1);
    let addr = a.mock.bind_report_to.lock().unwrap().last().cloned().flatten();
    let addr = addr.expect("the re-sign carried --report-to");
    assert!(addr.starts_with("daal1"));
    assert!(backup_status(&a.ctx).unwrap().stale, "the switch is a change to back up");

    let file = make(&a);
    let key = a.ctx.custody.get(&key_alias(pop.live)).unwrap();
    let b = phone();
    crate::recipient_identity::get_or_create(&b.ctx).unwrap();
    let path = carry(&file, &b);
    backup_restore(&b.ctx, &path, &words, None).unwrap();
    assert_eq!(b.ctx.custody.get(&key_alias(pop.live)).unwrap(), key);
    assert!(status(&b.ctx, pop.live).unwrap().is_test_relay);

    let off = set_test_relay(&a.ctx, pop.live, false, false).unwrap();
    assert!(!off.is_test_relay);
    assert_eq!(a.mock.bind_report_to.lock().unwrap().last().cloned().flatten(), None);
    assert_eq!(a.ctx.custody.get(&retired_alias(pop.live)).unwrap(), key);
    let st = status(&a.ctx, pop.live).unwrap();
    assert!(!st.is_test_relay && st.has_key);

    let again = set_test_relay(&a.ctx, pop.live, true, true).unwrap();
    assert!(!again.key_made, "the same key comes back");
    assert_eq!(*a.mock.report_keygen_calls.lock().unwrap(), 1);
    assert_eq!(a.mock.bind_report_to.lock().unwrap().last().cloned().flatten(), Some(addr));
}

/// A relay people connect with is not made the Test relay without the
/// second confirmation, and neither switching on nor off touches anyone
/// on the relay: no user is removed, added or given new keys, and no
/// file anyone holds is made again. (Re-making the everyone file would
/// re-key the shared user and cut off every phone holding the old one.)
#[test]
fn the_test_relay_switch_never_cuts_anyone_off() {
    use crate::report_key::{set_test_relay, status, E_TEST_RELAY_IN_USE};
    let a = phone();
    let pop = populate(&a);
    let st = status(&a.ctx, pop.live).unwrap();
    assert_eq!(st.people_on_relay, 2);
    assert!(st.everyone_file);

    a.mock.users_revoke_calls.lock().unwrap().clear();
    a.mock.users_provision_calls.lock().unwrap().clear();
    let shared = a.ctx.staging_dir.join(format!("{}.shared.sbp", pop.live));
    let everyone_before = std::fs::read(&shared).unwrap();
    let binds_before = a.mock.bind_report_to.lock().unwrap().len();

    let err = set_test_relay(&a.ctx, pop.live, true, false).unwrap_err();
    assert!(code(err).starts_with(E_TEST_RELAY_IN_USE));
    assert_eq!(*a.mock.report_keygen_calls.lock().unwrap(), 0, "refused before any key is made");
    assert_eq!(a.mock.bind_report_to.lock().unwrap().len(), binds_before, "nothing was signed");
    assert!(!status(&a.ctx, pop.live).unwrap().has_key);

    let on = set_test_relay(&a.ctx, pop.live, true, true).unwrap();
    assert!(on.is_test_relay && on.everyone_file_kept);
    set_test_relay(&a.ctx, pop.live, false, false).unwrap();

    assert!(a.mock.users_revoke_calls.lock().unwrap().is_empty(), "nobody was removed or re-keyed");
    assert!(a.mock.users_provision_calls.lock().unwrap().is_empty(), "nobody was added");
    assert_eq!(std::fs::read(&shared).unwrap(), everyone_before, "the everyone file is the one people hold");
}

/// A failed signature puts the switch back: the key's place says what
/// the signed pack carries.
#[test]
fn a_failed_signature_leaves_the_relay_as_it_was() {
    use crate::report_key::{set_test_relay, status};
    let a = phone();
    let pop = populate(&a);
    *a.mock.bind_error.lock().unwrap() = Some("relay unreachable".into());
    assert!(set_test_relay(&a.ctx, pop.live, true, true).is_err());
    let st = status(&a.ctx, pop.live).unwrap();
    assert!(!st.is_test_relay, "not the Test relay: its pack was not signed so");
    assert!(st.has_key, "the key made is kept for the next try");
    *a.mock.bind_error.lock().unwrap() = None;
    let on = set_test_relay(&a.ctx, pop.live, true, true).unwrap();
    assert!(on.is_test_relay && !on.key_made);
    assert_eq!(*a.mock.report_keygen_calls.lock().unwrap(), 1);
}

#[test]
fn a_received_report_opens_with_a_key_on_this_phone_and_nothing_else() {
    use crate::report_key::{open_report, set_test_relay, E_REPORT_NOT_A_REPORT, E_REPORT_NO_KEY, E_REPORT_NOT_OURS};
    let a = phone();
    let pop = populate(&a);
    let dat = a.dir.path().join("net-abcdefgh.dat");
    std::fs::write(&dat, b"DSBR\x00\x01sealed-bytes").unwrap();
    assert!(code(open_report(&a.ctx, &dat).unwrap_err()).starts_with(E_REPORT_NO_KEY));

    set_test_relay(&a.ctx, pop.live, true, true).unwrap();
    assert!(code(open_report(&a.ctx, &dat).unwrap_err()).starts_with(E_REPORT_NOT_OURS));
    *a.mock.report_open_result.lock().unwrap() = Some(r#"{"schema_version":2,"findings":[]}"#.into());
    let json = open_report(&a.ctx, &dat).unwrap();
    assert!(json.contains("\"schema_version\":2"));
    let keys = a.mock.report_open_keys.lock().unwrap().clone();
    assert!(keys.iter().all(|k| k.len() == 64));

    let pack = a.dir.path().join("pack.dat");
    std::fs::write(&pack, b"DSBP\x00\x01not-a-report").unwrap();
    assert!(code(open_report(&a.ctx, &pack).unwrap_err()).starts_with(E_REPORT_NOT_A_REPORT));
}

// ------------------------------------------------------------ add-ons (V019)

const ADDON_SECRET: &[u8] = b"cf-addon-token-in-the-backup-0001";

/// A Cloudflare add-on on the live relay, its token in custody.
fn with_addon(p: &Phone, live: i64) -> (i64, String) {
    use crate::addons::{insert, secret_alias, set_secret_alias, AddonKind, AddonState, NewAddon};
    let id = insert(
        &p.ctx,
        &NewAddon {
            operator_id: live,
            kind: Some(AddonKind::Cdn),
            state: Some(AddonState::Ready),
            provider_ids: BTreeMap::from([("zone_id".to_string(), "z-1".to_string())]),
            ..Default::default()
        },
    )
    .unwrap();
    let alias = secret_alias(id, AddonKind::Cdn);
    p.ctx.custody.put(&alias, ADDON_SECRET).unwrap();
    set_secret_alias(&p.ctx, id, &alias).unwrap();
    (id, alias)
}

#[test]
fn an_addon_and_its_secret_travel_in_the_backup() {
    let a = phone();
    let pop = populate(&a);
    let (id, alias) = with_addon(&a, pop.live);
    let words = set_words(&a);
    let file = make(&a);
    assert!(!backup_status(&a.ctx).unwrap().stale);

    let b = phone();
    crate::recipient_identity::get_or_create(&b.ctx).unwrap();
    let path = carry(&file, &b);
    backup_restore(&b.ctx, &path, &words, None).unwrap();
    let rows = crate::addons::list(&b.ctx, pop.live).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id);
    assert_eq!(rows[0].provider_ids.get("zone_id").map(String::as_str), Some("z-1"));
    assert!(rows[0].has_secret);
    assert_eq!(b.ctx.custody.get(&alias).unwrap(), ADDON_SECRET);
}

#[test]
fn an_empty_addon_ledger_leaves_the_digest_as_it_was_and_a_row_changes_it() {
    let a = phone();
    let pop = populate(&a);
    let mut snap = collect_state(&a.ctx, SecretMode::Lenient).unwrap();
    assert!(snap.tables.contains_key("relay_addons"));
    let with_empty = digest_of(&snap);
    snap.tables.remove("relay_addons");
    assert_eq!(digest_of(&snap), with_empty, "a phone that never used an add-on keeps its digest");

    with_addon(&a, pop.live);
    assert_ne!(state_digest(&a.ctx).unwrap(), with_empty);
}

#[test]
fn a_backup_made_before_the_addon_ledger_restores() {
    let a = phone();
    let pop = populate(&a);
    let words = set_words(&a);
    let file = std::fs::read(make(&a)).unwrap();
    let e = entropy(&a);
    // What a V018 build wrote: no relay_addons table, schema 18.
    let h = parse_header(&file).unwrap();
    let pt = decrypt_with(&file, &h, &e).unwrap();
    let mut v: Value = serde_json::from_slice(&pt).unwrap();
    v["tables"].as_object_mut().unwrap().remove("relay_addons");
    v["db_schema_version"] = json!(18);
    let old = seal(&e, &serde_json::to_vec(&v).unwrap(), make_params()).unwrap();

    let b = phone();
    crate::recipient_identity::get_or_create(&b.ctx).unwrap();
    let path = b.dir.path().join("old.daalbackup");
    std::fs::write(&path, &old).unwrap();
    backup_restore(&b.ctx, &path, &words, None).unwrap();
    assert!(crate::addons::list(&b.ctx, pop.live).unwrap().is_empty());
    assert_eq!(list_operators(&b.ctx).unwrap().len(), 2);

    // The same payload claiming the current schema is missing a table.
    v["db_schema_version"] = json!(crate::operator_db::current_schema_version());
    let lying = seal(&e, &serde_json::to_vec(&v).unwrap(), make_params()).unwrap();
    let c = phone();
    crate::recipient_identity::get_or_create(&c.ctx).unwrap();
    let path = c.dir.path().join("lying.daalbackup");
    std::fs::write(&path, &lying).unwrap();
    let err = backup_restore(&c.ctx, &path, &words, None).map(|_| ()).unwrap_err();
    assert_eq!(code(err), E_BACKUP_DAMAGED);
}
