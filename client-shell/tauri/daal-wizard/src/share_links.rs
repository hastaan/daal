//! "Links for other apps": standard share links for one person on a
//! relay (vless:// REALITY, ss:// 2022, and the Cloudflare way when its
//! signed commitment allows a plain hello; Hysteria 2 is left out until
//! a client is shown to connect with a pinned self-signed certificate), so
//! an iPhone or a second app can use the relay as that person.
//!
//! The person's material is staged exactly the way the per-person pack
//! path stages it (`recipient_book::merge_and_pack_sbpx`): the stored
//! per-person credentials, completed with the relay-wide material from
//! the OperatorRecord where they are empty, handed to `daal-deploy` as a
//! 0600 file (never argv) together with the signed `.sbp`, the relay's
//! address and its cover host. `daal-deploy users-share-links` decides
//! which ways can have a link (publisher/deploy/relaypack/share_links.go)
//! and holds every link to the signed endpoint.
//!
//! No relay round trip: links are made from what this device keeps, so
//! asking for them never re-keys the person and never breaks their file.
//!
//! A link is a credential. Nothing here logs one, `ShareLink` has no
//! `Debug` that prints it, and no error carries one.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli_bridge::AddonCliRequest;
use crate::commands::{WizardCtx, WizardError};
use crate::operator_db::DbError;
use crate::recipient_book::fill_box_material_from_record;

/// One importable link. `way` is `vless-reality`, `hysteria2`,
/// `shadowsocks` or `cdn`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareLink {
    pub way: String,
    pub label: String,
    pub link: String,
}

impl std::fmt::Debug for ShareLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareLink")
            .field("way", &self.way)
            .field("label", &self.label)
            .field("link", &"<redacted>")
            .finish()
    }
}

/// One way in that has no link. `reason` is a stable code:
/// `needs_insecure`, `missing_material`, `not_signed`,
/// `shows_cdn_name`, `no_link_format`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeftOutWay {
    pub way: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLinksResult {
    pub links: Vec<ShareLink>,
    pub left_out: Vec<LeftOutWay>,
}

/// The verb's stdout. `detail` (English prose) is dropped: the UI has
/// its own copy per reason code.
#[derive(Deserialize)]
struct Wire {
    #[serde(default)]
    links: Vec<ShareLink>,
    #[serde(default)]
    left_out: Vec<LeftOutWay>,
}

/// The links for one person. Refuses a removed person: a removed
/// person's credentials are dead on the relay, and handing them out
/// again would say otherwise.
pub fn recipient_share_links(
    ctx: &WizardCtx,
    operator_id: i64,
    recipient_id: i64,
) -> Result<ShareLinksResult, WizardError> {
    let r = ctx
        .db
        .get_recipient(operator_id, recipient_id)
        .map_err(WizardError::Db)?
        .ok_or_else(|| WizardError::Db(DbError::NotFound(recipient_id)))?;
    if r.revoked_at_unix != 0 {
        return Err(WizardError::Validation(
            "this person was removed — add them again to give them access".into(),
        ));
    }

    // Same input and same refusal as the per-person pack.
    let in_sbp_path = ctx.staging_dir.join(format!("{operator_id}.sbp"));
    if !in_sbp_path.exists() {
        return Err(WizardError::Pricing(
            "no signed bundle yet — build the relay pack first".into(),
        ));
    }
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let rec_val = serde_json::from_str::<serde_json::Value>(&row.operator_record_json)
        .unwrap_or(serde_json::Value::Null);
    let field = |k: &str| -> String {
        rec_val
            .get(k)
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string()
    };
    let relay_server_ip = field("public_ip");
    if relay_server_ip.is_empty() {
        return Err(WizardError::Pricing(
            "operator record has no public_ip — reprovision the box".into(),
        ));
    }
    let record_cover_sni = field("cover_sni");

    // The person's stored credentials, in the /users/provision shape the
    // verb reads (the same names `UserCredsResult` serialises to).
    let mut creds = serde_json::json!({
        "name": r.name,
        "vless_uuid": r.vless_uuid,
        "reality_short_id": r.reality_short_id,
        "hy2_password": r.hy2_password,
        "naive_password": r.naive_password,
        "ws_path": r.ws_path,
    });
    fill_box_material_from_record(&mut creds, &rec_val);
    let creds_json = Zeroizing::new(serde_json::to_string(&creds).unwrap_or_default());
    drop(creds);

    let mut args = vec![
        "users-share-links".to_string(),
        "--in".into(),
        in_sbp_path.to_string_lossy().to_string(),
        "--server".into(),
        relay_server_ip,
        "--cover-sni".into(),
        record_cover_sni,
    ];
    let nick = row.nickname.trim();
    if !nick.is_empty() {
        args.push("--label".into());
        args.push(nick.to_string());
    }
    let stdout = ctx
        .cli
        .run_addon(
            AddonCliRequest {
                args,
                secret_files: vec![("--creds-file", creds_json.as_str())],
                stdin: &[],
                progress: false,
            },
            &mut |_| {},
        )
        .map_err(crate::recipient_book::map_bridge_err)?;
    let wire: Wire = serde_json::from_slice(&stdout).map_err(|_| {
        // Never echo the stdout: it holds the links.
        WizardError::Subprocess("users-share-links: unreadable answer".into())
    })?;
    Ok(ShareLinksResult {
        links: wire.links,
        left_out: wire.left_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_bridge::{CliRunner, MockRunner, Pricing};
    use crate::keystore::Keystore;
    use crate::operator_db::OperatorDb;
    use std::sync::{Arc, Mutex};

    const RECORD: &str = r#"{"region":"fsn1","server_type":"cpx12","public_ip":"1.2.3.4","mgmt_port":42424,"reality_public_key":"rec-pbk","tls_cert_sha256":"rec-pin","cover_sni":"cover.example.net","cdn_front":{"origin_path":"/door-path"}}"#;

    fn mk_ctx() -> (WizardCtx, Arc<MockRunner>, i64) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let dir = std::env::temp_dir().join(format!("daal-share-links-ks-{nanos}"));
        let _ = std::fs::create_dir_all(&dir);
        let keystore = Arc::new(Keystore::new_in_memory(&dir));
        let op_id = db
            .insert_pre_provision(
                RECORD,
                "ab",
                "pub.priv",
                "hetzner",
                "cloud.tok",
                1_700_000_000,
            )
            .unwrap();
        db.set_helper_ip(op_id, "1.2.3.4", "manual", 1_700_000_000)
            .unwrap();
        let mock = Arc::new(MockRunner::new(Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cpx12".into(),
            hourly_eur: 0.0,
            monthly_eur: 0.0,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        }));
        let cli: Arc<dyn CliRunner> = mock.clone();
        let staging_dir = std::env::temp_dir().join(format!("daal-share-links-{nanos}"));
        let _ = std::fs::create_dir_all(&staging_dir);
        let custody: Arc<dyn crate::device_custody::DeviceCustody> =
            Arc::new(crate::device_custody::FileCustody::static_test(&dir).unwrap());
        custody.put("pub.priv", &[0u8; 64]).unwrap();
        custody.put("cloud.tok", b"mock-token").unwrap();
        let ctx = WizardCtx {
            db,
            keystore,
            journal_dir: staging_dir.join("provision-journal"),
            staging_dir,
            cli,
            clock: Arc::new(|| 1_700_000_500),
            custody,
        };
        (ctx, mock, op_id)
    }

    fn add_person(ctx: &WizardCtx, op_id: i64) -> i64 {
        let addr = daal_recipient_addr::encode(&[0x11u8; 32]);
        crate::recipient_book::recipient_provision(ctx, op_id, &addr, "Bahar")
            .unwrap()
            .id
    }

    fn write_signed_pack(ctx: &WizardCtx, op_id: i64) {
        std::fs::write(ctx.staging_dir.join(format!("{op_id}.sbp")), b"signed").unwrap();
    }

    const ANSWER: &str = r#"{"links":[{"way":"vless-reality","label":"Home · REALITY","link":"vless://secret@1.2.3.4:443?security=reality#x"}],"left_out":[{"way":"naive","reason":"needs_insecure","detail":"prose"}]}"#;

    #[test]
    fn stages_the_stored_person_and_returns_the_links() {
        let (ctx, mock, op_id) = mk_ctx();
        let rid = add_person(&ctx, op_id);
        write_signed_pack(&ctx, op_id);
        ctx.db.set_nickname(op_id, "Home").unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen2 = seen.clone();
        *mock.addon_reply.lock().unwrap() = Some(Box::new(move |args: &[String], stdin: &[u8]| {
            assert!(stdin.is_empty());
            *seen2.lock().unwrap() = args.to_vec();
            Ok(ANSWER.as_bytes().to_vec())
        }));
        let got = recipient_share_links(&ctx, op_id, rid).unwrap();
        assert_eq!(got.links.len(), 1);
        assert_eq!(got.links[0].way, "vless-reality");
        assert_eq!(
            got.left_out,
            vec![LeftOutWay {
                way: "naive".into(),
                reason: "needs_insecure".into()
            }]
        );
        let args = seen.lock().unwrap().clone();
        assert_eq!(args[0], "users-share-links");
        let after = |flag: &str| {
            let i = args.iter().position(|a| a == flag).unwrap();
            args[i + 1].clone()
        };
        assert!(after("--in").ends_with(&format!("{op_id}.sbp")));
        assert_eq!(after("--server"), "1.2.3.4");
        assert_eq!(after("--cover-sni"), "cover.example.net");
        assert_eq!(after("--label"), "Home");
        // The credentials never ride argv (they go as a 0600 file the
        // runner adds as --creds-file).
        let row = ctx.db.get_recipient(op_id, rid).unwrap().unwrap();
        for a in &args {
            assert!(!a.contains(&row.vless_uuid), "a credential in argv");
            assert!(!a.contains(&row.hy2_password), "a credential in argv");
        }
        // The Debug form never prints a link.
        assert!(!format!("{:?}", got.links[0]).contains("secret"));
    }

    #[test]
    fn refuses_a_removed_person() {
        let (ctx, mock, op_id) = mk_ctx();
        let rid = add_person(&ctx, op_id);
        write_signed_pack(&ctx, op_id);
        crate::recipient_book::recipient_revoke(&ctx, op_id, rid).unwrap();
        mock.addon_calls.lock().unwrap().clear();
        let err = recipient_share_links(&ctx, op_id, rid).unwrap_err();
        assert!(err.to_string().contains("removed"), "{err}");
        assert!(
            mock.addon_calls.lock().unwrap().is_empty(),
            "the verb ran for a removed person"
        );
    }

    #[test]
    fn needs_the_signed_pack() {
        let (ctx, _mock, op_id) = mk_ctx();
        let rid = add_person(&ctx, op_id);
        let _ = std::fs::remove_file(ctx.staging_dir.join(format!("{op_id}.sbp")));
        assert!(recipient_share_links(&ctx, op_id, rid).is_err());
    }

    #[test]
    fn an_unreadable_answer_does_not_echo_it() {
        let (ctx, mock, op_id) = mk_ctx();
        let rid = add_person(&ctx, op_id);
        write_signed_pack(&ctx, op_id);
        *mock.addon_reply.lock().unwrap() = Some(Box::new(|_: &[String], _: &[u8]| {
            Ok(b"vless://secret not json".to_vec())
        }));
        let err = recipient_share_links(&ctx, op_id, rid)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn record_fills_only_what_the_person_lacks() {
        let rec: serde_json::Value = serde_json::from_str(RECORD).unwrap();
        let mut creds = serde_json::json!({"vless_uuid": "u", "reality_public_key": ""});
        fill_box_material_from_record(&mut creds, &rec);
        assert_eq!(creds["reality_public_key"], "rec-pbk");
        assert_eq!(creds["tls_cert_sha256"], "rec-pin");
        assert_eq!(creds["cdn_ws_path"], "/door-path");
        let mut live = serde_json::json!({"reality_public_key": "live"});
        fill_box_material_from_record(&mut live, &rec);
        assert_eq!(live["reality_public_key"], "live");
    }
}
