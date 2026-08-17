//! Wave 3 Step 7 — heal a live relay in place.
//!
//! Two operations, and the whole point of this module is that they are
//! **two**, not one:
//!
//!   * [`rotate_credentials`] re-keys ONE named recipient across every
//!     inbound on the box. It is a targeted revocation. Exactly one
//!     person's connection file dies; everybody else keeps connecting
//!     with the file they already have.
//!
//!   * [`rotate_tls`] moves the relay's cover hostname and TLS
//!     parameters. Every recipient's pinned parameters go stale at
//!     once, so EVERY connection file ever handed out stops working —
//!     the everyone-pack and each person's own `.sbpx` alike.
//!
//! Those two blast radii differ by three orders of magnitude, and the
//! relay's mgmt service used to conflate them: one handler rotated
//! per-recipient credentials *and* the box-wide REALITY keypair in a
//! single call. Wave 3 splits them on the box; this module is the
//! publisher half, and it keeps them split all the way to the button.
//! There is deliberately no "rotate everything" entry point here.
//!
//! Rotating the box's REALITY keypair is a THIRD operation with its own
//! endpoint and its own confirmation. It is not exposed here, and it
//! must never become a side effect of either of these two.
//!
//! ## What this module will not pretend
//!
//! This section was written at Step 7 and read: "Step 8 (remote pack
//! replacement) is not built. Nothing repairs itself over the network.
//! After either rotation the affected people need a new file delivered
//! by hand." Step 8 landed at Wave 3b and that is now false. It is
//! corrected rather than deleted because the replacement claim is
//! narrower than "it heals itself now", and the narrowness is the
//! whole point:
//!
//!   * Whether a recipient can be repaired over the network is a
//!     property of the pack ALREADY IN THEIR HANDS — does it carry
//!     freshness endpoints? — and not of what the publisher has
//!     configured since. A pack minted before the publisher added any
//!     endpoint still needs a courier, forever. The UI branches on the
//!     signed pack (`mirrorsInPack`), never on configuration.
//!   * Neither operation here publishes anything. `rotate_execute`
//!     (commands.rs) re-signs and re-publishes the freshness document
//!     inside one transaction; these two do not. After a TLS rotation
//!     the operator must rebuild the packs and press Publish under
//!     Refresh addresses, and the result copy says so.
//!
//! Both summaries below still carry the counts, because the screen has
//! to be able to state the consequence rather than imply it.
//!
//! ## Version skew is the normal case
//!
//! `cmd/daal-relay-mgmt` ships as a hash-pinned artifact, so a relay
//! runs whatever binary it was born with until a human re-releases.
//! This app is therefore routinely newer than the relays it drives.
//! Every path here fails closed on a relay that cannot prove it
//! supports the scoped operation — see [`E_RELAY_TOO_OLD`].
//!
//! Position B: this module never opens a socket. Every box interaction
//! goes through the `daal-deploy` subprocess bridge.

use serde::{Deserialize, Serialize};

use crate::cli_bridge::{RotateCredentialsArgs, RotateTlsArgs};
use crate::commands::{
    coded, custody_get, custody_get_string, map_rotation_err, require_helper_ip, WizardCtx,
    WizardError, E_RELAY_TOO_OLD,
};
use crate::recipient_book::{merge_and_pack_sbpx, write_record_staging};

/// The outcome of a per-recipient credential rotation, shaped for the
/// result panel: what moved, and what the operator now has to do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotateCredentialsSummary {
    /// Local roster row id, so the UI can refresh exactly one card.
    pub recipient_id: i64,
    /// The box-side name (`r1`, `r7`, …).
    pub name: String,
    /// The operator's own alias for this person; may be empty.
    pub display_name: String,
    pub rotated_at_unix: i64,
    /// Path to the freshly built `.sbpx`, or empty when the rebuild
    /// failed. Empty is NOT "nothing happened": the box credentials
    /// have already moved by then, so `warnings` says so.
    pub sbpx_path: String,
    /// Every inbound the relay says it actually rewrote. Empty means the
    /// relay would not say, and therefore that nothing verified the
    /// revocation reached all four — the exact gap BUG-6 lived in.
    pub updated_inbounds: Vec<String>,
    /// True if the relay ALSO replaced its own key material. Must be
    /// false. When it is true this stopped being a per-recipient action
    /// and became a fleet-wide one, and the UI has to escalate rather
    /// than show the ordinary "one person needs a new file" result.
    pub box_keys_rotated: bool,
    /// Everything the relay, the cloud plane or this module wants said
    /// out loud. Rendered verbatim by the UI; never summarised.
    pub warnings: Vec<String>,
}

/// The outcome of a relay-level TLS rotation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotateTlsSummary {
    pub applied_at_unix: i64,
    /// The cover host the relay advertises now — the value the pack
    /// minter will use from here on.
    pub cover_sni: String,
    /// The cover host it advertised before, as far as the publisher
    /// knows. Empty on a relay provisioned before Wave 2.
    pub previous_cover_sni: String,
    /// True when the rotation was applied but the relay did not ECHO
    /// which host it landed on, so `cover_sni` is what was requested
    /// rather than what was verified. The rotation still happened; the
    /// publisher just cannot confirm the result. Surfacing this is the
    /// difference between an honest screen and one that presents an
    /// unverified hostname as fact.
    pub cover_sni_unknown: bool,
    /// True when the new cover host was written back to the stored
    /// OperatorRecord, so the pack minter's fallback is current.
    pub record_updated: bool,
    /// How many people are holding a file that just stopped working.
    pub live_recipients: i64,
    /// Whether an everyone-pack exists and is now dead too.
    pub shared_pack_stale: bool,
    pub warnings: Vec<String>,
}

/// `rotate_credentials` re-keys ONE recipient on the box and rebuilds
/// their `.sbpx`.
///
/// `recipient_name` is the box-side name (`r1`), not the roster row id,
/// because that is what the relay's `/rotate-credentials` scopes on.
/// An empty name is refused **here**, before any round-trip: on the box
/// a missing name is an error rather than "rotate all", and the client
/// must not be the thing that discovers that by accident.
pub fn rotate_credentials(
    ctx: &WizardCtx,
    operator_id: i64,
    recipient_name: &str,
) -> Result<RotateCredentialsSummary, WizardError> {
    let name = recipient_name.trim();
    if name.is_empty() {
        return Err(WizardError::Validation(
            "which recipient? a credential rotation is always scoped to one person".into(),
        ));
    }

    // The roster row has to exist first. Rotating a box user this app
    // has no row for would mint a live credential it can never store,
    // show or revoke — the same orphan-credential failure the repack
    // path exists to avoid.
    let row = ctx
        .db
        .list_recipients(operator_id)
        .map_err(WizardError::Db)?
        .into_iter()
        .find(|r| r.name == name)
        .ok_or_else(|| {
            WizardError::Validation(format!(
                "no recipient named {name} on this relay's roster"
            ))
        })?;
    if row.revoked_at_unix != 0 {
        // A revoked recipient has no user on the box to re-key, and
        // re-minting one would hand a working credential back to
        // someone the operator deliberately cut off.
        return Err(WizardError::Validation(
            "this recipient is revoked — add them again to give them access".into(),
        ));
    }

    // Fail on a missing helper IP before doing any work: without it the
    // ephemeral firewall window can't be punched and the subprocess
    // would burn 30 s to report "connection refused".
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let op_row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let priv_buf = custody_get(ctx, &op_row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &op_row.cloud_token_keystore_alias)?;

    let record_path = write_record_staging(ctx, operator_id, &op_row.operator_record_json)?;
    let res = ctx.cli.run_rotate_credentials(
        RotateCredentialsArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            name,
        },
        priv_buf.as_slice(),
    );
    let _ = std::fs::remove_file(&record_path);
    let creds = res.map_err(map_rotation_err)?;

    // Defence in depth behind the CLI's own pre-flight. A relay running
    // a pre-Step-7 mgmt binary ignores the name in the request body and
    // re-keys the box, so a response that does not echo the recipient we
    // asked for — or that carries no per-user material at all — is a
    // response we must not act on. We refuse to overwrite the local
    // credentials on it, because the roster would then disagree with the
    // box about every OTHER recipient too.
    if !creds.name.is_empty() && creds.name != name {
        return Err(coded(
            E_RELAY_TOO_OLD,
            format!(
                "asked this relay to rotate {name} and it answered about {}; \
                 its management service cannot scope a rotation to one recipient",
                creds.name
            ),
        ));
    }
    if creds.vless_uuid.is_empty() {
        return Err(coded(
            E_RELAY_TOO_OLD,
            "this relay returned no per-recipient credentials, so it cannot rotate one \
             recipient on their own",
        ));
    }

    let rotated_at = match (creds.rotated_at_unix, creds.generated_at_unix) {
        (n, _) if n > 0 => n,
        // The legacy spelling the box still emits alongside it.
        (_, n) if n > 0 => n,
        _ => (ctx.clock)(),
    };
    ctx.db
        .update_recipient_creds(
            operator_id,
            row.id,
            &creds.vless_uuid,
            &creds.reality_short_id,
            &creds.hy2_password,
            &creds.naive_password,
            &creds.ws_path,
            rotated_at,
        )
        .map_err(WizardError::Db)?;

    // The relay's own words, verbatim — it saw the config, we did not.
    let mut warnings = creds.warnings.clone();

    // `box_keys_rotated` is the assertion the whole split exists to make
    // checkable. A true here means the relay ALSO re-keyed its REALITY
    // keypair, which invalidates the pinned public key in every pack ever
    // distributed — a fleet-wide outage that arrived out of a
    // per-recipient button. It is not an error to return: the rotation
    // did happen and the box has already moved. But it changes what the
    // operator has to do next from "message one person" to "re-deliver to
    // everyone", so it is the one line allowed to preempt the relay's own
    // chatter rather than queue behind it.
    if creds.box_keys_rotated {
        warnings.insert(
            0,
            "this relay also replaced its own key material, so EVERY recipient's file has \
             stopped working — not just this one. Rebuild and re-deliver all of them."
                .into(),
        );
    }

    // The `.sbpx` rebuild is the deliverable, but its failure is NOT a
    // reason to return Err. By this point the box has already moved:
    // the recipient's old file is dead whether or not we managed to
    // build the new one. Reporting "rotation failed" here would leave
    // the operator believing their relative can still connect. So we
    // return the rotation as the success it was, with the missing file
    // stated as a warning and the roster row updated so the existing
    // Rebuild affordance can finish the job.
    let sbpx_path = match merge_and_pack_sbpx(
        ctx,
        operator_id,
        &row.name,
        &row.pubkey_x25519_hex,
        &creds,
        &op_row.operator_record_json,
    ) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            warnings.push(format!(
                "the credentials were rotated on the relay, but the new file could not be \
                 built: {e}"
            ));
            String::new()
        }
    };

    Ok(RotateCredentialsSummary {
        recipient_id: row.id,
        name: row.name,
        display_name: row.display_name,
        rotated_at_unix: rotated_at,
        sbpx_path,
        updated_inbounds: creds.updated_inbounds,
        box_keys_rotated: creds.box_keys_rotated,
        warnings,
    })
}

/// `rotate_tls` moves the relay's cover hostname / TLS parameters.
///
/// It touches no user credentials and no REALITY keypair. What it does
/// touch is every already-distributed pack, because each one pins the
/// cover host it was minted with — so the summary carries the count of
/// people who now need a new file by hand.
pub fn rotate_tls(ctx: &WizardCtx, operator_id: i64) -> Result<RotateTlsSummary, WizardError> {
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let op_row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let priv_buf = custody_get(ctx, &op_row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &op_row.cloud_token_keystore_alias)?;

    // Read the cover host the publisher believes is live BEFORE the
    // call. It is the fallback for `previous_cover_sni` so the result can
    // show the MOVE — "was X, now Y" — rather than just a destination,
    // and it has to be captured here because the CLI overwrites the
    // staged record with the post-rotation value.
    let record_cover_sni = serde_json::from_str::<serde_json::Value>(&op_row.operator_record_json)
        .ok()
        .and_then(|v| {
            v.get("cover_sni")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let record_path = write_record_staging(ctx, operator_id, &op_row.operator_record_json)?;
    let res = ctx.cli.run_rotate_tls(
        RotateTlsArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
        },
        priv_buf.as_slice(),
    );

    // READ BEFORE DELETE. `daal-deploy rotate-tls` rewrites the record
    // file IN PLACE with the updated OperatorRecord — it does not put it
    // on stdout — and the staged copy is this app's only sight of it. The
    // record's CoverSNI is what the pack minter falls back to, so dropping
    // this write means every pack built from here on quietly names the
    // burned host: the exact IP-to-SNI mismatch REALITY exists to prevent,
    // and one that shows up only as recipients who cannot connect.
    //
    // Deliberately unconditional on `res`: the CLI persists the record
    // BEFORE reporting, precisely so a rotation that applied and then
    // failed to report does not strand the operator with a relay they can
    // no longer mint packs for.
    let rewritten = std::fs::read_to_string(&record_path).ok();
    let _ = std::fs::remove_file(&record_path);

    // PERSIST BEFORE PROPAGATING. This block sits ABOVE the `?` on
    // purpose, and that placement is the whole point of the paragraph
    // above it. `mgmt.RotateTLSWithFW` deliberately returns a response
    // ALONGSIDE an error in the two cases where the box applied
    // something the publisher is unhappy about (the cover host did not
    // move; server_name and reality.handshake.server disagree), and
    // `runRotateTLS` writes the record and prints the JSON before
    // exiting non-zero for exactly that reason. Consuming the read-back
    // after the `?` — which is what this used to do — threw it away on
    // precisely the paths it exists to cover: the box moves, the record
    // file on disk carries the new cover host, we delete it, and the DB
    // keeps a value the relay stopped serving. Every pack minted after
    // that names a dead host, and the next rotation computes its
    // "previous" host wrongly on top of it.
    let mut record_warnings: Vec<String> = Vec::new();
    let mut record_updated = false;
    match rewritten {
        Some(body) if body.trim_start().starts_with('{') && body != op_row.operator_record_json => {
            ctx.db
                .update_record_json(operator_id, &body)
                .map_err(WizardError::Db)?;
            record_updated = true;
        }
        // Byte-identical to what we staged: the CLI rewrote nothing, so
        // the relay's recorded details did not move. Said out loud
        // rather than passed over in silence — on the success path it
        // means the cover host is unchanged despite a rotation the
        // operator believes happened.
        Some(_) => record_warnings.push(
            "the relay's recorded details did not change, so this app is still building files \
             for the cover host it had before"
                .into(),
        ),
        None => record_warnings.push(
            "the relay's updated details could not be read back, so this app may still be \
             building files for the old cover host"
                .into(),
        ),
    }

    let applied = res.map_err(map_rotation_err)?;

    // The relay's and the CLI's own words first; ours are appended.
    let mut warnings = applied.warnings.clone();
    warnings.extend(record_warnings);

    // `applied_sni` is the box's echo of what it actually put on the
    // wire. Empty means `cover_sni` below is what was REQUESTED, not
    // what was verified — a difference the screen must carry, because
    // acting on the wrong one mints packs for a host the relay is not
    // serving.
    let cover_sni_unknown = applied.applied_sni.is_empty();

    let live_recipients = ctx
        .db
        .count_live_recipients(operator_id)
        .map_err(WizardError::Db)?;
    let shared_pack_stale = ctx
        .staging_dir
        .join(format!("{operator_id}.shared.sbp"))
        .exists();

    Ok(RotateTlsSummary {
        applied_at_unix: if applied.applied_at_unix > 0 {
            applied.applied_at_unix
        } else {
            (ctx.clock)()
        },
        cover_sni: applied.cover_sni,
        previous_cover_sni: if applied.previous_cover_sni.is_empty() {
            record_cover_sni
        } else {
            applied.previous_cover_sni
        },
        cover_sni_unknown,
        record_updated,
        live_recipients,
        shared_pack_stale,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_bridge::{
        CliRunner, MockRunner, Pricing, RotateCredentialsResult, RotateTlsResult,
    };
    use crate::keystore::Keystore;
    use crate::operator_db::OperatorDb;
    use crate::recipient_book::{recipient_list, recipient_provision, recipient_revoke};
    use std::sync::Arc;

    fn mk_ctx() -> (WizardCtx, Arc<MockRunner>, i64) {
        let db = Arc::new(OperatorDb::open_in_memory().unwrap());
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("daal-w3s7-keystore-{nanos}"));
        let _ = std::fs::create_dir_all(&dir);
        let keystore = Arc::new(Keystore::new_in_memory(&dir));
        let priv_alias = "pub.priv".to_string();
        let token_alias = "cloud.tok".to_string();
        let op_id = db
            .insert_pre_provision(
                r#"{"region":"fsn1","server_type":"cpx12","public_ip":"1.2.3.4","mgmt_port":42424,"reality_public_key":"cmVjb3JkLXJlYWxpdHktcHVia2V5LWJhc2U2NC0zMg","tls_cert_sha256":"cmVjb3JkLXRscy1zcGtpLXNoYTI1Ni1waW4tYmFzZQ","cover_sni":"ftp.plusline.net"}"#,
                "ab",
                &priv_alias,
                "hetzner",
                &token_alias,
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
        let staging_dir = std::env::temp_dir().join(format!("daal-w3s7-staging-{nanos}"));
        let _ = std::fs::create_dir_all(&staging_dir);
        let custody: Arc<dyn crate::device_custody::DeviceCustody> =
            Arc::new(crate::device_custody::FileCustody::static_test(&dir).unwrap());
        custody.put(&priv_alias, &[0u8; 64]).unwrap();
        custody.put(&token_alias, b"mock-token").unwrap();
        let ctx = WizardCtx {
            db,
            keystore,
            staging_dir,
            cli,
            clock: Arc::new(|| 1_700_000_500),
            custody,
        };
        (ctx, mock, op_id)
    }

    fn sample_address() -> String {
        daal_recipient_addr::encode(&[0x11u8; 32])
    }

    /// Give the operator a signed bundle so the `.sbpx` rewrite has an
    /// input; without it the rebuild half is skipped.
    fn stage_signed_sbp(ctx: &WizardCtx, op_id: i64) {
        std::fs::write(ctx.staging_dir.join(format!("{op_id}.sbp")), b"signed-bundle").unwrap();
    }

    #[test]
    fn rotate_credentials_rekeys_one_recipient_and_rebuilds_their_file() {
        let (ctx, mock, op_id) = mk_ctx();
        let r = recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        stage_signed_sbp(&ctx, op_id);
        let before = ctx
            .db
            .get_recipient(op_id, r.id)
            .unwrap()
            .unwrap()
            .vless_uuid;

        let s = rotate_credentials(&ctx, op_id, "r1").unwrap();

        assert_eq!(s.recipient_id, r.id);
        assert_eq!(s.name, "r1");
        assert!(!s.sbpx_path.is_empty(), "the new file is the deliverable");
        assert!(std::path::Path::new(&s.sbpx_path).exists());
        // Scoped: exactly one box call, naming exactly one recipient.
        assert_eq!(*mock.rotate_credentials_calls.lock().unwrap(), vec!["r1"]);
        // And the local roster now agrees with the box.
        let after = ctx
            .db
            .get_recipient(op_id, r.id)
            .unwrap()
            .unwrap()
            .vless_uuid;
        assert_ne!(before, after);
        // Nobody was revoked and nobody else was minted.
        assert!(mock.users_revoke_calls.lock().unwrap().is_empty());
        assert_eq!(recipient_list(&ctx, op_id).unwrap().len(), 1);
    }

    #[test]
    fn rotate_credentials_refuses_an_empty_name() {
        // On the box a missing name is an error, never "rotate all".
        // The client must not be what discovers that.
        let (ctx, mock, op_id) = mk_ctx();
        let err = rotate_credentials(&ctx, op_id, "  ").unwrap_err();
        assert!(format!("{err:?}").contains("scoped to one person"), "{err:?}");
        assert!(mock.rotate_credentials_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn rotate_credentials_refuses_an_unknown_or_revoked_recipient() {
        let (ctx, _mock, op_id) = mk_ctx();
        let err = rotate_credentials(&ctx, op_id, "r9").unwrap_err();
        assert!(format!("{err:?}").contains("no recipient named r9"), "{err:?}");

        let r = recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        recipient_revoke(&ctx, op_id, r.id).unwrap();
        let err = rotate_credentials(&ctx, op_id, "r1").unwrap_err();
        assert!(format!("{err:?}").contains("revoked"), "{err:?}");
    }

    #[test]
    fn rotate_credentials_fails_closed_on_a_relay_that_cannot_scope() {
        // A pre-Step-7 mgmt binary ignores the requested name and
        // re-keys the whole box. Acting on that answer would leave the
        // roster lying about every OTHER recipient, so refuse — and do
        // NOT write the local credentials.
        let (ctx, mock, op_id) = mk_ctx();
        let r = recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        stage_signed_sbp(&ctx, op_id);
        let before = ctx
            .db
            .get_recipient(op_id, r.id)
            .unwrap()
            .unwrap()
            .vless_uuid;

        *mock.rotate_credentials_result.lock().unwrap() = Some(RotateCredentialsResult {
            // The old handler answers about inbounds[0].users[0].
            name: "r0".into(),
            vless_uuid: "22222222-2222-2222-2222-222222222222".into(),
            ..Default::default()
        });
        let err = rotate_credentials(&ctx, op_id, "r1").unwrap_err();
        assert!(format!("{err:?}").contains(E_RELAY_TOO_OLD), "{err:?}");
        assert_eq!(
            before,
            ctx.db.get_recipient(op_id, r.id).unwrap().unwrap().vless_uuid,
            "local credentials must not move when the box answer is untrustworthy"
        );

        // Same verdict when the box answers with no per-user material.
        *mock.rotate_credentials_result.lock().unwrap() =
            Some(RotateCredentialsResult { name: "r1".into(), ..Default::default() });
        let err = rotate_credentials(&ctx, op_id, "r1").unwrap_err();
        assert!(format!("{err:?}").contains(E_RELAY_TOO_OLD), "{err:?}");
    }

    #[test]
    fn rotate_credentials_reports_a_rotation_whose_file_could_not_be_rebuilt() {
        // No staged .sbp → the rewrite has no input. The box has still
        // moved, so this is a success with a warning, never an Err:
        // telling the operator "it failed" would leave them believing
        // their relative can still connect.
        let (ctx, _mock, op_id) = mk_ctx();
        recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        let s = rotate_credentials(&ctx, op_id, "r1").unwrap();
        assert!(s.sbpx_path.is_empty());
        assert!(
            s.warnings.iter().any(|w| w.contains("rotated on the relay")),
            "{:?}",
            s.warnings
        );
    }

    #[test]
    fn rotate_tls_writes_the_new_cover_host_back_and_counts_the_damage() {
        let (ctx, mock, op_id) = mk_ctx();
        recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        std::fs::write(ctx.staging_dir.join(format!("{op_id}.shared.sbp")), b"shared").unwrap();

        let s = rotate_tls(&ctx, op_id).unwrap();

        assert_eq!(*mock.rotate_tls_calls.lock().unwrap(), 1);
        assert_eq!(s.cover_sni, "mirror.hetzner.com");
        assert_eq!(s.previous_cover_sni, "ftp.plusline.net");
        assert!(!s.cover_sni_unknown);
        assert!(s.record_updated, "the pack minter's fallback must not go stale");
        assert_eq!(s.live_recipients, 1);
        assert!(s.shared_pack_stale);
        // No credentials were touched — that is a different operation.
        assert!(mock.rotate_credentials_calls.lock().unwrap().is_empty());
        assert!(mock.users_revoke_calls.lock().unwrap().is_empty());

        let rec: serde_json::Value =
            serde_json::from_str(&ctx.db.get(op_id).unwrap().operator_record_json).unwrap();
        assert_eq!(rec["cover_sni"], "mirror.hetzner.com");
    }

    #[test]
    fn rotate_tls_keeps_the_new_cover_host_even_when_the_cli_reports_a_failure() {
        // The box applied the move and the CLI then exited non-zero —
        // `mgmt.RotateTLSWithFW` returns a response ALONGSIDE an error
        // when it dislikes what the box reports (cover host did not
        // move; server_name and handshake disagree), and `runRotateTLS`
        // writes the record before propagating it. If the record
        // read-back is consumed only on the Ok path, the DB keeps a
        // cover host the relay stopped serving: every pack minted from
        // then on names a dead host, the next rotation's "previous host"
        // is wrong, and it can pick the host the box is already on.
        let (ctx, mock, op_id) = mk_ctx();
        *mock.rotate_tls_err.lock().unwrap() =
            Some("the box's server_name and reality.handshake.server disagree".into());

        let err = rotate_tls(&ctx, op_id).unwrap_err();
        assert!(format!("{err}").contains("disagree"), "{err}");

        let rec: serde_json::Value =
            serde_json::from_str(&ctx.db.get(op_id).unwrap().operator_record_json).unwrap();
        assert_eq!(
            rec["cover_sni"], "mirror.hetzner.com",
            "the relay moved and the record did not follow it: this app is now minting packs for a host the box no longer serves"
        );
    }

    #[test]
    fn rotate_tls_says_so_when_the_relay_will_not_confirm_the_new_host() {
        // A relay whose mgmt binary predates the echo applies the change
        // but does not report `applied_sni`. The value we then show and
        // record is what was REQUESTED, not what was verified — and the
        // difference has to reach the screen, because acting on the
        // wrong one mints packs for a host the relay is not serving.
        let (ctx, mock, op_id) = mk_ctx();
        *mock.rotate_tls_result.lock().unwrap() = Some(RotateTlsResult {
            applied_at_unix: 1_700_000_800,
            cover_sni: "mirror.init7.net".into(),
            previous_cover_sni: "ftp.plusline.net".into(),
            applied_sni: String::new(),
            ..Default::default()
        });
        let s = rotate_tls(&ctx, op_id).unwrap();
        assert_eq!(s.cover_sni, "mirror.init7.net");
        assert!(s.cover_sni_unknown, "unverified must not read as confirmed");
        assert_eq!(s.previous_cover_sni, "ftp.plusline.net");
    }

    #[test]
    fn rotate_credentials_surfaces_a_relay_that_re_keyed_the_whole_box() {
        // box_keys_rotated is the assertion the split exists to make
        // checkable. True means a per-recipient button just took every
        // recipient down, and that sentence has to lead the result — not
        // sit at the bottom of a warnings list.
        let (ctx, mock, op_id) = mk_ctx();
        recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        stage_signed_sbp(&ctx, op_id);
        *mock.rotate_credentials_result.lock().unwrap() = Some(RotateCredentialsResult {
            name: "r1".into(),
            vless_uuid: "33333333-3333-3333-3333-333333333333".into(),
            box_keys_rotated: true,
            warnings: vec!["relay note".into()],
            ..Default::default()
        });
        let s = rotate_credentials(&ctx, op_id, "r1").unwrap();
        assert!(s.box_keys_rotated);
        assert!(
            s.warnings[0].contains("EVERY recipient's file"),
            "the escalation must lead, not trail the relay's chatter: {:?}",
            s.warnings
        );
        assert!(
            s.warnings.contains(&"relay note".to_string()),
            "and the relay's own words must survive: {:?}",
            s.warnings
        );
    }

    #[test]
    fn rotate_credentials_carries_the_inbound_list_through() {
        // Empty updated_inbounds means nothing verified that the
        // revocation reached all four — the gap BUG-6 lived in. The
        // publisher must be able to tell "all four" from "we don't know".
        let (ctx, mock, op_id) = mk_ctx();
        recipient_provision(&ctx, op_id, &sample_address(), "Alice").unwrap();
        stage_signed_sbp(&ctx, op_id);

        let s = rotate_credentials(&ctx, op_id, "r1").unwrap();
        assert_eq!(s.updated_inbounds.len(), 4, "{:?}", s.updated_inbounds);

        *mock.rotate_credentials_result.lock().unwrap() = Some(RotateCredentialsResult {
            name: "r1".into(),
            vless_uuid: "44444444-4444-4444-4444-444444444444".into(),
            ..Default::default()
        });
        let s = rotate_credentials(&ctx, op_id, "r1").unwrap();
        assert!(s.updated_inbounds.is_empty());
    }

    #[test]
    fn rotate_credentials_keeps_the_box_material_the_pack_minter_reads() {
        // This hop re-serialises the box response into the creds file
        // that users-pack-sbp[x] parses, and serde drops unknown keys
        // silently — the same defect that swallowed cover_sni and
        // mux_inbound once already. Assert on the wire shape so a field
        // dropped from the struct fails here rather than in the field.
        let json = r#"{"name":"r1","vless_uuid":"u","cover_sni":"mirror.init7.net",
            "mux_inbound":true,"updated_inbounds":["a"],"box_keys_rotated":false,
            "rotated_at_unix":7,"reality_public_key":"rk","tls_cert_sha256":"pin",
            "tls_cert_pem":"pem","provisioned_at_unix":3,"warnings":["w"]}"#;
        let parsed: RotateCredentialsResult = serde_json::from_str(json).unwrap();
        let round = serde_json::to_value(&parsed).unwrap();
        for k in [
            "cover_sni",
            "mux_inbound",
            "reality_public_key",
            "tls_cert_sha256",
            "tls_cert_pem",
            "vless_uuid",
        ] {
            assert!(round.get(k).is_some(), "{k} dropped on the Rust hop");
        }
        assert_eq!(round["cover_sni"], "mirror.init7.net");
        assert_eq!(round["mux_inbound"], true);
    }
}
