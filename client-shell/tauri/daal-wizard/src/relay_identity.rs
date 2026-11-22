//! What the relay says it is — and keeping the signed pack true to it.
//!
//! # The problem this module closes
//!
//! A RelayPack commits every route to a **signed endpoint**: where the
//! route points, and what proves the far end is this relay — its
//! REALITY public key, its TLS key pin, its cover host, the digest of
//! its shadowsocks server key. A recipient's app refuses a route whose
//! outbound disagrees with that commitment, and refuses a route that
//! has none.
//!
//! The wizard signs the pack *before any recipient exists*. For a while
//! it signed from the stored relay record alone, and the record carries
//! the relay's keys only where a provider adapter happened to read them
//! over SSH while provisioning: one adapter read both, another read
//! neither, and none could ever read the shadowsocks key, which does
//! not exist until the relay has its first recipient. The result (rig
//! finding F-005): on one provider the Sign step failed outright; on
//! the other, shadowsocks was signed without an endpoint and silently
//! dropped from every file.
//!
//! # What this module does about it
//!
//! Two things, and it takes both for the flow to have no ordering trap:
//!
//!   1. **Ask the relay.** Before every signature the wizard asks the
//!      relay who it is (`daal-deploy relay-identity`, the relay's
//!      authenticated `GET /identity`). That works on every provider,
//!      with no SSH and no recipient. [`stage_for_signing`].
//!   2. **Notice when the relay has moved, and sign again.** The relay's
//!      identity is not a constant. Its shadowsocks key appears with
//!      the first recipient; its cover host moves on a disguise change;
//!      a rebuild replaces everything. So the wizard remembers what the
//!      active pack commits to (the signer reads it back out of the
//!      pack), compares every later relay reply against it, and when
//!      they differ signs again and republishes the refresh note —
//!      [`heal_after_reply`], [`resign_and_republish`].
//!
//! A relay too old to state its identity is the normal case for a while
//! (its management binary is a pinned artefact), so there is a fallback
//! and it is the same machinery fed from a different source: the
//! relay-wide fields of any reply the relay gives when a recipient is
//! added are turned into the same identity document
//! ([`identity_from_reply`]).
//!
//! # What is and is not stored
//!
//! Nothing secret. The shadowsocks server key reaches this app inside
//! each recipient's password (`<server key>:<user key>`); only its
//! digest is ever kept, and the digest is what the signed pack
//! publishes anyway.
//!
//! Position B: this module never opens a socket. Every box interaction
//! goes through the `daal-deploy` subprocess bridge.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli_bridge::{
    BindResult, CommittedIdentity, ProgressEvent, RelayIdentityArgs, RelayIdentityFetch,
    RotateCredentialsResult, UserCredsResult, UsersProvisionArgs,
};
use crate::commands::{
    coded, custody_get, custody_get_string, map_deploy_err, require_helper_ip, WizardCtx,
    WizardError, E_RELAY_KEYS_CHANGED, E_RELAY_TOO_OLD,
};

/// The publisher display name every re-sign uses — the one the address
/// swap and the rebuild rungs already pass.
pub(crate) const RESIGN_PUBLISHER_NAME: &str = "Family Relay Publisher";

/// `identity_source` values (V015).
const SOURCE_RELAY: &str = "relay";
const SOURCE_REPLY: &str = "reply";

/// The digest a signed endpoint carries for the relay's shadowsocks
/// server key.
///
/// A wire contract held in three places that share no symbol:
/// `bundle.SSServerKeyDigest` (what the recipient's app recomputes),
/// `ssServerKeyDigest` in `cmd/daal-relay-mgmt` (what the relay states),
/// and here (what the wizard derives from a reply). One test vector
/// pins all three.
pub fn ss_server_key_digest(server_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"daal/ss-server-key/v1\0");
    h.update(server_key.as_bytes());
    hex::encode(h.finalize())
}

/// The relay-wide half of a shadowsocks password
/// (`<server key>:<user key>`), or `""` when it is not of that shape.
fn ss_server_key(password: &str) -> &str {
    match password.split_once(':') {
        Some((server, user)) if !server.is_empty() && !user.is_empty() => server,
        _ => "",
    }
}

/// The fields of a relay reply that describe the RELAY rather than the
/// recipient it was minted for. Borrowed, never stored as-is: the
/// shadowsocks password in particular is a recipient secret.
#[derive(Debug, Clone, Copy)]
pub struct ReplyMaterial<'a> {
    pub reality_public_key: &'a str,
    pub tls_cert_sha256: &'a str,
    pub cover_sni: &'a str,
    pub ss_password: &'a str,
    pub ss_method: &'a str,
}

impl<'a> From<&'a UserCredsResult> for ReplyMaterial<'a> {
    fn from(c: &'a UserCredsResult) -> Self {
        Self {
            reality_public_key: &c.reality_public_key,
            tls_cert_sha256: &c.tls_cert_sha256,
            cover_sni: &c.cover_sni,
            ss_password: &c.ss_password,
            ss_method: &c.ss_method,
        }
    }
}

impl<'a> From<&'a RotateCredentialsResult> for ReplyMaterial<'a> {
    fn from(c: &'a RotateCredentialsResult) -> Self {
        Self {
            reality_public_key: &c.reality_public_key,
            tls_cert_sha256: &c.tls_cert_sha256,
            cover_sni: &c.cover_sni,
            ss_password: &c.ss_password,
            ss_method: &c.ss_method,
        }
    }
}

/// How current the identity behind a signature has to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Ask the relay now. The default, and the only choice after
    /// anything that can have moved the relay's keys or cover host.
    Fresh,
    /// An identity already learned from THIS relay may be reused. For
    /// the address swap only: it moves the address — which the record
    /// carries, not the relay's identity — and its whole value is a
    /// 15-second budget that a second round trip would spend.
    AllowCached,
}

/// What a re-sign did, shaped for a result panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PackResigned {
    pub relay_pack_id: String,
    pub sbp_sha256: String,
    /// Path of the newly signed (credential-less, publishable) file.
    pub signed_pack_path: String,
    /// Did the pack people ALREADY HOLD carry refresh addresses? Read
    /// before the re-sign, because that — not what is configured now —
    /// decides whether anybody's app can learn about the change.
    pub prior_pack_had_refresh_addresses: bool,
    /// The refresh note naming the new file was accepted by enough
    /// mirrors.
    pub refresh_note_published: bool,
    /// Why not, in the publisher's own words (`""` when it was, or when
    /// there was nothing to publish to).
    pub refresh_note_problem: String,
    /// Families the NEW pack still could not commit (see
    /// `BindResult::uncommitted_families`).
    pub uncommitted_families: Vec<String>,
}

// --------------------------------------------------------------------
// The identity document
// --------------------------------------------------------------------

fn text(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Build the identity document for a relay that cannot state one, from
/// what it said while minting a recipient. `base` is a document derived
/// earlier from the same relay: a field this reply leaves empty keeps
/// its earlier value (a reply for a recipient with no shadowsocks row
/// says nothing about the shadowsocks key; it does not unsay it).
pub fn identity_from_reply(reply: &ReplyMaterial<'_>, base: Option<&str>, now_unix: i64) -> String {
    let base: serde_json::Value = base
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let keep = |fresh: &str, key: &str| -> String {
        if fresh.trim().is_empty() {
            text(&base, key)
        } else {
            fresh.trim().to_string()
        }
    };
    let server_key = ss_server_key(reply.ss_password);
    let (ss_method, ss_digest) = if !server_key.is_empty() && !reply.ss_method.trim().is_empty() {
        (
            reply.ss_method.trim().to_string(),
            ss_server_key_digest(server_key),
        )
    } else {
        (
            text(&base, "ss_method"),
            text(&base, "ss_server_key_sha256"),
        )
    };
    let mut doc = serde_json::json!({
        "identity_version": 1,
        "families": [],
        "pending_families": [],
        "generated_at_unix": now_unix,
    });
    let mut put = |key: &str, value: String| {
        if !value.is_empty() {
            doc[key] = value.into();
        }
    };
    put(
        "reality_public_key",
        keep(reply.reality_public_key, "reality_public_key"),
    );
    put(
        "tls_cert_sha256",
        keep(reply.tls_cert_sha256, "tls_cert_sha256"),
    );
    put("cover_sni", keep(reply.cover_sni, "cover_sni"));
    // Method and digest travel together or not at all: the signer
    // refuses a document carrying one without the other.
    if !ss_method.is_empty() && !ss_digest.is_empty() {
        put("ss_method", ss_method);
        put("ss_server_key_sha256", ss_digest);
    }
    doc.to_string()
}

/// A document the relay stated must be one this app can read exactly:
/// it is about to go under a signature.
fn check_stated(json: &str) -> Result<(), WizardError> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        WizardError::Subprocess(format!("the relay's identity was not readable: {e}"))
    })?;
    match v.get("identity_version").and_then(|x| x.as_i64()) {
        Some(1) => Ok(()),
        other => Err(WizardError::Subprocess(format!(
            "the relay stated its identity in a format this app does not know (version {other:?})"
        ))),
    }
}

struct RecordView {
    box_fingerprint: String,
    mgmt_port: i64,
    cover_sni: String,
    has_key_material: bool,
    families: Vec<String>,
}

fn record_view(record_json: &str) -> RecordView {
    let v: serde_json::Value = serde_json::from_str(record_json).unwrap_or(serde_json::Value::Null);
    let families = v
        .get("candidates")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.get("family").and_then(|f| f.as_str()))
                .map(|f| f.to_string())
                .collect()
        })
        .unwrap_or_default();
    RecordView {
        box_fingerprint: text(&v, "mgmt_tls_fingerprint").to_ascii_lowercase(),
        mgmt_port: v.get("mgmt_port").and_then(|p| p.as_i64()).unwrap_or(0),
        cover_sni: text(&v, "cover_sni"),
        has_key_material: !text(&v, "reality_public_key").is_empty()
            || !text(&v, "tls_cert_sha256").is_empty(),
        families,
    }
}

/// A reply-derived document does not know about a later disguise
/// change, and the record does (rotate-tls rewrites it), so for that
/// source — and only that one — the record's cover host is written in.
/// A document the relay STATED is never edited: it is the authority.
fn with_record_cover(identity_json: &str, record_cover: &str) -> String {
    if record_cover.is_empty() {
        return identity_json.to_string();
    }
    match serde_json::from_str::<serde_json::Value>(identity_json) {
        Ok(mut v) if v.is_object() => {
            v["cover_sni"] = record_cover.into();
            v.to_string()
        }
        _ => identity_json.to_string(),
    }
}

fn staged_path(ctx: &WizardCtx, operator_id: i64) -> PathBuf {
    ctx.staging_dir
        .join(format!("{operator_id}.relay-identity.json"))
}

fn stage(ctx: &WizardCtx, operator_id: i64, identity_json: &str) -> Result<PathBuf, WizardError> {
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    let path = staged_path(ctx, operator_id);
    std::fs::write(&path, identity_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("stage relay identity: {e}")))?;
    Ok(path)
}

/// Ask the relay who it is. One firewall window, one read-only call.
fn ask_relay(ctx: &WizardCtx, operator_id: i64) -> Result<RelayIdentityFetch, WizardError> {
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    // The ROOT publisher key, always: it is the one whose public half
    // the relay holds for its management tokens. A pack may be signed
    // by a certified sub-key; a management call may not.
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    let record_path = ctx
        .staging_dir
        .join(format!("{operator_id}.identity-record.json"));
    std::fs::write(&record_path, row.operator_record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;
    let res = ctx.cli.run_relay_identity(
        RelayIdentityArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
        },
        priv_buf.as_slice(),
    );
    let _ = std::fs::remove_file(&record_path);
    res.map_err(map_deploy_err)
}

/// Decide what the next signature is made from, and stage it.
///
/// Returns the path of the identity document for `--relay-identity`,
/// or `None` when the relay cannot state one and the stored record is
/// enough to sign with on its own. The caller removes the file.
///
/// A relay that cannot be REACHED is an error, never a fallback: a
/// signature quietly made from an older source is one route short (or
/// names a cover host the relay left) and nothing would say so.
pub(crate) fn stage_for_signing(
    ctx: &WizardCtx,
    operator_id: i64,
    freshness: Freshness,
) -> Result<Option<PathBuf>, WizardError> {
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let rec = record_view(&row.operator_record_json);
    let stored = ctx
        .db
        .relay_identity(operator_id)
        .map_err(WizardError::Db)?;
    // An identity learned from a relay with a different management
    // certificate is about a machine that was since rebuilt.
    let known = !stored.identity_json.is_empty()
        && !rec.box_fingerprint.is_empty()
        && stored.box_fingerprint == rec.box_fingerprint;

    let cached = |ctx: &WizardCtx| -> Result<Option<PathBuf>, WizardError> {
        if !known {
            return Ok(None);
        }
        let doc = if stored.identity_source == SOURCE_REPLY {
            with_record_cover(&stored.identity_json, &rec.cover_sni)
        } else {
            stored.identity_json.clone()
        };
        stage(ctx, operator_id, &doc).map(Some)
    };

    if freshness == Freshness::AllowCached && known {
        // A stated identity is reused only while it still agrees with
        // the record about the cover host; a disagreement means one of
        // them is stale, and the relay is asked.
        let agrees = stored.identity_source == SOURCE_REPLY || {
            let v: serde_json::Value =
                serde_json::from_str(&stored.identity_json).unwrap_or(serde_json::Value::Null);
            let c = text(&v, "cover_sni");
            c.is_empty() || rec.cover_sni.is_empty() || c == rec.cover_sni
        };
        if agrees {
            return cached(ctx);
        }
    }

    // A record with no management plane describes a relay there is no
    // way to ask.
    if rec.mgmt_port == 0 || rec.box_fingerprint.is_empty() {
        return cached(ctx);
    }

    match ask_relay(ctx, operator_id)? {
        RelayIdentityFetch::Stated(json) => {
            check_stated(&json)?;
            let said: serde_json::Value =
                serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
            refuse_keys_changed_in_place(
                &stored,
                &rec,
                &text(&said, "reality_public_key"),
                &text(&said, "tls_cert_sha256"),
            )?;
            ctx.db
                .set_relay_identity_learned(
                    operator_id,
                    &json,
                    SOURCE_RELAY,
                    &rec.box_fingerprint,
                    (ctx.clock)(),
                )
                .map_err(WizardError::Db)?;
            stage(ctx, operator_id, &json).map(Some)
        }
        RelayIdentityFetch::Unsupported => {
            if known {
                return cached(ctx);
            }
            if rec.has_key_material {
                // The record can sign on its own (the provisioning SSH
                // read worked). Shadowsocks stays out until a recipient
                // reply teaches us its key — heal_after_reply.
                return Ok(None);
            }
            learn_by_adding_the_shared_user(ctx, operator_id, &rec)?;
            let stored = ctx
                .db
                .relay_identity(operator_id)
                .map_err(WizardError::Db)?;
            stage(
                ctx,
                operator_id,
                &with_record_cover(&stored.identity_json, &rec.cover_sni),
            )
            .map(Some)
        }
    }
}

/// The last resort, for a relay that can neither state its identity nor
/// was read at provision time: add the shared `r0` user and read the
/// relay's keys off the reply.
///
/// The reply's recipient secrets are dropped here and never stored —
/// nobody holds them, and `produce_shared_sbp` re-keys `r0` before it
/// hands the shared file to anyone. If `r0` already exists the relay
/// refuses (409), and re-keying it to learn the relay's keys would cut
/// off everyone holding the shared file; that is not a price a
/// signature may charge, so it is an error with the remedy in it.
fn learn_by_adding_the_shared_user(
    ctx: &WizardCtx,
    operator_id: i64,
    rec: &RecordView,
) -> Result<(), WizardError> {
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let record_path = ctx
        .staging_dir
        .join(format!("{operator_id}.identity-record.json"));
    std::fs::write(&record_path, row.operator_record_json.as_bytes())
        .map_err(|e| WizardError::Pricing(format!("write record: {e}")))?;
    let res = ctx.cli.run_users_provision(
        UsersProvisionArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            name: crate::recipient_book::SHARED_USER_NAME,
        },
        priv_buf.as_slice(),
    );
    let _ = std::fs::remove_file(&record_path);
    let creds = res.map_err(|e| {
        coded(
            E_RELAY_TOO_OLD,
            format!(
                "this relay's software is too old to tell the app its keys, and the app could not \
                 read them another way ({e}). Rebuild the relay to bring its software up to date."
            ),
        )
    })?;
    let doc = identity_from_reply(&ReplyMaterial::from(&creds), None, (ctx.clock)());
    ctx.db
        .set_relay_identity_learned(
            operator_id,
            &doc,
            SOURCE_REPLY,
            &rec.box_fingerprint,
            (ctx.clock)(),
        )
        .map_err(WizardError::Db)
}

/// Remember what the pack that was just signed commits the relay to.
pub(crate) fn record_committed(
    ctx: &WizardCtx,
    operator_id: i64,
    bind: &BindResult,
    now_unix: i64,
) -> Result<(), WizardError> {
    let Some(committed) = bind.committed_identity.as_ref() else {
        // A signer too old to say. Nothing to compare later replies
        // against, so nothing is recorded and nothing heals.
        return Ok(());
    };
    let committed_json = serde_json::to_string(committed).unwrap_or_default();
    let uncommitted_json =
        serde_json::to_string(&bind.uncommitted_families).unwrap_or_else(|_| "[]".into());
    ctx.db
        .set_relay_identity_committed(operator_id, &committed_json, &uncommitted_json, now_unix)
        .map_err(WizardError::Db)
}

/// What the active pack commits the relay to, if the wizard knows.
pub fn committed(
    ctx: &WizardCtx,
    operator_id: i64,
) -> Result<Option<CommittedIdentity>, WizardError> {
    let stored = ctx
        .db
        .relay_identity(operator_id)
        .map_err(WizardError::Db)?;
    if stored.committed_json.is_empty() {
        return Ok(None);
    }
    Ok(serde_json::from_str(&stored.committed_json).ok())
}

// --------------------------------------------------------------------
// Noticing that the relay moved
// --------------------------------------------------------------------

const PINNED_FAMILIES: &[&str] = &["hysteria2", "naive", "websocket-tls", "tuic", "anytls"];

/// In what ways does a relay reply disagree with what the active pack
/// commits to? Empty means the pack is still true.
///
/// `record_families` gates each comparison on the pack actually having
/// a route of that family: a relay may serve something its record does
/// not carry, and no number of signatures will ever commit a route that
/// is not in the pack. An empty list means "unknown" and gates nothing.
pub fn moved(
    committed: &CommittedIdentity,
    reply: &ReplyMaterial<'_>,
    record_families: &[String],
) -> Vec<&'static str> {
    let has = |f: &str| record_families.is_empty() || record_families.iter().any(|x| x == f);
    let differs = |reply_value: &str, signed: &str| {
        let r = reply_value.trim();
        !r.is_empty() && r != signed.trim()
    };
    let mut out = Vec::new();
    if has("vless-reality") {
        if differs(reply.reality_public_key, &committed.reality_public_key) {
            out.push("reality_public_key");
        } else if !committed.reality_public_key.is_empty()
            && differs(reply.cover_sni, &committed.cover_sni)
        {
            out.push("cover_sni");
        }
    }
    if PINNED_FAMILIES.iter().any(|f| has(f))
        && differs(reply.tls_cert_sha256, &committed.tls_cert_sha256)
    {
        out.push("tls_cert_sha256");
    }
    if has("shadowsocks") {
        let key = ss_server_key(reply.ss_password);
        if !key.is_empty() && ss_server_key_digest(key) != committed.ss_server_key_sha256 {
            out.push("ss_server_key");
        }
    }
    out
}

/// Which of the keys that only a rebuild can change does the relay now
/// state differently from what the active pack commits to?
///
/// Unlike [`moved`] this is not about keeping the pack true. The
/// relay's cover host moves and its shadowsocks key appears, and the
/// wizard follows. Its REALITY key and its TLS key do neither: the
/// management API has no operation that replaces them (a disguise
/// change re-issues the certificate on the SAME key), so on a machine
/// that was not rebuilt a different one is not news to sign.
///
/// A value the pack does not commit yet is being learned, not changed,
/// and a reply that leaves a value out says nothing about it.
pub fn keys_changed_in_place(
    committed: &CommittedIdentity,
    stated_reality_public_key: &str,
    stated_tls_cert_sha256: &str,
) -> Vec<&'static str> {
    let changed = |stated: &str, signed: &str| {
        let (s, c) = (stated.trim(), signed.trim());
        !s.is_empty() && !c.is_empty() && s != c
    };
    let mut out = Vec::new();
    if changed(stated_reality_public_key, &committed.reality_public_key) {
        out.push("reality_public_key");
    }
    if changed(stated_tls_cert_sha256, &committed.tls_cert_sha256) {
        out.push("tls_cert_sha256");
    }
    out
}

/// Refuse to follow a relay whose keys changed without a rebuild.
///
/// "Without a rebuild" is read off the management certificate: the
/// record's fingerprint is the one the relay's identity was last
/// learned under. A rebuilt relay has a new one — written into the
/// record by provisioning, never by anything the relay says — and its
/// new keys are then exactly what should be signed.
///
/// Why refuse rather than sign: every relay reply is believed on that
/// one pinned certificate. If the pin is ever wrong, or the relay is
/// no longer the publisher's alone, this is the step where the damage
/// would leave this device — a signed pack, and a published note
/// telling every recipient's app to fetch it, committing the relay's
/// address to somebody else's key. A signature is the one thing the
/// wizard must not produce on a relay's say-so alone.
fn refuse_keys_changed_in_place(
    stored: &crate::operator_db::RelayIdentityRow,
    rec: &RecordView,
    stated_reality_public_key: &str,
    stated_tls_cert_sha256: &str,
) -> Result<(), WizardError> {
    let same_box = !rec.box_fingerprint.is_empty() && stored.box_fingerprint == rec.box_fingerprint;
    if !same_box {
        return Ok(());
    }
    let Ok(signed) = serde_json::from_str::<CommittedIdentity>(&stored.committed_json) else {
        return Ok(());
    };
    let changed = keys_changed_in_place(&signed, stated_reality_public_key, stated_tls_cert_sha256);
    if changed.is_empty() {
        return Ok(());
    }
    Err(coded(
        E_RELAY_KEYS_CHANGED,
        format!(
            "the relay now states a different {} than the one the signed file commits to, and it \
             has not been rebuilt. Nothing on a relay changes these except a rebuild, so the app \
             did not sign or publish anything. If you did not expect this, treat the relay as \
             compromised: rebuild it.",
            changed.join(" and ")
        ),
    ))
}

/// A digest of a reply's relay-wide fields, to remember which reply
/// the pack was already signed again for. Not a secret and not reversible to
/// one: the shadowsocks key enters only as its own digest.
fn reply_digest(reply: &ReplyMaterial<'_>) -> String {
    let key = ss_server_key(reply.ss_password);
    let ss = if key.is_empty() {
        String::new()
    } else {
        ss_server_key_digest(key)
    };
    let mut h = Sha256::new();
    for part in [
        reply.reality_public_key.trim(),
        reply.tls_cert_sha256.trim(),
        reply.cover_sni.trim(),
        ss.as_str(),
    ] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

/// After any reply from the relay: if the relay is no longer what the
/// active pack commits to, sign again (and republish the refresh note)
/// BEFORE the caller builds a file from that reply.
///
/// This is what makes the order of operations stop mattering. The first
/// recipient on a relay that serves shadowsocks is the usual trigger:
/// the pack was signed when the relay had no shadowsocks key, the reply
/// carries one, and without this the file about to be built would have
/// that route dropped — for this recipient and every later one.
///
/// `Ok(None)` is the common case: nothing moved. A failed re-sign is an
/// error, because the caller is about to build a file from a pack that
/// is known to be wrong.
///
/// It also keeps the pack's NAME true. Everyone's file is built from
/// the relay's signed pack, so the name a family sees on a new file is
/// the one the pack was signed with — for a pack signed before the
/// relay's own name went into it (or before the relay was renamed),
/// not the relay's name. When the two differ the pack is signed again
/// first, by the same path; when they agree nothing is signed. That
/// half is best effort: a pack with an old name is still a correct
/// pack, so failing to rename it never stops a file being made.
pub(crate) fn heal_after_reply(
    ctx: &WizardCtx,
    operator_id: i64,
    reply: &ReplyMaterial<'_>,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<Option<PackResigned>, WizardError> {
    if let Some(resigned) = heal_identity_after_reply(ctx, operator_id, reply, on_progress)? {
        // Signing again took the relay's current name too.
        return Ok(Some(resigned));
    }
    Ok(heal_publisher_name(ctx, operator_id, on_progress)
        .ok()
        .flatten())
}

/// The publisher name inside a signed `.sbp` (`manifest.json` →
/// `publisher.name`), or `None` when the file is missing or cannot be
/// read as a pack — which is never a reason to sign.
pub(crate) fn signed_publisher_name(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut zip = zip::ZipArchive::new(file).ok()?;
    let entry = zip.by_name("manifest.json").ok()?;
    let mut buf = Vec::new();
    // A manifest is a few KiB; never read an unbounded entry.
    entry.take(4 << 20).read_to_end(&mut buf).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&buf).ok()?;
    v.get("publisher")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// Sign again when the relay's signed pack carries a different name
/// than the relay has. Reads one small file and signs nothing when the
/// names agree, so it is cheap to run before every file.
fn heal_publisher_name(
    ctx: &WizardCtx,
    operator_id: i64,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<Option<PackResigned>, WizardError> {
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let Some(want) = crate::commands::relay_publisher_name(&row) else {
        return Ok(None);
    };
    let path = crate::freshness::default_signed_pack_path(ctx, operator_id);
    match signed_publisher_name(&path) {
        Some(have) if have != want => {
            resign_and_republish(ctx, operator_id, Freshness::Fresh, on_progress).map(Some)
        }
        _ => Ok(None),
    }
}

/// The identity half of [`heal_after_reply`].
fn heal_identity_after_reply(
    ctx: &WizardCtx,
    operator_id: i64,
    reply: &ReplyMaterial<'_>,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<Option<PackResigned>, WizardError> {
    // No signed pack: nothing to keep true. The caller's own "build the
    // relay pack first" check speaks for itself.
    if !crate::freshness::default_signed_pack_path(ctx, operator_id).exists() {
        return Ok(None);
    }
    let stored = ctx
        .db
        .relay_identity(operator_id)
        .map_err(WizardError::Db)?;
    let Some(signed) = serde_json::from_str::<CommittedIdentity>(&stored.committed_json).ok()
    else {
        return Ok(None);
    };
    let row = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let rec = record_view(&row.operator_record_json);
    // Before anything else, and on every reply (not once per distinct
    // reply, like the heal below): a key only a rebuild can change.
    refuse_keys_changed_in_place(
        &stored,
        &rec,
        reply.reality_public_key,
        reply.tls_cert_sha256,
    )?;
    if moved(&signed, reply, &rec.families).is_empty() {
        return Ok(None);
    }
    // One SIGNATURE per distinct reply. A relay the pack can never be
    // made to match must not cost a signature on every recipient.
    let digest = reply_digest(reply);
    if stored.healed_for == digest {
        return Ok(None);
    }

    // A relay that cannot state its identity is taught from this reply.
    // One that can is simply asked again by the re-sign below.
    let known_same_box =
        !rec.box_fingerprint.is_empty() && stored.box_fingerprint == rec.box_fingerprint;
    if stored.identity_source != SOURCE_RELAY || !known_same_box {
        let base = if known_same_box && stored.identity_source == SOURCE_REPLY {
            Some(stored.identity_json.as_str())
        } else {
            None
        };
        let doc = identity_from_reply(reply, base, (ctx.clock)());
        ctx.db
            .set_relay_identity_learned(
                operator_id,
                &doc,
                SOURCE_REPLY,
                &rec.box_fingerprint,
                (ctx.clock)(),
            )
            .map_err(WizardError::Db)?;
    }
    let resigned = resign_and_republish(ctx, operator_id, Freshness::Fresh, on_progress)?;
    // Remembered only now that there IS a signature for this reply. A
    // re-sign that failed (the relay could not be reached for a moment)
    // has dealt with nothing: the next reply must try again, or every
    // later file is built from a pack known to be wrong with nothing
    // saying so. A reply the pack cannot be made to match still lands
    // here, because signing for it succeeds.
    ctx.db
        .set_relay_identity_healed_for(operator_id, &digest)
        .map_err(WizardError::Db)?;
    Ok(Some(resigned))
}

/// Sign the relay's pack again from its current identity, and publish
/// the refresh note that tells people's apps there is a new one.
///
/// The signature failing is an error. The NOTE failing is not: the pack
/// is signed and correct either way, and the caller has to be able to
/// say which half happened — see [`PackResigned`].
pub(crate) fn resign_and_republish(
    ctx: &WizardCtx,
    operator_id: i64,
    freshness: Freshness,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<PackResigned, WizardError> {
    // What the files people HOLD can do, read before the new signature
    // overwrites the stamp.
    let before = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let prior_pack_had_refresh_addresses =
        !crate::freshness::parse_mirrors_json(&before.freshness_mirrors_in_pack).is_empty();

    let bind = crate::commands::sign_relaypack_with(
        ctx,
        operator_id,
        crate::phase::RELAYPACK_PHASE,
        &ctx.staging_dir,
        RESIGN_PUBLISHER_NAME,
        freshness,
        on_progress,
    )?;

    let after = ctx.db.get(operator_id).map_err(WizardError::Db)?;
    let new_pack_has_refresh_addresses =
        !crate::freshness::parse_mirrors_json(&after.freshness_mirrors_in_pack).is_empty();
    let mut out = PackResigned {
        relay_pack_id: bind.relay_pack_id.clone(),
        sbp_sha256: bind.sbp_sha256.clone(),
        signed_pack_path: crate::freshness::default_signed_pack_path(ctx, operator_id)
            .to_string_lossy()
            .to_string(),
        prior_pack_had_refresh_addresses,
        refresh_note_published: false,
        refresh_note_problem: String::new(),
        uncommitted_families: bind.uncommitted_families.clone(),
    };
    if !new_pack_has_refresh_addresses {
        return Ok(out);
    }
    match crate::freshness::publish(ctx, operator_id, on_progress) {
        Ok(report) if !report.blocked_reason.is_empty() => {
            out.refresh_note_problem = report.blocked_reason;
        }
        Ok(report) if report.succeeded < report.min_mirrors => {
            out.refresh_note_problem = format!(
                "only {} of {} required places accepted it",
                report.succeeded, report.min_mirrors
            );
        }
        Ok(_) => out.refresh_note_published = true,
        Err(e) => out.refresh_note_problem = crate::freshness::redact_detail(&e.to_string()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector `cmd/daal-relay-mgmt` and `publisher/deploy/cli` pin
    /// the same function to (TestIdentitySSDigestMatchesTheSignedEndpointRule,
    /// TestSSServerKeyDigestVector).
    #[test]
    fn ss_digest_matches_the_signed_endpoint_rule() {
        assert_eq!(
            ss_server_key_digest("AAECAwQFBgcICQoLDA0ODw=="),
            "fcdbdca159bd5651a33cf17ba64d6bcda8b6fb65929529933faf309ab580eae2"
        );
    }

    fn reply<'a>(reality: &'a str, tls: &'a str, cover: &'a str, ss: &'a str) -> ReplyMaterial<'a> {
        ReplyMaterial {
            reality_public_key: reality,
            tls_cert_sha256: tls,
            cover_sni: cover,
            ss_password: ss,
            ss_method: if ss.is_empty() {
                ""
            } else {
                "2022-blake3-aes-128-gcm"
            },
        }
    }

    fn signed() -> CommittedIdentity {
        CommittedIdentity {
            server: "1.2.3.4".into(),
            cover_sni: "a.example".into(),
            reality_public_key: "PK".into(),
            tls_cert_sha256: "PIN".into(),
            ss_method: String::new(),
            ss_server_key_sha256: String::new(),
            families: vec!["hysteria2".into(), "vless-reality".into()],
        }
    }

    #[test]
    fn a_reply_that_agrees_with_the_pack_is_not_a_move() {
        assert!(moved(&signed(), &reply("PK", "PIN", "a.example", ""), &[]).is_empty());
        // A reply that says nothing about a value does not unsay it.
        assert!(moved(&signed(), &reply("", "", "", ""), &[]).is_empty());
    }

    #[test]
    fn the_first_shadowsocks_key_is_a_move() {
        let r = reply("PK", "PIN", "a.example", "SERVERKEY:USERKEY");
        assert_eq!(moved(&signed(), &r, &[]), vec!["ss_server_key"]);
        // …and stops being one once the pack commits that key.
        let mut s = signed();
        s.ss_server_key_sha256 = ss_server_key_digest("SERVERKEY");
        assert!(moved(&s, &r, &[]).is_empty());
        // A different recipient's password has the SAME server half.
        assert!(moved(
            &s,
            &reply("PK", "PIN", "a.example", "SERVERKEY:OTHERUSER"),
            &[]
        )
        .is_empty());
    }

    #[test]
    fn a_moved_cover_host_or_key_is_a_move() {
        assert_eq!(
            moved(&signed(), &reply("PK", "PIN", "b.example", ""), &[]),
            vec!["cover_sni"]
        );
        assert_eq!(
            moved(&signed(), &reply("PK2", "PIN2", "a.example", ""), &[]),
            vec!["reality_public_key", "tls_cert_sha256"]
        );
    }

    /// Keys only a rebuild can change. Learning one the pack does not
    /// have yet is not a change, silence is not a change, and neither a
    /// cover host nor a shadowsocks key is one of them.
    #[test]
    fn only_a_committed_key_stated_differently_is_a_key_changed_in_place() {
        let s = signed();
        assert!(keys_changed_in_place(&s, "PK", "PIN").is_empty());
        assert!(keys_changed_in_place(&s, " PK\n", "").is_empty());
        assert!(keys_changed_in_place(&s, "", "").is_empty());
        assert_eq!(keys_changed_in_place(&s, "PK2", "PIN"), vec!["reality_public_key"]);
        assert_eq!(keys_changed_in_place(&s, "PK", "PIN2"), vec!["tls_cert_sha256"]);
        assert_eq!(
            keys_changed_in_place(&s, "PK2", "PIN2"),
            vec!["reality_public_key", "tls_cert_sha256"]
        );
        let mut unsigned = signed();
        unsigned.reality_public_key.clear();
        unsigned.tls_cert_sha256.clear();
        assert!(keys_changed_in_place(&unsigned, "PK", "PIN").is_empty());
    }

    /// A relay may serve a family the pack has no route for. Signing
    /// again cannot commit a route that is not there, so it is not a
    /// reason to sign again.
    #[test]
    fn a_family_the_pack_does_not_carry_is_not_a_move() {
        let fams = vec!["vless-reality".to_string(), "hysteria2".to_string()];
        let r = reply("PK", "PIN", "a.example", "SERVERKEY:USERKEY");
        assert!(moved(&signed(), &r, &fams).is_empty());
        let fams = vec!["vless-reality".to_string(), "shadowsocks".to_string()];
        assert_eq!(moved(&signed(), &r, &fams), vec!["ss_server_key"]);
    }

    #[test]
    fn an_identity_derived_from_a_reply_never_carries_the_key() {
        let r = reply("PK", "PIN", "a.example", "SERVERKEY:USERKEY");
        let doc = identity_from_reply(&r, None, 7);
        assert!(
            !doc.contains("SERVERKEY") && !doc.contains("USERKEY"),
            "{doc}"
        );
        let v: serde_json::Value = serde_json::from_str(&doc).unwrap();
        assert_eq!(v["identity_version"], 1);
        assert_eq!(v["reality_public_key"], "PK");
        assert_eq!(v["tls_cert_sha256"], "PIN");
        assert_eq!(v["cover_sni"], "a.example");
        assert_eq!(v["ss_method"], "2022-blake3-aes-128-gcm");
        assert_eq!(v["ss_server_key_sha256"], ss_server_key_digest("SERVERKEY"));

        // A later reply with no shadowsocks row keeps what was learned.
        let later = reply("PK", "PIN", "a.example", "");
        let doc2 = identity_from_reply(&later, Some(&doc), 8);
        let v2: serde_json::Value = serde_json::from_str(&doc2).unwrap();
        assert_eq!(
            v2["ss_server_key_sha256"],
            ss_server_key_digest("SERVERKEY")
        );
        // And a method never travels without its digest.
        let lone = ReplyMaterial {
            ss_method: "2022-blake3-aes-128-gcm",
            ..reply("PK", "PIN", "a.example", "")
        };
        let v3: serde_json::Value =
            serde_json::from_str(&identity_from_reply(&lone, None, 9)).unwrap();
        assert!(v3.get("ss_method").is_none() && v3.get("ss_server_key_sha256").is_none());
    }
}
