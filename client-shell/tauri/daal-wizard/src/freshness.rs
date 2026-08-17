//! Wave 3 Step 8 — the publisher-app half of remote pack replacement.
//!
//! # What this is for
//!
//! Every rung of the rotation ladder used to end the same way: the
//! publisher hand-delivers a file to every recipient. Under the exact
//! conditions a rotation is *for* — a blackout, a burned address —
//! hand delivery is the thing that does not work. A freshness document
//! is the way out: a small signed JSON blob on ordinary static hosting
//! that says "the pack you are holding has been replaced; here is the
//! digest of the new one". The recipient's fetcher
//! (`core/refresh/relaypack.go`) verifies it against the publisher root
//! key (or the FRP-7.5 sub-key chain) and swaps the pack with nobody
//! touching a phone.
//!
//! # Division of labour — read this before adding an uploader here
//!
//! The document is built, signed and **uploaded** by
//! `daal-deploy publish-freshness`. The R2 SigV4 signer
//! (`publisher/deploy/freshness/backends/r2`), the GitHub Pages
//! contents-API uploader, and `freshness.PublishAll`'s
//! "fewer-than-MinMirrors is a failure" rule all live there and are
//! tested there.
//!
//! **This module deliberately contains no HTTP client and no SigV4.**
//! An earlier draft of this file carried a full Rust SigV4
//! implementation plus a rustls HTTP client; it was deleted rather than
//! shipped. Two implementations of one wire format is how a signature
//! mismatch becomes an opaque 403 during the one hour a publisher
//! cannot afford to debug, and a second TLS stack with a second root
//! store in a censorship tool is a liability, not redundancy.
//!
//! What is genuinely this side's problem, and is therefore what this
//! module does:
//!
//!   1. **Custody.** An R2 secret access key and a GitHub PAT are cloud
//!      WRITE credentials — whoever holds one can replace the document
//!      every recipient trusts. They belong in [`DeviceCustody`]
//!      alongside the publisher's signing key, never in the operator
//!      record (which is a plaintext JSON blob copied into staging
//!      files on every rotation) and never in a log line or a progress
//!      event. The CLI takes them only as `--…-file` paths, so this
//!      module is the thing that decrypts from custody, writes a
//!      mode-0600 tempfile, and wipes + unlinks it in every exit path
//!      including the failure ones. That is the same treatment the
//!      Ed25519 signing key already gets on this route.
//!   2. **Configuration.** Which providers this publisher holds
//!      accounts with. The CLI is stateless; the operator's answer has
//!      to be stored somewhere and this app is the only thing with a
//!      database.
//!   3. **The honesty ledger.** What actually happened on the last
//!      publish, per provider, from a real result rather than from
//!      "we tried". See [`FreshnessEndpointSummary::last_publish_ok`].
//!
//! # Why N endpoints, and why the count is of PROVIDERS
//!
//! A freshness URL is a fixed URL baked into a signed pack. It has the
//! same shelf life as any other fixed endpoint and arguably shorter: it
//! is small, unique and pollable, and a censor who obtains one
//! recipient's pack has the URL every other recipient of that publisher
//! will poll. One endpoint is a countdown, not a design.
//!
//! So the publisher configures several, and the unit of independence is
//! the *provider*, not the row: two R2 buckets in one Cloudflare
//! account die together the day Cloudflare is nationally blocked. This
//! module enforces one endpoint per provider (`UNIQUE(operator_id,
//! kind)` in V013) so the count the UI shows cannot be inflated by
//! adding a second bucket. `freshness.MinMirrors` (2) is mirrored here
//! as [`MIN_MIRRORS`]; below it, packs are signed with no freshness
//! path at all rather than with a single point of failure, and the UI
//! says exactly that.
//!
//! # What an observer learns from a freshness fetch
//!
//! Honest accounting, because the answer is "more than nothing", and
//! the UI copy is written from this list:
//!
//!   * **Cadence.** The fetch is scheduler-driven, so a network
//!     observer sees a periodic small HTTPS GET to a static host. The
//!     rhythm is the fingerprint; the payload is not.
//!   * **Correlation — the real cost.** Every recipient of one
//!     publisher polls the same URLs. An observer with server-side or
//!     provider-side visibility can therefore enumerate that
//!     publisher's readership by source IP. Nothing at this layer
//!     removes that. It is why the guidance in the UI is to point the
//!     mirrors at a host that serves other traffic — a Pages site with
//!     a real site on it, a CDN path in front of an ordinary domain —
//!     rather than a bespoke bucket hostname whose only visitors are
//!     Daal recipients.
//!   * **Size and change.** The document is a few hundred bytes and
//!     changes only when a rotation happens, so object size or ETag
//!     movement leaks "a rotation happened" to a passive observer
//!     without breaking TLS. That is a leak about the publisher, not
//!     about any recipient.
//!   * **Interaction with fail-closed refresh.** Wave 1 made refresh
//!     fail closed while a tunnel is up: the device does not fetch a
//!     freshness document through the tunnel it is trying to repair.
//!     In practice the GET therefore happens on the bare network. That
//!     is what makes the correlation above visible to the local ISP —
//!     and it is also the only reason the mechanism works at all when
//!     the tunnel is already dead, which is the case it exists for.
//!     Both halves are real and the UI states both.
//!
//! When every mirror is blocked, the layer below is the
//! bootstrap-pointer envelope (`core/bootstrap/pointer_rotation.go`),
//! not a hard-coded host. Nothing in this module hard-codes a hostname.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::cli_bridge::{FreshnessUploadArgs, ProgressEvent, PublishFreshnessArgs};
use crate::commands::{custody_get_string, custody_put, Result, WizardCtx, WizardError};
use crate::operator_db::FreshnessEndpointRow;

/// Mirrors `publisher/deploy/freshness.MinMirrors`. Two is not
/// "enough"; it is the smallest number for which the word "fallback"
/// means anything. Kept in sync by
/// `min_mirrors_matches_the_go_contract` below, which fails loudly if
/// the Go constant moves — the two are a contract, not a coincidence.
pub const MIN_MIRRORS: usize = 2;

/// Mirrors `publisher/deploy/freshness.MaxSupersedes`: how many prior
/// relay_pack_ids one document may claim to succeed.
///
/// The list is what lets a rotation reach recipients at all — the pack
/// id is derived from provider|server_id|region|public_ip|families, so
/// every rung above L2 renames the pack, and a recipient matching on
/// the id it holds would otherwise reject the document that repairs it.
/// A recipient more than this many rotations behind is months stale and
/// is past what a freshness document can fix; it falls through to the
/// bootstrap-pointer layer.
pub const MAX_SUPERSEDES: i64 = 16;

/// Provider labels this build knows how to upload to. The label must
/// match the one the pack's MirrorSet uses, or recipients poll a URL
/// nobody writes to.
pub const KIND_R2: &str = "r2";
pub const KIND_GHPAGES: &str = "ghpages";

/// What the operator fills in to add one endpoint. Credentials are in
/// this struct only on the way *in*; they are moved into custody and
/// zeroed before it is dropped, and no field of it is ever persisted
/// or serialised back to the UI.
/// `serde(default)` is load-bearing, not tidiness: the UI sends only
/// the fields the chosen provider needs, so a missing `gh_owner` on an
/// R2 form must deserialise to "" rather than failing the whole IPC
/// call with `missing field`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FreshnessEndpointInput {
    /// "r2" | "ghpages".
    pub kind: String,
    /// Recipient-facing HTTPS URL of the freshness document itself.
    pub public_url: String,
    // --- r2 ---
    pub account_id: String,
    pub bucket: String,
    pub object_key: String,
    pub access_key_id: String,
    /// R2 S3-compatible secret access key. Goes straight to custody.
    pub secret_access_key: String,
    // --- ghpages ---
    pub gh_owner: String,
    pub gh_repo: String,
    pub gh_path: String,
    pub gh_branch: String,
    /// Fine-grained PAT with Contents: Read+Write. Goes to custody.
    pub gh_pat: String,
}

/// One configured endpoint as the UI sees it. Contains no credential
/// and never can: the credential's only representation here is the
/// boolean [`Self::has_credential`], derived from a custody probe.
#[derive(Debug, Clone, Serialize)]
pub struct FreshnessEndpointSummary {
    pub id: i64,
    pub kind: String,
    pub public_url: String,
    /// Human-readable target, e.g. "bucket/key" or "owner/repo@branch".
    /// Enough for the operator to tell two endpoints apart without
    /// exposing anything that is not already in the public URL.
    pub target: String,
    pub has_credential: bool,
    /// 0 = never published. Rendered as "never published", never as
    /// "fine".
    pub last_publish_at_unix: i64,
    /// True ONLY when the provider returned success for this endpoint
    /// on the last attempt. This is the single field the UI may use to
    /// claim a publish worked.
    pub last_publish_ok: bool,
    /// The provider's own words on the last failure ("Bad credentials",
    /// "SignatureDoesNotMatch"). Shown verbatim: paraphrasing it into
    /// something friendly is how a publisher spends an hour on a typo.
    pub last_publish_detail: String,
    pub last_published_url: String,
}

/// Everything the freshness panel needs in one call.
#[derive(Debug, Clone, Serialize)]
pub struct FreshnessStatus {
    pub endpoints: Vec<FreshnessEndpointSummary>,
    /// Distinct provider count — NOT `endpoints.len()`. This is the
    /// number the "single point of censorship" warning is computed
    /// from.
    pub distinct_providers: i64,
    pub min_mirrors: i64,
    /// URL where the re-signed `.sbp` itself will be downloadable. The
    /// freshness document points at it, so without it there is nothing
    /// to point at and no document can be built.
    pub pack_url: String,
    /// The mirror list that is baked into the pack recipients are
    /// holding RIGHT NOW, as "provider=url" strings. Empty means the
    /// distributed packs have no refresh path — which is true of every
    /// pack signed before this feature existed, and is the difference
    /// between a rotation that heals itself and one that needs a
    /// courier. Never inferred from `endpoints`: configuring a mirror
    /// today does not change a bundle somebody imported last month.
    pub mirrors_in_pack: Vec<String>,
    /// Unix seconds of the signature on the pack described by
    /// `mirrors_in_pack`. Lets the UI say "anything you handed out
    /// before <date> will not repair itself".
    pub pack_signed_at_unix: i64,
}

/// Custody alias for one endpoint's credential blob.
///
/// Keyed by endpoint id, so deleting an endpoint can forget exactly one
/// secret and rotating a credential overwrites in place. The blob is
/// JSON rather than a bare string because R2 needs a pair
/// (access-key-id + secret) and the id half is credential material too:
/// it must not sit in SQLite where a backup would carry it.
pub fn endpoint_alias(endpoint_id: i64) -> String {
    format!("daal.freshness.{endpoint_id}.cred")
}

/// The credential shapes stored under [`endpoint_alias`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredCredential {
    #[serde(default)]
    access_key_id: String,
    #[serde(default)]
    secret_access_key: String,
    #[serde(default)]
    pat: String,
}

fn trimmed(s: &str) -> &str {
    s.trim()
}

fn require(value: &str, label: &str) -> Result<String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(WizardError::Pricing(format!("freshness: {label} required")));
    }
    Ok(v.to_string())
}

fn require_https(value: &str, label: &str) -> Result<String> {
    let v = require(value, label)?;
    if !v.starts_with("https://") {
        return Err(WizardError::Pricing(format!(
            "freshness: {label} must be an https:// URL — a plaintext endpoint lets anyone on the path replace the document"
        )));
    }
    Ok(v.trim_end_matches('/').to_string())
}

/// Add one endpoint. The credential is moved into custody before the
/// row is written, so a custody failure cannot leave a configured
/// endpoint with no key behind it.
pub fn add_endpoint(
    ctx: &WizardCtx,
    operator_id: i64,
    mut input: FreshnessEndpointInput,
) -> Result<i64> {
    // Confirm the relay exists before minting anything bound to it.
    let _ = ctx.db.get(operator_id)?;

    let kind = trimmed(&input.kind).to_ascii_lowercase();
    if kind != KIND_R2 && kind != KIND_GHPAGES {
        return Err(WizardError::Pricing(format!(
            "freshness: unknown provider {kind:?}"
        )));
    }
    // One endpoint per provider. A second bucket at the same provider
    // would inflate the count the "single point of censorship" warning
    // is computed from while adding no independence at all.
    if ctx
        .db
        .list_freshness_endpoints(operator_id)?
        .iter()
        .any(|e| e.kind == kind)
    {
        return Err(WizardError::Pricing(format!(
            "freshness: this relay already has a {kind} endpoint — replace it instead of adding a second one at the same provider"
        )));
    }

    let public_url = require_https(&input.public_url, "public URL")?;

    let (row_id, cred) = match kind.as_str() {
        KIND_R2 => {
            let account_id = require(&input.account_id, "account id")?;
            let bucket = require(&input.bucket, "bucket")?;
            let object_key = require(&input.object_key, "object key")?;
            let access_key_id = require(&input.access_key_id, "access key id")?;
            let secret = require(&input.secret_access_key, "secret access key")?;
            let id = ctx.db.insert_freshness_endpoint(
                operator_id,
                &kind,
                &public_url,
                &account_id,
                &bucket,
                &object_key,
                "",
                "",
                "",
                "",
                "", // secret_alias patched below, once the id exists
                (ctx.clock)(),
            )?;
            (
                id,
                StoredCredential {
                    access_key_id,
                    secret_access_key: secret,
                    pat: String::new(),
                },
            )
        }
        _ => {
            let owner = require(&input.gh_owner, "repository owner")?;
            let repo = require(&input.gh_repo, "repository name")?;
            let path = require(&input.gh_path, "path in the repository")?;
            let branch = {
                let b = trimmed(&input.gh_branch);
                if b.is_empty() {
                    "main".to_string()
                } else {
                    b.to_string()
                }
            };
            let pat = require(&input.gh_pat, "access token")?;
            let id = ctx.db.insert_freshness_endpoint(
                operator_id,
                &kind,
                &public_url,
                "",
                "",
                "",
                &owner,
                &repo,
                &path,
                &branch,
                "",
                (ctx.clock)(),
            )?;
            (
                id,
                StoredCredential {
                    access_key_id: String::new(),
                    secret_access_key: String::new(),
                    pat,
                },
            )
        }
    };

    let alias = endpoint_alias(row_id);
    let mut blob = serde_json::to_vec(&cred).map_err(|e| {
        WizardError::Pricing(format!("freshness: encode credential: {e}"))
    })?;
    let put = custody_put(ctx, &alias, &blob);
    blob.zeroize();
    // Wipe the caller's copy too: this struct came over the Tauri IPC
    // boundary and would otherwise sit in freed heap.
    input.secret_access_key.zeroize();
    input.gh_pat.zeroize();
    if let Err(e) = put {
        // Custody refused. Do not leave a configured endpoint with no
        // key behind it — the operator would see a green row that can
        // never publish.
        let _ = ctx.db.delete_freshness_endpoint(row_id);
        return Err(e);
    }
    ctx.db.set_freshness_endpoint_alias(row_id, &alias)?;
    Ok(row_id)
}

/// Delete one endpoint and forget its credential.
///
/// Forgetting is not optional. A deleted endpoint whose cloud
/// write-key is still in the keystore is a live credential nobody is
/// watching, on an account the operator has stopped thinking about.
pub fn delete_endpoint(ctx: &WizardCtx, endpoint_id: i64) -> Result<()> {
    let alias = ctx.db.delete_freshness_endpoint(endpoint_id)?;
    if !alias.is_empty() {
        ctx.custody.forget(&alias).ok();
    }
    Ok(())
}

/// Set the URL where the signed `.sbp` will be downloadable.
///
/// The freshness document's whole payload is "the pack changed, fetch
/// it here", so this is required before anything can be published. It
/// is a separate answer from the mirror URLs because the pack and the
/// document are different objects with different sizes and different
/// change rates; a publisher may well host the pack on a CDN and the
/// document on two static hosts.
pub fn set_pack_url(ctx: &WizardCtx, operator_id: i64, url: &str) -> Result<()> {
    let trimmed_url = url.trim();
    let normalised = if trimmed_url.is_empty() {
        String::new()
    } else {
        require_https(trimmed_url, "pack URL")?
    };
    ctx.db.set_freshness_pack_url(operator_id, &normalised)?;
    Ok(())
}

/// Read the freshness panel's whole state.
pub fn status(ctx: &WizardCtx, operator_id: i64) -> Result<FreshnessStatus> {
    let row = ctx.db.get(operator_id)?;
    let rows = ctx.db.list_freshness_endpoints(operator_id)?;
    let mut kinds: Vec<&str> = rows.iter().map(|r| r.kind.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let endpoints = rows
        .iter()
        .map(|r| FreshnessEndpointSummary {
            id: r.id,
            kind: r.kind.clone(),
            public_url: r.public_base_url.clone(),
            target: describe_target(r),
            // A probe, not an assumption: an endpoint whose credential
            // was wiped by a custody reset must not look ready.
            has_credential: ctx.custody.get(&r.secret_alias).is_ok(),
            last_publish_at_unix: r.last_publish_at_unix,
            last_publish_ok: r.last_publish_ok,
            last_publish_detail: r.last_publish_detail.clone(),
            last_published_url: r.last_published_url.clone(),
        })
        .collect();
    Ok(FreshnessStatus {
        endpoints,
        distinct_providers: kinds.len() as i64,
        min_mirrors: MIN_MIRRORS as i64,
        pack_url: row.freshness_pack_url.clone(),
        mirrors_in_pack: parse_mirrors(&row.freshness_mirrors_in_pack),
        pack_signed_at_unix: row.signed_sbp_at_unix.unwrap_or(0),
    })
}

fn describe_target(r: &FreshnessEndpointRow) -> String {
    if r.kind == KIND_R2 {
        format!("{}/{}", r.bucket, r.key_prefix)
    } else {
        format!("{}/{}@{}", r.gh_owner, r.gh_repo, r.gh_branch)
    }
}

/// Public alias so `rotate_execute` can ask "does the pack recipients
/// hold actually carry mirrors?" without duplicating the parse.
pub fn parse_mirrors_json(json: &str) -> Vec<String> {
    parse_mirrors(json)
}

fn parse_mirrors(json: &str) -> Vec<String> {
    if json.trim().is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

/// The `provider=url` arguments `bind-and-sign --freshness-mirror`
/// takes, in configured order.
///
/// Returns EMPTY when fewer than [`MIN_MIRRORS`] distinct providers are
/// configured. That is deliberate and it is the whole no-single-URL
/// contract in one branch: a pack with no freshness path is a pack that
/// needs a courier, which is bad; a pack with ONE freshness URL is a
/// pack whose recovery mechanism a censor turns off with one DNS entry
/// while the publisher believes it is covered, which is worse. The Go
/// side refuses the same shape (`NewMirrorSet`), so this is a
/// fail-early copy of a rule that is enforced twice on purpose.
pub fn mirror_args(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<String>> {
    let rows = ctx.db.list_freshness_endpoints(operator_id)?;
    let mut kinds: Vec<&str> = rows.iter().map(|r| r.kind.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.len() < MIN_MIRRORS {
        return Ok(Vec::new());
    }
    Ok(rows
        .iter()
        .map(|r| format!("{}={}", r.kind, r.public_base_url))
        .collect())
}

/// One provider's outcome, as returned to the UI after a publish.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PublishOutcome {
    pub endpoint_id: i64,
    pub kind: String,
    pub url: String,
    pub ok: bool,
    pub detail: String,
}

/// The result of one publish run.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PublishReport {
    pub results: Vec<PublishOutcome>,
    /// How many providers accepted the write. The UI compares this to
    /// `min_mirrors`; it does not compute "success" any other way.
    pub succeeded: i64,
    pub min_mirrors: i64,
    /// The document's monotonic sequence, echoed from the CLI. Shown so
    /// an operator can tell a re-publish from a no-op.
    pub sequence: u64,
    /// RFC3339 instant after which recipients stop trusting this
    /// document. Shown so an operator can see how long they have before
    /// a silent publish failure becomes a visible outage.
    pub not_after: String,
    /// Present when the run could not even be attempted (no pack URL,
    /// too few providers, custody locked). Empty when the CLI ran, even
    /// if every mirror failed — those failures are in `results`.
    pub blocked_reason: String,
}

/// Publish the current pack's freshness document to every configured
/// mirror.
///
/// The credential handling is the reason this function is long. Each
/// secret is decrypted from custody, written to a mode-0600 file inside
/// the staging directory, passed to the CLI by path, then overwritten
/// with zeroes and unlinked — on the error paths as well as the happy
/// one, which is why the cleanup is a closure run before every return
/// rather than a line at the bottom.
pub fn publish(
    ctx: &WizardCtx,
    operator_id: i64,
    on_progress: &mut dyn FnMut(ProgressEvent),
) -> Result<PublishReport> {
    let row = ctx.db.get(operator_id)?;
    let mut report = PublishReport {
        min_mirrors: MIN_MIRRORS as i64,
        ..Default::default()
    };

    // Blocked-before-we-start cases. Each returns a report rather than
    // an error so the UI can render the specific missing thing next to
    // the field that fixes it, instead of a red toast.
    let relay_pack_id = match row.signed_sbp_relay_pack_id.clone() {
        Some(v) if !v.is_empty() => v,
        _ => {
            report.blocked_reason = "no_signed_pack".into();
            return Ok(report);
        }
    };
    let bundle_sha = match row.signed_sbp_sha256.clone() {
        Some(v) if !v.is_empty() => v,
        _ => {
            report.blocked_reason = "no_signed_pack".into();
            return Ok(report);
        }
    };
    if row.freshness_pack_url.is_empty() {
        report.blocked_reason = "no_pack_url".into();
        return Ok(report);
    }
    let endpoints = ctx.db.list_freshness_endpoints(operator_id)?;
    let mut kinds: Vec<&str> = endpoints.iter().map(|e| e.kind.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.len() < MIN_MIRRORS {
        report.blocked_reason = "too_few_providers".into();
        return Ok(report);
    }

    std::fs::create_dir_all(&ctx.staging_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir staging: {e}")))?;
    let secret_dir = ctx.staging_dir.join(format!("freshness.{operator_id}"));
    std::fs::create_dir_all(&secret_dir)
        .map_err(|e| WizardError::Pricing(format!("mkdir freshness staging: {e}")))?;

    // Every path written below is wiped by `cleanup`, including on the
    // early returns.
    let mut scratch: Vec<PathBuf> = Vec::new();
    let cleanup = |paths: &[PathBuf], dir: &Path| {
        for p in paths {
            wipe_file(p);
        }
        let _ = std::fs::remove_dir(dir);
    };

    // 1. The signing key: publisher root, or the active sub-key.
    let active_subkey = match ctx.db.active_subkey(operator_id) {
        Ok(v) => v,
        Err(e) => {
            cleanup(&scratch, &secret_dir);
            return Err(e.into());
        }
    };
    let subkey_cert_path = active_subkey
        .as_ref()
        .map(|s| PathBuf::from(s.subkey_cert_path.clone()));
    let priv_path = secret_dir.join("priv.bin");
    let priv_bytes = match &active_subkey {
        Some(s) => std::fs::read(&s.subkey_priv_path).map_err(|e| {
            WizardError::Pricing(format!("read sub-key priv {}: {e}", s.subkey_priv_path))
        }),
        None => crate::commands::custody_get(ctx, &row.publisher_priv_keystore_alias)
            .map(|z| z.to_vec()),
    };
    let mut priv_bytes = match priv_bytes {
        Ok(b) => b,
        Err(e) => {
            cleanup(&scratch, &secret_dir);
            return Err(e);
        }
    };
    let wrote = write_secret_file(&priv_path, &priv_bytes);
    priv_bytes.zeroize();
    if let Err(e) = wrote {
        cleanup(&scratch, &secret_dir);
        return Err(e);
    }
    scratch.push(priv_path.clone());

    // 2. Per-provider routing + credential files.
    let mut upload = FreshnessUploadArgs::default();
    for ep in &endpoints {
        let cred = match read_credential(ctx, &ep.secret_alias) {
            Ok(c) => c,
            Err(e) => {
                cleanup(&scratch, &secret_dir);
                return Err(e);
            }
        };
        match ep.kind.as_str() {
            KIND_R2 => {
                let path = secret_dir.join(format!("r2.{}.secret", ep.id));
                if let Err(e) = write_secret_file(&path, cred.secret_access_key.as_bytes()) {
                    cleanup(&scratch, &secret_dir);
                    return Err(e);
                }
                scratch.push(path.clone());
                upload.r2_account = ep.account_id.clone();
                upload.r2_bucket = ep.bucket.clone();
                upload.r2_object_key = ep.key_prefix.clone();
                upload.r2_public_url = ep.public_base_url.clone();
                upload.r2_access_key_id = cred.access_key_id.clone();
                upload.r2_secret_file = Some(path);
            }
            KIND_GHPAGES => {
                let path = secret_dir.join(format!("gh.{}.pat", ep.id));
                if let Err(e) = write_secret_file(&path, cred.pat.as_bytes()) {
                    cleanup(&scratch, &secret_dir);
                    return Err(e);
                }
                scratch.push(path.clone());
                upload.gh_owner = ep.gh_owner.clone();
                upload.gh_repo = ep.gh_repo.clone();
                upload.gh_path = ep.gh_path_prefix.clone();
                upload.gh_branch = ep.gh_branch.clone();
                upload.gh_public_url = ep.public_base_url.clone();
                upload.gh_pat_file = Some(path);
            }
            other => {
                cleanup(&scratch, &secret_dir);
                return Err(WizardError::Pricing(format!(
                    "freshness: no uploader for provider {other}"
                )));
            }
        }
    }

    let mirrors: Vec<String> = endpoints
        .iter()
        .map(|e| format!("{}={}", e.kind, e.public_base_url))
        .collect();
    let out_file = ctx
        .staging_dir
        .join(format!("freshness.{operator_id}.json"));

    on_progress(ProgressEvent {
        step: "publish_freshness_start".into(),
        message: format!("relay_pack_id={relay_pack_id} mirrors={}", mirrors.len()),
        ts: String::new(),
        extra: Default::default(),
    });

    let now = (ctx.clock)();

    // THE SEQUENCE. max(stored + 1, now) — the clock when it is ahead,
    // the counter when it is not.
    //
    // Deriving it from the clock alone is what the CLI used to do, and
    // it is correct only while the clock moves forward. After an NTP
    // correction on a machine with a dead RTC, a restored VM snapshot,
    // or a second laptop that lags, the derived value lands BELOW the
    // high-water mark every already-provisioned recipient has persisted
    // — and then they reject every document, on every mirror, every
    // five minutes, until wall time catches up, while this screen shows
    // a green two-mirror publish. --min-sequence makes the CLI refuse
    // rather than upload one of those.
    let last_sequence = row.freshness_last_sequence.max(0) as u64;
    let sequence = std::cmp::max(last_sequence.saturating_add(1), now.max(0) as u64);

    // The ids this pack replaces. The pack id is a hash of the fields
    // the rotation ladder changes, so without these the document is
    // addressed to a name no recipient of the PREVIOUS pack answers to
    // and the whole channel is inert for exactly the rungs it exists
    // for. MaxSupersedes on the CLI side bounds the list; we hand it
    // newest-first so the truncation keeps the recipients most likely
    // to still be out there.
    let supersedes = ctx
        .db
        .prior_relay_pack_ids(operator_id, &relay_pack_id, MAX_SUPERSEDES)
        .unwrap_or_default();

    let res = ctx.cli.run_publish_freshness(PublishFreshnessArgs {
        relay_pack_id: &relay_pack_id,
        current_bundle_sha256: &bundle_sha,
        current_signed_url: &row.freshness_pack_url,
        publisher_pub_hex: &row.publisher_pub_hex,
        root_priv_path: if subkey_cert_path.is_some() {
            None
        } else {
            Some(&priv_path)
        },
        subkey_priv_path: if subkey_cert_path.is_some() {
            Some(&priv_path)
        } else {
            None
        },
        subkey_cert_path: subkey_cert_path.as_deref(),
        out_file: Some(&out_file),
        now_unix: now,
        sequence,
        min_sequence: last_sequence,
        supersedes: &supersedes,
        mirrors: &mirrors,
        upload: &upload,
    });
    // Wipe before inspecting the result: a failure path must not be
    // able to skip this.
    cleanup(&scratch, &secret_dir);

    // A non-zero exit is how the CLI reports "fewer mirrors accepted
    // the write than the contract requires". That is a real result the
    // operator must see per-provider, not an error to swallow — but the
    // CLI writes the detail to stderr and the JSON to stdout, and on a
    // non-zero exit the bridge only hands back stderr. So a hard
    // failure is surfaced with whatever the CLI said, and the ledger
    // rows are marked failed so the panel does not keep showing an old
    // green tick.
    let res = match res {
        Ok(r) => r,
        Err(e) => {
            let detail = redact_detail(&e.to_string());
            for ep in &endpoints {
                ctx.db
                    .record_freshness_publish(ep.id, now, false, 0, &detail, "")?;
                report.results.push(PublishOutcome {
                    endpoint_id: ep.id,
                    kind: ep.kind.clone(),
                    url: ep.public_base_url.clone(),
                    ok: false,
                    detail: detail.clone(),
                });
            }
            on_progress(ProgressEvent {
                step: "publish_freshness_failed".into(),
                message: detail,
                ts: String::new(),
                extra: Default::default(),
            });
            return Ok(report);
        }
    };

    // Fold the CLI's per-provider results into the ledger. Matching is
    // by provider label, which is exactly the label the pack's mirror
    // set uses — if it did not match, recipients would be polling a URL
    // nobody writes to, so a mismatch here is a bug worth surfacing
    // rather than papering over with positional matching.
    for ep in &endpoints {
        let found = res.published.iter().find(|p| p.provider == ep.kind);
        let (ok, detail, url) = match found {
            Some(p) => (
                p.ok,
                redact_detail(&p.error),
                if p.ok { p.url.clone() } else { String::new() },
            ),
            None => (
                false,
                "the publisher tool did not report a result for this provider".to_string(),
                String::new(),
            ),
        };
        ctx.db
            .record_freshness_publish(ep.id, now, ok, 0, &detail, &url)?;
        if ok {
            report.succeeded += 1;
        }
        report.results.push(PublishOutcome {
            endpoint_id: ep.id,
            kind: ep.kind.clone(),
            url: ep.public_base_url.clone(),
            ok,
            detail,
        });
    }
    report.sequence = res.sequence;
    report.not_after = res.not_after.clone();
    // Persist the counter BEFORE reporting success, and regardless of
    // how many mirrors accepted the write: the document exists and is
    // signed, so a recipient may already have fetched it from the one
    // mirror that did work. Re-using the value later would mint a
    // second document at the same sequence naming a different bundle,
    // which recipients refuse as a replay — correctly, and invisibly to
    // this side.
    if res.sequence > 0 {
        ctx.db
            .record_freshness_sequence(operator_id, res.sequence.min(i64::MAX as u64) as i64)?;
    }

    on_progress(ProgressEvent {
        step: "publish_freshness_done".into(),
        message: format!("{}/{} mirrors", report.succeeded, endpoints.len()),
        ts: String::new(),
        extra: Default::default(),
    });
    Ok(report)
}

fn read_credential(ctx: &WizardCtx, alias: &str) -> Result<StoredCredential> {
    let blob = custody_get_string(ctx, alias)?;
    serde_json::from_str::<StoredCredential>(&blob).map_err(|e| {
        WizardError::Pricing(format!("freshness: stored credential is unreadable: {e}"))
    })
}

/// Write `bytes` to `path` at mode 0600.
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .map_err(|e| WizardError::Pricing(format!("write credential tempfile: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Overwrite a file's bytes with zeroes, then unlink it.
///
/// The overwrite is not a guarantee on a journalling or copy-on-write
/// filesystem and is not claimed to be one. It is the same
/// best-effort the publisher signing key already gets on this route,
/// and it closes the case that actually happens: the file surviving in
/// the staging directory after a crash.
fn wipe_file(path: &Path) {
    if let Ok(len) = std::fs::metadata(path).map(|m| m.len()) {
        let _ = std::fs::write(path, vec![0u8; len as usize]);
    }
    let _ = std::fs::remove_file(path);
}

/// Scrub credential-shaped lines out of anything about to be shown or
/// stored.
///
/// Belt-and-braces: nothing here deliberately puts a secret into an
/// error. But subprocess stderr quotes the command that failed, and
/// `last_publish_detail` is a SQLite column — the one place a
/// publisher's cloud write-key could come to rest in plaintext.
pub fn redact_detail(s: &str) -> String {
    let mut out = String::new();
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("authorization")
            || lower.contains("aws4-hmac")
            || lower.contains("bearer ")
            || lower.contains("secret")
            || lower.contains("--gh-pat")
        {
            out.push_str("[redacted]");
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    let trimmed_out = out.trim().to_string();
    if trimmed_out.len() > 400 {
        trimmed_out[..400].to_string()
    } else {
        trimmed_out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MIN_MIRRORS is a copy of a Go constant. If somebody lowers
    /// `freshness.MinMirrors` to 1 to make a demo work, this is the
    /// test that has to be deleted first — which is the point.
    #[test]
    fn min_mirrors_matches_the_go_contract() {
        let go = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../publisher/deploy/freshness/mirrors.go"
        ));
        let Ok(src) = go else {
            // The Go tree is not always present next to a packaged
            // build; skipping is correct, asserting nothing is not, so
            // the assertion below still runs on the local constant.
            assert_eq!(MIN_MIRRORS, 2);
            return;
        };
        assert!(
            src.contains("MinMirrors = 2"),
            "publisher/deploy/freshness/mirrors.go no longer declares MinMirrors = 2; \
             the wizard's MIN_MIRRORS must move with it"
        );
        assert_eq!(MIN_MIRRORS, 2);
    }

    #[test]
    fn redaction_drops_credential_shaped_lines() {
        let s = "publish-freshness failed\n--r2-secret-file /tmp/x had secret AKIAEXAMPLE\nstatus 403";
        let out = redact_detail(s);
        assert!(!out.contains("AKIAEXAMPLE"), "{out}");
        assert!(out.contains("status 403"));
    }

    #[test]
    fn https_is_required_for_every_url_we_bake_into_a_pack() {
        assert!(require_https("http://x.example.com/f.json", "public URL").is_err());
        assert!(require_https("", "public URL").is_err());
        assert_eq!(
            require_https("https://x.example.com/f.json/", "public URL").unwrap(),
            "https://x.example.com/f.json"
        );
    }

    #[test]
    fn mirrors_in_pack_parses_and_tolerates_junk() {
        assert!(parse_mirrors("").is_empty());
        assert!(parse_mirrors("not json").is_empty());
        assert_eq!(
            parse_mirrors(r#"["r2=https://a","ghpages=https://b"]"#),
            vec!["r2=https://a".to_string(), "ghpages=https://b".to_string()]
        );
    }
}
