//! Subprocess bridge to the FRP-4a `daal-deploy` binary.
//!
//! At FRP-5, only the read-only `pricing` subcommand is wired live
//! (per phase-doc invariant 25). The bridge writes the cloud-token
//! to a tempfile (mode 0o600), invokes:
//!
//! ```sh
//! daal-deploy pricing \
//!     --provider hetzner \
//!     --region <region> \
//!     --server-type <server_type> \
//!     --token-file <tmp>
//! ```
//!
//! parses the JSON output, and returns a [`Pricing`] struct.
//!
//! The tempfile is deleted on drop; the spawned process inherits a
//! restricted env (`PATH` only).

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// Accept JSON `null` as `T::default()`. Required because Go marshals
/// `nil` slices to `null`, not `[]`, and `#[serde(default)]` only
/// fills in MISSING fields — not present-but-null ones.
fn null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("daal-deploy not on PATH; install FRP-4a binary")]
    BinaryMissing,
    #[error("daal-deploy failed: rc={rc} stderr={stderr}")]
    SubprocessFailed { rc: i32, stderr: String },
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, BridgeError>;

/// `Pricing` mirrors the JSON returned by `daal-deploy pricing`.
/// Field tags match FRP-4a `provider.Pricing` (Go struct).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pricing {
    pub provider: String,
    pub region: String,
    pub server_type: String,
    pub hourly_eur: f64,
    pub monthly_eur: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub included_traffic_tb_per_month: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overage_eur_per_gb: Option<f64>,
}

/// `BindResult` mirrors the JSON summary written by
/// `daal-deploy bind-and-sign` to stdout. The shim parses this
/// and emits it back to the wizard frontend (Screen 5/6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BindResult {
    #[serde(default, deserialize_with = "null_default")]
    pub sbp_path: String,
    #[serde(default, deserialize_with = "null_default")]
    pub sbp_sha256: String,
    #[serde(default, deserialize_with = "null_default")]
    pub relay_pack_id: String,
    #[serde(default, deserialize_with = "null_default")]
    pub fingerprint_hex: String,
    #[serde(default, deserialize_with = "null_default")]
    pub fingerprint_en: String,
    #[serde(default, deserialize_with = "null_default")]
    pub fingerprint_fa: String,
    /// Go marshals nil slices as `null`, so accept that as `[]`.
    #[serde(default, deserialize_with = "null_default")]
    pub lint_warnings: Vec<serde_json::Value>,
    #[serde(default)]
    pub shared_risk_edges: i64,
}

/// `ProgressEvent` is the JSON-line shape emitted by
/// `daal-deploy --progress-json` on stderr.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub step: String,
    pub message: String,
    #[serde(default)]
    pub ts: String,
    /// Anything else the CLI sends through (e.g. server_id,
    /// public_ip, candidates count). Kept opaque so the schema can
    /// extend without breaking the wizard.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `RotationRecommendation` mirrors the Go publisher
/// `rotation.RotationRecommendation` JSON shape (FRP-7). The wizard
/// surfaces this struct to Screen 6's RotateModal verbatim. The
/// `override_levels` field is rename-tagged "override" on the wire
/// (Go uses `override` directly; "override" is a Rust keyword).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationRecommendation {
    pub level: String,
    pub confidence: String,
    pub reason: String,
    /// The rule that fired, as a stable code from the Go side's closed
    /// vocabulary — `reason`'s machine-readable parallel.
    ///
    /// `reason` is English prose built in Go, and it is the most
    /// decisive sentence the advice panel renders: it is the whole
    /// substance of the answer, and three of the six rungs it can point
    /// at DESTROY the relay. The panel keys this code to say it in the
    /// operator's own language and falls back to `reason` when a
    /// catalog does not carry the code — so a NEW rule degrades to
    /// English, never to silence.
    ///
    /// Declared here for the reason `action` and `grounded` are: serde
    /// drops unknown keys silently, so a field Go emits and this struct
    /// omits dies with no error anywhere.
    #[serde(default)]
    pub reason_code: String,
    /// The machine-specific fragment some reason codes interpolate (the
    /// blocker that makes an address swap impossible; the inputs that
    /// matched no rung). Substituted for `{detail}` in the catalog
    /// string, and deliberately untranslated: it is provider notes and
    /// closed-vocabulary identifiers.
    #[serde(default)]
    pub reason_detail: String,
    pub est_wallclock: String,
    #[serde(rename = "override", default, alias = "override_levels")]
    pub override_levels: Vec<String>,
    /// Step 7's `rotation.Action`: the concrete operation behind the
    /// named rung — which verb, what it touches, whether the server
    /// survives, and whether the relay in front of you can do it.
    ///
    /// Declared here because serde drops unknown keys silently, which is
    /// the same trap that made `cover_sni`/`mux_inbound` inert one hop
    /// down; a field the Go side emits and this struct omits dies with
    /// no error anywhere.
    ///
    /// `availability` is "unknown" on every recommendation the wizard
    /// currently produces, and that is honest rather than broken: the
    /// recommender is offline by design, so it can only be told what a
    /// relay supports by a caller that probed it
    /// (`mgmt.CapabilitiesWithFW` / `--relay-capabilities`), and the
    /// wizard has no probe step yet. A UI must therefore render "not
    /// verified" and let the rotation's own capability interlock refuse,
    /// never a confident one-tap button.
    #[serde(default)]
    pub action: RotationAction,
    /// Wave 6. False means the Go side chose `level` from NOTHING —
    /// its last rule fired, which used to answer L1 in a sentence that
    /// read like advice. A UI must render that as "Daal cannot tell
    /// you", never as a rung to press.
    ///
    /// Declared here for the same reason `action` is: serde drops
    /// unknown keys silently, so a field the Go side emits and this
    /// struct omits dies with no error anywhere — and the one it would
    /// kill here is the flag that stops an operator destroying a
    /// working relay on no evidence.
    #[serde(default)]
    pub grounded: bool,
    /// What the recommender was given, and — as load-bearing — what it
    /// was not.
    #[serde(default)]
    pub evidence: RotationEvidence,
}

/// `RotationEvidence` mirrors the Go `rotation.Evidence`.
///
/// `absent` is the half that must never be dropped on the way to a
/// screen: a rung that cannot fire because nothing in Daal produces its
/// evidence is not a rung the operator has ruled out, and rendering
/// only the present inputs turns "unmeasured" into "measured and fine".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RotationEvidence {
    /// "explanation" | "context" — the ceiling on confidence.
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub classifications: Vec<String>,
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default)]
    pub cooldown_tags: Vec<String>,
    /// Inputs that WERE present and that no rung consumes.
    #[serde(default)]
    pub unrecognised: Vec<String>,
    /// Structurally unavailable inputs, each with its reason.
    #[serde(default)]
    pub absent: Vec<String>,
    /// One stable code per `absent` entry — same order, same length
    /// (pinned by the Go side's TestAbsentCodesParallelAbsentProse).
    ///
    /// THIS FIELD IS WHY THE ABSENCES ARE READABLE IN FARSI. It was
    /// added to Go and to the panel together and omitted here, and
    /// because serde drops unknown keys silently the Go side emitted
    /// codes, this struct discarded them, and the panel — which keys
    /// them and falls back to the English prose on a miss — fell back
    /// on every single run. No error anywhere; the exact trap that made
    /// `cover_sni`/`mux_inbound` inert one hop down.
    ///
    /// The absences are the half of that panel carrying its honesty:
    /// they are what separates "measured and fine" from "never measured
    /// at all". Losing them to English loses the half that matters.
    #[serde(default)]
    pub absent_codes: Vec<String>,
}

/// `RotationAction` mirrors the Go `rotation.Action`. Every field is
/// `#[serde(default)]`-friendly so a recommendation from an older
/// `daal-deploy` (which emits no `action` at all) decodes to the zero
/// value — which reads as "unknown", the safe answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RotationAction {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub cli_verb: String,
    /// "recipient" | "relay" | "server" — how much of the world this
    /// touches if it goes wrong.
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub in_place: bool,
    #[serde(default)]
    pub needs_recipient_name: bool,
    #[serde(default)]
    pub destroys_server: bool,
    /// After this runs, EVERY already-distributed pack stops working
    /// until its recipient is handed a new one by hand.
    #[serde(default)]
    pub invalidates_every_pack: bool,
    /// "ready" | "unknown" | "unsupported".
    #[serde(default)]
    pub availability: String,
    #[serde(default)]
    pub note: String,
}

/// `RotateRecommendArgs` is the FRP-7 input shape for the rotation
/// recommender CLI. Either `explanation_json` (recipient-diagnostics
/// path) or `context` (FRP-only path) is set, never both.
pub struct RotateRecommendArgs<'a> {
    pub record_path: &'a Path,
    pub explanation_json: Option<&'a str>,
    pub context: Option<RotateContext>,
}

/// `RotateContext` mirrors the Go `rotation.RotationContext`.
#[derive(Debug, Clone, Default)]
pub struct RotateContext {
    pub failure_classifications: Vec<String>,
    pub network_signals: Vec<String>,
    pub exposure_mode: String,
    pub credential_leak_suspected: bool,
}

/// `FountainFrame` is one JSON line of the `qr-fountain` stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FountainFrame {
    /// 0-based index in the emitted stream.
    pub i: i64,
    /// Source-block count (k). Same for every frame in a stream.
    pub k: i64,
    /// Base64url-encoded raw frame bytes (decode + drop into an
    /// alphanumeric QR encoder).
    pub frame_b64: String,
}

/// A single server type returned by `daal-deploy list-server-types`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTypeOption {
    pub id: String,
    pub description: String,
    pub cpus: u32,
    pub memory_gb: f64,
    pub disk_gb: u32,
    pub monthly_eur: f64,
    pub hourly_eur: f64,
    pub location: String,
    pub arch: String,
    /// Which currency `monthly_eur`/`hourly_eur` are in.
    ///
    /// CARRY IT EVEN THOUGH NOTHING IN RUST READS IT. Go states this
    /// deliberately — Vultr bills in USD and its adapter's own comment
    /// says the field is "what stops a dollar figure being drawn behind
    /// a euro sign" — and this struct is the only thing between that
    /// statement and the L5 sheet that draws the sign. A mirror that
    /// omits a field does not merely ignore it: serde drops it on the
    /// way in and it is gone by the time the UI asks. That is the same
    /// silent-drop bug `absent_codes` had.
    ///
    /// `default` so an older `daal-deploy` (which emits no currency at
    /// all, and only ever spoke to Hetzner) deserialises to "" rather
    /// than failing the whole listing.
    #[serde(default)]
    pub currency: String,
}

/// One resource `account-audit` found carrying daal-deploy's ownership
/// marks. Mirrors provider.AuditedResource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditedResourceRow {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub reclaimable: bool,
    /// Whether this resource costs money for as long as it exists.
    ///
    /// The auditor sets it (`provider.AuditedResource.Billing`); it
    /// used to be dropped here in favour of a `monthly_eur` the Go
    /// side never emits, so the row carried a price that was always
    /// 0.00 and lost the one fact the panel exists to report.
    #[serde(default)]
    pub billing: bool,
}

/// The account audit, mirroring provider.AccountAudit.
///
/// `server_list_complete` is carried because it is the one field that
/// decides whether any orphan finding means anything: a resource is an
/// orphan because NO server stands behind it, and if the server list
/// could not be read that claim cannot be made about anything. A UI
/// that drops this boolean turns "could not look" into "nothing found",
/// which is the single most dangerous thing this report can say.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAuditReport {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub resources: Vec<AuditedResourceRow>,
    #[serde(default)]
    pub server_list_complete: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// An existing server on the user's cloud account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExistingServer {
    pub id: String,
    pub name: String,
    pub status: String,
    pub server_type: String,
    pub region: String,
    pub public_ip: String,
    #[serde(default)]
    pub public_ipv6: String,
}

/// Trait so tests can substitute a mock without spawning a process.
pub trait CliRunner: Send + Sync {
    /// List existing servers on the user's cloud account.
    fn run_list_servers(&self, provider: &str, token: &str) -> Result<Vec<ExistingServer>>;

    /// List available server types with pricing for a provider+region.
    fn run_list_server_types(
        &self,
        provider: &str,
        region: &str,
        token: &str,
    ) -> Result<Vec<ServerTypeOption>>;

    /// `daal-deploy account-audit --json`. READ-ONLY: it enumerates
    /// and classifies, and never deletes.
    ///
    /// Takes no record on purpose. The orphan this answers for is born
    /// in the window where the wizard's record write never happened, so
    /// a lookup driven by the app's own rows would be blind to exactly
    /// the resource it was opened to find.
    fn run_account_audit(&self, provider: &str, token: &str) -> Result<AccountAuditReport>;

    fn run_pricing(
        &self,
        provider: &str,
        region: &str,
        server_type: &str,
        token: &str,
    ) -> Result<Pricing>;

    /// FRP-4b: invoke `daal-deploy provision` with `--progress-json`
    /// and stream every event line to `on_progress`. Returns the
    /// final OperatorRecord JSON (stdout) once the subprocess exits 0.
    fn run_provision(
        &self,
        args: ProvisionArgs<'_>,
        on_progress: &mut dyn FnMut(ProgressEvent),
    ) -> Result<String>;

    /// FRP-8: invoke `daal-deploy cdn-provision`, handing the
    /// Cloudflare token through a mode-0600 tempfile and returning
    /// the live FrontRecord JSON.
    fn run_cdn_provision(&self, args: CdnProvisionArgs<'_>) -> Result<CdnFrontResult>;

    /// FRP-9: invoke `daal-deploy cdn-rotate-path`. Re-uploads the
    /// rewrite worker with the new public path and rebinds the
    /// route. Hostname and origin path unchanged.
    fn run_cdn_rotate_path(&self, args: CdnRotatePathArgs<'_>) -> Result<CdnRotateResult>;

    /// FRP-9: invoke `daal-deploy cdn-rotate-hostname`. Migrates
    /// the proxied DNS to the new hostname and rebinds the worker
    /// on the new zone.
    fn run_cdn_rotate_hostname(&self, args: CdnRotateHostnameArgs<'_>) -> Result<CdnRotateResult>;

    /// FRP-9: invoke `daal-deploy cdn-rotate-origin`. Re-points
    /// the proxied A / AAAA records at the new origin IP. Hostname
    /// and public path unchanged. Origin-only path; the wizard
    /// MUST NOT re-sign the RelayPack.
    fn run_cdn_rotate_origin(&self, args: CdnRotateOriginArgs<'_>) -> Result<CdnRotateResult>;

    /// FRP-9: invoke `daal-deploy publish-freshness`. Builds and
    /// signs a freshness JSON document for the current SBP. The
    /// wizard calls this on L7 (path) and L8 (hostname) rotations
    /// after the RelayPack is re-signed. **Must not be called on
    /// L9 origin-only rotations** — bundle is unchanged, the
    /// existing freshness document is still valid.
    fn run_publish_freshness(
        &self,
        args: PublishFreshnessArgs<'_>,
    ) -> Result<PublishFreshnessResult>;

    /// FRP-7: invoke `daal-deploy reprovision`. This mutates the
    /// cloud-side box for L1/L2/L4/L5/L6 and returns the updated
    /// OperatorRecord JSON read back from `args.record_path`.
    fn run_reprovision(&self, args: ReprovisionArgs<'_>) -> Result<String>;

    /// FRP-7: invoke `daal-deploy assign-fip`. This is the L3
    /// fast path and returns the updated OperatorRecord JSON read
    /// back from `args.record_path`.
    ///
    /// TAKES THE SIGNING KEY SINCE WAVE 3c, and that is not a
    /// convenience. Attaching a floating IP is only the cloud half of
    /// an L3: a Hetzner address is routed to the server at the
    /// provider's network layer, but the guest OS does not answer on
    /// it until it is configured on the interface. `assign-fip` now
    /// tells the relay to do that, over a signed request inside an
    /// ephemeral firewall window — so it needs `--priv-key` and
    /// `--helper-ip` exactly like `rotate-credentials` does, and
    /// exits 2 without them rather than attaching an address nothing
    /// will ever answer on.
    fn run_assign_fip(&self, args: AssignFipArgs<'_>, priv_key: &[u8]) -> Result<String>;

    /// Give an address back. Never fails a rotation: the caller folds
    /// the outcome's warnings into its result instead, because the
    /// pack is already signed and committed and undoing that to tidy
    /// up a billing resource would be the wrong trade.
    ///
    /// Also signed since Wave 3c: the relay has to be told to drop the
    /// address BEFORE it returns to the provider pool, or the box keeps
    /// claiming an address another customer may be issued.
    fn run_release_fip(
        &self,
        args: ReleaseFipArgs<'_>,
        priv_key: &[u8],
    ) -> Result<ReleaseFipOutcome>;

    /// Teardown: invoke `daal-deploy decommission` to destroy the
    /// cloud resources this record owns — the VPS, the ephemeral
    /// SSH key and the baseline firewall.
    ///
    /// This is the only verb in the bridge whose whole point is to
    /// make the record's subject stop existing (and stop billing),
    /// so it reports **per resource** rather than pass/fail: a run
    /// that killed the server but could not reach the firewall is a
    /// materially different outcome from a clean sweep, and the user
    /// has to be told which one they got. Non-fatal cloud errors come
    /// back in `warnings` and are shown verbatim; only a failure that
    /// leaves the *server* alive is an `Err`, because that is the one
    /// the caller must not treat as "safe to forget this relay".
    fn run_decommission(&self, args: DecommissionArgs<'_>) -> Result<DecommissionResult>;

    /// FRP-4b: invoke `daal-deploy bind-and-sign`, piping the
    /// 64-byte privkey through stdin (never to disk). Streams
    /// progress events; returns the parsed BindResult on success.
    fn run_bind_and_sign(
        &self,
        args: BindAndSignArgs<'_>,
        priv_key: &[u8],
        on_progress: &mut dyn FnMut(ProgressEvent),
    ) -> Result<BindResult>;

    /// FRP-4b: invoke `daal-deploy qr-fountain` and call
    /// `on_frame` for each JSON-line frame on stdout. The runner
    /// reads up to `max_frames` frames (0 means unbounded — the
    /// caller must stop the iteration via the bool return value).
    fn run_qr_fountain(
        &self,
        sbp_path: &Path,
        block_size: u32,
        max_frames: u32,
        seed: i64,
        on_frame: &mut dyn FnMut(FountainFrame) -> bool,
    ) -> Result<()>;

    /// FRP-7: invoke `daal-deploy rotate-recommend`. Either
    /// `args.explanation_json` is supplied (piped to stdin) or
    /// `args.context` is supplied (translated into --classification /
    /// --signal / --credential-leak / --exposure-mode flags). Returns
    /// the parsed [`RotationRecommendation`].
    fn run_rotate_recommend(&self, args: RotateRecommendArgs<'_>)
        -> Result<RotationRecommendation>;

    /// FRP-14: invoke `daal-deploy users-provision` against the
    /// box. The publisher Ed25519 private key is piped through
    /// stdin (never to disk). Returns the freshly minted
    /// per-recipient credentials.
    fn run_users_provision(
        &self,
        args: UsersProvisionArgs<'_>,
        priv_key: &[u8],
    ) -> Result<UserCredsResult>;

    /// FRP-14: invoke `daal-deploy users-revoke` against the box.
    /// Returns the box-side revocation timestamp.
    fn run_users_revoke(
        &self,
        args: UsersRevokeArgs<'_>,
        priv_key: &[u8],
    ) -> Result<UsersRevokeResult>;

    /// FRP-14: invoke `daal-deploy users-list` against the box.
    /// Returns the box's authoritative recipient roster.
    fn run_users_list(
        &self,
        args: UsersListArgs<'_>,
        priv_key: &[u8],
    ) -> Result<Vec<UserMetaResult>>;

    /// FRP-14 Layer 3b.5: invoke `daal-deploy users-pack-sbpx`.
    /// Wraps an existing `.sbp` plaintext into an age-v1 envelope
    /// addressed to one recipient. No box round-trip, no priv-key.
    fn run_users_pack_sbpx(&self, args: UsersPackSbpxArgs<'_>) -> Result<UsersPackSbpxResult>;

    /// Shared-.sbp path: invoke `daal-deploy users-pack-sbp`.
    fn run_users_pack_sbp(&self, args: UsersPackSbpArgs<'_>) -> Result<UsersPackSbpResult>;

    /// FRP-14 Layer 3d: invoke `daal-deploy users-unpack-sbpx`.
    /// Decrypts a `.sbpx` envelope using the recipient's X25519
    /// private key (piped through stdin as 64 hex chars). Writes
    /// the plaintext `.sbp` to `out_path`.
    fn run_users_unpack_sbpx(
        &self,
        args: UsersUnpackSbpxArgs<'_>,
        priv_key_hex: &str,
    ) -> Result<UsersUnpackSbpxResult>;

    /// Wave 3 Step 7 (L1): invoke `daal-deploy rotate-credentials`.
    ///
    /// A **targeted revocation**: it re-keys ONE named recipient across
    /// every inbound on the box and leaves every other recipient — and
    /// the box's REALITY keypair — alone. `args.name` is mandatory;
    /// there is deliberately no "rotate everything" call, because that
    /// would be a fleet-wide outage wearing a per-row button.
    fn run_rotate_credentials(
        &self,
        args: RotateCredentialsArgs<'_>,
        priv_key: &[u8],
    ) -> Result<RotateCredentialsResult>;

    /// Wave 3 Step 7 (L2): invoke `daal-deploy rotate-tls`.
    ///
    /// Moves the relay's cover hostname and TLS parameters. It does NOT
    /// touch user credentials and does NOT touch the REALITY keypair —
    /// those are two other operations with two other blast radii. The
    /// publisher picks the replacement host (`provider.NextCoverSNI`
    /// excludes the burned one), so this call carries no SNI argument
    /// and reads the applied value back off the box.
    fn run_rotate_tls(
        &self,
        args: RotateTlsArgs<'_>,
        priv_key: &[u8],
    ) -> Result<RotateTlsResult>;
}

/// Wave 3 Step 7: args for `daal-deploy rotate-credentials`.
pub struct RotateCredentialsArgs<'a> {
    pub record_path: &'a Path,
    pub helper_ip: &'a str,
    pub token: &'a str,
    /// The box-side recipient name (`r1`, `r7`, …). Never empty — see
    /// [`CliRunner::run_rotate_credentials`].
    pub name: &'a str,
}

/// Wave 3 Step 7: args for `daal-deploy rotate-tls`.
pub struct RotateTlsArgs<'a> {
    pub record_path: &'a Path,
    pub helper_ip: &'a str,
    pub token: &'a str,
}

/// JSON returned by `daal-deploy rotate-credentials` — the Rust mirror
/// of `mgmt.RotatedCreds` (which embeds `mgmt.UserCreds`).
///
/// It is deliberately the provision shape plus rotation-specific fields,
/// because the pack minter consumes provision output: a rotation then
/// feeds the existing mint path with no translation layer.
///
/// EVERY credential field is carried, even ones this app never reads
/// itself. This struct is a TRANSPORT — the document is re-serialised
/// into the creds file that `users-pack-sbp[x]` parses — and serde drops
/// unknown keys silently, so a field omitted here is a field the pack
/// loses with no error anywhere. That is not hypothetical: `cover_sni`
/// and `mux_inbound` were echoed by the box and swallowed on this hop
/// once already.
///
/// EVERY field is `#[serde(default)]` on purpose. The box binary is a
/// hash-pinned artifact (`publisher/deploy/cloudinit/artifacts.go`) and
/// version-skews independently of this app, so a missing field must read
/// as "this relay did not tell us", never as a parse failure that hides
/// which half of the rotation actually happened.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RotateCredentialsResult {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub vless_uuid: String,
    #[serde(default)]
    pub reality_short_id: String,
    #[serde(default)]
    pub hy2_password: String,
    #[serde(default)]
    pub naive_password: String,
    #[serde(default)]
    pub ws_path: String,
    /// The embedded `UserCreds` spelling. Present because the struct is
    /// shared with the provision path; the rotation's own clock is
    /// `rotated_at_unix`.
    #[serde(default)]
    pub provisioned_at_unix: i64,
    /// Box-wide connection material, echoed so the pack rewrite does
    /// not have to fall back to a possibly-stale OperatorRecord.
    #[serde(default)]
    pub reality_public_key: String,
    #[serde(default)]
    pub tls_cert_sha256: String,
    #[serde(default)]
    pub tls_cert_pem: String,
    #[serde(default)]
    pub cover_sni: String,
    #[serde(default)]
    pub mux_inbound: bool,
    /// Wave 5 — shadowsocks-2022, echoed after a rotation exactly as on
    /// provision. The rotation replaces the recipient's uPSK only, so
    /// this is the LIVE box iPSK joined to the FRESH uPSK; the box
    /// assembles it, this side only carries it.
    #[serde(default)]
    pub ss_password: String,
    #[serde(default)]
    pub ss_method: String,
    /// Wave 5 — tuic, echoed after a rotation exactly as on provision.
    /// Empty when this relay does not serve the family, which is the
    /// same fail-closed signal the provision path uses: a rotation must
    /// not hand back credentials the minter would turn into a route
    /// nobody can dial.
    #[serde(default)]
    pub tuic_uuid: String,
    #[serde(default)]
    pub tuic_password: String,
    /// Wave 5 — anytls, echoed after a rotation exactly as on provision.
    /// Empty when this relay did not rotate an anytls row, which is the
    /// fail-closed signal: a rotation must never hand back a freshly
    /// minted password the box did not actually store.
    #[serde(default)]
    pub anytls_password: String,

    /// The box's own clock at the moment the rewritten config went live,
    /// so "when did this recipient's old UUID stop working?" has an
    /// answer.
    #[serde(default)]
    pub rotated_at_unix: i64,
    /// The legacy spelling the box still emits alongside it.
    #[serde(default)]
    pub generated_at_unix: i64,
    /// Every inbound whose user table the box actually rewrote.
    ///
    /// The honesty field, and the whole reason BUG-6 was a bug rather
    /// than a typo: a revocation that reached three of four inbounds
    /// leaves the leaked credential live on the fourth, and a 200 looks
    /// identical either way. Empty means nothing verified that the
    /// revocation was complete — which the caller must say out loud.
    #[serde(default)]
    pub updated_inbounds: Vec<String>,
    /// Must be false. It exists so "the box keypair was not touched" is
    /// something the publisher can CHECK rather than assume. True means
    /// every distributed pack just died, and the operator has to be told
    /// immediately rather than discovering it from silent disconnects.
    #[serde(default)]
    pub box_keys_rotated: bool,
    /// Anything the relay or the CLI wants said out loud. Rendered
    /// verbatim; never summarised.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// JSON returned by `daal-deploy rotate-tls`.
///
/// Note what is NOT here: the updated OperatorRecord. The CLI writes it
/// back to `--record-file` (mode 0600) rather than emitting it on
/// stdout, so the caller must read that file before deleting it — see
/// `relay_rotation::rotate_tls`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RotateTlsResult {
    #[serde(default)]
    pub applied_at_unix: i64,
    /// The cover host the record now carries — the value the pack minter
    /// will use. Empty only if the CLI could not resolve one at all.
    #[serde(default)]
    pub cover_sni: String,
    #[serde(default)]
    pub previous_cover_sni: String,
    /// What the box says it applied, as opposed to what was asked for.
    /// Empty from a relay whose mgmt binary predates the echo, and that
    /// gap has to reach the screen: `cover_sni` is then what was
    /// REQUESTED, not what was verified.
    #[serde(default)]
    pub applied_sni: String,
    #[serde(default)]
    pub applied_handshake: String,
    /// Echo of what was asked for; the box does not echo a ws path.
    #[serde(default)]
    pub ws_path: String,
    /// Path the CLI wrote the updated OperatorRecord to.
    #[serde(default)]
    pub record_written: String,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// FRP-14: args for `daal-deploy users-provision`.
pub struct UsersProvisionArgs<'a> {
    pub record_path: &'a Path,
    pub helper_ip: &'a str,
    pub token: &'a str,
    pub name: &'a str,
}

/// FRP-14: args for `daal-deploy users-revoke`.
pub struct UsersRevokeArgs<'a> {
    pub record_path: &'a Path,
    pub helper_ip: &'a str,
    pub token: &'a str,
    pub name: &'a str,
}

/// FRP-14: args for `daal-deploy users-list`.
pub struct UsersListArgs<'a> {
    pub record_path: &'a Path,
    pub helper_ip: &'a str,
    pub token: &'a str,
}

/// FRP-14: JSON returned by `daal-deploy users-provision`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UserCredsResult {
    pub name: String,
    pub vless_uuid: String,
    pub reality_short_id: String,
    pub hy2_password: String,
    pub naive_password: String,
    pub ws_path: String,
    pub provisioned_at_unix: i64,
    // FRP-14 Tier-2 box-wide connection material (empty on a pre-Tier-2
    // box). Needed to assemble the client outbound in the pack step.
    #[serde(default)]
    pub reality_public_key: String,
    #[serde(default)]
    pub tls_cert_sha256: String,
    /// The box's data-plane leaf cert (PEM) — naive's trusted root
    /// (Cronet). Without it the naive outbound can't be assembled.
    #[serde(default)]
    pub tls_cert_pem: String,

    // Wave 2 fields. They were added to `mgmt.UserCreds` on the Go side
    // and never here, which is the SAME silent-drop bug in a second
    // language: serde discards unknown keys exactly as encoding/json
    // does, so the box echoed both values, this struct omitted them, and
    // the creds file this app re-serialises for `users-pack-sbp[x]` lost
    // them with no error anywhere. `mux_inbound` is the one that bites —
    // `clientParamsFromCredsFile` gates mux emission on it and has no
    // fallback, so every pack minted through the wizard came out without
    // multiplexing. Anything the box learns and the minter reads MUST
    // appear here.
    /// The cover host this box actually serves, read off its own live
    /// inbound. Authoritative over the OperatorRecord, which only
    /// records what was *requested* — `/rotate-tls` can move the box.
    #[serde(default)]
    pub cover_sni: String,
    /// Whether every vless-family inbound carries an enabled multiplex
    /// block. The client may emit a mux outbound ONLY when this is true:
    /// mux client vs mux-less inbound fails hard, while a mux inbound
    /// serves a plain client fine. False is the safe default.
    #[serde(default)]
    pub mux_inbound: bool,

    // Wave 5 — shadowsocks-2022. Declared here for the same reason the
    // two fields above are, and it is not a theoretical risk: this
    // struct is what `recipient_book.rs` runs through
    // `serde_json::to_value` to produce the creds file the pack step
    // reads, so a field omitted here never reaches the minter. That is
    // exactly how `mux_inbound` came to be inert for an entire wave.
    /// The shadowsocks outbound's `password` VERBATIM: the box has
    /// already joined its box-wide iPSK to this recipient's uPSK with a
    /// colon. Do not split, re-join or re-encode it — SS-2022 decodes
    /// each half with padded base64-std and the separator is part of
    /// the wire format. Empty means this relay does not serve the
    /// family (its mgmt binary predates it), and the minter refuses the
    /// route rather than shipping one that cannot authenticate.
    #[serde(default)]
    pub ss_password: String,
    /// The method the box actually serves, today always
    /// `2022-blake3-aes-128-gcm`. Echoed rather than assumed because
    /// the PSK length follows from it.
    #[serde(default)]
    pub ss_method: String,
    /// Wave 5 — tuic. Same transport-struct rule as the fields above:
    /// omitted here, dropped from the creds file, invisible everywhere.
    ///
    /// tuic authenticates on the PAIR, so both halves are required and
    /// neither has a default. Their ABSENCE is the load-bearing signal:
    /// the box sends them only when its live config really carries a
    /// tuic-in row for this recipient, which is false both on a relay
    /// whose toolbox profile did not enable the family and on a relay
    /// running an mgmt binary that predates it — a real state, because
    /// cloud-init and `daal-relay-mgmt` are pinned as separate
    /// artifacts. The minter refuses the route without them rather than
    /// shipping a tier nobody can authenticate against.
    ///
    /// The uuid is NOT the VLESS uuid: a shared identifier would link
    /// the recipient across two tiers in one leaked pack, and rotating
    /// one would leave the leak live on the other.
    #[serde(default)]
    pub tuic_uuid: String,
    #[serde(default)]
    pub tuic_password: String,
    /// Wave 5 — anytls. THE SAME RULE AS EVERY FIELD ABOVE, and it was
    /// broken again here: this struct is what `recipient_book.rs` runs
    /// through `serde_json::to_value` to write the creds file
    /// `users-pack-sbp` reads, so a field the box echoes and this
    /// struct omits is discarded with no error anywhere. The box has
    /// echoed `anytls_password` since the family landed; without this
    /// declaration the minter read `""`, `ClientOutboundForFamily`
    /// refused the anytls route, and `RewriteProfilesForRecipient`
    /// failed the WHOLE pack on it — the recipient got nothing, not a
    /// pack missing one route.
    ///
    /// Empty means this relay does not serve anytls (its
    /// `daal-relay-mgmt` binary predates the family). The minter now
    /// drops just that route and reports it.
    #[serde(default)]
    pub anytls_password: String,
}

/// FRP-14: JSON returned by `daal-deploy users-revoke`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UsersRevokeResult {
    pub revoked_at_unix: i64,
}

/// FRP-14: an entry of the JSON returned by `daal-deploy users-list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UserMetaResult {
    pub name: String,
    pub provisioned_at_unix: i64,
}

/// FRP-14 Layer 3b.5: args for `daal-deploy users-pack-sbpx`.
pub struct UsersPackSbpxArgs<'a> {
    pub in_sbp_path: &'a Path,
    pub recipient_pub_hex: &'a str,
    pub out_sbpx_path: &'a Path,
    /// FRP-14 Tier-2: per-recipient creds JSON path (mgmt provision
    /// shape) + box server IP. When both are set, the pack step
    /// rewrites the inner .sbp's profiles with real client outbounds.
    /// Both None preserves the Tier-1 envelope-unchanged behaviour.
    pub creds_file_path: Option<&'a Path>,
    pub server: Option<&'a str>,
    /// OperatorRecord.cover_sni for this relay. Used only when the box's
    /// creds payload carries none — i.e. when the relay runs an
    /// mgmt binary older than the cover-host echo. Without it such a
    /// pack advertises the legacy fleet-wide constant against a box
    /// serving a pool host, and the REALITY tier dies silently.
    pub cover_sni: Option<&'a str>,
}

/// FRP-14 Layer 3b.5: JSON returned by `daal-deploy users-pack-sbpx`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UsersPackSbpxResult {
    pub sbpx_path: String,
    pub plaintext_size: i64,
    pub sbpx_size: i64,
}

/// Shared-.sbp path: args for `daal-deploy users-pack-sbp`. Rewrites a
/// signed .sbp's profiles with ONE shared box user's creds (no envelope,
/// no recipient pubkey) so any phone can import + connect it.
pub struct UsersPackSbpArgs<'a> {
    pub in_sbp_path: &'a Path,
    pub creds_file_path: &'a Path,
    pub server: &'a str,
    pub out_sbp_path: &'a Path,
    /// See `UsersPackSbpxArgs::cover_sni`.
    pub cover_sni: Option<&'a str>,
}

/// JSON returned by `daal-deploy users-pack-sbp`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UsersPackSbpResult {
    pub sbp_path: String,
    pub sbp_size: i64,
    pub shared: bool,
}

/// FRP-14 Layer 3d: args for `daal-deploy users-unpack-sbpx`.
pub struct UsersUnpackSbpxArgs<'a> {
    pub in_sbpx_path: &'a Path,
    pub out_sbp_path: &'a Path,
}

/// FRP-14 Layer 3d: JSON returned by `daal-deploy users-unpack-sbpx`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UsersUnpackSbpxResult {
    pub plaintext_path: String,
    pub plaintext_size: i64,
    pub sbpx_size: i64,
}

/// Static shape passed to `run_provision`. Field names correspond
/// to the `daal-deploy provision` flags 1:1.
pub struct ProvisionArgs<'a> {
    pub provider: &'a str,
    pub region: &'a str,
    pub server_type: &'a str,
    pub toolbox_profile: &'a str,
    pub families: Vec<&'a str>,
    pub helper_ip: &'a str,
    pub pubkey_file: &'a Path,
    pub token: &'a str,
    pub dry_run: bool,
    /// When non-empty, rebuild this existing server instead of creating new.
    pub existing_server_id: &'a str,
    /// The REALITY cover host this relay must advertise, or "" to let
    /// `daal-deploy` pick one from the pool for a brand-new relay.
    ///
    /// LOAD-BEARING ON REPROVISION. `daal-deploy provision` derives the
    /// pool host from the derived server name, which is a pure function
    /// of (publisher key, region) and does not change when a box is
    /// rebuilt. So an L2 rotation — whose whole purpose is to move the
    /// relay off a burned cover host — would compute the ORIGINAL host
    /// again and hand the operator back the exact name they paid a full
    /// rebuild to escape. `reprovision` writes the rotated host into the
    /// record; this field is how it survives the `provision` that
    /// follows.
    pub cover_sni: &'a str,
    /// Destroy the box if provisioning fails after it was created.
    ///
    /// `daal-deploy`'s own default is false — for a CLI operator, a box
    /// that failed its health wait is worth keeping: they have the id in
    /// their scrollback and the idempotent retry can reuse it. Neither
    /// is true from the app. `provision_run` only writes the
    /// OperatorRecord back on success, so a failure persists
    /// `server_id: ""` and the mgmt port that was minted for that box is
    /// gone with the process; the retry path then refuses ("existing
    /// server requires persisted MgmtPort") because it cannot know the
    /// port the running box was configured with. The kept box is
    /// therefore unusable *and* unnamed — a billing server the app can
    /// only reach by re-deriving its name at teardown. Rolling back
    /// stops the meter at the moment of failure and frees the derived
    /// name so "Try again" works.
    pub rollback_on_failure: bool,
}

/// Static shape passed to `daal-deploy cdn-provision`.
pub struct CdnProvisionArgs<'a> {
    pub hostname: &'a str,
    pub origin_ip: &'a str,
    pub origin_ipv6: &'a str,
    pub origin_path: &'a str,
    pub public_path: &'a str,
    pub out_dir: &'a Path,
    pub cf_token: &'a str,
    pub cloud_token: &'a str,
}

/// `CdnFrontResult` mirrors publisher/deploy/cloudflare.FrontRecord.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CdnFrontResult {
    pub hostname: String,
    pub zone_id: String,
    pub public_path: String,
    pub origin_path: String,
    pub worker_route_id: String,
    pub firewall_id: String,
    pub origin_ca_fingerprint: String,
    pub origin_ca_cert_path: String,
    pub origin_ca_priv_path: String,
    pub aop_client_cert_path: String,
    pub aop_enabled: bool,
}

/// FRP-9 commit 1/8: `daal-deploy cdn-rotate-path` args. The
/// rotate path changes the visible random path; the stable
/// origin path is untouched. Caller is expected to re-sign the
/// RelayPack and re-publish the freshness JSON document after
/// this call returns; this struct doesn't model that step.
pub struct CdnRotatePathArgs<'a> {
    pub front_id: i64,
    pub hostname: &'a str,
    pub zone_id: &'a str,
    pub account_id: &'a str,
    pub old_route_id: &'a str,
    pub origin_path: &'a str,
    pub new_public_path: &'a str,
    pub cf_token: &'a str,
}

/// FRP-9 commit 1/8: `daal-deploy cdn-rotate-hostname` args. The
/// hostname changes; public path + origin IP unchanged. Caller
/// re-signs the RelayPack afterwards.
pub struct CdnRotateHostnameArgs<'a> {
    pub front_id: i64,
    pub old_hostname: &'a str,
    pub old_zone_id: &'a str,
    pub public_path: &'a str,
    pub origin_path: &'a str,
    pub new_hostname: &'a str,
    pub origin_ipv4: &'a str,
    pub origin_ipv6: &'a str,
    pub cf_token: &'a str,
}

/// FRP-9 commit 1/8: `daal-deploy cdn-rotate-origin` args. Origin
/// IP changes; hostname + public path unchanged. **Caller MUST
/// NOT re-sign the RelayPack** — origin-only is invisible to the
/// family per supplement §14.4.
pub struct CdnRotateOriginArgs<'a> {
    pub front_id: i64,
    pub hostname: &'a str,
    pub zone_id: &'a str,
    pub new_origin_ipv4: &'a str,
    pub new_origin_ipv6: &'a str,
    pub cf_token: &'a str,
}

/// FRP-9 commit 4/8: `daal-deploy publish-freshness` args.
/// Either `root_priv_path` or (`subkey_priv_path` +
/// `subkey_cert_path`) must be set; sub-key wins when both are
/// supplied. The wizard ALWAYS prefers an active sub-key when one
/// is recorded for the operator; the root-key path is the
/// bootstrap fallback.
pub struct PublishFreshnessArgs<'a> {
    pub relay_pack_id: &'a str,
    pub current_bundle_sha256: &'a str,
    pub current_signed_url: &'a str,
    pub publisher_pub_hex: &'a str,
    pub root_priv_path: Option<&'a Path>,
    pub subkey_priv_path: Option<&'a Path>,
    pub subkey_cert_path: Option<&'a Path>,
    pub out_file: Option<&'a Path>,
    pub now_unix: i64,
    /// The monotonic counter stamped into the document. Zero lets the
    /// CLI derive it from the publish timestamp; the wizard always
    /// supplies max(last_published + 1, now) so a publishing machine
    /// whose clock went backwards cannot mint a document every already
    /// -provisioned recipient will reject as a rollback.
    pub sequence: u64,
    /// The last sequence this wizard published for this pack. The CLI
    /// refuses to publish anything that does not strictly exceed it,
    /// which is the only place the counter has an owner.
    pub min_sequence: u64,
    /// The relay_pack_ids this pack replaces, newest first.
    ///
    /// WITHOUT THESE THE DOCUMENT REACHES NOBODY AFTER A ROTATION. The
    /// pack id is a hash of provider|server_id|region|public_ip|
    /// families — exactly the fields L3/L4/L5/L6 change — so the rung
    /// that repairs a relay also renames it, and a recipient matching
    /// on the id it has installed rejects the new document as
    /// belonging to a different pack.
    pub supersedes: &'a [String],
    /// Wave 3 Step 8: the endpoint set to ADVERTISE inside the
    /// document, as `provider=https://url`. The document names every
    /// mirror so a recipient that reached one blocked-but-alive mirror
    /// learns the others even if its pack predates them.
    pub mirrors: &'a [String],
    /// Wave 3 Step 8: where to actually upload. Empty fields mean
    /// "build and sign only" — which the CLI reports on stderr as
    /// NOT PUBLISHED rather than treating as success.
    pub upload: &'a FreshnessUploadArgs,
}

/// Wave 3 Step 8: per-provider upload routing for
/// `daal-deploy publish-freshness`.
///
/// The two secret fields are PATHS, not bytes. `daal-deploy` reads
/// credentials only from files (same contract as the publisher signing
/// key and the Cloudflare token), so the wizard decrypts from
/// DeviceCustody into a mode-0600 file for the length of one
/// subprocess and wipes it afterwards. Nothing here may ever become a
/// command-line argument: argv is world-readable on Linux.
#[derive(Debug, Clone, Default)]
pub struct FreshnessUploadArgs {
    pub r2_account: String,
    pub r2_bucket: String,
    pub r2_object_key: String,
    pub r2_public_url: String,
    /// The access key ID is passed as an argument because it is an
    /// identifier rather than an authenticator; the SECRET half never
    /// leaves the file.
    pub r2_access_key_id: String,
    pub r2_secret_file: Option<PathBuf>,
    pub gh_owner: String,
    pub gh_repo: String,
    pub gh_path: String,
    pub gh_branch: String,
    pub gh_public_url: String,
    pub gh_pat_file: Option<PathBuf>,
}

impl FreshnessUploadArgs {
    /// True when at least one provider is fully specified. The CLI
    /// refuses a partially-specified provider, so this only gates
    /// "should we pass any upload flags at all".
    pub fn has_any(&self) -> bool {
        self.r2_secret_file.is_some() || self.gh_pat_file.is_some()
    }
}

/// One mirror's outcome, as reported by `publish-freshness`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PublishedMirror {
    pub provider: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub error: String,
}

/// FRP-9 commit 4/8: result shape returned by
/// `daal-deploy publish-freshness`. `signed_doc_b64` always carries
/// the bytes.
///
/// This comment used to end "published_url is empty until the live
/// backend SDK (R2 / GH Pages) is wired in a follow-up". That
/// follow-up landed at Wave 3b: both backends are real
/// (`publisher/deploy/freshness/backends/r2` signs AWS SigV4,
/// `.../ghpages` PUTs the contents API), and `cli.go` sets
/// `published_url` to the first mirror that accepted the write.
/// Reading `published_url == ""` as "not implemented yet" rather than
/// as "every mirror refused" is exactly backwards, which is why the
/// stale sentence is called out instead of just deleted.
///
/// `published_url` is still the WRONG field to render: it is only the
/// first success and says nothing about the others. Use `published`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PublishFreshnessResult {
    pub signed_doc_b64: String,
    pub signed_doc_path: String,
    pub relay_pack_id: String,
    pub current_bundle_sha256: String,
    pub published_url: String,
    /// Monotonic document counter. A recipient ignores a document whose
    /// sequence is not higher than the last one it accepted, so this is
    /// what makes a replayed old document harmless.
    #[serde(default)]
    pub sequence: u64,
    /// RFC3339 instant after which recipients stop trusting the
    /// document.
    #[serde(default)]
    pub not_after: String,
    /// One row per configured mirror. THIS is the field the wizard's
    /// honesty ledger is written from; `published_url` is only the
    /// first success and says nothing about the others.
    #[serde(default)]
    pub published: Vec<PublishedMirror>,
}

/// FRP-9 rotate result; mirrors the parts of the FrontRecord that
/// can change in a rotation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CdnRotateResult {
    pub hostname: String,
    pub zone_id: String,
    pub public_path: String,
    pub worker_route_id: String,
    pub origin_ipv4: String,
    pub origin_ipv6: String,
}

/// Static shape passed to `run_reprovision`.
pub struct ReprovisionArgs<'a> {
    pub record_path: &'a Path,
    pub token: &'a str,
    pub regen_credentials: bool,
    pub new_sni: Option<&'a str>,
    pub new_ws_path: Option<&'a str>,
    pub new_toolbox_profile: Option<&'a str>,
}

/// Static shape passed to `run_assign_fip`.
pub struct AssignFipArgs<'a> {
    pub record_path: &'a Path,
    pub token: &'a str,
    /// Helper's outbound public IP. Required: the bind leg opens a
    /// per-caller firewall window on the relay's mgmt port, and there
    /// is no window without an address to open it for.
    pub helper_ip: &'a str,
    pub fip_id: &'a str,
}

/// Static shape passed to `run_release_fip`.
///
/// Releasing is a SEPARATE verb from attaching on purpose, and the
/// rotation calls it only after the new pack is signed and the history
/// row is committed. Between the attach and this call the relay answers
/// on BOTH addresses, so every already-distributed pack keeps working;
/// releasing earlier would open a window in which a failure leaves
/// recipients holding a pack for an address that routes nowhere.
pub struct ReleaseFipArgs<'a> {
    pub record_path: &'a Path,
    pub token: &'a str,
    /// Helper's outbound public IP — see [`AssignFipArgs::helper_ip`].
    pub helper_ip: &'a str,
    /// The address to give back. Empty means "the one on the record",
    /// which is NOT what a rotation wants — it wants the PRIOR id.
    pub fip_id: &'a str,
    /// The prior ADDRESS, for the relay's unbind.
    ///
    /// The provider speaks ids and the box speaks addresses. When
    /// `fip_id` is the id the record names, the CLI resolves the
    /// address from the record — but a rotation has already replaced
    /// the record with the swap's OUTPUT (the new id, the new address)
    /// before this leg runs, so the address being released appears
    /// nowhere the CLI can look. Without it the CLI could not tell the
    /// relay to drop the address and used to release anyway: the old
    /// address stayed configured on eth0 with a persistence record
    /// re-asserted at every reboot, while the provider was free to
    /// issue it to another customer. It now REFUSES instead, so this
    /// field is mandatory for the rotation shape.
    pub fip_address: &'a str,
}

/// What `floating-ip release` did, in operator-facing terms.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ReleaseFipOutcome {
    /// The record as it stands after the release.
    pub record_json: String,
    /// Non-fatal notes: an address that was detached but left reserved
    /// (daal-deploy did not create it), or one that could not be
    /// released at all. Both mean "still on your bill", which is the
    /// opposite of what the rotation's success copy used to claim.
    pub warnings: Vec<String>,
}

/// Static shape passed to `run_decommission`. Field names
/// correspond to the `daal-deploy decommission` flags 1:1.
pub struct DecommissionArgs<'a> {
    pub record_path: &'a Path,
    pub token: &'a str,
}

/// JSON returned by `daal-deploy decommission --json`, one flag per
/// cloud resource the provisioner creates.
///
/// The flags are "is it gone now", not "did this run delete it":
/// a resource that was already absent reports `true`, because the
/// user's question is whether anything is still billing, not which
/// invocation removed it. `warnings` carries the provider's own
/// error text for any leg that could not be confirmed gone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DecommissionResult {
    pub server_deleted: bool,
    pub ssh_key_deleted: bool,
    pub firewall_deleted: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Static shape passed to `run_bind_and_sign`. Field names follow
/// the `daal-deploy bind-and-sign` flags 1:1.
pub struct BindAndSignArgs<'a> {
    pub operator_record_path: &'a Path,
    pub output_path: &'a Path,
    pub phase: &'a str,
    pub now_unix: i64,
    pub expiry_days: u32,
    pub publisher_name: &'a str,
    pub subkey_cert_path: Option<&'a Path>,
    /// Wave 3 Step 8: the freshness mirror set to bake into the pack,
    /// as `provider=https://url` entries.
    ///
    /// Empty means "sign a pack with no freshness path", which is a
    /// legal shape and is what happens for a publisher who has not
    /// configured mirrors. What is NOT legal is one entry: the CLI
    /// rejects a single-mirror set, and `freshness::mirror_args`
    /// returns empty rather than one, because a lone freshness URL is a
    /// recovery mechanism a censor disables with one DNS entry while
    /// the publisher believes they are covered.
    pub freshness_mirrors: &'a [String],
}

/// Extension trait so `.apply_env()` can be chained on `Command`.
///
/// On desktop: `env_clear()` + re-add `PATH` (minimal attack surface).
/// On Android: inherit the parent env (the CGO-built Go binary needs
/// `LD_LIBRARY_PATH`, system DNS via Bionic's `getaddrinfo()`, etc.).
trait CommandEnvExt {
    fn apply_env(&mut self) -> &mut Self;
}

impl CommandEnvExt for Command {
    fn apply_env(&mut self) -> &mut Self {
        #[cfg(not(target_os = "android"))]
        {
            self.env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        }
        self
    }
}

/// Production runner: spawns `daal-deploy`.
pub struct SubprocessRunner {
    binary: PathBuf,
}

impl SubprocessRunner {
    /// Locate `daal-deploy` via PATH or the explicit `bin` arg.
    pub fn new(bin: Option<PathBuf>) -> Self {
        let binary = bin.unwrap_or_else(|| PathBuf::from("daal-deploy"));
        Self { binary }
    }

    /// One `decommission` invocation. Split out of the trait method
    /// so the `--json` capability probe can run the same command
    /// twice without duplicating the token-tempfile dance; the token
    /// file is re-minted per attempt and dropped the instant the
    /// child exits.
    fn decommission_once(
        &self,
        args: &DecommissionArgs<'_>,
        want_json: bool,
    ) -> Result<std::process::Output> {
        let tmp = tempfile_with_secret(args.token)?;
        let token_path = tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("decommission")
            .arg("--record-file")
            .arg(args.record_path)
            .arg("--token-file")
            .arg(&token_path);
        if want_json {
            cmd.arg("--json");
        }
        let out = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(tmp);

        match out {
            Ok(o) => Ok(o),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(BridgeError::BinaryMissing),
            Err(e) => Err(BridgeError::Io(e)),
        }
    }
}

impl CliRunner for SubprocessRunner {
    fn run_list_servers(&self, provider: &str, token: &str) -> Result<Vec<ExistingServer>> {
        let tmp = tempfile_with_secret(token)?;
        let token_path = tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("list-servers")
            .arg("--provider")
            .arg(provider)
            .arg("--token-file")
            .arg(&token_path);
        cmd.apply_env();
        let out = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(tmp);

        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            let rc = out.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(BridgeError::SubprocessFailed { rc, stderr });
        }
        let servers: Vec<ExistingServer> = serde_json::from_slice(&out.stdout)?;
        Ok(servers)
    }

    fn run_list_server_types(
        &self,
        provider: &str,
        region: &str,
        token: &str,
    ) -> Result<Vec<ServerTypeOption>> {
        let tmp = tempfile_with_secret(token)?;
        let token_path = tmp.path().to_path_buf();

        let out = Command::new(&self.binary)
            .arg("list-server-types")
            .arg("--provider")
            .arg(provider)
            .arg("--region")
            .arg(region)
            .arg("--token-file")
            .arg(&token_path)
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(tmp);

        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            let rc = out.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(BridgeError::SubprocessFailed { rc, stderr });
        }
        let types: Vec<ServerTypeOption> = serde_json::from_slice(&out.stdout)?;
        Ok(types)
    }

    fn run_account_audit(&self, provider: &str, token: &str) -> Result<AccountAuditReport> {
        let tmp = tempfile_with_secret(token)?;
        let token_path = tmp.path().to_path_buf();

        let out = Command::new(&self.binary)
            .arg("account-audit")
            .arg("--provider")
            .arg(provider)
            .arg("--token-file")
            .arg(&token_path)
            .arg("--json")
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(tmp);

        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            let rc = out.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(BridgeError::SubprocessFailed { rc, stderr });
        }
        let report: AccountAuditReport = serde_json::from_slice(&out.stdout)?;
        Ok(report)
    }

    fn run_pricing(
        &self,
        provider: &str,
        region: &str,
        server_type: &str,
        token: &str,
    ) -> Result<Pricing> {
        // Write token to a tempfile, mode 0600 on unix.
        let tmp = tempfile_with_secret(token)?;
        let token_path = tmp.path().to_path_buf();

        let out = Command::new(&self.binary)
            .arg("pricing")
            .arg("--provider")
            .arg(provider)
            .arg("--region")
            .arg(region)
            .arg("--server-type")
            .arg(server_type)
            .arg("--token-file")
            .arg(&token_path)
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        // Explicitly drop the tempfile after the subprocess exits.
        drop(tmp);

        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };

        if !out.status.success() {
            let rc = out.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(BridgeError::SubprocessFailed { rc, stderr });
        }
        // daal-deploy emits one JSON object per line (or block);
        // we parse the whole stdout.
        let pricing: Pricing = serde_json::from_slice(&out.stdout)?;
        Ok(pricing)
    }

    fn run_provision(
        &self,
        args: ProvisionArgs<'_>,
        on_progress: &mut dyn FnMut(ProgressEvent),
    ) -> Result<String> {
        // Token tempfile (mode 0o600); zeroized on drop.
        let tmp = tempfile_with_secret(args.token)?;
        let token_path = tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("provision")
            .arg("--provider")
            .arg(args.provider)
            .arg("--region")
            .arg(args.region)
            .arg("--server-type")
            .arg(args.server_type)
            .arg("--toolbox-profile")
            .arg(args.toolbox_profile)
            .arg("--helper-ip")
            .arg(args.helper_ip)
            .arg("--pubkey-file")
            .arg(args.pubkey_file)
            .arg("--token-file")
            .arg(&token_path)
            .arg("--progress-json");
        if !args.families.is_empty() {
            cmd.arg("--families").arg(args.families.join(","));
        }
        if !args.existing_server_id.is_empty() {
            cmd.arg("--existing-server-id").arg(args.existing_server_id);
        }
        if !args.cover_sni.is_empty() {
            cmd.arg("--cover-sni").arg(args.cover_sni);
        }
        if args.rollback_on_failure {
            cmd.arg("--rollback-on-failure");
        }
        if args.dry_run {
            cmd.arg("--dry-run");
        }
        let mut child = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
                _ => BridgeError::Io(e),
            })?;

        let stderr = child.stderr.take().expect("piped");
        let stdout_handle = child.stdout.take().expect("piped");
        // Reader thread for stdout (final OperatorRecord JSON).
        let stdout_join = std::thread::spawn(move || {
            let mut buf = String::new();
            let mut r = BufReader::new(stdout_handle);
            let _ = r.read_to_string(&mut buf);
            buf
        });

        // Stream progress lines off stderr in this thread (callback runs here).
        let mut stderr_tail = String::new();
        let r = BufReader::new(stderr);
        for line in r.lines().flatten() {
            // Try to parse as ProgressEvent. If parse fails the line is
            // human prose (Go's `fmt.Fprintln` calls in the CLI); we
            // append to stderr_tail for the SubprocessFailed message.
            match serde_json::from_str::<ProgressEvent>(&line) {
                Ok(ev) => on_progress(ev),
                Err(_) => {
                    stderr_tail.push_str(&line);
                    stderr_tail.push('\n');
                }
            }
        }

        let status = child.wait().map_err(BridgeError::Io)?;
        let stdout_text = stdout_join.join().unwrap_or_default();
        drop(tmp);
        if !status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: status.code().unwrap_or(-1),
                stderr: stderr_tail,
            });
        }
        Ok(stdout_text)
    }

    fn run_cdn_provision(&self, args: CdnProvisionArgs<'_>) -> Result<CdnFrontResult> {
        let cf_tmp = tempfile_with_secret(args.cf_token)?;
        let cf_token_path = cf_tmp.path().to_path_buf();
        let cloud_tmp = tempfile_with_secret(args.cloud_token)?;
        let cloud_token_path = cloud_tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("cdn-provision")
            .arg("--hostname")
            .arg(args.hostname)
            .arg("--origin-ip")
            .arg(args.origin_ip)
            .arg("--origin-path")
            .arg(args.origin_path)
            .arg("--out-dir")
            .arg(args.out_dir)
            .arg("--cf-token-file")
            .arg(&cf_token_path)
            .arg("--token-file")
            .arg(&cloud_token_path);
        if !args.origin_ipv6.is_empty() {
            cmd.arg("--origin-ipv6").arg(args.origin_ipv6);
        }
        if !args.public_path.is_empty() {
            cmd.arg("--public-path").arg(args.public_path);
        }
        let out = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(cf_tmp);
        drop(cloud_tmp);

        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    fn run_cdn_rotate_path(&self, args: CdnRotatePathArgs<'_>) -> Result<CdnRotateResult> {
        let cf_tmp = tempfile_with_secret(args.cf_token)?;
        let cf_token_path = cf_tmp.path().to_path_buf();
        let mut cmd = Command::new(&self.binary);
        cmd.arg("cdn-rotate-path")
            .arg("--hostname")
            .arg(args.hostname)
            .arg("--zone-id")
            .arg(args.zone_id)
            .arg("--account-id")
            .arg(args.account_id)
            .arg("--old-route-id")
            .arg(args.old_route_id)
            .arg("--origin-path")
            .arg(args.origin_path)
            .arg("--new-public-path")
            .arg(args.new_public_path)
            .arg("--cf-token-file")
            .arg(&cf_token_path);
        let out = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(cf_tmp);
        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    fn run_cdn_rotate_hostname(&self, args: CdnRotateHostnameArgs<'_>) -> Result<CdnRotateResult> {
        let cf_tmp = tempfile_with_secret(args.cf_token)?;
        let cf_token_path = cf_tmp.path().to_path_buf();
        let mut cmd = Command::new(&self.binary);
        cmd.arg("cdn-rotate-hostname")
            .arg("--old-hostname")
            .arg(args.old_hostname)
            .arg("--old-zone-id")
            .arg(args.old_zone_id)
            .arg("--public-path")
            .arg(args.public_path)
            .arg("--origin-path")
            .arg(args.origin_path)
            .arg("--new-hostname")
            .arg(args.new_hostname)
            .arg("--origin-ipv4")
            .arg(args.origin_ipv4)
            .arg("--cf-token-file")
            .arg(&cf_token_path);
        if !args.origin_ipv6.is_empty() {
            cmd.arg("--origin-ipv6").arg(args.origin_ipv6);
        }
        let out = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(cf_tmp);
        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    fn run_cdn_rotate_origin(&self, args: CdnRotateOriginArgs<'_>) -> Result<CdnRotateResult> {
        let cf_tmp = tempfile_with_secret(args.cf_token)?;
        let cf_token_path = cf_tmp.path().to_path_buf();
        let mut cmd = Command::new(&self.binary);
        cmd.arg("cdn-rotate-origin")
            .arg("--hostname")
            .arg(args.hostname)
            .arg("--zone-id")
            .arg(args.zone_id)
            .arg("--new-origin-ipv4")
            .arg(args.new_origin_ipv4)
            .arg("--cf-token-file")
            .arg(&cf_token_path);
        if !args.new_origin_ipv6.is_empty() {
            cmd.arg("--new-origin-ipv6").arg(args.new_origin_ipv6);
        }
        let out = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(cf_tmp);
        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    fn run_publish_freshness(
        &self,
        args: PublishFreshnessArgs<'_>,
    ) -> Result<PublishFreshnessResult> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("publish-freshness")
            .arg("--relay-pack-id")
            .arg(args.relay_pack_id)
            .arg("--current-bundle-sha256")
            .arg(args.current_bundle_sha256)
            .arg("--current-signed-url")
            .arg(args.current_signed_url)
            .arg("--publisher-pub-hex")
            .arg(args.publisher_pub_hex);
        if let Some(p) = args.subkey_priv_path {
            cmd.arg("--subkey-priv-file").arg(p);
            if let Some(c) = args.subkey_cert_path {
                cmd.arg("--subkey-cert-file").arg(c);
            }
        } else if let Some(p) = args.root_priv_path {
            cmd.arg("--root-priv-file").arg(p);
        }
        if let Some(out) = args.out_file {
            cmd.arg("--out-file").arg(out);
        }
        if args.now_unix != 0 {
            cmd.arg("--now-unix").arg(args.now_unix.to_string());
        }
        if args.sequence != 0 {
            cmd.arg("--sequence").arg(args.sequence.to_string());
        }
        if args.min_sequence != 0 {
            cmd.arg("--min-sequence").arg(args.min_sequence.to_string());
        }
        for id in args.supersedes {
            cmd.arg("--supersedes").arg(id);
        }
        // Wave 3 Step 8: the endpoint set advertised INSIDE the
        // document, and the credentials to upload it with.
        for m in args.mirrors {
            cmd.arg("--mirror").arg(m);
        }
        let up = args.upload;
        if let Some(secret) = up.r2_secret_file.as_ref() {
            cmd.arg("--r2-account")
                .arg(&up.r2_account)
                .arg("--r2-bucket")
                .arg(&up.r2_bucket)
                .arg("--r2-object-key")
                .arg(&up.r2_object_key)
                .arg("--r2-public-url")
                .arg(&up.r2_public_url)
                .arg("--r2-access-key-id")
                .arg(&up.r2_access_key_id)
                // The secret itself is NEVER an argument — argv is
                // readable by any process on the box.
                .arg("--r2-secret-file")
                .arg(secret);
        }
        if let Some(pat) = up.gh_pat_file.as_ref() {
            cmd.arg("--gh-owner")
                .arg(&up.gh_owner)
                .arg("--gh-repo")
                .arg(&up.gh_repo)
                .arg("--gh-path")
                .arg(&up.gh_path)
                .arg("--gh-public-url")
                .arg(&up.gh_public_url)
                .arg("--gh-pat-file")
                .arg(pat);
            if !up.gh_branch.is_empty() {
                cmd.arg("--gh-branch").arg(&up.gh_branch);
            }
        }
        let out = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    }

    fn run_reprovision(&self, args: ReprovisionArgs<'_>) -> Result<String> {
        let tmp = tempfile_with_secret(args.token)?;
        let token_path = tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("reprovision")
            .arg("--record-file")
            .arg(args.record_path)
            .arg("--token-file")
            .arg(&token_path);
        if args.regen_credentials {
            cmd.arg("--regen-credentials");
        }
        if let Some(v) = args.new_sni {
            if !v.is_empty() {
                cmd.arg("--new-sni").arg(v);
            }
        }
        if let Some(v) = args.new_ws_path {
            if !v.is_empty() {
                cmd.arg("--new-ws-path").arg(v);
            }
        }
        if let Some(v) = args.new_toolbox_profile {
            if !v.is_empty() {
                cmd.arg("--new-toolbox-profile").arg(v);
            }
        }

        let out = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        drop(tmp);

        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(BridgeError::BinaryMissing);
            }
            Err(e) => return Err(BridgeError::Io(e)),
        };
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        std::fs::read_to_string(args.record_path).map_err(BridgeError::Io)
    }

    fn run_assign_fip(&self, args: AssignFipArgs<'_>, priv_key: &[u8]) -> Result<String> {
        let tmp = tempfile_with_secret(args.token)?;
        let token_path = tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("assign-fip")
            .arg("--record-file")
            .arg(args.record_path)
            .arg("--token-file")
            .arg(&token_path)
            // The guest-OS half of the swap. Without these two the CLI
            // exits 2 before it reserves anything — deliberately, since
            // an address attached to a box that was never told to
            // configure it is one nothing will ever answer on.
            .arg("--helper-ip")
            .arg(args.helper_ip)
            .arg("--priv-key")
            .arg("-")
            .arg("--fip-id")
            .arg(args.fip_id);
        let out = run_with_piped_priv_key(cmd, priv_key);
        drop(tmp);

        let out = out?;
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: out.stderr,
            });
        }
        std::fs::read_to_string(args.record_path).map_err(BridgeError::Io)
    }

    fn run_release_fip(
        &self,
        args: ReleaseFipArgs<'_>,
        priv_key: &[u8],
    ) -> Result<ReleaseFipOutcome> {
        let tmp = tempfile_with_secret(args.token)?;
        let token_path = tmp.path().to_path_buf();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("floating-ip")
            .arg("release")
            .arg("--record-file")
            .arg(args.record_path)
            .arg("--token-file")
            .arg(&token_path)
            // Signed since Wave 3c: the relay is told to drop the
            // address before it goes back to the provider pool. A
            // failure here STOPS the release (the CLI exits 1 and the
            // address stays reserved and billing) rather than handing
            // an address another customer may be issued to a box that
            // still claims it.
            .arg("--helper-ip")
            .arg(args.helper_ip)
            .arg("--priv-key")
            .arg("-");
        if !args.fip_id.is_empty() {
            cmd.arg("--fip-id").arg(args.fip_id);
        }
        if !args.fip_address.is_empty() {
            cmd.arg("--fip-address").arg(args.fip_address);
        }
        let out = run_with_piped_priv_key(cmd, priv_key);
        drop(tmp);

        let out = out?;
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: out.stderr,
            });
        }
        // The CLI reports "detached but still reserved" and "could not
        // release" on stderr with a zero exit, because neither is a
        // failure of the release — they are facts about the operator's
        // bill. Carry them up rather than dropping them: the rotation's
        // own copy says the old address no longer serves, and if it
        // still does the operator has to hear it here.
        let warnings: Vec<String> = out
            .stderr
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && (l.contains("still billing") || l.contains("still reserved")))
            .map(|l| l.to_string())
            .collect();
        Ok(ReleaseFipOutcome {
            record_json: std::fs::read_to_string(args.record_path).map_err(BridgeError::Io)?,
            warnings,
        })
    }

    fn run_decommission(&self, args: DecommissionArgs<'_>) -> Result<DecommissionResult> {
        // `--json` is an additive flag on a verb that shipped emitting
        // the bare line `decommissioned`. The app and the CLI are not
        // guaranteed to be the same vintage — on Android the deploy
        // engine is a pinned `libdaal_deploy.so` that lags the shell —
        // so an old binary rejecting the flag (flag-parse failures exit
        // 2) must degrade instead of turning a routine teardown into a
        // dead end. Retry once without it and read the legacy output.
        let (out, sent_json_flag) = match self.decommission_once(&args, true) {
            Ok(o) if o.status.code() == Some(2) => (self.decommission_once(&args, false)?, false),
            Ok(o) => (o, true),
            Err(e) => return Err(e),
        };
        if !out.status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).to_string(),
            });
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let body = stdout.trim();
        let parse_err = match serde_json::from_str::<DecommissionResult>(body) {
            Ok(res) => return Ok(res),
            Err(e) => e,
        };
        // The verb may narrate before it reports; take the last
        // non-empty line as the result document.
        if let Some(last) = body.lines().rev().find(|l| !l.trim().is_empty()) {
            if let Ok(res) = serde_json::from_str::<DecommissionResult>(last.trim()) {
                return Ok(res);
            }
        }
        // Legacy binary: exit 0 means the server call returned, and
        // nothing else was ever attempted. Claiming the key and the
        // firewall are gone here would be a lie the user acts on, so
        // report them unconfirmed and say why.
        if !sent_json_flag || body.contains("decommissioned") {
            return Ok(DecommissionResult {
                server_deleted: true,
                ssh_key_deleted: false,
                firewall_deleted: false,
                warnings: vec![
                    "this daal-deploy build removes only the server; the ephemeral SSH key and \
                     the cloud firewall may still exist in your provider account"
                        .to_string(),
                ],
            });
        }
        Err(BridgeError::Parse(parse_err))
    }

    fn run_bind_and_sign(
        &self,
        args: BindAndSignArgs<'_>,
        priv_key: &[u8],
        on_progress: &mut dyn FnMut(ProgressEvent),
    ) -> Result<BindResult> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("bind-and-sign")
            .arg("--operator-record")
            .arg(args.operator_record_path)
            .arg("--priv-key")
            .arg("-")
            .arg("--output")
            .arg(args.output_path)
            .arg("--phase")
            .arg(args.phase)
            .arg("--now-unix")
            .arg(args.now_unix.to_string())
            .arg("--expiry-days")
            .arg(args.expiry_days.to_string())
            .arg("--progress-json");
        if !args.publisher_name.is_empty() {
            cmd.arg("--publisher-name").arg(args.publisher_name);
        }
        if let Some(path) = args.subkey_cert_path {
            cmd.arg("--subkey-cert").arg(path);
        }
        // Wave 3 Step 8. Repeated, not comma-joined: the flag is a
        // repeatable list on the Go side and a URL may legitimately
        // contain a comma, so joining would silently corrupt one.
        for m in args.freshness_mirrors {
            cmd.arg("--freshness-mirror").arg(m);
        }
        let mut child = cmd
            .apply_env()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
                _ => BridgeError::Io(e),
            })?;

        // Pipe priv-key and close stdin immediately. Use a Zeroizing
        // copy so the buffer is wiped after write_all returns.
        {
            let mut stdin = child.stdin.take().expect("piped");
            let buf = Zeroizing::new(priv_key.to_vec());
            stdin.write_all(buf.as_slice())?;
            // dropping stdin closes the pipe.
        }

        let stderr = child.stderr.take().expect("piped");
        let stdout_handle = child.stdout.take().expect("piped");
        let stdout_join = std::thread::spawn(move || {
            let mut buf = String::new();
            let mut r = BufReader::new(stdout_handle);
            let _ = r.read_to_string(&mut buf);
            buf
        });

        let mut stderr_tail = String::new();
        let r = BufReader::new(stderr);
        for line in r.lines().flatten() {
            match serde_json::from_str::<ProgressEvent>(&line) {
                Ok(ev) => on_progress(ev),
                Err(_) => {
                    stderr_tail.push_str(&line);
                    stderr_tail.push('\n');
                }
            }
        }

        let status = child.wait().map_err(BridgeError::Io)?;
        let stdout_text = stdout_join.join().unwrap_or_default();
        if !status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: status.code().unwrap_or(-1),
                stderr: stderr_tail,
            });
        }
        let res: BindResult = serde_json::from_str(&stdout_text)?;
        Ok(res)
    }

    fn run_qr_fountain(
        &self,
        sbp_path: &Path,
        block_size: u32,
        max_frames: u32,
        seed: i64,
        on_frame: &mut dyn FnMut(FountainFrame) -> bool,
    ) -> Result<()> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("qr-fountain")
            .arg("--sbp")
            .arg(sbp_path)
            .arg("--block-size")
            .arg(block_size.to_string())
            .arg("--frames")
            .arg(max_frames.to_string())
            .arg("--seed")
            .arg(seed.to_string());
        let mut child = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
                _ => BridgeError::Io(e),
            })?;

        let stdout = child.stdout.take().expect("piped");
        let r = BufReader::new(stdout);
        let mut keep_going = true;
        for line in r.lines().flatten() {
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<FountainFrame>(&line) {
                Ok(frame) => {
                    if !on_frame(frame) {
                        keep_going = false;
                        break;
                    }
                }
                Err(_) => continue,
            }
        }

        // If we early-broke out of the iteration, terminate the
        // child so we don't leak the subprocess.
        if !keep_going {
            let _ = child.kill();
        }
        let status = child.wait().map_err(BridgeError::Io)?;
        if !status.success() && keep_going {
            let mut tail = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut tail);
            }
            return Err(BridgeError::SubprocessFailed {
                rc: status.code().unwrap_or(-1),
                stderr: tail,
            });
        }
        Ok(())
    }

    fn run_rotate_recommend(
        &self,
        args: RotateRecommendArgs<'_>,
    ) -> Result<RotationRecommendation> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("rotate-recommend")
            .arg("--record-file")
            .arg(args.record_path);
        let stdin_payload: Vec<u8> = if let Some(ctx) = &args.context {
            cmd.arg("--context-only");
            cmd.arg("--exposure-mode")
                .arg(if ctx.exposure_mode.is_empty() {
                    "direct_vps"
                } else {
                    ctx.exposure_mode.as_str()
                });
            for c in &ctx.failure_classifications {
                cmd.arg("--classification").arg(c);
            }
            for s in &ctx.network_signals {
                cmd.arg("--signal").arg(s);
            }
            if ctx.credential_leak_suspected {
                cmd.arg("--credential-leak");
            }
            Vec::new()
        } else if let Some(json) = args.explanation_json {
            json.as_bytes().to_vec()
        } else {
            // Empty stdin ⇒ recommender returns the L1 default
            // with low confidence (matches the Go implementation).
            Vec::new()
        };

        let mut child = cmd
            .apply_env()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
                _ => BridgeError::Io(e),
            })?;
        {
            let mut stdin = child.stdin.take().expect("piped");
            stdin.write_all(&stdin_payload)?;
        }
        let stdout_handle = child.stdout.take().expect("piped");
        let stderr = child.stderr.take().expect("piped");
        let stdout_join = std::thread::spawn(move || {
            let mut buf = String::new();
            let mut r = BufReader::new(stdout_handle);
            let _ = r.read_to_string(&mut buf);
            buf
        });
        let mut stderr_text = String::new();
        let mut stderr_reader = BufReader::new(stderr);
        let _ = stderr_reader.read_to_string(&mut stderr_text);
        let status = child.wait().map_err(BridgeError::Io)?;
        let stdout_text = stdout_join.join().unwrap_or_default();
        if !status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: status.code().unwrap_or(-1),
                stderr: stderr_text,
            });
        }
        let parsed: RotationRecommendation = serde_json::from_str(&stdout_text)?;
        Ok(parsed)
    }

    fn run_users_provision(
        &self,
        args: UsersProvisionArgs<'_>,
        priv_key: &[u8],
    ) -> Result<UserCredsResult> {
        let stdout = run_users_subprocess(
            &self.binary,
            "users-provision",
            args.record_path,
            args.helper_ip,
            args.token,
            Some(args.name),
            priv_key,
        )?;
        Ok(serde_json::from_str(&stdout)?)
    }

    fn run_users_revoke(
        &self,
        args: UsersRevokeArgs<'_>,
        priv_key: &[u8],
    ) -> Result<UsersRevokeResult> {
        let stdout = run_users_subprocess(
            &self.binary,
            "users-revoke",
            args.record_path,
            args.helper_ip,
            args.token,
            Some(args.name),
            priv_key,
        )?;
        Ok(serde_json::from_str(&stdout)?)
    }

    fn run_rotate_credentials(
        &self,
        args: RotateCredentialsArgs<'_>,
        priv_key: &[u8],
    ) -> Result<RotateCredentialsResult> {
        let stdout = run_users_subprocess(
            &self.binary,
            "rotate-credentials",
            args.record_path,
            args.helper_ip,
            args.token,
            Some(args.name),
            priv_key,
        )?;
        Ok(serde_json::from_str(&stdout)?)
    }

    fn run_rotate_tls(
        &self,
        args: RotateTlsArgs<'_>,
        priv_key: &[u8],
    ) -> Result<RotateTlsResult> {
        let stdout = run_users_subprocess(
            &self.binary,
            "rotate-tls",
            args.record_path,
            args.helper_ip,
            args.token,
            // No --name. rotate-tls is relay-wide by definition; passing
            // a recipient here would imply a scope it does not have.
            None,
            priv_key,
        )?;
        Ok(serde_json::from_str(&stdout)?)
    }

    fn run_users_list(
        &self,
        args: UsersListArgs<'_>,
        priv_key: &[u8],
    ) -> Result<Vec<UserMetaResult>> {
        let stdout = run_users_subprocess(
            &self.binary,
            "users-list",
            args.record_path,
            args.helper_ip,
            args.token,
            None,
            priv_key,
        )?;
        #[derive(Deserialize)]
        struct Wrap {
            users: Vec<UserMetaResult>,
        }
        let w: Wrap = serde_json::from_str(&stdout)?;
        Ok(w.users)
    }

    fn run_users_pack_sbpx(&self, args: UsersPackSbpxArgs<'_>) -> Result<UsersPackSbpxResult> {
        // Local file I/O only — no priv-key, no token, no record.
        let mut cmd = Command::new(&self.binary);
        cmd.arg("users-pack-sbpx")
            .arg("--in")
            .arg(args.in_sbp_path)
            .arg("--recipient-pub-hex")
            .arg(args.recipient_pub_hex)
            .arg("--out")
            .arg(args.out_sbpx_path);
        if let (Some(creds), Some(server)) = (args.creds_file_path, args.server) {
            cmd.arg("--creds-file").arg(creds).arg("--server").arg(server);
            if let Some(sni) = args.cover_sni.filter(|s| !s.is_empty()) {
                cmd.arg("--cover-sni").arg(sni);
            }
        }
        let mut child = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
                _ => BridgeError::Io(e),
            })?;
        let mut stdout_text = String::new();
        let mut stderr_text = String::new();
        if let Some(mut s) = child.stdout.take() {
            let _ = s.read_to_string(&mut stdout_text);
        }
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut stderr_text);
        }
        let status = child.wait().map_err(BridgeError::Io)?;
        if !status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: status.code().unwrap_or(-1),
                stderr: stderr_text,
            });
        }
        Ok(serde_json::from_str(&stdout_text)?)
    }

    fn run_users_pack_sbp(&self, args: UsersPackSbpArgs<'_>) -> Result<UsersPackSbpResult> {
        // Local file I/O only — no priv-key, no token, no record.
        let mut cmd = Command::new(&self.binary);
        cmd.arg("users-pack-sbp")
            .arg("--in")
            .arg(args.in_sbp_path)
            .arg("--creds-file")
            .arg(args.creds_file_path)
            .arg("--server")
            .arg(args.server)
            .arg("--out")
            .arg(args.out_sbp_path);
        if let Some(sni) = args.cover_sni.filter(|s| !s.is_empty()) {
            cmd.arg("--cover-sni").arg(sni);
        }
        let mut child = cmd
            .apply_env()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
                _ => BridgeError::Io(e),
            })?;
        let mut stdout_text = String::new();
        let mut stderr_text = String::new();
        if let Some(mut s) = child.stdout.take() {
            let _ = s.read_to_string(&mut stdout_text);
        }
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut stderr_text);
        }
        let status = child.wait().map_err(BridgeError::Io)?;
        if !status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: status.code().unwrap_or(-1),
                stderr: stderr_text,
            });
        }
        Ok(serde_json::from_str(&stdout_text)?)
    }

    fn run_users_unpack_sbpx(
        &self,
        args: UsersUnpackSbpxArgs<'_>,
        priv_key_hex: &str,
    ) -> Result<UsersUnpackSbpxResult> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("users-unpack-sbpx")
            .arg("--in")
            .arg(args.in_sbpx_path)
            .arg("--out")
            .arg(args.out_sbp_path);
        let mut child = cmd
            .apply_env()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
                _ => BridgeError::Io(e),
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(priv_key_hex.as_bytes())
                .map_err(BridgeError::Io)?;
        }
        let mut stdout_text = String::new();
        let mut stderr_text = String::new();
        if let Some(mut s) = child.stdout.take() {
            let _ = s.read_to_string(&mut stdout_text);
        }
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut stderr_text);
        }
        let status = child.wait().map_err(BridgeError::Io)?;
        if !status.success() {
            return Err(BridgeError::SubprocessFailed {
                rc: status.code().unwrap_or(-1),
                stderr: stderr_text,
            });
        }
        Ok(serde_json::from_str(&stdout_text)?)
    }
}

/// What [`run_with_piped_priv_key`] collected: the exit status plus both
/// streams already decoded, so callers never hold the raw bytes of a run
/// that had a secret on its stdin.
struct PipedOutput {
    status: std::process::ExitStatus,
    #[allow(dead_code)]
    stdout: String,
    stderr: String,
}

/// Wave 3c: run a subcommand that reads the publisher signing key from
/// stdin (`--priv-key -`) and returns both streams.
///
/// The key is written to a pipe and never to disk, and the buffer is a
/// `Zeroizing` copy that is wiped when this frame ends — the same rule
/// `run_users_subprocess` follows. It exists separately because the
/// floating-IP verbs take a different flag set (`--fip-id`,
/// `--skip-unbind`) and folding them into the users driver would mean a
/// driver whose argv depends on which of six verbs it was handed.
///
/// stdout is drained on its own thread while stderr is read here: a
/// child that fills one pipe's buffer while the parent is blocked
/// reading the other deadlocks, and `assign-fip` writes an
/// OperatorRecord to stdout and progress lines to stderr at the same
/// time.
fn run_with_piped_priv_key(mut cmd: Command, priv_key: &[u8]) -> Result<PipedOutput> {
    let mut child = cmd
        .apply_env()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
            _ => BridgeError::Io(e),
        })?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        let buf = Zeroizing::new(priv_key.to_vec());
        stdin.write_all(buf.as_slice())?;
    }
    let stdout_handle = child.stdout.take().expect("piped");
    let stderr_handle = child.stderr.take().expect("piped");
    let stdout_join = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = BufReader::new(stdout_handle).read_to_string(&mut buf);
        buf
    });
    let mut stderr_text = String::new();
    let _ = BufReader::new(stderr_handle).read_to_string(&mut stderr_text);
    let status = child.wait().map_err(BridgeError::Io)?;
    Ok(PipedOutput {
        status,
        stdout: stdout_join.join().unwrap_or_default(),
        stderr: stderr_text,
    })
}

// FRP-14: shared driver for every mgmt-plane subcommand that takes the
// same four inputs — the three users-* verbs and, since Wave 3 Step 7,
// rotate-credentials / rotate-tls. Pipes `priv_key` through stdin
// (never to disk) and the cloud-provider token through a mode-0600
// tempfile. `name` is threaded through as `--name` when present, which
// is exactly the flag that separates a per-recipient operation from a
// relay-wide one.
fn run_users_subprocess(
    binary: &Path,
    subcommand: &str,
    record_path: &Path,
    helper_ip: &str,
    token: &str,
    name: Option<&str>,
    priv_key: &[u8],
) -> Result<String> {
    let token_tmp = tempfile_with_secret(token)?;
    let token_path = token_tmp.path().to_path_buf();

    let mut cmd = Command::new(binary);
    cmd.arg(subcommand)
        .arg("--record-file")
        .arg(record_path)
        .arg("--helper-ip")
        .arg(helper_ip)
        .arg("--token-file")
        .arg(&token_path)
        .arg("--priv-key")
        .arg("-");
    if let Some(n) = name {
        cmd.arg("--name").arg(n);
    }
    let mut child = cmd
        .apply_env()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => BridgeError::BinaryMissing,
            _ => BridgeError::Io(e),
        })?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        let buf = Zeroizing::new(priv_key.to_vec());
        stdin.write_all(buf.as_slice())?;
    }
    let stdout_handle = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let stdout_join = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut r = BufReader::new(stdout_handle);
        let _ = r.read_to_string(&mut buf);
        buf
    });
    let mut stderr_text = String::new();
    let _ = BufReader::new(stderr).read_to_string(&mut stderr_text);
    let status = child.wait().map_err(BridgeError::Io)?;
    drop(token_tmp);
    let stdout_text = stdout_join.join().unwrap_or_default();
    if !status.success() {
        return Err(BridgeError::SubprocessFailed {
            rc: status.code().unwrap_or(-1),
            stderr: stderr_text,
        });
    }
    Ok(stdout_text)
}

/// `MockRunner` is the in-process stand-in for tests.
pub struct MockRunner {
    pub fixture: Pricing,
    pub last_call: Mutex<Option<MockCall>>,
    /// FRP-4b/FRP-7: count live provision calls.
    pub provision_calls: Mutex<usize>,
    /// Wave 2: the `--cover-sni` each `run_provision` was handed. The L2
    /// rotation's whole payload travels in this argument, and omitting
    /// it silently returns the relay to the burned cover host, so a test
    /// has to be able to see it.
    pub provision_cover_snis: Mutex<Vec<String>>,
    /// Step 10: the `(provider, region)` each `run_provision` was
    /// handed. L4's whole payload is the region and L5's is the
    /// provider, and both were previously read off the EXISTING record
    /// — which made both rungs byte-identical to L1 while still
    /// destroying the box. Only a recorded transcript catches that:
    /// the rotation succeeds either way.
    pub provision_targets: Mutex<Vec<(String, String)>>,
    /// Wave 6: the `(token, server_type)` each `run_provision` was
    /// handed, and the token each `run_reprovision` was handed.
    ///
    /// These exist because L5 is the one rung whose two legs run
    /// against DIFFERENT cloud accounts — `reprovision` deletes on the
    /// provider being left, `provision` creates on the one being moved
    /// to — and an operator row stores exactly one credential. The
    /// arm previously passed that single stored token to both, so a
    /// live L5 deleted the relay and was then refused by the new
    /// provider, leaving nothing to roll back to. A transcript is the
    /// only thing that catches it: with a mock that ignores
    /// credentials the rotation succeeds either way, which is exactly
    /// how the old test passed while the rung could only destroy.
    pub provision_tokens: Mutex<Vec<String>>,
    pub provision_server_types: Mutex<Vec<String>>,
    pub reprovision_tokens: Mutex<Vec<String>>,
    /// Wave 6: the `(toolbox_profile, families)` each `run_provision`
    /// was handed.
    ///
    /// L6's whole payload is the profile, and the families are what the
    /// Go side INTERSECTS it against — `candidatesForProfile` keeps a
    /// profile candidate only if the supplied family list also names
    /// it. So the pair is what decides the rebuilt relay's wire shape,
    /// and neither half is visible in the rotation's return value: an
    /// L6 that forwarded the wrong profile, or forwarded the right one
    /// with a family list that makes it a no-op, succeeds exactly like
    /// one that worked. Only a recorded transcript can tell them apart.
    pub provision_profiles: Mutex<Vec<(String, Vec<String>)>>,
    /// Wave 6: the `(provider, region, token)` of every
    /// `run_list_server_types` call, in order, and the catalogue it
    /// answers with.
    ///
    /// This is not bookkeeping. `list-server-types` is the READ-ONLY
    /// PREFLIGHT the L4/L5 guards run before the destroying legs: it is
    /// the single call that proves the credential authenticates on the
    /// target provider, that the region code exists in that provider's
    /// vocabulary, and that the plan is sold there. All three are
    /// otherwise discovered by `provision` — which runs after
    /// `reprovision` has already deleted the relay.
    ///
    /// A mock that answers the same catalogue to every caller cannot
    /// tell a preflight that ran from one that did not, and cannot
    /// express "this plan is not sold in that region" at all — so the
    /// guard would test green against a mock while a live L5 into a
    /// mistyped region still ended the relay. `server_type_catalogue`
    /// lets a test say what the target account actually offers, and
    /// `list_server_type_calls` proves the preflight asked the RIGHT
    /// account: an L5 preflight that asks the old provider with the old
    /// token proves nothing about the new one.
    pub list_server_type_calls: Mutex<Vec<(String, String, String)>>,
    pub server_type_catalogue: Mutex<Option<Vec<ServerTypeOption>>>,
    /// Make the preflight UNANSWERABLE. A 401 from a mistyped token is
    /// an error, not an empty catalogue, and the two must not be
    /// conflated: the guard has to refuse on both, and only an
    /// injected failure reaches the branch that decides so.
    pub list_server_types_error: Mutex<Option<String>>,
    /// Wave 6: the account audit the app can now run for itself.
    /// Make `run_provision` fail. The only way to reach the state that
    /// matters most on this ladder: the delete leg has succeeded, so
    /// the relay is already gone, and the build leg then refuses.
    pub provision_error: Mutex<Option<String>>,
    pub account_audit_calls: Mutex<usize>,
    pub account_audit_result: Mutex<Option<AccountAuditReport>>,
    /// FRP-4b: optional canned record JSON for `run_provision`.
    pub provision_record_json: Mutex<Option<String>>,
    /// FRP-8: optional canned CDN front for `run_cdn_provision`.
    pub cdn_front_result: Mutex<Option<CdnFrontResult>>,
    /// FRP-4b: optional canned bind result for `run_bind_and_sign`.
    pub bind_result: Mutex<Option<BindResult>>,
    /// Wave 6: make `run_release_fip` fail. Used to reach the branch
    /// where a rotation's unwind cannot give back the address it took —
    /// the leak the operator has to be told about by name.
    pub release_fip_error: Mutex<Option<String>>,
    /// Wave 6: make `run_bind_and_sign` fail. The re-sign is the first
    /// step of a rotation that runs AFTER the provider has been mutated,
    /// so it is the seam a test uses to ask what an L3 does when it
    /// fails with an address already attached and billing.
    pub bind_error: Mutex<Option<String>>,
    /// FRP-4b: a recorded copy of the priv-key bytes the wizard
    /// pushed through stdin. Used by tests to verify the end-to-end
    /// transport without leaving keys on disk.
    pub last_priv_key: Mutex<Option<Vec<u8>>>,
    /// FRP-7.5: recorded sub-key cert path supplied to
    /// bind-and-sign, if the wizard selected the active sub-key.
    pub last_subkey_cert_path: Mutex<Option<PathBuf>>,
    /// Every `--phase` value bind-and-sign was called with, in call
    /// order. The initial sign and a later rotation's re-sign must
    /// agree; they did not, and only a recorded transcript catches
    /// that (both calls succeed either way).
    pub bind_phases: Mutex<Vec<String>>,
    /// Wave 3 Step 8: the `--freshness-mirror` set passed on each
    /// bind-and-sign, newest last. A pack's mirror set is the only
    /// thing that decides whether a rotation can heal itself, so a test
    /// has to be able to see exactly what was baked in.
    pub bind_freshness_mirrors: Mutex<Vec<Vec<String>>>,
    /// Wave 4 Step 11: the `.sbp` path the last `run_qr_fountain` was
    /// pointed at. The QR sender can only be wrong in one way that
    /// nothing downstream notices — streaming the wrong file, flawlessly
    /// — so a test has to be able to see which file it opened.
    pub last_qr_fountain_path: Mutex<Option<PathBuf>>,
    /// FRP-7: optional canned rotation recommendation.
    pub rotation_recommendation: Mutex<Option<RotationRecommendation>>,
    /// FRP-7: recorded reprovision calls.
    pub reprovision_calls: Mutex<Vec<MockReprovisionCall>>,
    /// FRP-7: recorded floating-IP assign calls.
    pub assign_fip_calls: Mutex<Vec<MockAssignFipCall>>,
    /// `"<fip_id> <fip_address>"` per `floating-ip release` call, in
    /// order. The rotation must release the PRIOR address after the
    /// history row commits, and only then — before it, a failure
    /// strands every distributed pack on an address that routes
    /// nowhere. The ADDRESS is recorded alongside the id because the
    /// id alone is what the provider needs and the address is what the
    /// RELAY needs: a release that cannot name the address cannot tell
    /// the box to drop it, and the real CLI refuses rather than hand a
    /// live box's address back to the provider pool.
    pub release_fip_calls: Mutex<Vec<String>>,
    /// When set, `run_assign_fip` fails with this exit code and
    /// stderr instead of swapping. Exit 3 is the rotation verbs'
    /// reserved "this relay's software predates the operation" code,
    /// which is the answer EVERY relay in the field gives for L3 until
    /// the box artifact is re-released — so a test has to be able to
    /// reach it.
    pub assign_fip_error: Mutex<Option<(i32, String)>>,
    /// Teardown: recorded decommission calls.
    pub decommission_calls: Mutex<Vec<MockDecommissionCall>>,
    /// Teardown: optional canned result for `run_decommission`.
    /// `None` means "clean sweep, no warnings".
    pub decommission_result: Mutex<Option<DecommissionResult>>,
    /// Teardown: when set, `run_decommission` fails with this stderr
    /// instead of succeeding. Tests use it to prove a cloud failure
    /// leaves the local relay record intact.
    pub decommission_error: Mutex<Option<String>>,
    /// FRP-9: recorded CDN-rotate-path calls.
    pub cdn_rotate_path_calls: Mutex<Vec<MockCdnRotatePathCall>>,
    /// FRP-9: recorded CDN-rotate-hostname calls.
    pub cdn_rotate_hostname_calls: Mutex<Vec<MockCdnRotateHostnameCall>>,
    /// FRP-9: recorded CDN-rotate-origin calls.
    pub cdn_rotate_origin_calls: Mutex<Vec<MockCdnRotateOriginCall>>,
    /// FRP-9: recorded publish-freshness calls.
    pub publish_freshness_calls: Mutex<Vec<MockPublishFreshnessCall>>,
    /// Provider labels the mock should report as REFUSING the write.
    /// Lets a test drive the degraded-publish path without a network.
    pub publish_freshness_fail: Mutex<Vec<String>>,
    /// FRP-14: optional canned per-recipient credentials returned
    /// by `run_users_provision`.
    pub users_provision_result: Mutex<Option<UserCredsResult>>,
    /// FRP-14: optional canned response returned by
    /// `run_users_revoke`.
    pub users_revoke_result: Mutex<Option<UsersRevokeResult>>,
    /// FRP-14: optional canned roster returned by
    /// `run_users_list`.
    pub users_list_result: Mutex<Option<Vec<UserMetaResult>>>,
    /// FRP-14: a recorded copy of every provision call (name).
    pub users_provision_calls: Mutex<Vec<String>>,
    /// FRP-14: a recorded copy of every revoke call (name).
    pub users_revoke_calls: Mutex<Vec<String>>,
    /// FRP-14: count of list calls.
    pub users_list_calls: Mutex<usize>,
    /// FRP-14 Layer 3b.5: recorded pack-sbpx calls.
    pub users_pack_sbpx_calls: Mutex<Vec<MockPackSbpxCall>>,
    /// Wave 3 Step 7: recorded rotate-credentials calls (name).
    pub rotate_credentials_calls: Mutex<Vec<String>>,
    /// Wave 3 Step 7: canned rotate-credentials response. Tests set
    /// this to fake a relay whose mgmt binary answers in the old,
    /// unscoped shape.
    pub rotate_credentials_result: Mutex<Option<RotateCredentialsResult>>,
    /// Wave 3 Step 7: count of rotate-tls calls.
    pub rotate_tls_calls: Mutex<usize>,
    /// Wave 3 Step 7: canned rotate-tls response.
    pub rotate_tls_result: Mutex<Option<RotateTlsResult>>,
    /// Wave 3 Step 7: make rotate-tls FAIL after it has already
    /// rewritten the record. That combination is not contrived — it is
    /// the CLI's documented behaviour: `mgmt.RotateTLSWithFW` returns a
    /// response alongside an error when the box applied something the
    /// publisher disagrees with, and `runRotateTLS` persists the record
    /// and prints the JSON before exiting non-zero. Callers that consume
    /// the read-back only on the Ok path lose the new cover host exactly
    /// here.
    pub rotate_tls_err: Mutex<Option<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockPackSbpxCall {
    pub in_sbp_path: PathBuf,
    pub recipient_pub_hex: String,
    pub out_sbpx_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockPublishFreshnessCall {
    pub relay_pack_id: String,
    pub current_bundle_sha256: String,
    pub current_signed_url: String,
    pub used_subkey: bool,
    /// Wave 3 Step 8: the `provider=url` set the wizard advertised.
    pub mirrors: Vec<String>,
    /// True when upload credentials were staged, i.e. the call was a
    /// real publish rather than a build-and-sign.
    pub uploaded: bool,
    /// The prior relay_pack_ids the document claims to supersede. This
    /// is what decides whether the document reaches anybody after a
    /// rotation: the pack id is a hash of the fields the ladder
    /// changes, so the rung that repairs a relay also renames its pack.
    pub supersedes: Vec<String>,
    /// The monotonic counter and the caller's high-water mark. The
    /// sequence must strictly advance or every recipient that already
    /// accepted a higher one refuses the document as a rollback.
    pub sequence: u64,
    pub min_sequence: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockCdnRotatePathCall {
    pub front_id: i64,
    pub hostname: String,
    pub new_public_path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockCdnRotateHostnameCall {
    pub front_id: i64,
    pub old_hostname: String,
    pub new_hostname: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockCdnRotateOriginCall {
    pub front_id: i64,
    pub hostname: String,
    pub new_origin_ipv4: String,
    pub new_origin_ipv6: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockCall {
    pub provider: String,
    pub region: String,
    pub server_type: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockReprovisionCall {
    pub regen_credentials: bool,
    pub new_sni: Option<String>,
    pub new_ws_path: Option<String>,
    pub new_toolbox_profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockAssignFipCall {
    pub fip_id: String,
    /// Wave 3c: the two inputs the guest-OS half of the swap needs. The
    /// real CLI exits 2 without them, before it reserves anything, so a
    /// mock that did not record them could not tell a wired L3 from one
    /// that will refuse on contact with a relay.
    pub helper_ip: String,
    pub priv_key_len: usize,
}

/// The record body is captured, not just its path: the staged file
/// is deleted the moment `relay_destroy` returns, so a test that only
/// kept the path could never assert *which* server the app asked the
/// cloud to destroy.
#[derive(Debug, Clone, PartialEq)]
pub struct MockDecommissionCall {
    pub record_path: PathBuf,
    pub record_json: String,
    pub token: String,
}

impl MockRunner {
    pub fn new(fixture: Pricing) -> Self {
        Self {
            fixture,
            last_call: Mutex::new(None),
            provision_calls: Mutex::new(0),
            provision_cover_snis: Mutex::new(Vec::new()),
            provision_targets: Mutex::new(Vec::new()),
            provision_tokens: Mutex::new(Vec::new()),
            provision_server_types: Mutex::new(Vec::new()),
            reprovision_tokens: Mutex::new(Vec::new()),
            provision_profiles: Mutex::new(Vec::new()),
            list_server_type_calls: Mutex::new(Vec::new()),
            server_type_catalogue: Mutex::new(None),
            list_server_types_error: Mutex::new(None),
            provision_error: Mutex::new(None),
            account_audit_calls: Mutex::new(0),
            account_audit_result: Mutex::new(None),
            provision_record_json: Mutex::new(None),
            cdn_front_result: Mutex::new(None),
            bind_result: Mutex::new(None),
            bind_error: Mutex::new(None),
            release_fip_error: Mutex::new(None),
            last_priv_key: Mutex::new(None),
            last_subkey_cert_path: Mutex::new(None),
            bind_phases: Mutex::new(Vec::new()),
            bind_freshness_mirrors: Mutex::new(Vec::new()),
            last_qr_fountain_path: Mutex::new(None),
            rotation_recommendation: Mutex::new(None),
            reprovision_calls: Mutex::new(Vec::new()),
            publish_freshness_fail: Mutex::new(Vec::new()),
            assign_fip_calls: Mutex::new(Vec::new()),
            release_fip_calls: Mutex::new(Vec::new()),
            decommission_calls: Mutex::new(Vec::new()),
            decommission_result: Mutex::new(None),
            assign_fip_error: Mutex::new(None),
            decommission_error: Mutex::new(None),
            cdn_rotate_path_calls: Mutex::new(Vec::new()),
            cdn_rotate_hostname_calls: Mutex::new(Vec::new()),
            cdn_rotate_origin_calls: Mutex::new(Vec::new()),
            publish_freshness_calls: Mutex::new(Vec::new()),
            users_provision_result: Mutex::new(None),
            users_revoke_result: Mutex::new(None),
            users_list_result: Mutex::new(None),
            users_provision_calls: Mutex::new(Vec::new()),
            users_revoke_calls: Mutex::new(Vec::new()),
            users_list_calls: Mutex::new(0),
            users_pack_sbpx_calls: Mutex::new(Vec::new()),
            rotate_credentials_calls: Mutex::new(Vec::new()),
            rotate_credentials_result: Mutex::new(None),
            rotate_tls_calls: Mutex::new(0),
            rotate_tls_result: Mutex::new(None),
            rotate_tls_err: Mutex::new(None),
        }
    }

    /// FRP-7: stamp a canned recommendation that
    /// `run_rotate_recommend` will return.
    pub fn with_rotation_recommendation(self, r: RotationRecommendation) -> Self {
        *self.rotation_recommendation.lock().unwrap() = Some(r);
        self
    }

    /// What the target cloud account offers, by plan id.
    ///
    /// The ids are all the L4/L5 preflight compares, so a test only has
    /// to name them. Use this to build a target region that genuinely
    /// does NOT sell the relay's plan — the case that, without the
    /// preflight, deletes the relay and then fails to rebuild it.
    pub fn with_server_types(self, ids: &[&str]) -> Self {
        *self.server_type_catalogue.lock().unwrap() = Some(
            ids.iter()
                .map(|id| ServerTypeOption {
                    id: (*id).to_string(),
                    description: (*id).to_string(),
                    cpus: 1,
                    memory_gb: 1.0,
                    disk_gb: 25,
                    monthly_eur: 5.0,
                    hourly_eur: 0.007,
                    location: String::new(),
                    arch: "x86".into(),
                    currency: "EUR".into(),
                })
                .collect(),
        );
        self
    }

    /// The target account refuses the read entirely — a 401, a
    /// network failure, a provider outage. All of them must refuse the
    /// rebuild rather than proceed on an unanswered question.
    pub fn with_provision_error(self, msg: impl Into<String>) -> Self {
        *self.provision_error.lock().unwrap() = Some(msg.into());
        self
    }

    pub fn with_list_server_types_error(self, msg: impl Into<String>) -> Self {
        *self.list_server_types_error.lock().unwrap() = Some(msg.into());
        self
    }

    pub fn with_provision_record(self, json: impl Into<String>) -> Self {
        *self.provision_record_json.lock().unwrap() = Some(json.into());
        self
    }

    pub fn with_cdn_front_result(self, res: CdnFrontResult) -> Self {
        *self.cdn_front_result.lock().unwrap() = Some(res);
        self
    }

    /// The freshness mirror set baked into the most recent bind.
    pub fn last_freshness_mirrors(&self) -> Vec<String> {
        self.bind_freshness_mirrors
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    pub fn with_bind_result(self, res: BindResult) -> Self {
        *self.bind_result.lock().unwrap() = Some(res);
        self
    }

    /// Teardown: stamp the per-resource result `run_decommission`
    /// will return — used to exercise the partial-sweep path where
    /// the server dies but a warning comes back with it.
    pub fn with_decommission_result(self, res: DecommissionResult) -> Self {
        *self.decommission_result.lock().unwrap() = Some(res);
        self
    }

    /// Teardown: make `run_decommission` fail. The relay's local row
    /// and cloud token must survive that, so this is the switch the
    /// ordering test is built on.
    /// Make `run_assign_fip` fail the way a real relay does. Exit 3 is
    /// the capability refusal the UI must render as `pub.rotate.too_old`
    /// in the operator's own language, not as a developer sentence.
    /// Make the re-sign fail, which is the cheapest way to reach a
    /// rotation's mid-flight failure path: the provider mutation has
    /// already landed and nothing has been committed.
    pub fn with_bind_error(self, stderr: impl Into<String>) -> Self {
        *self.bind_error.lock().unwrap() = Some(stderr.into());
        self
    }

    pub fn with_release_fip_error(self, stderr: impl Into<String>) -> Self {
        *self.release_fip_error.lock().unwrap() = Some(stderr.into());
        self
    }

    pub fn with_assign_fip_error(self, rc: i32, stderr: impl Into<String>) -> Self {
        *self.assign_fip_error.lock().unwrap() = Some((rc, stderr.into()));
        self
    }

    pub fn with_decommission_error(self, stderr: impl Into<String>) -> Self {
        *self.decommission_error.lock().unwrap() = Some(stderr.into());
        self
    }
}

impl CliRunner for MockRunner {
    fn run_list_servers(&self, _provider: &str, _token: &str) -> Result<Vec<ExistingServer>> {
        Ok(vec![])
    }

    fn run_list_server_types(
        &self,
        provider: &str,
        region: &str,
        token: &str,
    ) -> Result<Vec<ServerTypeOption>> {
        self.list_server_type_calls.lock().unwrap().push((
            provider.to_string(),
            region.to_string(),
            token.to_string(),
        ));
        if let Some(e) = self.list_server_types_error.lock().unwrap().as_ref() {
            return Err(BridgeError::SubprocessFailed {
                rc: 1,
                stderr: e.clone(),
            });
        }
        if let Some(c) = self.server_type_catalogue.lock().unwrap().as_ref() {
            return Ok(c.clone());
        }
        Ok(vec![
            ServerTypeOption {
                id: "cax11".into(),
                description: "CAX11".into(),
                cpus: 2,
                memory_gb: 4.0,
                disk_gb: 40,
                monthly_eur: 3.79,
                hourly_eur: 0.006,
                location: "fsn1".into(),
                arch: "arm".into(),
                currency: "EUR".into(),
            },
            ServerTypeOption {
                id: "cx22".into(),
                description: "CX22".into(),
                cpus: 2,
                memory_gb: 4.0,
                disk_gb: 40,
                monthly_eur: 4.59,
                hourly_eur: 0.007,
                location: "fsn1".into(),
                arch: "x86".into(),
                currency: "EUR".into(),
            },
        ])
    }

    fn run_account_audit(&self, provider: &str, _token: &str) -> Result<AccountAuditReport> {
        *self.account_audit_calls.lock().unwrap() += 1;
        if let Some(r) = self.account_audit_result.lock().unwrap().as_ref() {
            return Ok(r.clone());
        }
        Ok(AccountAuditReport {
            provider: provider.to_string(),
            resources: vec![],
            server_list_complete: true,
            warnings: vec![],
        })
    }

    fn run_pricing(
        &self,
        provider: &str,
        region: &str,
        server_type: &str,
        token: &str,
    ) -> Result<Pricing> {
        *self.last_call.lock().unwrap() = Some(MockCall {
            provider: provider.to_string(),
            region: region.to_string(),
            server_type: server_type.to_string(),
            token: token.to_string(),
        });
        Ok(self.fixture.clone())
    }

    fn run_provision(
        &self,
        args: ProvisionArgs<'_>,
        on_progress: &mut dyn FnMut(ProgressEvent),
    ) -> Result<String> {
        *self.provision_calls.lock().unwrap() += 1;
        if let Some(e) = self.provision_error.lock().unwrap().clone() {
            return Err(BridgeError::SubprocessFailed { rc: 1, stderr: e });
        }
        self.provision_cover_snis
            .lock()
            .unwrap()
            .push(args.cover_sni.to_string());
        self.provision_targets
            .lock()
            .unwrap()
            .push((args.provider.to_string(), args.region.to_string()));
        self.provision_tokens
            .lock()
            .unwrap()
            .push(args.token.to_string());
        self.provision_server_types
            .lock()
            .unwrap()
            .push(args.server_type.to_string());
        self.provision_profiles.lock().unwrap().push((
            args.toolbox_profile.to_string(),
            args.families.iter().map(|f| f.to_string()).collect(),
        ));
        on_progress(ProgressEvent {
            step: "provision_start".into(),
            message: "starting".into(),
            ts: String::new(),
            extra: Default::default(),
        });
        on_progress(ProgressEvent {
            step: "provision_done".into(),
            message: "done".into(),
            ts: String::new(),
            extra: Default::default(),
        });
        let json = self
            .provision_record_json
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| {
                r#"{"provider":"hetzner","server_id":"mock-1","region":"fsn1","server_type":"cx22","public_ip":"5.75.0.1","candidates":[]}"#.to_string()
            });
        Ok(json)
    }

    fn run_cdn_provision(&self, _args: CdnProvisionArgs<'_>) -> Result<CdnFrontResult> {
        if let Some(res) = self.cdn_front_result.lock().unwrap().clone() {
            return Ok(res);
        }
        Ok(CdnFrontResult {
            hostname: "momsroute.example.com".into(),
            zone_id: "zone-example".into(),
            public_path: "/r/mock".into(),
            origin_path: "/ws".into(),
            worker_route_id: "route-example".into(),
            firewall_id: "fw-example".into(),
            origin_ca_fingerprint: "a".repeat(64),
            origin_ca_cert_path: "/tmp/origin_ca.pem".into(),
            origin_ca_priv_path: "/tmp/origin_ca.key".into(),
            aop_client_cert_path: "/tmp/aop_client.pem".into(),
            aop_enabled: true,
        })
    }

    fn run_cdn_rotate_path(&self, args: CdnRotatePathArgs<'_>) -> Result<CdnRotateResult> {
        self.cdn_rotate_path_calls
            .lock()
            .unwrap()
            .push(MockCdnRotatePathCall {
                front_id: args.front_id,
                hostname: args.hostname.to_string(),
                new_public_path: args.new_public_path.to_string(),
            });
        Ok(CdnRotateResult {
            hostname: args.hostname.to_string(),
            zone_id: args.zone_id.to_string(),
            public_path: args.new_public_path.to_string(),
            worker_route_id: format!("route-{}-rotated", args.zone_id),
            ..Default::default()
        })
    }

    fn run_cdn_rotate_hostname(&self, args: CdnRotateHostnameArgs<'_>) -> Result<CdnRotateResult> {
        self.cdn_rotate_hostname_calls
            .lock()
            .unwrap()
            .push(MockCdnRotateHostnameCall {
                front_id: args.front_id,
                old_hostname: args.old_hostname.to_string(),
                new_hostname: args.new_hostname.to_string(),
            });
        Ok(CdnRotateResult {
            hostname: args.new_hostname.to_string(),
            zone_id: format!("zone-{}", args.new_hostname),
            public_path: args.public_path.to_string(),
            worker_route_id: format!("route-{}-rebound", args.new_hostname),
            origin_ipv4: args.origin_ipv4.to_string(),
            origin_ipv6: args.origin_ipv6.to_string(),
        })
    }

    fn run_cdn_rotate_origin(&self, args: CdnRotateOriginArgs<'_>) -> Result<CdnRotateResult> {
        self.cdn_rotate_origin_calls
            .lock()
            .unwrap()
            .push(MockCdnRotateOriginCall {
                front_id: args.front_id,
                hostname: args.hostname.to_string(),
                new_origin_ipv4: args.new_origin_ipv4.to_string(),
                new_origin_ipv6: args.new_origin_ipv6.to_string(),
            });
        Ok(CdnRotateResult {
            hostname: args.hostname.to_string(),
            zone_id: args.zone_id.to_string(),
            origin_ipv4: args.new_origin_ipv4.to_string(),
            origin_ipv6: args.new_origin_ipv6.to_string(),
            ..Default::default()
        })
    }

    fn run_publish_freshness(
        &self,
        args: PublishFreshnessArgs<'_>,
    ) -> Result<PublishFreshnessResult> {
        self.publish_freshness_calls
            .lock()
            .unwrap()
            .push(MockPublishFreshnessCall {
                relay_pack_id: args.relay_pack_id.to_string(),
                current_bundle_sha256: args.current_bundle_sha256.to_string(),
                current_signed_url: args.current_signed_url.to_string(),
                used_subkey: args.subkey_priv_path.is_some(),
                mirrors: args.mirrors.to_vec(),
                uploaded: args.upload.has_any(),
                supersedes: args.supersedes.to_vec(),
                sequence: args.sequence,
                min_sequence: args.min_sequence,
            });
        // The mock reports every advertised mirror as accepted. Tests
        // that need a partial failure override `publish_freshness_fail`
        // — the default has to be "it worked", or every unrelated
        // rotation test would trip the fewer-than-MinMirrors guard.
        let published = args
            .mirrors
            .iter()
            .map(|m| {
                let (provider, url) = m.split_once('=').unwrap_or((m.as_str(), ""));
                PublishedMirror {
                    provider: provider.to_string(),
                    url: url.to_string(),
                    ok: !self
                        .publish_freshness_fail
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|p| p == provider),
                    error: String::new(),
                }
            })
            .collect::<Vec<_>>();
        Ok(PublishFreshnessResult {
            signed_doc_b64: "MOCK_BASE64".into(),
            signed_doc_path: args
                .out_file
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            relay_pack_id: args.relay_pack_id.to_string(),
            current_bundle_sha256: args.current_bundle_sha256.to_string(),
            published_url: published
                .iter()
                .find(|p| p.ok)
                .map(|p| p.url.clone())
                .unwrap_or_default(),
            sequence: if args.sequence != 0 {
                args.sequence
            } else {
                args.now_unix.max(0) as u64
            },
            not_after: String::new(),
            published,
        })
    }

    fn run_reprovision(&self, args: ReprovisionArgs<'_>) -> Result<String> {
        self.reprovision_tokens
            .lock()
            .unwrap()
            .push(args.token.to_string());
        self.reprovision_calls
            .lock()
            .unwrap()
            .push(MockReprovisionCall {
                regen_credentials: args.regen_credentials,
                new_sni: args.new_sni.map(|s| s.to_string()),
                new_ws_path: args.new_ws_path.map(|s| s.to_string()),
                new_toolbox_profile: args.new_toolbox_profile.map(|s| s.to_string()),
            });
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(args.record_path)?)?;
        v["last_reprovisioned_at"] = serde_json::Value::String("2026-05-03T00:00:00Z".to_string());
        // Mirror the real adapter: Reprovision sets rec.CoverSNI to
        // provider.NextCoverSNI(rec, opts.NewSNI, now) — the requested
        // host when one was named, otherwise a fresh pool host that
        // excludes the current one. The whole point of L2 is that this
        // value then survives the `provision` that rebuilds the box.
        v["cover_sni"] = serde_json::Value::String(
            args.new_sni.unwrap_or("mirror.rotated.test").to_string(),
        );
        let body = serde_json::to_string(&v)?;
        std::fs::write(args.record_path, body.as_bytes())?;
        Ok(body)
    }

    /// Mirrors the FIXED hetzner adapter, not the broken one.
    ///
    /// `assign-fip` moves every copy of the dialled address — the
    /// record's public_ip AND each candidate's public_ip:* tag — and
    /// exits non-zero if it did not (rotation.CheckAddressMoved). A
    /// mock that only stamped floating_ip_id, which is what this used
    /// to do, models the pre-Step-9 bug and would let a test assert
    /// that a no-op rotation "succeeded".
    ///
    /// An empty fip_id means "reserve one", which the real CLI does and
    /// which the UI must be able to reach.
    fn run_assign_fip(&self, args: AssignFipArgs<'_>, priv_key: &[u8]) -> Result<String> {
        // Mirror the CLI's own precondition: it refuses (exit 2) before
        // reserving anything when either half of the signing material
        // is missing, because an address attached to a box that was
        // never told to configure it is one nothing answers on.
        if args.helper_ip.trim().is_empty() || priv_key.is_empty() {
            return Err(BridgeError::SubprocessFailed {
                rc: 2,
                stderr: "assign-fip: attaching a floating IP is only half the swap — pass --priv-key and --helper-ip"
                    .into(),
            });
        }
        if let Some((rc, stderr)) = self.assign_fip_error.lock().unwrap().clone() {
            return Err(BridgeError::SubprocessFailed { rc, stderr });
        }
        self.assign_fip_calls
            .lock()
            .unwrap()
            .push(MockAssignFipCall {
                fip_id: args.fip_id.to_string(),
                helper_ip: args.helper_ip.to_string(),
                priv_key_len: priv_key.len(),
            });
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(args.record_path)?)?;
        let prior_ip = v["public_ip"].as_str().unwrap_or_default().to_string();
        let assigned = if args.fip_id.is_empty() {
            "fip-reserved-by-cli".to_string()
        } else {
            args.fip_id.to_string()
        };
        // The real CLI refuses when the swap did not move the address —
        // re-attaching the address the relay is already on is the
        // default a pre-filled UI field used to produce.
        if v["floating_ip_id"].as_str().unwrap_or_default() == assigned && !prior_ip.is_empty() {
            return Err(BridgeError::SubprocessFailed {
                rc: 1,
                stderr: "assign-fip: rotation: L3 completed without moving the record's dialled address".into(),
            });
        }
        let new_ip = format!("198.51.100.{}", (assigned.len() % 200) + 1);
        v["floating_ip_id"] = serde_json::Value::String(assigned);
        v["public_ip"] = serde_json::Value::String(new_ip.clone());
        if let Some(cands) = v["candidates"].as_array_mut() {
            for c in cands {
                if let Some(tags) = c["public_risk_tags"].as_array_mut() {
                    for t in tags.iter_mut() {
                        if t.as_str().unwrap_or_default().starts_with("public_ip:") {
                            *t = serde_json::Value::String(format!("public_ip:{new_ip}"));
                        }
                    }
                }
            }
        }
        let body = serde_json::to_string(&v)?;
        std::fs::write(args.record_path, body.as_bytes())?;
        Ok(body)
    }

    fn run_release_fip(
        &self,
        args: ReleaseFipArgs<'_>,
        priv_key: &[u8],
    ) -> Result<ReleaseFipOutcome> {
        // Same precondition as the real verb: without the signing
        // material it can only proceed by skipping the unbind, which
        // hands a live box's address back to the provider pool.
        if args.helper_ip.trim().is_empty() || priv_key.is_empty() {
            return Err(BridgeError::SubprocessFailed {
                rc: 2,
                stderr: "floating-ip release: pass --priv-key and --helper-ip, or --skip-unbind".into(),
            });
        }
        // The real verb refuses when it cannot resolve the address it
        // is releasing to something the box understands, because
        // releasing an address a live relay still holds hands another
        // customer an address this box answers on. The mock has to
        // refuse on the same condition or the rotation test would pass
        // over the seam it exists to hold down.
        if args.fip_address.trim().is_empty() {
            return Err(BridgeError::SubprocessFailed {
                rc: 2,
                stderr: "floating-ip release: pass --fip-address <addr> (a rotation releasing the PRIOR address knows it), \
                         or --skip-unbind if that relay no longer exists"
                    .into(),
            });
        }
        self.release_fip_calls
            .lock()
            .unwrap()
            .push(format!("{} {}", args.fip_id, args.fip_address));
        if let Some(stderr) = self.release_fip_error.lock().unwrap().clone() {
            return Err(BridgeError::SubprocessFailed { rc: 1, stderr });
        }
        Ok(ReleaseFipOutcome {
            record_json: std::fs::read_to_string(args.record_path).unwrap_or_default(),
            warnings: vec![],
        })
    }

    fn run_decommission(&self, args: DecommissionArgs<'_>) -> Result<DecommissionResult> {
        // Record the call BEFORE the injected-failure check: a test
        // asserting "the cloud was asked first, and nothing local was
        // touched after it refused" needs the evidence that the ask
        // happened even on the failing path.
        self.decommission_calls
            .lock()
            .unwrap()
            .push(MockDecommissionCall {
                record_path: args.record_path.to_path_buf(),
                record_json: std::fs::read_to_string(args.record_path).unwrap_or_default(),
                token: args.token.to_string(),
            });
        if let Some(stderr) = self.decommission_error.lock().unwrap().clone() {
            return Err(BridgeError::SubprocessFailed { rc: 1, stderr });
        }
        if let Some(res) = self.decommission_result.lock().unwrap().clone() {
            return Ok(res);
        }
        Ok(DecommissionResult {
            server_deleted: true,
            ssh_key_deleted: true,
            firewall_deleted: true,
            warnings: Vec::new(),
        })
    }

    fn run_bind_and_sign(
        &self,
        args: BindAndSignArgs<'_>,
        priv_key: &[u8],
        on_progress: &mut dyn FnMut(ProgressEvent),
    ) -> Result<BindResult> {
        *self.last_priv_key.lock().unwrap() = Some(priv_key.to_vec());
        *self.last_subkey_cert_path.lock().unwrap() =
            args.subkey_cert_path.map(|p| p.to_path_buf());
        if let Some(stderr) = self.bind_error.lock().unwrap().clone() {
            return Err(BridgeError::SubprocessFailed { rc: 1, stderr });
        }
        self.bind_phases
            .lock()
            .unwrap()
            .push(args.phase.to_string());
        self.bind_freshness_mirrors
            .lock()
            .unwrap()
            .push(args.freshness_mirrors.to_vec());
        on_progress(ProgressEvent {
            step: "bind_done".into(),
            message: "signed".into(),
            ts: String::new(),
            extra: Default::default(),
        });
        if let Some(res) = self.bind_result.lock().unwrap().clone() {
            return Ok(res);
        }
        Ok(BindResult {
            sbp_path: "/tmp/mock.sbp".into(),
            sbp_sha256: "0".repeat(64),
            relay_pack_id: "rp-mockmockmockmock".into(),
            fingerprint_hex: "f".repeat(64),
            fingerprint_en: "alpha bravo charlie delta".into(),
            fingerprint_fa: "یک دو سه چهار".into(),
            lint_warnings: vec![],
            shared_risk_edges: 0,
        })
    }

    fn run_qr_fountain(
        &self,
        sbp_path: &Path,
        _block_size: u32,
        max_frames: u32,
        _seed: i64,
        on_frame: &mut dyn FnMut(FountainFrame) -> bool,
    ) -> Result<()> {
        *self.last_qr_fountain_path.lock().unwrap() = Some(sbp_path.to_path_buf());
        let n = if max_frames == 0 { 4 } else { max_frames };
        for i in 0..n {
            let frame = FountainFrame {
                i: i as i64,
                k: 4,
                frame_b64: "AAAA".into(),
            };
            if !on_frame(frame) {
                break;
            }
        }
        Ok(())
    }

    fn run_rotate_recommend(
        &self,
        _args: RotateRecommendArgs<'_>,
    ) -> Result<RotationRecommendation> {
        if let Some(r) = self.rotation_recommendation.lock().unwrap().clone() {
            return Ok(r);
        }
        // Default: L1 with low confidence (matches the Go default
        // for an empty Explanation).
        Ok(RotationRecommendation {
            level: "L1".into(),
            confidence: "low".into(),
            reason: "mock default".into(),
            reason_code: "no_evidence_at_all".into(),
            reason_detail: String::new(),
            est_wallclock: "~90s".into(),
            override_levels: vec!["L2".into(), "L3".into()],
            grounded: Default::default(),
            evidence: Default::default(),
            // Unprobed, like every recommendation the wizard can
            // currently obtain: nothing in this app calls
            // mgmt.CapabilitiesWithFW or passes --relay-capabilities, so
            // the Go recommender always answers "unknown" here.
            action: RotationAction {
                kind: "rotate-credentials".into(),
                cli_verb: "rotate-credentials".into(),
                scope: "recipient".into(),
                in_place: true,
                needs_recipient_name: true,
                availability: "unknown".into(),
                ..Default::default()
            },
        })
    }

    fn run_users_provision(
        &self,
        args: UsersProvisionArgs<'_>,
        _priv_key: &[u8],
    ) -> Result<UserCredsResult> {
        self.users_provision_calls
            .lock()
            .unwrap()
            .push(args.name.to_string());
        if let Some(r) = self.users_provision_result.lock().unwrap().clone() {
            return Ok(r);
        }
        Ok(UserCredsResult {
            name: args.name.to_string(),
            vless_uuid: "00000000-0000-0000-0000-000000000000".into(),
            reality_short_id: "deadbeef".into(),
            hy2_password: "mockhy2password0000000".into(),
            naive_password: "mocknaivepassword00000".into(),
            ws_path: format!("/{}/cafebabe", args.name),
            provisioned_at_unix: 1_700_000_000,
            reality_public_key: "bW9jay1yZWFsaXR5LXB1YmtleS1iYXNlNjQtMzJi".into(),
            tls_cert_sha256: "bW9jay10bHMtc3BraS1zaGEyNTYtcGluLWJhc2U2".into(),
            tls_cert_pem: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n".into(),
            cover_sni: "ftp.plusline.net".into(),
            mux_inbound: true,
            // A box that DOES serve shadowsocks-2022: the password is
            // already the colon-joined "<iPSK>:<uPSK>" the outbound
            // wants, both halves padded base64-std of 16 bytes, which is
            // what the method requires.
            ss_password: "bW9jay1ib3gtaXBzay0xNg==:bW9jay11c2VyLXVwc2sxNg==".into(),
            ss_method: "2022-blake3-aes-128-gcm".into(),
            // A box that DOES serve tuic. A relay whose profile left the
            // family off sends both of these empty, and the minter then
            // refuses the route — see the field docs.
            tuic_uuid: "33333333-3333-3333-3333-333333333333".into(),
            tuic_password: "mocktuicpassword000000".into(),
            // A box that serves anytls. The password is opaque to the
            // protocol (hashed into the session key), so any non-empty
            // string is a faithful mock; empty would mean "this relay
            // does not serve the family".
            anytls_password: "mockanytlspassword0000".into(),
        })
    }

    fn run_users_revoke(
        &self,
        args: UsersRevokeArgs<'_>,
        _priv_key: &[u8],
    ) -> Result<UsersRevokeResult> {
        self.users_revoke_calls
            .lock()
            .unwrap()
            .push(args.name.to_string());
        if let Some(r) = self.users_revoke_result.lock().unwrap().clone() {
            return Ok(r);
        }
        Ok(UsersRevokeResult {
            revoked_at_unix: 1_700_000_001,
        })
    }

    fn run_rotate_credentials(
        &self,
        args: RotateCredentialsArgs<'_>,
        _priv_key: &[u8],
    ) -> Result<RotateCredentialsResult> {
        self.rotate_credentials_calls
            .lock()
            .unwrap()
            .push(args.name.to_string());
        if let Some(r) = self.rotate_credentials_result.lock().unwrap().clone() {
            return Ok(r);
        }
        // The default mock is a CORRECT box: it echoes the name it was
        // asked for and returns per-user material. Tests that want the
        // old, unscoped box override `rotate_credentials_result`.
        Ok(RotateCredentialsResult {
            name: args.name.to_string(),
            vless_uuid: "11111111-1111-1111-1111-111111111111".into(),
            reality_short_id: "beefcafe".into(),
            hy2_password: "rotatedhy2password0000".into(),
            naive_password: "rotatednaivepassword00".into(),
            ws_path: format!("/{}/feedface", args.name),
            provisioned_at_unix: 1_700_000_000,
            reality_public_key: "bW9jay1yZWFsaXR5LXB1YmtleS1iYXNlNjQtMzJi".into(),
            tls_cert_sha256: "bW9jay10bHMtc3BraS1zaGEyNTYtcGluLWJhc2U2".into(),
            tls_cert_pem: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n".into(),
            cover_sni: "ftp.plusline.net".into(),
            mux_inbound: true,
            // Rotation replaces the recipient's uPSK only; the box iPSK
            // (the first half) is the same string the provision mock
            // returns, because re-minting it would break every other
            // recipient's shadowsocks route.
            ss_password: "bW9jay1ib3gtaXBzay0xNg==:cm90LXVzZXItdXBzay0xNg==".into(),
            ss_method: "2022-blake3-aes-128-gcm".into(),
            // Both halves move on a rotation: tuic authenticates on the
            // pair, so leaving the uuid behind keeps half a leaked
            // credential live.
            tuic_uuid: "22222222-2222-2222-2222-222222222222".into(),
            tuic_password: "rotatedtuicpassword000".into(),
            // A fresh anytls password, distinct from the provision mock:
            // the box replaces the row and echoes what it stored.
            anytls_password: "rotatedanytlspassword0".into(),
            rotated_at_unix: 1_700_000_600,
            generated_at_unix: 1_700_000_600,
            updated_inbounds: vec![
                "vless-reality".into(),
                "vless-ws".into(),
                "hy2".into(),
                "naive".into(),
            ],
            box_keys_rotated: false,
            warnings: vec![],
        })
    }

    fn run_rotate_tls(
        &self,
        args: RotateTlsArgs<'_>,
        _priv_key: &[u8],
    ) -> Result<RotateTlsResult> {
        *self.rotate_tls_calls.lock().unwrap() += 1;
        let canned = self.rotate_tls_result.lock().unwrap().clone();
        let res = canned.unwrap_or(RotateTlsResult {
            applied_at_unix: 1_700_000_700,
            cover_sni: "mirror.hetzner.com".into(),
            previous_cover_sni: "ftp.plusline.net".into(),
            applied_sni: "mirror.hetzner.com".into(),
            applied_handshake: "mirror.hetzner.com:443".into(),
            ws_path: String::new(),
            record_written: args.record_path.to_string_lossy().to_string(),
            warnings: vec![],
        });
        // The real CLI REWRITES --record-file in place with the updated
        // OperatorRecord and does not put it on stdout. Callers read that
        // file back, so the mock has to move it too or the read-back path
        // goes untested.
        if !res.cover_sni.is_empty() {
            if let Ok(body) = std::fs::read_to_string(args.record_path) {
                if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert(
                            "cover_sni".into(),
                            serde_json::Value::String(res.cover_sni.clone()),
                        );
                        if let Ok(s) = serde_json::to_string(&v) {
                            let _ = std::fs::write(args.record_path, s);
                        }
                    }
                }
            }
        }
        // Ordering matters: the record has already been rewritten above,
        // exactly as the CLI does before a non-zero exit.
        if let Some(msg) = self.rotate_tls_err.lock().unwrap().clone() {
            return Err(BridgeError::SubprocessFailed {
                rc: 1,
                stderr: msg,
            });
        }
        Ok(res)
    }

    fn run_users_list(
        &self,
        _args: UsersListArgs<'_>,
        _priv_key: &[u8],
    ) -> Result<Vec<UserMetaResult>> {
        *self.users_list_calls.lock().unwrap() += 1;
        if let Some(r) = self.users_list_result.lock().unwrap().clone() {
            return Ok(r);
        }
        Ok(vec![])
    }

    fn run_users_pack_sbpx(&self, args: UsersPackSbpxArgs<'_>) -> Result<UsersPackSbpxResult> {
        // Record the call so tests can assert. Synthesise a
        // believable .sbpx file by prepending the magic to the
        // input bytes (NOT real encryption — tests don't need it).
        self.users_pack_sbpx_calls.lock().unwrap().push(MockPackSbpxCall {
            in_sbp_path: args.in_sbp_path.to_path_buf(),
            recipient_pub_hex: args.recipient_pub_hex.to_string(),
            out_sbpx_path: args.out_sbpx_path.to_path_buf(),
        });
        let in_bytes = std::fs::read(args.in_sbp_path).unwrap_or_default();
        let mut out = Vec::with_capacity(in_bytes.len() + 6);
        out.extend_from_slice(&[b'D', b'S', b'B', b'P', 0x00, 0x01]);
        out.extend_from_slice(&in_bytes);
        std::fs::write(args.out_sbpx_path, &out).ok();
        Ok(UsersPackSbpxResult {
            sbpx_path: args.out_sbpx_path.to_string_lossy().to_string(),
            plaintext_size: in_bytes.len() as i64,
            sbpx_size: out.len() as i64,
        })
    }
    fn run_users_pack_sbp(&self, args: UsersPackSbpArgs<'_>) -> Result<UsersPackSbpResult> {
        // Mock: copy input to output (the real rewrite is exercised by the
        // Go CLI tests), and report a believable result.
        let in_bytes = std::fs::read(args.in_sbp_path).unwrap_or_default();
        std::fs::write(args.out_sbp_path, &in_bytes).ok();
        Ok(UsersPackSbpResult {
            sbp_path: args.out_sbp_path.to_string_lossy().to_string(),
            sbp_size: in_bytes.len() as i64,
            shared: true,
        })
    }

    fn run_users_unpack_sbpx(
        &self,
        args: UsersUnpackSbpxArgs<'_>,
        _priv_key_hex: &str,
    ) -> Result<UsersUnpackSbpxResult> {
        // Strip the magic prefix and write the rest to out_path so
        // unit tests can drive the recipient lane end-to-end with
        // synthetic envelopes produced by run_users_pack_sbpx.
        let cipher = std::fs::read(args.in_sbpx_path).unwrap_or_default();
        let plaintext = if cipher.len() >= 6 && &cipher[..6] == b"DSBP\x00\x01" {
            cipher[6..].to_vec()
        } else {
            return Err(BridgeError::SubprocessFailed {
                rc: 1,
                stderr: "not an .sbpx file (bad magic)\n".into(),
            });
        };
        std::fs::write(args.out_sbp_path, &plaintext).ok();
        Ok(UsersUnpackSbpxResult {
            plaintext_path: args.out_sbp_path.to_string_lossy().to_string(),
            plaintext_size: plaintext.len() as i64,
            sbpx_size: cipher.len() as i64,
        })
    }
}

/// Helper: write `secret` to a tempfile with restrictive perms.
fn tempfile_with_secret(secret: &str) -> Result<tempfile::NamedTempFile> {
    let mut f = tempfile::Builder::new()
        .prefix("daal-token-")
        .suffix(".tok")
        .tempfile()?;
    {
        let file = f.as_file_mut();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        file.write_all(secret.as_bytes())?;
        file.flush()?;
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    // THE CURRENCY SURVIVES THE HOP.
    //
    // `daal-deploy list-server-types` states which currency a plan is
    // priced in, because the two providers do not agree: Hetzner bills
    // EUR, Vultr bills USD. This struct is the only thing between that
    // statement and the L5 sheet that draws a currency symbol, and a
    // mirror that omits a field does not ignore it — serde drops it
    // silently and the UI can never ask. That is precisely how a $5.00
    // Vultr plan came to be offered as "about EUR 5 a month".
    #[test]
    fn a_server_type_keeps_the_currency_it_was_priced_in() {
        let vultr = r#"[{
            "id": "vc2-1c-1gb",
            "description": "1 vCPU, 1 GB",
            "cpus": 1,
            "memory_gb": 1.0,
            "disk_gb": 25,
            "monthly_eur": 5.0,
            "hourly_eur": 0.007,
            "location": "fra",
            "arch": "x86",
            "currency": "USD"
        }]"#;
        let got: Vec<ServerTypeOption> = serde_json::from_str(vultr).unwrap();
        assert_eq!(got[0].currency, "USD", "the currency was dropped on the way in");

        // And it survives re-serialisation, which is the leg the UI
        // actually reads.
        let back = serde_json::to_string(&got).unwrap();
        assert!(
            back.contains("\"currency\":\"USD\""),
            "the currency was dropped on the way out: {back}"
        );
    }

    // An older `daal-deploy` predates the second provider and emits no
    // currency at all. That must degrade to a Hetzner-shaped answer,
    // not fail the whole catalogue and leave the operator unable to
    // pick a server.
    #[test]
    fn a_server_type_without_a_currency_still_parses() {
        let legacy = r#"[{
            "id": "cx22",
            "description": "CX22",
            "cpus": 2,
            "memory_gb": 4.0,
            "disk_gb": 40,
            "monthly_eur": 4.59,
            "hourly_eur": 0.007,
            "location": "fsn1",
            "arch": "x86"
        }]"#;
        let got: Vec<ServerTypeOption> = serde_json::from_str(legacy).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].currency, "");
    }

    #[test]
    fn pricing_json_round_trips() {
        let p = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.005,
            monthly_eur: 3.85,
            included_traffic_tb_per_month: None,
            overage_eur_per_gb: None,
        };
        let body = serde_json::to_string(&p).unwrap();
        let p2: Pricing = serde_json::from_str(&body).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn mock_runner_records_call_and_returns_fixture() {
        let fix = Pricing {
            provider: "hetzner".into(),
            region: "fsn1".into(),
            server_type: "cx22".into(),
            hourly_eur: 0.0042,
            monthly_eur: 3.50,
            included_traffic_tb_per_month: Some(20.0),
            overage_eur_per_gb: Some(0.0010),
        };
        let m = MockRunner::new(fix.clone());
        let got = m.run_pricing("hetzner", "fsn1", "cx22", "tok-123").unwrap();
        assert_eq!(got, fix);
        let call = m.last_call.lock().unwrap().clone().unwrap();
        assert_eq!(call.provider, "hetzner");
        assert_eq!(call.region, "fsn1");
        assert_eq!(call.server_type, "cx22");
        assert_eq!(call.token, "tok-123");
    }

    /// The recommender's `action` must survive the Go→Rust hop. serde
    /// drops unknown keys silently, so a field the CLI emits and this
    /// struct omits dies with no error anywhere — the same trap that
    /// made `cover_sni`/`mux_inbound` inert on the provision path. Pin
    /// the wire shape rather than trusting the two structs to stay in
    /// step by inspection.
    #[test]
    fn rotation_recommendation_carries_the_action() {
        let body = r#"{"level":"L1","confidence":"high","reason":"leak",
            "est_wallclock":"~90s","override":["L2"],
            "action":{"kind":"rotate-credentials","cli_verb":"rotate-credentials",
                      "scope":"recipient","in_place":true,"needs_recipient_name":true,
                      "destroys_server":false,"invalidates_every_pack":false,
                      "availability":"unknown","note":"not probed yet"}}"#;
        let r: RotationRecommendation = serde_json::from_str(body).unwrap();
        assert_eq!(r.action.kind, "rotate-credentials");
        assert_eq!(r.action.scope, "recipient");
        assert!(r.action.needs_recipient_name);
        assert_eq!(r.action.availability, "unknown");
        assert!(!r.action.note.is_empty());

        // An older daal-deploy emits no `action` at all. That must decode
        // to the zero value — availability "" reads as "not known", never
        // as a confident "ready".
        let old: RotationRecommendation = serde_json::from_str(
            r#"{"level":"L1","confidence":"low","reason":"x","est_wallclock":"~90s","override":[]}"#,
        )
        .unwrap();
        assert_eq!(old.action, RotationAction::default());
        assert!(old.action.availability.is_empty());
    }

    /// The two machine-readable parallels — `reason_code` and
    /// `evidence.absent_codes` — must survive the Go→Rust hop too.
    ///
    /// They exist so a Farsi operator reads the decisive text of the
    /// advice panel in Farsi: the panel keys them and falls back to the
    /// English prose on a catalog miss. A dropped key here is invisible
    /// — serde reports nothing, the prose still renders, and the whole
    /// translation path is silently dead. `absent_codes` shipped that
    /// way: it was added to Go and to the panel and omitted from this
    /// struct, so the fallback fired on every run.
    #[test]
    fn rotation_recommendation_carries_the_translation_codes() {
        let body = r#"{"level":"L3","confidence":"medium",
            "reason":"TCP reset on this relay, with no address-level attribution recorded",
            "reason_code":"address_reset_unattributed","reason_detail":"",
            "est_wallclock":"~10s","override":["L4","L2"],"grounded":true,
            "evidence":{"source":"explanation","classifications":["tcp_reset"],
                        "signals":[],"cooldown_tags":[],"unrecognised":[],
                        "absent":["cooldown tags: no producer — …","network signals …: no prober exists"],
                        "absent_codes":["no_cooldown_producer","no_prober"]}}"#;
        let r: RotationRecommendation = serde_json::from_str(body).unwrap();
        assert_eq!(r.reason_code, "address_reset_unattributed");
        assert!(r.reason_detail.is_empty());
        assert_eq!(
            r.evidence.absent_codes,
            vec!["no_cooldown_producer".to_string(), "no_prober".to_string()],
            "absent_codes did not survive the hop; the panel falls back to English on every run"
        );
        // Parallel arrays: the panel pairs them by index, so a length
        // drift attaches the wrong sentence to a code — on this screen
        // that means telling an operator something was measured and
        // clean when it was never measured at all.
        assert_eq!(r.evidence.absent.len(), r.evidence.absent_codes.len());

        // The detail some codes interpolate.
        let blocked: RotationRecommendation = serde_json::from_str(
            r#"{"level":"L4","confidence":"medium","reason":"Address-level block …",
                "reason_code":"address_block_no_swap",
                "reason_detail":"this relay's software cannot configure an address",
                "est_wallclock":"~3min","override":[]}"#,
        )
        .unwrap();
        assert_eq!(blocked.reason_code, "address_block_no_swap");
        assert!(blocked.reason_detail.contains("cannot configure an address"));

        // An older daal-deploy emits neither. Both must decode empty —
        // which is exactly what makes the panel render the English
        // prose instead of a bare key.
        let old: RotationRecommendation = serde_json::from_str(
            r#"{"level":"L1","confidence":"low","reason":"x","est_wallclock":"~90s","override":[]}"#,
        )
        .unwrap();
        assert!(old.reason_code.is_empty());
        assert!(old.reason_detail.is_empty());
        assert!(old.evidence.absent_codes.is_empty());
    }

    #[test]
    fn missing_binary_returns_binary_missing() {
        let r = SubprocessRunner::new(Some(PathBuf::from("/no/such/binary-asdf")));
        let err = r.run_pricing("hetzner", "fsn1", "cx22", "t").unwrap_err();
        match err {
            BridgeError::BinaryMissing => (),
            e => panic!("wanted BinaryMissing, got {e:?}"),
        }
    }

    /// Write an executable stand-in for `daal-deploy` and return its
    /// path. `script` is a `sh` body; `"$@"` is the real arg vector.
    #[cfg(unix)]
    /// Write a stand-in `daal-deploy` and return a path that is
    /// GUARANTEED to be exec-able by the time it is returned.
    ///
    /// The guarantee is the point. Without the preflight below these
    /// tests fail intermittently with
    /// `Io(Os { code: 26, kind: ExecutableFileBusy })`, and only under
    /// load — which is exactly when the pre-push gate runs them.
    ///
    /// The cause is a Linux race that has nothing to do with the code
    /// under test: `cargo test` runs tests on many threads in ONE
    /// process, so while this thread still holds the write fd to the
    /// script it just created, another test thread can `fork` for its
    /// own subprocess and inherit that fd. The child now holds a
    /// writable descriptor to our file, and `execve` on a file that is
    /// open for writing returns ETXTBSY until that child exits.
    ///
    /// The condition is transient by construction, so the fix is to
    /// wait it out here rather than to weaken any assertion: a test
    /// that fails for a reason unrelated to its subject teaches the
    /// reader to ignore a red gate, which is worse than a slow one.
    fn fake_deploy(dir: &std::path::Path, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("daal-deploy");
        std::fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Preflight: run it (output discarded) until the kernel stops
        // reporting ETXTBSY. These scripts only echo and exit, so an
        // extra invocation has no side effect the caller can observe.
        for attempt in 0..200 {
            match std::process::Command::new(&p).output() {
                Err(e) if e.raw_os_error() == Some(26) => {
                    if attempt == 199 {
                        panic!("fake_deploy: {} still ETXTBSY after 200 tries", p.display());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break,
            }
        }
        p
    }

    #[cfg(unix)]
    #[test]
    fn decommission_parses_per_resource_json() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("rec.json");
        std::fs::write(&rec, "{}").unwrap();
        let bin = fake_deploy(
            dir.path(),
            r#"echo '{"server_deleted":true,"ssh_key_deleted":true,"firewall_deleted":false,"warnings":["firewall 422"]}'"#,
        );
        let got = SubprocessRunner::new(Some(bin))
            .run_decommission(DecommissionArgs {
                record_path: &rec,
                token: "tok",
            })
            .unwrap();
        assert_eq!(
            got,
            DecommissionResult {
                server_deleted: true,
                ssh_key_deleted: true,
                firewall_deleted: false,
                warnings: vec!["firewall 422".into()],
            }
        );
    }

    /// The seam itself. The test above uses a hand-written one-liner;
    /// this one is the byte-for-byte stdout of a real
    /// `daal-deploy decommission --json` run, captured from the
    /// compiled binary. It is `MarshalIndent`, so the document spans
    /// many lines (the "last non-empty line" salvage path would see a
    /// bare `}`), and it carries four fields the Rust struct does not
    /// declare — `provider`, `preserved`, `deleted_ssh_key_ids`,
    /// `firewall_id`. Both properties have to hold or a real teardown
    /// reports nothing: no `deny_unknown_fields`, and the whole body
    /// parsed as one document.
    #[cfg(unix)]
    #[test]
    fn decommission_parses_the_real_binarys_indented_output() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("rec.json");
        std::fs::write(&rec, "{}").unwrap();
        let bin = fake_deploy(
            dir.path(),
            r#"cat <<'EOF'
{
  "provider": "hetzner",
  "server_id": "12345",
  "server_deleted": true,
  "ssh_key_deleted": false,
  "firewall_deleted": true,
  "deleted_ssh_key_ids": ["678"],
  "firewall_id": "910",
  "preserved": [
    "ssh-key:daal-fsn1-000000-ephemeral*"
  ],
  "warnings": [
    "could not confirm the one-shot SSH key is gone"
  ]
}
EOF
echo 'decommission warning: could not confirm the one-shot SSH key is gone' >&2"#,
        );
        let got = SubprocessRunner::new(Some(bin))
            .run_decommission(DecommissionArgs {
                record_path: &rec,
                token: "tok",
            })
            .unwrap();
        assert_eq!(
            got,
            DecommissionResult {
                server_deleted: true,
                ssh_key_deleted: false,
                firewall_deleted: true,
                warnings: vec!["could not confirm the one-shot SSH key is gone".into()],
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn decommission_retries_without_json_on_a_legacy_binary() {
        // On Android the deploy engine is a pinned libdaal_deploy.so
        // that can lag the shell. A build predating `--json` rejects
        // the flag at parse time (exit 2); that must degrade to the
        // legacy text protocol rather than fail the teardown — and it
        // must NOT claim the key and firewall are gone, because that
        // build never touched them.
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("rec.json");
        std::fs::write(&rec, "{}").unwrap();
        let bin = fake_deploy(
            dir.path(),
            r#"for a in "$@"; do
  if [ "$a" = "--json" ]; then
    echo "flag provided but not defined: -json" >&2
    exit 2
  fi
done
echo decommissioned"#,
        );
        let got = SubprocessRunner::new(Some(bin))
            .run_decommission(DecommissionArgs {
                record_path: &rec,
                token: "tok",
            })
            .unwrap();
        assert!(got.server_deleted);
        assert!(!got.ssh_key_deleted, "legacy build never deletes the key");
        assert!(!got.firewall_deleted);
        assert_eq!(got.warnings.len(), 1, "the gap is stated, not hidden");
    }

    #[cfg(unix)]
    #[test]
    fn decommission_surfaces_a_real_failure_not_a_flag_retry() {
        let dir = tempfile::tempdir().unwrap();
        let rec = dir.path().join("rec.json");
        std::fs::write(&rec, "{}").unwrap();
        let bin = fake_deploy(
            dir.path(),
            "echo 'decommission: 503 service unavailable' >&2\nexit 1",
        );
        let err = SubprocessRunner::new(Some(bin))
            .run_decommission(DecommissionArgs {
                record_path: &rec,
                token: "tok",
            })
            .unwrap_err();
        match err {
            BridgeError::SubprocessFailed { rc, stderr } => {
                assert_eq!(rc, 1);
                assert!(stderr.contains("503 service unavailable"), "{stderr}");
            }
            e => panic!("wanted SubprocessFailed, got {e:?}"),
        }
    }

    /// WAVE-5 REPAIR REGRESSION — the serde hop that has now dropped a
    /// field twice.
    ///
    /// `recipient_book::merge_and_pack_sbpx` produces the creds file
    /// `users-pack-sbp[x]` reads by calling `serde_json::to_value` on
    /// these structs. A field the box sends and the struct omits is
    /// discarded there, silently, with no error at any layer — that is
    /// how `mux_inbound` was inert for a wave and how `anytls_password`
    /// would have made every wizard-minted pack for an anytls relay
    /// fail to build.
    ///
    /// This asserts the OUTPUT of that exact call, not the struct
    /// definition, so it fails for a `skip_serializing_if` as well as
    /// for a missing field. `tools/check-creds-mirror.mjs` is the
    /// static half; this is the runtime half.
    #[test]
    fn creds_serialise_every_field_the_minter_reads() {
        // The wire names publisher/deploy/mgmt.UserCreds declares.
        // Keep in step with that struct — the gate script enforces it.
        const WIRE: &[&str] = &[
            "name",
            "vless_uuid",
            "reality_short_id",
            "hy2_password",
            "naive_password",
            "ws_path",
            "provisioned_at_unix",
            "reality_public_key",
            "tls_cert_sha256",
            "tls_cert_pem",
            "cover_sni",
            "mux_inbound",
            "tuic_uuid",
            "tuic_password",
            "ss_password",
            "ss_method",
            "anytls_password",
        ];

        let prov = serde_json::to_value(UserCredsResult::default()).unwrap();
        for k in WIRE {
            assert!(
                prov.get(k).is_some(),
                "UserCredsResult serialises without {k:?}; the creds file the pack step \
                 reads would not carry it and the route would be refused or minted dead"
            );
        }

        let rot = serde_json::to_value(RotateCredentialsResult::default()).unwrap();
        for k in WIRE {
            assert!(
                rot.get(k).is_some(),
                "RotateCredentialsResult serialises without {k:?}; a rotation would hand \
                 the minter a pack missing that family"
            );
        }
    }
}
