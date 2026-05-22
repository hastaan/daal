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

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

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
    pub sbp_path: String,
    pub sbp_sha256: String,
    pub relay_pack_id: String,
    pub fingerprint_hex: String,
    pub fingerprint_en: String,
    pub fingerprint_fa: String,
    #[serde(default)]
    pub lint_warnings: Vec<serde_json::Value>,
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
    pub est_wallclock: String,
    #[serde(rename = "override", default, alias = "override_levels")]
    pub override_levels: Vec<String>,
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

/// Trait so tests can substitute a mock without spawning a process.
pub trait CliRunner: Send + Sync {
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
    fn run_assign_fip(&self, args: AssignFipArgs<'_>) -> Result<String>;

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
}

/// FRP-9 commit 4/8: result shape returned by
/// `daal-deploy publish-freshness`. signed_doc_b64 always
/// carries the bytes; published_url is empty until the live
/// backend SDK (R2 / GH Pages) is wired in a follow-up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PublishFreshnessResult {
    pub signed_doc_b64: String,
    pub signed_doc_path: String,
    pub relay_pack_id: String,
    pub current_bundle_sha256: String,
    pub published_url: String,
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
    pub fip_id: &'a str,
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
}

impl CliRunner for SubprocessRunner {
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
        if args.dry_run {
            cmd.arg("--dry-run");
        }
        let mut child = cmd
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
        let out = cmd
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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

    fn run_assign_fip(&self, args: AssignFipArgs<'_>) -> Result<String> {
        let tmp = tempfile_with_secret(args.token)?;
        let token_path = tmp.path().to_path_buf();

        let out = Command::new(&self.binary)
            .arg("assign-fip")
            .arg("--record-file")
            .arg(args.record_path)
            .arg("--token-file")
            .arg(&token_path)
            .arg("--fip-id")
            .arg(args.fip_id)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
        let mut child = cmd
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
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
}

/// `MockRunner` is the in-process stand-in for tests.
pub struct MockRunner {
    pub fixture: Pricing,
    pub last_call: Mutex<Option<MockCall>>,
    /// FRP-4b/FRP-7: count live provision calls.
    pub provision_calls: Mutex<usize>,
    /// FRP-4b: optional canned record JSON for `run_provision`.
    pub provision_record_json: Mutex<Option<String>>,
    /// FRP-8: optional canned CDN front for `run_cdn_provision`.
    pub cdn_front_result: Mutex<Option<CdnFrontResult>>,
    /// FRP-4b: optional canned bind result for `run_bind_and_sign`.
    pub bind_result: Mutex<Option<BindResult>>,
    /// FRP-4b: a recorded copy of the priv-key bytes the wizard
    /// pushed through stdin. Used by tests to verify the end-to-end
    /// transport without leaving keys on disk.
    pub last_priv_key: Mutex<Option<Vec<u8>>>,
    /// FRP-7.5: recorded sub-key cert path supplied to
    /// bind-and-sign, if the wizard selected the active sub-key.
    pub last_subkey_cert_path: Mutex<Option<PathBuf>>,
    /// FRP-7: optional canned rotation recommendation.
    pub rotation_recommendation: Mutex<Option<RotationRecommendation>>,
    /// FRP-7: recorded reprovision calls.
    pub reprovision_calls: Mutex<Vec<MockReprovisionCall>>,
    /// FRP-7: recorded floating-IP assign calls.
    pub assign_fip_calls: Mutex<Vec<MockAssignFipCall>>,
    /// FRP-9: recorded CDN-rotate-path calls.
    pub cdn_rotate_path_calls: Mutex<Vec<MockCdnRotatePathCall>>,
    /// FRP-9: recorded CDN-rotate-hostname calls.
    pub cdn_rotate_hostname_calls: Mutex<Vec<MockCdnRotateHostnameCall>>,
    /// FRP-9: recorded CDN-rotate-origin calls.
    pub cdn_rotate_origin_calls: Mutex<Vec<MockCdnRotateOriginCall>>,
    /// FRP-9: recorded publish-freshness calls.
    pub publish_freshness_calls: Mutex<Vec<MockPublishFreshnessCall>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockPublishFreshnessCall {
    pub relay_pack_id: String,
    pub current_bundle_sha256: String,
    pub current_signed_url: String,
    pub used_subkey: bool,
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
}

impl MockRunner {
    pub fn new(fixture: Pricing) -> Self {
        Self {
            fixture,
            last_call: Mutex::new(None),
            provision_calls: Mutex::new(0),
            provision_record_json: Mutex::new(None),
            cdn_front_result: Mutex::new(None),
            bind_result: Mutex::new(None),
            last_priv_key: Mutex::new(None),
            last_subkey_cert_path: Mutex::new(None),
            rotation_recommendation: Mutex::new(None),
            reprovision_calls: Mutex::new(Vec::new()),
            assign_fip_calls: Mutex::new(Vec::new()),
            cdn_rotate_path_calls: Mutex::new(Vec::new()),
            cdn_rotate_hostname_calls: Mutex::new(Vec::new()),
            cdn_rotate_origin_calls: Mutex::new(Vec::new()),
            publish_freshness_calls: Mutex::new(Vec::new()),
        }
    }

    /// FRP-7: stamp a canned recommendation that
    /// `run_rotate_recommend` will return.
    pub fn with_rotation_recommendation(self, r: RotationRecommendation) -> Self {
        *self.rotation_recommendation.lock().unwrap() = Some(r);
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

    pub fn with_bind_result(self, res: BindResult) -> Self {
        *self.bind_result.lock().unwrap() = Some(res);
        self
    }
}

impl CliRunner for MockRunner {
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
        _args: ProvisionArgs<'_>,
        on_progress: &mut dyn FnMut(ProgressEvent),
    ) -> Result<String> {
        *self.provision_calls.lock().unwrap() += 1;
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
            });
        Ok(PublishFreshnessResult {
            signed_doc_b64: "MOCK_BASE64".into(),
            signed_doc_path: args
                .out_file
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            relay_pack_id: args.relay_pack_id.to_string(),
            current_bundle_sha256: args.current_bundle_sha256.to_string(),
            published_url: String::new(),
        })
    }

    fn run_reprovision(&self, args: ReprovisionArgs<'_>) -> Result<String> {
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
        let body = serde_json::to_string(&v)?;
        std::fs::write(args.record_path, body.as_bytes())?;
        Ok(body)
    }

    fn run_assign_fip(&self, args: AssignFipArgs<'_>) -> Result<String> {
        self.assign_fip_calls
            .lock()
            .unwrap()
            .push(MockAssignFipCall {
                fip_id: args.fip_id.to_string(),
            });
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(args.record_path)?)?;
        v["floating_ip_id"] = serde_json::Value::String(args.fip_id.to_string());
        let body = serde_json::to_string(&v)?;
        std::fs::write(args.record_path, body.as_bytes())?;
        Ok(body)
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
        _sbp_path: &Path,
        _block_size: u32,
        max_frames: u32,
        _seed: i64,
        on_frame: &mut dyn FnMut(FountainFrame) -> bool,
    ) -> Result<()> {
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
            est_wallclock: "~90s".into(),
            override_levels: vec!["L2".into(), "L3".into()],
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

    #[test]
    fn missing_binary_returns_binary_missing() {
        let r = SubprocessRunner::new(Some(PathBuf::from("/no/such/binary-asdf")));
        let err = r.run_pricing("hetzner", "fsn1", "cx22", "t").unwrap_err();
        match err {
            BridgeError::BinaryMissing => (),
            e => panic!("wanted BinaryMissing, got {e:?}"),
        }
    }
}
