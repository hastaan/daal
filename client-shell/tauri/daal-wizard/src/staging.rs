//! Pre-provision OperatorRecord staging-file writer.
//!
//! After the user finalises screen 3 (publisher key revealed), the
//! wizard writes a partial OperatorRecord JSON to
//! `~/.config/daal/staging/<id>.pre-provision.json`. FRP-4b reads
//! this file to drive `Provider.Provision` and `BindAndSign`.
//!
//! The JSON shape mirrors FRP-4a's `provider.OperatorRecord` Go
//! struct exactly (see `publisher/deploy/provider/types.go`). At
//! pre-provision the following fields are empty / zero-valued:
//!
//!   - `server_id`            (FRP-4b sets after Provision)
//!   - `public_ip` / `public_ipv6` (same)
//!   - `floating_ip_id`       (FRP-4b may set later)
//!   - `candidates`           (FRP-4b populates per family)
//!   - `provisioned_at`       (FRP-4b sets to wall clock)
//!   - `last_reprovisioned_at` (set on reprovision)
//!
//! The `freshness_url` slot is reserved at FRP-1 (relaypack-v1
//! invariant) and stays empty at V1.5; FRP-8 populates it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Accept `null` as the default value for any `Deserialize + Default`
/// type. Go marshals `nil` slices as JSON `null` (not `[]`), and
/// FRP-4b writes the OperatorRecord back through Go after Provision,
/// so several `Vec`/`String` fields can come back as `null` rather
/// than the empty form. Plain `#[serde(default)]` only covers
/// missing fields; this covers null values too.
fn null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

#[derive(Debug, Error)]
pub enum StagingError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialize: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StagingError>;

/// `PreProvisionRecord` is the wire shape FRP-4b reads. It carries
/// everything the wizard knows at screen-3 exit plus the empty
/// slots FRP-4b will fill.
///
/// The field names + JSON tags MUST match the Go struct
/// `provider.OperatorRecord` byte-for-byte. A schema cross-check
/// test (see `tests/schema_xref.rs`) pins this against a snapshot
/// of the Go field set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreProvisionRecord {
    pub provider: String,
    #[serde(default, deserialize_with = "null_default")]
    pub server_id: String,
    pub server_type: String,
    pub region: String,
    /// Empty string at pre-provision (Go `net.IP` marshals to JSON
    /// string; an empty string is the conventional "unset" form
    /// across the wizard <-> FRP-4b boundary). Go also marshals a
    /// nil `net.IP` to `null`, so we accept that here too.
    #[serde(default, deserialize_with = "null_default")]
    pub public_ip: String,
    #[serde(default, deserialize_with = "null_default", skip_serializing_if = "String::is_empty")]
    pub public_ipv6: String,
    #[serde(default, deserialize_with = "null_default", skip_serializing_if = "String::is_empty")]
    pub floating_ip_id: String,
    pub toolbox_profile: String,
    /// User-selected family subset. Empty means "use profile defaults".
    /// Maps to FRP-4a `ProvisionOpts.EnabledFamilies`.
    #[serde(default, deserialize_with = "null_default")]
    pub enabled_families: Vec<String>,
    /// Raw 32-byte Ed25519 public key, base64-encoded (matches Go
    /// `[]byte` JSON marshaling — nil slice → `null`).
    #[serde(default, deserialize_with = "null_default")]
    pub publisher_pub_key: String,
    /// Always empty at pre-provision; FRP-4b populates after Provision.
    /// Go nil slice marshals to `null`, so accept that as `[]`.
    #[serde(default, deserialize_with = "null_default")]
    pub candidates: Vec<serde_json::Value>,
    /// Always "0001-01-01T00:00:00Z" at pre-provision; FRP-4b sets.
    #[serde(default, deserialize_with = "null_default")]
    pub provisioned_at: String,
    /// Reserved at FRP-1; empty at V1.5; FRP-8 populates.
    #[serde(default, deserialize_with = "null_default")]
    pub freshness_url: String,
}

impl PreProvisionRecord {
    /// Construct a fresh pre-provision record with FRP-4b-pending
    /// fields zeroed. `publisher_pub_key_b64` is the base64 of the
    /// raw 32-byte pubkey.
    pub fn new(
        provider: &str,
        region: &str,
        server_type: &str,
        toolbox_profile: &str,
        enabled_families: Vec<String>,
        publisher_pub_key_b64: &str,
    ) -> Self {
        Self {
            provider: provider.to_string(),
            server_id: String::new(),
            server_type: server_type.to_string(),
            region: region.to_string(),
            public_ip: String::new(),
            public_ipv6: String::new(),
            floating_ip_id: String::new(),
            toolbox_profile: toolbox_profile.to_string(),
            enabled_families,
            publisher_pub_key: publisher_pub_key_b64.to_string(),
            candidates: Vec::new(),
            provisioned_at: "0001-01-01T00:00:00Z".to_string(),
            freshness_url: String::new(),
        }
    }
}

/// Write a pre-provision record to `<staging_dir>/<id>.pre-provision.json`.
/// Creates the directory if missing. Returns the path written.
pub fn write_record(
    staging_dir: impl AsRef<Path>,
    id: i64,
    rec: &PreProvisionRecord,
) -> Result<PathBuf> {
    let dir = staging_dir.as_ref();
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{id}.pre-provision.json"));
    let body = serde_json::to_vec_pretty(rec)?;
    std::fs::write(&path, &body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

/// Read a pre-provision record back. Used by FRP-4b at next phase.
pub fn read_record(staging_dir: impl AsRef<Path>, id: i64) -> Result<PreProvisionRecord> {
    let path = staging_dir
        .as_ref()
        .join(format!("{id}.pre-provision.json"));
    let body = std::fs::read(&path)?;
    Ok(serde_json::from_slice(&body)?)
}

/// Default staging-dir location: `~/.config/daal/staging/`.
pub fn default_staging_dir() -> PathBuf {
    if let Some(d) = dirs_next::config_dir() {
        return d.join("daal").join("staging");
    }
    std::env::temp_dir().join("daal").join("staging")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_then_read_round_trip() {
        let dir = tempdir().unwrap();
        let rec = PreProvisionRecord::new(
            "hetzner",
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".to_string(), "hysteria2".to_string()],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        let path = write_record(dir.path(), 7, &rec).unwrap();
        assert!(path.ends_with("7.pre-provision.json"));
        let got = read_record(dir.path(), 7).unwrap();
        assert_eq!(got, rec);
    }

    #[test]
    fn pre_provision_has_zeroed_fields() {
        let rec = PreProvisionRecord::new("hetzner", "fsn1", "cx22", "iran-default", vec![], "abc");
        assert_eq!(rec.server_id, "");
        assert_eq!(rec.public_ip, "");
        assert_eq!(rec.candidates.len(), 0);
        assert_eq!(rec.provisioned_at, "0001-01-01T00:00:00Z");
        assert_eq!(
            rec.freshness_url, "",
            "freshness_url empty at V1.5 (FRP-1 invariant)"
        );
    }

    #[test]
    fn json_includes_required_top_level_keys() {
        let rec = PreProvisionRecord::new(
            "hetzner",
            "fsn1",
            "cx22",
            "iran-default",
            vec!["vless-reality".to_string()],
            "abc=",
        );
        let body = serde_json::to_string(&rec).unwrap();
        for key in [
            "\"provider\":",
            "\"server_id\":",
            "\"server_type\":",
            "\"region\":",
            "\"public_ip\":",
            "\"toolbox_profile\":",
            "\"enabled_families\":",
            "\"publisher_pub_key\":",
            "\"candidates\":",
            "\"provisioned_at\":",
            "\"freshness_url\":",
        ] {
            assert!(body.contains(key), "missing JSON key {key} in {body}");
        }
    }

    #[test]
    fn enabled_families_empty_serialises_as_empty_array() {
        let rec =
            PreProvisionRecord::new("hetzner", "fsn1", "cx22", "iran-default", vec![], "abc=");
        let body = serde_json::to_string(&rec).unwrap();
        assert!(body.contains("\"enabled_families\":[]"));
    }
}
