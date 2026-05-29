//! Manifest types and ed25519 manifest verification.
//!
//! Mirrors `bundle/go/bundle/types.go` + `sign.go`. Field names and
//! `omitempty` semantics match the Go side so the canonical JSON
//! ser/de round-trips byte-identically.

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_marshal;
use crate::errors::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub spec_version: i32,
    pub publisher: PublisherInfo,
    pub bundle: BundleInfo,
    pub routes: Vec<RouteManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublisherInfo {
    pub name: String,
    pub key_fingerprint_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_fingerprint_en: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_fingerprint_fa: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_fingerprint_visual: String,
    pub key_created_at: String,
    pub trust_class: String,
    /// v2 (Phase 1.5A) — JSON-additive within v2; absent in v1.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revocation_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revocation_fingerprint_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub created_at: String,
    pub expires_at: String,
    /// `null` is a valid value here — Go writes a `*string` pointer.
    pub previous_bundle_id: Option<String>,
    pub supersedes_keys: Vec<String>,
    /// v2 (Phase 1.5A) — only on directory bundles.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "pointer_rotation_ref"
    )]
    pub pointer_rotation: Option<PointerRotationRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PointerRotationRef {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteManifestEntry {
    pub id: String,
    pub scarcity_class: String,
    pub transport_family: String,
    pub config_path: String,
    pub valid_from: String,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "skip_false")]
    pub udp_gated: bool,
}

fn skip_false(v: &bool) -> bool {
    !*v
}

/// Parse and validate the manifest JSON document. Does not verify the
/// signature — call `verify_manifest` for that.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    let m: Manifest = serde_json::from_slice(bytes)?;
    Ok(m)
}

/// **Authoritative** signature verifier.
///
/// Verifies the detached ed25519 signature over the **raw bytes** of
/// `manifest.json` as they were written into the `.sbp` archive by
/// the publisher. This is the verifier that production code should
/// use; it is immune to schema drift because it never parses the
/// manifest at all.
///
/// Caller obtains the bytes via `Sbp::manifest_bytes` (populated by
/// [`crate::parse_sbp`]).
pub fn verify_manifest_bytes(
    manifest_bytes: &[u8],
    sig: &[u8],
    pub_key: &[u8],
) -> Result<(), Error> {
    if pub_key.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublisherKey);
    }
    if sig.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignature);
    }
    let key_array: [u8; PUBLIC_KEY_LENGTH] =
        pub_key.try_into().map_err(|_| Error::InvalidPublisherKey)?;
    let vk = VerifyingKey::from_bytes(&key_array).map_err(|_| Error::InvalidPublisherKey)?;
    let sig_array: [u8; SIGNATURE_LENGTH] = sig.try_into().map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_array);
    vk.verify(manifest_bytes, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Legacy: verify the signature by re-marshaling the parsed manifest
/// into canonical-JSON form. Kept only for parity research and
/// existing fixture tests; **do not use for production verification**
/// — bundle-rs's `Manifest` struct is intentionally a lossy view
/// (e.g. spec-version-3 `relay_pack` fields are dropped), so this
/// path will reject otherwise-valid bundles whose manifest carries
/// any field bundle-rs doesn't model. Use
/// [`verify_manifest_bytes`] against the on-disk bytes instead.
#[deprecated(
    since = "0.2.0",
    note = "use verify_manifest_bytes with the raw manifest.json bytes; this re-marshal path is lossy and breaks when the Go publisher emits fields bundle-rs doesn't model"
)]
pub fn verify_manifest(manifest: &Manifest, sig: &[u8], pub_key: &[u8]) -> Result<(), Error> {
    if pub_key.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublisherKey);
    }
    if sig.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignature);
    }
    let canonical = canonical_marshal(manifest)?;
    let key_array: [u8; PUBLIC_KEY_LENGTH] =
        pub_key.try_into().map_err(|_| Error::InvalidPublisherKey)?;
    let vk = VerifyingKey::from_bytes(&key_array).map_err(|_| Error::InvalidPublisherKey)?;
    let sig_array: [u8; SIGNATURE_LENGTH] = sig.try_into().map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_array);
    vk.verify(&canonical, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Returns true iff the supplied RFC3339 timestamp is in the past.
pub fn expired(value: &str, now: time::OffsetDateTime) -> bool {
    match time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339) {
        Ok(t) => t <= now,
        Err(_) => true,
    }
}
