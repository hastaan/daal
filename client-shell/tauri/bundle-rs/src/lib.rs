//! `bundle-rs` — pure-Rust verify-only port of `bundle/go/bundle`.
//!
//! This crate is consumed by `client-ui` to give the UI a
//! fast local verifier that does not depend on the Go c-shared engine.
//! It supports:
//!
//! * `parse_manifest` / `verify_manifest` — manifest JSON + ed25519
//!   detached signature, with the same canonical-JSON serialization the
//!   Go side uses.
//! * `parse_sbp` — `.sbp` (zip) archive walk with `unsafe_path` checks.
//! * `verify_bundle` — full top-level verification matching
//!   `bundle.VerifyBundle` in Go (spec_version 1 OR 2 accepted; v3+
//!   rejected with `Error::UnsupportedSpec`).
//! * `render_fingerprint` — hex + EN words + FA words + visual SVG
//!   data-URI, byte-identical to `bundle.RenderFingerprint`.
//! * `verify_rotation_chain` — placeholder; expanded in Phase 2.
//! * `verify_revocation` — accepts the signed-revocation-list bytes
//!   produced by `publisher.BuildSignedRevocationList`.
//!
//! Parity is enforced by `tests/parity_with_go.rs`, which feeds the
//! same `specs/test-vectors/` corpus through both `bundle-go` (via a
//! pre-built JSON oracle) and this crate.
//!
//! ## Privacy
//!
//! No function in this crate touches the network, the filesystem, or
//! the clock for purposes other than RFC3339 expiry comparison. There
//! is no logging.
//!
//! ## Safety
//!
//! `#![forbid(unsafe_code)]` — see `Cargo.toml`.

pub mod canonical;
pub mod errors;
pub mod fingerprint;
pub mod manifest;
pub mod revocation;
pub mod rotation;
pub mod sbp;

pub use crate::errors::Error;
pub use crate::fingerprint::{render_fingerprint, Fingerprint, Lang, RenderedFingerprint};
#[allow(deprecated)]
pub use crate::manifest::verify_manifest;
pub use crate::manifest::{
    parse_manifest, verify_manifest_bytes, BundleInfo, Manifest, PointerRotationRef,
    PublisherInfo, RouteManifestEntry,
};
pub use crate::revocation::{parse_revocation, verify_revocation, RevocationList, RevocationSet};
pub use crate::rotation::{verify_rotation_chain, RotationEnvelope};
pub use crate::sbp::{parse_sbp, verify_bundle, verify_bundle_at, Sbp};

/// SHA-256 of the publisher public key, hex-encoded.
///
/// Matches `bundle.PublisherFingerprint` in Go.
pub fn publisher_fingerprint(pub_key: &[u8]) -> Fingerprint {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pub_key);
    let sum = h.finalize();
    Fingerprint::from_bytes(sum.into())
}
