//! Error type mirroring `bundle/go/bundle/errors.go`.
//!
//! The variant set is intentionally identical to the Go side so the
//! parity test can match by name.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("missing manifest.json")]
    MissingManifest,

    #[error("missing manifest.sig")]
    MissingSignature,

    #[error("missing publisher.pub")]
    MissingPublisherKey,

    #[error("invalid bundle signature")]
    InvalidSignature,

    #[error("invalid publisher public key")]
    InvalidPublisherKey,

    #[error("unsupported spec version")]
    UnsupportedSpec,

    #[error("bundle expired")]
    ExpiredBundle,

    #[error("route expired")]
    ExpiredRoute,

    #[error("missing route profile")]
    MissingProfile,

    #[error("unsafe archive path")]
    UnsafePath,

    #[error("invalid enum value")]
    InvalidEnum,

    #[error("publisher revoked")]
    RevokedPublisher,

    #[error("route revoked")]
    RevokedRoute,

    #[error("publisher fingerprint mismatch")]
    FingerprintMismatch,

    /// Wave 5. A route names `transport_family = "anytls"` while the
    /// manifest declares `spec_version < 5`. Twin of Go's
    /// `ErrAnyTLSSpecVersionTooOld`.
    #[error("transport_family=anytls requires spec_version >= 5")]
    AnyTlsSpecVersionTooOld,

    /// Wave 5, INTERNAL. Separates "this route names a family we do not
    /// know" from every other route failure so `verify_bundle_at` can
    /// apply the spec_version-gated degradation rule to that one case.
    ///
    /// Never escapes the crate's public verification path: at
    /// spec_version <= 4 it is translated back into `InvalidEnum` (what
    /// every shipped client and the cross-language fixture corpus
    /// expect), and at spec_version >= 5 it is swallowed in favour of
    /// dropping the route.
    #[error("unknown transport family")]
    UnknownFamily,

    /// Wave 5. Every route was dropped as an unknown transport family.
    /// Only reachable at `spec_version >= 5`, where an unknown family
    /// degrades the route instead of the pack. Twin of Go's
    /// `ErrNoUsableRoutes`.
    #[error("no route in this pack names a transport family this build understands")]
    NoUsableRoutes,

    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("zip read error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("invalid time format: {0}")]
    Time(String),
}

impl Error {
    /// Stable string code matching the Go variant name. Used by the
    /// parity oracle test and by the Tauri UI for translation lookup.
    pub fn code(&self) -> &'static str {
        match self {
            Error::MissingManifest => "ErrMissingManifest",
            Error::MissingSignature => "ErrMissingSignature",
            Error::MissingPublisherKey => "ErrMissingPublisherKey",
            Error::InvalidSignature => "ErrInvalidSignature",
            Error::InvalidPublisherKey => "ErrInvalidPublisherKey",
            Error::UnsupportedSpec => "ErrUnsupportedSpec",
            Error::ExpiredBundle => "ErrExpiredBundle",
            Error::ExpiredRoute => "ErrExpiredRoute",
            Error::MissingProfile => "ErrMissingProfile",
            Error::UnsafePath => "ErrUnsafePath",
            Error::InvalidEnum => "ErrInvalidEnum",
            Error::RevokedPublisher => "ErrRevokedPublisher",
            Error::RevokedRoute => "ErrRevokedRoute",
            Error::FingerprintMismatch => "ErrFingerprintMismatch",
            Error::AnyTlsSpecVersionTooOld => "ErrAnyTLSSpecVersionTooOld",
            Error::NoUsableRoutes => "ErrNoUsableRoutes",
            // Internal sentinel that never escapes verification. It is
            // given a code only so this match stays exhaustive; if it
            // ever appears in a parity oracle run, the degradation
            // branch in sbp.rs has leaked and that is the bug.
            Error::UnknownFamily => "ErrUnknownFamilyInternal",
            Error::Json(_) => "ErrJson",
            Error::Zip(_) => "ErrZip",
            Error::Io(_) => "ErrIo",
            Error::Hex(_) => "ErrHex",
            Error::Time(_) => "ErrTime",
        }
    }
}
