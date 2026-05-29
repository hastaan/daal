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
            Error::Json(_) => "ErrJson",
            Error::Zip(_) => "ErrZip",
            Error::Io(_) => "ErrIo",
            Error::Hex(_) => "ErrHex",
            Error::Time(_) => "ErrTime",
        }
    }
}
