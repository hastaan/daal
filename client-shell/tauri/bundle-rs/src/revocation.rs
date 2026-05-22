//! Revocation parsing & signed-revocation-list verification.
//!
//! `RevocationList` mirrors the in-archive `revocation.json` shape from
//! `bundle/go/bundle/types.go`.  `verify_revocation` mirrors
//! `publisher.VerifySignedRevocationBytes`, accepting the wire format
//! produced by `publisher.BuildSignedRevocationList`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::errors::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationList {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_publishers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_routes: Vec<String>,
}

/// Wire format for `publisher.BuildSignedRevocationList`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRevocation {
    pub v: i32,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_publishers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_routes: Vec<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_hex: String,
}

/// Result of a successful `verify_revocation`.
#[derive(Debug, Clone)]
pub struct RevocationSet {
    pub issued_at: String,
    pub revoked_publishers: Vec<String>,
    pub revoked_routes: Vec<String>,
    pub reason: String,
}

/// Parses an in-archive `revocation.json`.
pub fn parse_revocation(bytes: &[u8]) -> Result<RevocationList, Error> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Verifies a signed revocation list against a pinned ed25519 key.
///
/// Mirrors `publisher.VerifySignedRevocationBytes`.
pub fn verify_revocation(body: &[u8], signing_pub: &[u8]) -> Result<RevocationSet, Error> {
    if body.is_empty() {
        return Err(Error::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "revocation body is empty",
        ))));
    }
    if signing_pub.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublisherKey);
    }
    let rev: SignedRevocation = serde_json::from_slice(body)?;
    if rev.v != 1 {
        return Err(Error::UnsupportedSpec);
    }
    if rev.issued_at.is_empty() || rev.reason.is_empty() {
        return Err(Error::InvalidEnum);
    }
    let sig_bytes = hex::decode(&rev.signature_hex)?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignature);
    }

    // Strip the signature_hex field, then canonicalize what remains.
    let mut as_value = serde_json::to_value(&rev)?;
    if let serde_json::Value::Object(map) = &mut as_value {
        map.remove("signature_hex");
    }
    let canonical = canonical_json(&as_value)?;

    let key_array: [u8; PUBLIC_KEY_LENGTH] = signing_pub
        .try_into()
        .map_err(|_| Error::InvalidPublisherKey)?;
    let vk = VerifyingKey::from_bytes(&key_array).map_err(|_| Error::InvalidPublisherKey)?;
    let sig_array: [u8; SIGNATURE_LENGTH] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_array);
    vk.verify(&canonical, &signature)
        .map_err(|_| Error::InvalidSignature)?;

    Ok(RevocationSet {
        issued_at: rev.issued_at,
        revoked_publishers: rev.revoked_publishers,
        revoked_routes: rev.revoked_routes,
        reason: rev.reason,
    })
}
