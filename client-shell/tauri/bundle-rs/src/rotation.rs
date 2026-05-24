//! Rotation chain envelope, mirroring `publisher.RotationChain` in Go.
//!
//! Rotation envelopes are signed by the OLD root and assert that the
//! NEW root is trusted from `transition_starts_at` to `transition_ends_at`.
//! This module verifies a single rotation envelope; chain verification
//! over multiple rotations is the trivial repeated application below.

use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::errors::Error;
use crate::publisher_fingerprint;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationEnvelope {
    pub v: i32,
    pub kind: String,
    pub old_root_fingerprint_hex: String,
    pub new_root_pub_hex: String,
    pub transition_starts_at: String,
    pub transition_ends_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_hex: String,
}

/// Verifies a single rotation envelope. Mirrors
/// `publisher.VerifyRotationChain` in Go.
pub fn verify_rotation_envelope(
    chain: &RotationEnvelope,
    old_pub: &[u8],
    new_pub: &[u8],
    now: time::OffsetDateTime,
) -> Result<(), Error> {
    if chain.v != 1 || chain.kind != "root_rotation" {
        return Err(Error::UnsupportedSpec);
    }

    let fp = publisher_fingerprint(old_pub);
    if fp.hex() != chain.old_root_fingerprint_hex {
        return Err(Error::FingerprintMismatch);
    }

    let declared = hex::decode(&chain.new_root_pub_hex)?;
    if declared.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublisherKey);
    }
    if declared != new_pub {
        return Err(Error::FingerprintMismatch);
    }

    let from = parse_rfc3339(&chain.transition_starts_at)?;
    let until = parse_rfc3339(&chain.transition_ends_at)?;
    if now < from || now >= until {
        return Err(Error::ExpiredBundle);
    }

    let sig_bytes = hex::decode(&chain.signature_hex)?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignature);
    }

    let mut as_value = serde_json::to_value(chain)?;
    if let serde_json::Value::Object(map) = &mut as_value {
        map.remove("signature_hex");
    }
    let canonical = canonical_json(&as_value)?;

    if old_pub.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublisherKey);
    }
    let key_array: [u8; PUBLIC_KEY_LENGTH] =
        old_pub.try_into().map_err(|_| Error::InvalidPublisherKey)?;
    let vk = VerifyingKey::from_bytes(&key_array).map_err(|_| Error::InvalidPublisherKey)?;
    let sig_array: [u8; SIGNATURE_LENGTH] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_array);
    vk.verify(&canonical, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Verify a chain of rotation envelopes from `root` to the final pub.
///
/// Each envelope must connect to the next: envelope[i].new_root_pub_hex
/// equals the old fingerprint asserted by envelope[i+1].
pub fn verify_rotation_chain(
    envelopes: &[RotationEnvelope],
    root_pub: &[u8],
    now: time::OffsetDateTime,
) -> Result<Vec<u8>, Error> {
    if envelopes.is_empty() {
        return Ok(root_pub.to_vec());
    }
    let mut current = root_pub.to_vec();
    for env in envelopes {
        let new_pub = hex::decode(&env.new_root_pub_hex)?;
        verify_rotation_envelope(env, &current, &new_pub, now)?;
        current = new_pub;
    }
    Ok(current)
}

fn parse_rfc3339(s: &str) -> Result<time::OffsetDateTime, Error> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::Time(e.to_string()))
}
