//! `.sbp` (zip) parsing and full-bundle verification.
//!
//! Mirrors `bundle/go/bundle/sbp.go`.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::errors::Error;
use crate::manifest::{expired, parse_manifest, verify_manifest, Manifest};
use crate::publisher_fingerprint;
use crate::revocation::{parse_revocation, RevocationList};

#[derive(Debug, Clone)]
pub struct Sbp {
    pub manifest: Manifest,
    pub signature: Vec<u8>,
    pub publisher_pub: Vec<u8>,
    pub profiles: HashMap<String, Vec<u8>>,
    pub revocation: Option<RevocationList>,
    /// All other archive entries (e.g. `trust/pointer-rotation.json`).
    pub aux: HashMap<String, Vec<u8>>,
}

const SCARCITY_CLASSES: &[&str] = &[
    "emergency",
    "low",
    "normal",
    "bulk-capable",
    "experimental",
    "lifeline-only",
];

const TRANSPORT_FAMILIES: &[&str] = &[
    "vless-reality",
    "naive",
    "websocket-tls",
    "hysteria2",
    "tuic",
    "snowflake",
    "webtunnel",
    "masque",
    "shadowsocks",
    "tor-bridge",
    "wireguard",
    "amneziawg",
    "other",
];

/// Parses the bytes of a `.sbp` file into its component members.
///
/// Equivalent to `bundle.ParseSBP` in Go.
pub fn parse_sbp(bytes: &[u8]) -> Result<Sbp, Error> {
    let cursor = Cursor::new(bytes);
    let mut zr = zip::ZipArchive::new(cursor)?;

    let mut all = HashMap::<String, Vec<u8>>::new();
    for i in 0..zr.len() {
        let mut f = zr.by_index(i)?;
        let name = f.name().to_string();
        if unsafe_archive_path(&name) {
            return Err(Error::UnsafePath);
        }
        let mut data = Vec::with_capacity(f.size() as usize);
        f.read_to_end(&mut data)?;
        all.insert(name, data);
    }

    let manifest_bytes = all.remove("manifest.json").ok_or(Error::MissingManifest)?;
    let signature = all.remove("manifest.sig").ok_or(Error::MissingSignature)?;
    let publisher_pub = all
        .remove("publisher.pub")
        .ok_or(Error::MissingPublisherKey)?;

    if publisher_pub.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidPublisherKey);
    }

    let manifest = parse_manifest(&manifest_bytes)?;

    let mut profiles = HashMap::<String, Vec<u8>>::new();
    let mut revocation: Option<RevocationList> = None;
    let mut aux = HashMap::<String, Vec<u8>>::new();
    for (name, data) in all.into_iter() {
        if name.starts_with("profiles/") && name != "profiles/" {
            profiles.insert(name, data);
        } else if name == "revocation.json" {
            revocation = Some(parse_revocation(&data)?);
        } else {
            aux.insert(name, data);
        }
    }

    Ok(Sbp {
        manifest,
        signature,
        publisher_pub,
        profiles,
        revocation,
        aux,
    })
}

/// Full top-level bundle verification. Equivalent to
/// `bundle.VerifyBundle` in Go.
pub fn verify_bundle(b: &Sbp) -> Result<(), Error> {
    verify_bundle_at(b, time::OffsetDateTime::now_utc())
}

/// Full top-level bundle verification using an injected clock.
///
/// Production callers should use [`verify_bundle`]. Tests use this helper to
/// verify deterministic fixture bundles at the same pinned instant used by the
/// Go fixture generator, so parity does not change as wall-clock time passes.
pub fn verify_bundle_at(b: &Sbp, now: time::OffsetDateTime) -> Result<(), Error> {
    // Phase 1.5A: spec_version 1 OR 2 accepted.
    if b.manifest.spec_version != 1 && b.manifest.spec_version != 2 {
        return Err(Error::UnsupportedSpec);
    }
    verify_manifest(&b.manifest, &b.signature, &b.publisher_pub)?;

    let fp = publisher_fingerprint(&b.publisher_pub);
    if !b.manifest.publisher.key_fingerprint_hex.is_empty()
        && b.manifest.publisher.key_fingerprint_hex != fp.hex()
    {
        return Err(Error::FingerprintMismatch);
    }

    if expired(&b.manifest.bundle.expires_at, now) {
        return Err(Error::ExpiredBundle);
    }

    if let Some(rev) = &b.revocation {
        for publisher in &rev.revoked_publishers {
            if publisher == &fp.hex() {
                return Err(Error::RevokedPublisher);
            }
        }
    }

    for route in &b.manifest.routes {
        validate_route(route, b, now)?;
    }
    Ok(())
}

fn validate_route(
    route: &crate::manifest::RouteManifestEntry,
    b: &Sbp,
    now: time::OffsetDateTime,
) -> Result<(), Error> {
    if !SCARCITY_CLASSES.contains(&route.scarcity_class.as_str())
        || !TRANSPORT_FAMILIES.contains(&route.transport_family.as_str())
    {
        return Err(Error::InvalidEnum);
    }
    if unsafe_archive_path(&route.config_path) {
        return Err(Error::UnsafePath);
    }
    if !b.profiles.contains_key(&route.config_path) {
        return Err(Error::MissingProfile);
    }
    if expired(&route.valid_until, now) {
        return Err(Error::ExpiredRoute);
    }
    if let Some(rev) = &b.revocation {
        for revoked in &rev.revoked_routes {
            if revoked == &route.id {
                return Err(Error::RevokedRoute);
            }
        }
    }
    Ok(())
}

fn unsafe_archive_path(name: &str) -> bool {
    if name.starts_with('/') {
        return true;
    }
    // Mirror Go's path.Clean + prefix check.
    let cleaned = clean_path(name);
    cleaned == ".." || cleaned.starts_with("../")
}

/// Minimal port of Go's `path.Clean` for the unsafe-path check.
fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => continue,
            ".." => match out.last() {
                Some(&last) if last != ".." => {
                    out.pop();
                }
                _ => out.push(".."),
            },
            other => out.push(other),
        }
    }
    if out.is_empty() {
        return ".".to_string();
    }
    out.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_paths() {
        assert!(unsafe_archive_path("/etc/passwd"));
        assert!(unsafe_archive_path("../escape.txt"));
        assert!(unsafe_archive_path(".."));
        assert!(!unsafe_archive_path("profiles/route.json"));
        assert!(!unsafe_archive_path("trust/pointer-rotation.json"));
    }
}
