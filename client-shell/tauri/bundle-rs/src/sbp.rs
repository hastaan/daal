//! `.sbp` (zip) parsing and full-bundle verification.
//!
//! Mirrors `bundle/go/bundle/sbp.go`.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::errors::Error;
use crate::manifest::{expired, parse_manifest, verify_manifest_bytes, Manifest};
use crate::publisher_fingerprint;
use crate::revocation::{parse_revocation, RevocationList};

#[derive(Debug, Clone)]
pub struct Sbp {
    /// Parsed view of `manifest.json` — convenient for accessing
    /// `publisher.name`, `routes[]`, etc. Treat this as **lossy**:
    /// fields that bundle-rs's struct doesn't model (e.g.
    /// spec-version-3 `relay_pack`, `shared_risk_graph`, or
    /// `family_specific_config` route extensions) are dropped during
    /// deserialize. Use [`Sbp::manifest_bytes`] for anything where
    /// byte-exactness matters (signature verification, hashing).
    pub manifest: Manifest,
    /// **Authoritative** raw bytes of `manifest.json` as they were
    /// written to the archive by the publisher. The ed25519
    /// signature is over **these exact bytes**, not over a
    /// canonical re-serialization of the parsed struct.
    ///
    /// This is the modern best-practice approach used by every
    /// detached-signature format from JWS to signed Git commits:
    /// verify against the bytes that arrived, never against bytes
    /// re-derived by parse-then-re-marshal. It makes signature
    /// verification immune to schema drift (new fields on the
    /// publisher side don't break recipients) and removes a whole
    /// class of canonicalization-bug surface.
    pub manifest_bytes: Vec<u8>,
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
    // Wave 5. Legal only at spec_version >= SPEC_VERSION_ANYTLS;
    // `validate_route` enforces that separately, because this list is
    // also what `usable_routes` consults after verification.
    "anytls",
    "other",
];

/// The manifest `spec_version` at which `anytls` becomes a legal
/// transport family AND an unknown transport family stops being fatal
/// to the whole pack. Twin of Go's `bundle.SpecVersionAnyTLS`; the two
/// numbers must move together or the Rust and Go clients disagree about
/// the same file.
pub const SPEC_VERSION_ANYTLS: i32 = 5;

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
        manifest_bytes,
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
    // Accepted spec versions mirror the Go canonical verifier
    // (bundle/go/bundle/sbp.go::verifyBundleCore): 1 (legacy),
    // 2 (3A-3F), 3 (RelayPack), 4 (sub-key cert chain / cell
    // aggregator), 5 (anytls + per-route unknown-family degradation).
    // Anything outside that window is rejected.
    //
    // This gate runs BEFORE the route loop, which is what makes a
    // spec bump the right carrier for a new family: a build older than
    // this one stops here and reports "unsupported spec version"
    // rather than reaching the route loop and reporting the pack as
    // corrupt.
    if !matches!(b.manifest.spec_version, 1 | 2 | 3 | 4 | 5) {
        return Err(Error::UnsupportedSpec);
    }
    // Verify the ed25519 signature against the **raw** manifest.json
    // bytes from the archive, not against a re-marshaled canonical
    // form of the parsed struct. See `Sbp::manifest_bytes` for the
    // rationale.
    verify_manifest_bytes(&b.manifest_bytes, &b.signature, &b.publisher_pub)?;

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

    // Route loop. Mirrors the Go twin exactly, including which failure
    // is downgradable and which is not: an unknown transport family
    // costs one route at spec_version >= 5, everything else still
    // costs the pack. See `validate_route` for why the family check is
    // last.
    let mut usable = 0usize;
    for route in &b.manifest.routes {
        match validate_route(route, b, now) {
            Err(Error::UnknownFamily) => {
                if b.manifest.spec_version >= SPEC_VERSION_ANYTLS {
                    continue; // blast radius: this route, not the pack.
                }
                return Err(Error::InvalidEnum);
            }
            Err(e) => return Err(e),
            Ok(()) => usable += 1,
        }
    }
    if !b.manifest.routes.is_empty() && usable == 0 {
        return Err(Error::NoUsableRoutes);
    }
    Ok(())
}

/// Reports whether one route of a VERIFIED bundle names a transport
/// family this build understands. Twin of Go's `bundle.RouteUsable`.
pub fn route_usable(route: &crate::manifest::RouteManifestEntry) -> bool {
    TRANSPORT_FAMILIES.contains(&route.transport_family.as_str())
}

/// Returns the subset of a VERIFIED bundle's routes this build can
/// represent. Twin of Go's `bundle.UsableRoutes`.
///
/// Every consumer that turns a manifest into stored routes must use
/// this rather than walking `manifest.routes` directly, or it will
/// persist a route whose family nothing downstream can dial.
pub fn usable_routes(b: &Sbp) -> Vec<&crate::manifest::RouteManifestEntry> {
    b.manifest.routes.iter().filter(|r| route_usable(r)).collect()
}

/// Validates one route.
///
/// ORDER IS LOAD-BEARING, exactly as in the Go twin: the
/// transport_family check comes LAST, after every safety, freshness and
/// revocation check has passed, because it is the only failure the
/// caller may downgrade from "reject the pack" to "drop the route". If
/// it came first, an unknown family name would double as a way to skip
/// this route's own unsafe-path and revocation checks.
fn validate_route(
    route: &crate::manifest::RouteManifestEntry,
    b: &Sbp,
    now: time::OffsetDateTime,
) -> Result<(), Error> {
    // Scarcity stays hard-fatal and ungated; see the Go twin.
    if !SCARCITY_CLASSES.contains(&route.scarcity_class.as_str()) {
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
    // Wave 5, and LAST on purpose — see this function's doc comment.
    //
    // A pack may not name anytls while claiming an older spec_version:
    // such a pack is rejected WHOLE by every client shipped before
    // Wave 5, and reported as corrupted. Refusing it here means it
    // fails at mint time rather than in a recipient's hands.
    if route.transport_family == "anytls" && b.manifest.spec_version < SPEC_VERSION_ANYTLS {
        return Err(Error::AnyTlsSpecVersionTooOld);
    }
    if !TRANSPORT_FAMILIES.contains(&route.transport_family.as_str()) {
        // Internal sentinel; the caller turns this into either
        // InvalidEnum (spec <= 4, historical behaviour) or a dropped
        // route (spec >= 5). It never reaches an external caller.
        return Err(Error::UnknownFamily);
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
