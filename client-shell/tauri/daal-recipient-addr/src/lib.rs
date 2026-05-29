//! Branded `daal1...` recipient address codec.
//!
//! Rust mirror of `core/recipient/address`. The two impls share a
//! golden test-vector file at
//! `specs/test-vectors/recipient-address-v1/golden.json`; the test
//! `golden_vectors_round_trip()` below loads it and asserts byte
//! equality with the Go side.
//!
//! Spec: `specs/recipient-address-v1.md`.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Fixed length of an encoded daal1... address.
/// 32 bytes → 52 5-bit groups (with 1-bit zero pad) + 6 bech32m
/// checksum = 58 data chars; plus "daal" (4) + "1" (1) = 63 chars.
pub const ADDRESS_LEN: usize = 63;

/// Human-readable part of every Daal address.
pub const HRP: &str = "daal";

/// QR / deep-link URI prefix wrapping the bare address.
pub const URI_PREFIX: &str = "daal://addr/";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("daal address: invalid length")]
    InvalidLength,
    #[error("daal address: mixed case not permitted")]
    MixedCase,
    #[error("daal address: wrong human-readable part")]
    WrongHrp,
    #[error("daal address: bech32m checksum mismatch")]
    Checksum,
    #[error("daal address: payload is not 32 bytes")]
    PayloadLength,
    #[error("daal address: not a daal://addr/ URI")]
    InvalidUri,
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const BECH32M_CONST: u32 = 0x2BC8_30A3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = (chk & 0x1ff_ffff) << 5 ^ u32::from(v);
        for (i, &g) in GEN.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 2 + 1);
    for &c in bytes {
        out.push(c >> 5);
    }
    out.push(0);
    for &c in bytes {
        out.push(c & 0x1f);
    }
    out
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let m = polymod(&values) ^ BECH32M_CONST;
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((m >> (5 * (5 - i as u32))) & 31) as u8;
    }
    out
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut all = hrp_expand(hrp);
    all.extend_from_slice(data);
    polymod(&all) == BECH32M_CONST
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, AddressError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1u32 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &v in data {
        if u32::from(v) >= (1u32 << from) {
            return Err(AddressError::Checksum);
        }
        acc = (acc << from) | u32::from(v);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(AddressError::Checksum);
    }
    Ok(out)
}

/// Encode a 32-byte X25519 public key as a lowercase daal1...
/// address. Deterministic; pinned by cross-impl golden vectors.
pub fn encode(pub_key: &[u8; 32]) -> String {
    let conv = convert_bits(pub_key, 8, 5, true).expect("32-byte input always encodes");
    let mut combined = conv.clone();
    combined.extend_from_slice(&create_checksum(HRP, &conv));
    let mut s = String::with_capacity(ADDRESS_LEN);
    s.push_str(HRP);
    s.push('1');
    for c in &combined {
        s.push(CHARSET[*c as usize] as char);
    }
    s
}

/// Decode a daal1... or daal://addr/daal1... string into the 32
/// raw pubkey bytes. Rejects mixed case, wrong length, wrong HRP,
/// checksum failures, and wrong payload size.
pub fn decode(input: &str) -> Result<[u8; 32], AddressError> {
    let s = input.strip_prefix(URI_PREFIX).unwrap_or(input);
    if s.len() != ADDRESS_LEN {
        return Err(AddressError::InvalidLength);
    }
    let mut has_lower = false;
    let mut has_upper = false;
    for c in s.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        }
        if c.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    if has_lower && has_upper {
        return Err(AddressError::MixedCase);
    }
    let lower = s.to_ascii_lowercase();
    let sep = lower
        .rfind('1')
        .ok_or(AddressError::InvalidLength)?;
    if sep < 1 || sep + 7 > lower.len() {
        return Err(AddressError::InvalidLength);
    }
    let hrp = &lower[..sep];
    if hrp != HRP {
        return Err(AddressError::WrongHrp);
    }
    let data_part = &lower[sep + 1..];
    let mut data = Vec::with_capacity(data_part.len());
    for &b in data_part.as_bytes() {
        match CHARSET.iter().position(|&c| c == b) {
            Some(idx) => data.push(idx as u8),
            None => return Err(AddressError::Checksum),
        }
    }
    if !verify_checksum(hrp, &data) {
        return Err(AddressError::Checksum);
    }
    let payload = &data[..data.len() - 6];
    let raw = convert_bits(payload, 5, 8, false)?;
    if raw.len() != 32 {
        return Err(AddressError::PayloadLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Require the daal://addr/ prefix to be present and decode the
/// suffix. Use this for deep-link handlers; use `decode()` for
/// pasted text or scanned QR payloads that may or may not carry
/// the prefix.
pub fn parse_uri(input: &str) -> Result<[u8; 32], AddressError> {
    if !input.starts_with(URI_PREFIX) {
        return Err(AddressError::InvalidUri);
    }
    decode(&input[URI_PREFIX.len()..])
}

/// Return the SHA-256 of the 32-byte X25519 pub, hex-encoded
/// (64 lowercase chars). This is the value the publisher stamps
/// into `bundle.recipient_fp_hex` on a .sbpx-wrapped pack.
pub fn fingerprint(pub_key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(pub_key);
    let sum = h.finalize();
    hex::encode(sum)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_random_like() {
        // Deterministic patterns; no rand crate dependency here.
        let mut seed = [0x11u8; 32];
        for i in 0..256 {
            for (j, b) in seed.iter_mut().enumerate() {
                *b = (*b).wrapping_add((i as u8).wrapping_add(j as u8).wrapping_mul(7));
            }
            let s = encode(&seed);
            assert_eq!(s.len(), ADDRESS_LEN);
            assert!(s.starts_with("daal1"));
            let back = decode(&s).unwrap();
            assert_eq!(back, seed);
        }
    }

    #[test]
    fn zero_key_pin() {
        let z = [0u8; 32];
        let s = encode(&z);
        assert_eq!(s.len(), ADDRESS_LEN);
        assert!(s.starts_with("daal1qqqqqqqq"));
        assert_eq!(decode(&s).unwrap(), z);
    }

    #[test]
    fn single_char_corruption_detected() {
        let mut k = [0u8; 32];
        k[0] = 0x42;
        let s = encode(&k);
        for pos in HRP.len() + 1..s.len() {
            for &alt in CHARSET.iter() {
                if alt == s.as_bytes()[pos] {
                    continue;
                }
                let mut bytes = s.as_bytes().to_vec();
                bytes[pos] = alt;
                let corrupted = std::str::from_utf8(&bytes).unwrap();
                assert!(
                    decode(corrupted).is_err(),
                    "single-char corruption at {pos} not detected"
                );
            }
        }
    }

    #[test]
    fn mixed_case_rejected() {
        let z = [0u8; 32];
        let s = encode(&z);
        let mut bytes = s.into_bytes();
        bytes[10] = bytes[10].to_ascii_uppercase();
        let mixed = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(decode(mixed), Err(AddressError::MixedCase));
    }

    #[test]
    fn wrong_length_rejected() {
        for s in ["", "daal1", &"q".repeat(62), &"q".repeat(64)] {
            assert_eq!(decode(s), Err(AddressError::InvalidLength), "{s:?}");
        }
    }

    #[test]
    fn wrong_hrp_rejected() {
        let z = [0u8; 32];
        let good = encode(&z);
        let bad = format!("bcco{}", &good[4..]);
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn uri_prefix_strip() {
        let z = [0u8; 32];
        let s = encode(&z);
        let uri = format!("{URI_PREFIX}{s}");
        assert_eq!(decode(&uri).unwrap(), z);
        assert_eq!(parse_uri(&uri).unwrap(), z);
        assert_eq!(parse_uri(&s), Err(AddressError::InvalidUri));
    }

    #[test]
    fn fingerprint_zero_pin() {
        let z = [0u8; 32];
        let want = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925";
        assert_eq!(fingerprint(&z), want);
    }

    #[test]
    fn golden_vectors_round_trip() {
        use serde::Deserialize;
        #[derive(Deserialize)]
        struct V {
            pub_hex: String,
            address: String,
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../specs/test-vectors/recipient-address-v1/golden.json");
        let data = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("read {}: {e}", path.display());
        });
        let vectors: Vec<V> = serde_json::from_slice(&data).unwrap();
        assert!(vectors.len() >= 8);
        for v in &vectors {
            let pub_bytes = hex::decode(&v.pub_hex).unwrap();
            assert_eq!(pub_bytes.len(), 32);
            let mut k = [0u8; 32];
            k.copy_from_slice(&pub_bytes);
            assert_eq!(encode(&k), v.address);
            assert_eq!(decode(&v.address).unwrap(), k);
        }
    }
}
