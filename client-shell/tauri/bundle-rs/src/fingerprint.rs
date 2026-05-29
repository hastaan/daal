//! Fingerprint type + rendering, matching `bundle/go/bundle/fingerprint.go`.
//!
//! The `render_words` algorithm, the visual SVG palette, and the
//! data-URI base64 are all bit-for-bit identical to the Go side.

use base64::Engine as _;
use sha2::Digest;

use crate::errors::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    bytes: [u8; 32],
}

impl Fingerprint {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let v = hex::decode(hex_str)?;
        if v.len() != 32 {
            return Err(Error::FingerprintMismatch);
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        Ok(Self { bytes: a })
    }

    pub fn hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[derive(Debug, Clone)]
pub enum Lang {
    English,
    Persian,
}

#[derive(Debug, Clone)]
pub struct RenderedFingerprint {
    pub hex: String,
    pub en: String,
    pub fa: String,
    pub visual_data_uri: String,
}

/// Render a fingerprint into hex + EN words + FA words + a deterministic
/// visual SVG, byte-identical to `bundle.RenderFingerprint`.
pub fn render_fingerprint(
    fp: &Fingerprint,
    en_wordlist: &[&str],
    fa_wordlist: &[&str],
) -> RenderedFingerprint {
    let bytes = fp.bytes();
    let en = render_words(bytes, en_wordlist);
    let fa = render_words(bytes, fa_wordlist);
    let visual = render_visual(bytes);
    RenderedFingerprint {
        hex: fp.hex(),
        en,
        fa,
        visual_data_uri: visual,
    }
}

fn render_words(bytes: &[u8; 32], words: &[&str]) -> String {
    if words.is_empty() {
        return String::new();
    }
    // Mirrors the bit-extraction in Go.
    let i0 = ((bytes[0] as usize) << 3) | ((bytes[1] as usize) >> 5);
    let i1 = ((bytes[1] as usize & 0x1f) << 6) | ((bytes[2] as usize) >> 2);
    let i2 =
        ((bytes[2] as usize & 0x03) << 9) | ((bytes[3] as usize) << 1) | ((bytes[4] as usize) >> 7);
    let i3 = ((bytes[4] as usize & 0x7f) << 4) | ((bytes[5] as usize) >> 4);
    let indexes = [i0, i1, i2, i3];
    let parts: Vec<&str> = indexes.iter().map(|i| words[i % words.len()]).collect();
    parts.join("-")
}

fn render_visual(bytes: &[u8; 32]) -> String {
    let palette = ["#1b1b1b", "#0072b2", "#e69f00", "#009e73", "#cc79a7"];
    let mut s = String::new();
    s.push_str(r#"<svg xmlns="http://www.w3.org/2000/svg" width="50" height="50">"#);
    for i in 0..25 {
        let color = palette[(bytes[i % bytes.len()] as usize) % palette.len()];
        let x = (i % 5) * 10;
        let y = (i / 5) * 10;
        s.push_str(&format!(
            r#"<rect x="{}" y="{}" width="10" height="10" fill="{}"/>"#,
            x, y, color
        ));
    }
    s.push_str("</svg>");
    let mut out = String::from("data:image/svg+xml;base64,");
    out.push_str(&base64::engine::general_purpose::STANDARD.encode(s.as_bytes()));
    out
}

/// SHA-256 of arbitrary bytes, in case callers want the same primitive
/// the publisher fingerprint uses without going through the public API.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let fp = Fingerprint::from_bytes([7u8; 32]);
        let en = ["alpha", "bravo", "charlie", "delta"];
        let fa = ["یک", "دو", "سه", "چهار"];
        let a = render_fingerprint(&fp, &en, &fa);
        let b = render_fingerprint(&fp, &en, &fa);
        assert_eq!(a.hex, b.hex);
        assert_eq!(a.en, b.en);
        assert_eq!(a.fa, b.fa);
        assert_eq!(a.visual_data_uri, b.visual_data_uri);
        assert!(!a.hex.is_empty() && !a.en.is_empty() && !a.fa.is_empty());
    }
}
