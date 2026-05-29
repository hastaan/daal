//! Canonical JSON, byte-identical to `bundle/go/bundle/canonical.go`.
//!
//! Algorithm (matching Go):
//!
//! 1. Marshal the manifest with the language's standard JSON encoder.
//! 2. Re-parse to a generic value tree.
//! 3. Re-emit:
//!    - object keys sorted lexicographically;
//!    - integers formatted with no decimal point when float == int;
//!    - strings emitted via the standard JSON string-escaper.
//!
//! Steps 1+2 round-trip drops Go's omitted fields (zero values without
//! `omitempty`) the same way `serde_json` does for `Option<T>` with
//! `#[serde(skip_serializing_if = "Option::is_none")]`. We also follow
//! Go's habit of always emitting `[]` (not `null`) for slices that are
//! initialized but empty.

use std::io::Write;

use serde_json::Value;

use crate::errors::Error;

/// Re-serializes any JSON value into Go-compatible canonical form.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(512);
    write_value(&mut buf, value)?;
    Ok(buf)
}

/// Convenience: serialize a `Serialize` directly through canonical JSON.
pub fn canonical_marshal<T: serde::Serialize>(t: &T) -> Result<Vec<u8>, Error> {
    let v = serde_json::to_value(t)?;
    canonical_json(&v)
}

fn write_value(buf: &mut Vec<u8>, value: &Value) -> Result<(), Error> {
    match value {
        Value::Null => {
            buf.extend_from_slice(b"null");
        }
        Value::Bool(b) => {
            if *b {
                buf.extend_from_slice(b"true");
            } else {
                buf.extend_from_slice(b"false");
            }
        }
        Value::Number(n) => {
            // serde_json::Number is already a tight integer/float; we
            // mirror Go's choice: when the value is an integer, emit
            // without a decimal point.
            if let Some(i) = n.as_i64() {
                write!(buf, "{}", i).ok();
            } else if let Some(u) = n.as_u64() {
                write!(buf, "{}", u).ok();
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() && f == (f as i64 as f64) {
                    write!(buf, "{}", f as i64).ok();
                } else {
                    // Match Go's strconv.FormatFloat(v,'f',-1,64)
                    write!(buf, "{}", f).ok();
                }
            } else {
                return Err(Error::Json(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "non-finite number",
                ))));
            }
        }
        Value::String(s) => {
            // Use serde_json's own string emitter to match Go's
            // json.Marshal(string) escape rules for high characters.
            let s = serde_json::to_string(s)?;
            buf.extend_from_slice(s.as_bytes());
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_value(buf, item)?;
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            buf.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                let key_json = serde_json::to_string(*key)?;
                buf.extend_from_slice(key_json.as_bytes());
                buf.push(b':');
                write_value(buf, map.get(*key).unwrap())?;
            }
            buf.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_object_keys() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":2,"c":3}"#).unwrap();
        let bytes = canonical_json(&v).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"a":2,"b":1,"c":3}"#
        );
    }

    #[test]
    fn integer_no_decimal() {
        let v: Value = serde_json::from_str("42").unwrap();
        let bytes = canonical_json(&v).unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "42");
    }

    #[test]
    fn nested() {
        let v: Value = serde_json::from_str(r#"{"x":{"b":[1,2],"a":"hi"}}"#).unwrap();
        let bytes = canonical_json(&v).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"x":{"a":"hi","b":[1,2]}}"#
        );
    }
}
