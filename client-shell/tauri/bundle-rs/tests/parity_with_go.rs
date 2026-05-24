//! Parity test: feed every Go-generated fixture through bundle-rs and
//! assert the parse/verify outcome matches the oracle JSON shipped
//! alongside the fixtures.
//!
//! Regenerate fixtures with:
//!   cd ../../bundle/go && go run ./cmd/bundle-rs-fixtures \
//!       -out ../../client-shell/tauri/bundle-rs/tests/fixtures

use std::fs;
use std::path::PathBuf;

use bundle_rs::{parse_sbp, verify_bundle_at, verify_revocation, Error};
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Deserialize)]
struct Oracle {
    vector: String,
    #[allow(dead_code)]
    description: String,
    sbp_file: String,
    publisher_pub_hex: String,
    expect_parse: String,
    expect_verify: String,
}

fn fixtures_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p
}

fn load_oracles() -> Vec<Oracle> {
    let path = fixtures_dir().join("oracles.json");
    let data = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "could not read {}: {} -- run the fixtures generator (see tests/parity_with_go.rs)",
            path.display(),
            e
        )
    });
    serde_json::from_slice(&data).expect("oracles.json malformed")
}

fn err_code(e: &Error) -> &'static str {
    e.code()
}

fn fixture_clock() -> time::OffsetDateTime {
    time::OffsetDateTime::parse("2026-04-26T12:00:00Z", &Rfc3339).expect("fixture clock must parse")
}

#[test]
fn parity_with_go_for_every_fixture() {
    let oracles = load_oracles();
    assert!(!oracles.is_empty(), "no fixtures found");
    let mut total = 0;
    let mut failures = vec![];

    for o in &oracles {
        total += 1;
        let path = fixtures_dir().join(&o.sbp_file);
        let bytes = fs::read(&path).expect("fixture missing");

        if o.sbp_file.ends_with(".sbp") {
            let parse_outcome = match parse_sbp(&bytes) {
                Ok(_) => "ok".to_string(),
                Err(e) => err_code(&e).to_string(),
            };
            if parse_outcome != o.expect_parse {
                failures.push(format!(
                    "[parse] {} expected={} got={}",
                    o.vector, o.expect_parse, parse_outcome
                ));
                continue;
            }
            if parse_outcome != "ok" {
                continue;
            }
            let sbp = parse_sbp(&bytes).unwrap();
            let verify_outcome = match verify_bundle_at(&sbp, fixture_clock()) {
                Ok(()) => "ok".to_string(),
                Err(e) => err_code(&e).to_string(),
            };
            if verify_outcome != o.expect_verify {
                failures.push(format!(
                    "[verify] {} expected={} got={}",
                    o.vector, o.expect_verify, verify_outcome
                ));
            }
        } else if o.sbp_file.ends_with(".json") {
            let pub_bytes = hex::decode(&o.publisher_pub_hex).expect("pub hex");
            let outcome = match verify_revocation(&bytes, &pub_bytes) {
                Ok(_) => "ok".to_string(),
                Err(e) => err_code(&e).to_string(),
            };
            if outcome != o.expect_verify {
                failures.push(format!(
                    "[revoke] {} expected={} got={}",
                    o.vector, o.expect_verify, outcome
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{}/{} fixtures failed parity:\n  {}",
        failures.len(),
        total,
        failures.join("\n  ")
    );
}
