//! Schema cross-check: the JSON keys produced by the wizard's
//! `PreProvisionRecord` must equal the union of the FRP-4a Go
//! `OperatorRecord` keys plus the wizard-extra keys
//! (`enabled_families`, `freshness_url`).
//!
//! The pinned snapshot is `tests/frp5-schema-snapshot.json`. Drift
//! on either side fails this test loudly — the maintainer must
//! update the snapshot and the Go side together.

use std::collections::BTreeSet;

use daal_wizard::staging::PreProvisionRecord;
use serde_json::Value;

const SNAPSHOT: &str = include_str!("frp5-schema-snapshot.json");

#[test]
fn pre_provision_keys_equal_snapshot_union() {
    let snapshot: Value = serde_json::from_str(SNAPSHOT).unwrap();
    let mut want: BTreeSet<String> = snapshot["frp_4a_operator_record_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    for v in snapshot["frp_5_wizard_extras"]["keys"].as_array().unwrap() {
        want.insert(v.as_str().unwrap().to_string());
    }
    // last_reprovisioned_at is on the FRP-4a struct but not the
    // pre-provision wizard shape (it's set on reprovision only).
    want.remove("last_reprovisioned_at");
    // The Go side flags `public_ipv6` and `floating_ip_id` as
    // `omitempty`; the Rust side mirrors with skip_serializing_if.
    // They are absent from a default-constructed record.
    want.remove("public_ipv6");
    want.remove("floating_ip_id");

    let rec = PreProvisionRecord::new(
        "hetzner",
        "fsn1",
        "cx22",
        "iran-default",
        vec!["vless-reality".into()],
        "AAAA",
    );
    let body = serde_json::to_value(&rec).unwrap();
    let got: BTreeSet<String> = body.as_object().unwrap().keys().cloned().collect();

    assert_eq!(
        got,
        want,
        "PreProvisionRecord JSON keys diverged from FRP-4a/FRP-5 snapshot.\n\
         got - want = {:?}\n\
         want - got = {:?}",
        got.difference(&want).collect::<Vec<_>>(),
        want.difference(&got).collect::<Vec<_>>(),
    );
}

#[test]
fn freshness_url_is_present_and_empty_at_v1_5() {
    let rec = PreProvisionRecord::new("hetzner", "fsn1", "cx22", "iran-default", vec![], "AAAA");
    let body = serde_json::to_value(&rec).unwrap();
    assert!(body.as_object().unwrap().contains_key("freshness_url"));
    assert_eq!(body["freshness_url"].as_str().unwrap(), "");
}
