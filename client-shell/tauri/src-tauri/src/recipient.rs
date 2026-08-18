//! FRP-6 recipient surface. The recipient client receives a signed
//! `.sbp` from a publisher's QR-fountain stream. This module owns only
//! desktop-side session bookkeeping; the actual LT fountain decoder is
//! the existing Go core `engine_fountain_feed_frame` ABI, reached
//! through `daal-desktop-core`.
//!
//! Position B: this module never opens a network socket. The
//! `recipient_opsec_test.rs` greps the source tree for analytics
//! vendor symbols + outbound network hints.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single frame as supplied by the recipient UI. `data_b64` MUST be
/// the base64url `frame_b64` emitted by `daal-deploy qr-fountain`.
/// `index` and `total_frames` are UI hints only; the core fountain
/// decoder derives completion from the LT frame stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    pub index: u32,
    pub total_frames: u32,
    pub data_b64: String,
}

/// The recipient session contract, shared verbatim with the UI.
///
/// THIS STRUCT IS THE ONE TRUTH for the `recipient_qr_*` command
/// results. `client-ui/src/recipient/sessionStatus.ts` mirrors it
/// field-for-field and validates every field at runtime, so a rename
/// on either side fails loudly instead of silently making completion
/// unreachable (which is exactly what happened when the TS mirror
/// drifted to `{state, frames_in, bytes_decoded}` against this
/// struct's `{complete, received, total_frames}`: `state` was always
/// `undefined`, so `state === 'complete'` never fired and a finished
/// scan simply hung).
///
/// Field semantics, all sourced from the Go engine response:
///   * `received`      — source blocks recovered so far  (`progress`)
///   * `total_frames`  — source blocks required          (`total`)
///   * `bytes_decoded` — payload bytes recovered         (`decoded_size`)
///   * `complete`      — decoder finished                (`done`)
///   * `verdict`       — importer verdict, present iff `complete`
///
/// `verdict` is always serialized (as `null` when absent) so the UI
/// can distinguish "field missing => wrong contract" from "field
/// present but empty => not done yet".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStatus {
    pub session_id: String,
    pub received: u32,
    pub total_frames: u32,
    pub bytes_decoded: u64,
    pub complete: bool,
    pub verdict: Option<Value>,
}

impl SessionStatus {
    fn new(session_id: String) -> Self {
        Self {
            session_id,
            received: 0,
            total_frames: 0,
            bytes_decoded: 0,
            complete: false,
            verdict: None,
        }
    }

    /// Convert the core decoder's JSON response:
    ///
    ///   {"progress":3,"total":5,"done":false,"decoded_size":0}
    ///   {"progress":5,"total":5,"done":true,"decoded_size":1234,
    ///    "verdict":{...}}
    ///
    /// into the Tauri command status shape. The verdict is preserved
    /// verbatim so the UI can render the same trust/import response as
    /// the file-based `import_sbp` flow.
    ///
    /// `progress`, `total` and `done` are REQUIRED. They used to be
    /// read with `unwrap_or` defaults, which meant a renamed engine
    /// key degraded into a permanently-stalled session (`done` silently
    /// false forever) rather than an error. A contract we cannot read
    /// is an error, not a zero.
    fn from_engine_response(session_id: &str, body: &str) -> Result<Self, String> {
        let v: Value =
            serde_json::from_str(body).map_err(|e| format!("core fountain response JSON: {e}"))?;
        let require_u64 = |k: &str| -> Result<u64, String> {
            v.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("core fountain response: missing/invalid `{k}`"))
        };
        let received = require_u64("progress")? as u32;
        let total_frames = require_u64("total")? as u32;
        let complete = v
            .get("done")
            .and_then(Value::as_bool)
            .ok_or_else(|| "core fountain response: missing/invalid `done`".to_string())?;
        // decoded_size is informational; absent on older engines.
        let bytes_decoded = v.get("decoded_size").and_then(Value::as_u64).unwrap_or(0);
        let verdict = v.get("verdict").cloned().filter(|x| !x.is_null());
        // A completed decode with no verdict is a broken engine
        // response, not a completion. Refuse rather than hand the UI a
        // "done" it can never finalize.
        if complete && verdict.is_none() {
            return Err("core fountain response: done=true without verdict".to_string());
        }
        Ok(Self {
            session_id: session_id.to_string(),
            received,
            total_frames,
            bytes_decoded,
            complete,
            verdict,
        })
    }
}

/// Tauri-managed registry of active recipient sessions. This is not a
/// decoder. It records the latest status returned by the engine so the
/// UI can query/cancel/finalize without duplicating core logic.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<BTreeMap<String, SessionStatus>>,
}

impl SessionRegistry {
    pub fn new_session(&self) -> String {
        let id = generate_session_id();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(id.clone(), SessionStatus::new(id.clone()));
        id
    }

    pub fn ensure(&self, session_id: &str) -> Result<(), String> {
        let sessions = self.sessions.lock().unwrap();
        if sessions.contains_key(session_id) {
            Ok(())
        } else {
            Err(format!("unknown session: {session_id}"))
        }
    }

    pub fn record_engine_response(
        &self,
        session_id: &str,
        body: &str,
    ) -> Result<SessionStatus, String> {
        let status = SessionStatus::from_engine_response(session_id, body)?;
        let mut sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(session_id) {
            return Err(format!("unknown session: {session_id}"));
        }
        sessions.insert(session_id.to_string(), status.clone());
        Ok(status)
    }

    pub fn status(&self, session_id: &str) -> Result<SessionStatus, String> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| format!("unknown session: {session_id}"))
    }

    /// Consume a completed session and return its verdict JSON.
    ///
    /// Only a SUCCESSFUL finalize removes the session. An early call
    /// (user hit "Done" while frames are still missing, or the engine
    /// has not produced a verdict yet) leaves the session — and
    /// therefore every block decoded so far — intact so the caller can
    /// feed more frames and retry. This previously removed the session
    /// before checking `complete`, silently throwing away a partial
    /// decode and contradicting the documented contract on
    /// `recipient_qr_finalize`.
    pub fn finish(&self, session_id: &str) -> Result<String, String> {
        let mut sessions = self.sessions.lock().unwrap();
        let status = sessions
            .get(session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        if !status.complete {
            return Err("session not complete".to_string());
        }
        let verdict = status
            .verdict
            .as_ref()
            .ok_or_else(|| "session complete without verdict".to_string())?;
        let out = serde_json::to_string(verdict).map_err(|e| e.to_string())?;
        sessions.remove(session_id);
        Ok(out)
    }

    pub fn cancel(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }
}

fn generate_session_id() -> String {
    // Client-only handle, not a crypto identifier.
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("rs-{}-{}", now.as_secs(), now.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cross-language contract fixture. Also parsed by
    /// client-ui/src/recipient/sessionStatus.test.ts.
    fn contract_fixture() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../client-shared/contracts/recipient-session-status-v1.json"
        );
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read contract fixture {path}: {e}"));
        serde_json::from_str(&raw).expect("contract fixture is valid JSON")
    }

    #[test]
    fn records_incomplete_engine_progress() {
        let reg = SessionRegistry::default();
        let id = reg.new_session();
        let st = reg
            .record_engine_response(&id, r#"{"progress":2,"total":7,"done":false}"#)
            .unwrap();
        assert_eq!(st.received, 2);
        assert_eq!(st.total_frames, 7);
        assert!(!st.complete);
        assert!(st.verdict.is_none());
    }

    /// The wire shape the UI consumes. If this test fails, the TS
    /// mirror in client-ui/src/recipient/sessionStatus.ts and the
    /// fixture in client-shared/contracts/ must change with it.
    #[test]
    fn serialized_field_set_matches_the_contract_fixture() {
        let fixture = contract_fixture();

        for case in ["incomplete", "complete"] {
            let expected = fixture.get(case).expect("fixture case present");
            let actual: Value = serde_json::to_value(
                serde_json::from_value::<SessionStatus>(expected.clone())
                    .unwrap_or_else(|e| panic!("fixture `{case}` must deserialize: {e}")),
            )
            .unwrap();
            assert_eq!(
                &actual, expected,
                "SessionStatus round-trip changed the wire shape for `{case}`"
            );

            // Field names are the contract; assert them explicitly so a
            // rename cannot pass by coincidence. serde_json orders
            // object keys alphabetically, so compare sorted sets —
            // JSON key order is not part of the contract, the key set
            // is.
            let mut keys: Vec<&str> = actual.as_object().unwrap().keys().map(|k| &**k).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec![
                    "bytes_decoded",
                    "complete",
                    "received",
                    "session_id",
                    "total_frames",
                    "verdict"
                ],
                "wire field set drifted for `{case}`"
            );
        }
    }

    /// The completion path, end to end through the registry, driven by
    /// a real engine-shaped response. This is the path that could never
    /// fire from the UI before: prove it is reachable.
    #[test]
    fn engine_done_response_reaches_a_finalizable_verdict() {
        let reg = SessionRegistry::default();
        let id = reg.new_session();

        let mid = reg
            .record_engine_response(
                &id,
                r#"{"progress":3,"total":7,"done":false,"decoded_size":0}"#,
            )
            .unwrap();
        assert!(!mid.complete);
        assert_eq!(mid.bytes_decoded, 0);
        assert!(reg.finish(&id).is_err(), "must not finalize mid-stream");

        // finish() on an incomplete session must not have destroyed it.
        let still = reg.status(&id).expect("session survives a refused finish");
        assert_eq!(still.received, 3);

        let done = reg
            .record_engine_response(
                &id,
                r#"{"progress":7,"total":7,"done":true,"decoded_size":1792,
                    "verdict":{"Kind":1,"Fingerprint":"fp"}}"#,
            )
            .unwrap();
        assert!(done.complete);
        assert_eq!(done.bytes_decoded, 1792);
        let verdict = reg.finish(&id).expect("completion is reachable");
        assert!(verdict.contains(r#""Fingerprint":"fp""#));
    }

    #[test]
    fn missing_engine_keys_are_an_error_not_a_silent_stall() {
        let reg = SessionRegistry::default();
        let id = reg.new_session();
        // `done` renamed => must error, not decay into "never complete".
        let err = reg
            .record_engine_response(&id, r#"{"progress":7,"total":7,"finished":true}"#)
            .unwrap_err();
        assert!(err.contains("done"), "unexpected error: {err}");

        // done=true with no verdict is incoherent; refuse it.
        let err = reg
            .record_engine_response(&id, r#"{"progress":7,"total":7,"done":true}"#)
            .unwrap_err();
        assert!(err.contains("verdict"), "unexpected error: {err}");
    }

    #[test]
    fn records_complete_engine_verdict_and_finishes() {
        let reg = SessionRegistry::default();
        let id = reg.new_session();
        let st = reg
            .record_engine_response(
                &id,
                r#"{"progress":5,"total":5,"done":true,"verdict":{"Kind":1,"Fingerprint":"fp"}}"#,
            )
            .unwrap();
        assert!(st.complete);
        assert_eq!(st.verdict.as_ref().unwrap()["Fingerprint"], "fp");
        let verdict = reg.finish(&id).unwrap();
        assert!(verdict.contains(r#""Fingerprint":"fp""#));
        assert!(reg.status(&id).is_err());
    }

    #[test]
    fn cancel_removes_session() {
        let reg = SessionRegistry::default();
        let id = reg.new_session();
        reg.cancel(&id);
        assert!(reg.status(&id).is_err());
    }

    #[test]
    fn finish_before_complete_errors() {
        let reg = SessionRegistry::default();
        let id = reg.new_session();
        reg.record_engine_response(&id, r#"{"progress":1,"total":5,"done":false}"#)
            .unwrap();
        assert!(reg.finish(&id).is_err());
    }
}
