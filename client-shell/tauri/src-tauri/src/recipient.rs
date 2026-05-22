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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStatus {
    pub session_id: String,
    pub received: u32,
    pub total_frames: u32,
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Value>,
}

impl SessionStatus {
    fn new(session_id: String) -> Self {
        Self {
            session_id,
            received: 0,
            total_frames: 0,
            complete: false,
            verdict: None,
        }
    }

    /// Convert the core decoder's JSON response:
    ///
    ///   {"progress":3,"total":5,"done":false}
    ///   {"progress":5,"total":5,"done":true,"verdict":{...}}
    ///
    /// into the Tauri command status shape. The verdict is preserved
    /// verbatim so the UI can render the same trust/import response as
    /// the file-based `import_sbp` flow.
    fn from_engine_response(session_id: &str, body: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(body)
            .map_err(|e| format!("core fountain response JSON: {e}"))?;
        let received = v.get("progress").and_then(Value::as_u64).unwrap_or(0) as u32;
        let total_frames = v.get("total").and_then(Value::as_u64).unwrap_or(0) as u32;
        let complete = v.get("done").and_then(Value::as_bool).unwrap_or(false);
        let verdict = v.get("verdict").cloned();
        Ok(Self {
            session_id: session_id.to_string(),
            received,
            total_frames,
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

    pub fn finish(&self, session_id: &str) -> Result<String, String> {
        let mut sessions = self.sessions.lock().unwrap();
        let status = sessions
            .remove(session_id)
            .ok_or_else(|| format!("unknown session: {session_id}"))?;
        if !status.complete {
            return Err("session not complete".to_string());
        }
        let verdict = status
            .verdict
            .ok_or_else(|| "session complete without verdict".to_string())?;
        serde_json::to_string(&verdict).map_err(|e| e.to_string())
    }

    pub fn cancel(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(session_id);
    }
}

fn generate_session_id() -> String {
    // Client-only handle, not a crypto identifier.
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("rs-{}-{}", now.as_secs(), now.subsec_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

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
