//! PIN-attempt rate limiting.
//!
//! Policy:
//!   - 5 wrong attempts within `WINDOW_SECS` → lockout for `BASE_LOCKOUT`.
//!   - Successive lockouts double, capped at `MAX_LOCKOUT`.
//!   - A successful attempt clears the failure history (in the
//!     caller's logical view; the DB still records the row).
//!
//! Tracking is delegated to `OperatorDb::record_pin_attempt` and
//! `OperatorDb::count_recent_failed_pins`. This module is the
//! pure-arithmetic policy engine the wizard's command layer
//! consults before forwarding a PIN to `Keystore::open`.

use crate::operator_db::OperatorDb;

pub const WINDOW_SECS: i64 = 60;
pub const ATTEMPTS_BEFORE_LOCKOUT: i64 = 5;
pub const BASE_LOCKOUT_SECS: i64 = 60;
pub const MAX_LOCKOUT_SECS: i64 = 60 * 60; // 1 h cap

/// `LockoutStatus` is the result of [`check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockoutStatus {
    /// PIN entry is allowed.
    Allowed,
    /// PIN entry is blocked until `unlock_at_unix`.
    Locked { unlock_at_unix: i64 },
}

/// Compute the lockout state at `now_unix` given the failed-attempt
/// history. The caller passes a function for "now" to keep this
/// pure for tests.
pub fn check(db: &OperatorDb, now_unix: i64) -> Result<LockoutStatus, crate::operator_db::DbError> {
    let recent = db.count_recent_failed_pins(now_unix - WINDOW_SECS)?;
    if recent < ATTEMPTS_BEFORE_LOCKOUT {
        return Ok(LockoutStatus::Allowed);
    }
    // The doubling is a function of how many consecutive
    // ATTEMPTS_BEFORE_LOCKOUT-sized bursts have failed. We
    // approximate by counting total recent failures over a
    // 24-hour view: every additional ATTEMPTS_BEFORE_LOCKOUT
    // failures past the first threshold doubles the lockout.
    let day_recent = db.count_recent_failed_pins(now_unix - 24 * 60 * 60)?;
    let bursts = (day_recent / ATTEMPTS_BEFORE_LOCKOUT).max(1);
    let mut lockout = BASE_LOCKOUT_SECS;
    for _ in 1..bursts {
        lockout = (lockout * 2).min(MAX_LOCKOUT_SECS);
    }
    let unlock_at = now_unix + lockout;
    Ok(LockoutStatus::Locked {
        unlock_at_unix: unlock_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> OperatorDb {
        OperatorDb::open_in_memory().unwrap()
    }

    #[test]
    fn fresh_db_is_allowed() {
        let db = db();
        assert_eq!(check(&db, 1000).unwrap(), LockoutStatus::Allowed);
    }

    #[test]
    fn four_failures_in_window_still_allowed() {
        let db = db();
        for t in 950..954 {
            db.record_pin_attempt(t, false).unwrap();
        }
        assert_eq!(check(&db, 1000).unwrap(), LockoutStatus::Allowed);
    }

    #[test]
    fn five_failures_in_window_locks() {
        let db = db();
        for t in 950..955 {
            db.record_pin_attempt(t, false).unwrap();
        }
        match check(&db, 1000).unwrap() {
            LockoutStatus::Locked { unlock_at_unix } => {
                assert_eq!(unlock_at_unix, 1000 + BASE_LOCKOUT_SECS);
            }
            s => panic!("wanted Locked, got {s:?}"),
        }
    }

    #[test]
    fn old_failures_do_not_count() {
        let db = db();
        // Five failures at t=10..15, well outside the 60-s window
        // for now=1000.
        for t in 10..15 {
            db.record_pin_attempt(t, false).unwrap();
        }
        assert_eq!(check(&db, 1000).unwrap(), LockoutStatus::Allowed);
    }

    #[test]
    fn lockout_doubles_with_consecutive_bursts() {
        let db = db();
        // 10 failures (= 2 bursts) all within the last 24 h and
        // last minute.
        for t in 950..960 {
            db.record_pin_attempt(t, false).unwrap();
        }
        match check(&db, 1000).unwrap() {
            LockoutStatus::Locked { unlock_at_unix } => {
                assert_eq!(unlock_at_unix, 1000 + 2 * BASE_LOCKOUT_SECS);
            }
            s => panic!("wanted Locked, got {s:?}"),
        }
    }

    #[test]
    fn lockout_caps_at_max() {
        let db = db();
        // 200 failures = 40 bursts; doubling 39 times would
        // overflow, but we cap at MAX_LOCKOUT_SECS.
        for t in 800..1000 {
            db.record_pin_attempt(t, false).unwrap();
        }
        match check(&db, 1000).unwrap() {
            LockoutStatus::Locked { unlock_at_unix } => {
                assert_eq!(unlock_at_unix, 1000 + MAX_LOCKOUT_SECS);
            }
            s => panic!("wanted Locked, got {s:?}"),
        }
    }
}
