//! After a restore: who the relay does not know, and who it knows that
//! this phone does not (PB-1, PB-2).
//!
//! A backup is a snapshot. Two things can have changed on the old phone
//! after it was made, and the restored list cannot know either:
//!
//! * **Someone was removed.** The restored list still has them as not
//!   removed, and the relay no longer knows them. Every path that
//!   creates a person on the relay (renew's `--ensure` / `--replace`,
//!   the per-person repack, a credential rotation) would hand them a
//!   working file again, silently. So the restore marks everyone not
//!   removed as "restored, not yet settled" in the same transaction as
//!   its commit (V018, [`mark_restored`]). The first time the relay's
//!   list of people is read (the health check, the questions below, or
//!   a renew that has to read it first), each such person the relay
//!   knows is settled, and each it does not becomes a question asked BY
//!   NAME: "still should have access" (then, and only then, they may be
//!   created again) or "was removed" (marked removed here, never
//!   created). Until answered they are skipped with a reason. If the
//!   relay cannot be reached nothing is assumed either way.
//!
//! * **Someone was added.** The relay lets in a person (`r<n>`) this
//!   phone has no row for. [`relay_only_users`] lists them and
//!   [`relay_only_revoke`] removes one by its relay name through the
//!   same signed management call as any removal (`daal-deploy
//!   users-revoke --name`). It never touches a name in this phone's
//!   list: those go through their own row.
//!
//! Position B: no socket here; the relay is reached through the CLI
//! bridge only.

use std::collections::BTreeSet;

use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::cli_bridge::{verb_unknown, BridgeError, UsersListArgs, UsersRevokeArgs};
use crate::commands::{
    coded, custody_get, custody_get_string, require_helper_ip, Result, WizardCtx, WizardError,
    E_DEPLOY_TOO_OLD, E_HELPER_IP_STALE, E_RELAY_UNREACHABLE, E_RELAY_USER_INVALID,
    E_RELAY_USER_IN_LIST, E_RESTORE_ALREADY_ANSWERED, E_RESTORE_NOT_ASKED, E_RESTORE_UNANSWERED,
};
use crate::operator_db::DbError;

/// One person the relay did not know when it was first checked after a
/// restore. Mirrors `RestoreUnsettledPerson` in the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnsettledPerson {
    pub recipient_id: i64,
    /// The name the person using the phone gave them ("Maman"); the
    /// relay name when none was given.
    pub name: String,
    /// The relay's name for them (`r3`). Details only.
    #[serde(default)]
    pub relay_user: String,
}

/// `wizard_restore_unsettled`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RestoreUnsettled {
    /// Waiting for an answer. Empty when settled, or when the relay could
    /// not be checked (`checked` false).
    pub people: Vec<UnsettledPerson>,
    /// The relay's list has been read since the restore (or there was
    /// nothing to check).
    pub checked: bool,
    /// Why the check could not run, coded like any command error; for a
    /// Details disclosure and the choice of remedy.
    pub check_error: Option<String>,
}

/// What `relay_only_users` returns (tests and the rig; the app reads the
/// same names from `RelayHealth.relay_only`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RelayOnlyUsers {
    /// Relay names (`r<n>`, n >= 1) the relay lets in and this phone's
    /// list has never had, in number order.
    pub users: Vec<String>,
    pub checked: bool,
    pub check_error: Option<String>,
}

fn db(e: rusqlite::Error) -> WizardError {
    WizardError::Db(DbError::from(e))
}

/// Called by the restore inside its commit transaction: everyone not
/// removed is "restored, not yet settled". Replaces whatever an earlier
/// restore left.
pub(crate) fn mark_restored(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute("DELETE FROM restore_unsettled", [])?;
    tx.execute(
        "INSERT INTO restore_unsettled (operator_id, recipient_id, state)
         SELECT operator_id, id, 'unchecked' FROM recipients WHERE revoked_at_unix = 0",
        [],
    )?;
    Ok(())
}

fn count_state(ctx: &WizardCtx, operator_id: i64, state: &str) -> Result<i64> {
    ctx.db
        .with_conn(|c| {
            c.query_row(
                "SELECT COUNT(*) FROM restore_unsettled u
                   JOIN recipients r ON r.id = u.recipient_id
                  WHERE u.operator_id = ?1 AND u.state = ?2 AND r.revoked_at_unix = 0",
                params![operator_id, state],
                |r| r.get(0),
            )
        })
        .map_err(db)
}

fn has_unchecked(ctx: &WizardCtx, operator_id: i64) -> Result<bool> {
    Ok(count_state(ctx, operator_id, "unchecked")? > 0)
}

/// How many people on this relay wait for an answer. For the relay list
/// and the health check.
pub fn count_needing_answer(ctx: &WizardCtx, operator_id: i64) -> Result<i64> {
    count_state(ctx, operator_id, "ask")
}

/// Live people who must not be created on the relay yet: the relay was
/// checked and did not know them, and nobody has answered (`ask`), or it
/// has not been checked since the restore (`unchecked`).
pub(crate) fn unanswered_ids(ctx: &WizardCtx, operator_id: i64) -> Result<BTreeSet<i64>> {
    ctx.db
        .with_conn(|c| -> rusqlite::Result<BTreeSet<i64>> {
            let mut s = c.prepare(
                "SELECT u.recipient_id FROM restore_unsettled u
                   JOIN recipients r ON r.id = u.recipient_id
                  WHERE u.operator_id = ?1 AND u.state IN ('unchecked','ask')
                    AND r.revoked_at_unix = 0",
            )?;
            let v = s
                .query_map(params![operator_id], |r| r.get(0))?
                .collect::<rusqlite::Result<BTreeSet<i64>>>()?;
            Ok(v)
        })
        .map_err(db)
}

/// The relay's list of people has been read: settle every `unchecked`
/// person. Known to the relay -> nothing to settle (row deleted); not
/// known -> a question (`ask`). One transaction. Rows already asked or
/// answered are left as they are: each person is asked once.
pub(crate) fn settle_with(ctx: &WizardCtx, operator_id: i64, relay_users: &[String]) -> Result<()> {
    let on_relay: BTreeSet<&str> = relay_users.iter().map(String::as_str).collect();
    ctx.db
        .with_conn(|c| -> rusqlite::Result<()> {
            let tx = c.transaction()?;
            let rows: Vec<(i64, String)> = {
                let mut s = tx.prepare(
                    "SELECT u.recipient_id, r.name FROM restore_unsettled u
                       JOIN recipients r ON r.id = u.recipient_id
                      WHERE u.operator_id = ?1 AND u.state = 'unchecked'",
                )?;
                let v = s
                    .query_map(params![operator_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                v
            };
            for (rid, name) in rows {
                if on_relay.contains(name.as_str()) {
                    tx.execute(
                        "DELETE FROM restore_unsettled WHERE operator_id = ?1 AND recipient_id = ?2",
                        params![operator_id, rid],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE restore_unsettled SET state = 'ask'
                          WHERE operator_id = ?1 AND recipient_id = ?2",
                        params![operator_id, rid],
                    )?;
                }
            }
            tx.commit()
        })
        .map_err(db)
}

/// A relay-side failure, said as "nothing was assumed / changed".
fn map_relay_err(e: BridgeError, what: &str) -> WizardError {
    if verb_unknown(&e) {
        return coded(
            E_DEPLOY_TOO_OLD,
            format!("the setup helper bundled with this app cannot {what}"),
        );
    }
    let text = e.to_string();
    if crate::commands::looks_like_stale_allowlist(&text) {
        return coded(E_HELPER_IP_STALE, text);
    }
    coded(
        E_RELAY_UNREACHABLE,
        format!("the relay did not answer, so nothing was assumed or changed: {}", text.trim()),
    )
}

/// Read the relay's list of people (one firewall window).
fn read_relay_users(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<String>> {
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let row = ctx.db.get(operator_id)?;
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let record_path =
        crate::recipient_book::write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let res = ctx.cli.run_users_list(
        UsersListArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
        },
        priv_buf.as_slice(),
    );
    let _ = std::fs::remove_file(&record_path);
    let users = res.map_err(|e| map_relay_err(e, "read who the relay lets in"))?;
    Ok(users.into_iter().map(|u| u.name).collect())
}

/// Before anything that could create a person on this relay: if people
/// restored from a backup have not been checked against the relay yet,
/// read the relay's list first (an unreachable relay is an error and
/// nothing is created), then return the people who must be skipped.
/// Without a restore this costs one local query and no round trip.
pub(crate) fn blocked_before_create(ctx: &WizardCtx, operator_id: i64) -> Result<BTreeSet<i64>> {
    if has_unchecked(ctx, operator_id)? {
        let users = read_relay_users(ctx, operator_id)?;
        settle_with(ctx, operator_id, &users)?;
    }
    unanswered_ids(ctx, operator_id)
}

/// The per-person form of [`blocked_before_create`]: refuses, with a
/// plain reason, to create or re-key this one person while their
/// question is open. No round trip unless this person is unchecked.
pub(crate) fn refuse_if_unanswered(
    ctx: &WizardCtx,
    operator_id: i64,
    recipient_id: i64,
) -> Result<()> {
    if !unanswered_ids(ctx, operator_id)?.contains(&recipient_id) {
        return Ok(());
    }
    if blocked_before_create(ctx, operator_id)?.contains(&recipient_id) {
        return Err(coded(
            E_RESTORE_UNANSWERED,
            "this person came from your backup and the relay no longer knows them; \
             say first whether they still should have access",
        ));
    }
    Ok(())
}

fn people_to_ask(ctx: &WizardCtx, operator_id: i64) -> Result<Vec<UnsettledPerson>> {
    ctx.db
        .with_conn(|c| -> rusqlite::Result<Vec<UnsettledPerson>> {
            let mut s = c.prepare(
                "SELECT r.id, r.display_name, r.name FROM restore_unsettled u
                   JOIN recipients r ON r.id = u.recipient_id
                  WHERE u.operator_id = ?1 AND u.state = 'ask' AND r.revoked_at_unix = 0
                  ORDER BY r.id",
            )?;
            let v = s
                .query_map(params![operator_id], |r| {
                    let display: String = r.get(1)?;
                    let relay_user: String = r.get(2)?;
                    Ok(UnsettledPerson {
                        recipient_id: r.get(0)?,
                        name: if display.trim().is_empty() {
                            relay_user.clone()
                        } else {
                            display
                        },
                        relay_user,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })
        .map_err(db)
}

/// `wizard_restore_unsettled`: the people of this relay who wait for an
/// answer. Checks the relay first if it has not been checked since the
/// restore; a check that fails is reported, not assumed.
pub fn restore_unsettled(ctx: &WizardCtx, operator_id: i64) -> Result<RestoreUnsettled> {
    ctx.db.get(operator_id)?;
    if has_unchecked(ctx, operator_id)? {
        match read_relay_users(ctx, operator_id) {
            Ok(users) => settle_with(ctx, operator_id, &users)?,
            Err(WizardError::Db(e)) => return Err(WizardError::Db(e)),
            Err(e) => {
                return Ok(RestoreUnsettled {
                    people: Vec::new(),
                    checked: false,
                    check_error: Some(e.to_string()),
                })
            }
        }
    }
    Ok(RestoreUnsettled {
        people: people_to_ask(ctx, operator_id)?,
        checked: true,
        check_error: None,
    })
}

/// `wizard_restore_answer`: `keep` = "still should have access" (they
/// may now be created again by renew, with a new file); otherwise "was
/// removed" (marked removed on this phone in the same transaction, their
/// leftover file deleted, never created). Asked once: the same answer
/// again is fine, the other answer is refused.
pub fn restore_answer(
    ctx: &WizardCtx,
    operator_id: i64,
    recipient_id: i64,
    keep: bool,
) -> Result<()> {
    let now = (ctx.clock)();
    let answer = if keep { "keep" } else { "removed" };
    let outcome = ctx.db.with_conn(|c| -> rusqlite::Result<std::result::Result<Option<String>, WizardError>> {
        let tx = c.transaction()?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM restore_unsettled WHERE operator_id = ?1 AND recipient_id = ?2",
                params![operator_id, recipient_id],
                |r| r.get(0),
            )
            .optional()?;
        let name: Option<String> = tx
            .query_row(
                "SELECT name FROM recipients WHERE id = ?1 AND operator_id = ?2",
                params![recipient_id, operator_id],
                |r| r.get(0),
            )
            .optional()?;
        match state.as_deref() {
            None | Some("unchecked") => {
                return Ok(Err(coded(
                    E_RESTORE_NOT_ASKED,
                    "there is no question about this person; check the relay first",
                )))
            }
            Some(s) if s == answer => return Ok(Ok(None)),
            Some("keep") | Some("removed") => {
                return Ok(Err(coded(
                    E_RESTORE_ALREADY_ANSWERED,
                    "this person was already answered for",
                )))
            }
            _ => {}
        }
        tx.execute(
            "UPDATE restore_unsettled SET state = ?3, answered_at_unix = ?4
              WHERE operator_id = ?1 AND recipient_id = ?2",
            params![operator_id, recipient_id, answer, now],
        )?;
        if !keep {
            tx.execute(
                "UPDATE recipients SET revoked_at_unix = ?3
                  WHERE id = ?1 AND operator_id = ?2 AND revoked_at_unix = 0",
                params![recipient_id, operator_id, now.max(1)],
            )?;
        }
        tx.commit()?;
        Ok(Ok(if keep { None } else { name }))
    });
    let removed_name = outcome.map_err(db)??;
    if let Some(name) = removed_name {
        // The file they had from the backup carries credentials the relay
        // no longer honours; it is not something to hand out again.
        let _ = std::fs::remove_file(
            ctx.staging_dir
                .join(format!("{operator_id}.{name}.sbpx")),
        );
    }
    // The cached health counted them; the next check must not.
    let _ = ctx.db.set_last_health(operator_id, "", 0);
    Ok(())
}

/// Relay names (`r<n>`, n >= 1) the relay lets in that `book` (every
/// name this phone's list has, removed or not) has never had, in number
/// order, with the highest number seen. `r0` is the everyone file, not
/// a person.
pub(crate) fn relay_only_names(
    relay_users: &[String],
    book: &BTreeSet<String>,
) -> (Vec<String>, Option<i64>) {
    let mut numbered: Vec<(i64, &String)> = relay_users
        .iter()
        .filter_map(|u| relay_user_number(u).map(|n| (n, u)))
        .collect();
    numbered.sort();
    numbered.dedup();
    let max = numbered.iter().map(|(n, _)| *n).max();
    let unknown = numbered
        .iter()
        .filter(|(_, u)| !book.contains(*u))
        .map(|(_, u)| (*u).clone())
        .collect();
    (unknown, max)
}

/// `r<n>` with n >= 1 and no leading zero -> n.
fn relay_user_number(u: &str) -> Option<i64> {
    let d = u.strip_prefix('r')?;
    if d.is_empty() || d.len() > 9 || d.starts_with('0') || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    d.parse::<i64>().ok().filter(|n| *n >= 1)
}

fn book_names(ctx: &WizardCtx, operator_id: i64) -> Result<BTreeSet<String>> {
    Ok(ctx
        .db
        .list_recipients(operator_id)?
        .into_iter()
        .map(|r| r.name)
        .collect())
}

/// Who the relay lets in that this phone does not know (not a Tauri
/// command: the app reads `RelayHealth.relay_only`, one users read). Reading the relay's list also settles a restore's
/// unchecked people, and moves the name counter past every name seen.
pub fn relay_only_users(ctx: &WizardCtx, operator_id: i64) -> Result<RelayOnlyUsers> {
    ctx.db.get(operator_id)?;
    let users = match read_relay_users(ctx, operator_id) {
        Ok(u) => u,
        Err(WizardError::Db(e)) => return Err(WizardError::Db(e)),
        Err(e) => {
            return Ok(RelayOnlyUsers {
                users: Vec::new(),
                checked: false,
                check_error: Some(e.to_string()),
            })
        }
    };
    if has_unchecked(ctx, operator_id)? {
        settle_with(ctx, operator_id, &users)?;
    }
    let (unknown, max) = relay_only_names(&users, &book_names(ctx, operator_id)?);
    if let Some(max) = max {
        ctx.db.advance_recipient_name_counter(operator_id, max)?;
    }
    Ok(RelayOnlyUsers {
        users: unknown,
        checked: true,
        check_error: None,
    })
}

/// `wizard_relay_only_revoke`: remove one person the relay lets in that
/// this phone has no row for, by their relay name. DESTRUCTIVE (their
/// file stops working and nothing on this phone can give it back): the
/// UI asks first, naming them. Refuses a name in this phone's list.
pub fn relay_only_revoke(ctx: &WizardCtx, operator_id: i64, relay_user: &str) -> Result<()> {
    let user = relay_user.trim();
    if relay_user_number(user).is_none() {
        return Err(coded(
            E_RELAY_USER_INVALID,
            "that is not the name of a person on the relay",
        ));
    }
    if book_names(ctx, operator_id)?.contains(user) {
        return Err(coded(
            E_RELAY_USER_IN_LIST,
            "this person is in this phone's list; remove them from their own row",
        ));
    }
    let helper_ip = require_helper_ip(ctx, operator_id)?;
    let row = ctx.db.get(operator_id)?;
    let priv_buf = custody_get(ctx, &row.publisher_priv_keystore_alias)?;
    let token = custody_get_string(ctx, &row.cloud_token_keystore_alias)?;
    let record_path =
        crate::recipient_book::write_record_staging(ctx, operator_id, &row.operator_record_json)?;
    let res = ctx.cli.run_users_revoke(
        UsersRevokeArgs {
            record_path: &record_path,
            helper_ip: &helper_ip,
            token: token.as_str(),
            name: user,
        },
        priv_buf.as_slice(),
    );
    let _ = std::fs::remove_file(&record_path);
    res.map_err(|e| map_relay_err(e, "remove a person from the relay"))?;
    // The next health check reads the relay again.
    let _ = ctx.db.set_last_health(operator_id, "", 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_names_are_read_strictly() {
        assert_eq!(relay_user_number("r1"), Some(1));
        assert_eq!(relay_user_number("r42"), Some(42));
        for bad in ["r0", "r", "r01", "x1", "r1 ", "r-1", "r1a", "", "r9999999999"] {
            assert_eq!(relay_user_number(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn relay_only_names_skip_the_book_and_the_everyone_file() {
        let users: Vec<String> = ["r0", "r4", "r1", "r10", "r2", "r4"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let book: BTreeSet<String> = ["r1", "r2", "r3"].iter().map(|s| s.to_string()).collect();
        let (unknown, max) = relay_only_names(&users, &book);
        assert_eq!(unknown, vec!["r4".to_string(), "r10".to_string()]);
        assert_eq!(max, Some(10));
    }
}
