# Decision 0004 — One Rotation Executor

## Status

Accepted (Wave 6). Implemented: the Go `rotation.Executor` is deleted; the wizard's
`rotate_execute` is the only implementation of the ladder.

## Context

Two programs implemented the rotation ladder.

**`publisher/deploy/rotation.Executor` (Go).** Level dispatch for L1–L6, a re-sign through an
injected `Binder`, a three-statement history transaction against the V003 `signed_sbps` schema,
a 15-second wall-clock budget for L3, an L3 rollback (`l3Swap.rollback`) that restored the record
and handed back a reserved address, an unbind-before-release rule, and a `Revert`.

**`rotate_execute` in `client-shell/tauri/daal-wizard/src/commands.rs` (Rust).** The same ladder:
the same levels, the same re-sign, the same transaction against the same schema — driving the
provider through the `daal-deploy` CLI.

The Go executor had **no production caller**. Its only importer, `deploy/cli/cli.go`, used the
recommender and the two address post-conditions; it never constructed an `Executor`. So a
relay-destroying operation had two implementations, and every guarantee written down was written
on the one that did not run. Wave 3c had already found the consequences twice: the L3 budget
overrun fired after the record was committed, and the unbind-before-release rule "existed only in
the Go executor, which has no production caller, so that guard is on no seam a user can reach".

Leaving both was not an option. The question was which direction to collapse.

## Options considered

### Option A — the Rust path calls the Go executor

The CLI is already the bridge for everything else, so this is the shape the repository would
suggest. It fails on what the executor's guarantees are made of.

1. **The transaction cannot cross the process boundary.** `SBPStore`/`SBPTx` are the wizard's
   SQLite database, which is opened, migrated and written by rusqlite in the wizard process, under
   a single `Mutex<Connection>`. To let Go drive that transaction you either hand a second writer
   its own connection — giving up the single-writer property the transaction's guarantees rest on
   — or invent a callback protocol so a subprocess can drive a transaction it cannot see. The
   second is a distributed commit protocol with no coordinator, wearing the word "transaction".
   Under a rotation, doing that badly means a history table that disagrees with the pack on disk.
2. **The private key would have to travel further.** `Binder` is the FRP-4b `BindAndSign`. The
   publisher's Ed25519 key lives in this device's custody (Android keystore, OS keyring, or a
   passphrase-wrapped file). Today it is handed to a subprocess for the duration of one verb.
   Under Option A it would be held across a multi-step transaction driven from the other side.
3. **`daal-deploy` is deliberately stateless.** Every verb is one call: take a record, mutate the
   cloud, print the record. That is why it is safe to shell out to. An executor is the opposite
   shape — it holds state across steps — and pushing it behind the CLI would make the bridge
   stateful for exactly one caller.

### Option B — delete the Go executor, move its guarantees into the Rust path

Chosen. The state a rotation commits is in the wizard process: the V003 database, the operator
record, the signing key. Go owns the provider adapters, which is why the CLI is the bridge and
why it should stay a stateless one.

## Decision

Delete `publisher/deploy/rotation/executor.go` and the three test files that drove it. Keep, in
`publisher/deploy/rotation/postconditions.go`, the parts that were never duplicated and are on the
live path:

- `CheckAddressMoved` and `CheckRecordAddressConsistent` — called by `daal-deploy assign-fip`
  after the provider adapter returns. These are what stop an adapter that stamps a floating-IP id
  without moving the record from re-signing a pack aimed at the burned address.
- `FloatingIPProvisioner` — the optional provider capability an L3 needs.
- `L3FastPathBudget` — the Go-side definition of a cross-language number.

`publisher/deploy/rotation` is now a decision surface (recommender, action mapping,
post-conditions). It does not execute rotations, and its `doc.go` says so.

## What became of each guarantee

| Guarantee | Before | Now |
|---|---|---|
| L3 15s wall-clock budget | Go const + Go check, uncalled | `L3_FAST_PATH_BUDGET` in `commands.rs`, enforced before the history transaction. Go keeps the constant as the cross-language pin. |
| History transaction | Go `SBPStore`/`SBPTx`, no implementation | `OperatorDb::record_rotated_sbp` — one rusqlite transaction, three statements, this process the only writer. |
| L3 rollback (`l3Swap.rollback`) | Go only | `unwind_failed_rotation` in `commands.rs`: restores the record, then hands back the address the failed rotation had already taken. |
| Unbind before release | Go only | Already on the live path — `daal-deploy floating-ip release` refuses without `--fip-address` and unbinds first. |
| `Revert` | Go: flip any history row back to active | `rotate_revert`, which now **refuses** on every rung whose relay is gone. See below. |

## What Revert means now, per rung

`Revert` never touched the cloud, in either implementation. It flips a history row back to
`active=1` so the wizard hands that `.sbp` out again. It cannot un-delete a server, cannot reclaim
a released floating IP, and cannot put a CDN hostname back. So the honest question is not "can we
flip the row" — it always could — but "does the endpoint that pack names still answer".

On this ladder, almost never:

- **L1, L2, L4, L5, L6 — irreversible.** All five run `reprovision` + `provision`: the box is
  deleted and a new one built. The previous pack names a server, an address and credentials that
  no longer exist. That L1 and L2 are on this list surprises people; the *in-place* credential and
  disguise rotations are `rotate_credentials` / `rotate_tls`, different commands that supersede no
  pack and never reach this path.
- **L3 off a floating IP — irreversible.** The rotation releases the old address immediately after
  the history commit, deliberately. It may already be routing to another customer's server.
- **L3 off the server's own primary address — REVERSIBLE, and the only case that is.** A primary
  address cannot be released; the provider ties it to the server for the server's life. The relay
  keeps answering on it and the previous pack keeps connecting.
- **L7, L8 — irreversible.** The CDN no longer serves the path or hostname the previous pack
  names.
- **L9** — supersedes nothing (it writes an audit row at `active=0`), so there is nothing to go
  back to. It is now explicitly excluded from revert targeting; previously it was the most recent
  inactive row and would have been picked.

This verdict is knowable at rotation time and unknowable afterwards, so V014 records it per row
(`PriorPackFate` → `prior_pack_still_serves` + `prior_pack_dead_reason`) and
`revert_to_previous_sbp` enforces it, returning the stored sentence on refusal. Pre-V014 rows
backfill to *not revertible*: for the seven destructive rungs that is also the correct answer, and
for `direct_l3` it is genuinely unknowable — a wrong "yes" there is a dead pack presented as a
working one.

**The operator-facing consequence: rotation is not an undoable action.** The way back from a
rotation is another rotation. V003's header called Revert "the FRP-side undo button" and FRP-7's
invariant 24 called rotation "reversible"; both predate the rungs that delete the server, and the
sheets Owner L4L6 is writing should say "irreversible" up front rather than rely on a button that
now refuses.

## The budget: verdict

**15 seconds stands, and it is still unmeasured. Do not move it on this evidence.**

The constant is pinned in three places — `rotation.L3FastPathBudget`, `L3_FAST_PATH_BUDGET` in
`commands.rs`, and the soak rig's `v1-5-l3-fast-path` scenario — and **all three assert it against
an injected `Duration`**. Every suite is green regardless of what a real L3 costs. That was true
before this change and is still true; consolidating the executors did not measure anything.

The flow it bounds grew in Wave 3c. It was: reserve → attach → record readback → TCP probe. It is
now: capability probe (a full ephemeral-firewall window — provider read-modify-write of the rules,
TLS handshake, `GET /health`, blocking removal in a defer) → reserve → attach → readback → **bind**
(a second full window, plus its own capability re-check and a `POST /bind-address` that configures
the address and writes its persistence) → reachability probe → re-sign.

Moving the number in either direction would be guessing. Raising it silently converts a product
promise into whatever the code happens to cost; lowering it makes L3 fail on relays that are
working.

**The measurement that would settle it:** one live L3 on real hardware, timing `started.elapsed()`
at the budget check — the same clock the check uses, spanning the operator's "go" to just before
the history transaction. Backlog **W3-6** provisions a relay for other reasons and **W3-10** notes
the measurement comes free from that run. One run gives a number; three give a spread, which is
what a ceiling should be set from. Until then the number is a promise nobody has priced, and the
comment on the constant says so rather than implying the 15 was chosen.

If the measurement comes back over budget, the obvious saving is named in W3-10 and worth
repeating: the two ephemeral firewall windows. The capability probe cannot join the bind's window
(it must refuse *before* anything is reserved), but the bind re-probes capabilities inside its own
window with the answer already in hand.

## Consequences

- One implementation. `publisher/deploy/rotation` no longer advertises an execution surface.
- `Revert` is reachable and honest: it works for the one rung it can, and explains itself for the
  rest.
- A mid-flight L3 failure now hands back the address it took. Before this, it restored the record
  and left the address attached, billing, and named by nothing on any screen — and the operator's
  natural next action (retry) reserved another.
- The destroy-and-rebuild rungs still have **no unwind**, because none is possible: the box is
  gone before the failing steps run. That is a property of those rungs, not a gap in this code,
  and it is why they must be presented as irreversible before they are started. Note also that a
  failed *provision* still leaves a billing server and an SSH key that blocks retries — a separate
  open problem, tracked in the user's notes, and not addressed here.
- The Go executor's tests are gone; the post-condition tests they contained survive as
  `postconditions_test.go`, and the ordering they also pinned is now asserted in the wizard's
  `rotate_execute` tests, where the ordering actually happens.
