# Federation primitives v1 (FRP-11)

**Status**: locked at FRP-11. Append-only thereafter.
**Engine version**: `daal-core 0.9.0+v3-share` UNCHANGED.

## 1 Goals

V2 federation primitives are the connective tissue between trusted cells:

1. Per-cell directory contract (where a cell publishes its membership, delegation, aggregated `.sbp`, and revocation list).
2. Freshness + revocation hooks (how cell members and recipients reconcile against the cell's source of truth).
3. Abuse-ticket format (how cell members report cell-internal abuse to the admin set).
4. Local trust labels (how recipients tag cells privately on-device, never transmitted).
5. Signed publisher exchange (`.pubex`) — out-of-band, optional, NOT shipped at FRP-11; reserved primitive.

**Per FRP-11 invariant 34: there is NO public directory.** Each cell publishes to a URL of its choice. The supplement §17.2 conditions gate FRP-13's public-directory spec.

## 2 Per-cell directory contract

A cell publishes four documents at well-known paths beneath an FRP-9 `Backend.PublicURL()`:

| Path | Contents | Updated when |
|---|---|---|
| `<PublicURL>/cell/<cell_id>/membership.json` | `trust/cell-membership.json` mirror | Admin set / member list / quorum changes |
| `<PublicURL>/cell/<cell_id>/delegation.json` | `trust/cell-delegation.json` mirror | Bundle-signer rotation |
| `<PublicURL>/cell/<cell_id>/directory.json` | Cell-aggregated `.sbp` | Each aggregation round |
| `<PublicURL>/cell/<cell_id>/revocations.json` | JSON array of `CellRevocationDoc` | Each new admin-quorum-signed revocation |

The publisher contract is `publisher/cell/freshness.CellPublisher`. Today's adapters wrap the FRP-9 R2 + GH-Pages backends. Live SDK wiring is a V2 alpha pilot carry-over.

## 3 Freshness + revocation flow

```
1. Cell admins finalise a new aggregation round.
2. Aggregator (publisher/cell.Aggregate) seals a cell-aggregated .sbp.
3. CellPublisher uploads {membership, delegation, directory, revocations}.
4. Recipients holding an old directory poll <cell_id>/directory.json
   periodically (recipient-side polling cadence is engine policy).
5. New revocations propagate via revocations.json on the same poll.
```

Recipients walk the cell trust chain at every poll; tampered or expired delegations land at `ErrCellChainDelegationOutOfWindow` and the recipient falls back to its previously-trusted directory bytes.

## 4 Abuse-ticket format

Signed by the reporting publisher's key (NOT a cell admin key). The cell admins consume the ticket and may sign a cell-internal revocation. See `specs/cell-v1.md` §3.4 + §3.5 for the wire shapes.

A future widening (post-V2) MAY add inter-cell ticket forwarding; FRP-11 deliberately scopes admins' authority to their own cell.

## 5 Local trust labels

`core/trust/labels.go::LabelStore`. Engine-side, AES-GCM encrypted at rest, AEAD additional-data = cellIDFPHex (so labels keyed to one cell cannot be replayed against another). Never serialised into bundles or diagnostics.

The wizard's V008 schema carries an advisory hint (`cells.trust_label`) so the per-cell row in the wizard UI renders a name even if the engine label store is briefly unavailable; the engine store is authoritative.

## 6 Reserved-not-shipped: `.pubex` signed publisher exchange

Signed publisher exchange envelopes are reserved as a future primitive for cell-to-cell publisher key exchange (an admin in cell A vouches for an admin in cell B). FRP-11 does not ship the format; doing so requires a separate roadmap-level decision.

## 7 Closed-list status

This spec defines five primitives:

1. Per-cell directory contract — SHIPPED at FRP-11.
2. Freshness + revocation hooks — SHIPPED at FRP-11.
3. Abuse-ticket format — SHIPPED at FRP-11.
4. Local trust labels — SHIPPED at FRP-11.
5. Signed publisher exchange — RESERVED.

Any sixth primitive requires a roadmap-level decision and a `specs/federation-primitives-v2.md` widening.

End — locked at FRP-11.
