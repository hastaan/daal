# Fountain (Animated) QR v1

## Status

Phase 1C deliverable. Implementation: `bundle/go/fountain` (port of
divan/txqr's Luby-Transform codec).

## Wire format

Each fountain frame is a fixed-length byte sequence:

```
+--------+--------+--------+--------+
|       payload_len (uint32 LE)     |  bytes 0..3
+--------+--------+--------+--------+
|  block_size  | ver |  rsv |       |  bytes 4..7
+--------+--------+--------+--------+
|       frame_seed (uint32 LE)      |  bytes 8..11
+-----------------------------------+
|   block_size bytes of XOR body    |  bytes 12..(12+block_size-1)
+-----------------------------------+
```

- `payload_len` is the total decoded payload length in bytes; identical on
  every frame of a session.
- `block_size` is the fixed source-block size in bytes; identical on every
  frame.
- `ver` is `1` for this spec; `rsv` is `0`.
- `frame_seed` is a per-frame random uint32 that uniquely seeds both the
  degree and the index selection. The seed alone reconstructs the same
  index list on the receiver via `math/rand.NewSource(seed)`.

Frames are base64url-encoded for the QR alphanumeric mode and encoded by
`bundle/go/share.EncodeFountainFrameQR`.

## Parameters

- Default `block_size`: 256 bytes (driven by V1.4 roadmap).
- Number of source blocks `k = ceil(payload_len / block_size)`.
- Robust soliton distribution constants: `c = 0.03`, `delta = 0.5`
  (identical to txqr).
- Encoder uses `math/rand` for seed generation; for high-volume captures
  the encoder may switch to `crypto/rand` (no spec change required).
- Receiver expects `~1.05 × k` frames to decode. Test fixtures in
  `bundle/go/fountain/fountain_test.go` show a 4 KB payload decoding at
  1.0 × k on average.

## Belief-propagation decoder

`fountain.Decoder.Add` ingests one frame and runs a single propagation
pass:

1. For each pending frame, XOR out any indices already known.
2. If a frame ends up with exactly one unknown index, recover it.
3. Repeat until no progress is made.

Memory footprint: `O(k × block_size)` for known blocks plus the pending
frame queue (~2 × k frames at peak). For a 10 KB payload at block_size=256
that is ~80 KB — comfortably under any platform's bound.

## ABI surface

Two functions on the engine ABI:

- `engine_fountain_next_frame(session_id) → {seq, total_estimate, frame_b64}`
- `engine_fountain_feed_frame(session_id, frame_b64) → {progress, total, done, decoded_size, verdict?}`

The `verdict` field is populated by `engine_fountain_feed_frame` only when
`done==true`; it carries the importer Verdict so the UI can branch to a
trust prompt or a success toast directly.

## Privacy invariants

- Frames carry the bundle bytes only; no metadata about the sender or
  receiver is added.
- The session id used in the ABI is opaque and is wiped on `share_end`.
- The encoder produces an unbounded stream; the UI controls FPS.
  `frame_seed`s are random and do not leak time-of-day.
