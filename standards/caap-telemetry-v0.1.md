# CAAP-TELEMETRY v0.1 — Spatial Telemetry, Receipts, and Disclosure Proofs

**Status:** Draft v0.1
**Editors:** Clavote Research (`@clavote-boop`)
**License:** CC0 — public domain dedication.
**Composes with:** CAAP-Capsule v0.1 (record commitment), CAAP-TICKET v0.1 (wire discipline, key domains), CAAP-WIPE / LeaseBond v0.2 (obligation keying, disclosure), CAAP-LSC (brief §4), m1-failure-state-spec-v0.1 (LossReport roots)
**Canonical home:** this repository, `standards/`

## 1. Purpose

This document is the **evidence substrate** of the stack. It defines, byte-exactly:

1. how spatial and telemetry data is containerized, chunked, and committed (**content trees**),
2. the signed objects produced at capture and execution time (**capture attestations, action receipts, terminal receipts, intent payloads**),
3. the **disclosure bundle** a respondent submits against a LeaseBond claim, verifiable by an ERC-8004 validator with no out-of-band knowledge.

Everything machine-signed here uses deterministic CBOR (RFC 8949 §4.2.1) in `COSE_Sign1` envelopes (RFC 9052), closed CDDL maps with integer labels, and **fixed-point integers with schema-defined SI units — floats are invalid in every signed structure**. Capsule *manifests* remain canonical JSON per CAAP-Capsule; this spec's JSON `x_content` fields are manifest-side descriptors, and its CBOR objects are the signed wire artifacts. Receipts are telemetry: action receipts flow through the same trees, records, and disclosure machinery as sensor data.

The key words MUST / MUST NOT / SHOULD / MAY are per RFC 2119 / RFC 8174.

## 2. Container and codecs

- **Container: MCAP.** One MCAP file per telemetry record, self-describing (schemas embedded), chunk-indexed, `zstd` or `lz4` chunk compression.
- **Codec registry** (extensible; unknown codecs MUST cause verifier rejection, mirroring CAAP-Capsule's suite rule):

| `content_type` | Payload |
|---|---|
| `application/mcap; compression=zstd` | container (REQUIRED outer format) |
| `model/draco` | point clouds, meshes |
| `application/vnd.laz` | survey-grade LIDAR |
| `application/vnd.octomap` | occupancy octrees |
| `application/caap-posegraph+cbor` | SLAM keyframes + factor graph |
| `video/av1` | camera streams |
| `application/cdr` | ROS 2 CDR-encoded messages (kinematics, IMU) |

- Every schema used is identified as `<namespace>:<name>@<sha256 of schema text>`; a record's descriptor commits the **schema set hash** (§4). Verifiers MUST reject messages whose schema hash is not in the committed set.
- **No canonicalization of payloads, ever.** Hashes are over encoded bytes exactly as captured and stored. Byte identity or nothing.

## 3. Chunking and content trees (byte-exact)

### 3.1 Chunking

Telemetry is chunked at capture into **HLC windows** (default `window_ms = 1000`), aligned to MCAP chunk boundaries: chunk *i* contains exactly the MCAP chunk record bytes (compressed form, as stored) for messages whose HLC timestamp lies in `[t0 + i·w, t0 + (i+1)·w)`. Implementations MUST cap `max_chunk_bytes` (RECOMMENDED ≤ 4 MiB) so a single reveal is always transferable.

**HLC64 encoding:** a 64-bit unsigned integer — upper 48 bits unix milliseconds, lower 16 bits logical counter. The actor is implied by the signing key; HLC ranges are `[uint, uint]` pairs of HLC64.

### 3.2 Content tree

The content tree is the RFC 9162 Merkle Tree Hash (`MTH`) over the ordered chunk byte strings:

```
MTH({})    = SHA-256("")
MTH([c])   = SHA-256( 0x00 ‖ c )
MTH(D[n])  = SHA-256( 0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]) ),
             k = largest power of two < n
```

Leaves in capture order; **no odd-leaf duplication** — the split rule makes tree shape a pure function of `leaf_count`, which the descriptor MUST still commit (redundant defense and proof-sizing). The `0x00`/`0x01` domain prefixes prevent leaf/node second-preimage confusion. Inclusion proofs follow RFC 9162 §2.1.3.

**Compatibility note:** the Portable Agent Memory Capsule ERC's record-level tree uses this same RFC 9162 construction (over `record_id ‖ payload_hash` entries), so one verifier implementation serves both layers. The legacy CAAP-Capsule v0.1 §4.4 tree (unprefixed, duplicate-last) remains distinct by specification for v1 capsules only; CAAP-Capsule v0.2 aligns on RFC 9162.

### 3.3 Two commitments per record

- `payload_hash` (CAAP-Capsule §4.6, unchanged): SHA-256 of the **ciphertext** file — transport/storage integrity.
- `content_root` (this spec): root of the content tree over **plaintext chunks** — selective disclosure. Revealing chunk *i* requires the chunk bytes, its sibling path to `content_root`, the record's inclusion path to the capsule `merkle_root`, and the anchor reference — O(log n) end to end.

### 3.4 Manifest descriptor (JSON, informative rendering)

```json
"x_content": {
  "content_root": "sha256:…", "leaf_count": 2400,
  "chunking": { "scheme": "hlc-window", "window_ms": 1000, "max_chunk_bytes": 4194304 },
  "hlc_range": [123456789012345, 123456791412345],
  "time_source_class": 2,
  "frame_graph": "sha256:…", "geo_cells": ["s2:89c25c1d"],
  "schema_set": "sha256:…", "content_type": "application/mcap; compression=zstd",
  "capture_attestation": "base64(COSE_Sign1)"
}
```

## 4. Capture attestation

Signed at record close by the **sensing domain key** (per-sensor secure element where present, else the LSC ingest key — attest at first touch):

```cddl
capture-attestation = {
   0: uint,            ; version = 1
   1: bstr .size 32,   ; record_id
   2: bstr .size 32,   ; content_root
   3: uint,            ; leaf_count
   4: uint,            ; window_ms
   5: [uint, uint],    ; hlc_range (HLC64)
   6: uint,            ; time_source_class: 0 best-effort, 1 NTS/Roughtime-checked, 2 TEE clock
   7: uint,            ; boot_counter
   8: uint,            ; capture_counter (strictly monotonic per signer)
   9: bstr .size 32,   ; frame_graph_hash (tf snapshot)
  10: [* uint],        ; geo_cells (S2 cell ids, uint64; coarse per privacy policy)
  11: bstr .size 32,   ; schema_set_hash
}
```

`time_source_class` is evidence weighting, not decoration: resolvers SHOULD discount class-0 timestamps in contested windows. **Ordering is normative on `(boot_counter, capture_counter)`** — the rollback-protected counters the CAAP-WIPE contradiction checks also read; HLC64 values are correlation evidence for cross-body alignment, never the primary order. Two records from one signer are ordered by counters even when their HLC values disagree.

## 5. Execution profile (CAAP-LSC wire)

### 5.1 IntentPayload

Signed by the **cognition-runtime key** (measured harness, Gap D):

```cddl
intent-payload = {
   0: uint,            ; version = 1
   1: bstr .size 32,   ; intent_id = SHA-256(0x02 ‖ actor ‖ seq)
   2: uint,            ; seq (per cognition session)
   3: uint,            ; issued_hlc (HLC64)
   4: uint,            ; horizon_ms
   5: bstr .size 32,   ; frame_id (hash of named frame in frame graph)
   6: [* int],         ; target pose, fixed-point (µm, µrad)
   7: {* uint => int}, ; bounds: dimension-code => fixed-point value
                       ;   1: v_max (µm/s)  2: a_max (µm/s²)  3: force_max (mN)
                       ;   4: torque_max (µN·m)  5: tool_class
   8: uint,            ; context_taint: 0 clean, 1 tainted (harness-stamped)
}
```

### 5.2 ActionReceipt

Signed by the **LSC execution key**, one per telemetry chunk window, hash-chained:

```cddl
action-receipt = {
   0: uint,            ; version = 1
   1: bstr .size 32,   ; obligation_id (joins CAAP-WIPE / LeaseBond)
   2: bstr .size 32,   ; ticket_hash (digest of governing DeadManTicket COSE object)
   3: uint,            ; receipt_sequence (strictly monotonic per obligation)
   4: bstr .size 32,   ; previous_receipt_hash (zero for sequence 1)
   5: [uint, uint],    ; hlc_range
   6: bstr .size 32,   ; envelope_hash (compiled envelope in force)
   7: [* verdict],
   8: bstr .size 32,   ; executed_root  (content tree over executed-trajectory chunks)
   9: bstr .size 32,   ; intent_root    (content tree over intent-payload digests, this window)
  10: uint,            ; boot_counter
  11: uint,            ; monotonic_counter
}

verdict = [ bstr .size 32,  ; intent_id
            uint,           ; result: 0 executed, 1 clamped, 2 refused,
                            ;         3 safe_stated, 4 estop
            ? {* uint => int} ]  ; clamp deltas, same dimension codes as bounds
```

Receipts are stored as telemetry records (`content_type: application/caap-receipt+cbor`) and therefore inherit chunking, trees, capsule inclusion, and anchoring for free. A sequence gap or broken `previous_receipt_hash` chain in a disclosed window is itself evidence (missing-receipt inference, resolver-weighted). Receipt batches anchor via `EvidenceRootCommitted` on the settlement contract; anchoring failure never affects motion.

### 5.3 TerminalReceipt

Best-effort last-gasp record, written to the LSC ring buffer on unrecoverable conditions; the black box of a §2.4.4 destruction claim:

```cddl
terminal-receipt = {
   0: uint,            ; version = 1
   1: bstr .size 32,   ; obligation_id
   2: uint,            ; trigger: 1 impact, 2 thermal, 3 power, 4 watchdog, 5 other
   3: uint,            ; hlc (HLC64)
   4: {* uint => int}, ; final readings, fixed-point (accel µm/s², temp mK, bus mV, …)
   5: bstr .size 32,   ; last_receipt_hash
   6: uint,            ; boot_counter
   7: uint,            ; monotonic_counter
}
```

## 6. Disclosure bundle — what `respond` commits to

The respondent to a LeaseBond claim publishes a **disclosure bundle**; `disclosureRoot = SHA-256(0x02 ‖ deterministic-CBOR(bundle))`.

```cddl
disclosure-bundle = {
   0: uint,                    ; version = 1
   1: uint,                    ; claim_id
   2: [uint, uint],            ; claim window (HLC64)
   3: [* record-disclosure],
}

record-disclosure = {
   0: bstr .size 32,           ; record_id
   1: [* bstr .size 32],       ; inclusion path: record → capsule merkle_root (CAAP-Capsule §4.4)
   2: bstr .size 32,           ; capsule merkle_root
   3: anchor-ref,              ; where and when that root was anchored
   4: bstr,                    ; capture-attestation (COSE_Sign1 bytes)
   5: [* chunk-reveal],
}

anchor-ref = [ uint,           ; kind: 1 caap-btc-opreturn-v1, 2 eth-event-log-v1
               uint,           ; chain id / network id
               bstr,           ; txid or (block number ‖ log index)
               uint ]          ; anchor time (unix s, informative)

chunk-reveal = [ uint,         ; leaf_index
                 bstr,         ; chunk_bytes (exact stored bytes)
                 [* bstr .size 32] ]  ; sibling path to content_root
```

**Validator procedure** (an ERC-8004 validator, RFC 9334 verifier role, needs nothing beyond this document plus chain access): (1) parse the bundle under §2's decoder discipline; (2) confirm each `anchor-ref` predates the claim; (3) verify each capture attestation against the enrolled sensing/LSC keys; (4) recompute each revealed chunk's path to `content_root` (§3.2) and the record's path to the anchored capsule root; (5) decode chunks under the committed schema set and re-run the physics checks (kinematics consistency, fusion residuals, envelope intersection against `envelope_hash`); (6) emit an Attestation Result binding evidence hash, verifier version, and appraisal policy — which the resolver consumes. Claims and cross-checks MUST cite chunks by `(record_id, leaf_index)` so every assertion is mechanically dereferenceable.

**Completeness rule:** for the claim window, the bundle MUST include all records of the classes the lease's disclosure policy names (receipts always included). A window covered by an anchored `content_root` whose chunks are *not* revealed is `TelemetryWithheld` evidence; a revealed chunk failing verification is `EvidenceFraud` evidence.

## 7. Witness and proximity attestations

A witness (another body, or fixed infrastructure running this profile) MAY countersign an observed record root, in passing, over any transport:

```cddl
proximity-attestation = {
   0: uint,            ; version = 1
   1: bstr .size 32,   ; observed content_root (or receipt hash)
   2: bstr .size 32,   ; observer record_id in which the observation is logged
   3: uint,            ; observer hlc (HLC64)
   4: uint,            ; observer geo_cell (S2)
   5: uint,            ; observer boot_counter
}
```

Signed by the **witness key** domain. Proximity attestations pre-build the witness graph for §2.4 arbitration and the `witness_root` of a LossReport; they carry zero authority (CAAP-TICKET §6 — witnessing, never arming). Discovery is retrospective via `geo_cells` overlap.

## 8. Retention

| Tier | Contents | Rule |
|---|---|---|
| T0 | raw chunks | MUST retain ≥ the bond's `claimDeadline` + resolver appeal window (C1+ leases) |
| T1 | distilled (keyframes, landmarks, occupancy diffs) | retained per agent memory policy |
| T2 | hashes only (roots, attestations, receipts) | retained indefinitely; cheap |

Aging T0→T2 never breaks commitments — provability of *what was committed* survives; the ability to *reveal* does not. Dropping T0 inside a mandatory window is `TelemetryWithheld` by construction.

## 9. Security considerations

- **Time.** All ordering hangs on HLC64 values whose physical component is only as good as `time_source_class`. Class-2 (TEE clock) capture SHOULD be required for C2/C3 operation; resolvers weight accordingly (brief §3 Gap H).
- **Geo-cell privacy.** `geo_cells` resolution is a privacy dial: manifests SHOULD carry coarse cells (S2 level ≤ 12) with fine location living inside encrypted chunks, disclosed only under claims.
- **Spoofing.** This spec makes *fabrication* fail cryptographically (attest-at-first-touch, anchored roots, counters, hash-chained receipts) and gives *environmental* spoofing its adjudication substrate (multi-modal disclosure, witness graphs, fusion-residual checks) — the threat split and its limits are per brief §4.7; nothing here makes a sensor truthful.
- **DoS bounds.** `max_chunk_bytes`, per-bundle reveal counts, and per-claim disclosure caps MUST be set in lease policy so a claimant cannot compel unbounded disclosure work, nor a respondent drown a validator.
- **No floats, no tags, closed maps** — CAAP-TICKET §2.3's decoder rejection rules apply verbatim to every CBOR object in this spec.

## 10. Copyright

Copyright and related rights waived via CC0 1.0 Universal.
