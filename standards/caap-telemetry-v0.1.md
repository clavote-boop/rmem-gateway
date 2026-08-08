# CAAP-TELEMETRY v0.1

**Status:** Normative draft  
**Companion artifacts:** `caap-evidence-v0.1.cddl`, `m2-conformance-vectors-v0.1.json`  
**Consumes:** ERC-8269 lease/ticket state, CAAP-WIPE enrollment and obligation identifiers  
**Feeds:** LeaseBond claims and disclosures, CAAP-LSC receipts, CAAP-Capsule records  
**License:** CC0-1.0

## 1. Purpose

CAAP-TELEMETRY defines a byte-exact, selectively disclosable record profile for spatial, sensor, actuator, safety, and witness evidence produced by embodied agents.

The profile establishes five properties:

1. Exact captured bytes can be authenticated without reserialization.
2. A bounded incident window can be disclosed without revealing the rest of a mission.
3. Sensor, cognition, and execution evidence use one proof construction.
4. Every disclosed coordinate and timestamp carries enough context to be interpreted.
5. `LeaseBond.respond(disclosureRoot)` commits a complete, reproducible proof transcript.

This specification does not make sensors truthful. It makes their outputs attributable, fresh, internally ordered, tamper-evident, and comparable with independent evidence.

## 2. Normative terminology

- **EvidenceItem:** descriptor for one captured message or derived safety record.
- **EvidenceChunk:** a signed commitment to a time-bounded collection of EvidenceItems and exact MCAP Chunk bytes.
- **Content tree:** ordered RFC 9162 Merkle tree of signed EvidenceChunk byte strings.
- **Item tree:** ordered RFC 9162 Merkle tree of deterministic-CBOR EvidenceItem byte strings inside one EvidenceChunk.
- **Record content root:** root of the content tree stored in the CAAP-Capsule record profile.
- **DisclosureManifest:** deterministic-CBOR transcript binding disclosed chunks, proofs, schemas, frames, time policy, claim, bond, and obligation.
- **Capture producer:** enrolled sensor key or measured LSC ingest key that signs an EvidenceChunk.

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are normative.

## 3. Encoding profile

All metadata defined by this specification MUST use deterministic CBOR under RFC 8949 and the CDDL in `caap-evidence-v0.1.cddl`.

Decoders MUST reject:

- indefinite-length arrays, maps, byte strings, or text strings;
- duplicate map keys;
- non-preferred integer or length encodings;
- floating-point values, including NaN and infinities;
- unregistered CBOR tags;
- unknown fields in a closed profile;
- values outside their CDDL ranges;
- invalid UTF-8 where a referenced external schema permits text;
- a map whose encoded key order is not RFC 8949 deterministic order.

Physical values in CAAP metadata MUST be signed integers with profile-defined SI scale factors. Re-encoding a floating-point sensor payload is forbidden; payload bytes are hashed exactly as captured.

### 3.1 Core taint bitmap

For v0.1, `taint` bits have these meanings. Bits 16–31 are reserved and MUST be zero.

| Bit | Meaning |
|---:|---|
| 0 | Environmental visual text/symbol input contributed |
| 1 | Environmental speech/audio interpretation contributed |
| 2 | Unauthenticated network or Web/tool content contributed |
| 3 | Generative/model-derived assertion contributed |
| 4 | Unauthenticated human instruction contributed |
| 5 | Externally supplied coordinate, transform, or target contributed |
| 6 | A required sensor-integrity state was unresolved |
| 7 | Information crossed from another lease/body session |
| 8 | A policy-recognized authenticated operator approval contributed |
| 9 | A policy-recognized facility authorization contributed |
| 10 | Independent physical corroboration contributed |
| 11 | Witness evidence contributed |
| 12 | A declassification/appraisal step was applied |
| 13 | Source material was incomplete or selectively unavailable |
| 14 | Provenance graph was truncated |
| 15 | Profile-specific extension present in the committed schema bundle |

Bits 8–12 add provenance; they do not clear bits 0–7. The effective policy evaluates the complete bitmap and provenance graph.

## 4. Container profile

### 4.1 MCAP

The default container is MCAP. MCAP stores heterogeneous, timestamped, pre-serialized data and defines Chunk records containing compressed or uncompressed batches of Schema, Channel, Message, and private records.

Each CAAP EvidenceChunk MUST reference exactly one serialized MCAP Chunk record. `payload_hash` is:

```text
payload_hash = SHA-256(exact_mcap_chunk_record_bytes)
```

`exact_mcap_chunk_record_bytes` begins with the MCAP record opcode, includes the encoded record length and body, and ends at the record boundary. A verifier MUST hash the disclosed bytes before parsing them.

Implementations MUST NOT normalize, decompress and recompress, rewrite indexes, reorder records, convert schemas, or regenerate an equivalent MCAP record before verification. Equivalent semantics are not byte identity.

The Schema and Channel records needed to parse messages MUST either:

1. occur earlier within the same disclosed MCAP Chunk record; or
2. be supplied in a deterministic schema bundle whose root equals `schema_set_root`.

### 4.2 Compression and encryption

Compression occurs before hashing and encryption. The initially captured compressed bytes are the committed plaintext payload.

MCAP provides no CAAP confidentiality guarantee. Each payload chunk SHOULD be encrypted independently after capture signing so that one incident window can be disclosed without releasing a mission-wide decryption key.

The CAAP-Capsule `payload_hash` continues to commit the stored ciphertext artifact. CAAP-TELEMETRY `payload_hash` and `content_root` commit the selectively disclosable plaintext evidence. These commitments serve different purposes and MUST NOT be substituted for one another.

## 5. EvidenceItem construction

For each captured message or derived record, the producer constructs the CDDL `evidence-item` map.

```text
item_bytes  = deterministic_cbor(EvidenceItem)
item_digest = SHA-256(item_bytes)
```

The `payload_hash` field of an EvidenceItem is `SHA-256(exact_message_payload_bytes)`. Message payload bytes remain in the MCAP Chunk record; the EvidenceItem supplies their schema, time, frame, stream sequence, provenance, and taint commitment.

Items MUST be ordered by:

```text
(boot_counter, monotonic_ns, stream_id, stream_sequence)
```

Equal ordering tuples are invalid. Gaps MAY occur, but MUST be represented by a diagnostic item or chunk profile flag when the producer detected the loss.

## 6. Merkle construction

All trees in this specification use SHA-256 and the RFC 9162 construction:

```text
MTH({})       = SHA-256("")
MTH({d[0]})   = SHA-256(0x00 || d[0])
MTH(D[n])     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
```

For `n > 1`, `k` is the largest power of two smaller than `n`. Implementations MUST NOT duplicate an odd final node, sort digests, or use a power-of-two padding leaf.

### 6.1 Item tree

```text
item_root = MTH([item_bytes_0, ..., item_bytes_n-1])
```

The EvidenceChunk header binds `item_root` and `item_count`.

### 6.2 Content tree

Each deterministic EvidenceChunk header is carried as the payload of a tagged COSE_Sign1 object. The complete deterministic COSE_Sign1 byte string is one content-tree entry:

```text
signed_chunk_bytes  = deterministic_cbor(COSE_Sign1)
signed_chunk_digest = SHA-256(signed_chunk_bytes)
content_root        = MTH([signed_chunk_bytes_0, ..., signed_chunk_bytes_n-1])
```

The content tree order is `(boot_counter, chunk_sequence)`. The signed header's `previous signed-chunk digest` MUST equal the preceding entry's `signed_chunk_digest`, except for the first chunk of a body session where it is the zero hash.

The hash chain detects omission or alternative local histories; the Merkle tree supports selective disclosure and anchoring.

## 7. Capture signatures

EvidenceChunk headers MUST be signed at first touch by either:

- an enrolled per-sensor secure-element key; or
- the measured LSC ingest path that directly polls the sensor outside the cognitive runtime.

The COSE object MUST:

- use COSE_Sign1 with CBOR tag 18;
- carry the EvidenceChunk header as an embedded payload;
- place `alg`, `kid`, and content type in protected headers;
- use empty `external_aad` for v0.1;
- use an enrolled key whose measurement and role are discoverable from the obligation's enrollment evidence.

The baseline algorithm is ES256. ES256 signatures MUST use the low-S form, even though EIP-7951 accepts both S values. Receipt and chunk identity is always the digest of the signed statement bytes, never the signature alone.

Signature validity proves which enrolled capture path committed the bytes. It does not prove that the physical stimulus was truthful.

## 8. Chunking rules

The default profile uses monotonic-time windows of 1,000 milliseconds. A deployment MAY select a different duration in its retention and evidence policy.

Chunks MUST:

- be aligned using the secure monotonic time base for one `body_session_id`;
- contain a half-open time range `[start, end)`;
- never overlap another chunk from the same producer and stream set;
- close early on boot transition, producer-key rotation, envelope change, terminal LSC event, or counter discontinuity;
- not split one atomic MCAP Message record across payload artifacts;
- report truncation, overflow, dropped data, saturation, and writer backpressure in profile flags and diagnostics.

The v0.1 `profile_flags` bits are: bit 0 truncated chunk, 1 source sequence gap, 2 capture ring overflow, 3 writer backpressure, 4 payload CRC unavailable, 5 schema external to chunk, 6 frame graph external to chunk, 7 UTC unavailable, 8 UTC uncertainty exceeded, 9 producer counter discontinuity, 10 storage degradation, 11 anchoring deadline exceeded, and 12 terminal close. Bits 13–31 are reserved and MUST be zero.

The 1,000 ms default is an evidence cadence, not a control-loop frequency and not a safety deadline.

## 9. Time

Security ordering is established by:

```text
body_session_id + boot_counter + monotonic_ns + sequence
```

UTC, GNSS time, network time, and HLC fields are correlation evidence. They MUST NOT extend Operating Ticket validity, delay a local safety transition, or override monotonic ordering.

If UTC is supplied, `utc_uncertainty_ns` and `time_source` MUST also be supplied. A verifier applies the claim's versioned time-appraisal policy before comparing different bodies.

Clock rollback, unexplained boot-counter regression, or two signed chunks claiming incompatible time ranges under one counter lineage is contradiction evidence.

## 10. Spatial semantics

Robotics payload schemas SHOULD follow REP 103 SI units and right-handed coordinate conventions. Mobile-platform frame semantics SHOULD follow REP 105.

Every spatial EvidenceItem MUST provide a nonzero `frame_id_hash`. Every EvidenceChunk containing spatial items MUST provide a nonzero `frame_graph_hash` committing the transforms required to resolve those frames during the chunk interval.

The frame graph bundle MUST state:

- frame names and hashed identifiers;
- parent-child transforms;
- transform validity intervals;
- the fixed-point or original payload schema used;
- calibration identifiers and covariance/uncertainty representation;
- map/odom discontinuity events.

`geo_commitment` MUST be a commitment to a canonical list of profile-qualified spatial cells and a nonce. Raw geocells SHOULD remain encrypted or be disclosed only at policy-approved resolution. Public fine-grained cells create a fleet-surveillance surface.

## 11. Sensor integrity state

Trust is evaluated per observation, not permanently per modality. Evidence policies SHOULD distinguish:

| State | Meaning |
|---|---|
| Authenticated | Produced by an enrolled device or measured ingest path |
| Fresh | Counters, time, and sequence pass anti-replay policy |
| Plausible | Physical and temporal invariants pass |
| Corroborated | Independent fault domains agree within declared uncertainty |
| Safety-qualified | All evidence requirements for the proposed consequence class pass |

These states belong in profile-defined item payloads or diagnostics. A signature alone establishes only `Authenticated`.

## 12. ActionReceipt integration

A CAAP-LSC ActionReceipt is an EvidenceItem with `item_type = action_receipt`. Its exact deterministic-CBOR payload bytes are stored in the MCAP Chunk record and committed by the EvidenceItem `payload_hash`.

The receipt's:

- `intent_set_root` commits cognition requests;
- `verdict_set_root` commits LSC decisions;
- `command_root` commits actuator commands;
- `executed_root` commits independently captured actuator feedback and observed trajectory;
- `sensor_evidence_root` commits the sensor inputs used by the safety decision.

Each root uses the same RFC 9162 construction over deterministic EvidenceItem bytes. `executed_root` MUST NOT be an alias for `command_root`; the distinction is load-bearing for liability.

A TerminalReceipt is an independently signed special record and SHOULD also be inserted as `item_type = terminal_receipt` in the final recoverable EvidenceChunk.

## 13. CAAP-Capsule record profile

A CAAP-Capsule telemetry record MUST carry an extension equivalent to:

```json
{
  "x_content": {
    "profile": "caap-telemetry-v0.1",
    "content_root": "sha256:<32-byte root>",
    "tree_size": 2400,
    "chunking": { "scheme": "monotonic-window", "window_ms": 1000 },
    "time_range_commitment": "sha256:<commitment>",
    "frame_graph_root": "sha256:<root>",
    "schema_bundle_root": "sha256:<root>",
    "geo_commitment": "sha256:<commitment>",
    "retention_policy_hash": "sha256:<hash>"
  }
}
```

This JSON is part of the enclosing CAAP manifest and follows that specification's canonicalization. It is not used inside the LSC or capture path.

## 14. Selective disclosure

### 14.1 DisclosureManifest

`LeaseBond.respond(disclosureRoot)` uses:

```text
manifest_bytes = deterministic_cbor(DisclosureManifest)
disclosureRoot = SHA-256(0x02 || manifest_bytes)
```

The domain byte `0x02` distinguishes disclosure commitments from RFC 9162 leaves and internal nodes.

The manifest binds the claim, bond, obligation, lease, body, incident interval, Capsule root, anchor, disclosed content leaves, schema bundle, frame graph bundle, time policy, and prior commit-then-reveal transcript.

### 14.2 Reveal package

For every `disclosure-entry`, the responding party reveals:

1. deterministic signed EvidenceChunk bytes;
2. RFC 9162 inclusion path and content tree size;
3. exact MCAP Chunk record bytes;
4. item descriptors and item-level proofs needed by the claim;
5. decryption material scoped to those chunks;
6. schema, frame, calibration, time, and attestation appraisal bundles;
7. the CAAP record-to-Capsule proof and Capsule anchor proof.

The verifier MUST check in that order from byte hashes outward. Parsing unverified MCAP or schema material is forbidden.

### 14.3 Completeness

An inclusion proof establishes presence, not completeness. A claim policy MUST therefore name required stream classes for the incident type. Missing required streams, unexplained sequence gaps, expired raw-data retention, or refusal to disclose are explicit appraisal results; they are not silently treated as zero-valued sensors.

## 15. Retention tiers

- **T0:** raw MCAP payload chunks, signed headers, and proofs.
- **T1:** policy-approved derived/keyframe payloads plus T0 commitments.
- **T2:** signed headers, content roots, anchors, and appraisal results only.

T0 retention MUST extend beyond the maximum claim, response, appeal, and zombie/contradiction windows applicable to the obligation. Destruction or aging of T0 before that deadline is evidence unavailability and may trigger adverse inference under LeaseBond policy.

## 16. Witness evidence

Witnesses use the same EvidenceChunk schema. Mesh transport may relay signed chunks and cross-sign digests, but relays do not become capture producers and cannot change authority.

Real-time witness availability is not required for ordinary arbitration. Attest-at-first-touch and local persistence allow later discovery. A safety or site policy MAY separately require live corroboration before a C3 action.

RF jamming, channel occupancy, packet loss, and clock-quality observations SHOULD be captured as `rf_health` items so loss of corroboration is itself visible evidence.

## 17. Anchoring

Anchoring cadence is a security parameter because evidence generated after the last anchor remains susceptible to key compromise and alternative-history construction.

Policies MUST declare:

- maximum unanchored duration;
- elevated cadence for C2/C3 operations;
- accepted anchor types and finality rules;
- behavior during connectivity loss;
- whether witness cross-signatures provide interim anchoring weight.

Anchoring a content root proves a commitment existed no later than anchor inclusion/finality. It does not prove the underlying sensor was accurate.

## 18. Required conformance tests

Implementations MUST test:

1. deterministic encoding produces the published byte vector;
2. duplicate keys, floats, indefinite lengths, and unknown fields are rejected;
3. item and content roots match the published RFC 9162 vectors;
4. an odd number of leaves uses recursive splitting without duplication;
5. MCAP recompression changes `payload_hash` and is rejected;
6. a valid item proof and content proof verify through the Capsule anchor;
7. wrong tree size, index, sibling order, or domain byte fails;
8. boot-counter rollback and chunk-sequence reuse are contradiction evidence;
9. invalid or high-S ES256 capture signatures are rejected by this profile;
10. missing schemas and frame graphs fail spatial appraisal;
11. UTC comparison without uncertainty and time policy is rejected;
12. `command_root` and `executed_root` cannot be substituted;
13. a DisclosureManifest for another claim, bond, or obligation is rejected;
14. unavailable required streams produce an explicit incomplete result.
15. `node verify-vectors.js` succeeds against the published vectors.

## 19. References

- [MCAP format specification](https://mcap.dev/spec)
- [MCAP implementation notes](https://mcap.dev/spec/notes)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/info/rfc8949/)
- [RFC 9052 — COSE](https://www.rfc-editor.org/info/rfc9052/)
- [RFC 9162 — Merkle tree and proof construction](https://www.rfc-editor.org/info/rfc9162/)
- [ROS REP 103 — units and coordinate conventions](https://www.ros.org/reps/rep-0103.html)
- [ROS REP 105 — mobile-platform coordinate frames](https://www.ros.org/reps/rep-0105.html)
- [EIP-7951 — P-256 verification](https://eips.ethereum.org/EIPS/eip-7951)
