# CAAP Golden Test Vectors

**Status:** seed set v0.1 — deterministic vectors for independent implementations to converge on.
**License:** CC0.

## Files

- `merkle-hlc-vectors.json` — content-tree vectors (CAAP-TELEMETRY §3.2), capsule v2 record-tree vectors (Portable Agent Memory Capsule ERC §3), and HLC64 encoding examples.

## Construction rules the vectors pin down

1. All trees are the **RFC 9162 Merkle Tree Hash**: `MTH({}) = SHA-256("")`, `MTH([e]) = SHA-256(0x00 ‖ e)`, `MTH(D[n]) = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))` with `k` = largest power of two < n. No odd-leaf duplication; tree shape is a pure function of entry count.
2. Content-tree entries are raw chunk bytes in capture order (CAAP-TELEMETRY §3.2).
3. Capsule v2 record-tree entries are 64-byte `record_id(32) ‖ payload_hash(32)` concatenations of raw bytes (never hex strings), sorted ascending by `record_id` (Portable Agent Memory Capsule ERC §3).
4. HLC64: `uint64 = (unix_ms << 16) | logical_counter`.

## Planned additions (contributions welcome)

- `COSE_Sign1` DeadManTicket examples with fixed ES256 test keys (CAAP-TICKET §2) — encode/decode + signature verification.
- Deterministic-CBOR encode/decode pairs for `capture-attestation`, `action-receipt`, `terminal-receipt`, `intent-payload` (CAAP-TELEMETRY §§4–5), including required-rejection cases (floats, indefinite lengths, duplicate keys, unknown keys).
- `obligationId` derivation vectors (keccak-256; requires an EVM hashing dependency, deliberately excluded from this seed set's stdlib-only generator).
- Disclosure-bundle round-trip: bundle → `disclosureRoot`, chunk-reveal path verification.
- EIP-712 `CapsuleCommit` digest vectors for the capsule ERC's `eip-712` suite.

## Regenerating

Run `python3 generate_vectors.py` in this directory — the committed, stdlib-only generator (SHA-256, no external deps) rewrites `merkle-hlc-vectors.json` deterministically. Any mismatch between an implementation and these vectors is a bug in one of the two — file an issue either way.
