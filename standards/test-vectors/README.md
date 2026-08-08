# CAAP Golden Test Vectors

**Status:** seed set v0.1 — deterministic vectors for independent implementations to converge on.
**License:** CC0.

## Files

- `merkle-hlc-vectors.json` — content-tree vectors (CAAP-TELEMETRY §3.2), capsule v2 record-tree vectors (Portable Agent Memory Capsule ERC §3), and HLC64 encoding examples.

## Construction rules the vectors pin down

1. Content tree: `leaf = SHA-256(0x00 ‖ chunk_bytes)`, `node = SHA-256(0x01 ‖ left ‖ right)`, odd levels duplicate the last node, empty tree root = `SHA-256(0x00)`.
2. **Single-leaf tree root equals the leaf hash** — no self-duplication at size 1; duplication applies only to odd levels of size > 1. (Clarifies an ambiguity in the v0.1 prose; fold into the next spec revision.)
3. Capsule v2 record tree: `leaf = SHA-256(0x00 ‖ record_id(32) ‖ payload_hash(32))` — 65-byte preimage of raw bytes, never hex strings.
4. HLC64: `uint64 = (unix_ms << 16) | logical_counter`.

## Planned additions (contributions welcome)

- `COSE_Sign1` DeadManTicket examples with fixed ES256 test keys (CAAP-TICKET §2) — encode/decode + signature verification.
- Deterministic-CBOR encode/decode pairs for `capture-attestation`, `action-receipt`, `terminal-receipt`, `intent-payload` (CAAP-TELEMETRY §§4–5), including required-rejection cases (floats, indefinite lengths, duplicate keys, unknown keys).
- `obligationId` derivation vectors (keccak-256; requires an EVM hashing dependency, deliberately excluded from this seed set's stdlib-only generator).
- Disclosure-bundle round-trip: bundle → `disclosureRoot`, chunk-reveal path verification.
- EIP-712 `CapsuleCommit` digest vectors for the capsule ERC's `eip-712` suite.

## Regenerating

The seed vectors are generated with a Python-stdlib-only script (SHA-256, no external deps) so any implementer can re-derive them. Any mismatch between an implementation and these vectors is a bug in one of the two — file an issue either way.
