# CAAP-Capsule v0.1 — Chain-Agnostic Portable Agent Memory Capsule

**Status:** Draft v0.1
**Editors:** Clavote Research (`@clavote-boop`)
**License:** CC0 — public domain dedication.
**Discussion:** https://ethereum-magicians.org/t/erc-8269-body-lease-and-credential-broker/28597 (cross-posted; chain-agnostic venue TBD — candidate CAIP submission)

## 1. Purpose

A **Capsule** is a canonical, owner-signed, content-addressed bundle that carries an AI agent's memory across implementations, hosts, and chains. The Capsule format is intentionally decoupled from any specific blockchain, identity scheme, or authorization surface so that the same payload may move between Bitcoin-anchored agents, Ethereum-anchored agents, IPFS-pinned agents, and offline replicas.

This specification defines:

- The bytes of a Capsule (manifest schema, canonicalization, Merkle commitment).
- A **signature-suite registry** so multiple ecosystems can sign Capsules using their native conventions.
- An **optional anchoring registry** so Capsule Merkle roots may be committed to any public chain or content-addressed store.

This specification does *not* define:

- The authorization surface a gateway exposes to the agent (covered by ERC-8264 for Ethereum, or any equivalent rights interface in another ecosystem).
- The lease primitive that binds an agent identity to a host (covered by ERC-8269 for the EVM ecosystem).
- The encryption scheme used for Capsule payloads (implementor-defined; only ciphertext hashes are committed).

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

- **Subject** — the agent identity whose memory the Capsule carries. Represented as a `subject_id` opaque string (see §3.1). MAY be an Ethereum address, a `did:btc:` identifier, any other DID method, or an implementor-defined URI.
- **Controller** — an entity holding a private key authorized to sign manifests for the subject.
- **Signature suite** — a named convention specifying signing curve, message wrapping, and verification rules. Registered in §6.
- **Anchor** — an optional commitment of the Capsule's Merkle root to a public substrate. Registered in §7.

## 3. Capsule Structure

A Capsule is a directory or archive containing:

- `manifest.json` — a canonical-JSON object (see §4), signed under a registered signature suite.
- `records/<recordId>.enc` — encrypted payload files, where `recordId` matches an entry in the manifest's `record_index`.

## 4. Manifest

The manifest MUST include the following fields:

```json
{
  "capsule_version": "1",
  "subject_id": "<opaque string>",
  "subject_id_method": "<registered method name>",
  "controllers": [
    { "method": "<registered method>", "identifier": "<opaque string>" }
  ],
  "created_at": "2026-05-22T00:00:00Z",
  "signature_suite": "<registered suite name>",
  "record_index": [
    { "record_id": "...", "payload_hash": "sha256:<hex>" }
  ],
  "merkle_root": "sha256:<hex>",
  "owner_signature": "<suite-encoded signature>"
}
```

### 4.1 Subject identifier

`subject_id` is an opaque UTF-8 string identifying the agent. `subject_id_method` names the resolution method, drawn from the following registry (additional methods MAY be added by extension):

| Method            | `subject_id` format                                        |
|-------------------|------------------------------------------------------------|
| `eth-address`     | `0x` + 40 lowercase hex chars (EIP-55 case ignored)        |
| `did:btc`         | `did:btc:<bech32-pubkey>`                                  |
| `did:key`         | `did:key:<multibase-encoded-pubkey>`                       |
| `did:web`         | `did:web:<host>[:<path>]`                                  |
| `urn`             | `urn:<nid>:<nss>` per RFC 8141                             |

Implementors MAY register additional methods by extension; method names not in the registry are treated as opaque and MUST NOT be assumed verifiable by an importing gateway.

### 4.2 Controllers

`controllers` lists identifiers authorized to sign manifests for this subject. Each entry MUST itself name a registered `method`. The first entry is the active owner.

### 4.3 Canonicalization

The manifest MUST be canonicalized before signing or hashing per RFC 8785 (JSON Canonicalization Scheme):

- Object keys sorted lexicographically by UTF-16 code unit at every nesting level.
- No insignificant whitespace.
- Numbers serialized per RFC 8785 §3.2.2.2.
- UTF-8 encoding.

### 4.4 Merkle commitment

`merkle_root` MUST be a binary Merkle tree over the 32-byte SHA-256 hashes in `record_index`, in the order they appear. Internal nodes are `sha256(left || right)`. Odd levels duplicate the last node. The empty-index case is `sha256("")`.

### 4.5 Signature

`owner_signature` MUST be produced under the signature suite named in `signature_suite`, over the canonical JSON of the manifest with the `owner_signature` field removed. Suites are defined in §6.

### 4.6 Payload files

`.enc` files are encrypted off-chain; the encryption scheme is implementor-defined. The manifest MUST commit only to the `payload_hash` of the on-disk *ciphertext*, never to plaintext. Decryption keys MUST NOT be included in the Capsule.

### 4.7 Extension fields

Implementors MAY include extension fields prefixed `x_` in the manifest. Importing gateways MUST NOT reject capsules solely on the presence of unrecognized `x_` fields.

## 5. Verification

An importing gateway verifies a Capsule by:

1. Parsing `manifest.json` and resolving `signature_suite` from the registry in §6.
2. Computing the suite-defined signing input (the canonical manifest minus `owner_signature` for content-binding suites; the `owner_signature_message` value for auth-message-bound suites).
3. Verifying `owner_signature` against an authorized controller per the suite's verification rules.
4. Recomputing `merkle_root` from `record_index` and confirming the manifest's value.
5. For each `record_index` entry, reading `records/<record_id>.enc`, computing its SHA-256, and confirming the manifest's `payload_hash`.

Verification MUST fail closed: any suite name not in the registry, any signature mismatch, any hash mismatch, or any unresolved `subject_id_method` whose semantics the verifier relies on MUST cause rejection.

## 6. Signature Suite Registry

A signature suite specifies the signing curve, message wrapping, and verification rules. v0.1 defines three suites; additional suites MAY be registered by extension.

### 6.1 `eip-191`

- Curve: secp256k1.
- Signing input: `"\x19Ethereum Signed Message:\n" || len(msg) || msg`, where `msg` is the canonical JSON manifest (manifest with `owner_signature` removed).
- Hash: keccak-256 of the signing input.
- Signature: 65-byte `r || s || v` per Ethereum convention.
- `owner_signature` encoding: `0x` + hex.
- Authorized-controller resolution: the recovered secp256k1 public key's Ethereum address MUST match a controller whose `method` is `eth-address`.

### 6.2 `eip-191-authmsg`

A pre-sign variant of `eip-191` that lets the controller sign an authorization message off-host before the gateway constructs the manifest. The manifest carries the authorization message alongside the signature; verifiers recover the controller from the auth message rather than from the full manifest.

- Curve: secp256k1.
- Manifest MUST include an additional field `owner_signature_message` whose value is the canonical JSON of an authorization object with at least: `op` (the ERC-8264 op authorizing the export), `subject` (matching the manifest's `subject_id`), `nonce`, `expires_at`.
- Signing input: `"\x19Ethereum Signed Message:\n" || len(authmsg) || authmsg`, where `authmsg` is the value of `owner_signature_message`.
- Hash: keccak-256 of the signing input.
- Signature: 65-byte `r || s || v` per Ethereum convention.
- `owner_signature` encoding: `0x` + hex.
- Authorized-controller resolution: the recovered secp256k1 public key's Ethereum address MUST match a controller whose `method` is `eth-address`.
- **Binding gap (informative).** This suite's signature does NOT commit to the manifest's `merkle_root` or `record_index` directly. The auth message provides time-bounded export authorization but not content-binding; relying parties that require content-binding MUST use `eip-191` (signs the full canonical manifest) instead, or include `merkle_root` in a custom auth-message field and validate it.

### 6.3 `bip-322-legacy`

- Curve: secp256k1.
- Signing per BIP-322 (legacy single-signature mode).
- Signing input: the canonical JSON manifest (manifest with `owner_signature` removed).
- `owner_signature` encoding: base64.
- Authorized-controller resolution: the BIP-322-verified message MUST correspond to a controller whose `method` is `did:btc` whose pubkey derives the same secp256k1 key.

Implementors MAY register additional suites by extension (for example `ed25519-ed25519ph`, `did-jwt-es256k`). Suite names not in the registry MUST be treated as unverifiable and the Capsule rejected by importing gateways that do not implement the named suite.

## 7. Optional Anchoring Registry

Anchoring commits a Capsule's `merkle_root` to a public substrate. Anchoring is OPTIONAL; the canonical `merkle_root` is sufficient for content-addressed verification without anchoring.

v0.1 defines one anchor format; additional formats MAY be registered by extension.

### 7.1 `caap-btc-opreturn-v1`

A 38-byte Bitcoin `OP_RETURN` payload:

```
| 4 bytes | 1 byte  | 1 byte      | 32 bytes        |
| "CAAP"  | version | commit_type | sha256_root     |
```

- `version` = `0x01` for this revision.
- `commit_type` = `0x01` for "capsule merkle root".
- `sha256_root` is the 32-byte binary form of the manifest's `merkle_root`.

Verifiers MUST treat Bitcoin reorg semantics as the finality boundary; six confirmations on mainnet is RECOMMENDED before treating an anchor as canonical.

### 7.2 Future-registered anchors

The registry MAY be extended with at least:

- `eth-event-log-v1` — an EVM contract event whose indexed topic carries the Merkle root.
- `ipfs-cidv1-raw` — an IPFS CIDv1 over the manifest bytes.
- `arweave-tx-v1` — an Arweave transaction id over the manifest bytes.

This spec does not define those formats; they are listed to indicate intended registry shape.

## 8. Security Considerations

**Capsule confidentiality.** Capsule payload files contain ciphertext, with decryption keys held by the subject (or the subject's controller) and never by the importing gateway. A capsule in transit reveals only its manifest (record IDs, hashes, scope/type metadata, Merkle root) and ciphertext; it MUST NOT reveal plaintext memory.

**Owner-signature replay across capsules.** Capsule manifests include `created_at`. Importing gateways SHOULD treat manifests older than a configured horizon as suspect. Implementors SHOULD include a per-export nonce in the canonical manifest (as an `x_nonce` field or future-registered field) to make signed manifests single-use.

**Anchor finality.** Implementors that anchor Merkle roots to a public chain assume that chain's reorg and finality semantics. For Bitcoin `OP_RETURN` anchoring at six or more confirmations on mainnet, finality is sufficient for canonical memory state.

**Metadata side channels.** The manifest's `record_index` and per-record metadata, even without plaintext, reveal patterns of agent activity. Implementors SHOULD document the metadata exposure and offer an option to elide non-essential metadata at export when the receiving body does not require it.

**Suite downgrade.** A verifier honoring multiple signature suites MUST NOT silently accept a suite weaker than the one a previous manifest of the same subject used. Verifiers SHOULD record the strongest suite previously seen per subject and refuse downgrades absent explicit operator action.

**Cross-method controller substitution.** A Capsule's `controllers` array may list controllers under different `method`s (e.g. `eth-address` and `did:btc` keys belonging to the same secp256k1 keypair). Verifiers MUST NOT assume cross-method equivalence; each controller is verified strictly under its named method.

## 9. Interoperability Notes (informative)

### 9.1 Use with ERC-8264

An ERC-8264 implementation MAY return a CAAP-Capsule from `exportMemory(subject)`. The Capsule's `subject_id_method` SHOULD be `eth-address` matching the ERC-8264 subject. The Capsule's `signature_suite` SHOULD be `eip-191`.

### 9.2 Use with ERC-8269

ERC-8269 (Body Lease + Credential Broker) defines the lease and credential surfaces on top of ERC-8264. ERC-8269's Credential Broker rule applies to any memory export, including a CAAP-Capsule: implementors MUST NOT embed raw credentials in Capsule payloads.

### 9.3 Use with `did:btc` agents

A Bitcoin-rooted agent identifier MAY be carried as `subject_id_method: did:btc` and signed under `bip-322-legacy`. Cross-anchoring of the same Capsule to both Bitcoin (via `caap-btc-opreturn-v1`) and an EVM event log is permitted; finality of each anchor is computed independently.

## 10. Reference Implementation

A CC0 reference implementation is at <https://github.com/clavote-boop/rmem-gateway>:

- `rmem-gateway.py` — Capsule export (`exportMemory`) under `eip-191`.
- `rmem-migrate.py` — Capsule freeze / verify-capsule / mount with re-encryption.
- `rmem-anchor.py` — `caap-btc-opreturn-v1` anchoring on Bitcoin (mutinynet verified, mainnet via Knots).
- A live Capsule Merkle root anchor (`224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a` on mutinynet) verifies the on-chain commitment path end-to-end.

## 11. Versioning

`capsule_version` is the on-the-wire format version. This document specifies `capsule_version: "1"`. Future revisions of this spec that break wire compatibility MUST increment the major version.

The signature-suite registry (§6) and anchor registry (§7) are extensible without bumping `capsule_version`; additions are backwards-compatible at the wire level. A verifier that does not implement a referenced suite or anchor MUST reject the Capsule rather than silently accept it.

## 12. Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
