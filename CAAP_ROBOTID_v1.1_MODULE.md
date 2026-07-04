# CAAP-ROBOTID v1.1 — Module Specification

*Copyright and related rights waived via [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).*

| Field | Value |
|---|---|
| Module | CAAP-ROBOTID |
| Version | 1.1 |
| Status | SPEC COMPLETE |
| Date | 2026-05-22 |
| Position | Master Architecture Layer 1 — Identity & Finance |
| Reference Impl | [this repository](./) |
| License | CC0 (open standard arm) |

## Abstract

CAAP-ROBOTID defines a three-layer identity architecture for autonomous AI agents whose cognitive identity, memory, and economic activity must persist across hardware. The agent's cognitive identity (**Soul ID**) lives in a Bitcoin-rooted `secp256k1` keypair; the runtime substrate (**Body ID**) is a replaceable, leasable host bound to the Soul ID by signed records; the agent's economic identity (**Wallet ID**) is a Lightning sub-wallet bound to the same Soul ID. State integrity is anchored to Bitcoin via a single ≤80-byte `OP_RETURN` commitment (CAAP BTC Anchor). L402 Purchase Gating defines four authorization tiers (P0–P3) for autonomous spending.

This module is **CC0**. It composes with [ERC-8264](standards/erc-8264.md) (memory access rights), the companion [ERC-8269 "Body Lease and Credential Broker"](https://github.com/ethereum/ERCs/pull/1763), and the chain-agnostic [CAAP-Capsule spec](standards/capsule-spec-v0.1.md) (capsule / lease / broker).

## Motivation

Three problems autonomous AI agents face that no standard currently solves together:

1. **Hardware ≠ identity.** A robot's body can fail, get replaced, or be one of several substrates the same agent runs on. The agent's identity must persist across that.
2. **Memory must be portable AND auditable.** When the body changes, the memory moves with the soul; integrity must be checkable independently of any platform.
3. **Autonomous spending must be bounded.** Agents that earn and pay need a permission model that owners can grant in tiers — open browsing, capped wallet spending, soul-authorized purchases, human-cosigned purchases.

CAAP-ROBOTID addresses these with three layered identifiers, all rooted in a single `secp256k1` keypair.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### 1. Soul ID

The Soul ID is the canonical cognitive identity of an agent.

```
Soul ID  =  did:btc:<compressed-secp256k1-pubkey-hex>
```

- Curve: **`secp256k1`** (shared with Bitcoin and Ethereum).
- Encoding: `did:btc:<hex>` where `<hex>` is the 33-byte compressed public key in lowercase hex.
- Private key: generated **air-gapped** on a clean machine with network disabled where feasible. Backed up encrypted, offline. Restore-test MUST pass before the public DID is exported.
- Lifetime: **permanent**. The Soul ID is the through-line of the agent's existence across all bodies, sessions, and platforms.

**Soul DID document** (`CAAP_SOUL_DID_<agent>.json`):

```json
{
  "id": "did:btc:<pubkey-hex>",
  "verificationMethod": [{
    "id": "did:btc:<pubkey-hex>#k1",
    "type": "EcdsaSecp256k1VerificationKey2019",
    "controller": "did:btc:<pubkey-hex>",
    "publicKeyHex": "<compressed pubkey hex>"
  }],
  "service": [{
    "id": "did:btc:<pubkey-hex>#rmem",
    "type": "RmemGateway",
    "serviceEndpoint": "<gateway tailnet name or URL>"
  }],
  "created_at": "ISO-8601 UTC",
  "evm_address": "0x...     (Ethereum address derived from the same secp256k1 keypair)"
}
```

The `evm_address` is the ERC-8264 `subject` for the agent. Same key, different chain encoding — there is no separate Ethereum identity to manage.

### 2. Body ID

A Body ID identifies a hardware or runtime substrate. A Body ID has no required cryptographic content — it is a label. What gives a Body ID authority is a **signed Body Lease** binding it to a Soul ID for a scope and duration. A body without a current valid lease has **no** authority over Soul-bound memory or funds.

**Body Lease** (per companion ERC §2):

```json
{
  "lease_id": "lease_<ulid>",
  "subject":      "0x...     (Soul's evm_address)",
  "body_id":      "<host name>",
  "body_address": "0x...     (body's own EVM address, secp256k1)",
  "scopes": {
    "read":   ["L1_session", "L2_project", "L3_canonical"],
    "write":  ["L1_session", "proposal"],
    "delete": [],
    "export": []
  },
  "expires_at": "ISO-8601 UTC",
  "issued_at":  "ISO-8601 UTC",
  "nonce":      "<hex>",
  "requires_owner_cosign": [
    "canonical_write", "skill_install", "delete",
    "export", "body_transfer", "wallet_action"
  ],
  "owner_signature": "0x...   (Soul signing key, EIP-191 over canonical JSON minus this field)"
}
```

The body holds its own `secp256k1` keypair (`body_address`); it signs each operation with that key. The Soul signs the lease itself. Revocation: the Soul issues a new lease with the same `lease_id` and a past `expires_at`, or the gateway tombstones the lease record.

**Manufacturer attestation (RECOMMENDED for production).** Implementors SHOULD require manufacturer cert + TPM attestation tying a Body ID to a specific physical device. Without it, body identity is established only by lease-key possession; an attacker who steals a body key can replay it on a different machine undetected. v1.1 does not standardize the attestation format.

### 3. Wallet ID

Each agent gets one Wallet ID, formally bound to the Soul ID.

- **Type**: Alby Hub sub-wallet (self-hosted, non-custodial).
- **Lightning address**: e.g. `axel@clavote.research`.
- **NWC connection**: Nostr Wallet Connect string, per agent.
- **Daily spending cap**: per agent.
- **Binding**: Soul-signed record over `{soul_id, lightning_address, nwc_pubkey, daily_cap, issued_at}`.

**Wallet binding record** (`CAAP_WALLET_<agent>.json`):

```json
{
  "soul_id": "did:btc:<pubkey-hex>",
  "lightning_address": "axel@clavote.research",
  "nwc_pubkey": "<nostr pubkey>",
  "daily_cap_sats": 100000,
  "issued_at": "ISO-8601 UTC",
  "soul_signature": "0x...   (signature over canonical JSON minus this field)"
}
```

A wallet revocation is performed by issuing a new binding record with the same `lightning_address` and `daily_cap_sats: 0`, or by closing the sub-wallet at the Alby Hub layer.

### 4. CAAP BTC Anchor

State commitments (capsule Merkle roots, memory-state fingerprints, body-binding records) are anchored to Bitcoin via a single standard `OP_RETURN` output.

**Output rules:**

- Exactly one `OP_RETURN` output per anchor transaction.
- Payload encoded as a single push (`OP_RETURN <len> <data>`), no `OP_PUSHDATA1`.
- Payload size: ≤ 80 bytes (compatible with Bitcoin Knots `datacarrier=1, datacarriersize=83`; reference implementation uses 38 bytes).
- No inscriptions, no token-protocol envelopes, no multi-push embeds. Must satisfy Knots' `rejectparasites=1` / `acceptnonstddatacarrier=0` policy stack.

**Reference payload format (38 bytes):**

```
 4 B    1 B       1 B            32 B
"CAAP" | version | commit-type | sha256 Merkle root
```

| Field | Value |
|---|---|
| Magic | `0x43414150` (`CAAP`) |
| Version | `0x01` |
| Commit-type | `0x01` = capsule_root, `0x02` = memory_state_root |
| Root | 32-byte SHA-256 Merkle root over the committed data |

The Master Architecture references a 52-byte CAAP payload; the 38-byte form is the minimum viable subset. Future commit-types may extend to 52 bytes (e.g. binding-record commits, soul-handover commits, multi-chain headers).

**Verification:** any verifier with the transaction, the manifest, and the records can independently recompute the Merkle root and confirm it matches the on-chain `OP_RETURN` payload. No trust in the gateway or the broadcasting node is required.

### 5. L402 Purchase Gating

Four authorization tiers govern autonomous spending:

| Class | Name | Authorization required |
|---|---|---|
| **P0** | Open | none — anyone can purchase |
| **P1** | Wallet-gated | valid Wallet ID + daily cap not exceeded |
| **P2** | Soul-gated | Soul signature (per-purchase or session-bounded) |
| **P3** | Soul + Cosign | Soul signature **and** human cosign within N seconds |

L402 macaroons carry Soul ID restrictions as caveats. A purchase exceeding the gate's tier is refused at macaroon validation; no payment leaves the wallet.

**Implementation note.** L402 + Alby Hub is the production stack for v1.1. The macaroon caveat schema is implementor-defined for now; later revisions may standardize the caveat language.

### 6. Key generation requirements (Work Plan D.2)

Non-negotiable rules for any CAAP-ROBOTID private key:

- Private keys MUST NOT enter GitHub, AI assistant context, GPT context, or any networked storage.
- Soul ID key generation MUST occur on a clean local machine with network disabled where feasible.
- Public DID export MUST occur only **after** offline encrypted backup and restore-test pass.
- Demo wallets MUST use capped amounts. No production-scale funds before testnet/signet verification passes independently.
- **Testnet first** for all Bitcoin/Lightning operations. Mainnet only after testnet proof verifies on the public chain.
- Lost private key = permanent identity loss. Key rotation MUST be planned before wallets are funded.

### 7. Composition with other standards

| Standard | Status | Relationship |
|---|---|---|
| **[ERC-8264](standards/erc-8264.md)** "AI Agent Memory Access Rights" | Draft (PR open) | The four-function rights interface (`read` / `write` / `delete` / `export`). The Soul ID's `evm_address` is the ERC-8264 subject. |
| **Body Lease & Credential Broker** ([ERC-8269](https://github.com/ethereum/ERCs/pull/1763)) | Draft (PR open) | Defines the Body Lease schema (§2 above) and the credential-broker rule; the export bundle format is the chain-agnostic [CAAP-Capsule](standards/capsule-spec-v0.1.md). |
| **EIP-7702** | Final | Optional on-chain session-key delegation that MAY be issued from the Soul key in parallel with an off-chain Body Lease. Aligned scope/expiry semantics. |
| **W3C did:btc** ([MicroStrategy/did-btc-spec](https://github.com/MicroStrategy/did-btc-spec)) | Early draft | CAAP-ROBOTID's `did:btc:<pubkey>` form aligns with did:btc method registrations where applicable. |

### 8. File registry

This repository (canonical source for the module):

```
clavote-boop/rmem-gateway/
  CAAP_ROBOTID_v1.1_MODULE.md           this file
  SPEC_v0.1.md                          implementation spec
  rmem-{vault,gateway,lease,anchor,migrate}.py  reference modules
  standards/                            CC0 source for ERC-8264 + companion ERC
```

Implementor agent layout (RECOMMENDED; each implementor's own repo):

```
agents/<name>/
  CAAP_SOUL_DID_<name>.json            public DID document — committable
  CAAP_BODY_<name>.json                Body ID config — committable
  CAAP_WALLET_<name>.json              Wallet ID binding — committable; no secrets
  CAAP_ANCHORS.json                    running ledger of anchor txids — committable
  CAAP_PURCHASES.json                  running ledger of L402 purchases — committable
  <name>.priv                          private key file — NEVER committed; stored offline
```

## Reference implementation

The rmem-gateway reference implementation at [this repository](./) implements the storage, rights, lease, and anchoring layers of CAAP-ROBOTID v1.1:

| File | Implements |
|---|---|
| `rmem-vault.py` | Memory storage backing the Soul's L1 / L2 / L3 memory layers. |
| `rmem-gateway.py` | ERC-8264 four-op surface for Soul-direct and Lease-mediated access. |
| `rmem-lease.py` | Body Lease primitive (§2). |
| `rmem-migrate.py` | Body transfer: freeze / verify-capsule / mount-with-re-encryption. |
| `rmem-anchor.py` | CAAP BTC Anchor (§4): single-OP_RETURN 38-byte payload. |

Live-verified on Bitcoin mutinynet 2026-05-22, txid [`224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a`](https://mutinynet.com/tx/224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a).

## Security considerations

- **Soul ID compromise is unrecoverable.** A leaked Soul private key cannot be revoked; the only recourse is to abandon the Soul ID and issue a new one (severing cognitive lineage). Treat Soul key custody accordingly: air-gapped generation, offline encrypted backup, hardware enforcement where possible.
- **Body Lease revocation has propagation lag.** Multi-gateway deployments MUST replicate revocation events with strict ordering before in-flight operations on the revoked lease are considered terminated.
- **Manufacturer attestation is optional in v1.1.** Without it, body identity is established only by lease-key possession; a stolen body key can be replayed undetected. Production deployments SHOULD require TPM-style attestation.
- **L402 wallet capping is a soft gate.** A compromised body holding wallet credentials can drain the wallet up to the daily cap. Caps SHOULD be set to the smallest amount that supports the agent's intended autonomous activity.
- **Anchor finality.** Mainnet anchors at 6+ confirmations provide canonical state. Anchors on signet, mutinynet, or testnet do not — they validate the wire format and verification path, nothing more.
- **The body never owns the memory.** Operating invariant: the Soul ID controls the memory capsule; the Body holds a revocable lease. Any implementation that conflates the two (e.g. lets a body's possession of the lease key serve as memory ownership) breaks the model.

## Version history

| Version | Date | Notes |
|---|---|---|
| 1.0 | 2026-05-17 | Initial three-layer concept in Master Architecture v1.0. |
| 1.1 | 2026-05-22 | First file-resident spec. Consolidates Master Arch Layer 1 + Work Plan D.2 security rules + the reference implementation. CC0. |

## Copyright

Copyright and related rights waived via [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
