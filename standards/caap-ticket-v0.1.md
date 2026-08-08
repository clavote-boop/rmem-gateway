# CAAP-TICKET v0.1 — Dead-Man Capability Layer for Leased Bodies

**Status:** Draft v0.1
**Editors:** Clavote Research (`@clavote-boop`)
**License:** CC0 — public domain dedication.
**Composes with:** ERC-8269 (Body Lease and Credential Broker), CAAP-Capsule v0.1, CAAP-ROBOTID v1.1, CAAP-LSC (brief §4)
**Canonical home:** this repository, `standards/`

## 1. Purpose and position

A **DeadManTicket** is a short-lived, sequence-numbered, hardware-bound capability that keeps a leased body *armed*. It sits between the ERC-8269 Body Lease (long-lived eligibility) and the Local Safety Controller (per-action physical enforcement). The layers deliberately have different jobs:

| Layer | Authority |
|---|---|
| ERC-8269 Body Lease | Long-lived identity-to-body authorization (eligibility) |
| Settlement contract | Lease status, collateral, gateway authorization, disputes |
| **DeadManTicket (this spec)** | Short-lived permission to remain armed |
| Safety envelope | Maximum locally permissible behavior |
| LSC | Final decision on every physical action |

A ticket can keep a body armed. It **cannot** order motion, expand the safety envelope, or override the LSC. The central invariant of the whole layer:

> **Network availability may reduce liveness, but it must never expand physical authority.**

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in RFC 2119 and RFC 8174.

## 2. Wire format

### 2.1 Encoding

Tickets are encoded as **deterministic CBOR** per RFC 8949 §4.2.1 (preferred serialization, definite lengths only, map keys sorted) and signed inside a **`COSE_Sign1`** envelope per RFC 9052 §4.2. Integer map labels keep the encoding compact and unambiguous for constrained decoders. The lease itself remains canonical JSON with EIP-712/EIP-191 signatures — the lease is chain- and human-facing; the ticket is machine-to-machine.

### 2.2 Schema (CDDL, closed map)

```cddl
dead-man-ticket = {
   0: uint,             ; version = 1
   1: bstr .size 32,    ; lease_id       keccak256(utf8(lease.lease_id)) — lifecycle identity
   2: bstr .size 32,    ; lease_digest   keccak256(RFC 8785 canonical lease JSON) — revision-exact content
   3: bstr .size 32,    ; subject_id_hash
   4: bstr .size 32,    ; body_attestation_key_hash   (enrolled BAK, CAAP-WIPE §2.1)
   5: bstr .size 32,    ; attestation_digest   hash of the handshake attestation report
   6: uint,             ; boot_counter         body TEE boot-session counter
   7: bstr .size 32,    ; challenge_hash       hash of the LSC's fresh RNG challenge
   8: uint,             ; chain_id
   9: bstr .size 20,    ; settlement_contract
  10: bstr .size 32,    ; settlement_block_hash    finalized block the gateway observed
  11: uint,             ; settlement_block_number
  12: uint,             ; revocation_epoch
  13: uint,             ; gateway_set_epoch
  14: uint,             ; ticket_sequence      strictly monotonic per lease
  15: bstr .size 32,    ; previous_ticket_hash (zero-filled for sequence 1)
  16: uint,             ; issued_at            unix seconds, issuer clock
  17: uint,             ; not_before
  18: uint,             ; expires_at
  19: uint,             ; maximum_runtime_ms   monotonic-clock lifetime bound
  20: uint,             ; capability_bitmap    over the lease's declared capability table
  21: uint,             ; consequence_ceiling  0..3 (C0..C3); LSC classes above this are refused
  22: bstr .size 32,    ; safety_envelope_digest
  23: bstr .size 32,    ; minimal_risk_policy_digest
  24: ? [* bstr .size 32] ; cosign_grant_digests  owner-signed C3 grant objects, ticket-scoped
}
```

`lease_id` and `lease_digest` are deliberately distinct: the former joins settlement, wipe, and bond state across the lease's lifecycle; the latter pins the exact signed revision the ticket was issued under. Verifiers MUST check both — a ticket whose `lease_digest` does not match the highest-revision lease known for its `lease_id` MUST be rejected.

The map is **closed**: decoders MUST reject unknown keys. Schema changes require a `version` bump. Any COSE protected-header extension parameters MUST be marked critical (`crit`, RFC 9052 §3.1) so unrecognized extensions are a hard failure, never a silent pass. Because every context-binding field (lease, body, boot session, chain, epochs) is carried in the signed payload itself, `external_aad` MAY be left empty; implementations that populate it MUST document what the verifier supplies.

### 2.3 Decoder rejection rules (normative)

A verifier MUST reject a ticket exhibiting any of:

- non-deterministic encoding (non-preferred integer/length forms), indefinite-length items, or CBOR tags;
- duplicate map keys, unknown keys, or missing required keys;
- floating-point values, simple values, NaNs, or any implicit unit conversion;
- `ticket_sequence` ≤ the highest sequence already observed for the lease, or `previous_ticket_hash` not matching that ticket's hash;
- `revocation_epoch` or `gateway_set_epoch` below the verifier's current known epochs;
- `boot_counter` ≠ the body's current boot session, or `challenge_hash` not matching the challenge issued this session;
- any mismatch of lease, body, subject, chain, or envelope identifiers against local state.

**Physical quantities MUST be fixed-point integers with schema-defined SI units** (e.g. millimetres per second, millinewtons). Floats are invalid in ticket fields; RFC 8949's own guidance on cross-language float ambiguity is the reason.

## 3. Issuance handshake

1. The LSC generates a fresh challenge from its hardware RNG.
2. The body returns an attestation report: TEE attestation, hardware identity (BAK), firmware measurement, boot counter, secure-clock state, and current compiled-envelope digest.
3. The gateway checks **finalized** settlement state at a specific block: lease `ACTIVE`, current `revocation_epoch` and `gateway_set_epoch`, firmware measurement authorized (Safety Kernel Registry), collateral posted.
4. The gateway issues a ticket bound to that exact body, boot session, challenge, and settlement block.
5. The LSC starts a secure monotonic countdown (`maximum_runtime_ms`).
6. Renewal occurs before expiry (RECOMMENDED at ≤ half TTL); failure to renew initiates the lease's certified **minimal-risk action** (the digest in field 22), after which the safe-state rule applies.

Consequences: a captured ticket cannot arm another body (BAK + challenge binding), cannot survive a reboot (boot counter), cannot be replayed (sequence + hash chain), and cannot be issued against stale chain state without that being attributable (settlement block binding).

## 4. Expiry semantics — dual clock

Wall-clock expiry alone is insufficient: clocks drift and can be rolled back. A ticket carries both an issuer-time interval (`not_before` … `expires_at`) and a local monotonic lifetime (`maximum_runtime_ms`), measured by a rollback-resistant monotonic clock (TEE counter class, per CAAP-WIPE §2.1). **The LSC enforces the stricter of the two.** A body that cannot establish clock integrity within its declared tolerance MUST treat its ticket as expired.

The unavoidable safety bound, stated normatively:

```
T_revocation ≤ T_gateway_observation + T_ticket_remaining + T_minimal_risk_transition
```

This bound begins only once the gateway *observes* an authoritative revocation; from transaction submission, blockchain inclusion and finality remain unbounded and MUST NOT be relied upon for physical safety timing.

The fundamental trade — short tickets improve revocation latency but increase exposure to network denial of service; long tickets improve degraded-network availability but enlarge the compromised-body window — is resolved per consequence class, not globally. The lease's `ticket_policy` MUST declare a maximum TTL per class (e.g. seconds for heavy manipulation, minutes for a stationary sensing platform), and a ticket's TTL MUST NOT exceed the limit for its `consequence_ceiling`.

## 5. Minimal on-chain extension

The settlement contract manages coarse lease state only — **never individual tickets**:

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.20;

interface IBodyLeaseSettlement {
    enum Status { NONE, ACTIVE, REVOKED, EXPIRED, DISPUTED }

    event LeaseCommitted(bytes32 indexed leaseId, bytes32 leaseDigest,
                         bytes32 gatewaySetRoot, bytes32 envelopeDigest,
                         uint64 revocationEpoch);
    event LeaseRevoked(bytes32 indexed leaseId, uint64 newRevocationEpoch,
                       bytes32 reasonDigest);
    event GatewaySetRotated(bytes32 indexed leaseId, uint64 newGatewaySetEpoch,
                            bytes32 newGatewaySetRoot);
    event EvidenceRootCommitted(bytes32 indexed leaseId, uint64 batchSequence,
                                bytes32 evidenceRoot);

    function leaseState(bytes32 leaseId) external view
        returns (Status status, bytes32 leaseDigest, bytes32 gatewaySetRoot,
                 bytes32 envelopeDigest, uint64 revocationEpoch, uint64 gatewaySetEpoch);

    function revoke(bytes32 leaseId, bytes calldata authorization) external;
    function rotateGatewaySet(bytes32 leaseId, bytes32 newRoot,
                              bytes calldata authorization) external;
}
```

Required properties (invariants, not suggestions):

- `revocationEpoch` and `gatewaySetEpoch` only increase.
- **Revocation is terminal per `leaseId`**: a revoked lease cannot be reactivated; every replacement lease receives a new identifier.
- Ticket issuance is off-chain and produces no transaction; only periodic evidence roots and disputes reach the chain.
- Safety-envelope details remain off-chain; the contract stores only their immutable digest.
- Collateral/settlement modules (LeaseBond) reference `leaseId` without being embedded in this contract.

Lease-controller `authorization` SHOULD use EIP-712 typed data, verified via `ecrecover` for EOAs and ERC-1271 for smart accounts. Note that EIP-712 explicitly provides **no replay protection** — lease IDs, epochs, and nonces are enforced by this contract's invariants and the ERC-8269 lease schema, never assumed from the signature scheme. ERC-4337 MAY transport settlement operations, but robotic spending and safety limits belong in account modules and the escrow contract, not here.

`EvidenceRootCommitted` is the chain-side anchoring hook for CAAP-TELEMETRY receipt batches (`eth-event-log-v1` class): receipt anchoring is asynchronous and its failure MUST NOT affect motion — evidence queues and commits when connectivity allows.

## 6. Gateway and mesh rules

The mesh is a **transport substrate, not an authority system**. A peer MAY: relay an unchanged signed ticket; relay revocations and chain proofs; exchange witness challenges; cache evidence commitments. A peer MUST NOT: extend a ticket's expiry; synthesize a renewal; vote a revoked lease back into existence; modify an envelope; arm a body because a mesh quorum agrees. A Sybil-controlled local mesh must never become a substitute control plane.

For high-consequence bodies, ticket policy MAY require **threshold gateway signatures**; lower-consequence bodies MAY accept one signer proven against the on-chain `gatewaySetRoot`. Gateway equivocation — two conflicting tickets sharing lease, body, epoch, and sequence — is self-evident cryptographic misbehavior and slashable through the collateral layer.

Opportunistic **proximity attestations** (bodies cross-signing each other's telemetry chunk roots in passing) are a *witness* function and are specified in CAAP-TELEMETRY's witness protocol, deliberately outside the ticket path.

## 7. Cryptographic domains

Different keys for different purposes; no key crosses domains:

| Key | Purpose |
|---|---|
| Lease-controller key | Creates and revokes the long-lived Body Lease (EIP-712/ERC-1271) |
| Gateway ticket key | Issues short-lived dead-man capabilities (`COSE_Sign1`, ES256) |
| Body attestation key | Proves hardware and boot identity (enrolled per CAAP-WIPE §2.1) |
| LSC execution key | Signs ActionReceipts (CAAP-LSC §4.3) |
| Witness key | Signs independently observed telemetry |

P-256 (ES256) is RECOMMENDED for the hardware-backed gateway, TEE, and LSC keys: EIP-7951 supplies native EVM verification, so hardware-origin evidence is directly checkable on-chain during disputes.

## 8. Failure behavior (normative table)

| Failure | Required result |
|---|---|
| Ethereum unavailable | Continue only until current ticket expires |
| 5G jammed but mesh works | Mesh relays valid tickets; authority unchanged |
| All networking lost | Execute minimal-risk policy at expiry |
| Gateway compromised | Renewal can continue until lease expiry within the certified envelope, absent an independent revocation source; threshold issuance or body-verified chain proofs narrow the window to TTL |
| Gateway key revoked | Old epoch rejected immediately when learned, otherwise at ticket expiry |
| Ticket replayed after reboot | Boot-counter mismatch → reject |
| Body cloned | Attestation-key or challenge mismatch → reject |
| Clock rollback | Secure monotonic lifetime still expires |
| Receipt anchoring fails | Motion unaffected; evidence queues asynchronously |
| Lease expires during a lift | Controlled hold/lower per certified minimal-risk policy — not unconditional torque loss |

## 9. Security considerations

- **Issuer compromise** is the model's chokepoint, stated honestly: with a single compromised issuer, renewal continues until the lease's own expiry — attribution and slashing after an observable on-chain revocation are deterrence and recourse, not enforcement, because the body trusts issuer signatures. The mitigations that actually shorten the window: **threshold issuance** (a compromised minority cannot renew alone), and **body-side verification of relayed chain proofs** of the current revocation epoch against the epoch bound into each ticket, rejecting stale-epoch tickets. High-consequence deployments SHOULD require one or both, plus short lease expiries.
- **The ticket cannot be a motion command.** Verifiers MUST treat any attempt to encode actuation targets in ticket fields as schema violation; motion flows only through the CAAP-LSC `IntentPayload` path.
- **Downgrade:** verifiers MUST NOT accept `version` values below the highest they have processed for a given lease.
- **Denial of service is the accepted cost.** Every failure row above degrades toward the minimal-risk action and safe state. This is by construction: the adversary who controls the network can silence a body, never seize it.

## 10. Copyright

Copyright and related rights waived via CC0 1.0 Universal.
