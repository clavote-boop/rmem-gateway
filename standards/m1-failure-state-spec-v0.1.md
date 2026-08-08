# M1 Failure-State Specification v0.1

**Modules:** CAAP-WIPE + LeaseBond  
**Status:** Normative design draft preceding Solidity interfaces  
**License:** CC0-1.0  
**Date:** 2026-08-08

## 1. Scope

This document specifies failure classification and economic settlement for cryptographic erasure at the end of an ERC-8269 Body Lease. It does not claim that a protocol can prove the physical absence of every plaintext copy. It governs a narrower property:

> A Capsule was mounted through an attested sealed path, its Lease Data Key (`LDK`) was non-exportable, and the authorized decryption path was subsequently disabled by key destruction or qualified physical destruction.

CAAP-WIPE produces evidence about that property. LeaseBond prices failure to produce or preserve that evidence.

## 2. Required separation of concerns

Implementations MUST NOT represent every missing wipe proof as `WipeDefault` or treat it as proof of deliberate data retention. They MUST track at least three independent dimensions:

1. **Lifecycle state:** what obligation is currently due.
2. **Evidence state:** what can be cryptographically or physically established.
3. **Resolution:** who bears the economic loss and whether a protocol violation occurred.

### 2.1 Lifecycle state

```solidity
enum WipeCaseState {
    None,
    Bonded,
    Active,
    ExitPending,
    SafeStated,
    WipeDue,
    EvidenceSubmitted,
    Disputed,
    Resolved
}
```

### 2.2 Evidence state

```solidity
enum EvidenceState {
    None,
    ValidWipeReceipt,
    ValidDestructionEvidence,
    ProofUnavailable,
    CorrectableInvalid,
    Contradictory,
    FraudEvidence
}
```

- `ValidWipeReceipt` means an accepted verifier found that an enrolled attestation key signed a statement consistent with the corresponding mount receipt and with a strictly increasing rollback-protected counter.
- `ValidDestructionEvidence` means an approved physical-destruction verifier concluded that recovery of the relevant key material is infeasible under the applicable policy.
- `ProofUnavailable` means neither erasure nor retention has been established.
- `CorrectableInvalid` means a submission is malformed, stale, incomplete, or signed under an unsupported but non-fraudulent profile. It MUST receive a cure period.
- `Contradictory` means accepted evidence cannot all be true, including counter rollback, post-wipe use of the same LDK lineage, or attestation-key equivocation.
- `FraudEvidence` requires affirmative evidence of fabrication, not merely a failed signature check on caller-supplied bytes.

### 2.3 Resolution code

```solidity
enum ResolutionCode {
    None,
    TimelyWipe,
    LateWipeNoFault,
    LateWipeOperatorFault,
    QualifiedCasualty,
    UnprovenLoss,
    MountInvariantBreach,
    DeliberateRetention,
    AttestationEquivocation,
    OperatorNonCooperation,
    VendorOrVerifierFailure,
    ChallengerAbuse,
    ProtocolFailure
}
```

A resolution MUST identify the accepted evidence root, appraisal-policy version, resolver, and payout vector. A single reputation label such as `defaulted` is insufficient.

The authoritative machine-readable declarations of `ResolutionCode`, `ClaimKind`, and `Tranche` are those in `interfaces/CaapM1Types.sol`; enums excerpted in this document are illustrative and yield to that file on any divergence.


## 3. Evidence created before failure

A destruction case is only adjudicable if the protocol manufactures evidence before the incident. The following records are therefore mandatory.

### 3.1 MountReceipt

The TEE MUST emit a `MountReceipt` before Capsule plaintext becomes available:

```text
MountReceipt {
    version
    lease_id
    lease_hash
    lease_revision
    body_id
    body_attestation_key_hash
    capsule_root
    ldk_handle_hash
    key_policy_hash
    firmware_measurement
    boot_counter
    mount_counter
    mounted_at
    ticket_policy_hash
}
```

The applicable appraisal policy MUST establish that:

- the LDK was generated inside the measured boundary;
- the LDK was marked non-exportable;
- plaintext output paths were restricted to the measured workload;
- rollback protection covered the key state and counter;
- debug, diagnostic, crash-dump, and swap paths could not export plaintext or the LDK.

If a valid `MountReceipt` is absent, the lease MUST NOT enter `Active`. Discovery after activation is `MountInvariantBreach`, not merely `ProofUnavailable`.

### 3.2 KeyCustodyHeartbeat

For consequence classes whose policy requires continuous assurance, the TEE SHOULD periodically emit a compact heartbeat binding:

```text
KeyCustodyHeartbeat {
    lease_id
    body_id
    capsule_root
    firmware_measurement
    boot_counter
    current_counter
    prior_heartbeat_hash
    observed_at
}
```

Heartbeats MUST NOT expose the LDK. They narrow the unknown interval before a casualty and provide evidence that the sealed path remained intact.

### 3.3 WipeReceipt

Key destruction MUST occur from the local lease-exit state machine. It MUST NOT wait for an on-chain challenge. At destruction time, the attestation environment MUST emit:

```text
WipeReceipt {
    version
    lease_id
    lease_hash
    lease_revision
    body_id
    capsule_root
    mount_receipt_hash
    ldk_handle_hash
    safe_state_receipt_hash
    firmware_measurement
    boot_counter
    pre_wipe_counter
    post_wipe_counter
    wipe_method
    wiped_at
}
```

The receipt MUST be signed by the enrolled body attestation key and MUST be persisted outside the body as soon as connectivity permits. Mesh peers MAY countersign or store the receipt, but cannot create it.

Requiring a fresh post-loss challenge as the only acceptable proof is forbidden: a body can wipe correctly and then be destroyed before answering. A challenge MAY request stronger confirmation from a surviving body, but the event-bound `WipeReceipt` remains independently admissible.

## 4. Timing model

Expiry of an Operating Ticket begins the physical exit sequence; it does not justify an unsafe power cut.

Let:

- `t_auth_end` be the time at which operating authority expires;
- `d_mrc` be the certified maximum duration of the Minimal Risk Condition trajectory;
- `d_wipe` be the maximum key-destruction interval after safe state;
- `d_submit` be the maximum evidence-publication delay.

The implementation MUST enforce:

```text
safe_state_due = t_auth_end + d_mrc
wipe_due       = min(actual_safe_state_at, safe_state_due) + d_wipe
evidence_due   = wipe_due + d_submit
```

Failure to produce `SafeStateReceipt` by `safe_state_due` opens a distinct safety case. It MUST NOT indefinitely postpone the wipe deadline.

Chain or verifier unavailability MAY toll `d_submit`, but MUST NOT postpone local safe-state or key-destruction behavior. Tolling requires objective outage evidence and is capped by policy.

## 5. Catastrophic physical loss

A destroyed body cannot necessarily sign after the incident. This is an evidence failure, not automatically an erasure failure.

### 5.1 LossReport

The operator MAY open a casualty case with:

```text
LossReport {
    lease_id
    body_id
    incident_window
    casualty_class
    last_mount_receipt_hash
    last_heartbeat_hash
    telemetry_root
    witness_root
    rf_health_root
    salvage_or_nonrecovery_report_hash
    insurance_claim_hash
    reporter
}
```

### 5.2 Qualified casualty requirements

`QualifiedCasualty` requires all applicable policy predicates, including:

1. A valid pre-incident `MountReceipt`.
2. A last-known-good heartbeat within the policy window, if heartbeats were required.
3. Timely loss reporting.
4. Independent evidence of the incident or destruction. The operator cannot be the sole witness for C2/C3 leases.
5. No accepted signature, decrypt operation, heartbeat, or ticket request from the same body session after the claimed destruction time.
6. Salvage chain-of-custody evidence when remnants are recoverable, or qualified non-recovery evidence when they are not.
7. No evidence that the LDK or plaintext left the sealed boundary before loss.

Physical destruction MAY satisfy the sanitization policy if an approved verifier concludes that key recovery is infeasible. Destruction of hardware alone does not establish that conclusion; the pre-loss key-custody evidence remains load-bearing.

### 5.3 Volcano outcome

For a body credibly destroyed in a volcano:

- credentials and tickets expire normally;
- the case enters `Disputed` with `EvidenceState.ProofUnavailable` unless qualified destruction evidence is accepted;
- no hygiene or malicious-retention reputation fault is posted merely because a TEE wipe signature is absent;
- an evidence-availability reserve MAY pay the data subject or lease controller for residual uncertainty;
- the performance bond is released, partially charged, or paid by casualty insurance according to the agreed casualty policy;
- affirmative evidence of mount failure, key export, fabricated loss, or post-loss key use overrides the casualty treatment.

## 6. Economic tranches

LeaseBond SHOULD separate funds by purpose rather than treat collateral as a single slashable balance:

```solidity
struct BondTranches {
    uint128 performanceBond;
    uint128 evidenceReserve;
    uint128 casualtyReserve;
    uint128 challengeBond;
}
```

- **Performance bond:** backs compliance with sealed mount, safe state, wipe, cooperation, and non-equivocation duties.
- **Evidence reserve:** funds a predetermined no-fault payment when the required conclusion cannot be proven.
- **Casualty reserve or insurance:** absorbs covered destruction or unrecoverable loss.
- **Challenge bond:** deters frivolous challenges and fabricated evidence submissions by third parties.

This separation prevents a no-fault hardware casualty from receiving the same economic and reputational treatment as deliberate key retention while still pricing the residual data risk.

## 7. Settlement matrix

| Condition | Evidence result | Resolution | Default settlement |
|---|---|---|---|
| Timely valid wipe receipt | Valid wipe | `TimelyWipe` | Release performance and unused reserves |
| Valid wipe submitted late due to proven outage | Valid wipe | `LateWipeNoFault` | Release; charge only objectively incurred case costs |
| Valid wipe submitted late due to operator delay | Valid wipe | `LateWipeOperatorFault` | Limited performance penalty; no retention allegation |
| Credible destruction satisfying casualty policy | Valid destruction | `QualifiedCasualty` | Insurance/casualty reserve; no hygiene fault |
| Credible loss but erasure remains unprovable | Proof unavailable | `UnprovenLoss` | Evidence-reserve payout; adjudicated performance allocation |
| No evidence and no cooperation after cure period | Proof unavailable | `OperatorNonCooperation` | Full or policy-capped performance slash |
| Missing or false sealed-mount invariant | Contradictory/fraud | `MountInvariantBreach` | Full performance slash plus claim compensation |
| LDK use accepted after a valid wipe receipt | Contradictory | `DeliberateRetention` | Full slash and high-severity reputation record |
| Rollback or mutually inconsistent signed counters | Contradictory | `AttestationEquivocation` | Full slash, body quarantine, verifier review |
| Verifier unavailable or vendor collateral withdrawn after compliant mount | Proof unavailable | `VendorOrVerifierFailure` | Deadline toll or insurance allocation; no automatic operator fault |
| Frivolous/replayed challenge | None | `ChallengerAbuse` | Challenger-bond slash |

An invalid proof submitted by an arbitrary caller MUST NOT slash the operator. Only an authenticated operator submission can start a cure clock, and only affirmative fraud or unresolved noncooperation can justify the corresponding penalty.

## 8. Contract-facing transition rules

The eventual Solidity interfaces SHOULD expose distinct events:

```solidity
event LeaseExitStarted(bytes32 indexed leaseId, uint64 authorityEndedAt);
event SafeStateReported(bytes32 indexed leaseId, bytes32 receiptHash);
event WipeEvidenceSubmitted(bytes32 indexed leaseId, bytes32 evidenceHash);
event WipeEvidenceAccepted(bytes32 indexed leaseId, bytes32 resultHash);
event WipeProofUnavailable(bytes32 indexed leaseId);
event CasualtyReported(bytes32 indexed leaseId, bytes32 reportHash);
event WipeCaseDisputed(bytes32 indexed leaseId, bytes32 caseId);
event WipeCaseResolved(
    bytes32 indexed leaseId,
    ResolutionCode code,
    bytes32 evidenceRoot,
    bytes32 payoutRoot
);
```

`WipeProofUnavailable` is a procedural event. It MUST NOT itself transfer the full performance bond, post a malicious-retention reputation entry, or claim that the LDK remains recoverable.

Only the following outcomes are suitable for automatic final settlement:

- cryptographic acceptance of a timely wipe receipt;
- expiry of an undisputed cure or challenge window where the lease explicitly defines the resulting evidence-reserve payment;
- objective challenger-bond rules such as replay or wrong-lease submissions.

Physical causation, negligence, qualified destruction, and fraud generally require an agreed resolver or arbitration module. The contract stores commitments and executes the resolution; it does not infer physical truth from silence.

## 9. Attestation appraisal

CAAP-WIPE SHOULD follow the RATS separation between:

- **Evidence:** vendor-specific quote, EAT, TPM quote, measurement log, or destruction report;
- **Attestation Result:** an appraisal produced by an approved verifier;
- **Relying Party decision:** LeaseBond applying the lease's versioned policy to that result.

Verifier unavailability, negative appraisal, and relying-party policy rejection are different failure modes and MUST remain distinguishable.

The appraisal result MUST bind at least:

```text
evidence_hash
verifier_id
verifier_version
appraisal_policy_hash
reference_value_set_hash
body_id
lease_id
result_code
issued_at
expires_at
```

## 10. Security requirements

1. **No proof-by-timeout:** silence proves nonproduction of evidence, not survival of a key.
2. **No challenge-triggered wipe:** a disconnected or destroyed body must not retain the LDK merely because a chain challenge was never delivered.
3. **No LDK escrow:** casualty handling MUST NOT create a backup of the LDK; doing so invalidates the deletion guarantee.
4. **No self-witnessed C2/C3 casualty:** independent corroboration or insurance assessment is required.
5. **No permanent deadline tolling:** verifier and chain outages receive bounded extensions only.
6. **No stale appraisal policy:** every resolution binds the verifier, reference values, revocation collateral, and policy version used.
7. **No reputation collapse:** `QualifiedCasualty`, `UnprovenLoss`, `MountInvariantBreach`, and `DeliberateRetention` MUST produce different machine-readable outcomes.
8. **No automatic blame from malformed evidence:** the submitter, signature domain, and cure history must be established first.

## 11. Required conformance scenarios

An implementation MUST test at least:

1. Timely wipe and release.
2. Wipe performed offline, receipt submitted after connectivity returns.
3. Wipe performed, then body destroyed before a fresh challenge.
4. Body destroyed before wipe with qualified casualty evidence.
5. Body reported destroyed, followed by a valid post-loss body signature.
6. Counter rollback and two inconsistent wipe receipts.
7. Missing mount receipt.
8. Verifier outage during the submission window.
9. Vendor reference values revoked before mount and after mount.
10. Malformed evidence submitted by a third-party griefer.
11. Operator refuses evidence disclosure after cure period.
12. Chain outage while the local exit and wipe timers continue.

## 12. Standards basis

- NIST SP 800-88 Revision 2 treats sanitization as rendering access to target data infeasible for a defined level of effort and includes cryptographic erase within a risk-based media-sanitization program.
- RFC 9334 defines the RATS roles and distinguishes Evidence, Attestation Results, appraisal policies, relying-party decisions, and verifier unavailability.
- RFC 9711 defines EAT as a CBOR- or JSON-encoded attested claims set for devices and software.
- EIP-7951 provides native EVM verification of P-256 signatures commonly produced by secure hardware.

