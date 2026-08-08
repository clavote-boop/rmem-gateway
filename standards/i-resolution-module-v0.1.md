# IResolutionModule v0.1

**Status:** Normative draft  
**Interface:** `IResolutionModule.sol`  
**Consumes:** M1 `ClaimKind`, evidence/appraisal commitments, and LeaseBond policy  
**Produces:** final typed `ResolutionCode` and bounded payout vector  
**License:** CC0-1.0

## 1. Purpose

`IResolutionModule` is the adjudication boundary between evidence appraisal and LeaseBond settlement. It defines what a bond must know about a resolver without prescribing one governance mechanism.

A conforming implementation may be a threshold panel, staked optimistic resolver, court-backed adapter, or other policy-approved mechanism. Regardless of mechanism, it MUST expose immutable case inputs, explicit timing and appeal rules, a typed outcome, and a machine-enforceable payout vector.

ERC-8004 Validation Registry records MAY be inputs. ERC-8004 does not define a panel, quorum, stake, appeal, or economic finality; a validation response MUST NOT be treated as a final judgment unless the bond's separately committed resolution policy says how that response participates in decision-making.

## 2. Fixed dimensions

The module MUST keep these dimensions distinct:

- `ClaimKind`: the allegation that opened the case;
- `EvidenceState`: appraisal of submitted material;
- `ResolutionCode`: the economic/fault conclusion;
- `Payout[]`: transfers LeaseBond is authorized to execute;
- reputation result: a separate, policy-derived record.

Silence, malformed third-party input, proof unavailability, contradictory evidence, and affirmative fabrication are different states.

## 3. Immutable policy descriptor

Before collateral is posted, LeaseBond MUST bind:

```text
resolver address
module identifier and semantic version
policyHash
validatorSetRoot
quorumRuleHash
stakeRuleHash
appealRuleHash
timeoutRuleHash
evidenceRuleHash
```

`policyHash` commits the complete, retrievable policy bytes and the descriptor above. The resolver MUST return the same descriptor for every case under that bond.

Upgrading a proxy, validator set, quorum rule, appeal route, stake rule, evidence policy, or timeout route MUST NOT change an open case. A changed policy requires a new module/version or a new policy hash accepted before bond posting.

The policy MUST identify:

1. who may propose and attest decisions;
2. validator eligibility, independence, conflicts, stake, and slashing;
3. quorum calculation and duplicate-operator/Sybil treatment;
4. commit, reveal, response, deliberation, appeal, and finalization deadlines;
5. maximum bounded tolling for objectively defined outages;
6. evidence admissibility and appraisal-policy versions;
7. appeal standing, bond, route, scope, and number of levels;
8. resolver/validator nonresponse behavior and fallback;
9. fee and cost allocation;
10. privacy, retrieval, and retention requirements.

## 4. Case identity

The module computes:

```text
caseId = keccak256(abi.encode(
  "CAAP_RESOLUTION_CASE_V1",
  chainId,
  resolutionModule,
  leaseBond,
  bondId,
  claimId,
  obligationId,
  claimKind,
  claimCommitment,
  policyHash
))
```

The same tuple MUST NOT open two cases in one module. Cross-chain, cross-module, cross-bond, cross-claim, cross-obligation, and cross-policy replay therefore produce a different identifier.

## 5. Case phases

| Phase | Meaning |
|---|---|
| `Commit` | Parties publish salted evidence commitments |
| `Reveal` | Parties reveal DisclosureManifest roots and salts |
| `Validation` | Approved appraisers publish signed/registered appraisal references |
| `Deliberation` | A policy-authorized decision may be proposed |
| `Appealable` | Decision is visible and the appeal window is open |
| `Final` | Appeal path is exhausted and LeaseBond may execute payouts |
| `Cancelled` | Only a policy-defined dismissal with no economic judgment |

Phase transitions are monotonic. A final decision is immutable. Later contradiction/zombie evidence opens a new M1 claim; it does not rewrite history.

No party can obtain an economic default before its response and cure windows expire. Deadline tolling MUST be evented, objectively justified, bounded by the committed policy, and unable to postpone local wipe or safety behavior.

## 6. Commit and reveal

For party `P`, the evidence commitment is:

```text
keccak256(abi.encode(
  "CAAP_RESOLUTION_EVIDENCE_V1",
  chainId,
  resolutionModule,
  caseId,
  P,
  disclosureRoot,
  salt
))
```

`disclosureRoot` is the CAAP-TELEMETRY commitment:

```text
SHA-256(0x02 || deterministic_cbor(DisclosureManifest))
```

The module verifies the commitment on reveal and records only roots. Evidence retrieval, decryption, schema validation, kinematics, signatures, and Merkle proofs occur outside the EVM under the committed appraisal policy.

Non-reveal MAY forfeit a challenge/appeal deposit and MAY support adverse inference after cure. It MUST NOT by itself be labeled `EvidenceFraud`.

## 7. Validation records

Each accepted validation reference binds:

```text
caseId
validator identity and stake domain
validation request hash
validation response hash
evidence/disclosure root appraised
appraisal policy and reference-value-set hashes
result code and limitations
issued and expiry times
conflict declaration
```

The resolver verifies validator eligibility and quorum under the case's immutable policy. Counting signatures without operator-independence rules is not a quorum policy.

A negative validation may mean bad evidence, unsupported format, expired reference values, missing material, or an affirmative contradiction. These MUST remain distinguishable.

## 8. Decision and payout constraints

A proposed `Decision` binds the case, typed `ResolutionCode`, accepted evidence root, appraisal set root, reason hash, payout root, prior-decision/appeal history, and resolver policy.

Each payout identifies a bond tranche, recipient, amount, and purpose code. LeaseBond MUST reject a final result when:

- the decision does not bind the expected case, claim, bond, obligation, or policy;
- the recomputed payout root differs;
- a tranche amount exceeds its remaining balance;
- a recipient or purpose is forbidden by bond terms;
- the same decision digest has already been executed;
- the resolution code is inconsistent with a hard contract invariant.

Examples of hard invariants include: no performance-fault label solely from `ProofUnavailable`; no `QualifiedCasualty` without the policy-required appraisal class; no `TimelyWipe` without accepted obligation-bound wipe evidence; and no payout from unrelated obligations.

The module decides allocation; LeaseBond retains custody and executes the bounded vector. The module MUST NOT receive the principal collateral merely to decide a case.

## 9. Appeals and liveness

An appeal commits new grounds/evidence and supplies the policy-defined appeal deposit authorization. It MUST identify whether review is de novo or limited to enumerated errors.

Appeal adjudicators SHOULD be independent of the prior decision set. The final decision binds `priorDecisionDigest` so an appeal cannot silently replace the record.

Every non-final phase MUST have a timeout transition. The policy may use permissionless phase advancement, dismissal, fallback module, or a predetermined conservative allocation. Resolver silence MUST NOT lock collateral forever or manufacture an allegation of retention.

## 10. LeaseBond integration

LeaseBond SHALL:

1. call `openCase` only for an existing unresolved claim;
2. bind the returned `caseId` to that claim exactly once;
3. count the claim as open through appeal and until `Final` or policy-valid `Cancelled`;
4. verify `moduleId`, `policyHash`, finality, decision digest, and payout root;
5. execute the payout vector exactly once;
6. decrement `openClaims` only after execution or non-economic cancellation;
7. preserve evidence, challenge, casualty, performance, and holdback accounting separately;
8. emit the complete typed result and roots needed for audit and reputation consumers.

The release predicate remains conjunctive:

```text
lease ended
∧ claim window elapsed
∧ openClaims == 0
∧ (obligation wipe accepted OR qualified alternative resolution)
∧ applicable contradiction holdback rule satisfied
```

## 11. Required conformance tests

Implementations MUST test:

1. case replay across chain, module, bond, claim, obligation, and policy fails;
2. mid-case resolver or validator-policy upgrade has no effect;
3. wrong-party reveal or wrong salt fails;
4. a CAAP disclosure root from another claim fails;
5. duplicate validators under one operator do not inflate quorum;
6. conflicted, expired, or ineligible validations are excluded;
7. malformed third-party evidence cannot slash the respondent;
8. non-reveal follows cure/adverse-inference policy but is not automatically fraud;
9. payout root, tranche overdraw, forbidden recipient, and duplicate execution fail;
10. appeal binds the prior decision and uses the committed route;
11. every phase has a bounded timeout result;
12. resolver outage cannot extend local safety or wipe deadlines;
13. finalization before the appeal window or quorum fails;
14. a later zombie contradiction opens a new case and cannot mutate the old one;
15. LeaseBond cannot release while the case remains open.

## 12. References

- [EIP-8004 — Trustless Agents](https://eips.ethereum.org/EIPS/eip-8004)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/info/rfc8949/)
- [RFC 9052 — COSE](https://www.rfc-editor.org/info/rfc9052/)
- [RFC 9162 — Merkle tree and proof construction](https://www.rfc-editor.org/info/rfc9162/)
