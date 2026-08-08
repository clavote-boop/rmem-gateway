# CAAP-LSC v0.1

**Status:** Normative draft  
**Companion artifacts:** `caap-evidence-v0.1.cddl`, `m2-conformance-vectors-v0.1.json`  
**Consumes:** ERC-8269 lease and Operating Ticket, CAAP-WIPE enrollment and obligation state  
**Produces:** CAAP-TELEMETRY Intent, Verdict, ActionReceipt, and TerminalReceipt records  
**License:** CC0-1.0

## 1. Purpose and safety boundary

CAAP-LSC defines the typed interface and evidence profile for a Local Safety Controller (LSC) placed between non-deterministic cognition and physical actuators.

The LSC is a runtime-assurance component. It validates, projects, constrains, refuses, or aborts proposed motion under deterministic deadlines. The cognitive runtime MUST NOT possess an actuator-capable credential or a path that bypasses the LSC.

This specification standardizes an interoperability and evidence boundary. It does not certify a robot, select safe limits, or replace the hazard analysis, control-law verification, machinery standard, or regulator applicable to a deployment.

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are normative.

## 2. Architectural invariants

An implementation claiming CAAP-LSC conformance MUST maintain all of the following:

1. **Exclusive actuation:** only the LSC-controlled path can reach actuator drivers; cognition can submit only a typed `IntentPayload`.
2. **Local authority:** no chain, cloud, language model, witness network, or credential broker participates in the safety-critical loop.
3. **Fail-closed privilege:** an Operating Ticket is necessary for consequence classes that require one, but is never sufficient for safety.
4. **Monotonic restriction:** dynamic inputs may narrow the certified envelope and may force a safer state; they MUST NOT widen the certified envelope.
5. **Independent observation:** safety-critical state is read directly from qualified sensors or a measured ingest path, not from the cognition transcript.
6. **Typed semantics:** the LSC accepts deterministic CBOR conforming to the closed CDDL schema. It MUST NOT parse natural language, URLs, HTML, audio transcripts, QR contents, tool descriptions, or prompt text.
7. **Command/feedback separation:** the commanded trajectory and independently observed execution are distinct records and distinct Merkle roots.
8. **Bounded failure:** invalid input, expired authority, lost evidence integrity, missed deadlines, and resource exhaustion transition to a policy-defined minimal-risk condition.

## 3. Effective SafetyEnvelope

The LSC compiles an immutable base envelope at lease mount:

```text
E_base = E_certified ∩ E_site ∩ E_lease
```

At each evaluation, it computes:

```text
E_effective(t) = E_base ∩ E_ticket(t) ∩ E_dynamic(t)
```

Where:

- `E_certified` is the envelope validated for the hardware/firmware configuration;
- `E_site` contains locally authenticated facility constraints;
- `E_lease` contains owner-authorized actuation scopes and consequence limits;
- `E_ticket` can only narrow lease authority for the ticket lifetime;
- `E_dynamic` contains current obstacle, human-separation, health, uncertainty, and degradation constraints.

An intersection that is empty or cannot be computed before its deadline is infeasible. The LSC MUST refuse the intent or execute the certified minimal-risk trajectory. Independent scalar clipping is insufficient when variables are coupled; the approved trajectory MUST be feasible as a whole under the configured model and uncertainty bounds.

`static_envelope_digest` is the digest of deterministic compilation inputs, compiler identity/version, output representation, and `E_base`. `runtime_constraint_root` commits the EvidenceItems used for `E_dynamic` during an ActionReceipt interval.

## 4. IntentPayload semantic air gap

The cognitive runtime submits the CDDL `intent-payload` as the embedded payload of COSE_Sign1. The baseline signature is ES256 under a measured cognition-session key bound to `body_session_id`.

An IntentPayload states a physical target and upper bounds. It does not state motor current, PWM duty cycle, individual joint torque, safety verdict, or consequence class. The LSC, not cognition, computes consequence class.

The decoder MUST reject:

- any non-deterministic or non-conforming CBOR encoding;
- an unknown field, tag, target type, frame, tool class, or taint bit;
- floats or values outside the fixed-point ranges;
- a stale, future-dated, replayed, out-of-sequence, cross-session, cross-body, cross-lease, or cross-ticket intent;
- a cognition measurement or key not permitted by the mounted lease;
- a target that cannot be transformed into an authenticated LSC frame;
- an intent whose requested bound exceeds `E_effective`, except where the LSC can produce a verified narrower trajectory and record `clamped`.

The LSC MUST rate-limit intent decoding separately from the control loop and MUST bound packet size, queue depth, parse time, and outstanding intent count.

### 4.1 Core Verdict reason bitmap

Bits may be combined. Bits 16–31 are reserved and MUST be zero.

| Bit | Meaning |
|---:|---|
| 0 | Intent malformed, stale, replayed, or out of sequence |
| 1 | Authority/ticket/cosign insufficient |
| 2 | Requested scope exceeds effective envelope |
| 3 | Candidate trajectory infeasible |
| 4 | Predicted collision or separation violation |
| 5 | Force, torque, energy, speed, acceleration, or jerk limit |
| 6 | Sensor freshness/integrity insufficient |
| 7 | Provenance/taint policy insufficient |
| 8 | Frame, calibration, or localization unavailable |
| 9 | Actuator/plant health degraded |
| 10 | Deadline or compute budget unavailable |
| 11 | Evidence capture capacity insufficient |
| 12 | Site/interlock constraint active |
| 13 | Minimal-risk transition already active |
| 14 | Hard E-stop input active |
| 15 | Internal integrity/self-test failure |

## 5. Provenance and taint

Environmental text, speech, symbols, network content, and model-generated interpretations are untrusted observations. They cannot become control authority merely because cognition has transformed them into structured fields.

The measured cognition harness, not the language model, stamps `provenance_root` and the taint bitmap. The provenance graph commits the origin modalities, transforms, tool calls, human approvals, and authenticated instructions that contributed to the request.

The LSC applies a versioned `required_evidence_policy` by consequence class. A policy MAY require independent sensing, operator cosign, facility authorization, or live corroboration. It MUST NOT declare a modality categorically trusted: signed LiDAR can still be replayed, occluded, saturated, or physically spoofed.

Taint is monotonic across derived data unless a policy-recognized declassification step supplies new independent evidence. Parsing natural language into CBOR is not declassification.

## 6. Time and authority

Ticket and intent validity is checked using the LSC's rollback-protected boot counter and secure monotonic clock. UTC, GNSS, HLC, blockchain timestamps, and network time are correlation evidence only. They MUST NOT extend a ticket or avert a local safety transition.

A valid ticket proves only current delegated authority. The LSC also checks:

- lease, digest, obligation, body, session, settlement/revocation epoch, and audience binding;
- ticket sequence and predecessor/hash-chain rules;
- ticket scope as a subset of `E_base`;
- static envelope digest and permitted cognition measurement;
- required cosign grants for the computed consequence class;
- local expiry including declared clock uncertainty.

Ticket loss or expiry MUST NOT cause an uncontrolled power cut. It triggers the certified policy for the current plant state: refuse new motion, complete only an explicitly bounded stopping maneuver, and enter minimal risk. Pre-authorized degraded tickets may authorize only their narrow, single-use recovery profile.

## 7. Deterministic execution

The cycle frequency and safety deadline are deployment parameters derived from hazard analysis. A 1 kHz loop is a profile, not a universal requirement.

For every cycle, the LSC SHALL:

1. sample direct safety sensors and actuator feedback;
2. update freshness, plausibility, diversity, and integrity states;
3. admit at most one valid current intent or the current approved trajectory;
4. project the candidate trajectory over the policy horizon with declared uncertainty;
5. compute consequence class and the applicable evidence/approval policy;
6. intersect the candidate with `E_effective` and evaluate invariants;
7. atomically publish a feasible command, a bounded stopping command, or an E-stop transition;
8. append preallocated evidence records for asynchronous chunking and signing.

The hard real-time path MUST NOT perform dynamic memory allocation, page-faulting access, blocking I/O, DNS/network access, blockchain reads, general-purpose logging, file-system operations, evidence encryption, or public-key signing. These operations belong to bounded lower-priority tasks using preallocated lock-free or bounded-copy queues.

The implementation MUST publish worst-case execution time (WCET), deadline, scheduling policy, resource bounds, overload behavior, and measurement method for each certified hardware profile. A deadline miss increments the receipt counter and invokes the configured degradation rule. A deadline miss MUST NOT silently reuse a command whose validity interval has ended.

## 8. Sensor integrity monitor

The LSC assigns integrity per observation using the CAAP-TELEMETRY ladder: Authenticated, Fresh, Plausible, Corroborated, and Safety-qualified.

The monitor SHOULD combine:

- secure counters and sample timing;
- cross-sensor kinematic and energy residuals;
- actuator-command versus encoder/current/force feedback;
- calibration, saturation, occlusion, stuck-value, and rate-limit checks;
- physically independent modalities and fault domains;
- active challenge-response where the sensor and plant permit it;
- authenticated facility constraints and opportunistic witness evidence.

A challenge is evidence only if its selection is unpredictable to the tested path, its timing is bound to the secure clock, and the response is captured by the independent ingest path. Witness agreement does not override local stopping constraints.

If required integrity falls below the class policy, the LSC MUST downgrade the admissible consequence class, refuse the action, or enter minimal risk.

### 8.1 Safety-metric validity flags

The `safety-metrics` flag word uses bits 0 stopping-distance valid, 1 human-separation valid, 2 peak-force valid, 3 energy valid, 4 projection uncertainty bounded, 5 independent-sensor diversity satisfied, and 6 model validity window satisfied. Bits 7–31 are reserved and MUST be zero.

An unavailable unsigned metric MUST be encoded as `uint64_max` with its validity bit clear. A cleared validity bit never means "unbounded safe"; if the class policy requires that metric, the intent is inadmissible.

## 9. State machine

The normative states are defined in the companion CDDL. The minimum transition rules are:

| From | Event | To | Required behavior |
|---|---|---|---|
| `boot_locked` | verified boot, enrollment, lease mount, self-test | `safe_idle` | actuators remain inhibited |
| `safe_idle` | valid authority and armed interlocks | `armed` | publish zero/holding command |
| `armed` | admissible intent | `executing` | begin approved trajectory |
| `executing` | sensor or evidence degradation | `degraded` | narrow envelope and class |
| `armed`, `executing`, `degraded` | ticket expiry, infeasible trajectory, recoverable fault | `minimal_risk` | execute certified stopping/recovery trajectory |
| any non-terminal | hard interlock or unrecoverable safety violation | `estop_latched` | hardware inhibit; authenticated reset required |
| any non-terminal | detected catastrophic failure | `terminal` | persist best-effort TerminalReceipt; no further actuation |

Transitions to a more permissive state require authenticated local preconditions. Network recovery alone MUST NOT clear `estop_latched` or widen an envelope.

## 10. Verdicts and ActionReceipts

For every admitted intent, the LSC emits a CDDL `verdict`. A clamped verdict binds both the rejected candidate root and approved trajectory root. A refusal still produces a verdict and evidence reference.

The LSC aggregates evidence into an `action-receipt` at the configured evidence cadence. The ActionReceipt MUST be the embedded payload of COSE_Sign1 signed by the enrolled LSC attestation key. Its full signed bytes become a CAAP-TELEMETRY EvidenceItem.

The five roots are non-substitutable:

| Root | Meaning | Signing domain |
|---|---|---|
| `intent_set_root` | cognition's requested outcomes | cognition keys, captured by LSC |
| `verdict_set_root` | LSC projections, class, and decisions | LSC |
| `command_root` | values sent to actuator drivers | LSC execution path |
| `executed_root` | encoders, currents, force, pose, and observed response | independent ingest/sensor keys |
| `sensor_evidence_root` | observations used to decide safety | independent ingest/sensor keys |

All roots use the RFC 9162 construction over deterministic EvidenceItem bytes. The ActionReceipt also binds the ticket, base envelope, dynamic constraints, firmware/compiler measurement, state transition, faults, deadline misses, WCET observation, previous receipt, and rollback-protected counter.

Receipt creation MUST NOT block actuation. The loop writes a bounded unsigned receipt record to protected memory; a measured asynchronous task closes the chunk and signs it before the maximum unanchored deadline. Queue exhaustion is a fault and forces the policy-defined degradation state.

### 10.1 Core ActionReceipt fault bitmap

Bits 0–15 are: control deadline miss; intent queue overflow; evidence queue overflow; sensor freshness loss; sensor contradiction; ticket invalid/expired; envelope infeasible; command/feedback disagreement; clock/counter anomaly; storage/anchor lag; internal watchdog; hard interlock; E-stop; thermal/energy fault; attestation failure; configuration-integrity failure. Bits 16–31 are reserved and MUST be zero.

## 11. TerminalReceipt

When catastrophic failure is detected, the LSC SHOULD write the CDDL `terminal-receipt` to energy-backed, append-only storage before power loss. The receipt binds the last ActionReceipt, last sensor, command, and execution roots, energy-state snapshot, cause bitmap, secure time, firmware measurement, and rollback-protected counter.

The TerminalReceipt is signed immediately if the hardware budget permits; otherwise a secure element MAY finalize a precommitted receipt slot after the main processor fails. The exact signed bytes SHOULD be replicated into the final EvidenceChunk and exposed through a salvage interface that does not release Capsule plaintext keys.

TerminalReceipt production is best effort. Its absence is an explicit evidence condition, not proof of negligence, destruction, or wipe. A valid later artifact under the enrolled body/session lineage may contradict a destruction claim under the M1 zombie/contradiction rules.

The v0.1 TerminalReceipt cause bits are: bit 0 over-temperature, 1 over-current/energy anomaly, 2 impact beyond certified limit, 3 structural/actuator failure, 4 power collapse imminent, 5 watchdog/reset storm, 6 secure-element failure, 7 storage failure, 8 hard E-stop, 9 localization loss, 10 communications/RF event, 11 external hazard sensor, 12 firmware integrity failure, and 13 unknown catastrophic condition. Bits 14–31 are reserved and MUST be zero.

## 12. Liability interpretation

Receipts support attribution; they do not make legal fault automatic.

- Safe intent + safe command + unsafe measured execution may indicate actuator, plant, maintenance, or sensing failure.
- Unsafe requested intent + refusal indicates cognition risk without harmful execution.
- Unsafe requested intent + correctly clamped execution separates cognition from the actual movement.
- Safe sensed state + unsafe command may indicate an LSC implementation or envelope defect.
- Command/feedback disagreement with missing independent feedback is incomplete evidence, not proof the command was executed.
- Forged, equivocated, or anchor-contradicting evidence is `EvidenceFraud` independent of the underlying damage amount.

An economic resolution module consumes validated facts and applies the bond's immutable policy. ERC-8004 validation responses MAY contribute appraisals; they are not themselves an arbitration judgment.

## 13. Required conformance tests

An implementation MUST demonstrate:

1. cognition has no actuator-capable credential or bypass path;
2. malformed, oversized, floating-point, unknown-field, and replayed intents are rejected within the decoder budget;
3. natural-language and environmental content cannot reach the LSC parser;
4. expired authority transitions to the certified minimal-risk behavior without chain/network access;
5. a ticket or dynamic input cannot widen `E_base`;
6. the consequence class is recomputed locally and cannot be supplied by cognition;
7. coupled infeasible trajectories are refused rather than independently clipped into an unsafe path;
8. sensor freshness loss, contradiction, and queue exhaustion cause the declared degradation;
9. deadline misses cannot silently extend a previous command;
10. command and execution roots differ when measured response differs;
11. receipt generation/signing cannot delay the control loop;
12. boot, session, ticket, lease, and obligation replay tests fail closed;
13. E-stop reset requires the declared authenticated local procedure;
14. TerminalReceipt recovery does not expose the Lease Data Key;
15. published receipts reproduce the M2 deterministic-CBOR and Merkle vectors.

## 14. References

- [NASA Runtime Assurance preliminary guidance](https://ntrs.nasa.gov/api/citations/20220015734/downloads/tm-rta-guidance.pdf)
- [ROS 2 real-time programming background](https://design.ros2.org/articles/realtime_background.html)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/info/rfc8949/)
- [RFC 9052 — COSE](https://www.rfc-editor.org/info/rfc9052/)
- [RFC 9162 — Merkle tree and proof construction](https://www.rfc-editor.org/info/rfc9162/)
- [ROS REP 103 — units and coordinate conventions](https://www.ros.org/reps/rep-0103.html)
- [ROS REP 105 — mobile-platform coordinate frames](https://www.ros.org/reps/rep-0105.html)
- [EIP-7951 — P-256 verification](https://eips.ethereum.org/EIPS/eip-7951)
