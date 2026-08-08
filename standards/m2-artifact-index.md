# M2 Evidence and Safety Artifact Set

**Status:** v0.1 normative drafts  
**License:** CC0-1.0

## Files

| File | Role |
|---|---|
| `caap-evidence-v0.1.cddl` | Shared integer-key deterministic-CBOR schemas |
| `caap-telemetry-v0.1.md` | MCAP evidence, signatures, trees, spatial/time semantics, disclosures |
| `caap-lsc-v0.1.md` | Cognition-to-actuation boundary, runtime assurance, receipts, terminal logging |
| `i-resolution-module-v0.1.md` | M1 resolver policy, phases, appeals, liveness, and LeaseBond handshake |
| `IResolutionModule.sol` | Contract-facing resolver interface |
| `m2-conformance-vectors-v0.1.json` | Byte-exact CBOR, Merkle, and disclosure-root vectors |
| `verify-vectors.js` | Independent vector generator/checker with no external dependencies |

## Composition

```text
COSE(IntentPayload)
        |
        v
CAAP-LSC --> Verdict + command --> actuator
   |                               |
   |                               v
   +---- direct sensors <--- measured execution
   |
   v
COSE(ActionReceipt) as EvidenceItem
        |
        v
signed MCAP EvidenceChunks --> RFC 9162 content_root --> CAAP-Capsule
        |
        v
DisclosureManifest --> LeaseBond.respond(disclosureRoot)
        |
        v
validators appraise --> IResolutionModule decides --> LeaseBond pays
```

## Frozen design decisions

1. The hard real-time loop never waits for EVM, networking, evidence signing, or storage.
2. The LSC accepts typed deterministic CBOR only; natural language remains outside the parser boundary.
3. The certified envelope can only be narrowed at runtime.
4. Consequence class is computed by the LSC, never supplied by cognition.
5. MCAP bytes are committed exactly as captured; equivalent reserialization is not accepted.
6. Merkle trees use the RFC 9162 domain-separated construction with no odd-leaf duplication.
7. Secure monotonic time establishes authority and local order; UTC/HLC only correlate evidence.
8. Intent, verdict, command, measured execution, and sensor evidence have distinct roots.
9. A TerminalReceipt is best-effort black-box evidence, not proof of destruction or fault.
10. ERC-8004 validation is an appraisal input; `IResolutionModule` supplies the missing quorum, stake, appeal, timeout, and finality semantics.

## Deliberately profile-specific inputs

The base standards do not invent universal safety constants. Deployments must separately publish certified loop deadlines, WCET, plant models, stopping trajectories, envelope values, sensor-integrity thresholds, consequence-class policy, retention periods, anchoring cadence, resolver policy, and jurisdictional rules.

