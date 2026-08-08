# CAAP-LSC v0.1 — Local Safety Controller Profile

**Status:** Draft v0.1 (extracted from the M0–M2 architecture brief §4, which remains the design rationale; this document is the normative surface)
**Editors:** Clavote Research (`@clavote-boop`)
**License:** CC0 — public domain dedication.
**Composes with:** CAAP-TICKET v0.1 (arming), CAAP-TELEMETRY v0.1 (wire schemas for intents/receipts — defined there, not here), CAAP-WIPE / m1-failure-state-spec (obligations, terminal evidence), ERC-8269 (lease `actuate` scopes)
**Canonical home:** this repository, `standards/`

The key words MUST / MUST NOT / SHOULD / MAY are per RFC 2119 / RFC 8174.

## 1. Position and framing

The Local Safety Controller (LSC) is the deterministic kernel between an untrusted cognitive stack and a body's actuators. It is a **Runtime Assurance / Simplex architecture** (Sha 2001; ASTM F3269 class): an untrusted high-performance controller (the AI), a small certified monitor and recovery controller (the LSC), and switching logic that is itself part of the certified surface. Three consequences are normative:

1. **No ML in the kernel.** The LSC performs envelope checks, kinematic projection (control-barrier-function or reachability class), clamping, and safe-state trajectories only. Target IEC 61508 SIL-2/3-class development; independent MCU/FPGA; independent power and communication path to actuators. The hardware e-stop chain sits below the LSC, unconditionally.
2. **The switching logic is safety-critical.** Clamp/handover decisions are certified, not heuristic.
3. **The kernel speaks CBOR, not natural language.** The intent interface is a fixed typed schema (CAAP-TELEMETRY §5.1); anything else is refused at parse.

A DeadManTicket (CAAP-TICKET) can keep the body **armed**; it cannot order motion, expand the envelope, or override the LSC.

## 2. Trust anatomy

Three signing domains, separately measured at body enrollment (CAAP-WIPE §registerBody), so every incident decomposes into *what was sensed*, *what was asked*, *what was done*:

| Domain | Key | Signs |
|---|---|---|
| Sensing | per-sensor secure element, else LSC ingest key | telemetry chunks (attest-at-first-touch) |
| Cognition | measured-runtime key (cognition manifest: weights hash, harness, safety policy) | `intent-payload` objects |
| Execution | LSC safety-element key | `action-receipt` / `terminal-receipt` objects |

The LSC firmware measurement includes the **envelope compiler** (§4). A Safety Kernel Registry (measurement hash → certification attestation) SHOULD exist so counterparties and resolvers can check a body runs a certified kernel build.

## 3. Normative behavior

### 3.1 The control loop

Per tick (target 1 kHz class): (1) ingest the latest typed intent; verify the cognition-runtime signature; (2) poll sensors **directly**, bypassing the AI perception stack; (3) project the intent's trajectory over its horizon; (4) intersect with the compiled envelope — ticket validity (dual-clock, CAAP-TICKET §4) enters here as an envelope term: no valid ticket ⇒ only minimal-risk trajectories are admissible; (5) execute, clamp, refuse, or descend the degradation ladder — clamp → reduced-speed mode → safe-state trajectory → hardware e-stop — logging each verdict; (6) fold verdicts into the current `action-receipt` chunk (CAAP-TELEMETRY §5.2).

### 3.2 Consequence classes and taint

- **Consequence class (C0–C3) is computed by the LSC from projected physics** (mass in motion, kinetic energy, tool state, proximity), never accepted from the AI's declaration.
- **Taint is channel-level and harness-stamped**: the measured harness — not the model — sets `context_taint` when untrusted-modality content (OCR, decoded audio, web content) entered the planner's context since the last clean checkpoint. The LSC's rule is mechanical: computed class ≥ C2 AND tainted context ⇒ refuse or degrade to C1 limits. C3 requires a live cosign grant delivered on the current ticket.

### 3.3 Terminal failure

On detecting an unrecoverable condition (impact or temperature beyond certified limits, power loss outside the expected window, watchdog), the LSC MUST attempt to write a signed `terminal-receipt` (CAAP-TELEMETRY §5.3) to its ring buffer before power loss. Best-effort; it is the highest-weight evidence in a casualty case (m1-failure-state-spec §5).

### 3.4 Receipts

`action-receipt`s are hash-chained, strictly sequenced per obligation, signed per telemetry chunk window (never per tick), carry the `envelope_hash` in force, and are stored as telemetry records — inheriting chunking, capsule inclusion, anchoring, and disclosure from CAAP-TELEMETRY. A sequence gap or broken chain in a disclosed window is itself evidence.

## 4. The envelope compiler

The lease's `actuate` scopes (geofence cells, velocity/acceleration/force caps, tool classes, human-proximity deceleration rules) are compiled by a **deterministic, hash-stable compiler inside the measured LSC firmware** into the machine-checkable envelope. Every receipt asserts `envelope_hash = H(compile(lease.actuate))`, binding each physical action to the exact lease bytes both parties signed — arbitration checks a hash equality, not an interpretation.

## 5. What the LSC cannot do (normative honesty)

The LSC enforces **physics, not policy**. It cannot detect a safe-looking malicious intent (lawful slow theft violates no envelope — that is a cognition/assimilation and collateral problem); it cannot verify *why* the model formed an intent; its taint gating is only as good as the measured harness; its guarantee is only as good as the envelope compilation. Any claim that a safety kernel "solves" prompt injection is false: it bounds the blast radius to what the envelope permits, which is why envelope authorship is a negotiated, signed, priced term of the lease.

## 6. Conformance

An implementation MUST demonstrate: typed-schema rejection of malformed intents (the CAAP-TICKET §2.3 decoder rules apply); LSC-computed consequence classes overriding declared ones; ticket-expiry descent through the degradation ladder ending in safe state; receipt chain integrity across a power cycle (boot counter increments, chain restarts with a genesis reference); terminal-receipt emission on induced over-limit events in test harnesses; and envelope-hash stability (identical lease bytes compile to identical hashes across builds of the same measured firmware).

## 7. Copyright

Copyright and related rights waived via CC0 1.0 Universal.
