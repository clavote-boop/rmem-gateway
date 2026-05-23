# RMEM Gateway — SPEC v0.1

*© 2026 Jose C. Guzman / Clavote Research. All Rights Reserved.*
*Draft 2026-05-22. Implementation spec for the RMEM Gateway. Consolidates scattered canonical
material — Master Architecture Layer 1 (CAAP-ROBOTID v1.1), the Technical & Business Reference,
Work Plan Track D, and ERC-8264. No prior `RMEM v1.0 spec` file was located in the repo, Umbrel,
local disk, or Drive; this is the first consolidated draft. Private-repo only until attorney
clearance (Work Plan D.2).*

## 1. What it is

A small local service that gives the key owner sovereign control over an AI agent's memory —
read it, correct it, delete it, export it, and move it to a new body — without the body, the
model, or any platform owning that memory.

It is the **implementation layer** for three things already specified elsewhere:

- **ERC-8264** — the four-function rights interface (`readMemory` / `writeMemory` /
  `deleteMemory` / `exportMemory`).
- **CAAP-ROBOTID v1.1** — the Soul ID / Body ID / Wallet ID identity model.
- **RMEM** — the cryptographic memory standard (Bitcoin-anchored memory integrity).

Operating rule, verbatim from the founder narrative: **the body is a lease; the soul is
permanent.** The body never owns the memory. The model never owns the memory. The platform
never owns the memory. The key owner controls the memory.

## 2. Position in the stack

```
OWNER         — Soul ID private key. Off-gateway, always. Signs; never stored here.
   │
ERC-8264      — rights surface: read / write / delete / export, authorization-gated
   │
RMEM GATEWAY  — this spec. Verifies signatures, enforces policy, holds no secret.
   │
RMEM VAULT    — SQLite index + encrypted payload files. Ciphertext at rest.
   │
CAMIA ANCHOR  — single ≤80-byte OP_RETURN hash commitment on Bitcoin (testnet first).
```

The gateway is the only component that is *code we run*. Everything above it is keys and
signatures held by the owner; everything below it is encrypted data and a hash on a chain.

**v0.1 implementation scope = Phases A, B, C, D.** Phase C (body lease + gateway integration
+ migration CLI) was elevated from deferred-design to delivered during the v0.1 build.
**Phase E** (mainnet anchoring via Bunny's Knots node) remains gated on independent Phase D
on-chain proof and is not a v0.1 deliverable. The credential-broker rule is documented as
convention in the companion ERC §3; per-issuer integration (re-minting OpenRouter / Alby
credentials per body) is left to higher layers.

## 3. Identity — from CAAP-ROBOTID v1.1

| Layer | What it is | Lifetime |
|---|---|---|
| **Soul ID** | `did:btc:<pubkey>` (secp256k1). The agent's cognitive identity; the ERC-8264 *subject*. Tied to the memory hash chain. | Permanent — never regenerate |
| **Body ID** | The hardware/runtime substrate (an N100, Umbrel, a future chassis). Bound to a Soul ID by a signed **binding record**. | Changes with hardware |
| **Wallet ID** | Alby sub-wallet bound to the Soul ID. | Per agent |

The gateway only ever sees **public** Soul ID material. Private keys are generated air-gapped
and never enter the gateway, GitHub, Claude/GPT context, or any networked storage (Work Plan D.2).

**ERC-8264 subject ↔ Soul ID.** ERC-8264 types the subject as an Ethereum `address`;
CAAP-ROBOTID's Soul ID is `did:btc:<pubkey>`. These reconcile because Bitcoin and Ethereum
share the secp256k1 curve — one keypair yields both a `did:btc` public key and the Ethereum
address derived from it. The gateway implements ERC-8264's *interface shape and authorization
model* off-chain, against the Soul ID. An on-chain ERC-8264 enforcement contract, if later
deployed, would live on an EVM chain and key off that derived address; CAMIA anchoring stays on
Bitcoin. They share the key, not the chain — and v0.1 (off-chain gateway, testnet BTC anchor) is
unaffected by the distinction.

## 4. The four operations (ERC-8264)

Each call carries an owner-signed authorization or a valid body lease. The gateway verifies the
signature against the subject's public Soul ID — it cannot self-authorize.

| Op | Who may call | Effect |
|---|---|---|
| `readMemory(soul, record_id)` | Owner, or a body whose lease grants read scope | Returns the (still-encrypted) record + metadata |
| `writeMemory(soul, record, sig)` | A body may **propose**; commit needs policy auto-approve or owner signature, by record class | Stores a new/updated record; logs `MemoryWritten` |
| `deleteMemory(soul, record_id)` | Owner signature only | Tombstones the record; purges the payload file |
| `exportMemory(soul)` | Owner signature only | Produces the portable capsule (§7) |

Record classes for the write-commit rule:

- `session` — routine working memory. Auto-commits.
- `proposal` — agent-proposed canonical memory. Auto-commits **as a proposal**, never as canon.
- `canonical` — durable preferences/decisions. Commit requires an owner signature.

## 5. The vault

Local-first, on Umbrel. No new database technology — SQLite, the same as Hermes.

```
/home/umbrel/clavote/rmem-vault/        (dir 700)
  vault.db          SQLite — record metadata, hashes, leases, anchors, audit log
  records/          <record_id>.enc — encrypted payloads (file 600)
  capsules/         exported capsule bundles
```

Payloads are encrypted before they touch disk. The encryption key is owner-held and derived
outside the gateway; the gateway stores and serves **ciphertext only**. A full compromise of the
Umbrel box leaks ciphertext and metadata — never plaintext memory, never a signing key.

## 6. Memory record schema

```json
{
  "record_id": "mem_<ulid>",
  "soul_id": "did:btc:<pubkey>",
  "body_id": "<body that produced the record>",
  "layer": "L1_session | L2_project | L3_canonical",
  "type": "preference | decision | episodic | skill | project_state | body_calibration",
  "payload_ref": "records/mem_<ulid>.enc",
  "payload_hash": "sha256:<hash of the CIPHERTEXT>",
  "rights": {
    "read":   ["owner", "body:<id>"],
    "write":  ["owner"],
    "delete": ["owner"],
    "export": ["owner"]
  },
  "provenance": {
    "created_by": "<soul_id or body_id>",
    "source": "telegram:heavyside-room",
    "created_at": "ISO8601"
  },
  "anchor_ref": "<anchor_id> | null",
  "status": "active | tombstoned",
  "sig": "<signature over the canonicalised record, by owner or gateway>"
}
```

## 7. The capsule — ERC-8264 `exportMemory` output

The portable, encrypted, owner-controlled bundle that `exportMemory` produces and that a new
body imports. The `.enc` payload files travel alongside the manifest; the manifest commits their
hashes and the Merkle root, signed by the owner.

```json
{
  "capsule_version": "0.1",
  "soul_id": "did:btc:<pubkey>",
  "controller_pubkeys": ["<owner pubkey>"],
  "created_at": "ISO8601",
  "record_index": [{ "record_id": "mem_...", "payload_hash": "sha256:..." }],
  "merkle_root": "sha256:<root over record payload_hashes>",
  "body_capabilities": { "<descriptor of the source body>": "..." },
  "entitlements": ["openrouter:cap=$50/mo", "lightning:invoice<=10000sat", "skills:[...]"],
  "policy_hash": "sha256:<hash of the governing policy file>",
  "owner_signature": "<signature over soul_id + merkle_root + created_at>"
}
```

The capsule carries **entitlement descriptors, never raw secrets** (see §8).

## 8. Body lease + credential broker — design intent, Phase C

A body does not get the agent's secrets. It gets a **lease**: a signed, scoped, expiring
binding record between a Soul ID and a Body ID.

```json
{
  "lease_id": "lease_<ulid>",
  "soul_id": "did:btc:<pubkey>",
  "body_id": "<new body>",
  "scopes": {
    "read":   ["L2_project", "L3_canonical"],
    "write":  ["L1_session", "proposal"],
    "delete": [],
    "export": []
  },
  "expires_at": "ISO8601",
  "requires_owner_cosign": ["canonical_write", "skill_install", "delete",
                            "export", "body_transfer", "wallet_action"],
  "owner_signature": "<signature>"
}
```

**Credential-broker rule.** The capsule carries entitlement descriptors — "may use OpenRouter
under $X", "may sign Lightning invoices ≤ N sats", "skills A/B/C" — and **never** raw API keys
or wallet keys. On mount, the owner (or the gateway acting under an owner signature) re-mints
fresh, scoped, short-lived credentials for the new body. The old body's credentials are revoked.
Secrets are re-issued per body, never transported. A consequence worth stating: the Work Plan's
plaintext-secrets problem cannot propagate into a migrated body, because no secret is ever in
the capsule.

## 9. Migration: old body → new body — design intent, Phase C

```
freeze   stop durable writes, finish active tasks, write a final session summary, hash state
export   exportMemory → capsule + .enc files, owner-signed
verify   check owner signature, Merkle root, every payload hash, schema version
mount    decrypt locally on the new body, load policy + index, issue a fresh body lease
probation  first interval: canonical writes + skill installs require owner cosign; export off
revoke   delete the old body's decrypted cache, revoke its lease, tombstone its binding record
```

## 10. CAMIA anchoring

Anchoring proves a memory state existed at a point in time without putting memory on-chain.

- The anchor is a **single standard `OP_RETURN`, payload ≤ 80 bytes** — a 52-byte CAAP payload
  (Master Arch §Layer 1): the Merkle root of the capsule (or of a memory-state fingerprint) plus
  a short version prefix. A 32-byte root fits with room to spare.
- This must be a single standard datacarrier output. Bunny's Bitcoin **Knots** node runs the
  anti-spam policy stack (`rejectparasites=1`, `acceptnonstddatacarrier=0`); inscription-style or
  multi-push embeds will not relay. The hash-commitment design is exactly what `datacarrier=1`,
  `datacarriersize=83` permits.
- **Testnet first** (Work Plan D.2). v0.1 anchors to Bitcoin testnet/signet. Bunny's mainnet
  Knots node (RPC port 9332, verified working) is the **production target only** — Phase E,
  gated on testnet proof verifying independently.
- `verify_fingerprint(capsule, txid)` recomputes the Merkle root and checks it against the
  `OP_RETURN` payload at `txid`. Anchoring never blocks a memory write; it is asynchronous.

## 11. Security model — "do not get hacked"

1. **The gateway holds no secrets.** It verifies signatures against public Soul IDs. It never
   holds a Soul private key, a payload encryption key, or an agent API key.
2. **Ciphertext at rest.** Payloads are encrypted before disk. A box compromise leaks ciphertext
   and metadata — not plaintext memory, not a signing key.
3. **Network posture.** The gateway binds `127.0.0.1` only. Never public. No `tailscale funnel`.
   Bitcoin RPC is reached over loopback.
4. **No real funds in v0.1.** Testnet only. The anchoring wallet, when funded, is a separate
   low-value hot wallet — never the production Clavonode Lightning key.
5. **Minimal attack surface.** Python standard library plus a short, hash-pinned dependency list.
   The gateway loads **no** third-party OpenClaw skills — the `~/skills/skills/` tree on Umbrel is
   untrusted public code and stays out of the gateway's path.
6. **Tamper-evident audit.** Every read/write/delete/export/anchor appends to a hash-chained
   audit log in `vault.db`.
7. **Authorization cannot be bypassed.** Every mutating op verifies an owner signature, or a
   valid, unexpired, in-scope body lease, before any state change (ERC-8264 §Security).
8. **Deletion is real.** `deleteMemory` tombstones the index entry and purges the `.enc` file.
   On-chain anchors only ever held a hash, so the payload that mattered is gone.
9. **Keys never touch this context.** Per Work Plan D.2 — no private key enters GitHub, Claude
   context, GPT context, or networked storage. Key generation is air-gapped.

## 12. Deployment on Umbrel

- Runs as a small supervised service on Umbrel (systemd unit or equivalent), bound to loopback.
- Vault at `/home/umbrel/clavote/rmem-vault/` (dir `700`, payload files `600`).
- Not packaged as an Umbrel app for v0.1 — a plain service. App packaging is later.
- v0.1 anchors to testnet/signet (see §14.1). Bunny's mainnet Knots node is Phase E only.

## 13. Build phases

| Phase | Deliverable | Chain | v0.1? |
|---|---|---|---|
| **A** | `rmem-vault.py` — create / read / tombstone encrypted records, SQLite index, hash-chained audit log. CLI. | none | **yes** ✅ |
| **B** | `rmem-gateway.py` — the four ERC-8264 ops + owner-signature verification, capsule export, lease-based auth path. CLI + library. | none | **yes** ✅ |
| **C** | `rmem-lease.py` (lease issuance / verify / revoke) + gateway lease integration + `rmem-migrate.py` (freeze / verify-capsule / mount with re-encryption). | none | **yes** ✅ |
| **D** | `rmem-anchor.py` — CAMIA OP_RETURN anchoring with signet/testnet/mutinynet support; live-verified on mutinynet 2026-05-22 (txid `224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a`). | testnet | **yes** ✅ |
| **E** | Mainnet anchoring via Bunny's Knots node. GATED on Phase D proof verifying independently. | mainnet | no |

Each phase is independently testable; all five modules ship a `selftest` subcommand. The
combined module suite forms a complete v0.1 implementation of ERC-8264 plus the Capsule +
Lease layers of the companion ERC.

## 14. Relationship to other standards

The companion ERC (Capsule / Lease / Broker) sits in a real but uncrowded gap. Verified
against `ethereum/ERCs` PRs and W3C/MCP/Bitcoin-side repos 2026-05-22.

| Standard | Status | Relationship |
|---|---|---|
| **ERC-8264** "Memory Access Rights" ([PR #1752](https://github.com/ethereum/ERCs/pull/1752)) | Draft, open | The rights interface this gateway implements. Companion ERC `requires: 8264`. |
| **ERC-7857** "AI Agent NFT w/ Private Metadata" | **Final** | Adjacent, narrower — NFT-coupled, transfer-bound re-encryption. Capsule is export-on-demand by subject, not NFT-bound. Different. |
| **ERC-8181** "Self-Sovereign Agent NFTs" ([PR #1579](https://github.com/ethereum/ERCs/pull/1579)) | Draft, open | **Closest on-chain neighbour to Capsule** — same "state anchoring + memory integrity proof" framing. Treat as composition target; cite in `see-also`. |
| **EIP-7702** session-key delegation | **Final** (Core EIP) | Body Lease composes with 7702's authorization-list semantics. Align scope/expiry fields rather than reinvent. |
| **ERC-8118** "Agent Authorization" ([PR #1450](https://github.com/ethereum/ERCs/pull/1450)) | Draft, open | Credential Broker explicitly disclaims overlap in Rationale: 8118 governs **on-chain action authz**; our broker governs **off-chain entitlement descriptors + re-minting**. Complementary. |
| **ERC-8004** "Trustless Agents" | Draft, open | EVM agent-identity layer (NFT-based, CAIP-10 addressing). Soul ID composition story: agent has Soul ID (off-chain BTC root) + optional 8004 NFT (EVM-side discovery). Different layers, same key (secp256k1). |
| **MCP SEP-2072** "Memory Portals" + SEP-2342 MIF | MCP Draft / Closed | **Different protocol layer.** MCP defines the *interchange wire format* (`mem://` URIs, vendor-neutral JSON); this ERC defines the *rights and attestation surface* on EVM. Complementary, not duplicative. Rationale section should state this explicitly to pre-empt the reviewer objection. |
| **did:btc** ([MicroStrategy/did-btc-spec](https://github.com/MicroStrategy/did-btc-spec)) | Early draft | CAAP-ROBOTID's Soul ID `did:btc:<pubkey>` can cite this existing method (TxRef/BIP-136 anchored) rather than inventing one. |

No open PR in `ethereum/ERCs` or `ethereum/EIPs` proposes a portable memory capsule, body
lease, or off-chain credential broker. Slot is open.

## 15. Open decisions for Joe

1. **Testnet source** — run a signet / testnet4 datadir on the existing Umbrel Knots install, or
   use an external testnet RPC for v0.1? *Recommend signet* — fast, stable, free coins, isolated
   from the mainnet node.
2. **Owner key tiering** — confirm a two-tier model: the agent's own **Soul ID key** signs
   routine `session`/`proposal` writes; **Joe's personal key** is the higher controller required
   for `canonical` writes, `deleteMemory`, `exportMemory`, and migration. *Recommended.*
3. **Encryption key** — derive the payload encryption key from the Soul ID key, or use a
   separate owner-held vault key? *Recommend separate* — so decrypting memory and signing
   identity are two different compromises.
4. **Capsule transport** — when a capsule moves between bodies, over what channel? *Recommend a
   file, hand-carried or over the tailnet; never email, never a public service.*
5. **Gateway interface** — loopback HTTP API, or CLI + library only for v0.1? *Recommend CLI +
   library;* add a loopback HTTP layer only when a remote body needs it.
6. **Publication** — the spec and the companion ERC are **CC0 open standards**. No legal
   gate. The standards are technically disjoint from the patent docket (US 63/983,363, ASP
   sensor fusion) and from the Curriculum Method trade secret; they cannot create prior-art
   conflicts or trade-secret leakage. Publishing is the intended IP-strategy: value derives
   from authorship + first-mover, not from owning the spec. The Work Plan D.2 "attorney
   clearance" line was a generic risk-aversion instinct, corrected 2026-05-22: standards ship;
   only patent-docket activity is attorney-gated.
