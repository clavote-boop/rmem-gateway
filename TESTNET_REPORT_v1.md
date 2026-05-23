# Testnet validation: CAAP-Capsule v1 chain-agnostic format

**Run date:** 2026-05-22 (UTC: 2026-05-23T03:52:57Z)
**Scope:** End-to-end exercise of the patched rmem-gateway implementation against the CAAP-Capsule v0.1 chain-agnostic specification and the slim ERC-8265 (Body Lease + Credential Broker).
**Outcome:** All offline checks pass. Anchor TX construction is deferred to a broadcast step that runs off-host (per Work Plan D.2 — private keys never enter networked storage).

## What was tested

The script `testnet_e2e_v1.py` runs in nine stages inside a fresh tempdir, all in-process:

| # | Stage | Result |
|---|---|---|
| 1 | Fresh vault A initialized with a random 32-byte key | OK |
| 2 | Three records written across `L1_session` / `L2_project` / `L3_canonical` with distinct types | 3 records written |
| 3 | ERC-8265 Body Lease minted (owner-signed via EIP-191) and signature re-verified | Lease verifies |
| 4 | `exportMemory` produces a Capsule whose manifest matches the **v1 chain-agnostic schema** (`subject_id` + `subject_id_method` + `controllers[]` + `signature_suite`) | Manifest emitted; all spec-required fields present; no legacy `soul_id` / `controller_pubkeys` fields leak through |
| 5 | `verify_capsule` accepts the freshly-emitted capsule | Valid |
| 6 | Tamper detection: flipped one byte in one ciphertext → `verify_capsule` rejects; restored → accepts again | Tamper detected; clean restored |
| 7 | `mount_capsule` re-encrypts the three payloads into a fresh vault B under a new key | 3 records mounted |
| 8 | Each record read back from vault B under the new key, plaintext compared against the original | 3/3 plaintexts round-trip exactly |
| 9 | `caap-btc-opreturn-v1` OP_RETURN payload assembled from the capsule's `merkle_root` | 38 bytes, anchor-ready |

All 5 module selftests (`rmem-vault.py`, `rmem-gateway.py`, `rmem-lease.py`, `rmem-migrate.py`, `rmem-anchor.py`) pass under the patched impl.

## Artifacts from the canonical run

```
subject_id            0xb4aE87405d5073c79E99F96A8ecDE5E9A8DD6347
subject_id_method     eth-address
signature_suite       eip-191-authmsg
capsule_version       1
record_count          3
merkle_root           sha256:6cd35a424fad84c4da7d4d2a2717acb7282f5c248b7976ffec8b23b8839fed3c

OP_RETURN (caap-btc-opreturn-v1, 38 bytes)
hex   434141500101 6cd35a424fad84c4da7d4d2a2717acb7282f5c248b7976ffec8b23b8839fed3c
      └CAAP┘└v┘└t┘ └────────────── sha256 merkle_root ──────────────────────────────┘
```

Lease (ERC-8265):

```
lease_id              lease_1779508377537_04a2c3f40e82
scopes.read           ["L1_session", "L2_project", "L3_canonical"]
scopes.write          ["L1_session"]
scopes.delete         []
scopes.export         []
expires_at            2026-05-23T04:52:57Z (1 hour after issuance)
signature             EIP-191 over canonical lease JSON, verified
```

The full run log is at [testnet_e2e_v1_run.json](testnet_e2e_v1_run.json). Subject ID, lease ID, and merkle root are regenerated on every run (random key per invocation); these artifacts are from the 2026-05-23T03:52:57Z run.

## Anchor broadcast (next step, off-host)

To anchor the Capsule's `merkle_root` on Bitcoin mutinynet, run on a host that has the anchor WIF — **not in Claude's context** per Work Plan D.2:

```
python rmem-anchor.py anchor-memory-root \
    --soul 0x<subject_id> \
    --network mutinynet \
    --anchor-key /secure/anchor.wif \
    --broadcast-via public-api \
    --fee 500
```

The OP_RETURN payload assembled by `rmem-anchor` matches what stage 9 above produced. The anchor module's `selftest` (which builds + signs an OP_RETURN TX offline) passes under the patched impl.

A successful broadcast on mutinynet — like the prior Phase D anchor (txid `224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a`) — gives:

1. An on-chain commitment of the Capsule's `merkle_root` under the `caap-btc-opreturn-v1` anchor format.
2. Public, verifiable proof that the v1 chain-agnostic manifest's content hash existed at the time of the broadcast.

## Disclosed divergences from strict spec compliance

These are intentional in v0.1 of the reference implementation and registered in the spec accordingly:

1. **Signature suite is `eip-191-authmsg`, not strict `eip-191`.** The impl uses an auth-message-bound EIP-191 signature: the controller signs a short authorization message off-host and the gateway embeds it in `owner_signature_message`. This preserves the pre-sign UX but the signature does **not** cryptographically commit to the manifest's `merkle_root` or `record_index`. The `caap-btc-opreturn-v1` on-chain anchor closes that gap externally (Bitcoin commits to merkle_root). A v0.2 of the impl will add strict `eip-191` (sign the canonical manifest itself) as an opt-in suite. The capsule spec §6.2 documents this trade-off explicitly.

2. **Canonicalization is `json.dumps(sort_keys=True, separators=(",", ":"))`, not strict RFC 8785 JCS.** The two agree on field ordering and whitespace but diverge on Unicode escape forms and number serialization edge cases. The reference impl does not encounter the divergent cases in practice (manifests use only ASCII, integer record counts, sha256-hex strings). A v0.2 of the impl will swap in a vetted RFC 8785 implementation.

3. **`bip-322-legacy` suite not yet implemented.** Registered in the spec but no Bitcoin-rooted-controller code path in the impl yet. `did:btc` subjects remain a forward-looking surface.

## Verifying the verifier

The `verify_capsule` implementation now accepts both schemas:

- **v1 (new):** `subject_id` + `subject_id_method` + `controllers[]` + `signature_suite` (canonical going forward).
- **Legacy v0.1 (back-compat):** `soul_id` + `controller_pubkeys[]` — translated through `_normalize_manifest()` so old capsules continue to verify.

The selftest run included a tamper-injection round-trip (stage 6) to confirm the verifier still fails closed on payload-byte mutation under the new schema.

## What's intentionally out of scope

- **Mainnet anchoring.** Mainnet (Bunny's Knots node, port 9332) is gated on independent verification of the testnet anchor per Work Plan D.2. Mutinynet is the only target for this validation pass.
- **Body-lease enforcement at the ERC-8264 op layer in this script.** The lease is minted, signed, and signature-verified here; integration tests where a body issues a `writeMemory` under a lease are covered by the `rmem-gateway.py` selftest.
- **Migrate.py `freeze`/`unfreeze` and `mount_capsule`'s deep audit-log path.** Covered by `rmem-migrate.py selftest`.

## Sign-off

All offline checks pass. The patched implementation emits the v1 chain-agnostic capsule format end-to-end, with backward-compatible verification of legacy v0.1 capsules. The OP_RETURN payload is anchor-ready for mutinynet broadcast.
