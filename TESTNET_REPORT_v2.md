# Testnet validation: v0.3.4 spec-conformance pass

**Run date:** 2026-05-23
**Scope:** Close the three blocking gaps surfaced by the engineering audit of `rmem-gateway` against `agent_memory_rights_v0_3_4` (the formal spec paper). The audit found that the v0.1 reference implementation diverged from the paper's Def. 1 (`canonProfile`), Def. 4 (Merkle leaf/internal prefixes + tagged-hash domain separation per Table 1) and the `¬Revoked` conjunct of Eqs. allow-revoke / lease-revoke (which was implicit-via-deletion rather than an explicit predicate). This report documents the impl-side closure plus the on-chain evidence captured on 2026-05-23.

**Outcome:** All three blockers closed. Foundry suite expanded from 19 to 21 tests; all 5 Python module selftests pass; v0x02 OP_RETURN anchor live on Bitcoin mutinynet; v0.3.4 EVM reference contracts deployed and exercised on three EVM testnets.

## Impl-side changes

### New module: `rmem_hashes.py`

Single source of truth for the paper's hash discipline (Def. 2 / Def. 4 / Eq. anchor / Eq. cosign):

- `tagged_sha256(tag, *parts)` — length-prefixed SHA-256, `sha256(len(tag) || tag || parts…)`. Six TAG constants from Table 1: `MEMORY_RECORD`, `ERC8263_EVENT`, `CAPSULE_CHUNK`, `CAPSULE_MANIFEST`, `CAAP_ANCHOR`, `BODY_ACTION`.
- `merkle_root_v2(leaves)` — Def. 4 leaf prefix `0x00`, internal prefix `0x01`, right-duplicate padding to power of two.
- `capsule_merkle_root(meta, chunk_hashes, G_X)` — builds the full leaf sequence `(h_m, h_1, …, h_n, H(canon(G_X)))` and computes `R_X`.
- `anchor_digest(R_X, domain)` — `H(CAAP_ANCHOR || R_X || domain)` per Eq. anchor.
- `body_action_digest(canon(α))` — `H(BODY_ACTION || canon(α))` per Eq. cosign.
- `CANON_PROFILE_JCS = "jcs-rfc8785"`, `RECOGNIZED_CANON_PROFILES = {jcs-rfc8785, cbor-rfc8949}`.

### Capsule format → v0.2 (Def. 4 conformant)

`rmem-gateway.py` `export_memory()` now emits manifests with: `canonProfile`, `hashAlg`, per-record `chunk_hash` (tagged), and `provenance_graph`. The Merkle root is computed under Def. 4 (leaf/internal prefixes + correct leaf ordering) rather than the previous untagged `sha256(left || right)` form.

`rmem-migrate.py` `verify_capsule()` now:
- Rejects capsules with missing or unrecognized `canonProfile` per Def. 1.
- Re-derives each `chunk_hash` from the on-disk `.enc` bytes and compares to the manifest entry.
- Recomputes `R_X` via `capsule_merkle_root` and compares to manifest.

### OP_RETURN anchor → v0x02 (CAAP_ANCHOR domain-separated)

`rmem-anchor.py`:
- `ANCHOR_VERSION = 0x02`. The 32-byte field in the payload now carries `H(CAAP_ANCHOR || R_X || domain)` per Eq. anchor, not the bare `R_X`. Cross-protocol replay of the same root is prevented by the per-protocol `domain` string mixed into the tagged hash.
- The `anchors` table gains a `domain` column (PRAGMA-detected migration for pre-v2 vaults).
- `verify_anchor_onchain()` recomputes the tagged digest from the locally-stored `(R_X, domain)` pair and matches against the on-chain bytes.
- `compute_memory_root()` reads each chunk's `.enc` bytes and computes leaves via `chunk_hash` (tagged); Merkle uses Def. 4 prefixes.

### Off-chain `¬Revoked` as an independent conjunct

`rmem-lease.py`:
- New `is_lease_revoked(lease, vault=None)` — checks both `lease["_status"]` and (if a vault is supplied) the persisted lease record's `status`. Independent of expiry.
- `verify_body_signed_request(lease, msg, sig, vault=None)` now performs the `¬Revoked` check separately from `is_lease_expired`. A body presenting a stale (pre-revoke) lease JSON is rejected via the vault lookup.
- New `verify_body_action_cosign(action, cosig, subject_address)` and `sign_body_action(action, account)` for Eq. cosign over the `BODY_ACTION`-tagged digest.

The `rmem-gateway.py` lease auth path now passes `vault=self.vault` to `verify_body_signed_request`.

### On-chain `¬Revoked` as a separate state field

`contracts/src/RmemMemoryRegistry.sol`:
- New `mapping(address => mapping(address => uint64)) public revokedAt;` — explicit revocation timestamp, 0 means never revoked.
- `_isAuthorized` checks `revokedAt[subject][msg.sender] != 0` BEFORE the `expiresAt` check, implementing Eq. allow-revoke as two distinct conjuncts.
- `revokeLease(body)` writes `revokedAt[msg.sender][body] = uint64(block.timestamp)`.
- `grantLease(...)` clears `revokedAt[msg.sender][body] = 0` so re-grant after revoke is supported.

## Test surface

### Foundry: 21/21 passing

Two new tests directly prove the spec's independent-conjunct property:

- `test_revocation_sets_explicit_timestamp_independent_of_expiry` — grants a 365-day lease, revokes immediately, asserts `revokedAt(subject, body) == block.timestamp` and that `writeMemory` reverts even though the lease's `expiresAt` is well in the future. **This is the test the v0.1 contract could not have passed**, because `_isAuthorized` previously had no notion of revocation distinct from a zeroed-`expiresAt` deletion side-effect.
- `test_regrant_clears_prior_revocation` — proves `grantLease` resets `revokedAt`, so re-granting after revoke works.

Existing 19 tests continue to pass under the new contract.

### Python module selftests: all OK

| Module | New v0.3.4 selftest assertions |
|---|---|
| `rmem-vault.py` | unchanged |
| `rmem-gateway.py` | manifest carries `canonProfile`, `capsule_version=0.2`; Merkle root recomputes under Def. 4; each `chunk_hash` matches independently-computed tagged hash |
| `rmem-lease.py` | stale lease JSON rejected via vault revocation lookup; `BODY_ACTION` cosign roundtrip + wrong-signer + tampered-action rejection |
| `rmem-migrate.py` | missing `canonProfile` rejected; unrecognized `canonProfile` rejected; tampered `chunk_hash` leaf rejected |
| `rmem-anchor.py` | payload is NOT the bare root; cross-domain replay digest verification fails; round-trip preserves anchor digest |

## On-chain v0.3.4 evidence

### Bitcoin mutinynet — v0x02 OP_RETURN anchor

| Field | Value |
|---|---|
| txid | `0e595f6786d4ad8f0f87fc112732d68a40003cb7ddd0997de50a27f46f334c5a` |
| Block height | 3124650 |
| Anchor address | `tb1q0wlexrxl582t3zp8xvvdcjc2y59qkmej5pqh92` |
| Funding tx | `a786f38080117a2ca8a9541e2de1964388511dd609e4227a0cea3e1efd08a6df` |
| Domain | `bitcoin-mutinynet` |
| Merkle root R_X | `sha256:d63ee73810a7d64e3bb22c73360551f147cce897a38893a43aabd21a6d294a8d` |
| 32-byte anchor digest in OP_RETURN | `be84dcade46ea25c73ba7748e8ce7b6475d0d78e2441b04974c34e36b85b549f` |
| Recomputed `H(CAAP_ANCHOR ‖ R_X ‖ domain)` | `be84dcade46ea25c73ba7748e8ce7b6475d0d78e2441b04974c34e36b85b549f` ✓ |

Block explorer: https://mutinynet.com/tx/0e595f6786d4ad8f0f87fc112732d68a40003cb7ddd0997de50a27f46f334c5a

The on-chain bytes match the tagged digest computed locally from `(R_X, domain)`, proving the v0x02 anchor format is what landed on chain (not the bare root from v0x01).

### EVM testnets — v0.3.4 reference contracts with explicit `revokedAt`

| Chain | Chain ID | Contract address | Deploy txid |
|---|---|---|---|
| Sepolia | 11155111 | `0x31dc2367b3aa512a5e58a2e116fd956276723405` | `0x958a40bc78720276ba0305bf9efc39f4f0f3c1575feff5a2f9a81a846c6928c1` |
| Base Sepolia | 84532 | `0xe03a97717ab166c555da4bb9f09e719135e521b8` | `0x8b0c4c0a007606fc2cdb9636a5bde75690646bc109c8ac1cfe5172bd0afb9648` |
| BSC Testnet | 97 | `0xe03a97717ab166c555da4bb9f09e719135e521b8` | `0x7c2e2bbb19cfd05a093993ddb6e2f50ea2d6b8aeb906d15495f63a1f44b38059` |

Same address on Base Sepolia + BSC Testnet because the deployer was at nonce 1 on both; Sepolia differs because the deployer was at nonce 2 there.

### `revokedAt` mapping exercised on every chain

For each contract, a paired `grantLease` → `revokeLease` was issued, with `revokedAt(subject, body)` read both before and after:

| Chain | grantLease txid | revokeLease txid | post-revoke `revokedAt` |
|---|---|---|---|
| Sepolia | `0x74e0927f43f3f7c5b28bd702e1d534fac8a570b6d0c3ac5f4fc2dd2cea9ae19a` | `0xf610c66b686b14d5f8f605e3b74e0fea4078ab22abf110078f5978cd4c30d516` | 1779570456 |
| Base Sepolia | `0x3d18cb286bf11b01df0179e28c1ae700e408ea84dccf4a040f76c9d05c4208ca` | `0xab1c139cff839492d112bf2239d8fd6102079cd4bd599ce4ec57bd8f5048f92a` | 1779570468 |
| BSC Testnet | `0x8f2468c0bc45d641fc87e1487d43dd232d93c47a5cc151200b35121e34b1dc06` | `0x487b1502db10a469d600a6bbda09dc5bd89a62bb916c02fd2384d16ea60885dc` | 1779570475 |

The `grantLease` set the lease's `expiresAt` to year 2286 (Unix `9999999999`), well within the time window. `revokedAt` returned `0` pre-revocation and a non-zero block timestamp post-revocation, demonstrating that the on-chain `¬Revoked` conjunct fires independently of `WithinTime`.

## Relationship to v1 deployments

The v0.1 reference contracts at `0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e` (deployer nonce-0 on each chain) remain valid for the v1 chain-agnostic capsule format and the v0x01 OP_RETURN anchor format. They lack the `revokedAt` mapping and therefore implement the `¬Revoked` conjunct only implicitly via the `delete leases[...]` side effect inside `revokeLease`. The v0.3.4 contracts above implement the conjunct explicitly per the spec.

The v0x01 Phase-D mutinynet anchor (txid `224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a`) remains valid as a root commitment, but its OP_RETURN carries the bare root, not the `CAAP_ANCHOR`-tagged digest. The v0x02 anchor above is the first on-chain instance carrying the tagged digest with explicit `domain` separation.

## Disclosed divergences still standing

These are unchanged from `TESTNET_REPORT_v1.md` and remain open:

1. **Signature suite is `eip-191-authmsg`, not strict EIP-191 over the canonical manifest.** The Bitcoin OP_RETURN commitment closes the gap externally; a future impl version may add an opt-in strict suite.

2. **`canonProfile = "jcs-rfc8785"` is honest for the manifest's value subset only.** All manifest values are ASCII strings, integers, booleans, lists, or nested objects with the same subset — no floats, no surrogates, no NFC-affecting characters. For that subset, `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` produces byte-identical output to RFC 8785 JCS. A vetted RFC 8785 library has not been swapped in, so an adversarially-constructed manifest with floats or surrogate-pair edge cases could in principle diverge.

3. **`bip-322-legacy` suite not yet implemented.** Registered in the spec but no Bitcoin-rooted-controller code path in the impl.

## Sign-off

The three audit blockers (`canonProfile` gate, explicit `¬Revoked` conjunct on both layers, Def. 4 Merkle with full Table 1 TAG scheme) are closed in the impl, verified by tests, and demonstrated on three EVM testnets and one Bitcoin testnet. The v0.3.4 paper (`agent_memory_rights_v0_3_4.tex`) cites the v0x02 anchor txid and all three v0.3.4 EVM contract addresses in §13 as concrete on-chain evidence.
