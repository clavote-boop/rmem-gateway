# rmem-solana-registry

Solana mirror of the `RmemMemoryRegistry.sol` EVM contract.  Implements the ERC-8264 four memory ops plus body-lease grant/revoke with the **explicit `revoked_at` field** that closes the `¬Revoked` conjunct gap in the v0.3.4 spec audit (Eq. allow-revoke of the formal paper).

**Native Solana program** (no Anchor framework dependency).  Built with `solana-program ~2.0` and `borsh 1.5`.  Size-optimized (`opt-level = "z"`, LTO, stripped) so deploy fits under 1 SOL of rent.

## State layout

Solana's account model has no nested mappings; each logical mapping entry is its own account, addressed by a Program-Derived Address (PDA):

| Logical mapping | PDA seeds |
|---|---|
| memory record | `["mem",   subject_pubkey, record_id]` |
| lease state   | `["lease", subject_pubkey, body_pubkey]` |

The `MemoryRecord` PDA stores a 32-byte commitment + discriminator (33 bytes total). The `Lease` PDA stores `{discriminator, scopes, expires_at, revoked_at}` = 18 bytes.

## Authorization (Allow_8264 predicate decomposition)

`authorize(signer, subject, lease_account, required_scope)`:

1. `signer == subject` → always allow.
2. Otherwise the `(subject, signer)` lease PDA must exist, AND:
   - `revoked_at == 0` (¬Revoked — **independent conjunct** from WithinTime, per Eq. allow-revoke)
   - `clock.unix_timestamp < expires_at` (WithinTime)
   - `scopes & required_scope == required_scope` (Scope)

The order is for early-exit only; both predicates must independently hold.

## Build + deploy

```bash
cargo build-sbf
solana program deploy target/sbpf-solana-solana/release/rmem_solana_registry.so
```

Build requires Rust + the Solana CLI (`solana --version` ≥ 3.x).  Deploy needs ~1 SOL of devnet/mainnet SOL on the configured keypair.

## Live deployment

| Field | Value |
|---|---|
| Cluster | Solana devnet |
| Program ID | `2BcJ1EYpBrphcTSmbpeaxzWwCZegjBvXPDmbAMoxN7TP` |
| Deploy date | 2026-05-23 |
| Explorer | https://explorer.solana.com/address/2BcJ1EYpBrphcTSmbpeaxzWwCZegjBvXPDmbAMoxN7TP?cluster=devnet |

Test exercise (paired grant + revoke proving `revoked_at` fires inside the time window):
- Lease PDA: `ADEVfKui9y43UN7adcVGk2v7V4LoSNk1chMPaQpehevM`
- grantLease tx: `39Z716iuy5tN1J24LoWe97GqZR1Q4R19yEBU9nLRJnxZ4BoQx9MZsxZqWiRXw4pEr8NXxinDnKgrCvAwSbtZztcb`
- revokeLease tx: `5462KwTrW4CWrYzkRFZd4nth9vRDMYGV59gVCiFJUMqiQRuk8ciQo16tRrcGMwpQa5oGwApcqiELcCPcr8X9ZBzu`
- Result: `revoked_at = 1779573192` (block-time of revoke) while `expires_at = 1811109190` (year 2027) — proves the ¬Revoked conjunct is set independently of WithinTime.

## Relationship to the EVM contract

This program is **semantically equivalent** to `contracts/src/RmemMemoryRegistry.sol` (in the parent directory). Same scope bitmap (READ=1, WRITE=2, DELETE=4, EXPORT=8), same authorization predicate decomposition, same explicit-revocation property. The difference is the account model (PDA-per-mapping-entry on Solana vs. nested-mapping on EVM) and the instruction encoding (Borsh enum dispatch vs. Solidity function selectors).

## Out of scope (vs the EVM contract)

- ERC-165 surface — Solana has no equivalent interface-detection standard.
- `anchorMemoryRoot` event — Solana evidence uses the Memo program with a `caap1:` wire prefix instead. See parent `rmem-anchor.py` for the cross-chain anchor logic.
- Capsule export end-to-end — the off-chain Python tooling (`rmem-gateway.py`, `rmem-migrate.py`) handles capsule manifests identically regardless of which chain the registry is on.
