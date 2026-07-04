# RMEM Gateway — Ethereum reference contract

ERC-8264 reference implementation extended with **subject-controlled lease
delegation** and **hash-commitment storage**. Mirrors the off-chain Python
gateway (`../rmem-gateway.py`) on EVM: same auth model (subject OR scoped Body
Lease), same "ciphertext at rest, hash on chain" posture.

## Layout

```
contracts/
  src/
    IAgentMemoryAccess.sol      ERC-8264 interface (verbatim)
    RmemMemoryRegistry.sol      reference impl + Body Lease + MemoryAnchored
  test/
    RmemMemoryRegistry.t.sol    Foundry tests
  script/
    DeployRmemRegistry.s.sol    deploy to any --rpc-url
  foundry.toml
```

## Design choices vs. the spec's `SimpleAgentMemory`

| | SimpleAgentMemory (spec) | RmemMemoryRegistry (here) |
|---|---|---|
| `writeMemory` data | stored verbatim as `bytes` | hashed to `keccak256(data)`, 32 B stored |
| `readMemory` returns | the stored `bytes` | the 32-byte commitment (`abi.encodePacked`) |
| `exportMemory` returns | `(bytes32[], bytes[])` of full payloads | `(bytes32[], bytes[])` of 32-byte commitments, tombstones filtered |
| Authorization | subject-only (`msg.sender == subject`) | subject **OR** active scoped Body Lease |
| Lease management | n/a | `grantLease(body, scopes, expiresAt)` / `revokeLease(body)` |
| Anchoring | n/a | `anchorMemoryRoot(subject, root, commitType)` emits `MemoryAnchored` |
| ERC-165 | yes | yes |

Both designs satisfy the ERC-8264 interface; only the *storage and
authorization* layers differ. The spec is explicit that those layers are
implementor-defined.

### Scope bitmap

```
SCOPE_READ   = 1
SCOPE_WRITE  = 2
SCOPE_DELETE = 4
SCOPE_EXPORT = 8
```

A lease grants `scopes` (OR'd) and an `expiresAt` (unix seconds). The check is
`(lease.scopes & required) == required && lease.expiresAt > block.timestamp`.

## Build & test

Requires [Foundry](https://book.getfoundry.sh/). On Windows, install via
WSL (Ubuntu) or use the native installer.

```bash
# from contracts/
forge install foundry-rs/forge-std    # one-time
forge build
forge test -vvv
```

## Deploy

```bash
# Sepolia
export DEPLOYER_PRIVATE_KEY=0x...
export SEPOLIA_RPC_URL=https://...
export ETHERSCAN_API_KEY=...
forge script script/DeployRmemRegistry.s.sol:Deploy \
  --rpc-url $SEPOLIA_RPC_URL --broadcast --verify

# Base Sepolia
export BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
export BASESCAN_API_KEY=...
forge script script/DeployRmemRegistry.s.sol:Deploy \
  --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast --verify
```

The deployed address goes into ERC-8264 PR #1752's **Reference Implementation**
section and ERC-8269 PR #1763's companion section.

## Security notes

- The contract holds **no secrets**. It stores only `keccak256` commitments;
  raw memory lives off-chain encrypted in the Python vault.
- A lease is **scoped + time-bounded + revocable**. The subject can always
  `revokeLease(body)` immediately.
- `exportMemory` filters tombstoned records; the `_index` array is not pruned
  on `deleteMemory` (gas), so `commitmentOf(subject, rid) == 0` is the
  authoritative "deleted" check.
- Deletion finality: an on-chain `MemoryDeleted` event is permanent; the
  commitment slot is cleared. The off-chain payload (whose hash was committed)
  must be purged in the vault — that's what `rmem-vault.py tombstone_record`
  does.
- `anchorMemoryRoot` requires SCOPE_WRITE — i.e., the subject or a leased
  body with write scope. This matches the off-chain semantics where the
  body that wrote the memory may also anchor its current root.
