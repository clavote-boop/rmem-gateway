# rmem-gateway

Reference implementation of [ERC-8264](standards/erc-8264.md) "AI Agent Memory Access Rights" plus the companion [Portable Agent Memory Capsule and Body Lease](standards/erc-portable-agent-memory-capsule-DRAFT.md) draft. Also hosts [CAAP-ROBOTID v1.1](CAAP_ROBOTID_v1.1_MODULE.md), the identity-layer module these specs slot into.

License: **CC0 1.0 Universal** (open standards arm). See [LICENSE](LICENSE.md).

## What's here

| File | Purpose |
|---|---|
| [`SPEC_v0.1.md`](SPEC_v0.1.md) | Implementation spec |
| [`CAAP_ROBOTID_v1.1_MODULE.md`](CAAP_ROBOTID_v1.1_MODULE.md) | Identity-layer module — Soul ID / Body ID / Wallet ID |
| `rmem-vault.py` | Encrypted local store + SQLite index + hash-chained audit log |
| `rmem-gateway.py` | The four ERC-8264 ops + **EIP-191 and EIP-712** owner-sig verification + capsule export + lease auth + `--also-anchor` |
| `rmem-lease.py` | Body Lease primitive (issue / verify / scope-check / revoke) |
| `rmem-anchor.py` | OP_RETURN commitment of capsule Merkle roots on a Bitcoin chain |
| `rmem-migrate.py` | freeze / verify-capsule / mount (decrypt+re-encrypt across vault keys) |
| `rmem-evm.py` | EVM client (web3.py) for `RmemMemoryRegistry`: write/read/anchor/lease + `anchor-vault` |
| [`contracts/`](contracts/) | Solidity `RmemMemoryRegistry` (ERC-8264 + on-chain lease registry + `MemoryAnchored`) + Foundry tests + Sepolia/Base Sepolia deploy script |
| `standards/erc-8264.md` | ERC-8264 source — also submitted to [ethereum/ERCs PR #1752](https://github.com/ethereum/ERCs/pull/1752) |
| `standards/erc-portable-agent-memory-capsule-DRAFT.md` | Companion ERC draft — submission pending |

## Quick start

```bash
git clone https://github.com/clavote-boop/rmem-gateway
cd rmem-gateway
python -m pip install -r requirements.txt

# Each module ships a self-contained selftest
for m in vault gateway lease anchor migrate; do
  python rmem-$m.py selftest
done
```

All five should print `selftest: OK`. The tests cover happy path, tamper detection, signature verification, scope enforcement, capsule round-trip, and OP_RETURN extraction.

## Status

| Phase | Module | State |
|---|---|---|
| A | `rmem-vault.py` — vault + audit chain | shipped, selftest |
| B | `rmem-gateway.py` — four ERC-8264 ops + capsule export + EIP-712 | shipped, selftest |
| C | `rmem-lease.py` + gateway lease auth + `rmem-migrate.py` | shipped, selftest |
| D | `rmem-anchor.py` — OP_RETURN anchoring (signet / mutinynet / testnet) | shipped, live-verified |
| **D-EVM** | `rmem-evm.py` + `contracts/RmemMemoryRegistry.sol` — EVM ops + `MemoryAnchored` event anchoring | shipped, 19/19 Foundry tests, **deployed on Sepolia + Base Sepolia** |
| E | Mainnet anchoring via local Bitcoin node | not in v0.1; gated on independent on-chain proof from D |

Live anchors verified 2026-05-22:

- Bitcoin mutinynet (OP_RETURN): [`224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a`](https://mutinynet.com/tx/224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a)
- Ethereum Sepolia (`RmemMemoryRegistry`): [`0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e`](https://sepolia.etherscan.io/address/0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e)
- Base Sepolia (`RmemMemoryRegistry`): [`0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e`](https://sepolia.basescan.org/address/0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e)

Both EVM deployments pass `supportsInterface(0x13a642d4)` (ERC-8264) and `supportsInterface(0x01ffc9a7)` (ERC-165). The two addresses are identical by design (same deployer EOA + nonce 0).

## Composition

The Rationale sections of both ERCs detail composition with existing standards. Summary:

- **EIP-7702** (Final) — Body Lease scope/expiry semantics align with 7702 authorization-list semantics for joint issuance.
- **ERC-7857** (Final) — different surface (NFT-coupled re-encryption on transfer).
- **ERC-8181** ([PR #1579](https://github.com/ethereum/ERCs/pull/1579)) — closest neighbour; composes (8181 = container/sovereignty; this = rights + wire format).
- **ERC-8118** ([PR #1450](https://github.com/ethereum/ERCs/pull/1450)) — on-chain action authorisation; the Credential Broker rule in the companion ERC is the off-chain analogue.
- **MCP SEP-2072 "Memory Portals"** + SEP-2342 MIF — different layer (MCP protocol); complementary. An implementor MAY use MIF as the payload format inside a Capsule.
- **W3C did:btc** — CAAP-ROBOTID's Soul ID format aligns where applicable.

## Author

Clavote ([@clavote-boop](https://github.com/clavote-boop)).

Discussion: see the eth-magicians thread linked from each ERC's `discussions-to`.
