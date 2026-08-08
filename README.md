# rmem-gateway

Reference implementation of [ERC-8264](standards/erc-8264.md) "AI Agent Memory Access Rights" plus the companion [ERC-8269 "Body Lease and Credential Broker"](https://github.com/ethereum/ERCs/pull/1763) draft and the chain-agnostic [CAAP-Capsule spec](standards/capsule-spec-v0.1.md). Also hosts [CAAP-ROBOTID v1.1](CAAP_ROBOTID_v1.1_MODULE.md), the identity-layer module these specs slot into.

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
| `standards/capsule-spec-v0.1.md` | Chain-agnostic CAAP-Capsule v0.1 format; companion ERC-8269 "Body Lease and Credential Broker" is [ethereum/ERCs PR #1763](https://github.com/ethereum/ERCs/pull/1763) |
| [`standards/caap-ticket-v0.1.md`](standards/caap-ticket-v0.1.md) | CAAP-TICKET v0.1 — dead-man capability layer for leased bodies: deterministic CBOR/`COSE_Sign1` ticket, issuance handshake, dual-clock expiry, settlement binding, mesh relay-only rules |
| [`standards/caap-telemetry-v0.1.md`](standards/caap-telemetry-v0.1.md) | CAAP-TELEMETRY v0.1 — evidence wire layer: domain-separated content trees, capture/receipt/terminal/intent CBOR schemas, disclosure bundles, witness attestations |
| [`standards/m1-failure-state-spec-v0.1.md`](standards/m1-failure-state-spec-v0.1.md) | M1 failure-state spec — normative failure taxonomy, timing model, casualty criteria, and settlement matrix for CAAP-WIPE + LeaseBond |
| [`embodied-ai-infrastructure-brief.md`](embodied-ai-infrastructure-brief.md) | Architecture brief (M0–M2): gap designs, safety kernel, adversarial-telemetry model, and sequencing across the stack |

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
| **D-EVM** | `rmem-evm.py` + `contracts/RmemMemoryRegistry.sol` — EVM ops + `MemoryAnchored` event anchoring | shipped, **21/21 Foundry tests** (v0.3.4), **deployed on Sepolia + Base Sepolia + BNB Testnet** (both v0.1 and v0.3.4) |
| E | Mainnet anchoring via local Bitcoin node | not in v0.1; gated on independent on-chain proof from D |

### v0.1 anchors (2026-05-22; bare-root format)

- Bitcoin mutinynet (OP_RETURN v0x01): [`224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a`](https://mutinynet.com/tx/224958929c193488e639715d278d98bd82b742b579a110a6b8309ce903969f0a)
- Ethereum Sepolia (`RmemMemoryRegistry` v0.1): [`0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e`](https://sepolia.etherscan.io/address/0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e)
- Base Sepolia (`RmemMemoryRegistry` v0.1): [`0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e`](https://sepolia.basescan.org/address/0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e)
- BNB Smart Chain Testnet (`RmemMemoryRegistry` v0.1): [`0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e`](https://testnet.bscscan.com/address/0x2cf251859d172e292aa6a4ef4bbf7621b8117e4e)

All v0.1 EVM deployments are at the same address — deterministic from deployer EOA + nonce 0 — and each passes `supportsInterface(0x13a642d4)` (ERC-8264) and `supportsInterface(0x01ffc9a7)` (ERC-165).

### v0.3.4 anchors (2026-05-23; Def. 4 Merkle + tagged-digest format)

Closes the three spec-conformance gaps surfaced by the engineering audit of `agent_memory_rights_v0_3_4`: `canonProfile` enforced, explicit `revokedAt` mapping on both layers, Def. 4 Merkle with full Table 1 domain-separation tags. Full audit + on-chain evidence in [`TESTNET_REPORT_v2.md`](TESTNET_REPORT_v2.md).

- Bitcoin mutinynet (OP_RETURN v0x02; tagged `H(CAAP_ANCHOR || R_X || "bitcoin-mutinynet")`): [`0e595f6786d4ad8f0f87fc112732d68a40003cb7ddd0997de50a27f46f334c5a`](https://mutinynet.com/tx/0e595f6786d4ad8f0f87fc112732d68a40003cb7ddd0997de50a27f46f334c5a)
- Ethereum Sepolia (`RmemMemoryRegistry` v0.3.4 with `revokedAt`): [`0x31dc2367b3aa512a5e58a2e116fd956276723405`](https://sepolia.etherscan.io/address/0x31dc2367b3aa512a5e58a2e116fd956276723405)
- Base Sepolia (`RmemMemoryRegistry` v0.3.4 with `revokedAt`): [`0xe03a97717ab166c555da4bb9f09e719135e521b8`](https://sepolia.basescan.org/address/0xe03a97717ab166c555da4bb9f09e719135e521b8)
- BNB Smart Chain Testnet (`RmemMemoryRegistry` v0.3.4 with `revokedAt`): [`0xe03a97717ab166c555da4bb9f09e719135e521b8`](https://testnet.bscscan.com/address/0xe03a97717ab166c555da4bb9f09e719135e521b8)

On each EVM chain, a paired `grantLease` → `revokeLease` was issued and `revokedAt(subject, body)` read both before (`0`) and after (a non-zero Unix timestamp), demonstrating the spec's `¬Revoked` conjunct fires independently of the lease's still-future `expiresAt`. Full txid list in [`TESTNET_REPORT_v2.md`](TESTNET_REPORT_v2.md).

### v0.3.4 on Solana (2026-05-23; non-EVM chain-agnostic proof)

The chain-agnostic claim was further exercised on Solana devnet across two surfaces. Source: [`solana-program/`](solana-program/).

- **v0x02 CAAP anchor via Memo program** (Memo v2 enforces UTF-8; wire format is `caap1:` + hex of the canonical 38-byte payload, which decodes byte-for-byte to what Bitcoin OP_RETURN carries): [`kCUwcmdShwrn7j5QSPpsPnxrBYYMZ6LJDxW1JP7tNaVeBj6UdGeRj2JVDuLAyf8wBhLAbwxCe7QyVDWrBoz71fp`](https://explorer.solana.com/tx/kCUwcmdShwrn7j5QSPpsPnxrBYYMZ6LJDxW1JP7tNaVeBj6UdGeRj2JVDuLAyf8wBhLAbwxCe7QyVDWrBoz71fp?cluster=devnet)
- **`rmem-solana-registry` program** (native Solana, no Anchor framework; mirrors `RmemMemoryRegistry.sol` semantically with PDA-per-(subject,body) lease accounts containing explicit `revoked_at: i64`): [`2BcJ1EYpBrphcTSmbpeaxzWwCZegjBvXPDmbAMoxN7TP`](https://explorer.solana.com/address/2BcJ1EYpBrphcTSmbpeaxzWwCZegjBvXPDmbAMoxN7TP?cluster=devnet)

A paired `grantLease` → `revokeLease` against PDA [`ADEVfKui9y43UN7adcVGk2v7V4LoSNk1chMPaQpehevM`](https://explorer.solana.com/address/ADEVfKui9y43UN7adcVGk2v7V4LoSNk1chMPaQpehevM?cluster=devnet) left `expires_at` at year 2027 while `revoked_at` was set to the block-time Unix timestamp — same `¬Revoked` property demonstrated on a non-EVM chain with a fundamentally different account model.

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
