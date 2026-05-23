#!/usr/bin/env python3
"""rmem-evm -- Phase D-EVM client for the RmemMemoryRegistry contract.

Off-chain Python wrapper around the deployed Solidity registry. Same posture
as the Bitcoin OP_RETURN anchor: the gateway never sees a private key it
hasn't been handed, and on-chain state is hash-commitments only.

Three usage modes:

1. **Compose with the vault.** After `rmem-gateway write` commits a record
   to the local vault, call `write-commitment` to publish the same record's
   payload_hash to the registry. Off-chain ciphertext + on-chain commitment.

2. **EVM-side anchoring.** `anchor-memory-root --network sepolia` calls
   `anchorMemoryRoot` -- emits `MemoryAnchored(subject, root, type)`. Parallel
   path to the OP_RETURN anchor in `rmem-anchor.py`.

3. **Lease management on chain.** `grant-lease` / `revoke-lease` -- the
   subject's on-chain delegation that mirrors the off-chain Body Lease in
   `rmem-lease.py`.

Security invariants:
- The private key is supplied per invocation (file or env), never persisted.
- It is a low-value funded testnet key. NOT the Soul ID key, NOT a wallet key.
- The Soul ID and on-chain `subject` address derive from the same secp256k1
  key (Bitcoin + Ethereum share the curve); they are reconciled by the caller,
  not by this module.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Optional

try:
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware
    from eth_account import Account
except ImportError:
    sys.exit("rmem-evm requires 'web3' and 'eth-account'. pip install -r requirements.txt")


# ---- Import Phase A vault library (for compose-with-vault commands) ----

def _import_vault():
    spec_path = Path(__file__).resolve().parent / "rmem-vault.py"
    if not spec_path.exists():
        sys.exit(f"rmem-vault.py not found at {spec_path}")
    spec = importlib.util.spec_from_file_location("rmem_vault", spec_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["rmem_vault"] = module
    spec.loader.exec_module(module)
    return module


_vault = _import_vault()
VaultStore = _vault.VaultStore
DEFAULT_VAULT_DIR = _vault.DEFAULT_VAULT_DIR


# ---- ABI ----

ABI_PATH = Path(__file__).resolve().parent / "rmem-evm-abi.json"
if not ABI_PATH.exists():
    sys.exit(f"ABI file not found: {ABI_PATH}")
ABI = json.loads(ABI_PATH.read_text())


# ---- Scope bitmap (mirror RmemMemoryRegistry.sol) ----

SCOPE_READ   = 1
SCOPE_WRITE  = 2
SCOPE_DELETE = 4
SCOPE_EXPORT = 8

COMMIT_CAPSULE_ROOT = 1
COMMIT_MEMORY_ROOT  = 2


# ---- Network presets ----

NETWORK_PRESETS = {
    "sepolia":      {"chain_id": 11155111, "is_poa": False},
    "base-sepolia": {"chain_id": 84532,    "is_poa": False},
    "anvil":        {"chain_id": 31337,    "is_poa": False},
}


def _load_private_key(arg: Optional[str]) -> str:
    """Load a hex private key from --key-file or DEPLOYER_PRIVATE_KEY env."""
    if arg:
        return Path(arg).read_text().strip()
    env = os.environ.get("DEPLOYER_PRIVATE_KEY")
    if env:
        return env.strip()
    sys.exit("private key required: pass --key-file <path> or set DEPLOYER_PRIVATE_KEY")


def _b32(value: str) -> bytes:
    """Accept '0x...' / 'sha256:hex' / raw hex; return 32 bytes."""
    s = value
    if s.startswith("sha256:"):
        s = s.split(":", 1)[1]
    if s.startswith("0x"):
        s = s[2:]
    b = bytes.fromhex(s)
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    return b


class RegistryClient:
    """Thin wrapper over web3.py for RmemMemoryRegistry.

    Construct with rpc_url + contract_address; pass private_key only when
    you intend to send a write tx. Read-only operations never need a key.
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: Optional[str] = None,
        chain_id: Optional[int] = None,
        is_poa: bool = False,
    ):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if is_poa:
            self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        if not self.w3.is_connected():
            raise ConnectionError(f"could not connect to RPC at {rpc_url}")
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address), abi=ABI,
        )
        self.chain_id = chain_id or self.w3.eth.chain_id
        if private_key:
            self.account = Account.from_key(private_key)
        else:
            self.account = None

    # ---- read ops ----

    def commitment_of(self, subject: str, record_id: bytes) -> bytes:
        return self.contract.functions.commitmentOf(
            Web3.to_checksum_address(subject), record_id,
        ).call()

    def index_of(self, subject: str) -> list[bytes]:
        return self.contract.functions.indexOf(
            Web3.to_checksum_address(subject),
        ).call()

    def get_lease(self, subject: str, body: str) -> dict:
        expires_at, scopes = self.contract.functions.leases(
            Web3.to_checksum_address(subject),
            Web3.to_checksum_address(body),
        ).call()
        return {"expires_at": expires_at, "scopes": scopes}

    def supports_interface(self, interface_id: bytes) -> bool:
        return self.contract.functions.supportsInterface(interface_id).call()

    def read_memory(self, subject: str, record_id: bytes, caller: Optional[str] = None) -> bytes:
        """Off-chain helper: pull the commitment via `commitmentOf` (no auth required)
        rather than the auth-gated `readMemory`. Equivalent observable state."""
        return self.commitment_of(subject, record_id)

    # ---- write ops (signed by self.account) ----

    def _send(self, fn) -> dict:
        if self.account is None:
            sys.exit("write op requires a private key (--key-file or DEPLOYER_PRIVATE_KEY)")
        nonce = self.w3.eth.get_transaction_count(self.account.address)
        # Use 1559 fees where supported (Sepolia / Base Sepolia / anvil all do).
        tx = fn.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "chainId": self.chain_id,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        if receipt.status != 1:
            raise RuntimeError(f"tx reverted: {tx_hash.hex()}")
        return {
            "tx_hash": "0x" + tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
        }

    def write_memory(self, subject: str, record_id: bytes, data: bytes) -> dict:
        return self._send(self.contract.functions.writeMemory(
            Web3.to_checksum_address(subject), record_id, data,
        ))

    def delete_memory(self, subject: str, record_id: bytes) -> dict:
        return self._send(self.contract.functions.deleteMemory(
            Web3.to_checksum_address(subject), record_id,
        ))

    def grant_lease(self, body: str, scopes: int, expires_at: int) -> dict:
        return self._send(self.contract.functions.grantLease(
            Web3.to_checksum_address(body), scopes, expires_at,
        ))

    def revoke_lease(self, body: str) -> dict:
        return self._send(self.contract.functions.revokeLease(
            Web3.to_checksum_address(body),
        ))

    def anchor_memory_root(
        self, subject: str, merkle_root: bytes, commit_type: int,
    ) -> dict:
        return self._send(self.contract.functions.anchorMemoryRoot(
            Web3.to_checksum_address(subject), merkle_root, commit_type,
        ))


# ---- CLI ----

def _client_from_args(args: argparse.Namespace, need_key: bool) -> RegistryClient:
    if not args.rpc_url:
        args.rpc_url = os.environ.get(
            "SEPOLIA_RPC_URL" if args.network == "sepolia"
            else "BASE_SEPOLIA_RPC_URL" if args.network == "base-sepolia"
            else "RPC_URL"
        )
    if not args.rpc_url:
        sys.exit("--rpc-url required (or set SEPOLIA_RPC_URL / BASE_SEPOLIA_RPC_URL / RPC_URL)")
    if not args.contract:
        args.contract = os.environ.get("RMEM_REGISTRY_ADDRESS")
    if not args.contract:
        sys.exit("--contract required (or set RMEM_REGISTRY_ADDRESS)")
    pk = _load_private_key(args.key_file) if need_key else None
    preset = NETWORK_PRESETS.get(args.network, {})
    return RegistryClient(
        rpc_url=args.rpc_url,
        contract_address=args.contract,
        private_key=pk,
        chain_id=preset.get("chain_id"),
        is_poa=preset.get("is_poa", False),
    )


def cmd_supports(args):
    c = _client_from_args(args, need_key=False)
    # ERC-8264 interfaceId: XOR of four selectors (see SPEC §ERC-165 Support).
    erc8264 = bytes.fromhex("9d8c8d8a")  # placeholder; real value printed below
    # Compute it locally so we don't rely on a guessed constant:
    from eth_utils import keccak as eth_keccak
    selectors = [
        eth_keccak(text="readMemory(address,bytes32)")[:4],
        eth_keccak(text="writeMemory(address,bytes32,bytes)")[:4],
        eth_keccak(text="deleteMemory(address,bytes32)")[:4],
        eth_keccak(text="exportMemory(address)")[:4],
    ]
    iid = bytes(a ^ b ^ c_ ^ d for a, b, c_, d in zip(*selectors))
    erc165 = bytes.fromhex("01ffc9a7")
    out = {
        "erc165":   c.supports_interface(erc165),
        "erc8264":  c.supports_interface(iid),
        "erc8264_interface_id": "0x" + iid.hex(),
    }
    print(json.dumps(out, indent=2))


def cmd_commitment(args):
    c = _client_from_args(args, need_key=False)
    rid = _b32(args.record)
    val = c.commitment_of(args.subject, rid)
    print(json.dumps({"subject": args.subject, "record": "0x" + rid.hex(),
                      "commitment": "0x" + val.hex(),
                      "present": val != b"\x00" * 32}, indent=2))


def cmd_write(args):
    c = _client_from_args(args, need_key=True)
    rid = _b32(args.record)
    if args.payload == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.payload).read_bytes()
    receipt = c.write_memory(args.subject, rid, data)
    print(json.dumps({**receipt, "subject": args.subject,
                      "record": "0x" + rid.hex()}, indent=2))


def cmd_delete(args):
    c = _client_from_args(args, need_key=True)
    rid = _b32(args.record)
    receipt = c.delete_memory(args.subject, rid)
    print(json.dumps({**receipt, "subject": args.subject,
                      "record": "0x" + rid.hex()}, indent=2))


def cmd_grant_lease(args):
    c = _client_from_args(args, need_key=True)
    import time
    expires_at = int(time.time()) + args.hours * 3600
    receipt = c.grant_lease(args.body, args.scopes, expires_at)
    print(json.dumps({**receipt, "body": args.body, "scopes": args.scopes,
                      "expires_at": expires_at}, indent=2))


def cmd_revoke_lease(args):
    c = _client_from_args(args, need_key=True)
    receipt = c.revoke_lease(args.body)
    print(json.dumps({**receipt, "body": args.body}, indent=2))


def cmd_get_lease(args):
    c = _client_from_args(args, need_key=False)
    lease = c.get_lease(args.subject, args.body)
    print(json.dumps(lease, indent=2))


def cmd_anchor(args):
    c = _client_from_args(args, need_key=True)
    commit_type = (
        COMMIT_CAPSULE_ROOT if args.type == "capsule_root"
        else COMMIT_MEMORY_ROOT
    )
    root = _b32(args.root)
    receipt = c.anchor_memory_root(args.subject, root, commit_type)
    print(json.dumps({**receipt, "subject": args.subject,
                      "merkle_root": "0x" + root.hex(),
                      "commit_type": args.type}, indent=2))


def cmd_anchor_vault(args):
    """Compose with vault: compute the memory_root over the vault's records
    for `subject` and anchor it on-chain."""
    import hashlib
    vault = VaultStore(Path(args.vault).expanduser())
    rows = vault.list_records(soul_id=args.soul, include_tombstoned=False)
    leaves = [r["payload_hash"] for r in rows]
    # Merkle root (matches rmem-anchor.py's merkle_root function).
    if not leaves:
        root_bytes = hashlib.sha256(b"").digest()
    else:
        level = [
            bytes.fromhex(h.split(":", 1)[1]) if h.startswith("sha256:") else bytes.fromhex(h)
            for h in leaves
        ]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            level = [hashlib.sha256(level[i] + level[i+1]).digest()
                     for i in range(0, len(level), 2)]
        root_bytes = level[0]
    c = _client_from_args(args, need_key=True)
    receipt = c.anchor_memory_root(args.subject, root_bytes, COMMIT_MEMORY_ROOT)
    print(json.dumps({**receipt, "subject": args.subject,
                      "soul_id": args.soul,
                      "merkle_root": "sha256:" + root_bytes.hex(),
                      "leaf_count": len(leaves)}, indent=2))


def cmd_selftest(args):
    """Offline-only: verify ABI shape, scope-bitmap constants, helper functions.

    A live test against anvil is in contracts/test/RmemMemoryRegistry.t.sol;
    Python integration is verified once a registry is deployed and SEPOLIA_RPC_URL
    + RMEM_REGISTRY_ADDRESS are set."""
    failures = []
    # ABI sanity
    function_names = {item["name"] for item in ABI if item["type"] == "function"}
    required = {"anchorMemoryRoot", "commitmentOf", "deleteMemory", "exportMemory",
                "grantLease", "indexOf", "leases", "readMemory", "revokeLease",
                "supportsInterface", "writeMemory"}
    missing = required - function_names
    if missing:
        failures.append(f"ABI missing functions: {missing}")
    # Event sanity
    event_names = {item["name"] for item in ABI if item["type"] == "event"}
    req_events = {"LeaseGranted", "LeaseRevoked", "MemoryAnchored",
                  "MemoryDeleted", "MemoryWritten"}
    if req_events - event_names:
        failures.append(f"ABI missing events: {req_events - event_names}")
    # Scope constants
    if (SCOPE_READ | SCOPE_WRITE | SCOPE_DELETE | SCOPE_EXPORT) != 0xF:
        failures.append("scope bitmap not 4-bit contiguous")
    # _b32 helpers
    try:
        if _b32("0x" + "ab" * 32) != b"\xab" * 32:
            failures.append("_b32 0x-prefixed roundtrip failed")
        if _b32("sha256:" + "cd" * 32) != b"\xcd" * 32:
            failures.append("_b32 sha256: roundtrip failed")
    except Exception as e:
        failures.append(f"_b32 raised: {e}")
    # ABI is loadable as a contract (offline, no RPC)
    try:
        w3 = Web3()
        w3.eth.contract(abi=ABI)
    except Exception as e:
        failures.append(f"ABI does not parse: {e}")

    if failures:
        print("selftest: FAIL")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("selftest: OK")


def main():
    parser = argparse.ArgumentParser(
        prog="rmem-evm",
        description="rmem-evm -- Phase D-EVM client for RmemMemoryRegistry",
    )
    parser.add_argument("--network", default="sepolia",
                        choices=["sepolia", "base-sepolia", "anvil"],
                        help="network preset (default: sepolia)")
    parser.add_argument("--rpc-url", default=None,
                        help="RPC URL (else SEPOLIA_RPC_URL / BASE_SEPOLIA_RPC_URL / RPC_URL)")
    parser.add_argument("--contract", default=None,
                        help="registry contract address (else RMEM_REGISTRY_ADDRESS)")
    parser.add_argument("--key-file", default=None,
                        help="path to file containing 0x... private key "
                             "(else DEPLOYER_PRIVATE_KEY env)")
    parser.add_argument("--vault", default=str(DEFAULT_VAULT_DIR),
                        help=f"vault root dir (default: {DEFAULT_VAULT_DIR})")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("supports", help="check ERC-165 interface support")
    p.set_defaults(func=cmd_supports)

    p = sub.add_parser("commitment", help="read commitmentOf(subject, recordId)")
    p.add_argument("--subject", required=True)
    p.add_argument("--record", required=True, help="record id (0x... or sha256:...)")
    p.set_defaults(func=cmd_commitment)

    p = sub.add_parser("write", help="writeMemory(subject, recordId, data)")
    p.add_argument("--subject", required=True)
    p.add_argument("--record", required=True)
    p.add_argument("--payload", required=True, help="file path or '-' for stdin")
    p.set_defaults(func=cmd_write)

    p = sub.add_parser("delete", help="deleteMemory(subject, recordId)")
    p.add_argument("--subject", required=True)
    p.add_argument("--record", required=True)
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("grant-lease",
                       help="grantLease(body, scopes, expiresAt) -- caller is subject")
    p.add_argument("--body", required=True)
    p.add_argument("--scopes", type=int, required=True,
                   help="OR of: 1=read, 2=write, 4=delete, 8=export")
    p.add_argument("--hours", type=int, default=24, help="lease lifetime in hours")
    p.set_defaults(func=cmd_grant_lease)

    p = sub.add_parser("revoke-lease", help="revokeLease(body)")
    p.add_argument("--body", required=True)
    p.set_defaults(func=cmd_revoke_lease)

    p = sub.add_parser("get-lease", help="read leases(subject, body)")
    p.add_argument("--subject", required=True)
    p.add_argument("--body", required=True)
    p.set_defaults(func=cmd_get_lease)

    p = sub.add_parser("anchor", help="anchorMemoryRoot -- emit MemoryAnchored event")
    p.add_argument("--subject", required=True)
    p.add_argument("--root", required=True, help="merkle root (0x... or sha256:...)")
    p.add_argument("--type", default="memory_root",
                   choices=["capsule_root", "memory_root"])
    p.set_defaults(func=cmd_anchor)

    p = sub.add_parser("anchor-vault",
                       help="compute memory_root from local vault and anchor it on-chain")
    p.add_argument("--subject", required=True, help="on-chain subject address")
    p.add_argument("--soul", required=True, help="vault Soul ID (did:btc:...)")
    p.set_defaults(func=cmd_anchor_vault)

    p = sub.add_parser("selftest", help="offline ABI / helper sanity test")
    p.set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
