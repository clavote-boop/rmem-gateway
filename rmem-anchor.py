#!/usr/bin/env python3
"""rmem-anchor -- Phase D of the RMEM Gateway.

CAMIA anchoring: commits capsule / memory-state fingerprints to Bitcoin via a
single standard OP_RETURN. testnet/signet first per Work Plan D.2; mainnet
(Phase E, via Bunny's Knots node) is gated on independent testnet proof verifying.

Security invariants:
- The anchoring private key is supplied per invocation (file or env), never
  stored. It is a separate low-value hot key -- never the Clavonode Lightning
  key or any production key (Work Plan D.2 / SPEC v0.1 \xa711.4).
- The OP_RETURN payload is a fixed 38-byte CAAP commitment:
      4B magic "CAAP" | 1B version | 1B commit-type | 32B sha256 Merkle root
  Single output, single push, datacarrier-standard. Well within Knots'
  datacarriersize=83 policy; no inscriptions, no multi-push.
- An anchor is only marked "verified" after the tx is independently re-fetched
  from a public chain API and its OP_RETURN payload matched against the
  expected Merkle root. Trust the chain, not the broadcast receipt.

Supports signet (default for testnet), testnet4, mainnet (Phase E only).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from embit import script, ec, networks
    from embit.transaction import Transaction, TransactionInput, TransactionOutput
    from embit.psbt import PSBT
except ImportError:
    sys.exit("rmem-anchor requires 'embit'. pip install embit")


# ---- Import Phase A vault library ----

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
canon_json = _vault.canon_json
sha256_hex = _vault.sha256_hex
now_iso = _vault.now_iso


# ---- CAAP OP_RETURN payload format ----

CAAP_MAGIC = b"CAAP"
ANCHOR_VERSION = 0x01
COMMIT_CAPSULE_ROOT = 0x01
COMMIT_MEMORY_ROOT = 0x02
PAYLOAD_LEN = 4 + 1 + 1 + 32  # 38 bytes
MAX_OP_RETURN = 80


def build_caap_payload(merkle_root_hex: str, commit_type: int) -> bytes:
    if commit_type not in (COMMIT_CAPSULE_ROOT, COMMIT_MEMORY_ROOT):
        raise ValueError(f"invalid commit_type {commit_type}")
    root = merkle_root_hex.split(":", 1)[1] if merkle_root_hex.startswith("sha256:") \
        else merkle_root_hex
    root_bytes = bytes.fromhex(root)
    if len(root_bytes) != 32:
        raise ValueError(f"merkle root must be 32 bytes, got {len(root_bytes)}")
    payload = CAAP_MAGIC + bytes([ANCHOR_VERSION, commit_type]) + root_bytes
    assert len(payload) == PAYLOAD_LEN, f"payload length {len(payload)} != {PAYLOAD_LEN}"
    assert len(payload) <= MAX_OP_RETURN
    return payload


def parse_caap_payload(payload: bytes) -> dict:
    if len(payload) < PAYLOAD_LEN:
        return {"valid": False, "reason": f"too short ({len(payload)} bytes)"}
    if payload[:4] != CAAP_MAGIC:
        return {"valid": False, "reason": "magic mismatch"}
    version = payload[4]
    commit_type = payload[5]
    root = payload[6:6 + 32]
    if version != ANCHOR_VERSION:
        return {"valid": False, "reason": f"unsupported version {version}"}
    if commit_type not in (COMMIT_CAPSULE_ROOT, COMMIT_MEMORY_ROOT):
        return {"valid": False, "reason": f"unknown commit_type {commit_type}"}
    return {
        "valid": True,
        "version": version,
        "commit_type": commit_type,
        "commit_type_name": "capsule_root" if commit_type == COMMIT_CAPSULE_ROOT else "memory_root",
        "merkle_root": "sha256:" + root.hex(),
    }


def extract_op_return_from_tx(tx: Transaction) -> Optional[bytes]:
    """Return the data payload of the first standard OP_RETURN output, or None."""
    for out in tx.vout:
        data = out.script_pubkey.data
        if len(data) < 2 or data[0] != 0x6a:
            continue
        # Standard datacarrier: OP_RETURN <length> <data>
        push_len = data[1]
        if push_len > 75:
            # Could be OP_PUSHDATA1 (0x4c) — not standard datacarrier in Knots policy
            continue
        if len(data) != 2 + push_len:
            continue
        return data[2:2 + push_len]
    return None


# ---- Merkle root over a list of sha256 hex strings ----

def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return sha256_hex(b"")
    level = [
        bytes.fromhex(h.split(":", 1)[1]) if h.startswith("sha256:") else bytes.fromhex(h)
        for h in leaves
    ]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return "sha256:" + level[0].hex()


def compute_memory_root(vault: VaultStore, soul_id: str) -> str:
    rows = vault.list_records(soul_id=soul_id, include_tombstoned=False)
    leaves = [r["payload_hash"] for r in rows]
    return merkle_root(leaves)


# ---- anchors table (lazy create in vault.db) ----

ANCHORS_SCHEMA = """
CREATE TABLE IF NOT EXISTS anchors (
  anchor_id    TEXT PRIMARY KEY,
  network      TEXT NOT NULL,
  txid         TEXT NOT NULL,
  vout_index   INTEGER NOT NULL,
  payload_hex  TEXT NOT NULL,
  commit_type  TEXT NOT NULL,
  merkle_root  TEXT NOT NULL,
  soul_id      TEXT,
  broadcast_at TEXT NOT NULL,
  verified_at  TEXT,
  block_height INTEGER,
  status       TEXT NOT NULL DEFAULT 'broadcast'
);
CREATE INDEX IF NOT EXISTS idx_anchors_network ON anchors(network);
CREATE INDEX IF NOT EXISTS idx_anchors_soul    ON anchors(soul_id);
"""


def ensure_anchors_table(vault: VaultStore) -> None:
    conn = vault.connect()
    try:
        with conn:
            conn.executescript(ANCHORS_SCHEMA)
    finally:
        conn.close()


def record_anchor(
    vault: VaultStore, *,
    network: str, txid: str, payload: bytes, commit_type: int,
    merkle_root_hex: str, soul_id: Optional[str],
) -> str:
    ensure_anchors_table(vault)
    anchor_id = f"anchor_{int(datetime.now(timezone.utc).timestamp() * 1000):013d}_{secrets.token_hex(4)}"
    conn = vault.connect()
    try:
        with conn:
            conn.execute(
                "INSERT INTO anchors (anchor_id, network, txid, vout_index, payload_hex, "
                "commit_type, merkle_root, soul_id, broadcast_at, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (anchor_id, network, txid, 0, payload.hex(),
                 "capsule_root" if commit_type == COMMIT_CAPSULE_ROOT else "memory_root",
                 merkle_root_hex, soul_id, now_iso(), "broadcast"),
            )
            vault._append_audit(
                conn, "anchor.broadcast", soul_id, None,
                {"anchor_id": anchor_id, "network": network, "txid": txid,
                 "merkle_root": merkle_root_hex},
            )
    finally:
        conn.close()
    return anchor_id


def mark_anchor_verified(
    vault: VaultStore, anchor_id: str, block_height: Optional[int]
) -> None:
    conn = vault.connect()
    try:
        with conn:
            conn.execute(
                "UPDATE anchors SET status = 'verified', verified_at = ?, block_height = ? "
                "WHERE anchor_id = ?",
                (now_iso(), block_height, anchor_id),
            )
            vault._append_audit(
                conn, "anchor.verified", None, None,
                {"anchor_id": anchor_id, "block_height": block_height},
            )
    finally:
        conn.close()


# ---- Bitcoin tx build + sign (embit, PSBT-based) ----

def _net(network: str):
    return networks.NETWORKS[_EMBIT_NETWORK_ALIAS.get(network, network)]


def build_anchor_tx(
    utxos: list[dict], anchor_address: str, payload: bytes,
    fee_sats: int, network: str,
) -> Transaction:
    """Build a tx that spends the provided UTXOs into one OP_RETURN + optional change."""
    net = _net(network)
    # embit's TransactionInput stores txid in display (big-endian) order;
    # its write_to() reverses to little-endian wire format. Do NOT pre-reverse.
    inputs = [
        TransactionInput(bytes.fromhex(u["txid"]), int(u["vout"]))
        for u in utxos
    ]
    total_in = sum(int(u["value"]) for u in utxos)
    change = total_in - fee_sats
    if change < 0:
        raise ValueError(f"INSUFFICIENT_FUNDS: utxos sum {total_in} < fee {fee_sats}")
    op_return_script = script.Script(bytes([0x6a, len(payload)]) + payload)
    outs = [TransactionOutput(0, op_return_script)]
    if change >= 546:
        outs.append(TransactionOutput(change, script.address_to_scriptpubkey(anchor_address)))
    return Transaction(version=2, vin=inputs, vout=outs, locktime=0)


def sign_anchor_tx(
    tx: Transaction, privkey_wif: str, utxos: list[dict], network: str,
) -> str:
    """Sign all P2WPKH inputs (BIP-143) and return finalized tx hex.

    Builds the BIP-143 sighash directly via embit's Transaction.sighash_segwit
    and assigns the witness to the tx's TransactionInput. (PSBT was tried first
    but PSBT.tx is a fresh-build property, so mutations to psbt.tx.vin don't
    persist.)
    """
    priv = ec.PrivateKey.from_wif(privkey_wif)
    pub = priv.get_public_key()
    # BIP-143 script_code for P2WPKH is the P2PKH script of the pubkey:
    # OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
    script_code = script.p2pkh(pub)
    SIGHASH_ALL = 0x01
    for i, u in enumerate(utxos):
        sighash = tx.sighash_segwit(i, script_code, int(u["value"]))
        sig_der = priv.sign(sighash).serialize() + bytes([SIGHASH_ALL])
        tx.vin[i].witness = script.Witness(items=[sig_der, pub.sec()])
    return tx.serialize().hex()


def derive_p2wpkh_address(privkey_wif: str, network: str) -> str:
    priv = ec.PrivateKey.from_wif(privkey_wif)
    return script.p2wpkh(priv.get_public_key()).address(_net(network))


# ---- network I/O (UTXOs, broadcast, fetch) ----

API_BASE = {
    "signet":    "https://blockstream.info/signet/api",
    "testnet":   "https://blockstream.info/testnet/api",
    "mainnet":   "https://blockstream.info/api",
    "mutinynet": "https://mutinynet.com/api",
}

# Networks that use the same address format / embit params as public signet
# (mutinynet is a separate chain but shares the testnet `tb1...` prefix and protocol).
_EMBIT_NETWORK_ALIAS = {
    "mutinynet": "signet",
}


def _http(url: str, method: str = "GET", data: Optional[bytes] = None,
          timeout: int = 15) -> str:
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            # mutinynet's mempool.space deployment rejects short UAs (403); use a browser UA.
            "User-Agent": "Mozilla/5.0 (rmem-anchor/0.1)",
            "Content-Type": "text/plain" if method == "POST" else "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def fetch_utxos(address: str, network: str) -> list[dict]:
    return json.loads(_http(f"{API_BASE[network]}/address/{address}/utxo"))


def broadcast_tx(tx_hex: str, network: str) -> str:
    return _http(f"{API_BASE[network]}/tx", method="POST", data=tx_hex.encode()).strip()


def fetch_tx(txid: str, network: str) -> dict:
    return json.loads(_http(f"{API_BASE[network]}/tx/{txid}"))


# ---- Sovereign broadcast via Bunny's Knots node (SSH + RPC) ----

KNOTS_RPC_DEFAULTS = {
    "ssh_target":    "umbrel@100.112.55.13",
    "ssh_key":       str(Path.home() / ".ssh" / "id_ed25519_umbrel"),
    "cookie_path":   "~/umbrel/app-data/bitcoin-knots/data/bitcoin/.cookie",
    "rpc_url":       "http://127.0.0.1:9332/",
}


def broadcast_via_knots_rpc(
    tx_hex: str, *,
    ssh_target: Optional[str] = None, ssh_key: Optional[str] = None,
    cookie_path: Optional[str] = None, rpc_url: Optional[str] = None,
    timeout_seconds: int = 30,
) -> str:
    """Broadcast a raw tx through Bunny's Knots node via SSH + Bitcoin Core RPC.

    Returns txid on success. Raises ValueError with a clear reason on failure
    (SSH error, JSON error, or RPC rejection).
    """
    import subprocess
    ssh_target  = ssh_target  or KNOTS_RPC_DEFAULTS["ssh_target"]
    ssh_key     = ssh_key     or KNOTS_RPC_DEFAULTS["ssh_key"]
    cookie_path = cookie_path or KNOTS_RPC_DEFAULTS["cookie_path"]
    rpc_url     = rpc_url     or KNOTS_RPC_DEFAULTS["rpc_url"]

    rpc_body = json.dumps({
        "jsonrpc": "1.0", "id": "rmem-anchor",
        "method": "sendrawtransaction", "params": [tx_hex],
    })
    # Build the remote command: read cookie file, POST to local Knots RPC.
    # The cookie file holds the "__cookie__:<random>" creds; never leaves Bunny.
    remote_cmd = (
        f"curl -s --max-time 20 "
        f"--user $(cat {cookie_path}) "
        f"--data-binary {json.dumps(rpc_body)} "
        f"-H 'content-type:text/plain;' {rpc_url}"
    )
    cmd = [
        "ssh", "-i", ssh_key,
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
        "-o", "StrictHostKeyChecking=accept-new",
        ssh_target, remote_cmd,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        raise ValueError(
            f"BROADCAST_TIMEOUT: SSH to {ssh_target} took >{timeout_seconds}s"
        )
    except FileNotFoundError:
        raise ValueError("SSH_NOT_FOUND: 'ssh' executable not on PATH")
    if result.returncode != 0:
        raise ValueError(
            f"SSH command failed (rc={result.returncode}): {result.stderr.strip()}"
        )
    out = result.stdout.strip()
    if not out:
        raise ValueError("Knots RPC returned empty response")
    try:
        response = json.loads(out)
    except json.JSONDecodeError:
        raise ValueError(f"Knots RPC returned non-JSON: {out[:200]}")
    if response.get("error"):
        raise ValueError(f"Knots RPC error: {response['error']}")
    txid = response.get("result")
    if not txid or not isinstance(txid, str) or len(txid) != 64:
        raise ValueError(f"Knots RPC: unexpected result shape: {response}")
    return txid


# ---- verification ----

def verify_anchor_onchain(txid: str, expected_root_hex: str, network: str) -> dict:
    """Re-fetch a tx from the chain, parse its OP_RETURN, compare to expected root."""
    tx_data = fetch_tx(txid, network)
    op_return_payload = None
    for vout in tx_data.get("vout", []):
        spk = vout.get("scriptpubkey", "")
        spk_bytes = bytes.fromhex(spk)
        if len(spk_bytes) >= 2 and spk_bytes[0] == 0x6a:
            push_len = spk_bytes[1]
            if 2 + push_len == len(spk_bytes):
                op_return_payload = spk_bytes[2:]
                break
    if op_return_payload is None:
        return {"verified": False, "reason": "no OP_RETURN in tx"}
    parsed = parse_caap_payload(op_return_payload)
    if not parsed["valid"]:
        return {"verified": False, "reason": parsed["reason"]}
    expected = expected_root_hex if expected_root_hex.startswith("sha256:") \
        else "sha256:" + expected_root_hex
    if parsed["merkle_root"] != expected:
        return {"verified": False, "reason": "merkle root mismatch",
                "onchain": parsed["merkle_root"], "expected": expected}
    return {
        "verified": True,
        "merkle_root": parsed["merkle_root"],
        "commit_type": parsed["commit_type_name"],
        "block_height": tx_data.get("status", {}).get("block_height"),
    }


# ---- CLI ----

def _vault_for(args: argparse.Namespace) -> VaultStore:
    return VaultStore(Path(args.vault).expanduser())


def _load_anchor_key(arg: Optional[str]) -> str:
    """Load anchor WIF. Priority: --anchor-key path > ANCHOR_KEY_WIF env. Never persisted."""
    if arg:
        return Path(arg).read_text().strip()
    env = os.environ.get("ANCHOR_KEY_WIF")
    if env:
        return env.strip()
    sys.exit("anchor key required: pass --anchor-key <path> or set ANCHOR_KEY_WIF")


def cmd_anchor_memory(args: argparse.Namespace) -> None:
    vault = _vault_for(args)
    wif = _load_anchor_key(args.anchor_key)
    anchor_addr = derive_p2wpkh_address(wif, args.network)
    root = compute_memory_root(vault, args.soul)
    payload = build_caap_payload(root, COMMIT_MEMORY_ROOT)
    utxos = fetch_utxos(anchor_addr, args.network)
    if not utxos:
        sys.exit(f"no UTXOs at {anchor_addr} on {args.network}; fund the address first")
    tx = build_anchor_tx(utxos, anchor_addr, payload, args.fee, args.network)
    tx_hex = sign_anchor_tx(tx, wif, utxos, args.network)
    if args.dry_run:
        print(json.dumps({"dry_run": True, "anchor_address": anchor_addr,
                          "merkle_root": root, "payload_hex": payload.hex(),
                          "tx_hex": tx_hex, "tx_size": len(tx_hex) // 2,
                          "broadcast_via": args.broadcast_via}, indent=2))
        return
    if args.broadcast_via == "knots-rpc":
        try:
            txid = broadcast_via_knots_rpc(
                tx_hex,
                ssh_target=args.ssh_target,
                ssh_key=args.ssh_key,
            )
        except ValueError as e:
            sys.exit(f"sovereign broadcast (knots-rpc) failed: {e}")
    else:
        txid = broadcast_tx(tx_hex, args.network)
    anchor_id = record_anchor(
        vault, network=args.network, txid=txid, payload=payload,
        commit_type=COMMIT_MEMORY_ROOT, merkle_root_hex=root, soul_id=args.soul,
    )
    print(json.dumps({"anchor_id": anchor_id, "txid": txid, "network": args.network,
                      "broadcast_via": args.broadcast_via,
                      "merkle_root": root}, indent=2))


def cmd_verify(args: argparse.Namespace) -> None:
    vault = _vault_for(args)
    ensure_anchors_table(vault)
    conn = vault.connect()
    try:
        row = conn.execute(
            "SELECT * FROM anchors WHERE anchor_id = ?", (args.anchor,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        sys.exit(f"anchor {args.anchor} not found")
    result = verify_anchor_onchain(row["txid"], row["merkle_root"], row["network"])
    if result["verified"]:
        mark_anchor_verified(vault, args.anchor, result.get("block_height"))
    print(json.dumps(result, indent=2))


def cmd_list(args: argparse.Namespace) -> None:
    vault = _vault_for(args)
    ensure_anchors_table(vault)
    conn = vault.connect()
    try:
        rows = conn.execute(
            "SELECT anchor_id, network, txid, commit_type, merkle_root, status, "
            "broadcast_at, verified_at, block_height FROM anchors ORDER BY broadcast_at DESC"
        ).fetchall()
    finally:
        conn.close()
    print(json.dumps([dict(r) for r in rows], indent=2, default=str))


def cmd_selftest(args: argparse.Namespace) -> None:
    """End-to-end OFFLINE test: build -> sign -> serialize -> parse -> verify OP_RETURN.

    Live signet broadcast requires funded UTXOs; out of scope for selftest. Use
    `anchor-memory-root --dry-run` to inspect a real tx without broadcasting,
    then drop --dry-run when you've funded the anchor address.
    """
    import tempfile
    import shutil
    tmp = Path(tempfile.mkdtemp(prefix="rmem-anchor-selftest-"))
    failures: list[str] = []
    try:
        # --- vault + a test record ---
        vault = VaultStore(tmp / "v")
        vault.init()
        enc_key = secrets.token_bytes(_vault.KEY_LEN)
        write_result = vault.put_record(
            key=enc_key, soul_id="did:btc:testsoul", body_id="test-body",
            layer="L3_canonical", type_="preference", payload=b"anchor me",
            rights={"read": ["owner"], "write": ["owner"],
                    "delete": ["owner"], "export": ["owner"]},
            provenance={"created_by": "test", "source": "anchor-selftest",
                        "created_at": now_iso()},
        )

        # --- compute memory root ---
        root = compute_memory_root(vault, "did:btc:testsoul")
        expected_root_bytes = bytes.fromhex(root.split(":", 1)[1])
        if len(expected_root_bytes) != 32:
            failures.append("memory root is not 32 bytes")

        # --- build CAAP payload ---
        payload = build_caap_payload(root, COMMIT_MEMORY_ROOT)
        if len(payload) != PAYLOAD_LEN:
            failures.append(f"payload length {len(payload)} != {PAYLOAD_LEN}")
        if payload[:4] != CAAP_MAGIC:
            failures.append("payload missing CAAP magic")
        if payload[4] != ANCHOR_VERSION or payload[5] != COMMIT_MEMORY_ROOT:
            failures.append("payload version/type bytes wrong")

        # --- generate test signet keypair ---
        priv_bytes = secrets.token_bytes(32)
        priv = ec.PrivateKey(priv_bytes, compressed=True)
        net = networks.NETWORKS["signet"]
        wif = priv.wif(net)
        addr = derive_p2wpkh_address(wif, "signet")
        if not addr.startswith("tb1"):
            failures.append(f"signet P2WPKH address should start with tb1, got {addr!r}")

        # --- build + sign tx with a mock UTXO ---
        mock_utxo = {
            "txid": "00" * 32,
            "vout": 0,
            "value": 100000,  # 1 mBTC
        }
        tx = build_anchor_tx(
            utxos=[mock_utxo], anchor_address=addr, payload=payload,
            fee_sats=1000, network="signet",
        )
        if len(tx.vout) != 2:
            failures.append(f"expected 2 outputs (OP_RETURN + change), got {len(tx.vout)}")
        if tx.vout[0].value != 0:
            failures.append("OP_RETURN output value must be 0")

        # --- sign ---
        tx_hex = sign_anchor_tx(tx, wif, [mock_utxo], "signet")
        if not tx_hex:
            failures.append("sign returned empty hex")

        # --- parse back and verify OP_RETURN ---
        parsed_tx = Transaction.parse(bytes.fromhex(tx_hex))
        extracted = extract_op_return_from_tx(parsed_tx)
        if extracted is None:
            failures.append("could not extract OP_RETURN from signed tx")
        elif extracted != payload:
            failures.append("extracted OP_RETURN does not match original payload")

        # --- parse CAAP payload ---
        parsed_payload = parse_caap_payload(extracted) if extracted else {"valid": False}
        if not parsed_payload.get("valid"):
            failures.append(f"parse_caap_payload failed: {parsed_payload.get('reason')}")
        elif parsed_payload["merkle_root"] != root:
            failures.append("round-tripped merkle root does not match")
        elif parsed_payload["commit_type"] != COMMIT_MEMORY_ROOT:
            failures.append("round-tripped commit_type does not match")

        # --- anchor record storage ---
        anchor_id = record_anchor(
            vault, network="signet", txid="ab" * 32, payload=payload,
            commit_type=COMMIT_MEMORY_ROOT, merkle_root_hex=root,
            soul_id="did:btc:testsoul",
        )
        ensure_anchors_table(vault)
        conn = vault.connect()
        try:
            row = conn.execute(
                "SELECT status, merkle_root FROM anchors WHERE anchor_id = ?",
                (anchor_id,),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            failures.append("anchor record not stored")
        elif row["status"] != "broadcast" or row["merkle_root"] != root:
            failures.append("anchor record fields wrong")

        # --- audit chain still intact ---
        ok, bad = vault.verify_audit_chain()
        if not ok:
            failures.append(f"audit chain broken at id={bad}")

        # --- bad payload detection ---
        bad = parse_caap_payload(b"NOTCAAP" + b"\x00" * 31)
        if bad["valid"]:
            failures.append("parse_caap_payload accepted bogus magic")
        bad2 = parse_caap_payload(b"CAAP" + bytes([0x02, COMMIT_CAPSULE_ROOT]) + b"\x00" * 32)
        if bad2["valid"]:
            failures.append("parse_caap_payload accepted unsupported version")

        if failures:
            print("selftest: FAIL")
            for f in failures:
                print(f"  - {f}")
            sys.exit(1)
        print("selftest: OK")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rmem-anchor",
        description="rmem-anchor -- Phase D (CAMIA OP_RETURN anchoring on Bitcoin testnet/signet)",
    )
    parser.add_argument(
        "--vault", default=str(DEFAULT_VAULT_DIR),
        help=f"vault root dir (default: {DEFAULT_VAULT_DIR})",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("anchor-memory-root",
                       help="commit current memory-state Merkle root to chain")
    p.add_argument("--soul", required=True, help="Soul ID")
    p.add_argument("--network", default="signet",
                   choices=["signet", "testnet", "mainnet", "mutinynet"])
    p.add_argument("--anchor-key", help="path to file with anchor WIF; else ANCHOR_KEY_WIF env")
    p.add_argument("--fee", type=int, default=500, help="fee in sats (default 500)")
    p.add_argument("--dry-run", action="store_true",
                   help="build + sign but do not broadcast; print tx hex")
    p.add_argument(
        "--broadcast-via", default="public-api",
        choices=["public-api", "knots-rpc"],
        help="public-api uses Esplora/Blockstream; knots-rpc broadcasts via "
             "Bunny's Knots node over SSH (sovereign mainnet path; needs SSH key + "
             "Tailscale)",
    )
    p.add_argument("--ssh-target", default=None,
                   help="SSH target for --broadcast-via knots-rpc (default: umbrel@100.112.55.13)")
    p.add_argument("--ssh-key", default=None,
                   help="SSH private key path (default: ~/.ssh/id_ed25519_umbrel)")
    p.set_defaults(func=cmd_anchor_memory)

    p = sub.add_parser("verify", help="re-fetch anchor tx from chain and verify OP_RETURN")
    p.add_argument("--anchor", required=True, help="anchor_id")
    p.set_defaults(func=cmd_verify)

    sub.add_parser("list", help="list anchors stored in vault").set_defaults(func=cmd_list)
    sub.add_parser("selftest", help="end-to-end offline test").set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
