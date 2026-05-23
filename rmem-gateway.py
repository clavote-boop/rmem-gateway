#!/usr/bin/env python3
"""rmem-gateway — Phase B of the RMEM Gateway.

Implements the ERC-8264 four operations (readMemory / writeMemory / deleteMemory /
exportMemory) on top of the Phase A vault. The gateway holds no signing key — every
mutating operation requires an EIP-191 owner signature verified against the subject's
Ethereum address (derived from the same secp256k1 key as the Soul ID).

See product/caas/rmem-gateway/SPEC_v0.1.md.

Security invariants (do not violate):
- The gateway never holds a private key. Owner signs externally; gateway verifies.
- All four ERC-8264 ops require a valid owner signature in v0.1.
- Signatures are bound to an op-specific canonical message (op, subject, nonce,
  expires_at, op-specific fields), preventing replay across ops or beyond expiry.
- Capsule export bundles the manifest (hash tree + owner sig) + the encrypted payloads.
- Body-lease-scoped writes/reads are Phase C — v0.1 is owner-only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import shutil
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct, encode_typed_data
except ImportError:
    sys.exit("rmem-gateway requires 'eth-account'. pip install eth-account")


# ---- Import Phase A vault library (dash-named file, use importlib) ----

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
new_record_id = _vault.new_record_id
canon_json = _vault.canon_json
sha256_hex = _vault.sha256_hex
now_iso = _vault.now_iso
load_vault_key = _vault.load_vault_key
KEY_LEN = _vault.KEY_LEN
VALID_LAYERS = _vault.VALID_LAYERS
VALID_TYPES = _vault.VALID_TYPES


# ---- Import Phase C lease helpers ----

def _import_lease():
    spec_path = Path(__file__).resolve().parent / "rmem-lease.py"
    if not spec_path.exists():
        sys.exit(f"rmem-lease.py not found at {spec_path}")
    spec = importlib.util.spec_from_file_location("rmem_lease", spec_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["rmem_lease"] = module
    spec.loader.exec_module(module)
    return module


_lease = _import_lease()
verify_lease_signature = _lease.verify_lease_signature
is_lease_expired = _lease.is_lease_expired
lease_authorizes_op = _lease.lease_authorizes_op
verify_body_signed_request = _lease.verify_body_signed_request


# ---- Tagged-hash helpers (Def. 2 / Def. 4 / Eq. anchor) ----

def _import_hashes():
    spec_path = Path(__file__).resolve().parent / "rmem_hashes.py"
    if not spec_path.exists():
        sys.exit(f"rmem_hashes.py not found at {spec_path}")
    spec = importlib.util.spec_from_file_location("rmem_hashes", spec_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["rmem_hashes"] = module
    spec.loader.exec_module(module)
    return module


_hashes = _import_hashes()
CANON_PROFILE_JCS = _hashes.CANON_PROFILE_JCS
capsule_merkle_root_hex = _hashes.capsule_merkle_root_hex
chunk_hash_hex = _hashes.chunk_hash_hex


# ---- ERC-8264 op codes ----

OP_READ = "readMemory"
OP_WRITE = "writeMemory"
OP_DELETE = "deleteMemory"
OP_EXPORT = "exportMemory"

# Bumped from 0.1: v0.2 capsule manifest is Def. 4 conformant
# (canonProfile, h_m, tagged chunk hashes, G_X leaf).
CAPSULE_VERSION = "0.2"
CAPSULE_HASH_ALG = "sha256"

SIG_EIP191 = "eip191"
SIG_EIP712 = "eip712"


# ---- signature layer (EIP-191) ----

def build_auth_message(op: str, subject: str, **fields) -> str:
    """Canonical message the owner signs to authorise an operation.

    Format: canonical JSON of {op, subject, ...op-specific fields, nonce, expires_at}.
    A nonce + expires_at make every signature single-use and time-bound.
    """
    payload = {"op": op, "subject": subject, **fields}
    if "nonce" not in payload:
        payload["nonce"] = secrets.token_hex(16)
    if "expires_at" not in payload:
        payload["expires_at"] = (datetime.now(timezone.utc) + timedelta(minutes=10)) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    return canon_json(payload)


def verify_owner_signature(message: str, signature_hex: str, owner_address: str) -> bool:
    """Verify EIP-191 signature against the expected owner Ethereum address.

    The owner address is the EVM-encoded form of the secp256k1 pubkey behind
    the Soul ID (did:btc:<pubkey>). Caller derives both off-chain from the
    same key; gateway verifies the recovered address matches.
    """
    try:
        encoded = encode_defunct(text=message)
        recovered = Account.recover_message(encoded, signature=signature_hex)
        return recovered.lower() == owner_address.lower()
    except Exception:
        return False


def check_expiry(message_json: str) -> bool:
    """Return True if message is still within its expires_at window."""
    try:
        msg = json.loads(message_json)
        expires = msg.get("expires_at")
        if not expires:
            return False
        exp_dt = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return exp_dt > datetime.now(timezone.utc)
    except Exception:
        return False


# ---- signature layer (EIP-712 typed data) ----
#
# Parallel to EIP-191. The semantics are identical: same op codes, same nonce
# + expiry replay protection, same subject-binding. The difference is wire
# format: EIP-712 produces a typed-data hash that wallets can render with
# field names + types, instead of asking the user to sign an opaque hex blob.
#
# Field name choices follow Solidity camelCase (subject, recordId, bodyId,
# expiresAt) rather than the EIP-191 path's snake_case JSON. They are *not*
# interchangeable wire formats; the caller picks one scheme per op.

EIP712_DOMAIN = {
    "name": "RmemGateway",
    "version": "0.1",
    "chainId": 0,  # off-chain gateway; no enforcement contract bound to this domain
}

_EIP712_DOMAIN_TYPE = [
    {"name": "name",    "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
]

_EIP712_FIELDS_PER_OP: dict[str, list[dict]] = {
    OP_READ: [
        {"name": "op",         "type": "string"},
        {"name": "subject",    "type": "string"},
        {"name": "recordId",   "type": "string"},
        {"name": "nonce",      "type": "bytes32"},
        {"name": "expiresAt",  "type": "uint64"},
    ],
    OP_WRITE: [
        {"name": "op",                 "type": "string"},
        {"name": "subject",            "type": "string"},
        {"name": "bodyId",             "type": "string"},
        {"name": "layer",              "type": "string"},
        {"name": "recordType",         "type": "string"},
        {"name": "payloadFingerprint", "type": "bytes32"},
        {"name": "nonce",              "type": "bytes32"},
        {"name": "expiresAt",          "type": "uint64"},
    ],
    OP_DELETE: [
        {"name": "op",        "type": "string"},
        {"name": "subject",   "type": "string"},
        {"name": "recordId",  "type": "string"},
        {"name": "nonce",     "type": "bytes32"},
        {"name": "expiresAt", "type": "uint64"},
    ],
    OP_EXPORT: [
        {"name": "op",        "type": "string"},
        {"name": "subject",   "type": "string"},
        {"name": "nonce",     "type": "bytes32"},
        {"name": "expiresAt", "type": "uint64"},
    ],
}

_EIP712_PRIMARY_TYPE = {
    OP_READ:   "ReadAuth",
    OP_WRITE:  "WriteAuth",
    OP_DELETE: "DeleteAuth",
    OP_EXPORT: "ExportAuth",
}


def _to_bytes32(value) -> bytes:
    """Accept 0x-hex / sha256: prefixed / raw hex / bytes; return exactly 32 bytes."""
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError(f"expected 32 bytes, got {len(value)}")
        return value
    s = str(value)
    if s.startswith("sha256:"):
        s = s.split(":", 1)[1]
    if s.startswith("0x"):
        s = s[2:]
    b = bytes.fromhex(s)
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    return b


def build_typed_auth_message(op: str, subject: str, **fields) -> dict:
    """Canonical EIP-712 typed-data message the owner signs to authorise an op.

    Returns the full `{domain, types, primaryType, message}` dict accepted by
    eth_account.messages.encode_typed_data(full_message=...).
    """
    if op not in _EIP712_FIELDS_PER_OP:
        raise ValueError(f"unknown op {op!r}")
    primary = _EIP712_PRIMARY_TYPE[op]
    msg = {"op": op, "subject": subject}
    # Per-op fields the caller supplied (e.g. recordId, bodyId, payloadFingerprint).
    for f in _EIP712_FIELDS_PER_OP[op]:
        name = f["name"]
        if name in ("op", "subject", "nonce", "expiresAt"):
            continue
        if name not in fields:
            raise ValueError(f"build_typed_auth_message: missing field {name!r} for op {op!r}")
        v = fields[name]
        if f["type"] == "bytes32":
            v = _to_bytes32(v)
        msg[name] = v
    # Nonce + expiry.
    nonce = fields.get("nonce")
    msg["nonce"] = _to_bytes32(nonce) if nonce else secrets.token_bytes(32)
    expires_at = fields.get("expiresAt") or fields.get("expires_at")
    if expires_at is None:
        expires_at = int((datetime.now(timezone.utc)
                          + timedelta(minutes=10)).timestamp())
    msg["expiresAt"] = int(expires_at)
    return {
        "domain": dict(EIP712_DOMAIN),
        "types": {
            "EIP712Domain": _EIP712_DOMAIN_TYPE,
            primary: _EIP712_FIELDS_PER_OP[op],
        },
        "primaryType": primary,
        "message": msg,
    }


def _coerce_typed_message(message) -> dict:
    """Accept either a typed-data dict or its JSON-string form. Re-coerce
    bytes32 fields if the input came through JSON (where bytes were hex strings).
    """
    if isinstance(message, str):
        td = json.loads(message)
    else:
        td = message
    primary = td.get("primaryType")
    fields = td.get("types", {}).get(primary, [])
    msg = td.get("message", {})
    for f in fields:
        if f["type"] == "bytes32" and isinstance(msg.get(f["name"]), str):
            msg[f["name"]] = _to_bytes32(msg[f["name"]])
    td["message"] = msg
    return td


def verify_owner_signature_712(typed_data, signature_hex: str, owner_address: str) -> bool:
    """Verify EIP-712 signature against the expected owner Ethereum address."""
    try:
        td = _coerce_typed_message(typed_data)
        signable = encode_typed_data(full_message=td)
        recovered = Account.recover_message(signable, signature=signature_hex)
        return recovered.lower() == owner_address.lower()
    except Exception:
        return False


def check_expiry_712(typed_data) -> bool:
    """Return True if the typed message is still within its expiresAt window."""
    try:
        td = _coerce_typed_message(typed_data)
        expires = td["message"].get("expiresAt")
        if not isinstance(expires, int):
            return False
        return expires > int(datetime.now(timezone.utc).timestamp())
    except Exception:
        return False


# ---- capsule manifest construction (Def. 4) ----

def _build_manifest_meta(*, soul_id: str, owner_address: str, sig_scheme: str,
                         created_at: str) -> dict:
    """The fields h_m commits to. Must NOT include record_index, provenance_graph,
    merkle_root, or the signature — those are downstream of h_m."""
    return {
        "capsule_version": CAPSULE_VERSION,
        "canonProfile": CANON_PROFILE_JCS,
        "hashAlg": CAPSULE_HASH_ALG,
        "soul_id": soul_id,
        "controller_pubkeys": [owner_address],
        "created_at": created_at,
        "sig_scheme": sig_scheme,
    }


def _build_provenance_graph(record_index: list[dict]) -> dict:
    """Minimal G_X: each record is a vertex; no edges (records do not currently
    track explicit parents). Spec only requires acyclicity + identifier
    consistency, both trivially satisfied."""
    return {
        "vertices": [r["record_id"] for r in record_index],
        "edges": [],
    }


# ---- gateway ops ----

class RmemGateway:
    """ERC-8264 implementation on top of the Phase A vault.

    The gateway is stateless aside from the vault it wraps. Every mutating op
    takes a (message, signature, owner_address) tuple; the gateway verifies
    the signature, checks expiry, and either commits or rejects.
    """

    def __init__(self, vault: VaultStore):
        self.vault = vault

    # --- read ---

    def read_memory(
        self,
        subject_soul: str,
        record_id: str,
        *,
        # Owner-direct auth:
        message=None,
        signature: Optional[str] = None,
        owner_address: Optional[str] = None,
        sig_scheme: str = SIG_EIP191,
        # Lease auth:
        lease: Optional[dict] = None,
        body_message: Optional[str] = None,
        body_signature: Optional[str] = None,
        # Decryption:
        decrypt_key: Optional[bytes] = None,
    ) -> dict:
        if lease is not None:
            self._authorise_via_lease(
                OP_READ, lease, body_message, body_signature,
                extra_match={"record_id": record_id},
            )
        elif message is not None:
            self._authorise(OP_READ, subject_soul, message, signature, owner_address,
                            extra_match={"record_id": record_id},
                            sig_scheme=sig_scheme)
        else:
            sys.exit("AUTH_REQUIRED: pass owner-direct (message+signature+owner_address) "
                     "or lease (lease+body_message+body_signature)")
        result = self.vault.get_record(soul_id=subject_soul, record_id=record_id,
                                       key=decrypt_key)
        return {
            "op": OP_READ,
            "subject": subject_soul,
            "record_id": record_id,
            "meta": result["meta"],
            "decrypted": result["decrypted"],
            "payload_b64": (
                __import__("base64").b64encode(result["payload"]).decode()
                if result["decrypted"] and result["payload"] else None
            ),
        }

    # --- write ---

    def write_memory(
        self,
        subject_soul: str,
        *,
        # Op data:
        body_id: str,
        layer: str,
        type_: str,
        payload: bytes,
        rights: dict,
        provenance: dict,
        encrypt_key: bytes,
        # Owner-direct auth:
        message=None,
        signature: Optional[str] = None,
        owner_address: Optional[str] = None,
        sig_scheme: str = SIG_EIP191,
        # Lease auth:
        lease: Optional[dict] = None,
        body_message: Optional[str] = None,
        body_signature: Optional[str] = None,
    ) -> dict:
        payload_fingerprint = sha256_hex(payload)
        extra = {
            "body_id": body_id,
            "layer": layer,
            "type": type_,
            "payload_fingerprint": payload_fingerprint,
        }
        if lease is not None:
            self._authorise_via_lease(OP_WRITE, lease, body_message, body_signature,
                                      extra_match=extra)
        elif message is not None:
            self._authorise(OP_WRITE, subject_soul, message, signature, owner_address,
                            extra_match=extra, sig_scheme=sig_scheme)
        else:
            sys.exit("AUTH_REQUIRED: pass owner-direct (message+signature+owner_address) "
                     "or lease (lease+body_message+body_signature)")
        result = self.vault.put_record(
            key=encrypt_key, soul_id=subject_soul, body_id=body_id,
            layer=layer, type_=type_,
            payload=payload, rights=rights, provenance=provenance,
        )
        return {"op": OP_WRITE, "subject": subject_soul, **result}

    # --- delete ---

    def delete_memory(
        self,
        subject_soul: str,
        record_id: str,
        message,
        signature: str,
        owner_address: str,
        sig_scheme: str = SIG_EIP191,
    ) -> dict:
        self._authorise(OP_DELETE, subject_soul, message, signature, owner_address,
                        extra_match={"record_id": record_id},
                        sig_scheme=sig_scheme)
        result = self.vault.tombstone_record(soul_id=subject_soul, record_id=record_id)
        return {"op": OP_DELETE, "subject": subject_soul, **result}

    # --- export ---

    def export_memory(
        self,
        subject_soul: str,
        message,
        signature: str,
        owner_address: str,
        out_dir: Path,
        sig_scheme: str = SIG_EIP191,
    ) -> dict:
        self._authorise(OP_EXPORT, subject_soul, message, signature, owner_address,
                        sig_scheme=sig_scheme)
        records = self.vault.list_records(soul_id=subject_soul, include_tombstoned=False)
        if not records:
            sys.exit(f"no active records for {subject_soul}")
        out_dir.mkdir(parents=True, exist_ok=True)
        records_dir = out_dir / "records"
        records_dir.mkdir(exist_ok=True)
        record_index = []
        chunk_hashes: list[bytes] = []
        for r in records:
            src = self.vault.root / "records" / f"{r['record_id']}.enc"
            dst = records_dir / f"{r['record_id']}.enc"
            shutil.copyfile(src, dst)
            chunk_bytes = dst.read_bytes()
            chunk_h = _hashes.chunk_hash(chunk_bytes)
            chunk_hashes.append(chunk_h)
            record_index.append({
                "record_id": r["record_id"],
                "payload_hash": r["payload_hash"],       # raw sha256(chunk) for on-disk integrity
                "chunk_hash": "sha256:" + chunk_h.hex(), # tagged h_i = H(CAPSULE_CHUNK || chunk)
                "layer": r["layer"],
                "type": r["type"],
            })
        # For EIP-712, serialize the typed-data with bytes32 fields hex-encoded so
        # the manifest is plain JSON (bytes are not JSON-serializable).
        if sig_scheme == SIG_EIP712:
            td = _coerce_typed_message(message)
            primary = td.get("primaryType")
            for f in td.get("types", {}).get(primary, []):
                if f["type"] == "bytes32":
                    v = td["message"].get(f["name"])
                    if isinstance(v, (bytes, bytearray)):
                        td["message"][f["name"]] = "0x" + bytes(v).hex()
            manifest_message = td
        else:
            manifest_message = message
        created_at = now_iso()
        manifest_meta = _build_manifest_meta(
            soul_id=subject_soul, owner_address=owner_address,
            sig_scheme=sig_scheme, created_at=created_at,
        )
        provenance_graph = _build_provenance_graph(record_index)
        root = capsule_merkle_root_hex(manifest_meta, chunk_hashes, provenance_graph)
        manifest = {
            **manifest_meta,
            "record_index": record_index,
            "provenance_graph": provenance_graph,
            "merkle_root": root,
            "owner_signature_message": manifest_message,
            "owner_signature": signature,
        }
        (out_dir / "manifest.json").write_text(canon_json(manifest))
        return {
            "op": OP_EXPORT,
            "subject": subject_soul,
            "out_dir": str(out_dir),
            "record_count": len(record_index),
            "merkle_root": root,
            "canonProfile": CANON_PROFILE_JCS,
        }

    # --- internal ---

    # Mapping from EIP-191 snake_case field names to EIP-712 camelCase names.
    # Used to translate `extra_match` keys when verifying typed-data messages.
    _EIP712_FIELD_ALIAS = {
        "record_id":           "recordId",
        "body_id":             "bodyId",
        "type":                "recordType",
        "layer":               "layer",
        "payload_fingerprint": "payloadFingerprint",
    }

    def _authorise(
        self,
        op: str,
        subject_soul: str,
        message,
        signature: str,
        owner_address: str,
        extra_match: Optional[dict] = None,
        sig_scheme: str = SIG_EIP191,
    ) -> None:
        if sig_scheme == SIG_EIP712:
            self._authorise_712(op, subject_soul, message, signature,
                                owner_address, extra_match)
            return
        try:
            msg = json.loads(message)
        except Exception:
            sys.exit(f"AUTH_FAILED: message is not valid JSON")
        if msg.get("op") != op:
            sys.exit(f"AUTH_FAILED: message op {msg.get('op')!r} != expected {op!r}")
        if msg.get("subject") != subject_soul:
            sys.exit(f"AUTH_FAILED: message subject does not match request subject")
        if not check_expiry(message):
            sys.exit("AUTH_FAILED: signature expired or missing expires_at")
        if extra_match:
            for k, v in extra_match.items():
                if msg.get(k) != v:
                    sys.exit(f"AUTH_FAILED: message {k}={msg.get(k)!r} != request {v!r}")
        if not verify_owner_signature(message, signature, owner_address):
            sys.exit("AUTH_FAILED: signature does not verify against owner address")

    def _authorise_712(
        self,
        op: str,
        subject_soul: str,
        typed_data,
        signature: str,
        owner_address: str,
        extra_match: Optional[dict] = None,
    ) -> None:
        td = _coerce_typed_message(typed_data)
        msg = td.get("message", {})
        if msg.get("op") != op:
            sys.exit(f"AUTH_FAILED: typed-data op {msg.get('op')!r} != expected {op!r}")
        if msg.get("subject") != subject_soul:
            sys.exit("AUTH_FAILED: typed-data subject does not match request subject")
        if td.get("primaryType") != _EIP712_PRIMARY_TYPE[op]:
            sys.exit(f"AUTH_FAILED: typed-data primaryType {td.get('primaryType')!r} "
                     f"!= expected {_EIP712_PRIMARY_TYPE[op]!r}")
        if td.get("domain") != EIP712_DOMAIN:
            sys.exit("AUTH_FAILED: typed-data domain does not match gateway domain")
        if not check_expiry_712(td):
            sys.exit("AUTH_FAILED: typed-data signature expired or missing expiresAt")
        if extra_match:
            for k_in, v in extra_match.items():
                k = self._EIP712_FIELD_ALIAS.get(k_in, k_in)
                got = msg.get(k)
                # Normalise bytes32 fields (extras like payload_fingerprint).
                if isinstance(got, (bytes, bytearray)):
                    got = "sha256:" + bytes(got).hex()
                if got != v:
                    sys.exit(f"AUTH_FAILED: typed-data {k}={got!r} != request {v!r}")
        if not verify_owner_signature_712(td, signature, owner_address):
            sys.exit("AUTH_FAILED: signature does not verify against owner address")

    def _authorise_via_lease(
        self,
        op: str,
        lease: dict,
        body_message: str,
        body_signature: str,
        extra_match: Optional[dict] = None,
    ) -> None:
        """Authorise an ERC-8264 op via a Body Lease + body signature.

        Checks (in order):
          1. Lease owner-signature recovers to lease.subject.
          2. Lease not expired.
          3. body_message is valid JSON.
          4. body_message.lease_id == presented lease.lease_id (binding).
          5. body_message.op == requested op.
          6. body_message.subject == lease.subject (verify_body_signed_request).
          7. body_message has unexpired expires_at (per-request replay window).
          8. body_signature recovers to lease.body_address (verify_body_signed_request).
          9. Any extra_match fields in body_message match the request.
         10. Lease scopes authorise (op, scope) where scope = body_message.layer.
         11. If lease.requires_owner_cosign covers this op/scope, REFUSE in v0.1
             (the dual-sig lease+cosign flow is not yet implemented; caller must
             use direct owner-sig auth for such ops).
        """
        if body_message is None or body_signature is None:
            sys.exit("AUTH_FAILED: lease auth requires body_message and body_signature")
        # 1, 2, 6, 8 + explicit ¬Revoked via vault lookup: stale lease JSONs
        # cannot bypass revocation just because their dict has no _status.
        check = verify_body_signed_request(
            lease, body_message, body_signature, vault=self.vault,
        )
        if not check["valid"]:
            sys.exit(f"AUTH_FAILED: {check['reason']}")
        # 3 -- parse body_message
        try:
            msg = json.loads(body_message)
        except Exception:
            sys.exit("AUTH_FAILED: body_message is not valid JSON")
        # 4 -- lease_id binding
        if msg.get("lease_id") != lease.get("lease_id"):
            sys.exit("AUTH_FAILED: body_message.lease_id != presented lease.lease_id")
        # 5 -- op match
        if msg.get("op") != op:
            sys.exit(f"AUTH_FAILED: body_message.op {msg.get('op')!r} != requested {op!r}")
        # 7 -- per-request expiry
        if not check_expiry(body_message):
            sys.exit("AUTH_FAILED: body_message expired or missing expires_at")
        # 9 -- extra_match
        if extra_match:
            for k, v in extra_match.items():
                if msg.get(k) != v:
                    sys.exit(f"AUTH_FAILED: body_message {k}={msg.get(k)!r} != request {v!r}")
        # 10 -- scope check (layer is op-specific; only writeMemory carries one)
        scope = msg.get("layer")
        auth = lease_authorizes_op(lease, op, scope)
        if not auth["authorized"]:
            sys.exit(f"AUTH_FAILED: {auth['reason']}")
        # 11 -- cosign refusal in v0.1
        if auth["requires_owner_cosign"]:
            sys.exit(
                f"AUTH_FAILED: op {op!r} (scope={scope!r}) requires owner cosign; "
                "v0.1 gateway does not yet implement the lease + cosign dual-sig flow. "
                "Use direct owner-signed auth for this op, or use a lease whose "
                "requires_owner_cosign list does not cover this op."
            )


# ---- CLI ----

def _vault_for(args: argparse.Namespace) -> VaultStore:
    return VaultStore(Path(args.vault).expanduser())


def _load_message_arg(path: str, sig_scheme: str):
    """Load a message file. For EIP-712, parse as JSON typed-data; for EIP-191
    pass through as raw text (the canonical JSON string the owner signed)."""
    text = Path(path).read_text()
    if sig_scheme == SIG_EIP712:
        return json.loads(text)
    return text


def cmd_read(args: argparse.Namespace) -> None:
    gw = RmemGateway(_vault_for(args))
    key = load_vault_key(args.vault_key) if args.decrypt else None
    kwargs = {
        "subject_soul": args.soul, "record_id": args.record,
        "decrypt_key": key,
    }
    if args.lease_file:
        if not (args.body_message and args.body_signature):
            sys.exit("--lease-file requires --body-message and --body-signature")
        kwargs["lease"] = json.loads(Path(args.lease_file).read_text())
        kwargs["body_message"] = Path(args.body_message).read_text()
        kwargs["body_signature"] = args.body_signature
    elif args.message:
        kwargs["message"] = _load_message_arg(args.message, args.sig_scheme)
        kwargs["signature"] = args.signature
        kwargs["owner_address"] = args.owner
        kwargs["sig_scheme"] = args.sig_scheme
    else:
        sys.exit("AUTH_REQUIRED: provide --message+--signature+--owner (owner-direct) "
                 "or --lease-file+--body-message+--body-signature (lease)")
    result = gw.read_memory(**kwargs)
    if args.decrypt and result["payload_b64"]:
        import base64
        sys.stdout.buffer.write(base64.b64decode(result["payload_b64"]))
    else:
        print(json.dumps({k: v for k, v in result.items() if k != "payload_b64"},
                         indent=2, default=str))


def cmd_write(args: argparse.Namespace) -> None:
    gw = RmemGateway(_vault_for(args))
    enc_key = load_vault_key(args.vault_key)
    payload = sys.stdin.buffer.read() if args.payload == "-" else Path(args.payload).read_bytes()
    rights = json.loads(args.rights) if args.rights else {
        "read": ["owner", f"body:{args.body}"], "write": ["owner"],
        "delete": ["owner"], "export": ["owner"],
    }
    provenance = json.loads(args.provenance) if args.provenance else {
        "created_by": args.body, "source": args.source or "gateway", "created_at": now_iso(),
    }
    kwargs = {
        "subject_soul": args.soul,
        "body_id": args.body, "layer": args.layer, "type_": args.type,
        "payload": payload, "rights": rights, "provenance": provenance,
        "encrypt_key": enc_key,
    }
    if args.lease_file:
        if not (args.body_message and args.body_signature):
            sys.exit("--lease-file requires --body-message and --body-signature")
        kwargs["lease"] = json.loads(Path(args.lease_file).read_text())
        kwargs["body_message"] = Path(args.body_message).read_text()
        kwargs["body_signature"] = args.body_signature
    elif args.message:
        kwargs["message"] = _load_message_arg(args.message, args.sig_scheme)
        kwargs["signature"] = args.signature
        kwargs["owner_address"] = args.owner
        kwargs["sig_scheme"] = args.sig_scheme
    else:
        sys.exit("AUTH_REQUIRED: provide --message+--signature+--owner (owner-direct) "
                 "or --lease-file+--body-message+--body-signature (lease)")
    result = gw.write_memory(**kwargs)
    if args.also_anchor:
        anchor_result = _also_anchor(gw.vault, args)
        result = {**result, "anchor": anchor_result}
    print(json.dumps(result, indent=2))


def _also_anchor(vault: VaultStore, args: argparse.Namespace) -> dict:
    """Compute the post-write memory_root and publish it to the EVM registry.

    Mirrors `rmem-evm.py anchor-vault` but invoked inline after a successful
    gateway write. Config via env: RMEM_REGISTRY_ADDRESS, RPC_URL,
    DEPLOYER_PRIVATE_KEY. Anchor subject defaults to --owner (the Ethereum
    address that signed the write) so the on-chain subject matches the
    off-chain signing identity.
    """
    import importlib.util as _impu
    spec_path = Path(__file__).resolve().parent / "rmem-evm.py"
    if not spec_path.exists():
        sys.exit(f"--also-anchor requires rmem-evm.py at {spec_path}")
    spec = _impu.spec_from_file_location("rmem_evm", spec_path)
    mod = _impu.module_from_spec(spec)
    sys.modules["rmem_evm"] = mod
    spec.loader.exec_module(mod)

    rows = vault.list_records(soul_id=args.soul, include_tombstoned=False)
    # Compute tagged chunk hashes by re-reading each .enc file; gives a
    # Def. 4-prefixed Merkle root over the live memory state.
    chunk_hs: list[bytes] = []
    for r in rows:
        enc_path = vault.root / "records" / f"{r['record_id']}.enc"
        chunk_hs.append(_hashes.chunk_hash(enc_path.read_bytes()))
    root_bytes = _hashes.merkle_root_v2(chunk_hs)

    rpc_url = args.anchor_rpc_url or os.environ.get("RPC_URL") \
        or os.environ.get("SEPOLIA_RPC_URL")
    contract = args.anchor_contract or os.environ.get("RMEM_REGISTRY_ADDRESS")
    pk_file = args.anchor_key_file
    pk = (Path(pk_file).read_text().strip() if pk_file
          else os.environ.get("DEPLOYER_PRIVATE_KEY"))
    if not (rpc_url and contract and pk):
        sys.exit("--also-anchor requires RPC_URL, RMEM_REGISTRY_ADDRESS, "
                 "and DEPLOYER_PRIVATE_KEY (or --anchor-* flags)")
    anchor_subject = args.anchor_subject or args.owner
    if not anchor_subject:
        sys.exit("--also-anchor needs a subject address (--anchor-subject or --owner)")

    preset = mod.NETWORK_PRESETS.get(args.anchor_network, {})
    client = mod.RegistryClient(
        rpc_url=rpc_url, contract_address=contract, private_key=pk,
        chain_id=preset.get("chain_id"), is_poa=preset.get("is_poa", False),
    )
    receipt = client.anchor_memory_root(
        anchor_subject, root_bytes, mod.COMMIT_MEMORY_ROOT,
    )
    return {
        **receipt,
        "subject": anchor_subject,
        "merkle_root": "sha256:" + root_bytes.hex(),
        "leaf_count": len(leaves),
    }


def cmd_delete(args: argparse.Namespace) -> None:
    gw = RmemGateway(_vault_for(args))
    message = _load_message_arg(args.message, args.sig_scheme)
    result = gw.delete_memory(
        subject_soul=args.soul, record_id=args.record,
        message=message, signature=args.signature, owner_address=args.owner,
        sig_scheme=args.sig_scheme,
    )
    print(json.dumps(result, indent=2))


def cmd_export(args: argparse.Namespace) -> None:
    gw = RmemGateway(_vault_for(args))
    message = _load_message_arg(args.message, args.sig_scheme)
    result = gw.export_memory(
        subject_soul=args.soul, message=message, signature=args.signature,
        owner_address=args.owner, out_dir=Path(args.out).expanduser(),
        sig_scheme=args.sig_scheme,
    )
    print(json.dumps(result, indent=2))


def cmd_selftest(args: argparse.Namespace) -> None:
    """End-to-end test: write -> read -> export -> verify manifest -> delete -> blocked write."""
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="rmem-gateway-selftest-"))
    failures: list[str] = []
    try:
        vault = VaultStore(tmp / "v")
        vault.init()
        gw = RmemGateway(vault)

        # Generate owner test key (Ethereum keypair from random)
        owner_priv = "0x" + secrets.token_hex(32)
        owner_account = Account.from_key(owner_priv)
        owner_address = owner_account.address
        soul = f"did:btc:{owner_account._key_obj.public_key.to_compressed_bytes().hex()}"

        enc_key = secrets.token_bytes(KEY_LEN)
        body = "test-body-n100"

        # --- WRITE: build message, sign, submit ---
        payload = b"my canonical preference: dark mode"
        payload_fp = sha256_hex(payload)
        write_msg = build_auth_message(
            OP_WRITE, soul,
            **{
                "body_id": body,
                "layer": "L3_canonical",
                "type": "preference",
                "payload_fingerprint": payload_fp,
            },
        )
        write_sig = owner_account.sign_message(encode_defunct(text=write_msg)).signature.hex()
        write_result = gw.write_memory(
            subject_soul=soul, message=write_msg, signature=write_sig,
            owner_address=owner_address,
            body_id=body, layer="L3_canonical", type_="preference",
            payload=payload,
            rights={"read": ["owner"], "write": ["owner"], "delete": ["owner"], "export": ["owner"]},
            provenance={"created_by": "selftest", "source": "selftest", "created_at": now_iso()},
            encrypt_key=enc_key,
        )
        rid = write_result["record_id"]

        # --- WRITE with tampered payload: should be rejected ---
        tampered = b"my canonical preference: light mode"
        rejected = False
        try:
            gw.write_memory(
                subject_soul=soul, message=write_msg, signature=write_sig,
                owner_address=owner_address,
                body_id=body, layer="L3_canonical", type_="preference",
                payload=tampered,  # fingerprint won't match the signed message
                rights={"read": ["owner"], "write": ["owner"], "delete": ["owner"], "export": ["owner"]},
                provenance={"created_by": "selftest", "source": "selftest", "created_at": now_iso()},
                encrypt_key=enc_key,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("payload-fingerprint mismatch was NOT rejected")

        # --- READ: signed read returns metadata ---
        read_msg = build_auth_message(OP_READ, soul, record_id=rid)
        read_sig = owner_account.sign_message(encode_defunct(text=read_msg)).signature.hex()
        read_result = gw.read_memory(
            subject_soul=soul, record_id=rid,
            message=read_msg, signature=read_sig, owner_address=owner_address,
            decrypt_key=enc_key,
        )
        import base64
        if base64.b64decode(read_result["payload_b64"]) != payload:
            failures.append("decrypted payload did not match original")

        # --- READ with wrong signature: should be rejected ---
        bad_sig = "0x" + "0" * 130
        rejected = False
        try:
            gw.read_memory(
                subject_soul=soul, record_id=rid,
                message=read_msg, signature=bad_sig, owner_address=owner_address,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("bad signature was NOT rejected on read")

        # --- READ with mismatched subject: should be rejected ---
        wrong_soul_msg = build_auth_message(OP_READ, "did:btc:00ff", record_id=rid)
        wrong_soul_sig = owner_account.sign_message(
            encode_defunct(text=wrong_soul_msg)
        ).signature.hex()
        rejected = False
        try:
            gw.read_memory(
                subject_soul=soul, record_id=rid,
                message=wrong_soul_msg, signature=wrong_soul_sig,
                owner_address=owner_address,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("subject mismatch was NOT rejected")

        # --- EXPORT: produce capsule, verify manifest ---
        export_msg = build_auth_message(OP_EXPORT, soul)
        export_sig = owner_account.sign_message(encode_defunct(text=export_msg)).signature.hex()
        capsule_dir = tmp / "capsule"
        export_result = gw.export_memory(
            subject_soul=soul, message=export_msg, signature=export_sig,
            owner_address=owner_address, out_dir=capsule_dir,
        )
        manifest = json.loads((capsule_dir / "manifest.json").read_text())
        if manifest["soul_id"] != soul:
            failures.append("manifest soul_id mismatch")
        if manifest.get("canonProfile") != CANON_PROFILE_JCS:
            failures.append(f"manifest canonProfile = {manifest.get('canonProfile')!r} "
                            f"(expected {CANON_PROFILE_JCS!r})")
        if manifest.get("capsule_version") != CAPSULE_VERSION:
            failures.append(f"manifest capsule_version != {CAPSULE_VERSION}")
        if len(manifest["record_index"]) != 1:
            failures.append(f"manifest record_index has {len(manifest['record_index'])} entries (expected 1)")
        # Re-verify Def. 4 Merkle root independently from the .enc files we just wrote.
        meta_check = _build_manifest_meta(
            soul_id=manifest["soul_id"],
            owner_address=manifest["controller_pubkeys"][0],
            sig_scheme=manifest["sig_scheme"],
            created_at=manifest["created_at"],
        )
        chunk_hs_check = [
            _hashes.chunk_hash((capsule_dir / "records" / f"{e['record_id']}.enc").read_bytes())
            for e in manifest["record_index"]
        ]
        recomputed = capsule_merkle_root_hex(
            meta_check, chunk_hs_check, manifest["provenance_graph"],
        )
        if recomputed != manifest["merkle_root"]:
            failures.append(f"merkle_root does not recompute: got {recomputed} "
                            f"vs manifest {manifest['merkle_root']}")
        # Each manifest chunk_hash equals our independently-computed tagged hash.
        for e, h in zip(manifest["record_index"], chunk_hs_check):
            if e["chunk_hash"] != "sha256:" + h.hex():
                failures.append(f"chunk_hash mismatch for {e['record_id']}")
        # Verify the manifest's owner_signature
        if not verify_owner_signature(
            manifest["owner_signature_message"],
            manifest["owner_signature"],
            owner_address,
        ):
            failures.append("manifest owner_signature does not verify")
        if not (capsule_dir / "records" / f"{rid}.enc").exists():
            failures.append("capsule records dir missing .enc file")

        # --- DELETE: tombstone the record ---
        delete_msg = build_auth_message(OP_DELETE, soul, record_id=rid)
        delete_sig = owner_account.sign_message(
            encode_defunct(text=delete_msg)
        ).signature.hex()
        gw.delete_memory(
            subject_soul=soul, record_id=rid,
            message=delete_msg, signature=delete_sig, owner_address=owner_address,
        )
        # Confirm tombstone took effect
        listed = vault.list_records(soul_id=soul, include_tombstoned=False)
        if listed:
            failures.append(f"after delete: {len(listed)} active records remain (expected 0)")

        # --- DELETE with expired signature: should be rejected ---
        expired_msg_payload = {
            "op": OP_DELETE, "subject": soul, "record_id": rid,
            "nonce": secrets.token_hex(16),
            "expires_at": "2020-01-01T00:00:00Z",  # in the past
        }
        expired_msg = canon_json(expired_msg_payload)
        expired_sig = owner_account.sign_message(
            encode_defunct(text=expired_msg)
        ).signature.hex()
        rejected = False
        try:
            gw.delete_memory(
                subject_soul=soul, record_id=rid,
                message=expired_msg, signature=expired_sig, owner_address=owner_address,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("expired signature was NOT rejected")

        # --- LEASE PATH: owner issues lease, body acts under it ---
        body_account = Account.from_key("0x" + secrets.token_hex(32))
        unsigned_lease = _lease.build_lease_unsigned(
            subject=owner_address, body_id="lease-test-body",
            body_address=body_account.address, expires_in_hours=1,
        )
        lease_obj = _lease.sign_lease(unsigned_lease, owner_account)

        def _body_message(op_name, **fields):
            return canon_json({
                "op": op_name, "subject": owner_address,
                "lease_id": lease_obj["lease_id"], "nonce": secrets.token_hex(16),
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10))
                    .strftime("%Y-%m-%dT%H:%M:%SZ"),
                **fields,
            })

        # Body writes an L1_session record via lease (no cosign required for L1)
        l1_payload = b"body proposes a session note"
        l1_fp = sha256_hex(l1_payload)
        l1_msg = _body_message(
            OP_WRITE, body_id="lease-test-body",
            layer="L1_session", type="episodic", payload_fingerprint=l1_fp,
        )
        l1_sig = body_account.sign_message(encode_defunct(text=l1_msg)).signature.hex()
        l1_result = gw.write_memory(
            subject_soul=soul,
            body_id="lease-test-body", layer="L1_session", type_="episodic",
            payload=l1_payload,
            rights={"read": ["owner", "body:lease-test-body"], "write": ["owner"],
                    "delete": ["owner"], "export": ["owner"]},
            provenance={"created_by": "lease-test-body", "source": "selftest-lease",
                        "created_at": now_iso()},
            encrypt_key=enc_key,
            lease=lease_obj, body_message=l1_msg, body_signature=l1_sig,
        )
        l1_rid = l1_result["record_id"]

        # Body reads the record via lease
        l1_read_msg = _body_message(OP_READ, record_id=l1_rid)
        l1_read_sig = body_account.sign_message(
            encode_defunct(text=l1_read_msg)).signature.hex()
        l1_read = gw.read_memory(
            subject_soul=soul, record_id=l1_rid,
            lease=lease_obj, body_message=l1_read_msg, body_signature=l1_read_sig,
            decrypt_key=enc_key,
        )
        import base64 as _b64
        if _b64.b64decode(l1_read["payload_b64"]) != l1_payload:
            failures.append("lease-path: decrypted payload mismatch")

        # Wrong body signature -> rejected
        wrong_body = Account.from_key("0x" + secrets.token_hex(32))
        wrong_sig = wrong_body.sign_message(
            encode_defunct(text=l1_read_msg)).signature.hex()
        rejected = False
        try:
            gw.read_memory(
                subject_soul=soul, record_id=l1_rid,
                lease=lease_obj, body_message=l1_read_msg, body_signature=wrong_sig,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("lease-path: wrong body signature was accepted")

        # Wrong lease_id in body_message -> rejected
        bad_msg_payload = {
            "op": OP_READ, "subject": owner_address,
            "lease_id": "lease_DOES_NOT_MATCH", "record_id": l1_rid,
            "nonce": secrets.token_hex(16),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10))
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        bad_msg = canon_json(bad_msg_payload)
        bad_sig = body_account.sign_message(
            encode_defunct(text=bad_msg)).signature.hex()
        rejected = False
        try:
            gw.read_memory(
                subject_soul=soul, record_id=l1_rid,
                lease=lease_obj, body_message=bad_msg, body_signature=bad_sig,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("lease-path: mismatched lease_id was accepted")

        # L3 canonical write via lease -> rejected (canonical_write requires cosign in default lease)
        unsigned_l3 = _lease.build_lease_unsigned(
            subject=owner_address, body_id="lease-test-body",
            body_address=body_account.address,
            scopes={"read":   ["L1_session", "L3_canonical"],
                    "write":  ["L1_session", "L3_canonical"],
                    "delete": [], "export": []},
        )
        lease_l3 = _lease.sign_lease(unsigned_l3, owner_account)
        l3_payload = b"body tries canonical write (should fail cosign check)"
        l3_fp = sha256_hex(l3_payload)
        l3_msg = canon_json({
            "op": OP_WRITE, "subject": owner_address,
            "lease_id": lease_l3["lease_id"],
            "body_id": "lease-test-body", "layer": "L3_canonical",
            "type": "preference", "payload_fingerprint": l3_fp,
            "nonce": secrets.token_hex(16),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10))
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        l3_sig = body_account.sign_message(encode_defunct(text=l3_msg)).signature.hex()
        rejected = False
        try:
            gw.write_memory(
                subject_soul=soul,
                body_id="lease-test-body", layer="L3_canonical", type_="preference",
                payload=l3_payload,
                rights={"read": ["owner"], "write": ["owner"],
                        "delete": ["owner"], "export": ["owner"]},
                provenance={"created_by": "lease-test-body", "source": "selftest-l3",
                            "created_at": now_iso()},
                encrypt_key=enc_key,
                lease=lease_l3, body_message=l3_msg, body_signature=l3_sig,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("lease-path: L3 canonical write was accepted without owner cosign")

        # --- EIP-712 PATH: parallel write/read/delete using typed-data signatures ---
        td_payload = b"my eip-712 preference: dark mode"
        td_fp = sha256_hex(td_payload)
        td_write = build_typed_auth_message(
            OP_WRITE, soul,
            bodyId=body, layer="L3_canonical", recordType="preference",
            payloadFingerprint=td_fp,
        )
        td_write_sig = owner_account.sign_message(
            encode_typed_data(full_message=td_write)
        ).signature.hex()
        td_result = gw.write_memory(
            subject_soul=soul,
            message=td_write, signature=td_write_sig, owner_address=owner_address,
            sig_scheme=SIG_EIP712,
            body_id=body, layer="L3_canonical", type_="preference",
            payload=td_payload,
            rights={"read": ["owner"], "write": ["owner"],
                    "delete": ["owner"], "export": ["owner"]},
            provenance={"created_by": "selftest-712", "source": "selftest-712",
                        "created_at": now_iso()},
            encrypt_key=enc_key,
        )
        td_rid = td_result["record_id"]

        # 712 read
        td_read = build_typed_auth_message(OP_READ, soul, recordId=td_rid)
        td_read_sig = owner_account.sign_message(
            encode_typed_data(full_message=td_read)
        ).signature.hex()
        td_read_result = gw.read_memory(
            subject_soul=soul, record_id=td_rid,
            message=td_read, signature=td_read_sig, owner_address=owner_address,
            sig_scheme=SIG_EIP712,
            decrypt_key=enc_key,
        )
        if base64.b64decode(td_read_result["payload_b64"]) != td_payload:
            failures.append("eip712: decrypted payload mismatch")

        # 712 read with wrong signature -> rejected
        bad_712_sig = "0x" + "0" * 130
        rejected = False
        try:
            gw.read_memory(
                subject_soul=soul, record_id=td_rid,
                message=td_read, signature=bad_712_sig, owner_address=owner_address,
                sig_scheme=SIG_EIP712,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("eip712: bad signature was NOT rejected")

        # 712 write with tampered payload (payloadFingerprint mismatch) -> rejected
        tampered_712 = b"my eip-712 preference: light mode"
        rejected = False
        try:
            gw.write_memory(
                subject_soul=soul,
                message=td_write, signature=td_write_sig, owner_address=owner_address,
                sig_scheme=SIG_EIP712,
                body_id=body, layer="L3_canonical", type_="preference",
                payload=tampered_712,  # different fp
                rights={"read": ["owner"], "write": ["owner"],
                        "delete": ["owner"], "export": ["owner"]},
                provenance={"created_by": "selftest-712", "source": "selftest-712",
                            "created_at": now_iso()},
                encrypt_key=enc_key,
            )
        except SystemExit:
            rejected = True
        if not rejected:
            failures.append("eip712: payload-fingerprint mismatch was NOT rejected")

        # 712 export -> manifest carries sig_scheme + dict message + signature verifies
        td_export = build_typed_auth_message(OP_EXPORT, soul)
        td_export_sig = owner_account.sign_message(
            encode_typed_data(full_message=td_export)
        ).signature.hex()
        td_capsule_dir = tmp / "capsule_712"
        gw.export_memory(
            subject_soul=soul, message=td_export, signature=td_export_sig,
            owner_address=owner_address, out_dir=td_capsule_dir,
            sig_scheme=SIG_EIP712,
        )
        td_manifest = json.loads((td_capsule_dir / "manifest.json").read_text())
        if td_manifest.get("sig_scheme") != SIG_EIP712:
            failures.append("eip712 manifest: sig_scheme not set")
        # Reconstruct the typed-data dict from manifest and verify the signature.
        if not verify_owner_signature_712(
            td_manifest["owner_signature_message"],
            td_manifest["owner_signature"],
            owner_address,
        ):
            failures.append("eip712 manifest: owner_signature does not verify")

        # 712 cross-domain replay protection: tamper the domain -> verification fails
        tampered_td = json.loads(json.dumps({
            **td_export,
            "domain": {**EIP712_DOMAIN, "name": "WrongDomain"},
        }))
        if verify_owner_signature_712(tampered_td, td_export_sig, owner_address):
            failures.append("eip712: cross-domain signature should not verify")

        # Audit chain still intact through lease ops too
        ok, bad = vault.verify_audit_chain()
        if not ok:
            failures.append(f"audit chain broken at entry id={bad}")

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
        prog="rmem-gateway",
        description="rmem-gateway -- Phase B (ERC-8264 ops on top of the vault)",
    )
    parser.add_argument(
        "--vault", default=str(DEFAULT_VAULT_DIR),
        help=f"vault root dir (default: {DEFAULT_VAULT_DIR})",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("read", help="readMemory (owner-direct OR lease auth)")
    p.add_argument("--soul", required=True, help="Soul ID (did:btc:...)")
    p.add_argument("--record", required=True)
    # Owner-direct auth:
    p.add_argument("--sig-scheme", default=SIG_EIP191,
                   choices=[SIG_EIP191, SIG_EIP712],
                   help="signature scheme for --message (default eip191)")
    p.add_argument("--message", help="path to canonical owner-signed message JSON")
    p.add_argument("--signature", help="owner signature hex (0x...)")
    p.add_argument("--owner", help="owner Ethereum address (0x...)")
    # Lease auth:
    p.add_argument("--lease-file", help="path to lease JSON")
    p.add_argument("--body-message", help="path to body-signed message JSON")
    p.add_argument("--body-signature", help="body EIP-191 signature hex (0x...)")
    # Decryption:
    p.add_argument("--decrypt", action="store_true")
    p.add_argument("--vault-key", help="required with --decrypt")
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("write", help="writeMemory (owner-direct OR lease auth)")
    p.add_argument("--soul", required=True)
    # Owner-direct auth:
    p.add_argument("--sig-scheme", default=SIG_EIP191,
                   choices=[SIG_EIP191, SIG_EIP712],
                   help="signature scheme for --message (default eip191)")
    p.add_argument("--message", help="path to canonical owner-signed message JSON")
    p.add_argument("--signature", help="owner signature hex")
    p.add_argument("--owner", help="owner Ethereum address")
    # Lease auth:
    p.add_argument("--lease-file", help="path to lease JSON")
    p.add_argument("--body-message", help="path to body-signed message JSON")
    p.add_argument("--body-signature", help="body EIP-191 signature hex")
    # Op data:
    p.add_argument("--vault-key", required=True)
    p.add_argument("--body", required=True)
    p.add_argument("--layer", required=True, choices=sorted(VALID_LAYERS))
    p.add_argument("--type", required=True, choices=sorted(VALID_TYPES))
    p.add_argument("--payload", required=True, help="file path or '-' for stdin")
    p.add_argument("--rights", help="JSON")
    p.add_argument("--provenance", help="JSON")
    p.add_argument("--source", help="provenance.source override")
    # --also-anchor: after the vault write, also call registry.anchorMemoryRoot
    # on the EVM side with the new memory_root.
    p.add_argument("--also-anchor", action="store_true",
                   help="after vault write, anchor the new memory_root on the EVM registry "
                        "(needs RPC_URL, RMEM_REGISTRY_ADDRESS, DEPLOYER_PRIVATE_KEY)")
    p.add_argument("--anchor-network", default="sepolia",
                   choices=["sepolia", "base-sepolia", "anvil"],
                   help="EVM network preset (default sepolia)")
    p.add_argument("--anchor-rpc-url", default=None,
                   help="RPC URL (else RPC_URL / SEPOLIA_RPC_URL env)")
    p.add_argument("--anchor-contract", default=None,
                   help="registry address (else RMEM_REGISTRY_ADDRESS env)")
    p.add_argument("--anchor-key-file", default=None,
                   help="anchor signer key file (else DEPLOYER_PRIVATE_KEY env)")
    p.add_argument("--anchor-subject", default=None,
                   help="on-chain subject address (defaults to --owner)")
    p.set_defaults(func=cmd_write)

    p = sub.add_parser("delete", help="deleteMemory: tombstone a record (owner-signed)")
    p.add_argument("--soul", required=True)
    p.add_argument("--record", required=True)
    p.add_argument("--sig-scheme", default=SIG_EIP191,
                   choices=[SIG_EIP191, SIG_EIP712],
                   help="signature scheme for --message (default eip191)")
    p.add_argument("--message", required=True)
    p.add_argument("--signature", required=True)
    p.add_argument("--owner", required=True)
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("export", help="exportMemory: produce a portable capsule (owner-signed)")
    p.add_argument("--soul", required=True)
    p.add_argument("--sig-scheme", default=SIG_EIP191,
                   choices=[SIG_EIP191, SIG_EIP712],
                   help="signature scheme for --message (default eip191)")
    p.add_argument("--message", required=True)
    p.add_argument("--signature", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--out", required=True, help="output dir for capsule")
    p.set_defaults(func=cmd_export)

    sub.add_parser("selftest", help="end-to-end test").set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
