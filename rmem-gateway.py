#!/usr/bin/env python3
"""rmem-gateway — Phase B of the RMEM Gateway.

Implements the ERC-8264 four operations (readMemory / writeMemory / deleteMemory /
exportMemory) on top of the Phase A vault. The gateway holds no signing key — every
mutating operation requires an EIP-191 owner signature verified against the subject's
Ethereum address (derived from the same secp256k1 key as the Soul ID).

See SPEC_v0.1.md.

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
import secrets
import shutil
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
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


# ---- ERC-8264 op codes ----

OP_READ = "readMemory"
OP_WRITE = "writeMemory"
OP_DELETE = "deleteMemory"
OP_EXPORT = "exportMemory"

CAPSULE_VERSION = "1"
SIGNATURE_SUITE = "eip-191-authmsg"
SUBJECT_ID_METHOD = "eth-address"
CONTROLLER_METHOD = "eth-address"


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


# ---- merkle root for capsule manifest ----

def merkle_root(leaves: list[str]) -> str:
    """Compute simple binary merkle root over a list of sha256 hex strings.

    Each leaf is treated as the hash itself (already hashed). Internal nodes are
    sha256(left || right). Odd levels duplicate the last node.
    """
    if not leaves:
        return sha256_hex(b"")
    level = [bytes.fromhex(h.split(":", 1)[1]) if h.startswith("sha256:") else bytes.fromhex(h)
             for h in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            import hashlib
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = next_level
    return "sha256:" + level[0].hex()


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
        message: Optional[str] = None,
        signature: Optional[str] = None,
        owner_address: Optional[str] = None,
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
                            extra_match={"record_id": record_id})
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
        message: Optional[str] = None,
        signature: Optional[str] = None,
        owner_address: Optional[str] = None,
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
                            extra_match=extra)
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
        message: str,
        signature: str,
        owner_address: str,
    ) -> dict:
        self._authorise(OP_DELETE, subject_soul, message, signature, owner_address,
                        extra_match={"record_id": record_id})
        result = self.vault.tombstone_record(soul_id=subject_soul, record_id=record_id)
        return {"op": OP_DELETE, "subject": subject_soul, **result}

    # --- export ---

    def export_memory(
        self,
        subject_soul: str,
        message: str,
        signature: str,
        owner_address: str,
        out_dir: Path,
    ) -> dict:
        self._authorise(OP_EXPORT, subject_soul, message, signature, owner_address)
        records = self.vault.list_records(soul_id=subject_soul, include_tombstoned=False)
        if not records:
            sys.exit(f"no active records for {subject_soul}")
        out_dir.mkdir(parents=True, exist_ok=True)
        records_dir = out_dir / "records"
        records_dir.mkdir(exist_ok=True)
        record_index = []
        for r in records:
            src = self.vault.root / "records" / f"{r['record_id']}.enc"
            dst = records_dir / f"{r['record_id']}.enc"
            shutil.copyfile(src, dst)
            record_index.append({
                "record_id": r["record_id"],
                "payload_hash": r["payload_hash"],
                "layer": r["layer"],
                "type": r["type"],
            })
        leaves = [r["payload_hash"] for r in record_index]
        root = merkle_root(leaves)
        manifest = {
            "capsule_version": CAPSULE_VERSION,
            "subject_id": subject_soul,
            "subject_id_method": SUBJECT_ID_METHOD,
            "controllers": [{"method": CONTROLLER_METHOD, "identifier": owner_address}],
            "created_at": now_iso(),
            "signature_suite": SIGNATURE_SUITE,
            "record_index": record_index,
            "merkle_root": root,
            "owner_signature_message": message,
            "owner_signature": signature,
        }
        (out_dir / "manifest.json").write_text(canon_json(manifest))
        return {
            "op": OP_EXPORT,
            "subject": subject_soul,
            "out_dir": str(out_dir),
            "record_count": len(record_index),
            "merkle_root": root,
        }

    # --- internal ---

    def _authorise(
        self,
        op: str,
        subject_soul: str,
        message: str,
        signature: str,
        owner_address: str,
        extra_match: Optional[dict] = None,
    ) -> None:
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
        # 1, 2, 6, 8 -- lease sig + lease expiry + subject match + body sig vs body_address
        check = verify_body_signed_request(lease, body_message, body_signature)
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
        kwargs["message"] = Path(args.message).read_text()
        kwargs["signature"] = args.signature
        kwargs["owner_address"] = args.owner
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
        kwargs["message"] = Path(args.message).read_text()
        kwargs["signature"] = args.signature
        kwargs["owner_address"] = args.owner
    else:
        sys.exit("AUTH_REQUIRED: provide --message+--signature+--owner (owner-direct) "
                 "or --lease-file+--body-message+--body-signature (lease)")
    result = gw.write_memory(**kwargs)
    print(json.dumps(result, indent=2))


def cmd_delete(args: argparse.Namespace) -> None:
    gw = RmemGateway(_vault_for(args))
    message = Path(args.message).read_text()
    result = gw.delete_memory(
        subject_soul=args.soul, record_id=args.record,
        message=message, signature=args.signature, owner_address=args.owner,
    )
    print(json.dumps(result, indent=2))


def cmd_export(args: argparse.Namespace) -> None:
    gw = RmemGateway(_vault_for(args))
    message = Path(args.message).read_text()
    result = gw.export_memory(
        subject_soul=args.soul, message=message, signature=args.signature,
        owner_address=args.owner, out_dir=Path(args.out).expanduser(),
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
        if manifest.get("subject_id") != soul:
            failures.append(f"manifest subject_id mismatch: got {manifest.get('subject_id')!r}")
        if manifest.get("subject_id_method") != "eth-address":
            failures.append(f"manifest subject_id_method != eth-address: {manifest.get('subject_id_method')!r}")
        if manifest.get("capsule_version") != "1":
            failures.append(f"manifest capsule_version != '1': {manifest.get('capsule_version')!r}")
        if manifest.get("signature_suite") != "eip-191-authmsg":
            failures.append(f"manifest signature_suite != eip-191-authmsg: {manifest.get('signature_suite')!r}")
        controllers = manifest.get("controllers") or []
        if not controllers or controllers[0].get("identifier") != owner_address:
            failures.append(f"manifest controllers[0].identifier mismatch: {controllers!r}")
        if len(manifest["record_index"]) != 1:
            failures.append(f"manifest record_index has {len(manifest['record_index'])} entries (expected 1)")
        # Re-verify merkle root independently
        recomputed = merkle_root([r["payload_hash"] for r in manifest["record_index"]])
        if recomputed != manifest["merkle_root"]:
            failures.append("merkle_root does not verify")
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
    p.add_argument("--message", help="path to canonical owner-signed message JSON")
    p.add_argument("--signature", help="owner EIP-191 signature hex (0x...)")
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
    p.add_argument("--message", help="path to canonical owner-signed message JSON")
    p.add_argument("--signature", help="owner EIP-191 signature hex")
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
    p.set_defaults(func=cmd_write)

    p = sub.add_parser("delete", help="deleteMemory: tombstone a record (owner-signed)")
    p.add_argument("--soul", required=True)
    p.add_argument("--record", required=True)
    p.add_argument("--message", required=True)
    p.add_argument("--signature", required=True)
    p.add_argument("--owner", required=True)
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("export", help="exportMemory: produce a portable capsule (owner-signed)")
    p.add_argument("--soul", required=True)
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
