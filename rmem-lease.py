#!/usr/bin/env python3
"""rmem-lease -- Phase C of the RMEM Gateway.

Body Lease primitive: a signed, scoped, expiring binding between an ERC-8264
subject (the owner) and a body (a host/runtime substrate). Implements the Lease
layer of the Portable Agent Memory Capsule companion ERC.

A lease lets a body present an owner-signed credential to the gateway saying
"this body may operate as me, under these scopes, until this time" -- without
the owner having to sign every operation.

Security invariants:
- The owner private key never enters this code's context as text. The owner-key
  file is passed by path and read only inside a subprocess; the key is in memory
  briefly during signing and is not returned by any CLI command.
- The canonical lease JSON is signed with EIP-191 over the manifest *minus* the
  owner_signature field. Verification recovers the address and matches against
  lease.subject.
- A body's signed request is independently verified to match lease.body_address.
- Revocation is effective immediately for subsequent verifications.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except ImportError:
    sys.exit("rmem-lease requires 'eth-account'. pip install eth-account")


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
now_iso = _vault.now_iso


# ---- defaults ----

DEFAULT_SCOPES = {
    "read":   ["L1_session", "L2_project", "L3_canonical"],
    "write":  ["L1_session", "proposal"],
    "delete": [],
    "export": [],
}

DEFAULT_REQUIRES_OWNER_COSIGN = [
    "canonical_write", "skill_install", "delete",
    "export", "body_transfer", "wallet_action",
]


# ---- canonical message helpers ----

def _iso_fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def build_lease_unsigned(
    *, subject: str, body_id: str, body_address: str,
    scopes: Optional[dict] = None, expires_in_hours: int = 24,
    requires_owner_cosign: Optional[list[str]] = None,
) -> dict:
    """Build an unsigned lease dict ready for sign_lease()."""
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(hours=expires_in_hours)
    lease_id = f"lease_{int(issued.timestamp() * 1000):013d}_{secrets.token_hex(6)}"
    return {
        "lease_id": lease_id,
        "subject": subject,
        "body_id": body_id,
        "body_address": body_address,
        "scopes": scopes if scopes is not None else DEFAULT_SCOPES,
        "expires_at": _iso_fmt(expires),
        "issued_at": _iso_fmt(issued),
        "nonce": secrets.token_hex(16),
        "requires_owner_cosign": (
            requires_owner_cosign if requires_owner_cosign is not None
            else DEFAULT_REQUIRES_OWNER_COSIGN
        ),
    }


def sign_lease(unsigned: dict, owner_account: Account) -> dict:
    """Owner-sign an unsigned lease. Returns the full lease dict with owner_signature."""
    if "owner_signature" in unsigned:
        raise ValueError("lease already has owner_signature; clear it first")
    msg = canon_json(unsigned)
    sig_hex = owner_account.sign_message(encode_defunct(text=msg)).signature.hex()
    if not sig_hex.startswith("0x"):
        sig_hex = "0x" + sig_hex
    return {**unsigned, "owner_signature": sig_hex}


def verify_lease_signature(lease: dict) -> bool:
    """Verify the lease's owner_signature recovers to lease.subject."""
    if "owner_signature" not in lease or "subject" not in lease:
        return False
    unsigned = {k: v for k, v in lease.items() if k != "owner_signature"
                and not k.startswith("_")}
    msg = canon_json(unsigned)
    try:
        recovered = Account.recover_message(
            encode_defunct(text=msg), signature=lease["owner_signature"],
        )
        return recovered.lower() == lease["subject"].lower()
    except Exception:
        return False


def is_lease_expired(lease: dict, now: Optional[datetime] = None) -> bool:
    if now is None:
        now = datetime.now(timezone.utc)
    try:
        return now > _parse_iso(lease["expires_at"])
    except Exception:
        return True


def lease_authorizes_op(
    lease: dict, op: str, scope: Optional[str] = None,
) -> dict:
    """Check if a lease covers the requested op + scope.

    Returns {authorized: bool, reason: str|None, requires_owner_cosign: bool}.

    The lease's `requires_owner_cosign` list uses semantic action names
    ("canonical_write", "delete", "export", "skill_install", "body_transfer",
    "wallet_action") rather than ERC-8264 op names. Map ERC-8264 ops to those
    semantic names here:
      - writeMemory + scope=L3_canonical  -> canonical_write
      - deleteMemory                       -> delete
      - exportMemory                       -> export
      - readMemory                         -> never triggers cosign
    """
    op_to_scope_key = {
        "readMemory":   "read",
        "writeMemory":  "write",
        "deleteMemory": "delete",
        "exportMemory": "export",
    }
    scope_key = op_to_scope_key.get(op)
    if scope_key is None:
        return {"authorized": False, "reason": f"unknown op {op!r}",
                "requires_owner_cosign": False}
    allowed = lease.get("scopes", {}).get(scope_key, [])
    if not allowed:
        return {"authorized": False,
                "reason": f"lease grants no {scope_key} scope",
                "requires_owner_cosign": False}
    if scope is not None and scope not in allowed:
        return {"authorized": False,
                "reason": f"scope {scope!r} not in lease.{scope_key} ({allowed})",
                "requires_owner_cosign": False}
    # Map ERC-8264 op (+ optional scope) to semantic cosign-list name(s)
    cosign_list = lease.get("requires_owner_cosign", [])
    requires_cosign = False
    if op == "writeMemory" and scope == "L3_canonical" and "canonical_write" in cosign_list:
        requires_cosign = True
    elif op == "deleteMemory" and "delete" in cosign_list:
        requires_cosign = True
    elif op == "exportMemory" and "export" in cosign_list:
        requires_cosign = True
    # readMemory never triggers cosign
    return {"authorized": True, "reason": None,
            "requires_owner_cosign": requires_cosign}


def verify_body_signed_request(
    lease: dict, message: str, body_signature: str,
    now: Optional[datetime] = None,
) -> dict:
    """Verify a body-signed request against a lease.

    Checks: lease signature valid, lease not expired, message subject matches
    lease.subject, body signature recovers to lease.body_address.
    Returns {valid: bool, reason: str|None}.
    """
    if not verify_lease_signature(lease):
        return {"valid": False, "reason": "lease owner_signature invalid"}
    if is_lease_expired(lease, now):
        return {"valid": False, "reason": "lease expired"}
    try:
        msg = json.loads(message)
    except Exception:
        return {"valid": False, "reason": "message is not valid JSON"}
    if msg.get("subject") != lease["subject"]:
        return {"valid": False, "reason": "message subject != lease subject"}
    try:
        recovered = Account.recover_message(
            encode_defunct(text=message), signature=body_signature,
        )
    except Exception:
        return {"valid": False, "reason": "body signature recovery error"}
    if recovered.lower() != lease["body_address"].lower():
        return {"valid": False,
                "reason": "body signature does not match lease.body_address"}
    return {"valid": True, "reason": None}


# ---- leases table (lazy create in vault.db) ----

LEASES_SCHEMA = """
CREATE TABLE IF NOT EXISTS leases (
  lease_id              TEXT PRIMARY KEY,
  subject               TEXT NOT NULL,
  body_id               TEXT NOT NULL,
  body_address          TEXT NOT NULL,
  scopes_json           TEXT NOT NULL,
  requires_cosign_json  TEXT NOT NULL,
  expires_at            TEXT NOT NULL,
  issued_at             TEXT NOT NULL,
  nonce                 TEXT NOT NULL,
  owner_signature       TEXT NOT NULL,
  full_json             TEXT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'active',
  revoked_at            TEXT
);
CREATE INDEX IF NOT EXISTS idx_leases_subject ON leases(subject);
CREATE INDEX IF NOT EXISTS idx_leases_body    ON leases(body_id);
CREATE INDEX IF NOT EXISTS idx_leases_status  ON leases(status);
"""


def ensure_leases_table(vault: VaultStore) -> None:
    conn = vault.connect()
    try:
        with conn:
            conn.executescript(LEASES_SCHEMA)
    finally:
        conn.close()


def store_lease(vault: VaultStore, lease: dict) -> None:
    if not verify_lease_signature(lease):
        raise ValueError("refusing to store: lease owner_signature does not verify")
    ensure_leases_table(vault)
    conn = vault.connect()
    try:
        with conn:
            conn.execute(
                "INSERT INTO leases (lease_id, subject, body_id, body_address, "
                "scopes_json, requires_cosign_json, expires_at, issued_at, nonce, "
                "owner_signature, full_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (lease["lease_id"], lease["subject"], lease["body_id"],
                 lease["body_address"], canon_json(lease["scopes"]),
                 canon_json(lease["requires_owner_cosign"]),
                 lease["expires_at"], lease["issued_at"], lease["nonce"],
                 lease["owner_signature"], canon_json(lease)),
            )
            vault._append_audit(
                conn, "lease.issued", lease["subject"], None,
                {"lease_id": lease["lease_id"], "body_id": lease["body_id"],
                 "body_address": lease["body_address"],
                 "expires_at": lease["expires_at"]},
            )
    finally:
        conn.close()


def load_lease(vault: VaultStore, lease_id: str) -> Optional[dict]:
    ensure_leases_table(vault)
    conn = vault.connect()
    try:
        row = conn.execute(
            "SELECT full_json, status, revoked_at FROM leases WHERE lease_id = ?",
            (lease_id,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    lease = json.loads(row["full_json"])
    lease["_status"] = row["status"]
    lease["_revoked_at"] = row["revoked_at"]
    return lease


def list_leases(
    vault: VaultStore, *, subject: Optional[str] = None,
    body_id: Optional[str] = None, active_only: bool = False,
) -> list[dict]:
    ensure_leases_table(vault)
    q = ("SELECT lease_id, subject, body_id, body_address, expires_at, "
         "issued_at, status, revoked_at FROM leases WHERE 1=1")
    params: list = []
    if subject:
        q += " AND subject = ?"
        params.append(subject)
    if body_id:
        q += " AND body_id = ?"
        params.append(body_id)
    if active_only:
        q += " AND status = 'active'"
    q += " ORDER BY issued_at DESC"
    conn = vault.connect()
    try:
        rows = conn.execute(q, params).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def revoke_lease(vault: VaultStore, lease_id: str, owner_account: Account) -> dict:
    lease = load_lease(vault, lease_id)
    if not lease:
        raise ValueError(f"lease {lease_id} not found")
    if lease.get("_status") != "active":
        raise ValueError(f"lease {lease_id} already {lease.get('_status')}")
    if owner_account.address.lower() != lease["subject"].lower():
        raise ValueError(
            f"REVOKE_DENIED: owner key {owner_account.address} != lease subject {lease['subject']}"
        )
    revoked_at = now_iso()
    conn = vault.connect()
    try:
        with conn:
            conn.execute(
                "UPDATE leases SET status = 'revoked', revoked_at = ? WHERE lease_id = ?",
                (revoked_at, lease_id),
            )
            vault._append_audit(
                conn, "lease.revoked", lease["subject"], None,
                {"lease_id": lease_id,
                 "revoked_by": owner_account.address},
            )
    finally:
        conn.close()
    return {"lease_id": lease_id, "revoked_at": revoked_at}


# ---- CLI ----

def _load_owner_privkey(arg_path: Optional[str]) -> str:
    """Load owner private key (hex, 0x-prefixed). File or env. Never persisted."""
    if arg_path:
        data = Path(arg_path).read_text(encoding="utf-8-sig").strip()
        if not data.startswith("0x"):
            data = "0x" + data
        return data
    env = os.environ.get("OWNER_PRIVKEY")
    if env:
        return env.strip() if env.startswith("0x") else "0x" + env.strip()
    sys.exit("owner key required: pass --owner-key <path> or set OWNER_PRIVKEY env")


def _vault_for(args: argparse.Namespace) -> VaultStore:
    return VaultStore(Path(args.vault).expanduser())


def cmd_issue(args: argparse.Namespace) -> None:
    owner_priv = _load_owner_privkey(args.owner_key)
    owner_account = Account.from_key(owner_priv)
    scopes = json.loads(args.scopes) if args.scopes else None
    rc = args.requires_cosign.split(",") if args.requires_cosign else None
    unsigned = build_lease_unsigned(
        subject=owner_account.address,
        body_id=args.body_id, body_address=args.body_address,
        scopes=scopes, expires_in_hours=args.expires_in_hours,
        requires_owner_cosign=rc,
    )
    lease = sign_lease(unsigned, owner_account)
    store_lease(_vault_for(args), lease)
    print(json.dumps({
        "lease_id": lease["lease_id"], "subject": lease["subject"],
        "body_id": lease["body_id"], "body_address": lease["body_address"],
        "expires_at": lease["expires_at"], "scopes": lease["scopes"],
    }, indent=2))


def cmd_present(args: argparse.Namespace) -> None:
    lease = load_lease(_vault_for(args), args.lease_id)
    if not lease:
        sys.exit(f"lease {args.lease_id} not found")
    for k in ("_status", "_revoked_at"):
        lease.pop(k, None)
    print(json.dumps(lease, indent=2))


def cmd_list(args: argparse.Namespace) -> None:
    rows = list_leases(
        _vault_for(args), subject=args.subject, body_id=args.body,
        active_only=args.active_only,
    )
    print(json.dumps(rows, indent=2, default=str))


def cmd_verify(args: argparse.Namespace) -> None:
    lease = load_lease(_vault_for(args), args.lease_id)
    if not lease:
        sys.exit(f"lease {args.lease_id} not found")
    sig_ok = verify_lease_signature(lease)
    expired = is_lease_expired(lease)
    status = lease.get("_status")
    print(json.dumps({
        "lease_id": args.lease_id,
        "signature_valid": sig_ok,
        "expired": expired,
        "status": status,
        "active_now": sig_ok and not expired and status == "active",
    }, indent=2))


def cmd_revoke(args: argparse.Namespace) -> None:
    owner_priv = _load_owner_privkey(args.owner_key)
    owner_account = Account.from_key(owner_priv)
    try:
        result = revoke_lease(_vault_for(args), args.lease_id, owner_account)
    except ValueError as e:
        sys.exit(str(e))
    print(json.dumps(result, indent=2))


def cmd_selftest(args: argparse.Namespace) -> None:
    """End-to-end: issue -> verify sig -> body-signs request -> revoke -> verify denied."""
    import tempfile
    import shutil
    tmp = Path(tempfile.mkdtemp(prefix="rmem-lease-selftest-"))
    failures: list[str] = []
    try:
        vault = VaultStore(tmp / "v")
        vault.init()

        # --- generate test keypairs (in-process, no files) ---
        owner = Account.from_key("0x" + secrets.token_hex(32))
        body = Account.from_key("0x" + secrets.token_hex(32))

        # --- issue lease ---
        unsigned = build_lease_unsigned(
            subject=owner.address, body_id="n100-test", body_address=body.address,
            expires_in_hours=1,
        )
        lease = sign_lease(unsigned, owner)
        if not verify_lease_signature(lease):
            failures.append("issued lease signature does not verify")
        store_lease(vault, lease)
        lid = lease["lease_id"]

        # --- load back, sig still valid ---
        loaded = load_lease(vault, lid)
        if not loaded:
            failures.append("could not load just-stored lease")
        elif not verify_lease_signature(loaded):
            failures.append("loaded lease signature does not verify")

        # --- list filters ---
        all_leases = list_leases(vault, subject=owner.address)
        if len(all_leases) != 1:
            failures.append(f"list by subject got {len(all_leases)} (expected 1)")
        active_only = list_leases(vault, active_only=True)
        if len(active_only) != 1:
            failures.append(f"active_only got {len(active_only)} (expected 1)")

        # --- lease_authorizes_op checks ---
        read_check = lease_authorizes_op(lease, "readMemory", "L3_canonical")
        if not read_check["authorized"]:
            failures.append(f"readMemory L3 should be authorized: {read_check['reason']}")
        delete_check = lease_authorizes_op(lease, "deleteMemory")
        if delete_check["authorized"]:
            failures.append("deleteMemory should NOT be authorized (empty delete scope)")
        write_session = lease_authorizes_op(lease, "writeMemory", "L1_session")
        if not write_session["authorized"]:
            failures.append("writeMemory L1 should be authorized")
        if write_session["requires_owner_cosign"]:
            failures.append("L1 session write should not require owner cosign by default")

        # --- cosign mapping: a lease that allows L3 writes still requires
        #     owner cosign for canonical writes (when 'canonical_write' is in
        #     the cosign list, which is the default).
        unsigned_l3 = build_lease_unsigned(
            subject=owner.address, body_id="n100-l3-test", body_address=body.address,
            scopes={"read":   ["L1_session", "L3_canonical"],
                    "write":  ["L1_session", "L3_canonical"],
                    "delete": [], "export": []},
        )
        lease_l3 = sign_lease(unsigned_l3, owner)
        l1_check = lease_authorizes_op(lease_l3, "writeMemory", "L1_session")
        if not l1_check["authorized"]:
            failures.append("L1 write should still be authorized in L3-extended lease")
        if l1_check["requires_owner_cosign"]:
            failures.append("L1 write should NOT require cosign even with canonical_write listed")
        l3_check = lease_authorizes_op(lease_l3, "writeMemory", "L3_canonical")
        if not l3_check["authorized"]:
            failures.append("L3 canonical write should be authorized in L3-extended lease")
        if not l3_check["requires_owner_cosign"]:
            failures.append("L3 canonical write SHOULD require owner cosign (canonical_write in default cosign list)")

        # --- body signs a valid request, verify succeeds ---
        msg = canon_json({
            "op": "readMemory", "subject": owner.address,
            "record_id": "mem_test", "nonce": secrets.token_hex(8),
        })
        body_sig = body.sign_message(encode_defunct(text=msg)).signature.hex()
        check = verify_body_signed_request(lease, msg, body_sig)
        if not check["valid"]:
            failures.append(f"valid body-signed request rejected: {check['reason']}")

        # --- wrong body signs, verification fails ---
        wrong_body = Account.from_key("0x" + secrets.token_hex(32))
        wrong_sig = wrong_body.sign_message(encode_defunct(text=msg)).signature.hex()
        check2 = verify_body_signed_request(lease, msg, wrong_sig)
        if check2["valid"]:
            failures.append("wrong body signature was accepted")

        # --- message subject mismatch fails ---
        bad_msg = canon_json({
            "op": "readMemory", "subject": wrong_body.address,
            "record_id": "mem_test", "nonce": secrets.token_hex(8),
        })
        bad_body_sig = body.sign_message(encode_defunct(text=bad_msg)).signature.hex()
        check3 = verify_body_signed_request(lease, bad_msg, bad_body_sig)
        if check3["valid"]:
            failures.append("mismatched subject was accepted")

        # --- expired lease rejected ---
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        if not is_lease_expired({"expires_at": _iso_fmt(past)}):
            failures.append("past expires_at not detected as expired")
        if is_lease_expired({"expires_at": _iso_fmt(future)}):
            failures.append("future expires_at incorrectly flagged as expired")

        # --- revoke ---
        result = revoke_lease(vault, lid, owner)
        if "revoked_at" not in result:
            failures.append("revoke did not return revoked_at")
        post = load_lease(vault, lid)
        if not post or post.get("_status") != "revoked":
            failures.append(f"post-revoke status: {post.get('_status') if post else 'None'}")

        # --- second revoke fails ---
        try:
            revoke_lease(vault, lid, owner)
            failures.append("second revoke should have failed")
        except ValueError:
            pass

        # --- revoke by wrong key fails ---
        unsigned2 = build_lease_unsigned(
            subject=owner.address, body_id="n100-test2", body_address=body.address,
        )
        lease2 = sign_lease(unsigned2, owner)
        store_lease(vault, lease2)
        try:
            revoke_lease(vault, lease2["lease_id"], wrong_body)
            failures.append("revoke by wrong key should have failed")
        except ValueError:
            pass

        # --- tampered lease detected ---
        tampered = dict(lease)
        tampered["expires_at"] = _iso_fmt(datetime.now(timezone.utc) + timedelta(days=365))
        if verify_lease_signature(tampered):
            failures.append("tampered lease (expiry extended) verified as valid")

        # --- audit chain still intact ---
        ok, bad = vault.verify_audit_chain()
        if not ok:
            failures.append(f"audit chain broken at id={bad}")

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
        prog="rmem-lease",
        description="rmem-lease -- Phase C (Body Lease primitive)",
    )
    parser.add_argument(
        "--vault", default=str(DEFAULT_VAULT_DIR),
        help=f"vault root dir (default: {DEFAULT_VAULT_DIR})",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("issue", help="owner-sign a new lease and store it")
    p.add_argument("--owner-key", help="path to file with 32-byte hex priv key; else OWNER_PRIVKEY env")
    p.add_argument("--body-id", required=True, help="implementor name (e.g. n100-clemsbox)")
    p.add_argument("--body-address", required=True, help="body Ethereum address (0x...)")
    p.add_argument("--scopes", help="JSON: scope vocabulary override")
    p.add_argument("--expires-in-hours", type=int, default=24)
    p.add_argument("--requires-cosign", help="comma-separated ops requiring owner cosign")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("present", help="output a lease's full JSON for handing to a body")
    p.add_argument("--lease-id", required=True)
    p.set_defaults(func=cmd_present)

    p = sub.add_parser("list", help="list leases (with filters)")
    p.add_argument("--subject")
    p.add_argument("--body")
    p.add_argument("--active-only", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("verify", help="re-verify a stored lease's signature + check status")
    p.add_argument("--lease-id", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("revoke", help="owner-revoke a lease (must hold subject key)")
    p.add_argument("--owner-key", help="path to file with owner priv key; else OWNER_PRIVKEY env")
    p.add_argument("--lease-id", required=True)
    p.set_defaults(func=cmd_revoke)

    sub.add_parser("selftest", help="end-to-end test").set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
