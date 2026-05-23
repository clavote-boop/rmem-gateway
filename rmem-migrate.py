#!/usr/bin/env python3
"""rmem-migrate -- Phase C body migration CLI.

Body-to-body migration: freeze a subject, verify a capsule, mount it into a
fresh target vault with a new vault key (decrypt with old, re-encrypt with new).

Security invariants:
- Vault keys are supplied per invocation by file path; never printed, never
  persisted by this module. Old + new keys live only in process memory.
- Mount NEVER decrypts a record whose on-disk hash does not match the
  capsule's committed payload_hash (integrity gate).
- Mount NEVER overwrites an existing target vault.
- Owner signature on the capsule manifest is verified before any decryption
  is attempted -- a tampered manifest is rejected up front.
- Lease revocation for the old body is handled by rmem-lease.py; this module
  does not duplicate that surface.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import secrets
import shutil
import sys
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("rmem-migrate requires 'cryptography'. pip install cryptography")

try:
    from eth_account import Account
    from eth_account.messages import encode_defunct
except ImportError:
    sys.exit("rmem-migrate requires 'eth-account'. pip install eth-account")


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
load_vault_key = _vault.load_vault_key
KEY_LEN = _vault.KEY_LEN
NONCE_LEN = _vault.NONCE_LEN


# ---- Merkle (must match gateway export) ----

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


def _verify_owner_sig(message: str, sig_hex: str, owner_address: str) -> bool:
    try:
        recovered = Account.recover_message(
            encode_defunct(text=message), signature=sig_hex,
        )
        return recovered.lower() == owner_address.lower()
    except Exception:
        return False


# ---- freeze / unfreeze (vault meta flag) ----

FROZEN_META_PREFIX = "frozen:"


def set_frozen(vault: VaultStore, soul_id: str, frozen: bool = True) -> None:
    conn = vault.connect()
    try:
        with conn:
            key = f"{FROZEN_META_PREFIX}{soul_id}"
            if frozen:
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    (key, now_iso()),
                )
            else:
                conn.execute("DELETE FROM meta WHERE key = ?", (key,))
            vault._append_audit(
                conn, "subject.freeze" if frozen else "subject.unfreeze",
                soul_id, None, {"frozen": frozen},
            )
    finally:
        conn.close()


def is_frozen(vault: VaultStore, soul_id: str) -> bool:
    conn = vault.connect()
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = ?",
            (f"{FROZEN_META_PREFIX}{soul_id}",),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


# ---- verify capsule ----

REQUIRED_MANIFEST_FIELDS = (
    "capsule_version", "soul_id", "controller_pubkeys", "created_at",
    "record_index", "merkle_root", "owner_signature_message", "owner_signature",
)


def verify_capsule(capsule_dir: Path | str) -> dict:
    """Verify a capsule's manifest, signature, Merkle root, and every payload hash.

    Returns {valid: bool, reasons: [str], manifest: dict|None}.
    """
    capsule_dir = Path(capsule_dir)
    manifest_path = capsule_dir / "manifest.json"
    if not manifest_path.exists():
        return {"valid": False, "reasons": ["manifest.json not found"], "manifest": None}
    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception as e:
        return {"valid": False, "reasons": [f"manifest is not valid JSON: {e}"],
                "manifest": None}
    reasons: list[str] = []

    for fld in REQUIRED_MANIFEST_FIELDS:
        if fld not in manifest:
            reasons.append(f"missing required manifest field: {fld}")
    if reasons:
        return {"valid": False, "reasons": reasons, "manifest": manifest}

    # Owner signature on the export-authorization message must recover to
    # controller_pubkeys[0] (the active owner).
    owner_pk = (manifest["controller_pubkeys"] or [None])[0]
    if not owner_pk:
        reasons.append("controller_pubkeys is empty")
    elif not _verify_owner_sig(
        manifest["owner_signature_message"],
        manifest["owner_signature"],
        owner_pk,
    ):
        reasons.append("owner_signature does not recover to controller_pubkeys[0]")

    # Each record's .enc file present + on-disk hash matches manifest entry.
    for entry in manifest["record_index"]:
        rid = entry["record_id"]
        enc_path = capsule_dir / "records" / f"{rid}.enc"
        if not enc_path.exists():
            reasons.append(f"missing payload file: records/{rid}.enc")
            continue
        if sha256_hex(enc_path.read_bytes()) != entry["payload_hash"]:
            reasons.append(f"payload hash mismatch for {rid}")

    # Merkle root recomputes from record_index payload_hashes.
    leaves = [e["payload_hash"] for e in manifest["record_index"]]
    if merkle_root(leaves) != manifest["merkle_root"]:
        reasons.append("merkle_root does not recompute from record_index")

    return {"valid": len(reasons) == 0, "reasons": reasons, "manifest": manifest}


# ---- mount ----

def mount_capsule(
    capsule_dir: Path | str, target_vault_root: Path | str,
    old_vault_key: bytes, new_vault_key: bytes,
    body_id: str = "migrated",
) -> dict:
    """Mount a capsule into a FRESH target vault.

    Decrypts each payload with the old vault key, re-encrypts with the new key
    (preserving record_id and AAD = record_id|soul_id), and stores in the new
    vault. The target vault must not already exist.
    """
    v = verify_capsule(capsule_dir)
    if not v["valid"]:
        raise ValueError(f"capsule verification failed: {v['reasons']}")
    if len(old_vault_key) != KEY_LEN or len(new_vault_key) != KEY_LEN:
        raise ValueError(f"vault keys must be {KEY_LEN} bytes")
    manifest = v["manifest"]
    soul_id = manifest["soul_id"]
    capsule_dir = Path(capsule_dir)
    target = VaultStore(Path(target_vault_root).expanduser())
    if target.db_path.exists():
        raise ValueError(f"target vault already exists at {target.root}")
    target.init()

    mounted: list[str] = []
    aead_old = AESGCM(old_vault_key)
    aead_new = AESGCM(new_vault_key)

    for entry in manifest["record_index"]:
        rid = entry["record_id"]
        layer = entry.get("layer", "L1_session")
        type_ = entry.get("type", "episodic")
        on_disk = (capsule_dir / "records" / f"{rid}.enc").read_bytes()
        nonce, ct = on_disk[:NONCE_LEN], on_disk[NONCE_LEN:]
        aad = f"{rid}|{soul_id}".encode()
        try:
            plaintext = aead_old.decrypt(nonce, ct, aad)
        except Exception as e:
            raise ValueError(f"decryption failed for {rid}: {e}")

        # Re-encrypt with new key + fresh nonce; AAD identical (preserves binding).
        new_nonce = secrets.token_bytes(NONCE_LEN)
        new_ct = aead_new.encrypt(new_nonce, plaintext, aad)
        new_on_disk = new_nonce + new_ct
        new_path = target.records_dir / f"{rid}.enc"
        with open(new_path, "xb") as fh:
            fh.write(new_on_disk)
        try:
            new_path.chmod(0o600)
        except OSError:
            pass
        new_hash = sha256_hex(new_on_disk)

        conn = target.connect()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO records (record_id, soul_id, body_id, layer, type, "
                    "payload_ref, payload_hash, rights_json, provenance_json, anchor_ref, "
                    "status, created_at, tombstoned_at, sig) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, soul_id, body_id, layer, type_,
                     f"records/{rid}.enc", new_hash,
                     canon_json({"read": ["owner"], "write": ["owner"],
                                 "delete": ["owner"], "export": ["owner"]}),
                     canon_json({"created_by": "mount",
                                 "source": f"capsule:{capsule_dir.name}",
                                 "created_at": now_iso(),
                                 "original_payload_hash": entry["payload_hash"]}),
                     None, "active", now_iso(), None, None),
                )
                target._append_audit(
                    conn, "record.mount", soul_id, rid,
                    {"source_capsule": str(capsule_dir),
                     "original_payload_hash": entry["payload_hash"],
                     "new_payload_hash": new_hash},
                )
        finally:
            conn.close()
        mounted.append(rid)

    return {
        "target_vault": str(target.root),
        "soul_id": soul_id,
        "records_mounted": mounted,
        "count": len(mounted),
    }


# ---- CLI ----

def _vault_for(args: argparse.Namespace) -> VaultStore:
    return VaultStore(Path(args.vault).expanduser())


def cmd_freeze(args: argparse.Namespace) -> None:
    set_frozen(_vault_for(args), args.soul, frozen=True)
    print(json.dumps({"soul_id": args.soul, "frozen": True, "at": now_iso()}, indent=2))


def cmd_unfreeze(args: argparse.Namespace) -> None:
    set_frozen(_vault_for(args), args.soul, frozen=False)
    print(json.dumps({"soul_id": args.soul, "frozen": False, "at": now_iso()}, indent=2))


def cmd_is_frozen(args: argparse.Namespace) -> None:
    print(json.dumps({
        "soul_id": args.soul,
        "frozen": is_frozen(_vault_for(args), args.soul),
    }, indent=2))


def cmd_verify_capsule(args: argparse.Namespace) -> None:
    result = verify_capsule(args.capsule_dir)
    out = {"valid": result["valid"], "reasons": result["reasons"]}
    if result["manifest"]:
        out["soul_id"] = result["manifest"]["soul_id"]
        out["record_count"] = len(result["manifest"]["record_index"])
        out["merkle_root"] = result["manifest"]["merkle_root"]
    print(json.dumps(out, indent=2))
    if not result["valid"]:
        sys.exit(1)


def cmd_mount(args: argparse.Namespace) -> None:
    old_key = load_vault_key(args.old_vault_key)
    new_key = load_vault_key(args.new_vault_key)
    try:
        result = mount_capsule(
            args.capsule_dir, args.target_vault, old_key, new_key,
            body_id=args.body_id,
        )
    except ValueError as e:
        sys.exit(str(e))
    print(json.dumps(result, indent=2))


def cmd_selftest(args: argparse.Namespace) -> None:
    """End-to-end: source vault -> hand-built capsule -> verify -> mount -> read back."""
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="rmem-migrate-selftest-"))
    failures: list[str] = []
    try:
        src = VaultStore(tmp / "src")
        src.init()
        old_key = secrets.token_bytes(KEY_LEN)
        new_key = secrets.token_bytes(KEY_LEN)
        owner = Account.from_key("0x" + secrets.token_hex(32))
        soul = owner.address  # use EVM address as subject for capsule

        payload = b"the soul's memory, version 1"
        put = src.put_record(
            key=old_key, soul_id=soul, body_id="old-body-n100",
            layer="L3_canonical", type_="preference", payload=payload,
            rights={"read": ["owner"], "write": ["owner"],
                    "delete": ["owner"], "export": ["owner"]},
            provenance={"created_by": "selftest", "source": "migrate-test",
                        "created_at": now_iso()},
        )
        rid = put["record_id"]

        # Hand-build a capsule that matches rmem-gateway.py's exportMemory output.
        records = src.list_records(soul_id=soul, include_tombstoned=False)
        capsule = tmp / "capsule"
        (capsule / "records").mkdir(parents=True)
        rec_idx = []
        for r in records:
            shutil.copyfile(
                src.root / "records" / f"{r['record_id']}.enc",
                capsule / "records" / f"{r['record_id']}.enc",
            )
            rec_idx.append({
                "record_id": r["record_id"], "payload_hash": r["payload_hash"],
                "layer": r["layer"], "type": r["type"],
            })
        mroot = merkle_root([e["payload_hash"] for e in rec_idx])
        export_msg = canon_json({
            "op": "exportMemory", "subject": soul,
            "nonce": secrets.token_hex(8), "expires_at": "2099-01-01T00:00:00Z",
        })
        export_sig = owner.sign_message(encode_defunct(text=export_msg)).signature.hex()
        manifest = {
            "capsule_version": "0.1", "soul_id": soul,
            "controller_pubkeys": [owner.address],
            "created_at": now_iso(), "record_index": rec_idx,
            "merkle_root": mroot,
            "owner_signature_message": export_msg, "owner_signature": export_sig,
        }
        (capsule / "manifest.json").write_text(canon_json(manifest))

        # --- verify capsule ---
        v = verify_capsule(capsule)
        if not v["valid"]:
            failures.append(f"capsule verify failed: {v['reasons']}")

        # --- tamper detection ---
        bad_path = capsule / "records" / f"{rid}.enc"
        orig = bad_path.read_bytes()
        bad_path.write_bytes(orig + b"X")
        v_tamper = verify_capsule(capsule)
        if v_tamper["valid"]:
            failures.append("tampered payload was accepted by verify_capsule")
        bad_path.write_bytes(orig)

        # --- forged signature detection ---
        man = json.loads((capsule / "manifest.json").read_text())
        man["owner_signature"] = "0x" + "00" * 65
        (capsule / "manifest.json").write_text(canon_json(man))
        v_forge = verify_capsule(capsule)
        if v_forge["valid"]:
            failures.append("forged owner_signature was accepted")
        # restore good manifest
        (capsule / "manifest.json").write_text(canon_json(manifest))

        # --- mount ---
        target_dir = tmp / "target"
        result = mount_capsule(capsule, target_dir, old_key, new_key,
                                body_id="new-body-n100")
        if result["count"] != 1:
            failures.append(f"mount count={result['count']}, expected 1")

        # Read back from target with new key
        target = VaultStore(target_dir)
        got = target.get_record(soul_id=soul, record_id=rid, key=new_key)
        if got["payload"] != payload:
            failures.append("mounted payload != original")

        # Mounted record metadata reflects migration
        meta = got["meta"]
        if meta.get("body_id") != "new-body-n100":
            failures.append(f"mounted body_id={meta.get('body_id')!r}, expected 'new-body-n100'")
        prov = meta.get("provenance", {})
        if prov.get("source", "").split(":")[0] != "capsule":
            failures.append(f"mounted provenance source missing 'capsule:' prefix: {prov}")

        # Old vault key should NOT decrypt mounted records (re-encrypted with new key)
        try:
            target.get_record(soul_id=soul, record_id=rid, key=old_key)
            failures.append("mounted record decrypted with OLD key (re-encryption failed)")
        except SystemExit:
            pass  # expected

        # Second mount to same dir should fail
        try:
            mount_capsule(capsule, target_dir, old_key, new_key)
            failures.append("second mount to existing target should have failed")
        except ValueError:
            pass

        # Mount with wrong old key should fail at decryption
        try:
            mount_capsule(capsule, tmp / "target_wrongkey",
                          secrets.token_bytes(KEY_LEN), new_key)
            failures.append("mount with wrong old key should have failed")
        except ValueError:
            pass

        # --- freeze / unfreeze ---
        if is_frozen(src, soul):
            failures.append("src vault should not be frozen initially")
        set_frozen(src, soul)
        if not is_frozen(src, soul):
            failures.append("set_frozen did not stick")
        set_frozen(src, soul, frozen=False)
        if is_frozen(src, soul):
            failures.append("unfreeze did not stick")

        # Audit chains intact on both vaults
        ok1, bad1 = src.verify_audit_chain()
        if not ok1:
            failures.append(f"src audit chain broken at id={bad1}")
        ok2, bad2 = target.verify_audit_chain()
        if not ok2:
            failures.append(f"target audit chain broken at id={bad2}")

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
        prog="rmem-migrate",
        description="rmem-migrate -- Phase C body migration (freeze / verify-capsule / mount)",
    )
    parser.add_argument("--vault", default=str(DEFAULT_VAULT_DIR))
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("freeze", help="mark a subject as frozen in the vault meta")
    p.add_argument("--soul", required=True)
    p.set_defaults(func=cmd_freeze)

    p = sub.add_parser("unfreeze", help="clear the frozen flag for a subject")
    p.add_argument("--soul", required=True)
    p.set_defaults(func=cmd_unfreeze)

    p = sub.add_parser("is-frozen", help="check whether a subject is frozen")
    p.add_argument("--soul", required=True)
    p.set_defaults(func=cmd_is_frozen)

    p = sub.add_parser("verify-capsule",
                       help="verify a capsule's manifest signature + Merkle root + payload hashes")
    p.add_argument("--capsule-dir", required=True)
    p.set_defaults(func=cmd_verify_capsule)

    p = sub.add_parser("mount",
                       help="mount a capsule into a FRESH target vault "
                            "(decrypt with old key + re-encrypt with new key)")
    p.add_argument("--capsule-dir", required=True)
    p.add_argument("--target-vault", required=True)
    p.add_argument("--old-vault-key", required=True, help="path to old vault key")
    p.add_argument("--new-vault-key", required=True, help="path to new vault key")
    p.add_argument("--body-id", default="migrated",
                   help="body_id to assign to mounted records (default: 'migrated')")
    p.set_defaults(func=cmd_mount)

    sub.add_parser("selftest", help="end-to-end test").set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
