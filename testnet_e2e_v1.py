#!/usr/bin/env python3
"""End-to-end testnet validation of the chain-agnostic v1 Capsule format.

Walks the full ERC-8264 + ERC-8269 + CAAP-Capsule v0.1 path with the patched
implementation:

  1. Fresh vault A.
  2. Write three records with different layers / types.
  3. Mint a body lease (ERC-8269 Body Lease primitive) and verify its signature.
  4. exportMemory -> Capsule with the v1 chain-agnostic manifest schema.
  5. verify-capsule.
  6. Tamper-detection sanity check (payload byte flip rejected).
  7. Mount the capsule into a fresh vault B with re-encryption.
  8. Confirm the records round-trip back to plaintext under the new key.
  9. Emit the CAAP-Capsule v1 OP_RETURN payload (the 38 bytes that would be
     anchored to Bitcoin via rmem-anchor --network mutinynet).

Network broadcast is intentionally out of scope: the anchor private key
remains off-host per the Work Plan D.2 rule. To actually anchor on mutinynet,
run after this script:

  rmem-anchor anchor-memory-root --soul <subject_id> --network mutinynet \
      --anchor-key <wif_file> --broadcast-via public-api

Exits non-zero on any check failure.
"""
from __future__ import annotations

import importlib.util
import json
import secrets
import sys
import tempfile
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct


HERE = Path(__file__).resolve().parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    vault_mod = _load("rmem_vault", "rmem-vault.py")
    gw_mod = _load("rmem_gateway", "rmem-gateway.py")
    migrate_mod = _load("rmem_migrate", "rmem-migrate.py")
    lease_mod = _load("rmem_lease", "rmem-lease.py")

    VaultStore = vault_mod.VaultStore
    KEY_LEN = vault_mod.KEY_LEN
    sha256_hex = vault_mod.sha256_hex
    RmemGateway = gw_mod.RmemGateway
    build_auth_message = gw_mod.build_auth_message
    OP_EXPORT = gw_mod.OP_EXPORT
    OP_WRITE = gw_mod.OP_WRITE
    build_lease_unsigned = lease_mod.build_lease_unsigned
    sign_lease = lease_mod.sign_lease
    verify_lease_signature = lease_mod.verify_lease_signature
    verify_capsule = migrate_mod.verify_capsule
    mount_capsule = migrate_mod.mount_capsule

    failures: list[str] = []
    artifacts: dict[str, object] = {}

    with tempfile.TemporaryDirectory(prefix="rmem-testnet-e2e-") as tmp_str:
        tmp = Path(tmp_str)

        # 1. Fresh vault A
        vault_a = VaultStore(tmp / "vault_a")
        vault_a.init()
        key_a = secrets.token_bytes(KEY_LEN)

        owner = Account.from_key("0x" + secrets.token_hex(32))
        subject_id = owner.address
        artifacts["subject_id"] = subject_id
        artifacts["subject_id_method"] = "eth-address"

        gw = RmemGateway(vault_a)

        # 2. Three records across layers
        body_id_owner_writes = "owner-direct-body"
        record_payloads = [
            ("L1_session",   "episodic",      b"ephemeral working memory chunk"),
            ("L2_project",   "project_state", b"project-bound note about the ERC split"),
            ("L3_canonical", "preference",    b"durable preference: prefer terse output"),
        ]
        record_ids: list[str] = []
        for layer, type_, payload in record_payloads:
            write_msg = build_auth_message(
                OP_WRITE, subject_id,
                body_id=body_id_owner_writes,
                layer=layer, type=type_,
                payload_fingerprint=sha256_hex(payload),
            )
            write_sig = owner.sign_message(
                encode_defunct(text=write_msg)
            ).signature.hex()
            res = gw.write_memory(
                subject_soul=subject_id,
                body_id=body_id_owner_writes,
                layer=layer, type_=type_,
                payload=payload,
                rights={"read": ["owner"], "write": ["owner"],
                        "delete": ["owner"], "export": ["owner"]},
                provenance={"created_by": "testnet-e2e", "source": "v1-validation"},
                encrypt_key=key_a,
                message=write_msg, signature=write_sig, owner_address=subject_id,
            )
            record_ids.append(res["record_id"])
        artifacts["record_ids"] = record_ids
        if len(record_ids) != 3:
            failures.append(f"wrote {len(record_ids)} records, expected 3")

        # 3. Mint + verify a Body Lease (ERC-8269 primitive)
        body_account = Account.from_key("0x" + secrets.token_hex(32))
        body_id = "test-body-mutinynet-validation"
        unsigned_lease = build_lease_unsigned(
            subject=subject_id,
            body_id=body_id,
            body_address=body_account.address,
            scopes={
                "read":   ["L1_session", "L2_project", "L3_canonical"],
                "write":  ["L1_session"],
                "delete": [],
                "export": [],
            },
            expires_in_hours=1,
        )
        lease = sign_lease(unsigned_lease, owner)
        artifacts["lease_id"] = lease["lease_id"]
        artifacts["lease_scopes"] = lease["scopes"]
        artifacts["lease_expires_at"] = lease["expires_at"]
        if not verify_lease_signature(lease):
            failures.append("lease signature did not verify")

        # 4. exportMemory -> v1 capsule
        export_msg = build_auth_message(OP_EXPORT, subject_id)
        export_sig = owner.sign_message(
            encode_defunct(text=export_msg)
        ).signature.hex()
        capsule_dir = tmp / "capsule_v1"
        gw.export_memory(
            subject_soul=subject_id, message=export_msg, signature=export_sig,
            owner_address=subject_id, out_dir=capsule_dir,
        )
        manifest = json.loads((capsule_dir / "manifest.json").read_text())
        artifacts["manifest"] = manifest
        artifacts["merkle_root"] = manifest["merkle_root"]

        # Spec-compliance checks on the manifest itself
        expected = {
            "capsule_version": "1",
            "subject_id_method": "eth-address",
            "signature_suite": "eip-191-authmsg",
        }
        for k, v in expected.items():
            if manifest.get(k) != v:
                failures.append(
                    f"manifest[{k!r}] = {manifest.get(k)!r}, expected {v!r}"
                )
        if manifest.get("subject_id") != subject_id:
            failures.append(
                f"manifest subject_id = {manifest.get('subject_id')!r}, "
                f"expected {subject_id!r}"
            )
        controllers = manifest.get("controllers") or []
        if not controllers:
            failures.append("manifest controllers is empty")
        elif controllers[0].get("method") != "eth-address":
            failures.append(f"controllers[0].method = {controllers[0].get('method')!r}")
        elif controllers[0].get("identifier") != subject_id:
            failures.append("controllers[0].identifier mismatch")
        if "soul_id" in manifest or "controller_pubkeys" in manifest:
            failures.append("legacy field present in v1 manifest")

        # 5. verify-capsule (should be clean)
        v = verify_capsule(capsule_dir)
        if not v["valid"]:
            failures.append(f"verify_capsule failed: {v['reasons']}")

        # 6. Tamper detection: flip one byte in one ciphertext
        rid0 = manifest["record_index"][0]["record_id"]
        target = capsule_dir / "records" / f"{rid0}.enc"
        orig = target.read_bytes()
        target.write_bytes(orig[:-1] + bytes([orig[-1] ^ 0x01]))
        v_tamper = verify_capsule(capsule_dir)
        if v_tamper["valid"]:
            failures.append("tampered capsule was accepted by verify_capsule")
        target.write_bytes(orig)
        v_clean = verify_capsule(capsule_dir)
        if not v_clean["valid"]:
            failures.append(
                f"clean capsule no longer verifies after restoration: {v_clean['reasons']}"
            )

        # 7. Mount into fresh vault B with re-encryption
        vault_b_root = tmp / "vault_b"
        key_b = secrets.token_bytes(KEY_LEN)
        mount_result = mount_capsule(
            capsule_dir=capsule_dir,
            target_vault_root=vault_b_root,
            old_vault_key=key_a, new_vault_key=key_b,
            body_id="mounted-body",
        )
        artifacts["mounted_record_count"] = mount_result["count"]
        if mount_result["count"] != 3:
            failures.append(f"mounted {mount_result['count']} records, expected 3")

        # 8. Read back from vault B under new key, confirm plaintext matches
        vault_b = VaultStore(vault_b_root)
        roundtrip_pass = 0
        for (layer, type_, expected_bytes), rid in zip(record_payloads, record_ids):
            rec = vault_b.get_record(soul_id=subject_id, record_id=rid, key=key_b)
            if rec["payload"] != expected_bytes:
                failures.append(
                    f"record {rid} plaintext mismatch after mount: "
                    f"got {rec['payload']!r}"
                )
            else:
                roundtrip_pass += 1
        artifacts["records_roundtripped"] = roundtrip_pass

        # 9. CAAP-Capsule v1 OP_RETURN payload (per capsule-spec-v0.1 §7.1)
        #    Layout: 4-byte "CAAP" + 1-byte version + 1-byte commit_type + 32-byte sha256
        merkle_hex = manifest["merkle_root"]
        if merkle_hex.startswith("sha256:"):
            merkle_hex = merkle_hex[len("sha256:"):]
        op_return = b"CAAP" + bytes([0x01]) + bytes([0x01]) + bytes.fromhex(merkle_hex)
        artifacts["op_return_bytes_hex"] = op_return.hex()
        artifacts["op_return_format"] = "caap-btc-opreturn-v1"
        if len(op_return) != 38:
            failures.append(f"OP_RETURN payload {len(op_return)} bytes, expected 38")

    if failures:
        print(json.dumps({
            "status": "FAIL", "failures": failures, "artifacts": artifacts,
        }, indent=2, default=str))
        return 1

    print(json.dumps({"status": "OK", "artifacts": artifacts}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
