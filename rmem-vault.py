#!/usr/bin/env python3
"""rmem-vault — Phase A of the RMEM Gateway.

Encrypted, owner-controlled local memory vault. SQLite index + AES-256-GCM
encrypted payload files + hash-chained audit log. CLI only; no network, no chain.

See product/caas/rmem-gateway/SPEC_v0.1.md.

Security invariants:
- The vault key is never persisted by this code. Caller supplies it per invocation.
- Plaintext payloads exist only in-memory during a single operation.
- payload_hash is computed over the on-disk ciphertext (nonce|ct|tag), so
  integrity is verifiable without decryption.
- The audit log is hash-chained; every operation is recorded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("rmem-vault requires 'cryptography'. pip install cryptography")


SCHEMA_VERSION = 1
DEFAULT_VAULT_DIR = Path.home() / "clavote" / "rmem-vault"
NONCE_LEN = 12
KEY_LEN = 32
ZERO_HASH = "sha256:" + "0" * 64

VALID_LAYERS = {"L1_session", "L2_project", "L3_canonical"}
VALID_TYPES = {
    "preference", "decision", "episodic", "skill", "project_state", "body_calibration",
}


# ---------- helpers ----------

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_hex(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def new_record_id() -> str:
    return f"mem_{int(time.time() * 1000):013d}_{secrets.token_hex(6)}"


def chmod_or_warn(p: Path, mode: int) -> None:
    try:
        p.chmod(mode)
    except OSError as e:
        print(f"warning: could not chmod {p}: {e}", file=sys.stderr)


def load_vault_key(arg_path: Optional[str]) -> bytes:
    """Load 32-byte vault key. --vault-key <path> first, then VAULT_KEY env (hex). Never persisted."""
    if arg_path:
        data = Path(arg_path).read_bytes()
        if len(data) == KEY_LEN:
            return data
        try:
            return bytes.fromhex(data.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            sys.exit(f"vault key file {arg_path}: not {KEY_LEN} raw bytes or hex of same")
    env = os.environ.get("VAULT_KEY")
    if env:
        try:
            return bytes.fromhex(env.strip())
        except ValueError:
            sys.exit("VAULT_KEY env: not valid hex")
    sys.exit("vault key required: pass --vault-key <path> or set VAULT_KEY (hex)")


# ---------- schema ----------

SCHEMA_SQL = """
CREATE TABLE records (
  record_id      TEXT PRIMARY KEY,
  soul_id        TEXT NOT NULL,
  body_id        TEXT,
  layer          TEXT NOT NULL,
  type           TEXT NOT NULL,
  payload_ref    TEXT NOT NULL,
  payload_hash   TEXT NOT NULL,
  rights_json    TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  anchor_ref     TEXT,
  status         TEXT NOT NULL DEFAULT 'active',
  created_at     TEXT NOT NULL,
  tombstoned_at  TEXT,
  sig            TEXT
);
CREATE INDEX idx_records_soul   ON records(soul_id);
CREATE INDEX idx_records_status ON records(status);

CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  op          TEXT NOT NULL,
  soul_id     TEXT,
  record_id   TEXT,
  details     TEXT NOT NULL,
  prev_hash   TEXT NOT NULL,
  this_hash   TEXT NOT NULL
);
CREATE INDEX idx_audit_ts ON audit_log(ts);

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


# ---------- vault ----------

@dataclass
class VaultStore:
    root: Path

    @property
    def db_path(self) -> Path:
        return self.root / "vault.db"

    @property
    def records_dir(self) -> Path:
        return self.root / "records"

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        if self.db_path.exists():
            sys.exit(f"vault already initialised at {self.root}")
        self.root.mkdir(parents=True, exist_ok=True)
        chmod_or_warn(self.root, 0o700)
        self.records_dir.mkdir(exist_ok=True)
        chmod_or_warn(self.records_dir, 0o700)
        conn = self.connect()
        try:
            with conn:
                conn.executescript(SCHEMA_SQL)
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES (?, ?)",
                    ("schema_version", str(SCHEMA_VERSION)),
                )
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES (?, ?)",
                    ("init_ts", now_iso()),
                )
                self._append_audit(conn, "vault.init", None, None, {})
        finally:
            conn.close()
        chmod_or_warn(self.db_path, 0o600)

    # --- audit chain ---

    def _last_audit_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT this_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["this_hash"] if row else ZERO_HASH

    def _append_audit(self, conn: sqlite3.Connection, op: str,
                      soul_id: Optional[str], record_id: Optional[str],
                      details: dict) -> str:
        prev = self._last_audit_hash(conn)
        ts = now_iso()
        entry_bytes = canon_json({
            "prev": prev, "ts": ts, "op": op,
            "soul": soul_id, "record": record_id, "details": details,
        }).encode()
        this_hash = sha256_hex(entry_bytes)
        conn.execute(
            "INSERT INTO audit_log (ts, op, soul_id, record_id, details, prev_hash, this_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, op, soul_id, record_id, canon_json(details), prev, this_hash),
        )
        return this_hash

    def verify_audit_chain(self) -> tuple[bool, Optional[int]]:
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT id, ts, op, soul_id, record_id, details, prev_hash, this_hash "
                "FROM audit_log ORDER BY id ASC"
            ).fetchall()
        finally:
            conn.close()
        expected_prev = ZERO_HASH
        for row in rows:
            entry_bytes = canon_json({
                "prev": expected_prev, "ts": row["ts"], "op": row["op"],
                "soul": row["soul_id"], "record": row["record_id"],
                "details": json.loads(row["details"]),
            }).encode()
            if sha256_hex(entry_bytes) != row["this_hash"] or row["prev_hash"] != expected_prev:
                return False, row["id"]
            expected_prev = row["this_hash"]
        return True, None

    # --- records ---

    def put_record(self, *, key: bytes, soul_id: str, body_id: str, layer: str, type_: str,
                   payload: bytes, rights: dict, provenance: dict) -> dict:
        if layer not in VALID_LAYERS:
            sys.exit(f"invalid layer {layer!r}; valid: {sorted(VALID_LAYERS)}")
        if type_ not in VALID_TYPES:
            sys.exit(f"invalid type {type_!r}; valid: {sorted(VALID_TYPES)}")
        if len(key) != KEY_LEN:
            sys.exit(f"vault key must be {KEY_LEN} bytes, got {len(key)}")
        record_id = new_record_id()
        nonce = secrets.token_bytes(NONCE_LEN)
        aad = f"{record_id}|{soul_id}".encode()
        ct = AESGCM(key).encrypt(nonce, payload, aad)
        on_disk = nonce + ct
        rel_path = f"records/{record_id}.enc"
        target = self.root / rel_path
        with open(target, "xb") as fh:
            fh.write(on_disk)
        chmod_or_warn(target, 0o600)
        payload_hash = sha256_hex(on_disk)
        created_at = now_iso()
        conn = self.connect()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO records (record_id, soul_id, body_id, layer, type, payload_ref, "
                    "payload_hash, rights_json, provenance_json, anchor_ref, status, created_at, "
                    "tombstoned_at, sig) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (record_id, soul_id, body_id, layer, type_, rel_path, payload_hash,
                     canon_json(rights), canon_json(provenance),
                     None, "active", created_at, None, None),
                )
                self._append_audit(
                    conn, "record.put", soul_id, record_id,
                    {"payload_hash": payload_hash, "layer": layer, "type": type_},
                )
        except Exception:
            target.unlink(missing_ok=True)
            raise
        finally:
            conn.close()
        return {"record_id": record_id, "payload_hash": payload_hash, "created_at": created_at}

    def get_record(self, *, soul_id: str, record_id: str,
                   key: Optional[bytes] = None) -> dict:
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT * FROM records WHERE record_id = ? AND soul_id = ?",
                (record_id, soul_id),
            ).fetchone()
            if not row:
                sys.exit(f"record {record_id} not found for soul {soul_id}")
            meta = {k: row[k] for k in row.keys() if k not in {"rights_json", "provenance_json"}}
            meta["rights"] = json.loads(row["rights_json"])
            meta["provenance"] = json.loads(row["provenance_json"])
            status = row["status"]
            payload_hash = row["payload_hash"]
            payload_ref = row["payload_ref"]
            if status == "tombstoned":
                with conn:
                    self._append_audit(conn, "record.read.tombstoned", soul_id, record_id, {})
                return {"meta": meta, "payload": None, "decrypted": False}
            on_disk = (self.root / payload_ref).read_bytes()
            if sha256_hex(on_disk) != payload_hash:
                with conn:
                    self._append_audit(conn, "record.read.hash_mismatch", soul_id, record_id, {})
                sys.exit(f"INTEGRITY FAILURE: on-disk hash != indexed hash for {record_id}")
            if key is None:
                with conn:
                    self._append_audit(conn, "record.read.ciphertext", soul_id, record_id, {})
                return {"meta": meta, "payload": on_disk, "decrypted": False}
            nonce, ct = on_disk[:NONCE_LEN], on_disk[NONCE_LEN:]
            aad = f"{record_id}|{soul_id}".encode()
            try:
                plaintext = AESGCM(key).decrypt(nonce, ct, aad)
            except Exception:
                with conn:
                    self._append_audit(conn, "record.read.decrypt_fail", soul_id, record_id, {})
                sys.exit(f"decryption failed for {record_id} -- wrong key?")
            with conn:
                self._append_audit(conn, "record.read.decrypted", soul_id, record_id, {})
            return {"meta": meta, "payload": plaintext, "decrypted": True}
        finally:
            conn.close()

    def list_records(self, *, soul_id: str, include_tombstoned: bool) -> list[dict]:
        query = (
            "SELECT record_id, layer, type, payload_hash, status, created_at "
            "FROM records WHERE soul_id = ?"
        )
        params: list[Any] = [soul_id]
        if not include_tombstoned:
            query += " AND status = 'active'"
        query += " ORDER BY created_at ASC"
        conn = self.connect()
        try:
            rows = conn.execute(query, params).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def tombstone_record(self, *, soul_id: str, record_id: str) -> dict:
        conn = self.connect()
        try:
            row = conn.execute(
                "SELECT payload_ref, status FROM records WHERE record_id = ? AND soul_id = ?",
                (record_id, soul_id),
            ).fetchone()
            if not row:
                sys.exit(f"record {record_id} not found for soul {soul_id}")
            if row["status"] == "tombstoned":
                sys.exit(f"record {record_id} already tombstoned")
            ts = now_iso()
            with conn:
                conn.execute(
                    "UPDATE records SET status = 'tombstoned', tombstoned_at = ? WHERE record_id = ?",
                    (ts, record_id),
                )
                self._append_audit(conn, "record.tombstone", soul_id, record_id, {})
            target = self.root / row["payload_ref"]
            target.unlink(missing_ok=True)
        finally:
            conn.close()
        return {"record_id": record_id, "tombstoned_at": ts}


# ---------- CLI ----------

def cmd_init(args: argparse.Namespace) -> None:
    VaultStore(Path(args.vault).expanduser()).init()
    print(f"initialised vault at {args.vault}")


def cmd_put(args: argparse.Namespace) -> None:
    key = load_vault_key(args.vault_key)
    vs = VaultStore(Path(args.vault).expanduser())
    payload = sys.stdin.buffer.read() if args.payload == "-" else Path(args.payload).read_bytes()
    rights = json.loads(args.rights) if args.rights else {
        "read": ["owner", f"body:{args.body}"], "write": ["owner"],
        "delete": ["owner"], "export": ["owner"],
    }
    provenance = json.loads(args.provenance) if args.provenance else {
        "created_by": args.body, "source": args.source or "cli", "created_at": now_iso(),
    }
    result = vs.put_record(
        key=key, soul_id=args.soul, body_id=args.body,
        layer=args.layer, type_=args.type,
        payload=payload, rights=rights, provenance=provenance,
    )
    print(json.dumps(result, indent=2))


def cmd_get(args: argparse.Namespace) -> None:
    key = load_vault_key(args.vault_key) if args.decrypt else None
    vs = VaultStore(Path(args.vault).expanduser())
    result = vs.get_record(soul_id=args.soul, record_id=args.record, key=key)
    if args.decrypt and result["decrypted"]:
        sys.stdout.buffer.write(result["payload"])
    else:
        print(json.dumps(result["meta"], indent=2, default=str))


def cmd_list(args: argparse.Namespace) -> None:
    vs = VaultStore(Path(args.vault).expanduser())
    rows = vs.list_records(soul_id=args.soul, include_tombstoned=args.all)
    print(json.dumps(rows, indent=2))


def cmd_tombstone(args: argparse.Namespace) -> None:
    vs = VaultStore(Path(args.vault).expanduser())
    print(json.dumps(
        vs.tombstone_record(soul_id=args.soul, record_id=args.record),
        indent=2,
    ))


def cmd_audit(args: argparse.Namespace) -> None:
    vs = VaultStore(Path(args.vault).expanduser())
    ok, bad_id = vs.verify_audit_chain()
    print(json.dumps({"chain_ok": ok, "broken_at_id": bad_id}, indent=2))


def cmd_selftest(args: argparse.Namespace) -> None:
    """End-to-end smoke test: init -> put -> get (meta + decrypt + wrong-key) -> list -> tombstone -> audit verify."""
    import tempfile
    import shutil
    tmp = Path(tempfile.mkdtemp(prefix="rmem-vault-selftest-"))
    failures: list[str] = []
    try:
        vs = VaultStore(tmp / "v")
        vs.init()
        key = secrets.token_bytes(KEY_LEN)
        soul = "did:btc:testsoul"
        body = "test-body"

        r = vs.put_record(
            key=key, soul_id=soul, body_id=body,
            layer="L1_session", type_="episodic", payload=b"hello world",
            rights={"read": ["owner"], "write": ["owner"], "delete": ["owner"], "export": ["owner"]},
            provenance={"created_by": "test", "source": "selftest", "created_at": now_iso()},
        )
        rid = r["record_id"]

        meta_only = vs.get_record(soul_id=soul, record_id=rid)
        if meta_only["meta"]["record_id"] != rid:
            failures.append("get(meta) returned wrong record_id")

        got = vs.get_record(soul_id=soul, record_id=rid, key=key)
        if got["payload"] != b"hello world":
            failures.append("decrypted payload mismatch")

        wrong_blocked = False
        try:
            vs.get_record(
                soul_id=soul, record_id=rid, key=secrets.token_bytes(KEY_LEN),
            )
        except SystemExit:
            wrong_blocked = True
        if not wrong_blocked:
            failures.append("wrong key did not fail")

        listed = vs.list_records(soul_id=soul, include_tombstoned=False)
        if len(listed) != 1 or listed[0]["record_id"] != rid:
            failures.append(f"list returned {len(listed)} active records (expected 1)")

        vs.tombstone_record(soul_id=soul, record_id=rid)
        enc_path = tmp / "v" / "records" / f"{rid}.enc"
        if enc_path.exists():
            failures.append("tombstone did not delete .enc file")

        post = vs.get_record(soul_id=soul, record_id=rid)
        if post["payload"] is not None:
            failures.append("tombstoned record still returned payload")

        active = vs.list_records(soul_id=soul, include_tombstoned=False)
        all_recs = vs.list_records(soul_id=soul, include_tombstoned=True)
        if len(active) != 0 or len(all_recs) != 1:
            failures.append(
                f"after tombstone: active={len(active)}, all={len(all_recs)} (expected 0, 1)"
            )

        ok, bad = vs.verify_audit_chain()
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
        prog="rmem-vault",
        description="rmem-vault -- Phase A of the RMEM Gateway",
    )
    parser.add_argument(
        "--vault", default=str(DEFAULT_VAULT_DIR),
        help=f"vault root dir (default: {DEFAULT_VAULT_DIR})",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    p = sub.add_parser("put", help="store an encrypted record")
    p.add_argument("--vault-key", help="path to 32-byte key file (or hex); else VAULT_KEY env (hex)")
    p.add_argument("--soul", required=True, help="Soul ID (did:btc:...)")
    p.add_argument("--body", required=True, help="Body ID")
    p.add_argument("--layer", required=True, choices=sorted(VALID_LAYERS))
    p.add_argument("--type", required=True, choices=sorted(VALID_TYPES))
    p.add_argument("--payload", required=True, help="file path, or '-' for stdin")
    p.add_argument("--rights", help="JSON; default: owner-only + read by body")
    p.add_argument("--provenance", help="JSON; default: minimal")
    p.add_argument("--source", help="provenance.source override when using default")
    p.set_defaults(func=cmd_put)

    p = sub.add_parser("get", help="read a record (metadata by default)")
    p.add_argument("--soul", required=True)
    p.add_argument("--record", required=True)
    p.add_argument("--decrypt", action="store_true", help="decrypt and emit plaintext to stdout")
    p.add_argument("--vault-key", help="required with --decrypt")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("list", help="list records for a soul")
    p.add_argument("--soul", required=True)
    p.add_argument("--all", action="store_true", help="include tombstoned")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("tombstone", help="tombstone a record and delete its payload file")
    p.add_argument("--soul", required=True)
    p.add_argument("--record", required=True)
    p.set_defaults(func=cmd_tombstone)

    sub.add_parser("audit", help="verify hash-chained audit log").set_defaults(func=cmd_audit)
    sub.add_parser("selftest", help="run end-to-end smoke test").set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
