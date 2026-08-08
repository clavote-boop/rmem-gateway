#!/usr/bin/env python3
"""Golden vector generator for CAAP standards. Stdlib only. CC0.

Trees are RFC 9162 Merkle Tree Hash (MTH):
  MTH({})   = SHA-256("")
  MTH([e])  = SHA-256(0x00 || e)
  MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])), k = largest power of 2 < n
"""
import hashlib, json

H = lambda b: hashlib.sha256(b).digest()
hx = lambda b: "0x" + b.hex()

def mth(entries):
    n = len(entries)
    if n == 0:
        return H(b"")
    if n == 1:
        return H(b"\x00" + entries[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return H(b"\x01" + mth(entries[:k]) + mth(entries[k:]))

def main():
    chunks = [b"CAAP golden vector chunk %d" % i for i in range(4)]
    out = {
        "tree_construction": "RFC 9162 MTH; leaf 0x00-prefixed, node 0x01-prefixed, "
                             "split at largest power of two < n, no duplication, "
                             "empty root = SHA-256(\"\")",
        "content_tree": {
            "empty_root": hx(mth([])),
            "chunks_utf8": [c.decode() for c in chunks],
            "leaf_hashes": [hx(H(b"\x00" + c)) for c in chunks],
            "roots": {
                "1_leaf": hx(mth(chunks[:1])),
                "2_leaves": hx(mth(chunks[:2])),
                "3_leaves_split_2_1": hx(mth(chunks[:3])),
                "4_leaves": hx(mth(chunks)),
            },
        },
        "hlc64": {
            "unix_ms": 1754680000123,
            "logical": 7,
            "encoded_uint64": (1754680000123 << 16) | 7,
            "encoded_hex": "0x%016x" % ((1754680000123 << 16) | 7),
        },
    }
    rid, ph = bytes.fromhex("11" * 32), bytes.fromhex("22" * 32)
    rid2, ph2 = bytes.fromhex("33" * 32), bytes.fromhex("44" * 32)
    entries = [rid + ph, rid2 + ph2]  # record_index MUST be sorted by record_id
    out["capsule_v2_record_tree"] = {
        "note": "entries are 64-byte record_id||payload_hash, sorted ascending by record_id",
        "record_1": {"record_id": hx(rid), "payload_hash": hx(ph),
                     "leaf": hx(H(b"\x00" + entries[0]))},
        "record_2": {"record_id": hx(rid2), "payload_hash": hx(ph2),
                     "leaf": hx(H(b"\x00" + entries[1]))},
        "root_2_records": hx(mth(entries)),
        "root_1_record": hx(mth(entries[:1])),
        "empty_root": hx(mth([])),
    }
    with open("merkle-hlc-vectors.json", "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print("regenerated merkle-hlc-vectors.json")

if __name__ == "__main__":
    main()
