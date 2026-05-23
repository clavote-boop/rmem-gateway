"""Domain-separated hashing and Merkle construction per
agent_memory_rights_v0_3_3 (Def. 2, Table 1, Def. 4).

All TAG strings from Table 1 are length-prefixed per Def. 2 ("with a
length-prefixed TAG to prevent extension"). Merkle leaves and internal nodes
carry the 0x00 / 0x01 byte prefixes from Def. 4 to prevent second-preimage
confusion between leaves and internal nodes.

Used by every other rmem-gateway module that needs to produce or verify a
spec-conformant hash.
"""
from __future__ import annotations

import hashlib
import json
from typing import Iterable


# ---- Table 1 tags ----
TAG_MEMORY_RECORD    = b"MEMORY_RECORD"
TAG_ERC8263_EVENT    = b"ERC8263_EVENT"
TAG_CAPSULE_CHUNK    = b"CAPSULE_CHUNK"
TAG_CAPSULE_MANIFEST = b"CAPSULE_MANIFEST"
TAG_CAAP_ANCHOR      = b"CAAP_ANCHOR"
TAG_BODY_ACTION      = b"BODY_ACTION"

# ---- Merkle node prefixes (Def. 4) ----
MERKLE_LEAF_PREFIX     = b"\x00"
MERKLE_INTERNAL_PREFIX = b"\x01"

# ---- canonProfile (Def. 1) ----
CANON_PROFILE_JCS = "jcs-rfc8785"
CANON_PROFILE_CBOR = "cbor-rfc8949"
RECOGNIZED_CANON_PROFILES = frozenset({CANON_PROFILE_JCS, CANON_PROFILE_CBOR})


def canon_json(obj) -> str:
    """RFC 8785-shaped canonicalization for the JSON subset used here.

    All keys in this codebase are ASCII; values are strings, ints, bools, lists,
    and objects (no floats, no surrogates). For that subset, sort_keys=True with
    comma/colon separators matches RFC 8785.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def tagged_sha256(tag: bytes, *parts: bytes) -> bytes:
    """Length-prefixed tagged SHA-256: sha256(len(tag) || tag || part1 || ...).

    The 1-byte length prefix is sufficient for all TAGs in Table 1 (max 16 bytes).
    """
    if not isinstance(tag, (bytes, bytearray)):
        raise TypeError("tag must be bytes")
    if len(tag) == 0 or len(tag) > 255:
        raise ValueError(f"tag length {len(tag)} out of range")
    h = hashlib.sha256()
    h.update(bytes([len(tag)]))
    h.update(tag)
    for p in parts:
        if not isinstance(p, (bytes, bytearray)):
            raise TypeError("hash parts must be bytes")
        h.update(p)
    return h.digest()


def tagged_sha256_hex(tag: bytes, *parts: bytes) -> str:
    """Same as tagged_sha256 but returns 'sha256:<hex>' string for storage."""
    return "sha256:" + tagged_sha256(tag, *parts).hex()


def hex_to_bytes(h: str) -> bytes:
    """Accept 'sha256:<hex>' / '0x<hex>' / '<hex>' and return raw bytes."""
    s = h.split(":", 1)[1] if h.startswith("sha256:") else h
    s = s[2:] if s.startswith("0x") else s
    return bytes.fromhex(s)


def _merkle_combine(level: list[bytes]) -> list[bytes]:
    if len(level) % 2 == 1:
        level = level + [level[-1]]
    return [
        hashlib.sha256(MERKLE_INTERNAL_PREFIX + level[i] + level[i + 1]).digest()
        for i in range(0, len(level), 2)
    ]


def merkle_root_v2(leaves: Iterable[bytes]) -> bytes:
    """Capsule Merkle root per Def. 4.

    - Empty leaf set: sentinel = sha256(0x00) — distinct from any real leaf hash.
    - Leaves: H(0x00 || leaf)
    - Internal: H(0x01 || left || right)
    - Right-duplicate padding to power of two.
    """
    leaves = list(leaves)
    if not leaves:
        return hashlib.sha256(MERKLE_LEAF_PREFIX).digest()
    level = [hashlib.sha256(MERKLE_LEAF_PREFIX + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        level = _merkle_combine(level)
    return level[0]


def merkle_root_v2_hex(leaves: Iterable[bytes]) -> str:
    return "sha256:" + merkle_root_v2(leaves).hex()


def manifest_meta_hash(meta: dict) -> bytes:
    """h_m per Def. 4: tagged hash over the canonical manifest metadata.

    `meta` must contain ONLY the manifest-configuration fields (capsule_version,
    canonProfile, hashAlg, soul_id, controller_pubkeys, created_at, sig_scheme)
    — not record_index, not merkle_root, not the signature itself, since those
    are downstream of h_m.
    """
    return tagged_sha256(TAG_CAPSULE_MANIFEST, canon_json(meta).encode("utf-8"))


def chunk_hash(chunk_bytes: bytes) -> bytes:
    """h_i per Def. 4: tagged hash over the canonical chunk bytes.

    For our capsule the canonical form of an encrypted chunk is its raw bytes
    (already a deterministic byte string by construction).
    """
    return tagged_sha256(TAG_CAPSULE_CHUNK, chunk_bytes)


def chunk_hash_hex(chunk_bytes: bytes) -> str:
    return "sha256:" + chunk_hash(chunk_bytes).hex()


def graph_hash(graph: dict) -> bytes:
    """H(canon(G_X)) per Def. 4: untagged hash over canonical provenance graph."""
    return hashlib.sha256(canon_json(graph).encode("utf-8")).digest()


def capsule_merkle_root(
    manifest_meta: dict,
    chunk_hashes: list[bytes],
    provenance_graph: dict,
) -> bytes:
    """Build the full Def. 4 leaf sequence and compute R_X.

    ℓ_0 = h_m
    ℓ_1..ℓ_n = h_1..h_n
    ℓ_{n+1} = H(canon(G_X))
    """
    leaves = [manifest_meta_hash(manifest_meta)]
    leaves.extend(chunk_hashes)
    leaves.append(graph_hash(provenance_graph))
    return merkle_root_v2(leaves)


def capsule_merkle_root_hex(
    manifest_meta: dict,
    chunk_hashes: list[bytes],
    provenance_graph: dict,
) -> str:
    return "sha256:" + capsule_merkle_root(
        manifest_meta, chunk_hashes, provenance_graph,
    ).hex()


def anchor_digest(merkle_root_bytes: bytes, domain: str) -> bytes:
    """H(CAAP_ANCHOR || R_X || domain) per Eq. anchor.

    `domain` is the chain/protocol scope (e.g. 'bitcoin-signet', 'ethereum-1');
    pinning it into the digest prevents replaying R_X across protocols.
    """
    if len(merkle_root_bytes) != 32:
        raise ValueError(f"merkle_root must be 32 bytes, got {len(merkle_root_bytes)}")
    return tagged_sha256(TAG_CAAP_ANCHOR, merkle_root_bytes, domain.encode("utf-8"))


def body_action_digest(action_canon_bytes: bytes) -> bytes:
    """H(BODY_ACTION || canon(α)) per Eq. cosign. Subject signs this digest."""
    return tagged_sha256(TAG_BODY_ACTION, action_canon_bytes)
