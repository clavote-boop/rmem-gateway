// SPDX-License-Identifier: CC0-1.0
// Generates and verifies the byte-exact CAAP M2 v0.1 vectors.

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function concat(...parts) {
  return Buffer.concat(parts);
}

function uintHead(major, value) {
  const n = BigInt(value);
  if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
  if (n <= 0xffn) return Buffer.from([(major << 5) | 24, Number(n)]);
  if (n <= 0xffffn) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(Number(n), 1);
    return b;
  }
  if (n <= 0xffffffffn) {
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(Number(n), 1);
    return b;
  }
  if (n <= 0xffffffffffffffffn) {
    const b = Buffer.alloc(9);
    b[0] = (major << 5) | 27;
    b.writeBigUInt64BE(n, 1);
    return b;
  }
  throw new RangeError("integer outside uint64");
}

function encode(value) {
  if (typeof value === "bigint" || (typeof value === "number" && Number.isInteger(value))) {
    const n = BigInt(value);
    return n >= 0n ? uintHead(0, n) : uintHead(1, -1n - n);
  }
  if (Buffer.isBuffer(value)) return concat(uintHead(2, value.length), value);
  if (Array.isArray(value)) return concat(uintHead(4, value.length), ...value.map(encode));
  if (value instanceof Map) {
    const entries = [...value.entries()].map(([key, item]) => [encode(key), encode(item)]);
    entries.sort((a, b) => a[0].length - b[0].length || Buffer.compare(a[0], b[0]));
    return concat(uintHead(5, entries.length), ...entries.flat());
  }
  throw new TypeError(`unsupported CBOR value: ${typeof value}`);
}

function sha256(...parts) {
  return crypto.createHash("sha256").update(concat(...parts)).digest();
}

function mth(leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  if (leaves.length === 1) return sha256(Buffer.from([0]), leaves[0]);
  let k = 1;
  while ((k << 1) < leaves.length) k <<= 1;
  return sha256(Buffer.from([1]), mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

function repeat(byte, count = 32) {
  return Buffer.alloc(count, byte);
}

function timePoint() {
  return new Map([
    [0, 3],
    [1, 1_000_000_000],
    [2, 1_700_000_000_000_000_000n],
    [3, 1_000_000],
    [4, 2],
    [5, 0],
  ]);
}

function evidenceItem() {
  return new Map([
    [0, 1],
    [1, 6],
    [2, repeat(0x11)],
    [3, 7],
    [4, timePoint()],
    [5, repeat(0x22)],
    [6, repeat(0x33)],
    [7, repeat(0x44)],
    [8, repeat(0x55)],
    [9, 1],
  ]);
}

function disclosureManifest() {
  const zero = repeat(0x00);
  const start = timePoint();
  const end = new Map(timePoint());
  end.set(1, 2_000_000_000);
  const entry = new Map([
    [0, repeat(0xa0)],
    [1, repeat(0xa1)],
    [2, 3],
    [3, 2],
    [4, repeat(0xa2)],
    [5, [repeat(0xa3), repeat(0xa4)]],
    [6, repeat(0xa5)],
    [7, repeat(0xa6)],
  ]);
  return new Map([
    [0, 1],
    [1, 42],
    [2, 9],
    [3, repeat(0x61)],
    [4, repeat(0x62)],
    [5, repeat(0x63)],
    [6, repeat(0x64)],
    [7, new Map([[0, start], [1, end]])],
    [8, repeat(0x65)],
    [9, repeat(0x66)],
    [10, [entry]],
    [11, repeat(0x67)],
    [12, repeat(0x68)],
    [13, repeat(0x69)],
    [14, zero],
  ]);
}

function actualVectors() {
  const itemBytes = encode(evidenceItem());
  const leaves = [Buffer.from("a"), Buffer.from("b"), Buffer.from("c")];
  const manifestBytes = encode(disclosureManifest());
  return {
    profile: "caap-m2-v0.1",
    evidenceItem: {
      deterministicCborHex: itemBytes.toString("hex"),
      sha256: sha256(itemBytes).toString("hex"),
    },
    rfc9162ThreeLeafTree: {
      leavesHex: leaves.map((leaf) => leaf.toString("hex")),
      leafHashes: leaves.map((leaf) => sha256(Buffer.from([0]), leaf).toString("hex")),
      inclusionProofIndex2: [mth(leaves.slice(0, 2)).toString("hex")],
      root: mth(leaves).toString("hex"),
    },
    disclosureManifest: {
      deterministicCborHex: manifestBytes.toString("hex"),
      disclosureRoot: sha256(Buffer.from([2]), manifestBytes).toString("hex"),
    },
  };
}

const actual = actualVectors();
const vectorPath = path.join(__dirname, "m2-conformance-vectors-v0.1.json");

if (process.argv.includes("--print")) {
  process.stdout.write(`${JSON.stringify(actual, null, 2)}\n`);
  process.exit(0);
}

const expected = JSON.parse(fs.readFileSync(vectorPath, "utf8"));
if (JSON.stringify(actual) !== JSON.stringify(expected)) {
  process.stderr.write("M2 conformance vector mismatch\n");
  process.exit(1);
}
process.stdout.write("M2 conformance vectors verified\n");
