import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { imageSize } from "image-size";

test("reads the checked-in PNG metadata through the bounded local fork", async () => {
  const bytes = await readFile(new URL("../public/og.png", import.meta.url));
  const result = imageSize(bytes);
  assert.equal(result.type, "png");
  assert.ok(result.width > 0);
  assert.ok(result.height > 0);
});

test("rejects the upstream zero-length ICNS denial-of-service shape", () => {
  const malicious = Buffer.alloc(16);
  malicious.write("icns", 0, "ascii");
  malicious.writeUInt32BE(16, 4);
  malicious.write("ic10", 8, "ascii");
  malicious.writeUInt32BE(0, 12);
  assert.throws(() => imageSize(malicious), /Unsupported or unsafe/);
});

test("rejects HEIF and JXL containers instead of parsing unbounded boxes", () => {
  for (const brand of ["heic", "JXL "]) {
    const malicious = Buffer.alloc(32);
    malicious.writeUInt32BE(0, 0);
    malicious.write("ftyp", 4, "ascii");
    malicious.write(brand, 8, "ascii");
    assert.throws(() => imageSize(malicious), /Unsupported or unsafe/);
  }
});
