// Tests for the npm install shim's checksum contract. Run with:
//   node --test npm/
//
// The shim exports its helpers for these tests; postinstall behavior is
// unchanged because main() only runs when install.js is the entrypoint.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");

const { getArchiveName, verifyChecksum } = require("./install.js");

function digest(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

test("verifyChecksum refuses a missing platform checksum", () => {
  // A production manifest that lacks the platform archive's checksum must
  // fail instead of silently installing unverified bytes (#190).
  const pkg = { version: "1.2.3", binaryChecksums: { "nyx_1.2.3_linux_amd64.tar.gz": digest(Buffer.from("other")) } };
  assert.throws(
    () => verifyChecksum(Buffer.from("archive-bytes"), "nyx_1.2.3_darwin_arm64.tar.gz", pkg),
    /Missing checksum for nyx_1.2.3_darwin_arm64\.tar\.gz/
  );
});

test("verifyChecksum passes on a matching checksum", () => {
  const buffer = Buffer.from("archive-bytes");
  const pkg = { version: "1.2.3", binaryChecksums: { "nyx_1.2.3_linux_amd64.tar.gz": digest(buffer) } };
  assert.doesNotThrow(() => verifyChecksum(buffer, "nyx_1.2.3_linux_amd64.tar.gz", pkg));
});

test("verifyChecksum throws on a mismatch", () => {
  const pkg = { version: "1.2.3", binaryChecksums: { "nyx_1.2.3_linux_amd64.tar.gz": digest(Buffer.from("different")) } };
  assert.throws(
    () => verifyChecksum(Buffer.from("archive-bytes"), "nyx_1.2.3_linux_amd64.tar.gz", pkg),
    /Checksum mismatch/
  );
});

test("getArchiveName maps the six supported platforms", () => {
  assert.equal(getArchiveName("1.2.3", "linux", "x64"), "nyx_1.2.3_linux_amd64.tar.gz");
  assert.equal(getArchiveName("1.2.3", "linux", "arm64"), "nyx_1.2.3_linux_arm64.tar.gz");
  assert.equal(getArchiveName("1.2.3", "darwin", "x64"), "nyx_1.2.3_darwin_amd64.tar.gz");
  assert.equal(getArchiveName("1.2.3", "darwin", "arm64"), "nyx_1.2.3_darwin_arm64.tar.gz");
  assert.equal(getArchiveName("1.2.3", "win32", "x64"), "nyx_1.2.3_windows_amd64.zip");
  assert.equal(getArchiveName("1.2.3", "win32", "arm64"), "nyx_1.2.3_windows_arm64.zip");
});
