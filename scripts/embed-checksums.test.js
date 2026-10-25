// Tests for the release checksum embedding script. Run with:
//   node --test scripts/
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const SCRIPT = path.join(__dirname, "embed-checksums.js");

function runEmbed(checksumLines, packageJson) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nyx-embed-test-"));
  const checksumFile = path.join(dir, "checksums.txt");
  const packageFile = path.join(dir, "package.json");
  fs.writeFileSync(checksumFile, checksumLines.join("\n") + "\n");
  fs.writeFileSync(packageFile, JSON.stringify(packageJson, null, 2));
  const result = spawnSync(process.execPath, [SCRIPT, checksumFile, packageFile], {
    encoding: "utf8",
  });
  const written = JSON.parse(fs.readFileSync(packageFile, "utf8"));
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, written };
}

const fullChecksums = (version) =>
  [
    "1111111111111111111111111111111111111111111111111111111111111111  nyx_" + version + "_linux_amd64.tar.gz",
    "2222222222222222222222222222222222222222222222222222222222222222  nyx_" + version + "_linux_arm64.tar.gz",
    "3333333333333333333333333333333333333333333333333333333333333333  nyx_" + version + "_darwin_amd64.tar.gz",
    "4444444444444444444444444444444444444444444444444444444444444444  nyx_" + version + "_darwin_arm64.tar.gz",
    "5555555555555555555555555555555555555555555555555555555555555555  nyx_" + version + "_windows_amd64.zip",
    "6666666666666666666666666666666666666666666666666666666666666666  nyx_" + version + "_windows_arm64.zip",
  ];

test("embeds all six platform checksums", () => {
  const { status, stderr, written } = runEmbed(fullChecksums("0.5.4"), { version: "0.5.3" });
  assert.equal(status, 0, stderr);
  assert.equal(written.binaryChecksums["nyx_0.5.4_linux_amd64.tar.gz"], "1".repeat(64));
  assert.equal(Object.keys(written.binaryChecksums).length, 6);
});

test("refuses an incomplete checksum manifest", () => {
  // A manifest missing a supported platform archive must fail the embed
  // step instead of publishing an incomplete checksum set (#190).
  const lines = fullChecksums("0.5.4").slice(0, 5); // missing windows_arm64
  const { status, stderr } = runEmbed(lines, { version: "0.5.3" });
  assert.notEqual(status, 0);
  assert.match(stderr, /nyx_0\.5\.4_windows_arm64\.zip/);
});

test("refuses a manifest with mixed release versions", () => {
  const lines = fullChecksums("0.5.4").concat([
    "7777777777777777777777777777777777777777777777777777777777777777  nyx_0.5.5_linux_amd64.tar.gz",
  ]);
  const { status, stderr } = runEmbed(lines, { version: "0.5.3" });
  assert.notEqual(status, 0);
  assert.match(stderr, /version/);
});
