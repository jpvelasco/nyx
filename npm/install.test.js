// Tests for the npm install shim's checksum and extraction contracts. Run with:
//   node --test npm/
//
// The shim exports its helpers for these tests; postinstall behavior is
// unchanged because main() only runs when install.js is the entrypoint.
"use strict";

const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { getArchiveName, verifyChecksum, extract } = require("./install.js");

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

// ZIP containing root-level nyx and nyx.exe entries, each with "fixture-binary".
const binaryZip = Buffer.from(
  "UEsDBBQAAAAIAJuwb10/oAnPEAAAAA4AAAADAAAAbnl4S8usKCktStVNysxLLKoEAFBLAwQUAAAACACbsG9dP6AJzxAAAAAOAAAABwAAAG55eC5leGVLy6woKS1K1U3KzEssqgQAUEsBAhQAFAAAAAgAm7BvXT+gCc8QAAAADgAAAAMAAAAAAAAAAAAAAAAAAAAAAG55eFBLAQIUABQAAAAIAJuwb10/oAnPEAAAAA4AAAAHAAAAAAAAAAAAAAAAADEAAABueXguZXhlUEsFBgAAAAACAAIAZgAAAGYAAAAAAA==",
  "base64"
);
const binaryTarGz = Buffer.from(
  "H4sIANWe+moAA+3TMQ6AIAwFUI7CBTRFpT0PJpi4MKAkcHvrymYMGmPf0qQD/A4/lKxaAwBE1Odk9WQGtbEDoTU4AWkwvBuVhubJWNp2FznK3Xfq4z5iWfOeou/mNbhY3k4jnhZK7n32Tf/gPhDRpf5bROn/E6T/QgjxTwcVGrCXAAwAAA==",
  "base64"
);
const archive = process.platform === "win32"
  ? { name: "fixture.zip", buffer: binaryZip }
  : { name: "fixture.tar.gz", buffer: binaryTarGz };

test("extract installs platform archive bytes from quoted paths without the archive module", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nyx install's "));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const binDir = path.join(dir, "bin");
  const installer = path.join(dir, "install.js");
  fs.copyFileSync(path.join(__dirname, "install.js"), installer);
  const modules = path.join(dir, "modules");
  const archiveModule = path.join(modules, "Microsoft.PowerShell.Archive");
  fs.mkdirSync(archiveModule, { recursive: true });
  fs.writeFileSync(
    path.join(archiveModule, "Microsoft.PowerShell.Archive.psm1"),
    "function Expand-Archive { throw 'Incompatible archive module loaded' }; Export-ModuleMember -Function Expand-Archive"
  );
  const result = spawnSync(process.execPath, [
    "-e",
    'require(process.argv[1]).extract(Buffer.from(process.argv[2], "base64"), process.argv[3], process.argv[4])',
    installer, archive.buffer.toString("base64"), archive.name, binDir,
  ], {
    encoding: "utf8",
    env: {
      ...process.env,
      PSModulePath: [modules, process.env.PSModulePath].filter(Boolean).join(path.delimiter),
    },
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(path.join(dir, ".tmp-install")), false);

  const binaryName = process.platform === "win32" ? "nyx.exe" : "nyx";
  assert.equal(fs.readFileSync(path.join(binDir, binaryName), "utf8"), "fixture-binary");
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(path.join(binDir, binaryName)).mode & 0o777, 0o755);
  }
});

test("extract surfaces platform extraction errors and cleans up", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nyx-invalid-archive-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const binDir = path.join(dir, "bin");

  assert.throws(
    () => extract(Buffer.from("not an archive"), archive.name, binDir),
    /exited with code/
  );
  assert.equal(fs.existsSync(binDir), false);
  assert.equal(fs.existsSync(path.join(__dirname, ".tmp-install")), false);
});
