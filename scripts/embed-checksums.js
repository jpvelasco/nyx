#!/usr/bin/env node
// nosemgrep: all — release build script, not application code
"use strict";

// embed-checksums.js — Embeds SHA-256 checksums from GoReleaser's checksums.txt
// into npm/package.json's binaryChecksums field.
//
// Usage: node scripts/embed-checksums.js dist/checksums.txt npm/package.json
//
// GoReleaser checksums.txt format:
//   <sha256hex>  <filename>

const fs = require("fs");

const [checksumFile, packageFile] = process.argv.slice(2);
if (!checksumFile || !packageFile) {
  console.error("Usage: node embed-checksums.js <checksums.txt> <package.json>");
  process.exit(1);
}

const checksums = fs.readFileSync(checksumFile, "utf8");
const pkg = JSON.parse(fs.readFileSync(packageFile, "utf8"));

pkg.binaryChecksums = {};
for (const line of checksums.split("\n")) {
  const match = line.match(/^([0-9a-f]{64})\s+(.+)$/i);
  if (match) {
    const [, hash, filename] = match;
    pkg.binaryChecksums[filename] = hash.toLowerCase();
  }
}

const count = Object.keys(pkg.binaryChecksums).length;
if (count === 0) {
  console.error("Warning: no checksums found in " + checksumFile);
  process.exit(1);
}

// Completeness: every supported platform archive must carry a checksum —
// an incomplete manifest would let the install shim fail on (or worse,
// before this fix, silently skip verification for) the missing platform.
// The release version is derived from the checksummed archive names
// themselves: this script runs before `npm version`, so package.json
// still carries the previous version.
const versions = new Set();
for (const filename of Object.keys(pkg.binaryChecksums)) {
  const match = filename.match(/^nyx_(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)_/);
  if (match) {
    versions.add(match[1]);
  }
}
if (versions.size !== 1) {
  console.error(
    "Expected exactly one release version in checksums, got: " + [...versions].join(", ")
  );
  process.exit(1);
}
const releaseVersion = [...versions][0];
const requiredArchives = [
  "linux_amd64.tar.gz",
  "linux_arm64.tar.gz",
  "darwin_amd64.tar.gz",
  "darwin_arm64.tar.gz",
  "windows_amd64.zip",
  "windows_arm64.zip",
].map((platform) => `nyx_${releaseVersion}_${platform}`);
const missing = requiredArchives.filter((name) => !pkg.binaryChecksums[name]);
if (missing.length > 0) {
  console.error("Missing checksums for required platform archives: " + missing.join(", "));
  process.exit(1);
}

fs.writeFileSync(packageFile, JSON.stringify(pkg, null, 2) + "\n");
console.log(`Embedded ${count} checksums into ${packageFile}`);
