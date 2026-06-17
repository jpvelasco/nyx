#!/usr/bin/env node
// nosemgrep: all — npm run shim, not application code
"use strict";

const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const binaryName = process.platform === "win32" ? "nyx.exe" : "nyx";
const binaryPath = path.join(__dirname, "bin", binaryName);

function runBinary() {
  const child = spawn(binaryPath, process.argv.slice(2), {
    stdio: "inherit",
  });

  // Forward signals so the Go binary shuts down cleanly
  ["SIGINT", "SIGTERM", "SIGHUP"].forEach((sig) => {
    process.on(sig, () => child.kill(sig));
  });

  child.on("error", (err) => {
    if (err.code === "ENOENT") {
      console.error(
        `nyx: binary not found at ${binaryPath}\n` +
          "Try running: node " +
          path.join(__dirname, "install.js")
      );
    } else {
      console.error(`nyx: failed to start: ${err.message}`);
    }
    process.exit(1);
  });

  child.on("exit", (code, signal) => {
    process.exit(signal ? 1 : code || 0);
  });
}

// If the binary is missing, postinstall was likely blocked by npm's allow-scripts
// security policy. Attempt a lazy download, but the package dir may be root-owned
// (e.g. sudo npm install -g). In that case, surface a clear recovery message.
if (!fs.existsSync(binaryPath)) {
  const installScript = path.join(__dirname, "install.js");

  // Check if we can write to the package dir before attempting the download.
  let canWrite = false;
  try {
    fs.accessSync(__dirname, fs.constants.W_OK);
    canWrite = true;
  } catch (_) {
    // directory is not writable by current user
  }

  if (!canWrite) {
    console.error(
      "nyx: binary not found and the package directory is not writable.\n" +
        "Run the installer with the same permissions used for npm install:\n" +
        "  sudo node " + installScript
    );
    process.exit(1);
  }

  console.error(
    "nyx: binary not found — postinstall was likely blocked by npm allow-scripts."
  );
  console.error("nyx: downloading binary now...");
  const result = spawnSync(process.execPath, [installScript], {
    stdio: "inherit",
  });
  if (result.error || result.status !== 0) {
    console.error(
      "nyx: download failed. Manual recovery:\n" +
        "  node " + installScript
    );
    process.exit(1);
  }
}

runBinary();
