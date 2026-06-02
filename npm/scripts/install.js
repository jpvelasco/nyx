const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

const VERSION = '0.1.0';
const REPO = 'jpvelasco/nyx';

function getPlatformInfo() {
  const platform = os.platform();
  const arch = os.arch();

  const platformMap = { linux: 'linux', darwin: 'darwin', win32: 'windows' };
  const archMap = { x64: 'amd64', arm64: 'arm64' };

  return {
    platform: platformMap[platform] || platform,
    arch: archMap[arch] || arch,
    ext: platform === 'win32' ? '.exe' : '',
  };
}

async function download() {
  const info = getPlatformInfo();
  const binaryName = "nyx-"+info.platform+"-"+info.arch+info.ext;
  const url = "https://github.com/"+REPO+"/releases/download/v"+VERSION+"/"+binaryName;
  const destDir = path.join(__dirname, '..', 'bin');
  const destPath = path.join(destDir, binaryName);

  if (fs.existsSync(destPath)) {
    console.log("Binary already exists: "+destPath);
    return;
  }

  fs.mkdirSync(destDir, { recursive: true });

  console.log("Downloading "+binaryName+" from "+url+"...");
  console.log('NOTE: Prebuilt binaries are not yet available for v0.1.0.');
  console.log('Build from source: go build -o nyx ./cmd/nyx/');
  console.log('');

  // In production, this would download the binary.
  // For v0.1.0, we just print instructions.
}

download().catch((err) => {
  console.error('Download failed:', err.message);
  console.error('Build from source instead: go build -o nyx ./cmd/nyx/');
  process.exit(0); // Don't fail npm install
});
