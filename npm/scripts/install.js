const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

const { version: VERSION } = require('../package.json');
const REPO = 'jpvelasco/nyx';
const MAX_REDIRECTS = 5;
const DOWNLOAD_TIMEOUT_MS = 30000;
const RELEASE_HOSTS = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'github-releases.githubusercontent.com',
]);

function getPlatformInfo() {
  const platform = os.platform();
  const arch = os.arch();

  const platformMap = { linux: 'linux', darwin: 'darwin', win32: 'windows' };
  const archMap = { x64: 'amd64', arm64: 'arm64' };
  const mappedPlatform = platformMap[platform];
  const mappedArch = archMap[arch];

  if (!mappedPlatform || !mappedArch) {
    throw new Error("Unsupported platform: "+platform+"-"+arch);
  }

  return {
    platform: mappedPlatform,
    arch: mappedArch,
    ext: platform === 'win32' ? '.exe' : '',
  };
}

function releaseURL(assetName) {
  return new URL("https://github.com/"+REPO+"/releases/download/v"+VERSION+"/"+assetName);
}

function validateDownloadURL(url) {
  if (url.protocol !== 'https:') {
    throw new Error("Refusing non-HTTPS download URL: "+url.href);
  }

  if (!RELEASE_HOSTS.has(url.hostname) && !url.hostname.endsWith('.githubusercontent.com')) {
    throw new Error("Refusing unexpected download host: "+url.hostname);
  }
}

function request(url, redirects) {
  validateDownloadURL(url);

  return new Promise((resolve, reject) => {
    const req = https.get(url, { // nosemgrep: codacy.tools-configs.rules_lgpl_javascript_ssrf_rule-node-ssrf
      headers: {
        'User-Agent': 'nyx-npm-installer/'+VERSION,
      },
    }, (res) => {
      const statusCode = res.statusCode || 0;

      if ([301, 302, 303, 307, 308].includes(statusCode)) {
        res.resume();
        if (!res.headers.location) {
          reject(new Error("Redirect response did not include a Location header"));
          return;
        }
        if (redirects >= MAX_REDIRECTS) {
          reject(new Error("Too many redirects while downloading "+url.href));
          return;
        }

        const nextURL = new URL(res.headers.location, url);
        request(nextURL, redirects + 1).then(resolve, reject);
        return;
      }

      if (statusCode < 200 || statusCode > 299) {
        res.resume();
        reject(new Error("Download failed with HTTP "+statusCode+" for "+url.href));
        return;
      }

      resolve(res);
    });

    req.setTimeout(DOWNLOAD_TIMEOUT_MS, () => {
      req.destroy(new Error("Timed out downloading "+url.href));
    });
    req.on('error', reject);
  });
}

async function downloadText(url) {
  const res = await request(url, 0);

  return new Promise((resolve, reject) => {
    const chunks = [];
    res.setEncoding('utf8');
    res.on('data', (chunk) => chunks.push(chunk));
    res.on('end', () => resolve(chunks.join('')));
    res.on('error', reject);
  });
}

async function downloadFile(url, destPath) {
  const tempPath = destPath+".tmp-"+process.pid;
  const res = await request(url, 0);

  try {
    await new Promise((resolve, reject) => {
      const file = fs.createWriteStream(tempPath); // nosemgrep: codacy.tools-configs.javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename
      res.pipe(file);
      res.on('error', reject);
      file.on('error', reject);
      file.on('finish', () => {
        file.close((err) => {
          if (err) {
            reject(err);
            return;
          }
          resolve();
        });
      });
    });

    if (os.platform() !== 'win32') {
      await fs.promises.chmod(tempPath, 0o755);  // nosemgrep: generic.file-permissions
    }
    await fs.promises.rename(tempPath, destPath); // nosemgrep: javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename
  } catch (err) {
    await fs.promises.unlink(tempPath).catch(() => {}); // nosemgrep: javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename
    throw err;
  }
}

function expectedChecksum(checksums, binaryName) {
  const line = checksums.split(/\r?\n/).find((entry) => entry.endsWith("  "+binaryName) || entry.endsWith(" *"+binaryName));
  if (!line) {
    throw new Error("checksums.txt does not include "+binaryName);
  }

  const checksum = line.split(/\s+/)[0];
  if (!/^[a-f0-9]{64}$/i.test(checksum)) {
    throw new Error("Invalid checksum entry for "+binaryName);
  }
  return checksum.toLowerCase();
}

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath); // nosemgrep: codacy.tools-configs.javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename

    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

async function verifyChecksum(binaryName, destPath) {
  const checksums = await downloadText(releaseURL('checksums.txt'));
  const expected = expectedChecksum(checksums, binaryName);
  const actual = await sha256File(destPath);

  if (actual !== expected) {
    throw new Error("Checksum mismatch for "+binaryName);
  }
}

async function main() {
  const info = getPlatformInfo();
  const binaryName = "nyx-"+info.platform+"-"+info.arch+info.ext;
  const destDir = path.join(__dirname, '..', 'bin');  // nosemgrep: generic.dynamic-path-construction
  const destPath = path.join(destDir, binaryName);  // nosemgrep: generic.dynamic-path-construction
  // nosemgrep: javascript.lang.security.audit.detect-non-literal-fs-filename.detect-non-literal-fs-filename

  try {
    await fs.promises.access(destPath);
    await verifyChecksum(binaryName, destPath);
    console.log("Binary already exists: "+destPath);
    return;
  } catch (err) {
    await fs.promises.unlink(destPath).catch(() => {});
    await fs.promises.mkdir(destDir, { recursive: true });
  }

  console.log("Downloading "+binaryName+" from "+releaseURL(binaryName).href+"...");
  await downloadFile(releaseURL(binaryName), destPath);
  try {
    await verifyChecksum(binaryName, destPath);
  } catch (err) {
    await fs.promises.unlink(destPath).catch(() => {});
    throw err;
  }
  console.log("Installed "+binaryName);
}

main().catch((err) => {
  console.error('Download failed:', err.message);
  console.error('Install from source instead: go install github.com/jpvelasco/nyx/cmd/nyx@v'+VERSION);
  process.exit(1);
});
