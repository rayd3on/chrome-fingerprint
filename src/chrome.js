'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { CHROME_DIR } = require('./paths');
const { runCapture, commandExists, findCommandOnPath } = require('./tshark');
const { ask } = require('./args');

function findSystemChrome() {
  const platform = os.platform();
  const candidates = platform === 'win32'
    ? [
        path.join(process.env.PROGRAMFILES || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
        path.join(process.env['PROGRAMFILES(X86)'] || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
        path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
      ]
    : [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium-browser',
        '/usr/bin/chromium',
      ];

  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }

  return platform === 'win32'
    ? findCommandOnPath(['chrome.exe'])
    : findCommandOnPath(['google-chrome', 'google-chrome-stable', 'chromium-browser', 'chromium']);
}

function getInstalledChromeVersion(binary) {
  function readCachedVersion(binaryPath) {
    let dir = binaryPath ? path.dirname(binaryPath) : '';
    const root = path.resolve(CHROME_DIR);
    while (dir && path.resolve(dir).startsWith(root)) {
      const versionFile = path.join(dir, 'version.txt');
      if (fs.existsSync(versionFile)) {
        const match = fs.readFileSync(versionFile, 'utf8').match(/(\d+\.\d+\.\d+\.\d+)/);
        if (match) return match[1];
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return null;
  }

  const cachedVersion = readCachedVersion(binary);
  if (cachedVersion) return cachedVersion;

  // chrome.exe --version exits silently on Windows; read the file's VersionInfo
  // via PowerShell, then fall back to the installer's sibling VERSION directory
  // (chrome.dll lives there).
  if (os.platform() === 'win32' && binary && fs.existsSync(binary)) {
    const escaped = binary.replace(/'/g, "''");
    const versionInfo = runCapture('powershell', [
      '-NoProfile',
      '-Command',
      `(Get-Item -LiteralPath '${escaped}').VersionInfo.FileVersion`,
    ], { timeout: 10000 });
    const psMatch = `${versionInfo.stdout}\n${versionInfo.stderr}`.match(/(\d+\.\d+\.\d+\.\d+)/);
    if (psMatch) return psMatch[1];

    try {
      const appDir = path.dirname(binary);
      for (const entry of fs.readdirSync(appDir)) {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(entry)) {
          const dllPath = path.join(appDir, entry, 'chrome.dll');
          if (fs.existsSync(dllPath)) return entry;
        }
      }
    } catch {}

    return null;
  }

  const result = runCapture(binary, ['--version'], { timeout: 5000 });
  const combined = `${result.stdout}\n${result.stderr}`;
  const match = combined.match(/(\d+\.\d+\.\d+\.\d+)/);
  if (match) return match[1];

  return null;
}

function cftPlatform() {
  const platform = os.platform();
  const arch = os.arch();
  if (platform === 'darwin') return arch === 'arm64' ? 'mac-arm64' : 'mac-x64';
  if (platform === 'linux') return 'linux64';
  if (platform === 'win32') return arch === 'x64' || arch === 'arm64' ? 'win64' : 'win32';
  return null;
}

function resolveChromeBinary(dir, platform) {
  if (!fs.existsSync(dir)) return null;
  try {
    const entries = fs.readdirSync(dir);

    if (platform.startsWith('mac')) {
      // Omaha DMGs get ditto'd so the .app sits directly under versionDir;
      // CfT / ulixee archives put it one level deeper under chrome-*.
      const directApp = path.join(dir, 'Google Chrome.app', 'Contents', 'MacOS', 'Google Chrome');
      if (fs.existsSync(directApp)) return directApp;
      for (const entry of entries) {
        const realApp = path.join(dir, entry, 'Google Chrome.app', 'Contents', 'MacOS', 'Google Chrome');
        if (fs.existsSync(realApp)) return realApp;
      }
      const appDir = entries.find(d => d.startsWith('chrome-'));
      if (appDir) {
        const cftApp = path.join(dir, appDir, 'Google Chrome for Testing.app', 'Contents', 'MacOS', 'Google Chrome for Testing');
        if (fs.existsSync(cftApp)) return cftApp;
      }
      for (const entry of entries) {
        const bare = path.join(dir, entry, 'chrome');
        if (fs.existsSync(bare)) return bare;
      }
      return null;
    }

    if (platform === 'linux64') {
      const optPath = path.join(dir, 'opt', 'google', 'chrome', 'chrome');
      if (fs.existsSync(optPath)) return optPath;
      const subdir = entries.find(d => d.startsWith('chrome-'));
      if (subdir) { const p = path.join(dir, subdir, 'chrome'); if (fs.existsSync(p)) return p; }
      for (const entry of entries) { const p = path.join(dir, entry, 'chrome'); if (fs.existsSync(p)) return p; }
      return null;
    }

    const chromeBin = path.join(dir, 'Chrome-bin');
    if (fs.existsSync(chromeBin)) {
      const topExe = path.join(chromeBin, 'chrome.exe');
      if (fs.existsSync(topExe)) return topExe;
    }
    const subdir = entries.find(d => d.startsWith('chrome-'));
    if (subdir) { const p = path.join(dir, subdir, 'chrome.exe'); if (fs.existsSync(p)) return p; }
    const bare = path.join(dir, 'chrome.exe');
    if (fs.existsSync(bare)) return bare;
    return null;
  } catch { return null; }
}

function extractZip(zipPath, destination) {
  if (os.platform() === 'win32') {
    const result = runCapture('powershell', [
      '-NoProfile',
      '-Command',
      `Expand-Archive -Force -Path '${zipPath.replace(/'/g, "''")}' -DestinationPath '${destination.replace(/'/g, "''")}'`,
    ], { timeout: 120000 });

    if (!result.ok) {
      throw new Error(result.stderr.trim() || 'PowerShell Expand-Archive failed');
    }
    return;
  }

  if (commandExists('unzip')) {
    const result = runCapture('unzip', ['-o', '-q', zipPath, '-d', destination], { timeout: 60000 });
    if (!result.ok) {
      throw new Error(result.stderr.trim() || 'unzip failed');
    }
    return;
  }

  const python = commandExists('python3') ? 'python3' : commandExists('python') ? 'python' : null;
  if (python) {
    const result = runCapture(python, ['-m', 'zipfile', '-e', zipPath, destination], { timeout: 120000 });
    if (!result.ok) {
      throw new Error(result.stderr.trim() || `${python} zip extraction failed`);
    }
    return;
  }

  throw new Error('No ZIP extractor found. Install unzip (apt/dnf/apk install unzip) or Python 3.');
}

async function downloadFile(url, destPath, label) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const totalBytes = parseInt(res.headers.get('content-length') || '0', 10) || 0;
  const tag = label || path.basename(destPath);

  const fileStream = fs.createWriteStream(destPath);
  let received = 0;
  let lastPct = -1;

  const reader = res.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      fileStream.write(Buffer.from(value));
      received += value.length;

      if (process.stdout.isTTY) {
        const recvMB = (received / 1024 / 1024).toFixed(1);
        if (totalBytes > 0) {
          const pct = Math.min(100, Math.floor((received / totalBytes) * 100));
          if (pct !== lastPct) {
            lastPct = pct;
            const filled = Math.floor(pct / 2.5);
            const bar = '\u2588'.repeat(filled) + '\u2591'.repeat(40 - filled);
            const totalMB = (totalBytes / 1024 / 1024).toFixed(0);
            process.stdout.write(`\r  ${tag}: ${bar} ${pct}% (${recvMB}/${totalMB}MB)`);
          }
        } else {
          process.stdout.write(`\r  ${tag}: ${recvMB}MB downloaded...`);
        }
      }
    }
  } finally {
    fileStream.end();
    await new Promise(resolve => fileStream.on('finish', resolve));
  }
  if (process.stdout.isTTY) process.stdout.write('\n');
  console.log(`  Downloaded ${(received / 1024 / 1024).toFixed(1)}MB`);
  return received;
}

function find7Zip() {
  if (commandExists('7z')) return '7z';
  const locations = [
    'C:\\Program Files\\7-Zip\\7z.exe',
    'C:\\Program Files (x86)\\7-Zip\\7z.exe',
    path.join(process.env.LOCALAPPDATA || '', '7-Zip', '7z.exe'),
  ];
  for (const loc of locations) {
    if (loc && fs.existsSync(loc)) return loc;
  }
  return null;
}

async function ensure7Zip() {
  const existing = find7Zip();
  if (existing) return existing;

  console.log('  7-Zip is required to extract the Chrome installer on Windows and was not found.');
  const answer = (await ask('  Install via winget now? [y/N]: ')).toLowerCase();
  if (answer !== 'y' && answer !== 'yes') {
    console.log('  Skipping Omaha download; falling back to ulixee/Chrome for Testing.');
    return null;
  }

  const winget = runCapture('winget', ['install', '7zip.7zip', '--accept-source-agreements', '--accept-package-agreements'], { timeout: 180000 });
  if (winget.ok) {
    const installed = find7Zip();
    if (installed) {
      console.log('  7-Zip installed.');
      return installed;
    }
  }
  console.log('  winget install did not produce a usable 7-Zip. Install it manually from https://www.7-zip.org and retry.');
  return null;
}

// Google Omaha serves branded Chrome. Chrome for Testing (Chromium) has
// different sec-ch-ua branding and header ordering, so prefer Omaha/ulixee.
async function downloadViaOmaha(version, platform, versionDir) {
  const isWin = platform.startsWith('win');
  const isMac = platform.startsWith('mac');
  if (!isWin && !isMac) return null;

  const osPlatform = isWin ? 'win' : 'mac';
  const osVersion = isWin ? '10.0' : '15.0';
  const osArch = platform === 'win32' ? 'x86' : (platform === 'mac-arm64' ? 'arm64' : 'x64');
  const appId = isWin ? '{8A69D345-D564-463C-AFF1-A69D9E530F96}' : 'com.google.Chrome';

  const body = `<?xml version="1.0" encoding="UTF-8"?>`
    + `<request protocol="3.0" version="1.3.23.0" ismachine="${isWin ? '1' : '0'}">`
    + `<os platform="${osPlatform}" version="${osVersion}" arch="${osArch}"/>`
    + `<app appid="${appId}" version="0.0.0.0" lang="en">`
    + `<updatecheck targetversionprefix="${version}."/>`
    + `</app></request>`;

  try {
    const res = await fetch('https://tools.google.com/service/update2', {
      method: 'POST', headers: { 'Content-Type': 'application/xml' }, body,
    });
    const xml = await res.text();
    if (xml.includes('status="noupdate"')) return null;

    const versionMatch = xml.match(/manifest version="([^"]+)"/);
    const urlMatch = xml.match(/codebase="(https:\/\/dl\.google\.com\/release2\/chrome\/[^"]+)"/);
    const pkgMatch = xml.match(/<package[^>]*name="([^"]+)"[^>]*size="(\d+)"/);
    if (!versionMatch || !urlMatch || !pkgMatch) return null;

    const fullVersion = versionMatch[1];
    const downloadUrl = urlMatch[1] + pkgMatch[1];
    const sizeMB = (parseInt(pkgMatch[2]) / 1024 / 1024).toFixed(0);
    console.log(`  Found Google Chrome ${fullVersion} via Omaha (${sizeMB}MB)`);

    const tmpFile = path.join(os.tmpdir(), `chrome-omaha-${fullVersion}${isWin ? '.exe' : '.dmg'}`);
    await downloadFile(downloadUrl, tmpFile, `Chrome ${fullVersion}`);

    fs.mkdirSync(versionDir, { recursive: true });

    if (isWin) {
      const sevenZip = await ensure7Zip();
      if (!sevenZip) {
        console.log(`  7-Zip not available`);
        try { fs.unlinkSync(tmpFile); } catch {}
        return null;
      }

      console.log(`  Extracting installer...`);
      runCapture(sevenZip, ['x', tmpFile, `-o${versionDir}`, '-y'], { timeout: 120000 });
      try { fs.unlinkSync(tmpFile); } catch {}
      const chrome7z = path.join(versionDir, 'chrome.7z');
      if (fs.existsSync(chrome7z)) {
        console.log(`  Extracting chrome.7z...`);
        runCapture(sevenZip, ['x', chrome7z, `-o${versionDir}`, '-y'], { timeout: 120000 });
        try { fs.unlinkSync(chrome7z); } catch {}
      }
    } else if (isMac) {
      console.log(`  Mounting DMG...`);
      const mountPoint = path.join(os.tmpdir(), `chrome-dmg-${process.pid}-${Date.now()}`);
      const attach = runCapture('hdiutil', ['attach', tmpFile, '-nobrowse', '-readonly', '-mountpoint', mountPoint], { timeout: 30000 });
      if (!attach.ok) {
        console.log(`  hdiutil attach failed: ${(attach.stderr || attach.error?.message || 'unknown error').trim()}`);
        try { fs.unlinkSync(tmpFile); } catch {}
        return null;
      }
      try {
        const appSrc = path.join(mountPoint, 'Google Chrome.app');
        if (!fs.existsSync(appSrc)) {
          let contents;
          try { contents = fs.readdirSync(mountPoint).join(', '); }
          catch { contents = '<unreadable>'; }
          console.log(`  Google Chrome.app not found at the DMG root. Contents: ${contents}`);
        } else {
          // ditto preserves macOS bundle metadata (resource forks, ACLs,
          // code-signing extended attributes) better than cp -R, which has
          // quietly produced broken .app bundles here in the past.
          const copy = runCapture('ditto', [appSrc, path.join(versionDir, 'Google Chrome.app')], { timeout: 120000 });
          if (!copy.ok) {
            console.log(`  ditto copy failed: ${(copy.stderr || copy.error?.message || 'unknown error').trim()}`);
          }
        }
      } finally {
        runCapture('hdiutil', ['detach', mountPoint, '-force'], { timeout: 15000 });
        try { fs.unlinkSync(tmpFile); } catch {}
      }
    }

    try { fs.writeFileSync(path.join(versionDir, 'version.txt'), `${fullVersion}\n`); } catch {}
    try { fs.writeFileSync(path.join(versionDir, 'source.txt'), 'google-omaha\n'); } catch {}

    const binary = resolveChromeBinary(versionDir, platform);
    if (binary && fs.existsSync(binary)) {
      if (os.platform() !== 'win32') {
        try { fs.chmodSync(binary, 0o755); } catch {}
      }
      console.log(`  Google Chrome ${fullVersion} ready`);
      return binary;
    }
    console.log(`  Omaha extracted but no chrome binary was found under ${versionDir}.`);
    return null;
  } catch (e) {
    const detail = e.cause ? ` (cause: ${e.cause.code || e.cause.message || e.cause})` : '';
    console.log(`  Omaha download failed: ${e.message}${detail}`);
    return null;
  }
}

async function downloadViaUlixee(version, platform, versionDir) {
  const ulixeePlatform = {
    'win32': 'win32', 'win64': 'win64',
    'mac-x64': 'mac', 'mac-arm64': 'mac_arm64',
    'linux64': 'linux',
  }[platform];
  if (!ulixeePlatform) return null;

  try {
    console.log(`  Searching ulixee/chrome-versions for v${version}...`);
    const res = await fetch(`https://api.github.com/repos/ulixee/chrome-versions/releases?per_page=100`);
    if (!res.ok) throw new Error(`GitHub API ${res.status}`);
    const releases = await res.json();

    for (const rel of releases) {
      if (!rel.tag_name.startsWith(version + '.')) continue;
      const asset = rel.assets.find(a => a.name.includes(`_${ulixeePlatform}.tar.gz`));
      if (!asset) continue;

      const fullVersion = rel.tag_name;
      console.log(`  Found Google Chrome ${fullVersion} on ulixee (${(asset.size / 1024 / 1024).toFixed(0)}MB)`);

      const tmpFile = path.join(os.tmpdir(), asset.name);
      await downloadFile(asset.browser_download_url, tmpFile, `Chrome ${fullVersion}`);
      fs.mkdirSync(versionDir, { recursive: true });
      console.log(`  Extracting...`);

      const tar = runCapture('tar', ['xzf', tmpFile, '-C', versionDir], { timeout: 120000 });
      try { fs.unlinkSync(tmpFile); } catch {}
      if (!tar.ok) {
        console.log(`  tar extraction failed: ${(tar.stderr || tar.error?.message || 'unknown error').trim()}`);
        continue;
      }

      try { fs.writeFileSync(path.join(versionDir, 'version.txt'), `${fullVersion}\n`); } catch {}
      try { fs.writeFileSync(path.join(versionDir, 'source.txt'), 'ulixee\n'); } catch {}

      const binary = resolveChromeBinary(versionDir, platform);
      if (binary && fs.existsSync(binary)) {
        if (os.platform() !== 'win32') {
          try { fs.chmodSync(binary, 0o755); } catch {}
        }
        console.log(`  Google Chrome ${fullVersion} ready`);
        return binary;
      }
      console.log(`  Extracted archive but could not locate a chrome binary under ${versionDir}.`);
    }
  } catch (e) {
    console.log(`  ulixee lookup failed: ${e.message}`);
  }
  return null;
}

async function downloadViaCft(version, platform, versionDir) {
  console.log('');
  console.log('  Falling back to Chrome for Testing (Chromium).');
  console.log('  sec-ch-ua branding and header ordering WILL differ from real Chrome.');
  console.log('');

  let downloadUrl = null, fullVersion = null;
  try {
    const response = await fetch('https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const candidates = data.versions.filter(e =>
      e.version.startsWith(`${version}.`) && e.downloads?.chrome?.some(d => d.platform === platform));
    if (candidates.length) {
      const latest = candidates[candidates.length - 1];
      downloadUrl = latest.downloads.chrome.find(d => d.platform === platform)?.url;
      fullVersion = latest.version;
    }
  } catch {}

  if (!downloadUrl) return null;
  const zipPath = path.join(os.tmpdir(), `chrome-cft-${version}.zip`);
  try {
    await downloadFile(downloadUrl, zipPath, `Chromium ${fullVersion}`);
    fs.mkdirSync(versionDir, { recursive: true });
    extractZip(zipPath, versionDir);
  } catch (e) { console.log(`  Download failed: ${e.message}`); return null; }
  finally { try { fs.unlinkSync(zipPath); } catch {} }

  try { fs.writeFileSync(path.join(versionDir, 'version.txt'), `${fullVersion}\n`); } catch {}
  try { fs.writeFileSync(path.join(versionDir, 'source.txt'), 'chrome-for-testing\n'); } catch {}

  const binary = resolveChromeBinary(versionDir, platform);
  if (binary && os.platform() !== 'win32') {
    try { fs.chmodSync(binary, 0o755); } catch {}
  }
  return binary;
}

async function downloadChrome(version, platform) {
  const cacheDir = path.join(CHROME_DIR, `chrome-${version}`);
  const cachedBinary = resolveChromeBinary(cacheDir, platform);
  if (cachedBinary) {
    let source;
    try { source = fs.readFileSync(path.join(cacheDir, 'source.txt'), 'utf8').trim(); }
    catch { source = 'cached'; }
    console.log(`  Using cached Chrome ${version} (${source})`);
    return cachedBinary;
  }

  let binary = await downloadViaOmaha(version, platform, cacheDir);
  if (binary) return binary;

  binary = await downloadViaUlixee(version, platform, cacheDir);
  if (binary) return binary;

  binary = await downloadViaCft(version, platform, cacheDir);
  return binary;
}

async function ensureChrome(customPath, version) {
  if (customPath) {
    if (fs.existsSync(customPath)) return customPath;
    console.error(`Chrome not found at ${customPath}`);
    process.exit(1);
  }

  const systemChrome = findSystemChrome();
  if (systemChrome) {
    const systemVersion = getInstalledChromeVersion(systemChrome);
    if (systemVersion && systemVersion.startsWith(`${version}.`)) {
      console.log(`  Using system Google Chrome ${systemVersion}`);
      return systemChrome;
    }
    if (systemVersion) console.log(`  System Chrome is ${systemVersion}, target is ${version}`);
  }

  const platform = cftPlatform();
  if (!platform) {
    if (systemChrome) return systemChrome;
    console.error('Unsupported platform and no system Chrome was found.');
    process.exit(1);
  }

  const downloaded = await downloadChrome(version, platform);
  if (downloaded) return downloaded;

  if (systemChrome) {
    console.log('  Falling back to the system Chrome binary.');
    return systemChrome;
  }

  console.error('No Chrome binary is available.');
  process.exit(1);
}

module.exports = {
  findSystemChrome,
  getInstalledChromeVersion,
  cftPlatform,
  resolveChromeBinary,
  extractZip,
  downloadFile,
  downloadChrome,
  ensureChrome,
};
