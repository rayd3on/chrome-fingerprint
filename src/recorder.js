'use strict';

const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const readline = require('readline');

const { ROOT } = require('./paths');
const { sleep } = require('./args');
const { runCapture, commandExists } = require('./tshark');
const { hostMatches } = require('./tls');

function getAvailablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(error => error ? reject(error) : resolve(address.port));
    });
  });
}

async function terminateProcess(proc, graceMs = 500) {
  if (!proc || proc.exitCode !== null) return;

  // Windows has no POSIX signals -Node maps kill() to TerminateProcess, so
  // no graceful flush. Expect up to ~1s of trailing traffic to be lost.
  if (process.platform === 'win32') {
    try { proc.kill(); } catch {}
    await sleep(graceMs);
    if (proc.exitCode === null) try { proc.kill('SIGKILL'); } catch {}
  } else {
    try { proc.kill('SIGTERM'); } catch {}
    await sleep(graceMs);
    if (proc.exitCode === null) try { proc.kill('SIGKILL'); } catch {}
  }
}

async function ensureRecorderBinary() {
  if (!commandExists('go')) return null;

  const binary = path.join(os.tmpdir(), `chrome-fingerprint-header-recorder${os.platform() === 'win32' ? '.exe' : ''}`);
  const roots = [...new Set([ROOT, process.cwd()].map(dir => path.resolve(dir)))];

  for (const root of roots) {
    if (!fs.existsSync(path.join(root, 'go.mod'))) continue;
    if (!fs.existsSync(path.join(root, 'go', 'main.go'))) continue;

    const build = runCapture('go', ['build', '-o', binary, './go'], { cwd: root, timeout: 120000 });
    if (build.ok && fs.existsSync(binary)) return binary;
    console.error(`  Failed to build header recorder: ${(build.stderr || build.error?.message || 'go build failed').trim()}`);
    return null;
  }

  console.error('  Go header recorder sources were not found near the script.');
  return null;
}

// CA lives under the user's home directory so OS-level trust installs
// persist across runs and the repo never ships a private key. The Go
// recorder's loadOrCreateCA populates the files on first launch.
function getRecorderCAPaths() {
  const dir = process.env.CHROME_FINGERPRINT_CA_DIR
    || path.join(os.homedir(), '.chrome-fingerprint', 'ca');
  return {
    dir,
    certPath: path.join(dir, 'rootCA.pem'),
    keyPath: path.join(dir, 'rootCA-key.pem'),
  };
}

function ensureRecorderCADir() {
  const paths = getRecorderCAPaths();
  fs.mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  return paths;
}

function normalizeFingerprint(raw) {
  return String(raw || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
}

function getRecorderCertFingerprint(certPath) {
  try {
    const cert = new crypto.X509Certificate(fs.readFileSync(certPath));
    return normalizeFingerprint(cert.fingerprint);
  } catch {
    return '';
  }
}

function resolveMacHomeDirectory(username) {
  if (!username || username === 'root') return os.homedir();
  const lookup = runCapture('dscl', ['.', '-read', `/Users/${username}`, 'NFSHomeDirectory'], { timeout: 5000 });
  if (lookup.ok) {
    const match = lookup.stdout.match(/NFSHomeDirectory:\s*(.+)/);
    if (match?.[1]) return match[1].trim();
  }
  return path.join('/Users', username);
}

function macSecurityContext() {
  const currentUid = process.getuid?.();
  const sudoUser = process.env.SUDO_USER;
  const sudoUid = Number.parseInt(process.env.SUDO_UID || '', 10);
  const sudoGid = Number.parseInt(process.env.SUDO_GID || '', 10);

  if (currentUid === 0 && sudoUser && sudoUser !== 'root' && Number.isInteger(sudoUid) && sudoUid > 0) {
    return {
      user: sudoUser,
      home: resolveMacHomeDirectory(sudoUser),
      uid: sudoUid,
      gid: Number.isInteger(sudoGid) && sudoGid > 0 ? sudoGid : undefined,
    };
  }

  return {
    user: process.env.USER || process.env.LOGNAME || '',
    home: os.homedir(),
  };
}

function macSecurityRunOptions(context, timeout = 15000) {
  return {
    timeout,
    env: {
      ...process.env,
      HOME: context.home,
      USER: context.user || process.env.USER || process.env.LOGNAME || '',
      LOGNAME: context.user || process.env.LOGNAME || process.env.USER || '',
    },
  };
}

function macLoginKeychainPath(context) {
  return path.join(context.home, 'Library', 'Keychains', 'login.keychain-db');
}

function macTrustSettingsContainsFingerprint(fingerprint) {
  const context = macSecurityContext();
  const userTrust = runMacSecurity(['dump-trust-settings'], context);
  const adminTrust = runCapture('security', ['dump-trust-settings', '-d'], { timeout: 15000 });
  return normalizeFingerprint(`${userTrust.stdout}${adminTrust.stdout}`).includes(fingerprint);
}

function macKeychainContainsFingerprint(keychainPath, fingerprint, options) {
  // Keychain path is a positional argument for find-certificate, not -k flag.
  const lookup = runCapture('security', ['find-certificate', '-Z', '-a', keychainPath], options);
  return lookup.ok && normalizeFingerprint(lookup.stdout).includes(fingerprint);
}

function macUserKeychainContainsFingerprint(keychainPath, fingerprint, context, timeout = 15000) {
  // Keychain path is a positional argument for find-certificate, not -k flag.
  const lookup = runMacSecurity(['find-certificate', '-Z', '-a', keychainPath], context, timeout);
  return lookup.ok && normalizeFingerprint(lookup.stdout).includes(fingerprint);
}

function runMacSecurity(args, context, timeout = 15000) {
  const options = macSecurityRunOptions(context, timeout);
  if (process.getuid?.() === 0 && Number.isInteger(context.uid) && context.uid > 0) {
    return runCapture('launchctl', ['asuser', String(context.uid), 'security', ...args], options);
  }
  return runCapture('security', args, options);
}

function captureCommandDetail(result) {
  if (!result) return '';
  const pieces = [
    `status=${result.status}`,
    String(result.stderr || '').trim(),
    String(result.stdout || '').trim(),
    result.error?.message || '',
  ].filter(Boolean);
  return pieces.join(' | ');
}

function isRecorderCATrusted(certPath) {
  if (!fs.existsSync(certPath)) return false;
  const fingerprint = getRecorderCertFingerprint(certPath);
  if (!fingerprint) return false;

  if (os.platform() === 'win32') {
    const lookup = runCapture('certutil', ['-user', '-store', 'Root'], { timeout: 15000 });
    return lookup.ok && normalizeFingerprint(lookup.stdout).includes(fingerprint);
  }

  if (os.platform() === 'darwin') {
    const context = macSecurityContext();
    const inUserKeychain = macUserKeychainContainsFingerprint(
      macLoginKeychainPath(context),
      fingerprint,
      context
    );
    const inSystemKeychain = macKeychainContainsFingerprint(
      '/Library/Keychains/System.keychain',
      fingerprint,
      { timeout: 15000 }
    );
    // dump-trust-settings only shows cert names, not fingerprints, so we
    // rely solely on keychain membership — the cert is only ever added via
    // add-trusted-cert trustRoot so presence in a keychain implies trust.
    return inUserKeychain || inSystemKeychain;
  }

  return false;
}

function ensureRecorderCATrust(certPath) {
  if (!fs.existsSync(certPath)) {
    return { trusted: false, installed: false, message: 'Recorder CA certificate was not created.' };
  }
  if (isRecorderCATrusted(certPath)) {
    return { trusted: true, installed: false, message: 'Using existing trusted recorder CA.' };
  }

  if (os.platform() === 'win32') {
    const install = runCapture('certutil', ['-user', '-addstore', 'Root', certPath], { timeout: 30000 });
    if (install.ok && isRecorderCATrusted(certPath)) {
      return { trusted: true, installed: true, message: 'Trusted local recorder CA in the current user Root store.' };
    }
    return {
      trusted: false,
      installed: false,
      message: `Could not trust recorder CA automatically.${install.stderr ? ` ${install.stderr.trim()}` : ''}`.trim(),
    };
  }

  if (os.platform() === 'darwin') {
    const context = macSecurityContext();
    const keychain = macLoginKeychainPath(context);
    const fingerprint = getRecorderCertFingerprint(certPath);
    const installUserTrust = runMacSecurity(
      ['add-trusted-cert', '-r', 'trustRoot', '-p', 'ssl', '-k', keychain, certPath],
      context,
      45000
    );
    if (installUserTrust.ok && macUserKeychainContainsFingerprint(keychain, fingerprint, context)) {
      return { trusted: true, installed: true, message: 'Trusted local recorder CA in the user login keychain.' };
    }

    let installSystemTrust = null;
    if (process.getuid?.() === 0) {
      installSystemTrust = runCapture(
        'security',
        ['add-trusted-cert', '-d', '-r', 'trustRoot', '-p', 'ssl', '-k', '/Library/Keychains/System.keychain', certPath],
        { timeout: 45000 }
      );
      if (installSystemTrust.ok && macKeychainContainsFingerprint('/Library/Keychains/System.keychain', fingerprint, { timeout: 15000 })) {
        return { trusted: true, installed: true, message: 'Trusted local recorder CA in the system keychain.' };
      }
    }

    const detail = [captureCommandDetail(installUserTrust), captureCommandDetail(installSystemTrust)]
      .find(Boolean);
    return {
      trusted: false,
      installed: false,
      message: `Could not trust recorder CA automatically.${detail ? ` ${detail}` : ''}`.trim(),
    };
  }

  return {
    trusted: false,
    installed: false,
    message: `Automatic CA trust is not implemented for ${os.platform()}. Trust ${certPath} manually if you want a secure padlock.`,
  };
}

async function waitForProcessOutput(proc, matcher, timeoutMs) {
  return new Promise(resolve => {
    let settled = false;
    let collected = '';

    const finish = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    const onChunk = chunk => {
      collected += chunk.toString();
      if (matcher.test(collected)) finish(true);
    };

    const timer = setTimeout(() => finish(false), timeoutMs);
    proc.stdout?.on('data', onChunk);
    proc.stderr?.on('data', onChunk);
    proc.once('exit', () => finish(false));
  });
}

function sanitizeHeaderOrder(headerNames) {
  const skip = new Set(['host', 'connection', 'transfer-encoding', 'proxy-connection', 'pragma']);
  const seen = new Set();
  const headers = [];

  for (const rawName of headerNames || []) {
    const name = String(rawName || '').toLowerCase();
    if (!name || name.startsWith(':') || skip.has(name) || seen.has(name)) continue;
    seen.add(name);
    headers.push(name);
  }

  return headers;
}

function sanitizePseudoHeaderOrder(headerNames) {
  const seen = new Set();
  const headers = [];

  for (const rawName of headerNames || []) {
    const name = String(rawName || '').toLowerCase();
    if (!name || !name.startsWith(':') || seen.has(name)) continue;
    seen.add(name);
    headers.push(name);
  }

  return headers;
}

// For document requests Chrome emits different orderings depending on context
// (typed URL vs server redirect vs same-origin click vs refresh). Prefer the
// canonical "user-typed top-level navigation" pattern when present, since
// that is what most consumers want to replay. Falls back to first-with-order
// for non-document types where these heuristics don't apply.
function chooseRepresentativeRequest(requests) {
  if (!Array.isArray(requests) || !requests.length) return null;

  const withOrder = requests.filter(r => Array.isArray(r?.headerOrder) && r.headerOrder.length);
  if (!withOrder.length) return requests[0];

  const score = (req) => {
    const m = new Map((req.headers || []).map(h => [String(h.name || '').toLowerCase(), h.value || '']));
    let s = 0;
    if (m.get('sec-fetch-site') === 'none') s += 4;
    if (m.get('sec-fetch-user') === '?1') s += 2;
    if (!m.has('referer')) s += 1;
    if (!m.has('cookie')) s += 1;
    return s;
  };

  return withOrder.reduce((best, cur) => (score(cur) > score(best) ? cur : best), withOrder[0]);
}

function classifyRequestFromHeaderPairs(headerPairs, request = {}) {
  const headers = new Map((headerPairs || []).map(({ name, value }) => [name.toLowerCase(), value]));
  const method = String(request.method || headers.get(':method') || '').toUpperCase();
  const dest = headers.get('sec-fetch-dest') || '';
  const mode = headers.get('sec-fetch-mode') || '';
  const cache = headers.get('cache-control') || '';

  if (method === 'POST' && dest === 'empty' && mode === 'cors') return 'xhr-post';
  if (method === 'GET' && dest === 'empty' && mode === 'cors') return 'xhr-get';
  if (dest === 'script') return 'script';
  if (dest === 'iframe') return 'iframe';
  if (dest === 'style') return 'style';
  if (dest === 'font') return 'font';
  if (dest === 'image') return 'image';
  if (dest === 'document') return cache ? 'document-refresh' : 'document';
  if (method === 'GET' && !dest && !mode) return 'plain-get';
  return 'other';
}

// Two-label public suffixes so multi-label TLDs collapse to the right
// registrable domain. Not a full Public Suffix List; falls back to
// last-two-labels for anything not listed. Kept short on purpose to stay
// dependency-free.
const SECOND_LEVEL_SUFFIXES = new Set([
  'co.uk', 'co.jp', 'co.in', 'co.kr', 'co.za', 'co.nz', 'co.il', 'co.id', 'co.th',
  'com.au', 'com.br', 'com.mx', 'com.sg', 'com.ar', 'com.tr', 'com.cn', 'com.hk',
  'com.tw', 'com.my', 'com.pk', 'com.ph', 'com.vn',
  'org.uk', 'net.au', 'gov.uk', 'ac.uk', 'ne.jp', 'or.jp', 'ac.jp',
]);

function registrableDomain(host) {
  if (!host) return '';
  const parts = String(host).toLowerCase().split('.');
  if (parts.length < 2) return parts.join('.');
  const last2 = parts.slice(-2).join('.');
  if (parts.length >= 3 && SECOND_LEVEL_SUFFIXES.has(last2)) {
    return parts.slice(-3).join('.');
  }
  return last2;
}

function getHeaderValue(headers, name) {
  for (const header of headers || []) {
    if (String(header.name || '').toLowerCase() === name) return header.value || '';
  }
  return '';
}

function summarizeRecordedRequests(requests, targetUrl) {
  if (!Array.isArray(requests) || !requests.length) return null;

  const targetHost = new URL(targetUrl).hostname;

  // Cross-domain redirects would otherwise leave us with only the initial
  // document; pick up any host that received a top-level document fetch and
  // accept that registrable domain too, so subresources on the redirect
  // target are recorded. Iframes are deliberately excluded - they are
  // usually third-party embeds (analytics, ads, auth widgets) whose
  // subresources we don't want to fold into the target's header orders.
  const acceptedDomains = new Set([registrableDomain(targetHost)]);
  for (const request of requests) {
    const dest = getHeaderValue(request.headers, 'sec-fetch-dest');
    if (dest === 'document') {
      acceptedDomains.add(registrableDomain(request.host));
    }
  }

  const filtered = requests.filter(request =>
    hostMatches(request.host, targetHost) || acceptedDomains.has(registrableDomain(request.host))
  );
  if (!filtered.length) return null;

  const byType = {};
  let userAgent = '';
  let secCHUA = '';
  let secCHUAMobile = '';
  let secCHUAPlatform = '';
  let pseudoHeaderOrder = [];

  for (const request of filtered) {
    const type = classifyRequestFromHeaderPairs(request.headers || [], {
      method: request.method,
      path: request.path,
    });
    if (!byType[type]) byType[type] = [];
    byType[type].push({ ...request, requestType: type });

    for (const header of request.headers || []) {
      const name = String(header.name || '').toLowerCase();
      if (name === 'user-agent' && !userAgent) userAgent = header.value;
      if (name === 'sec-ch-ua' && !secCHUA) secCHUA = header.value;
      if (name === 'sec-ch-ua-mobile' && !secCHUAMobile) secCHUAMobile = header.value;
      if (name === 'sec-ch-ua-platform' && !secCHUAPlatform) secCHUAPlatform = header.value;
    }

    if (!pseudoHeaderOrder.length) {
      pseudoHeaderOrder = sanitizePseudoHeaderOrder(request.pseudoHeaderOrder);
    }
  }

  const headerOrders = {};
  for (const [type, items] of Object.entries(byType)) {
    if (type === 'other') continue;
    const selected = chooseRepresentativeRequest(items);
    if (!selected) continue;
    const orderSource = Array.isArray(selected.headerOrder) && selected.headerOrder.length
      ? selected.headerOrder
      : (selected.headers || []).map(header => header.name);
    const sanitized = sanitizeHeaderOrder(orderSource);
    if (sanitized.length) headerOrders[type] = sanitized;
  }

  return {
    userAgent,
    secCHUA,
    secCHUAMobile,
    secCHUAPlatform,
    pseudoHeaderOrder,
    headerOrders,
    rawRequests: filtered.length,
    requestTypes: Object.fromEntries(Object.entries(byType).map(([type, items]) => [type, items.length])),
  };
}

function parseRecorderOutput(file, targetUrl) {
  if (!fs.existsSync(file) || fs.statSync(file).size === 0) return null;

  const lines = fs.readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);

  return summarizeRecordedRequests(lines, targetUrl) || {
    userAgent: '',
    secCHUA: '',
    secCHUAMobile: '',
    secCHUAPlatform: '',
    pseudoHeaderOrder: [],
    headerOrders: {},
    rawRequests: 0,
    requestTypes: {},
  };
}

function mergeRecorderData(profile, recorderData) {
  if (!recorderData) return profile;

  const merged = {
    ...profile,
    captureSources: { ...(profile.captureSources || {}) },
  };

  merged.userAgent = recorderData.userAgent || merged.userAgent || '';
  merged.secCHUA = recorderData.secCHUA || merged.secCHUA || '';
  merged.secCHUAMobile = recorderData.secCHUAMobile || merged.secCHUAMobile || '';
  merged.secCHUAPlatform = recorderData.secCHUAPlatform || merged.secCHUAPlatform || '';

  // tshark owns HTTP/2 SETTINGS (decrypted from the ClientHello pcap); the
  // recorder only contributes pseudo-header order on proxied requests.
  if (recorderData.pseudoHeaderOrder?.length) {
    merged.http2 = { ...(merged.http2 || {}), pseudoHeaderOrder: recorderData.pseudoHeaderOrder };
  }

  if (recorderData.headerOrders && Object.keys(recorderData.headerOrders).length) {
    merged.headerOrders = recorderData.headerOrders;
    merged.captureSources.headerOrders = 'recorder';
  }

  return merged;
}

async function captureHeadersWithRecorder(chromePath, targetUrl, timeoutSeconds) {
  const recorderBinary = await ensureRecorderBinary();
  if (!recorderBinary) return null;

  const outputFile = path.join(os.tmpdir(), `chrome-header-recorder-${Date.now()}.jsonl`);
  const userData = path.join(os.tmpdir(), `chrome-header-recorder-${Date.now()}`);
  const port = await getAvailablePort();
  const listenAddr = `127.0.0.1:${port}`;
  const recorderCA = ensureRecorderCADir();
  const caExistedBeforeLaunch = fs.existsSync(recorderCA.certPath);
  if (!caExistedBeforeLaunch) {
    console.log(`  Generating recorder CA at ${recorderCA.dir}`);
  }

  console.log('\n--- Header Recorder ---\n');
  console.log(`  Recorder: ${recorderBinary}`);
  console.log(`  Proxy:    ${listenAddr}`);

  const recorder = spawn(recorderBinary, [
    '-listen', listenAddr,
    '-out', outputFile,
    '-ca-cert', recorderCA.certPath,
    '-ca-key', recorderCA.keyPath,
  ], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let recorderError = '';
  recorder.stderr.on('data', chunk => { recorderError += chunk.toString(); });

  const ready = await waitForProcessOutput(recorder, /listening on /i, 5000);
  if (!ready || recorder.exitCode !== null) {
    await terminateProcess(recorder);
    console.error(`  Header recorder failed to start.${recorderError ? ` ${recorderError.trim()}` : ''}`);
    return null;
  }

  const trust = ensureRecorderCATrust(recorderCA.certPath);
  console.log(`  ${trust.message}`);

  const chrome = spawn(chromePath, [
    `--user-data-dir=${userData}`,
    `--proxy-server=http://${listenAddr}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--no-session-id',
    '--no-restore-state',
    '--disable-session-crashed-bubble',
    '--disable-infobars',
    '--noerrdialogs',
    '--disable-background-networking',
    '--disable-sync',
    '--disable-translate',
    '--disable-quic',
    ...(!trust.trusted ? ['--ignore-certificate-errors'] : []),
    targetUrl,
  ], {
    stdio: 'ignore',
  });

  console.log(`  Waiting ${timeoutSeconds}s...`);
  await sleep(timeoutSeconds * 1000);

  console.log('  25s extra for manual navigation -browse around in Chrome now...');
  console.log('  Press ENTER to skip waiting early...');
  await new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const timer = setTimeout(() => { rl.close(); resolve(); }, 25000);
    rl.once('line', () => { clearTimeout(timer); rl.close(); resolve(); });
  });

  await terminateProcess(chrome);
  await terminateProcess(recorder, 1000);

  try { fs.rmSync(userData, { recursive: true, force: true }); } catch {}

  const summary = parseRecorderOutput(outputFile, targetUrl);
  try { fs.unlinkSync(outputFile); } catch {}

  return summary;
}

module.exports = {
  getAvailablePort,
  terminateProcess,
  ensureRecorderBinary,
  getRecorderCAPaths,
  ensureRecorderCADir,
  ensureRecorderCATrust,
  sanitizeHeaderOrder,
  sanitizePseudoHeaderOrder,
  classifyRequestFromHeaderPairs,
  registrableDomain,
  summarizeRecordedRequests,
  parseRecorderOutput,
  mergeRecorderData,
  captureHeadersWithRecorder,
};
