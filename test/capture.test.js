const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  classifyRequestFromHeaderPairs,
  mergeRecorderData,
  normalizeChromeVersion,
  normalizeNumericToken,
  normalizeTargetUrl,
  parseArgs,
  parseRecorderOutput,
  selectInterfaceFromList,
  summarizeRecordedRequests,
  summarizeTlsKeylogFile,
} = require('../capture');

test('parseArgs reads supported flags', () => {
  const opts = parseArgs([
    '--version', '147',
    '--url', 'example.com',
    '--interface', 'en0',
    '--header-source', 'recorder',
    '--skip-headers',
    '--timeout', '20',
  ]);

  assert.equal(opts.version, '147');
  assert.equal(opts.url, 'example.com');
  assert.equal(opts.iface, 'en0');
  assert.equal(opts.headerSource, 'recorder');
  assert.equal(opts.skipHeaders, true);
  assert.equal(opts.timeout, 20);
});

test('parseArgs rejects unknown flags and missing values', () => {
  assert.throws(() => parseArgs(['--version']), /requires a value/);
  assert.throws(() => parseArgs(['--wat']), /Unknown option/);
  assert.throws(() => parseArgs(['--header-source', 'tshark']), /auto, recorder/);
});

test('normalizeChromeVersion accepts major and full versions', () => {
  assert.equal(normalizeChromeVersion('147'), '147');
  assert.equal(normalizeChromeVersion('147.0.7727.56'), '147');
  assert.throws(() => normalizeChromeVersion('stable'), /Chrome version/);
});

test('normalizeTargetUrl adds https by default', () => {
  assert.equal(normalizeTargetUrl('example.com'), 'https://example.com/');
  assert.equal(normalizeTargetUrl('http://example.com'), 'http://example.com/');
  assert.throws(() => normalizeTargetUrl('ftp://example.com'), /Only http/);
});

test('selectInterfaceFromList chooses sensible defaults per platform', () => {
  const linuxList = [
    '1. eth0',
    '2. any',
    '3. lo',
  ].join('\n');
  assert.equal(selectInterfaceFromList(linuxList, 'linux'), 'any');

  const windowsList = [
    '1. \\Device\\NPF_{AAAA} (Loopback)',
    '2. \\Device\\NPF_{BBBB} (Wi-Fi)',
  ].join('\n');
  assert.equal(selectInterfaceFromList(windowsList, 'win32'), '2');
});

test('normalizeNumericToken handles decimal, hex, and ambiguous tshark values', () => {
  const map = {
    29: 'x25519',
    0x1301: 'TLS_AES_128_GCM_SHA256',
  };

  assert.equal(normalizeNumericToken('29', map), 29);
  assert.equal(normalizeNumericToken('0x1301', map), 0x1301);
  assert.equal(normalizeNumericToken('1301', map), 0x1301);
});

test('summarizeTlsKeylogFile distinguishes handshake and application secrets', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome-fingerprint-test-'));
  const keylogPath = path.join(tempDir, 'keys.log');
  fs.writeFileSync(keylogPath, [
    'CLIENT_HANDSHAKE_TRAFFIC_SECRET abc def',
    'SERVER_HANDSHAKE_TRAFFIC_SECRET abc def',
    'CLIENT_TRAFFIC_SECRET_0 abc def',
    'SERVER_TRAFFIC_SECRET_0 abc def',
    'EXPORTER_SECRET abc def',
  ].join('\n'));

  const summary = summarizeTlsKeylogFile(keylogPath);
  assert.deepEqual(summary.labels, [
    'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
    'CLIENT_TRAFFIC_SECRET_0',
    'EXPORTER_SECRET',
    'SERVER_HANDSHAKE_TRAFFIC_SECRET',
    'SERVER_TRAFFIC_SECRET_0',
  ]);
  assert.equal(summary.hasTls13HandshakeSecrets, true);
  assert.equal(summary.hasTls13ApplicationSecrets, true);
  assert.equal(summary.counts.CLIENT_HANDSHAKE_TRAFFIC_SECRET, 1);
  assert.equal(summary.counts.SERVER_TRAFFIC_SECRET_0, 1);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('summarizeRecordedRequests keeps target-host requests and preserves first header order', () => {
  const requests = [
    {
      url: 'https://static.example.com/app.js',
      method: 'GET',
      path: '/app.js',
      host: 'static.example.com',
      pseudoHeaderOrder: [':method', ':authority', ':scheme', ':path'],
      headerOrder: [
        'sec-ch-ua-platform',
        'user-agent',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'accept',
        'sec-fetch-site',
        'sec-fetch-mode',
        'sec-fetch-dest',
        'referer',
        'accept-encoding',
        'accept-language',
      ],
      headers: [
        { name: 'sec-ch-ua-platform', value: '"macOS"' },
        { name: 'user-agent', value: 'UA' },
        { name: 'sec-ch-ua', value: '"Chromium";v="147"' },
        { name: 'sec-ch-ua-mobile', value: '?0' },
        { name: 'accept', value: '*/*' },
        { name: 'sec-fetch-site', value: 'same-origin' },
        { name: 'sec-fetch-mode', value: 'no-cors' },
        { name: 'sec-fetch-dest', value: 'script' },
        { name: 'referer', value: 'https://example.com/' },
        { name: 'accept-encoding', value: 'gzip, deflate, br' },
        { name: 'accept-language', value: 'en-US,en;q=0.9' },
      ],
    },
    {
      url: 'https://tracker.invalid/pixel',
      method: 'GET',
      path: '/pixel',
      host: 'tracker.invalid',
      headerOrder: ['accept'],
      headers: [{ name: 'accept', value: '*/*' }],
    },
  ];

  const summary = summarizeRecordedRequests(requests, 'https://example.com/');
  assert.deepEqual(summary.headerOrders.script, [
    'sec-ch-ua-platform',
    'user-agent',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'accept',
    'sec-fetch-site',
    'sec-fetch-mode',
    'sec-fetch-dest',
    'referer',
    'accept-encoding',
    'accept-language',
  ]);
  assert.deepEqual(summary.pseudoHeaderOrder, [':method', ':authority', ':scheme', ':path']);
  assert.equal(summary.userAgent, 'UA');
  assert.equal(summary.requestTypes.script, 1);
});

test('mergeRecorderData overlays recorder pseudo-header order onto tshark-owned http2', () => {
  const merged = mergeRecorderData({
    userAgent: '',
    secCHUA: '',
    secCHUAMobile: '',
    secCHUAPlatform: '',
    http2: {
      settings: { HEADER_TABLE_SIZE: 65536, INITIAL_WINDOW_SIZE: 6291456 },
      settingsOrder: ['HEADER_TABLE_SIZE', 'INITIAL_WINDOW_SIZE'],
      windowUpdate: 15663105,
    },
    headerOrders: null,
    captureSources: { tls: 'tshark', http2: 'tshark' },
  }, {
    userAgent: 'UA',
    secCHUA: '"Chromium";v="147"',
    secCHUAMobile: '?0',
    secCHUAPlatform: '"macOS"',
    pseudoHeaderOrder: [':method', ':authority', ':scheme', ':path'],
    headerOrders: {
      script: ['user-agent', 'accept'],
    },
  });

  assert.equal(merged.userAgent, 'UA');
  assert.deepEqual(merged.http2, {
    settings: { HEADER_TABLE_SIZE: 65536, INITIAL_WINDOW_SIZE: 6291456 },
    settingsOrder: ['HEADER_TABLE_SIZE', 'INITIAL_WINDOW_SIZE'],
    windowUpdate: 15663105,
    pseudoHeaderOrder: [':method', ':authority', ':scheme', ':path'],
  });
  assert.deepEqual(merged.headerOrders, {
    script: ['user-agent', 'accept'],
  });
  assert.deepEqual(merged.captureSources, {
    tls: 'tshark',
    http2: 'tshark',
    headerOrders: 'recorder',
  });
});

test('classifyRequestFromHeaderPairs classifies script and xhr post shapes', () => {
  assert.equal(classifyRequestFromHeaderPairs([
    { name: 'sec-fetch-dest', value: 'script' },
  ]), 'script');

  assert.equal(classifyRequestFromHeaderPairs([
    { name: 'sec-fetch-dest', value: 'empty' },
    { name: 'sec-fetch-mode', value: 'cors' },
  ], { method: 'POST' }), 'xhr-post');
});
