'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const { sleep } = require('./args');
const { runCapture, runTsharkRead } = require('./tshark');

const CIPHER_NAMES = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
};

const EXT_NAMES = {
  0: 'server_name',
  5: 'status_request',
  10: 'supported_groups',
  11: 'ec_point_formats',
  13: 'signature_algorithms',
  16: 'alpn',
  17: 'signed_certificate_timestamp',
  18: 'client_certificate_type',
  21: 'padding',
  23: 'extended_master_secret',
  27: 'compress_certificate',
  35: 'session_ticket',
  41: 'pre_shared_key',
  43: 'supported_versions',
  44: 'cookie',
  45: 'psk_key_exchange_modes',
  49: 'post_handshake_auth',
  50: 'signature_algorithms_cert',
  51: 'key_share',
  17513: 'application_settings',
  0xfe0d: 'encrypted_client_hello',
};

const GROUP_NAMES = {
  23: 'secp256r1',
  24: 'secp384r1',
  25: 'secp521r1',
  29: 'x25519',
  30: 'x448',
  0x6399: 'X25519Kyber768',
  0x4588: 'X25519MLKEM768',
};

const SIG_NAMES = {
  0x0403: 'ecdsa_secp256r1_sha256',
  0x0503: 'ecdsa_secp384r1_sha384',
  0x0603: 'ecdsa_secp521r1_sha512',
  0x0804: 'rsa_pss_rsae_sha256',
  0x0805: 'rsa_pss_rsae_sha384',
  0x0806: 'rsa_pss_rsae_sha512',
  0x0401: 'rsa_pkcs1_sha256',
  0x0501: 'rsa_pkcs1_sha384',
  0x0601: 'rsa_pkcs1_sha512',
};

function isGrease(value) {
  return Number.isInteger(value) && (value & 0x0f0f) === 0x0a0a;
}

function formatHex(value) {
  if (!Number.isInteger(value)) return '0x0000';
  return `0x${value.toString(16).padStart(value <= 0xffff ? 4 : 2, '0')}`;
}

function normalizeNumericToken(raw, map = {}) {
  const token = String(raw || '').trim().toLowerCase();
  if (!token) return null;

  if (token.startsWith('0x')) {
    return Number.parseInt(token, 16);
  }

  if (/^[0-9]+$/.test(token)) {
    const decimal = Number.parseInt(token, 10);
    const hex = Number.parseInt(token, 16);
    const decimalKnown = Object.hasOwn(map, decimal) || isGrease(decimal);
    const hexKnown = Object.hasOwn(map, hex) || isGrease(hex);

    if (decimalKnown && !hexKnown) return decimal;
    if (hexKnown && !decimalKnown) return hex;
    return decimal;
  }

  if (/^[0-9a-f]+$/.test(token)) {
    return Number.parseInt(token, 16);
  }

  return null;
}

function parseNumericList(raw, map = {}) {
  return String(raw || '')
    .split(/[,\t]/)
    .map(token => normalizeNumericToken(token, map))
    .filter(value => Number.isInteger(value));
}

function parseStringList(raw) {
  return String(raw || '')
    .split(',')
    .map(value => value.replace(/\\,/g, ',').trim())
    .filter(Boolean);
}

function nameFromValue(value, map) {
  if (isGrease(value)) return `GREASE(${formatHex(value)})`;
  return map[value] || `unknown(${formatHex(value)})`;
}

function firstPopulatedFieldRow(raw, valueStartIndex = 0) {
  for (const line of String(raw || '').split(/\r?\n/)) {
    const cols = line.split('\t');
    for (let i = valueStartIndex; i < cols.length; i++) {
      if (cols[i] && cols[i].trim()) return cols;
    }
  }
  return null;
}

function summarizeTlsKeylogFile(keylogFile) {
  if (!keylogFile || !fs.existsSync(keylogFile)) return null;
  const counts = {};
  for (const line of fs.readFileSync(keylogFile, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const [label] = trimmed.split(/\s+/, 1);
    if (!label) continue;
    counts[label] = (counts[label] || 0) + 1;
  }
  const labels = Object.keys(counts).sort();
  return {
    counts,
    labels,
    hasTls13HandshakeSecrets: labels.some(label => label.endsWith('HANDSHAKE_TRAFFIC_SECRET')),
    hasTls13ApplicationSecrets: labels.some(label => label.includes('TRAFFIC_SECRET_0')),
  };
}

function hostMatches(candidate, target) {
  if (!candidate || !target) return false;
  const a = candidate.toLowerCase();
  const b = target.toLowerCase();
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

function parseTls(pcap, targetUrl, keylog = null) {
  const targetHost = new URL(targetUrl).hostname;
  const allClientHellos = runTsharkRead(pcap, [
    '-Y', 'tls.handshake.type == 1',
    '-T', 'fields',
    '-e', 'frame.number',
    '-e', 'tls.handshake.extensions_server_name',
    '-e', 'tcp.stream',
    '-e', 'tls.handshake.ciphersuite',
  ]);

  const helloFrames = allClientHellos
    .split(/\r?\n/)
    .map(line => {
      const [frame, serverName, stream, ciphersRaw] = line.split('\t');
      const ciphers = parseNumericList(ciphersRaw, CIPHER_NAMES);
      return {
        frame: frame ? frame.trim() : '',
        serverName: serverName ? serverName.trim() : '',
        stream: stream ? stream.trim() : '',
        ciphers,
      };
    })
    .filter(entry => entry.frame);

  function isTls13Like(entry) {
    return entry.ciphers.some(cipher => cipher >= 0x1301 && cipher <= 0x1303);
  }

  function prioritizeHelloFrames(list) {
    const seen = new Set();
    const ordered = [];
    const groups = [
      list.filter(entry => hostMatches(entry.serverName, targetHost) && isTls13Like(entry)),
      list.filter(entry => isTls13Like(entry)),
      list.filter(entry => hostMatches(entry.serverName, targetHost)),
      list,
    ];
    for (const group of groups) {
      for (const entry of group) {
        if (seen.has(entry.frame)) continue;
        seen.add(entry.frame);
        ordered.push(entry);
      }
    }
    return ordered;
  }

  const prioritizedFrames = prioritizeHelloFrames(helloFrames);
  let selected = prioritizedFrames[0] || null;

  const frame = selected?.frame || null;
  if (!frame) {
    try { fs.unlinkSync(pcap); } catch {}
    console.error('  No TLS ClientHello was found in the capture.');
    return null;
  }

  const selectedStream = selected.stream || '';

  function readField(extraArgs) {
    const filter = `frame.number == ${selected.frame} && tls.handshake.type == 1`;
    return runTsharkRead(pcap, ['-Y', filter, '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=,', ...extraArgs]).split(/\r?\n/)[0]?.trim() || '';
  }

  // tshark field names vary between versions -try each spelling per field.
  function tryFields(names, parser) {
    for (const name of names) {
      const raw = readField(['-e', name]);
      if (raw) return parser(raw);
    }
    return [];
  }

  const ciphers = parseNumericList(readField(['-e', 'tls.handshake.ciphersuite']), CIPHER_NAMES);
  const extensions = tryFields(
    ['tls.handshake.extension.type', 'tls.handshake.extensions.type'],
    raw => parseNumericList(raw, EXT_NAMES)
  );
  const groups = tryFields(
    ['tls.handshake.extensions_supported_group', 'tls.handshake.extensions_supported_groups', 'tls.handshake.extensions.supported_group', 'tls.handshake.extensions.supported_groups', 'tls.handshake.extensions_elliptic_curves'],
    raw => parseNumericList(raw, GROUP_NAMES)
  );
  const signatures = tryFields(
    ['tls.handshake.sig_hash_alg', 'tls.handshake.sig_hash_algorithm', 'tls.handshake.extensions.signature_algorithms'],
    raw => parseNumericList(raw, SIG_NAMES)
  );
  const alpn = tryFields(
    ['tls.handshake.extensions_alpn_str', 'tls.handshake.extensions.alpn_str'],
    raw => parseStringList(raw)
  );
  const supportedVersions = tryFields(
    ['tls.handshake.extensions.supported_version', 'tls.handshake.extensions_supported_version', 'tls.handshake.extensions_supported_versions', 'tls.handshake.extensions.supported_versions'],
    raw => parseNumericList(raw)
  );

  const ja3 = [
    '771',
    ciphers.join('-'),
    extensions.join('-'),
    groups.join('-'),
    '0',
  ].join(',');

  console.log(`  ClientHellos: ${helloFrames.length}, selected frame: ${frame}`);
  console.log(`  ClientHello selection: SNI=${selected.serverName || 'n/a'} stream=${selectedStream || 'n/a'}`);
  console.log(`  Ciphers: ${ciphers.length}, Extensions: ${extensions.length}, Groups: ${groups.length}, SigAlgs: ${signatures.length}`);
  console.log(`  Offered ALPN: ${alpn.join(', ') || 'n/a'}`);

  // HTTP/2 SETTINGS live inside the encrypted TLS stream. Two-pass tshark with
  // SSLKEYLOGFILE decrypts them. Known broken on Windows ARM: the dissector
  // never receives the decrypted bytes, so http2.settings will be empty.
  let http2 = null;
  if (keylog) {
    const h2Fields = ['-E', 'occurrence=a', '-E', 'aggregator=,', '-e', 'frame.number',
      '-e', 'http2.settings.header_table_size', '-e', 'http2.settings.enable_push',
      '-e', 'http2.settings.initial_window_size', '-e', 'http2.settings.max_header_list_size',
      '-e', 'http2.settings.max_concurrent_streams', '-e', 'http2.settings.max_frame_size'];

    const h2Raw = runTsharkRead(pcap, ['-Y', 'http2.type == 4 && http2.streamid == 0', '-T', 'fields', ...h2Fields], { twoPass: true, keylog });
    const h2Row = firstPopulatedFieldRow(h2Raw, 1);
    if (h2Row) {
      const names = ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE', 'MAX_CONCURRENT_STREAMS', 'MAX_FRAME_SIZE'];
      http2 = { settings: {}, settingsOrder: [] };
      h2Row.slice(1).forEach((val, i) => { if (val) { http2.settings[names[i]] = parseInt(val, 10); http2.settingsOrder.push(names[i]); } });

      const wuRaw = runTsharkRead(pcap,
        ['-Y', 'http2.type == 8 && http2.streamid == 0', '-T', 'fields', '-e', 'http2.window_update.window_size_increment'],
        { twoPass: true, keylog });
      const wuRow = firstPopulatedFieldRow(wuRaw);
      if (wuRow?.[0]) http2.windowUpdate = parseInt(wuRow[0], 10);
      console.log(`  HTTP/2 SETTINGS: ${Object.keys(http2.settings).length} settings captured`);
    } else {
      console.log('  HTTP/2 SETTINGS: not captured (TLS decryption unavailable -Windows ARM tshark)');
    }
  }

  try { fs.unlinkSync(pcap); } catch {}

  return {
    cipherSuites: ciphers.map(value => nameFromValue(value, CIPHER_NAMES)),
    cipherSuitesHex: ciphers.map(formatHex),
    extensions: extensions.map(value => nameFromValue(value, EXT_NAMES)),
    extensionsHex: extensions.map(formatHex),
    supportedGroups: groups.map(value => nameFromValue(value, GROUP_NAMES)),
    supportedGroupsHex: groups.map(formatHex),
    signatureAlgorithms: signatures.map(value => nameFromValue(value, SIG_NAMES)),
    signatureAlgorithmsHex: signatures.map(formatHex),
    alpn,
    supportedVersions: supportedVersions.map(formatHex),
    ja3,
    ja3Hash: crypto.createHash('md5').update(ja3).digest('hex'),
    http2,
  };
}

async function captureTls(chromePath, url, iface, timeout, { terminateProcess }) {
  console.log('\n--- TLS Capture ---\n');

  const pcap = path.join(os.tmpdir(), `chrome-tls-${Date.now()}.pcap`);
  const userData = path.join(os.tmpdir(), `chrome-tls-${Date.now()}`);
  const keylogFile = path.join(os.tmpdir(), `chrome-tls-${Date.now()}.keys.log`);
  fs.writeFileSync(keylogFile, '');

  const tshark = spawn('tshark', ['-i', String(iface), '-f', 'tcp port 443', '-w', pcap, '-q'], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let tsharkErr = '';
  tshark.stderr.on('data', chunk => {
    tsharkErr += chunk.toString();
  });

  await sleep(2000);

  if (/permission denied/i.test(tsharkErr)) {
    await terminateProcess(tshark);
    try { fs.unlinkSync(keylogFile); } catch {}
    if (os.platform() === 'win32') {
      console.error('  Permission denied. Run the terminal as Administrator.');
    } else {
      console.error('  Permission denied. Re-run with elevated privileges.');
      console.error(`    sudo node capture.js ${process.argv.slice(2).join(' ')}`);
      if (os.platform() === 'darwin') {
        console.error('  If needed, install the Wireshark ChmodBPF package.');
      }
    }
    return null;
  }

  if (/npcap|wpcap\.dll/i.test(tsharkErr)) {
    await terminateProcess(tshark);
    try { fs.unlinkSync(keylogFile); } catch {}
    console.error('  Npcap is required for packet capture on Windows: https://npcap.com/');
    return null;
  }

  console.log(`  Interface: ${iface}`);
  console.log(`  Target: ${url}`);

  const chrome = spawn(chromePath, [
    `--user-data-dir=${userData}`,
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
    `--ssl-key-log-file=${keylogFile}`,
    url,
  ], {
    stdio: 'ignore',
    env: { ...process.env, SSLKEYLOGFILE: keylogFile },
  });

  console.log(`  Waiting ${timeout}s...`);
  await sleep(timeout * 1000);

  await terminateProcess(chrome);
  await terminateProcess(tshark, 1000);

  try {
    fs.rmSync(userData, { recursive: true, force: true });
  } catch {}

  if (!fs.existsSync(pcap) || fs.statSync(pcap).size < 500) {
    try { fs.unlinkSync(pcap); } catch {}
    try { fs.unlinkSync(keylogFile); } catch {}
    console.error('  No TLS traffic was captured. Check the interface and privileges.');
    return null;
  }

  const keylogSize = fs.existsSync(keylogFile) ? fs.statSync(keylogFile).size : 0;
  if (keylogSize > 0) {
    console.log(`  TLS key log: ${keylogSize} bytes`);
    const keylogSummary = summarizeTlsKeylogFile(keylogFile);
    if (keylogSummary?.labels.length) {
      const labelSummary = keylogSummary.labels.map(label => `${label}=${keylogSummary.counts[label]}`).join(', ');
      console.log(`  TLS key labels: ${labelSummary}`);
      if (keylogSummary.hasTls13ApplicationSecrets && !keylogSummary.hasTls13HandshakeSecrets) {
        console.log('  Note: key log has TLS 1.3 application secrets but no handshake secrets.');
      }
    }
  } else {
    console.log('  WARNING: Chrome did not write any TLS secrets to the key log file.');
    console.log('  TLS fingerprint capture still works because ClientHello fields do not require decryption.');
  }

  const stats = runCapture('tshark', ['-r', pcap, '-q', '-z', 'io,phs'], { timeout: 10000 });
  if (stats.stdout) {
    const tlsCount = (stats.stdout.match(/tls\s+frames:(\d+)/i) || [])[1] || '0';
    const quicCount = (stats.stdout.match(/quic\s+frames:(\d+)/i) || [])[1] || '0';
    const totalMatch = stats.stdout.match(/frames:\s*(\d+)/);
    console.log(`  Pcap stats: ${totalMatch ? totalMatch[1] : '?'} total frames, ${tlsCount} TLS, ${quicCount} QUIC`);
    if (quicCount !== '0') {
      console.log('  Chrome may have used QUIC despite --disable-quic. Delete .chrome-versions and retry.');
    }
  }

  const parsed = parseTls(pcap, url, keylogSize > 0 ? keylogFile : null);
  try { fs.unlinkSync(keylogFile); } catch {}
  return parsed;
}

module.exports = {
  CIPHER_NAMES,
  EXT_NAMES,
  GROUP_NAMES,
  SIG_NAMES,
  isGrease,
  formatHex,
  normalizeNumericToken,
  parseNumericList,
  parseStringList,
  nameFromValue,
  firstPopulatedFieldRow,
  summarizeTlsKeylogFile,
  hostMatches,
  parseTls,
  captureTls,
};
