#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { PROFILES_DIR } = require('./src/paths');
const args = require('./src/args');
const tshark = require('./src/tshark');
const { ensureChrome, getInstalledChromeVersion } = require('./src/chrome');
const tls = require('./src/tls');
const recorder = require('./src/recorder');

const {
  ask, parseArgs, printHelp,
  normalizeChromeVersion, normalizeTargetUrl,
} = args;

function printSummary(profile, outputPath) {
  console.log(`\n  Saved: ${outputPath}\n`);
  if (profile.tls) {
    console.log('  TLS:');
    console.log(`    JA3:     ${profile.tls.ja3Hash || 'n/a'}`);
    console.log(`    Ciphers: ${(profile.tls.cipherSuites || []).length}`);
    console.log(`    ALPN:    ${(profile.tls.alpn || []).join(', ') || 'n/a'}`);
  }
  if (profile.http2) {
    console.log('  HTTP/2:');
    console.log(`    Settings: ${Object.keys(profile.http2.settings || {}).length}`);
    console.log(`    Pseudo-Headers: ${(profile.http2.pseudoHeaderOrder || []).join(', ') || 'n/a'}`);
  }
  if (profile.headerOrders) {
    console.log('  Headers:');
    for (const [type, order] of Object.entries(profile.headerOrders)) {
      console.log(`    ${type.padEnd(25)} ${order.length} headers`);
    }
  }
  console.log('');
}

async function main() {
  let opts;
  try { opts = parseArgs(); }
  catch (error) { console.error(error.message); printHelp(); process.exit(1); }

  if (opts.skipTls && opts.skipHeaders) {
    console.error('  --skip-tls and --skip-headers together leave nothing to capture.');
    process.exit(1);
  }

  console.log('\n  Chrome Fingerprint Capture\n');

  if (!opts.version) opts.version = await ask('  Chrome version (for example 147): ');
  if (!opts.url) opts.url = await ask('  Target URL: ');
  if (!opts.version || !opts.url) { console.error('Version and URL are required.'); process.exit(1); }

  try {
    opts.version = normalizeChromeVersion(opts.version);
    opts.url = normalizeTargetUrl(opts.url);
  } catch (error) { console.error(error.message); process.exit(1); }

  if (!opts.skipTls && !tshark.hasBin('tshark')) { tshark.printDependencyHelp('tshark'); process.exit(1); }

  const chromePath = await ensureChrome(opts.chromePath, opts.version);
  const fullVersion = getInstalledChromeVersion(chromePath);
  if (!fullVersion) {
    console.error(`  Could not determine Chrome version for ${chromePath}. Refusing to save an unverified profile.`);
    process.exit(1);
  }
  if (!fullVersion.startsWith(`${opts.version}.`)) {
    console.error(`  Resolved Chrome ${fullVersion} does not match requested major ${opts.version}. Refusing to capture mislabeled output.`);
    process.exit(1);
  }
  console.log(`  Chrome: ${fullVersion} (${chromePath})`);

  if (!opts.skipTls && !opts.iface) {
    const interfaces = tshark.listInterfaces();
    if (interfaces) {
      console.log('\n  Available interfaces:\n');
      console.log(interfaces.split(/\r?\n/).map(line => `    ${line}`).join('\n'));
      const detected = tshark.selectInterfaceFromList(interfaces);
      opts.iface = await ask(`\n  Select interface [${detected}]: `) || detected;
    } else {
      opts.iface = tshark.autoDetectInterface();
    }
  }

  const profile = {
    chromeVersion: opts.version,
    chromeFullVersion: fullVersion,
    platform: os.platform() === 'darwin' ? 'macOS' : os.platform() === 'win32' ? 'Windows' : 'Linux',
    capturedAt: new Date().toISOString(),
    targetUrl: opts.url,
    userAgent: '', secCHUA: '', secCHUAMobile: '', secCHUAPlatform: '',
    tls: null, http2: null, headerOrders: null,
    captureSources: {},
  };

  if (!opts.skipTls) {
    const tlsResult = await tls.captureTls(chromePath, opts.url, opts.iface, opts.timeout, { terminateProcess: recorder.terminateProcess });
    if (tlsResult) {
      if (tlsResult.http2) { profile.http2 = tlsResult.http2; profile.captureSources.http2 = 'tshark'; delete tlsResult.http2; }
      profile.tls = tlsResult;
      profile.captureSources.tls = 'tshark';
    }
  }

  if (!opts.skipHeaders) {
    let recorderHeaders = null;
    if (opts.headerSource === 'recorder' || opts.headerSource === 'auto') {
      recorderHeaders = await recorder.captureHeadersWithRecorder(chromePath, opts.url, opts.timeout);
      if (!recorderHeaders && opts.headerSource === 'recorder') {
        console.error('  Recorder header capture failed.'); process.exit(1);
      }
    }
    Object.assign(profile, recorder.mergeRecorderData(profile, recorderHeaders));
    if (recorderHeaders?.headerOrders && Object.keys(recorderHeaders.headerOrders).length) {
      console.log('  Header orders: sourced from Go recorder.');
      console.log(`  Recorder request types: ${JSON.stringify(recorderHeaders.requestTypes)}`);
    } else {
      console.log('  Header orders were not found from the recorder.');
    }
  }

  if (!profile.tls && !profile.headerOrders) {
    console.error('\n  No capture data was produced.\n'); process.exit(1);
  }

  fs.mkdirSync(PROFILES_DIR, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const outputPath = path.join(PROFILES_DIR, `chrome-${opts.version}-${timestamp}.json`);
  fs.writeFileSync(outputPath, JSON.stringify(profile, null, 2));
  printSummary(profile, outputPath);
}

if (require.main === module) {
  main().catch(error => { console.error(error); process.exit(1); });
}

module.exports = {
  classifyRequestFromHeaderPairs: recorder.classifyRequestFromHeaderPairs,
  mergeRecorderData: recorder.mergeRecorderData,
  normalizeChromeVersion: args.normalizeChromeVersion,
  normalizeNumericToken: tls.normalizeNumericToken,
  normalizeTargetUrl: args.normalizeTargetUrl,
  parseArgs: args.parseArgs,
  parseRecorderOutput: recorder.parseRecorderOutput,
  parseNumericList: tls.parseNumericList,
  sanitizeHeaderOrder: recorder.sanitizeHeaderOrder,
  selectInterfaceFromList: tshark.selectInterfaceFromList,
  summarizeTlsKeylogFile: tls.summarizeTlsKeylogFile,
  summarizeRecordedRequests: recorder.summarizeRecordedRequests,
};
