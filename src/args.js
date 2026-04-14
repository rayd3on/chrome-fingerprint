'use strict';

const readline = require('readline');

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => {
    rl.close();
    resolve(answer.trim());
  }));
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function consumeValue(argv, index, flag) {
  const value = argv[index];
  if (value === undefined || value.startsWith('-')) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parseArgs(argv = process.argv.slice(2)) {
  const opts = {
    version: null,
    url: null,
    chromePath: null,
    iface: null,
    headerSource: 'auto',
    skipHeaders: false,
    skipTls: false,
    timeout: 15,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--version':
      case '-v':
        opts.version = consumeValue(argv, ++i, arg);
        break;
      case '--url':
      case '-u':
        opts.url = consumeValue(argv, ++i, arg);
        break;
      case '--chrome-path':
        opts.chromePath = consumeValue(argv, ++i, arg);
        break;
      case '--interface':
      case '-i':
        opts.iface = consumeValue(argv, ++i, arg);
        break;
      case '--skip-headers':
        opts.skipHeaders = true;
        break;
      case '--skip-tls':
        opts.skipTls = true;
        break;
      case '--header-source':
        opts.headerSource = consumeValue(argv, ++i, arg);
        break;
      case '--timeout':
      case '-t':
        opts.timeout = Number.parseInt(consumeValue(argv, ++i, arg), 10);
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (!Number.isInteger(opts.timeout) || opts.timeout <= 0) {
    throw new Error('--timeout must be a positive integer in seconds.');
  }

  opts.headerSource = String(opts.headerSource || 'auto').toLowerCase();
  if (!['auto', 'recorder'].includes(opts.headerSource)) {
    throw new Error('--header-source must be one of: auto, recorder.');
  }

  return opts;
}

function printHelp() {
  console.log(`
Usage: node capture.js [options]

Capture Chrome's TLS fingerprint and HTTP request header ordering for a URL.

Options:
  --version, -v    Chrome major version (for example: 147). Prompted if omitted.
  --url, -u        Target URL. Prompted if omitted.
  --interface, -i  Capture interface for tshark. Prompted if omitted.
  --chrome-path    Path to a Chrome or Chromium binary.
  --header-source  Recorder capture mode: auto or recorder (default: auto).
  --skip-headers   Skip recorder capture and capture TLS only.
  --skip-tls       Skip TLS capture and run the recorder only.
  --timeout, -t    Wait time in seconds for each phase (default: 15).
  --help, -h       Show this help.

Examples:
  node capture.js --version 147 --url https://example.com
  node capture.js --version 147 --url https://example.com --header-source recorder
  node capture.js --version 147 --url https://example.com --skip-headers
  node capture.js
`);
}

function normalizeChromeVersion(version) {
  const value = String(version || '').trim();
  const match = value.match(/^(\d+)(?:\.\d+\.\d+\.\d+)?$/);
  if (!match) {
    throw new Error('Chrome version must be a major version like "147" or a full Chrome version string.');
  }
  return match[1];
}

function normalizeTargetUrl(input) {
  let value = String(input || '').trim();
  if (!value) throw new Error('Target URL is required.');

  if (!/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(value)) {
    value = `https://${value}`;
  }

  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only http:// and https:// URLs are supported.');
  }

  return url.toString();
}

module.exports = {
  ask,
  sleep,
  consumeValue,
  parseArgs,
  printHelp,
  normalizeChromeVersion,
  normalizeTargetUrl,
};
