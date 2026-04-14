'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { TSHARK_MAX_BUFFER, TOOL_PATHS } = require('./paths');

function runCapture(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: TSHARK_MAX_BUFFER,
    ...options,
  });

  return {
    ok: !result.error && result.status === 0,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error || null,
  };
}

function commandExists(command) {
  const lookup = os.platform() === 'win32' ? 'where' : 'which';
  return runCapture(lookup, [command]).ok;
}

function hasBin(command) {
  if (commandExists(command)) return true;

  const candidates = (TOOL_PATHS[os.platform()] || {})[command] || [];
  const sep = os.platform() === 'win32' ? ';' : ':';
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      process.env.PATH = `${path.dirname(candidate)}${sep}${process.env.PATH || ''}`;
      return true;
    }
  }

  return false;
}

function findCommandOnPath(commands) {
  for (const command of commands) {
    const lookup = os.platform() === 'win32' ? runCapture('where', [command]) : runCapture('which', [command]);
    if (!lookup.ok) continue;
    const first = lookup.stdout.split(/\r?\n/).map(line => line.trim()).find(Boolean);
    if (first) return first;
  }
  return null;
}

function listInterfaces() {
  return runCapture('tshark', ['-D'], { timeout: 5000 }).stdout.trim();
}

function selectInterfaceFromList(list, platform = os.platform()) {
  if (!list) {
    if (platform === 'darwin') return 'en0';
    if (platform === 'linux') return 'any';
    return '1';
  }

  const entries = list
    .split(/\r?\n/)
    .map(line => {
      const match = line.match(/^(\d+)\.\s+(.+)$/);
      if (!match) return null;
      const body = match[2].trim();
      const name = body.split(/\s+\(/)[0];
      return { index: match[1], body, name };
    })
    .filter(Boolean);

  if (!entries.length) {
    if (platform === 'darwin') return 'en0';
    if (platform === 'linux') return 'any';
    return '1';
  }

  if (platform === 'linux') {
    const any = entries.find(entry => entry.name === 'any');
    if (any) return any.name;
  }

  if (platform === 'darwin') {
    const en0 = entries.find(entry => entry.name === 'en0');
    if (en0) return en0.name;
  }

  const preferred = entries.find(entry => /(wi-?fi|wireless|airport|ethernet|wlan|en0|eth0)/i.test(entry.body));
  if (preferred) return platform === 'win32' ? preferred.index : preferred.name;

  return platform === 'win32' ? entries[0].index : entries[0].name;
}

function autoDetectInterface() {
  return selectInterfaceFromList(listInterfaces());
}

function runTsharkRead(pcap, args, options = {}) {
  const { twoPass = false, keylog = null } = options;
  const prefs = [
    '-o', 'tcp.desegment_tcp_streams:TRUE',
    '-o', 'tcp.reassemble_out_of_order:TRUE',
    '-o', 'tls.desegment_ssl_records:TRUE',
    '-o', 'tls.desegment_ssl_application_data:TRUE',
  ];
  if (keylog) {
    prefs.push('-o', `tls.keylog_file:${keylog}`);
  }
  const passArgs = twoPass ? ['-2'] : [];
  const timeout = twoPass ? 120000 : 15000;
  return runCapture('tshark', [...passArgs, '-r', pcap, ...prefs, ...args], { timeout }).stdout.trim();
}

function printDependencyHelp(tool) {
  const hints = {
    tshark: {
      name: 'tshark',
      homepage: 'https://www.wireshark.org/download.html',
      commands: {
        darwin: 'brew install wireshark',
        linux: 'Install the Wireshark CLI package for your distro (for example: sudo apt install tshark)',
        win32: 'winget install WiresharkFoundation.Wireshark --source winget',
      },
    },
  };

  const hint = hints[tool];
  const platform = os.platform();
  console.error(`  ${hint.name} was not found on PATH.`);
  console.error(`  Install it first: ${hint.commands[platform] || hint.homepage}`);
  console.error(`  Download page: ${hint.homepage}`);
}

module.exports = {
  runCapture,
  commandExists,
  hasBin,
  findCommandOnPath,
  listInterfaces,
  selectInterfaceFromList,
  autoDetectInterface,
  runTsharkRead,
  printDependencyHelp,
};
