'use strict';

const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PROFILES_DIR = path.join(ROOT, 'profiles');
const CHROME_DIR = path.join(ROOT, '.chrome-versions');
const TSHARK_MAX_BUFFER = 128 * 1024 * 1024;

const TOOL_PATHS = {
  win32: {
    tshark: [
      'C:\\Program Files\\Wireshark\\tshark.exe',
      'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
    ],
  },
  darwin: {
    tshark: [
      '/opt/homebrew/bin/tshark',
      '/usr/local/bin/tshark',
      '/Applications/Wireshark.app/Contents/MacOS/tshark',
    ],
  },
  linux: {
    tshark: [
      '/usr/bin/tshark',
      '/usr/sbin/tshark',
      '/usr/local/bin/tshark',
      '/snap/bin/wireshark.tshark',
      '/snap/bin/tshark',
    ],
  },
};

module.exports = {
  ROOT,
  PROFILES_DIR,
  CHROME_DIR,
  TSHARK_MAX_BUFFER,
  TOOL_PATHS,
};
