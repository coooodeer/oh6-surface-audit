'use strict';

function requireWindowsNative(platform = process.platform) {
  if (platform === 'win32') return;
  const error = new Error('autonomy tools require native Windows; no Linux/WSL fallback is configured');
  error.code = 'windows-native-required';
  throw error;
}

module.exports = { requireWindowsNative };
