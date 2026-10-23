'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { requireWindowsNative } = require('../lib/autonomy/platform');

test('native Windows is the only configured autonomy execution platform', () => {
  assert.doesNotThrow(() => requireWindowsNative('win32'));
  for (const platform of ['linux', 'darwin', 'freebsd']) {
    assert.throws(() => requireWindowsNative(platform), { code: 'windows-native-required' });
  }
  assert.equal(process.platform, 'win32');
});

test('CLI and direct dispatcher refuse simulated WSL before reading facts or spending budget', () => {
  const root = path.join(__dirname, '..');
  const simulate = "Object.defineProperty(process, 'platform', {value:'linux'}); ";
  const cli = spawnSync(process.execPath, ['-e', simulate +
    "require('./bin/autonomy').main(['run']).then(code=>process.exitCode=code)"],
  { cwd: root, encoding: 'utf8' });
  assert.equal(cli.status, 4);
  assert.match(cli.stderr, /windows-native-required/);
  const tool = spawnSync(process.execPath, ['-e', simulate +
    "require('./lib/autonomy/tools').run('getScopeOverview', {}, {}).catch(e=>{console.log(e.code);process.exitCode=4})"],
  { cwd: root, encoding: 'utf8' });
  assert.equal(tool.status, 4);
  assert.match(tool.stdout, /windows-native-required/);
});
