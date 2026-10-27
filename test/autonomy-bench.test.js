'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const BENCH = path.join(ROOT, 'tools', 'autonomy-bench.js');

test('autonomy-bench records wall, CPU, RSS and fs metrics for a child run', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-bench-'));
  try {
    const tmpRoot = path.resolve(os.tmpdir());
    const resolvedTmp = path.resolve(tmp);
    assert.ok(resolvedTmp.startsWith(tmpRoot + path.sep), `temp dir ${resolvedTmp} must stay under ${tmpRoot}`);
    const out = path.join(resolvedTmp, 'metrics.json');

    // 裸 `-e` 在 Node 25 上不会经过公开 fs，故加载一个真实模块，让 readBytes>0 有意义。
    const target = 'require("./lib/autonomy/ids.js");process.stdout.write("x".repeat(1000))';
    const result = spawnSync(process.execPath, [
      BENCH,
      `--out=${out}`,
      '--label=selftest',
      '--',
      '-e',
      target
    ], { cwd: ROOT, encoding: 'utf8' });

    assert.equal(result.status, 0, result.stderr || String(result.error));
    assert.ok(fs.existsSync(out), 'metrics file must exist');
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    assert.equal(doc.schema, 'autonomy-bench-v1');
    assert.equal(doc.label, 'selftest');
    assert.equal(doc.exitCode, 0);
    assert.ok(doc.wallMs >= 0);
    assert.ok(doc.fs.readBytes > 0);
    assert.ok(doc.fs.readCalls > 0);
    assert.ok(doc.fs.writeBytes >= 0);
    assert.ok(doc.sampledPeakRssBytes > 0);
  } finally {
    const tmpRoot = path.resolve(os.tmpdir());
    const resolvedTmp = path.resolve(tmp);
    assert.ok(resolvedTmp.startsWith(tmpRoot + path.sep), `refusing to remove ${resolvedTmp}: outside ${tmpRoot}`);
    fs.rmSync(resolvedTmp, { recursive: true, force: true });
  }
});
