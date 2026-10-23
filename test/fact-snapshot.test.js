'use strict';

/**
 * test/fact-snapshot.test.js —— AG0.1（P1）单元与失败用例。
 * 覆盖：fileStats 行数/哈希、snapshotId 对内容敏感、compdb 流式扫描（gen 目录 + root 过滤 + 变体计数）、截断输入不崩。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const ids = require('../lib/facts/ids');
const scope = require('../lib/facts/scope');
const compdb = require('../lib/facts/compdb');

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ag0-p1-'));
}

test('fileStats：行数、字节数与内容哈希', () => {
  const dir = tmpdir();
  try {
    const a = path.join(dir, 'a.cpp');
    const b = path.join(dir, 'b.cpp');
    const c = path.join(dir, 'c.cpp');
    fs.writeFileSync(a, 'int a;\nint b;\n', 'utf8');
    fs.writeFileSync(b, 'int a;\nint b;', 'utf8');
    fs.writeFileSync(c, 'int a;\nint c;\n', 'utf8');
    const sa = scope.fileStats(a);
    const sb = scope.fileStats(b);
    const sc = scope.fileStats(c);
    assert.strictEqual(sa.lines, 2);
    assert.strictEqual(sb.lines, 2, '无结尾换行仍是 2 行');
    assert.strictEqual(sa.bytes, 14);
    assert.notStrictEqual(sa.sha256, sb.sha256, '结尾换行属于内容，哈希必须不同');
    assert.notStrictEqual(sa.sha256, sc.sha256, '内容不同哈希不同');
    assert.strictEqual(sa.sha256, crypto.createHash('sha256').update(fs.readFileSync(a)).digest('hex'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('snapshotId：同载荷相同，内容/工具变化则不同', () => {
  const base = {
    scope: 'd4-r1',
    source: [{ root: 'r', repo: 'r', head: 'abc', files: 1, bytes: 10, sourceManifestHash: 'h1' }],
    build: { parts: [{ part: 'p', present: true, sha256: 's', bytes: 1, entries: 1 }], genVisibility: { referenced: 1, missing: 0 } },
    metadata: { sources: [] },
    tools: { node: 'v1', clang: 'c', treeSitter: 't' }
  };
  const id1 = ids.snapshotIdOf(base);
  assert.strictEqual(id1, ids.snapshotIdOf(JSON.parse(JSON.stringify(base))));
  const changedSource = JSON.parse(JSON.stringify(base));
  changedSource.source[0].sourceManifestHash = 'h2';
  assert.notStrictEqual(id1, ids.snapshotIdOf(changedSource), '源码哈希变化必须改变 snapshotId');
  const changedTools = JSON.parse(JSON.stringify(base));
  changedTools.tools.clang = 'c2';
  assert.notStrictEqual(id1, ids.snapshotIdOf(changedTools), '工具版本变化必须改变 snapshotId');
  const changedBuild = JSON.parse(JSON.stringify(base));
  changedBuild.build.parts[0].sha256 = 's2';
  assert.notStrictEqual(id1, ids.snapshotIdOf(changedBuild), 'compdb 变化必须改变 snapshotId');
});

test('compdb.scanPart：条目数、root 过滤、gen 目录、变体计数、文件哈希', () => {
  const dir = tmpdir();
  try {
    const genA = '-I/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/out/rk3568/gen/rootA/x';
    const genMissing = '-I/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/out/rk3568/gen/rootB/y';
    const entries = [
      { directory: '/mnt/d/w/out/rk3568', file: '/mnt/d/w/OpenHarmony/rootA/a.cpp', command: `clang++ ${genA} -c a.cpp` },
      { directory: '/mnt/d/w/out/rk3568', file: '/mnt/d/w/OpenHarmony/rootA/a.cpp', command: `clang++ ${genA} -c a.cpp -DX` },
      { directory: '/mnt/d/w/out/rk3568', file: '/mnt/d/w/OpenHarmony/rootB/b.c', command: `clang ${genMissing} -c b.c` },
      { directory: '/mnt/d/w/out/rk3568', file: '/mnt/d/w/OpenHarmony/other/c.cpp', command: 'clang++ -c c.cpp' }
    ];
    const file = path.join(dir, 'compile_commands.json');
    const body = JSON.stringify(entries);
    fs.writeFileSync(file, body, 'utf8');

    const res = compdb.scanPart(file, { rootPrefixes: ['/OpenHarmony/rootA/'] });
    assert.strictEqual(res.entries, 4);
    assert.strictEqual(res.bytes, Buffer.byteLength(body));
    assert.strictEqual(res.sha256, crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'));
    assert.deepStrictEqual([...res.rootEntries.keys()], ['/mnt/d/w/OpenHarmony/rootA/a.cpp']);
    assert.strictEqual(res.rootEntries.get('/mnt/d/w/OpenHarmony/rootA/a.cpp').variants, 2);
    assert.strictEqual(res.rootEntries.get('/mnt/d/w/OpenHarmony/rootA/a.cpp').compiler, 'clang++');
    assert.deepStrictEqual([...res.genDirs.keys()].sort(), [
      '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/out/rk3568/gen/rootA/x',
      '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/out/rk3568/gen/rootB/y'
    ]);
    assert.strictEqual(res.complete, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('compdb.scanPart：截断的 JSON 不抛错且标记 complete=false（失败用例）', () => {
  const dir = tmpdir();
  try {
    const file = path.join(dir, 'broken.json');
    fs.writeFileSync(file, '[{"file":"/mnt/d/w/OpenHarmony/rootA/a.cpp","command":"clang++ -c a.cpp"},{"file":', 'utf8');
    const res = compdb.scanPart(file, { rootPrefixes: ['/OpenHarmony/rootA/'] });
    assert.strictEqual(res.complete, false);
    assert.strictEqual(res.entries, 1, '完整的那条仍应被解析');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('wslToWin：路径投影', () => {
  assert.strictEqual(compdb.wslToWin('/mnt/d/a/b.cpp'), 'D:/a/b.cpp');
  assert.strictEqual(compdb.wslToWin('D:/already'), 'D:/already');
  assert.strictEqual(compdb.wslToWin(''), '');
});
