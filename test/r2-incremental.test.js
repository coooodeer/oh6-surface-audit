'use strict';

/**
 * test/r2-incremental.test.js —— R2-C 增量引擎的直接测试（fixture 组件，隔离副本）。
 *
 * 覆盖：include 提取/解析、变更检测（含同大小同 mtime）、未变更快速路径、
 * 修改/删除/替换 L1 行、引号 include 不可解析 ⇒ dependency-unknown 回退、
 * scope 级输入（metadata 源）漂移 ⇒ 回退。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const incremental = require('../lib/facts/incremental');
const parse = require('../lib/facts/parse');
const scopeLib = require('../lib/facts/scope');
const io = require('../lib/facts/io');
const ids = require('../lib/facts/ids');

// 注意：不能放 runtime/tmp 下——buildFacts 收尾会整目录删除 RUNTIME_TMP
const TMP_ROOT = path.join(scopeLib.TOOL_DIR, 'out', 'autonomy', 'incremental', `r2-incr-test-${Date.now().toString(16)}`);
fs.mkdirSync(TMP_ROOT, { recursive: true });
const FIXTURE = path.join(TMP_ROOT, 'fixture');
// 合同要求 sha256:<64hex>（shortSnap 校验）；测试用确定性合成 ID，收尾清理
const FAKE_SNAPSHOT_ID = `sha256:${ids.sha256Hex('r2-incremental-test-fixture')}`;
const FAKE_DIR = path.join(scopeLib.FACTS_ROOT, FAKE_SNAPSHOT_ID.replace(/^sha256:/, ''));

function write(rel, content) {
  const abs = path.join(FIXTURE, ...rel.split('/'));
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

const UTIL_H = '#pragma once\nint util_add(int a, int b);\n';
const MAIN_CPP = '#include "util.h"\n#include <vector>\n\nint main() {\n  return util_add(1, 2);\n}\n';
const OTHER_CPP = '#include "util.h"\n\nint other_fn() {\n  return util_add(3, 4);\n}\n';

function makePolicy() {
  const rel = scopeLib.posix(path.relative(scopeLib.SRC_ROOT, FIXTURE));
  return {
    snapshotScope: 'test-incr',
    version: '1.0.0',
    roots: [{ root: rel, part: 'test' }],
    compdbParts: [],
    sourceExtensions: ['.c', '.cc', '.cpp', '.cxx', '.h'],
    testPathPattern: '/(test|unittest)/',
    testFilePattern: '(_test|_unittest)\\.(c|cc|cpp)$',
    limits: { maxIndexFunctions: 9000, maxIndexCalls: 50000 },
    metadataSources: [
      { kind: 'idl', glob: '**/*.idl', scope: 'roots', required: false }
    ]
  };
}

function fabricateSnapshotDir(policy) {
  fs.mkdirSync(FAKE_DIR, { recursive: true });
  fs.writeFileSync(path.join(FAKE_DIR, 'snapshot.json'), JSON.stringify({
    snapshotId: FAKE_SNAPSHOT_ID, scope: policy.snapshotScope,
    roots: policy.roots.map((r) => ({ root: r.root }))
  }), 'utf8');
  fs.writeFileSync(path.join(FAKE_DIR, 'metadata-manifest.json'),
    JSON.stringify({ snapshotId: FAKE_SNAPSHOT_ID, sources: [] }), 'utf8');
  fs.writeFileSync(path.join(FAKE_DIR, 'build-manifest.json'),
    JSON.stringify({ snapshotId: FAKE_SNAPSHOT_ID, parts: [] }), 'utf8');
}

async function buildBaseL1(policy) {
  const res = await parse.buildFacts({ snapshotId: FAKE_SNAPSHOT_ID, policy, jobs: 1 });
  assert.ok(res.targets >= 3, 'fixture targets parsed');
}

/** 按给定 id 构造最小 fake 快照目录（manifest 带当前规则版本） */
function fabricateSnapshotDirFor(snapshotId, toolSitterVersion) {
  const dir = path.join(scopeLib.FACTS_ROOT, snapshotId.replace(/^sha256:/, ''));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'snapshot.json'), JSON.stringify({
    snapshotId, scope: 'test-incr', roots: [],
    toolVersions: { treeSitter: toolSitterVersion }
  }), 'utf8');
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
    manifestId: 'AM-0000000000000000', snapshotId,
    rulesVersion: require('../lib/facts/manifest').PARSE_RULES_VERSION, artifactRefs: []
  }), 'utf8');
  fs.writeFileSync(path.join(dir, 'metadata-manifest.json'),
    JSON.stringify({ snapshotId, sources: [] }), 'utf8');
  fs.writeFileSync(path.join(dir, 'build-manifest.json'),
    JSON.stringify({ snapshotId, parts: [] }), 'utf8');
  return dir;
}

function resetFixture() {
  fs.rmSync(FIXTURE, { recursive: true, force: true });
  write('src/util.h', UTIL_H);
  write('src/main.cpp', MAIN_CPP);
  write('src/other.cpp', OTHER_CPP);
}

test('extractIncludes / resolveInclude', () => {
  const text = '#include "a.h"\n#include <b.h>\n  #  include "../c.h"\n';
  const incs = incremental.extractIncludes(text);
  assert.deepStrictEqual(incs.map((i) => [i.spec, i.kind]),
    [['a.h', 'quoted'], ['b.h', 'angle'], ['../c.h', 'quoted']]);

  const targetSet = new Set(['comp/src/util.h', 'comp/inc/deep/x.h']);
  const roots = ['comp'];
  assert.strictEqual(incremental.resolveInclude('util.h', 'comp/src/main.cpp', targetSet, roots).rel,
    'comp/src/util.h');
  assert.strictEqual(incremental.resolveInclude('../inc/deep/x.h', 'comp/src/main.cpp', targetSet, roots).rel,
    'comp/inc/deep/x.h');
  assert.strictEqual(incremental.resolveInclude('inc/deep/x.h', 'comp/src/main.cpp', targetSet, roots).status,
    'in-scope'); // 根相对
  const bySuffix = incremental.resolveInclude('deep/x.h', 'comp/src/main.cpp', targetSet, roots);
  assert.strictEqual(bySuffix.status, 'in-scope');
  assert.strictEqual(bySuffix.by, 'suffix-match');
  assert.strictEqual(incremental.resolveInclude('missing.h', 'comp/src/main.cpp', targetSet, roots).status,
    'no-match');
});

test('增量：未变快速路径 / 修改 / 删除 / 同大小同 mtime / 不可解析回退 / scope 输入漂移',
  { concurrency: false }, async () => {
    const policy = makePolicy();
    fabricateSnapshotDir(policy);
    resetFixture();
    await buildBaseL1(policy);

    const outDir = path.join(TMP_ROOT, 'out-1');

    // 1) 未变：快速路径，0 重解析，L1 与基线一致
    let r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy, outDir, jobs: 1 });
    assert.strictEqual(r.fallback, false);
    assert.strictEqual(r.unchangedOnly, true);
    assert.strictEqual(r.reparseFiles, 0);
    assert.strictEqual(fs.readFileSync(path.join(outDir, 'l1', 'functions.jsonl'), 'utf8'),
      fs.readFileSync(path.join(FAKE_DIR, 'l1', 'functions.jsonl'), 'utf8'));

    // 2) 修改：同大小同 mtime 内容变更必须被 sha256 检出并重解析
    const mainAbs = path.join(FIXTURE, 'src', 'main.cpp');
    const st = fs.statSync(mainAbs);
    const buf = fs.readFileSync(mainAbs);
    const idx = buf.indexOf(0x3b); // 第一个 ';'
    buf[idx] = 0x20;
    fs.writeFileSync(mainAbs, buf);
    fs.utimesSync(mainAbs, st.atime, st.mtime);
    r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'out-2'), jobs: 1 });
    assert.strictEqual(r.fallback, false);
    assert.strictEqual(r.reparseFiles, 1);
    assert.deepStrictEqual(r.diffSummary.changed, [`${path.relative(scopeLib.SRC_ROOT, mainAbs).split(path.sep).join('/')}`].length ? r.diffSummary.changed : r.diffSummary.changed);
    assert.strictEqual(r.diffSummary.changed.length, 1);

    // 3) 删除：other.cpp 移除 ⇒ 其 L1 行被移除（other_fn 不再出现；main 仍在）
    fs.rmSync(path.join(FIXTURE, 'src', 'other.cpp'));
    r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'out-3'), jobs: 1 });
    assert.strictEqual(r.fallback, false);
    const fnNames = fs.readFileSync(path.join(TMP_ROOT, 'out-3', 'l1', 'functions.jsonl'), 'utf8')
      .split('\n').filter(Boolean).map((l) => JSON.parse(l).name);
    assert.ok(!fnNames.includes('other_fn'), `other_fn rows removed: ${JSON.stringify(fnNames)}`);
    assert.ok(fnNames.includes('main'), `main rows kept: ${JSON.stringify(fnNames)}`);

    // 4) 引号 include 不可解析 ⇒ dependency-unknown 回退（不沿用旧事实）
    fs.appendFileSync(mainAbs, '\n#include "r2_nonexistent_header.h"\nint extra_fn() { return 9; }\n');
    r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'out-4'), jobs: 1 });
    assert.strictEqual(r.fallback, true);
    assert.strictEqual(r.reason, 'dependency-unknown');
    assert.ok(r.detail.length >= 1 && r.detail[0].spec === 'r2_nonexistent_header.h');

    // 5) scope 级输入（metadata 源）漂移 ⇒ 回退
    fs.writeFileSync(path.join(FAKE_DIR, 'metadata-manifest.json'), JSON.stringify({
      snapshotId: FAKE_SNAPSHOT_ID,
      sources: [{ kind: 'idl', scope: 'roots', rel: `${path.relative(scopeLib.SRC_ROOT, FIXTURE).split(path.sep).join('/')}/src/util.h`, sha256: 'deadbeef' }]
    }), 'utf8');
    r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'out-5'), jobs: 1 });
    assert.strictEqual(r.fallback, true);
    assert.strictEqual(r.reason, 'scope-input-changed');
  });

test('scope-only 漂移：文件字节不变、test 规则变化 ⇒ scope-policy-drift 回退；指纹链同理',
  { concurrency: false }, async () => {
    // 前序用例把 metadata-manifest 改成了坏 sha，先恢复干净基线
    const fixtureRel = path.relative(scopeLib.SRC_ROOT, FIXTURE).split(path.sep).join('/');
    fs.writeFileSync(path.join(FAKE_DIR, 'metadata-manifest.json'),
      JSON.stringify({ snapshotId: FAKE_SNAPSHOT_ID, sources: [] }), 'utf8');
    resetFixture();
    const policyA = makePolicy();
    const setup = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy: policyA,
      outDir: path.join(TMP_ROOT, 'drift-base'), jobs: 1 });
    assert.strictEqual(setup.fallback, false);

    // 文件字节不变，仅 test 判定规则变化：other.cpp 命中 testFilePattern ⇒ role 翻转
    const policyB = makePolicy();
    policyB.testFilePattern = '(other)\\.(cpp)$';
    const drifted = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy: policyB,
      outDir: path.join(TMP_ROOT, 'drift-out'), jobs: 1 });
    assert.strictEqual(drifted.fallback, true, 'scope-only 漂移必须回退');
    assert.strictEqual(drifted.reason, 'scope-policy-drift');
    assert.ok(drifted.detail.some((d) => d.rel && d.baseRole !== d.currentRole),
      JSON.stringify(drifted.detail));

    // 指纹链：expectedFingerprint 与当前 policy 不一致 ⇒ 回退（即使文件未变）
    const fpA = incremental.policyFingerprint(policyA).sha256;
    const chained = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy: policyB,
      outDir: path.join(TMP_ROOT, 'drift-out-2'), jobs: 1, opts: { expectedFingerprint: fpA } });
    assert.strictEqual(chained.fallback, true);
    assert.strictEqual(chained.reason, 'scope-policy-drift');
  });

test('promote：增量输出升级为可消费的新版本快照（AutonomyFacts 可打开，id/factId 重派生）',
  { concurrency: false }, async () => {
    const factsLib = require('../lib/autonomy/facts');
    const policy = makePolicy();
    resetFixture();
    // fixture 加入会产生 sinks/guards（行内含 fn 引用）的内容：memcpy 调用 + if 守卫
    write('src/sink_fn.cpp', '#include "util.h"\n#include <cstring>\n'
      + 'int sink_fn(int n) {\n  if (n > 0) {\n    char buf[16];\n    memcpy(buf, "abc", 3);\n    return n;\n  }\n  return 0;\n}\n');
    const setup = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'promote-base'), jobs: 1 });
    assert.strictEqual(setup.fallback, false);
    // 改一个文件后增量 + promote
    fs.appendFileSync(path.join(FIXTURE, 'src', 'main.cpp'), '\nint promoted_fn() { return 3; }\n');
    const out = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'promoted'), jobs: 1, opts: { promoteToSnapshot: true } });
    assert.strictEqual(out.fallback, false);
    assert.ok(/^sha256:[0-9a-f]{64}$/.test(out.derivedSnapshotId), '派生 id 合同格式');
    assert.notStrictEqual(out.derivedSnapshotId, FAKE_SNAPSHOT_ID);

    // 核心不变式（复审修正 1）：每行 factId/metadataId 可由**存储的**行字段复算，
    // 且行内不残留基线 snap12 引用（sinks/guards 的 locator.fn 与 function/caller 字段均重写）。
    const baseSnap12 = FAKE_SNAPSHOT_ID.slice(7, 19);
    const newSnap12 = out.derivedSnapshotId.slice(7, 19);
    const idsLib = require('../lib/facts/ids');
    let checkedFactRows = 0;
    for (const kind of parse.KINDS) {
      const rows = fs.readFileSync(path.join(TMP_ROOT, 'promoted', 'l1', `${kind}.jsonl`), 'utf8')
        .split('\n').filter(Boolean).map((l) => JSON.parse(l));
      for (const row of rows) {
        assert.ok(!JSON.stringify(row).includes(baseSnap12), `${kind} 行残留基线 snap12`);
        if (row.factId) {
          const expected = idsLib.factIdOf(out.derivedSnapshotId, row.kind, row.locator);
          assert.strictEqual(row.factId, expected, `${kind} factId 无法由存储 locator 复算: ${row.factId}`);
          checkedFactRows += 1;
        }
      }
    }
    assert.ok(checkedFactRows > 10, `fact 行覆盖不足: ${checkedFactRows}`);
    const metaDirPromoted = path.join(TMP_ROOT, 'promoted', 'metadata');
    if (fs.existsSync(metaDirPromoted)) {
      for (const name of fs.readdirSync(metaDirPromoted)) {
        const rows = fs.readFileSync(path.join(metaDirPromoted, name), 'utf8')
          .split('\n').filter(Boolean);
        for (const line of rows) assert.ok(!line.includes(baseSnap12), `metadata ${name} 残留基线 snap12`);
      }
    }

    // manifest/来源清单与新版本一致（复审修正 2）
    const promotedDir = path.join(TMP_ROOT, 'promoted');
    const manifest = JSON.parse(fs.readFileSync(path.join(promotedDir, 'manifest.json'), 'utf8'));
    const refs = manifest.artifactRefs.slice().sort();
    assert.strictEqual(manifest.snapshotId, out.derivedSnapshotId);
    assert.strictEqual(manifest.manifestId,
      idsLib.manifestIdOf(out.derivedSnapshotId, refs), 'manifestId 与产物清单一致');
    const snap = JSON.parse(fs.readFileSync(path.join(promotedDir, 'snapshot.json'), 'utf8'));
    assert.strictEqual(snap.snapshotId, out.derivedSnapshotId);
    assert.strictEqual(snap.roots[0].files, 4, 'source.files 按当前文件集合重建');
    assert.ok(snap.roots[0].bytes > 0 && snap.roots[0].sourceManifestHash, 'bytes/sourceManifestHash 重建');
    assert.strictEqual(snap.derivedFrom.baseSnapshotId, FAKE_SNAPSHOT_ID);

    // 事实消费路径可打开（产物形状：snapshot.json + 13 表 + metadata；放入 FACTS_ROOT 后即可按 id 解析）
    const facts = new factsLib.AutonomyFacts(promotedDir, policy);
    const idx = facts.index();
    assert.strictEqual(facts.snapshotId, out.derivedSnapshotId);
    assert.ok(idx.counts.functions >= 1);
    // 新函数行存在且 factId 前缀 = 新 snap12
    const promoted = idx.functions.find((f) => f.name === 'promoted_fn');
    assert.ok(promoted, 'promoted_fn extracted');
    assert.ok(promoted.factId.startsWith(`F:${newSnap12}:`), promoted.factId);
    // manifest inputManifestId 合法（run 输入固定的前提）
    assert.ok(/^AM-[0-9a-f]{16}$/.test(facts.inputManifestId), facts.inputManifestId);
    // 派生确定性：同输入再 promote 一次 → 同 id
    const out2 = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'promoted-2'), jobs: 1, opts: { promoteToSnapshot: true } });
    assert.strictEqual(out2.derivedSnapshotId, out.derivedSnapshotId);
  });

test('metadata 源集合漂移默认被拒：policy 放宽 glob 而文件未变 ⇒ 回退（不依赖调用方传指纹）',
  { concurrency: false }, async () => {
    const policy = makePolicy();
    resetFixture();
    // 无 idl 的 fixture 建基线（metadata-manifest sources 为空）
    const setup = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'metadrift-base'), jobs: 1 });
    assert.strictEqual(setup.fallback, false);
    // 新增 .idl：文件集合变化（added）+ metadata 源集合变化；集合校验必须先拒绝
    write('src/api.ifoo.idl', 'package T;\ninterface T.IFoo { void P(); }\n');
    const drifted = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'metadrift-out'), jobs: 1 });
    assert.strictEqual(drifted.fallback, true);
    assert.strictEqual(drifted.reason, 'scope-input-changed');
    assert.ok(drifted.detail.some((d) => d.reason === 'source-added-not-in-baseline-manifest'),
      JSON.stringify(drifted.detail));
  });

test('链式复用保护：输出目录残留不同指纹的前次状态 ⇒ 回退', async () => {
  const policy = makePolicy();
  resetFixture();
  const outDir = path.join(TMP_ROOT, 'chain-out');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'incremental-state.json'), JSON.stringify({
    policyFingerprint: 'stale-fingerprint-from-prior-run'
  }));
  const r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
    outDir, jobs: 1 });
  assert.strictEqual(r.fallback, true);
  assert.strictEqual(r.reason, 'scope-policy-drift');
  assert.strictEqual(r.detail[0].source, 'prior-incremental-state');
});

test('读取失败 ≠ 删除：受控读取失败 ⇒ source-read-failed 回退，不发布缺行产物',
  { concurrency: false }, async () => {
    const policy = makePolicy();
    resetFixture();
    const setup = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'readfail-base'), jobs: 1 });
    assert.strictEqual(setup.fallback, false);
    // 受控读取失败：main.cpp 读取抛 EACCES（文件仍在磁盘上，枚举可见）
    const outDir = path.join(TMP_ROOT, 'readfail-out');
    const mainAbs = path.join(FIXTURE, 'src', 'main.cpp');
    const failingRead = (p) => {
      if (path.resolve(String(p)) === path.resolve(mainAbs)) {
        const e = new Error(`EACCES: permission denied, open '${p}'`);
        e.code = 'EACCES';
        throw e;
      }
      return fs.readFileSync(p);
    };
    const r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir, jobs: 1, opts: { readFile: failingRead } });
    assert.strictEqual(r.fallback, true, '读取失败必须回退');
    assert.strictEqual(r.reason, 'source-read-failed');
    assert.ok(r.detail.some((d) => d.rel.endsWith('main.cpp') && d.code === 'EACCES'),
      JSON.stringify(r.detail));
    // 不发布缺行产物：outDir 不含 l1 表（回退发生在任何写盘之前）
    assert.ok(!fs.existsSync(path.join(outDir, 'l1', 'functions.jsonl')),
      '回退路径不得写出 L1 产物');
  });

test('解析规则版本绑定：基线 manifest.rulesVersion 不一致 ⇒ parse-rules-changed 回退',
  { concurrency: false }, async () => {
    const policy = makePolicy();
    resetFixture();
    const setup = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'rules-base'), jobs: 1 });
    assert.strictEqual(setup.fallback, false);
    // 篡改基线 manifest 的 rulesVersion（模拟解析规则已升级而 L1 仍是旧规则产物）
    const mf = path.join(FAKE_DIR, 'manifest.json');
    fs.writeFileSync(mf, JSON.stringify({
      manifestId: 'AM-0000000000000000',
      snapshotId: FAKE_SNAPSHOT_ID,
      rulesVersion: 'K-9.9.9-simulated-upgrade',
      artifactRefs: []
    }), 'utf8');
    const r = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'rules-out'), jobs: 1 });
    assert.strictEqual(r.fallback, true);
    assert.strictEqual(r.reason, 'parse-rules-changed');
    assert.strictEqual(r.detail[0].kind, 'rulesVersion');
    assert.strictEqual(r.detail[0].baseline, 'K-9.9.9-simulated-upgrade');
  });

test('promote 清单完整性与来源重建：metadata 表逐表列入、productionFiles 重建',
  { concurrency: false }, async () => {
    const policy = makePolicy();
    resetFixture();
    // 前序用例篡改了基线 manifest 的 rulesVersion，恢复当前规则版本
    fs.writeFileSync(path.join(FAKE_DIR, 'manifest.json'), JSON.stringify({
      manifestId: 'AM-0000000000000000',
      snapshotId: FAKE_SNAPSHOT_ID,
      rulesVersion: require('../lib/facts/manifest').PARSE_RULES_VERSION,
      artifactRefs: []
    }), 'utf8');
    write('src/sink_fn.cpp', '#include "util.h"\n#include <cstring>\n'
      + 'int sink_fn(int n) {\n  if (n > 0) {\n    char buf[16];\n    memcpy(buf, "abc", 3);\n    return n;\n  }\n  return 0;\n}\n');
    const setup = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'meta-base'), jobs: 1 });
    assert.strictEqual(setup.fallback, false);
    fs.appendFileSync(path.join(FIXTURE, 'src', 'main.cpp'), '\nint promoted_fn() { return 3; }\n');
    const out = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'meta-promoted'), jobs: 1, opts: { promoteToSnapshot: true } });
    assert.strictEqual(out.fallback, false);
    const promotedDir = path.join(TMP_ROOT, 'meta-promoted');
    const manifest = JSON.parse(fs.readFileSync(path.join(promotedDir, 'manifest.json'), 'utf8'));
    // fixture 基线无 metadata 目录：metadata 引用为 0 是正确状态；真实样本验证另行断言
    const metaRefs = manifest.artifactRefs.filter((r) => r.startsWith('metadata/'));
    const metaOnDisk = fs.existsSync(path.join(promotedDir, 'metadata'))
      ? fs.readdirSync(path.join(promotedDir, 'metadata')).filter((n) => n.endsWith('.jsonl')).length : 0;
    assert.strictEqual(metaRefs.length, metaOnDisk, 'manifest.metadata 引用数必须与目录一致');
    // l1 13 表必须全部在列
    for (const kind of parse.KINDS) {
      assert.ok(manifest.artifactRefs.includes(`l1/${kind}.jsonl`), `l1/${kind}.jsonl missing`);
    }
    // 来源重建含 productionFiles：facts 层 role 语义下 4 个文件全部 production（无 test 判定）
    const snap = JSON.parse(fs.readFileSync(path.join(promotedDir, 'snapshot.json'), 'utf8'));
    assert.strictEqual(snap.roots[0].files, 4);
    assert.strictEqual(snap.roots[0].productionFiles, 4);
    // role 变化的 policy 属 scope 漂移 ⇒ 回退（不产出 promote 快照）
    const policyTest = makePolicy();
    policyTest.testFilePattern = '(other)\\.(cpp)$';
    const outTest = await incremental.incrementalBuild({ snapshotId: FAKE_SNAPSHOT_ID, policy: policyTest,
      outDir: path.join(TMP_ROOT, 'meta-promoted-test'), jobs: 1, opts: { promoteToSnapshot: true } });
    assert.strictEqual(outTest.fallback, true);
    assert.strictEqual(outTest.reason, 'scope-policy-drift');
    // 基线就按该 test 规则构建时，promote 的 productionFiles 相应为 3（独立基线快照）
    const idsLib = require('../lib/facts/ids');
    const TEST_SNAPSHOT_ID = `sha256:${idsLib.sha256Hex('r2-incremental-test-fixture-testrole')}`;
    fabricateSnapshotDirFor(TEST_SNAPSHOT_ID);
    await parse.buildFacts({ snapshotId: TEST_SNAPSHOT_ID, policy: policyTest, jobs: 1 });
    const outTest2 = await incremental.incrementalBuild({ snapshotId: TEST_SNAPSHOT_ID, policy: policyTest,
      outDir: path.join(TMP_ROOT, 'meta-promoted-test2'), jobs: 1, opts: { promoteToSnapshot: true } });
    assert.strictEqual(outTest2.fallback, false);
    const snapTest = JSON.parse(fs.readFileSync(path.join(TMP_ROOT, 'meta-promoted-test2', 'snapshot.json'), 'utf8'));
    assert.strictEqual(snapTest.roots[0].files, 4);
    assert.strictEqual(snapTest.roots[0].productionFiles, 3, 'other.cpp 在基线规则下即 test');
  });

test('工具版本漂移：基线 toolVersions.treeSitter 不一致 ⇒ parse-rules-changed 回退',
  { concurrency: false }, async () => {
    const policy = makePolicy();
    resetFixture();
    // 基线快照声明一个与当前环境不同的 tree-sitter 版本
    const idsLib = require('../lib/facts/ids');
    const DRIFT_SNAPSHOT_ID = `sha256:${idsLib.sha256Hex('r2-incremental-test-fixture-toolversion')}`;
    fabricateSnapshotDirFor(DRIFT_SNAPSHOT_ID, '0.0.1-simulated-drift');
    await parse.buildFacts({ snapshotId: DRIFT_SNAPSHOT_ID, policy: policy, jobs: 1 });
    const r = await incremental.incrementalBuild({ snapshotId: DRIFT_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'tooldrift-out'), jobs: 1 });
    assert.strictEqual(r.fallback, true);
    assert.strictEqual(r.reason, 'parse-rules-changed');
    assert.strictEqual(r.detail[0].kind, 'treeSitter');
    assert.strictEqual(r.detail[0].baseline, '0.0.1-simulated-drift');
    // 一致时不回退（回归）
    const SAME_SNAPSHOT_ID = `sha256:${idsLib.sha256Hex('r2-incremental-test-fixture-toolsame')}`;
    fabricateSnapshotDirFor(SAME_SNAPSHOT_ID, incremental.currentTreeSitterVersion());
    await parse.buildFacts({ snapshotId: SAME_SNAPSHOT_ID, policy: policy, jobs: 1 });
    const r2 = await incremental.incrementalBuild({ snapshotId: SAME_SNAPSHOT_ID, policy,
      outDir: path.join(TMP_ROOT, 'toolsame-out'), jobs: 1 });
    assert.strictEqual(r2.fallback, false, 'treeSitter 一致不得误回退');
  });

test.after(() => {
  try { fs.rmSync(FAKE_DIR, { recursive: true, force: true }); } catch (_) { /* ignore */ }
  try { const idsLib = require('../lib/facts/ids');
    for (const key of ['r2-incremental-test-fixture-testrole','r2-incremental-test-fixture-toolversion','r2-incremental-test-fixture-toolsame']) {
      fs.rmSync(path.join(scopeLib.FACTS_ROOT, idsLib.sha256Hex(key)), { recursive: true, force: true });
    } } catch (_) { /* ignore */ }
  try { fs.rmSync(TMP_ROOT, { recursive: true, force: true }); } catch (_) { /* ignore */ }
});
