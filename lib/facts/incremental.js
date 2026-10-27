'use strict';

/**
 * lib/facts/incremental.js —— R2-C：按文件的事实层增量更新与失效模型。
 *
 * 失效模型（分层声明，全部默认生效，不依赖调用方传参）：
 *   - L1 解析事实：parse-worker 只读目标文件本身 ⇒ file-local（由构造证明，
 *     并由场景对照实证：头文件变更只改变头文件自身行，依赖方行与干净全量一致）。
 *   - metadata（idl/sa/permission/napi）：输入为按当前 policy 重新枚举的源文件集合，
 *     与基线 metadata-manifest 的 {rel, sha, kind} 集合比对（glob 收窄/放宽、源增删、
 *     内容修改都拒绝）；一致时才允许复制 metadata 层。
 *   - build/compdb 输入：build-manifest 登记的 compdb part sha256；变化 ⇒ 回退全量。
 *   - 解析规则/工具版本：基线 manifest.json.rulesVersion 与 PARSE_RULES_VERSION、
 *     基线 snapshot.toolVersions.treeSitter 与当前版本，不一致 ⇒ 回退全量。
 *   - include 边：增量运行时从源码提取（相对/父目录/根相对/范围内后缀匹配）；
 *     引号 include 无法解析 ⇒ dependency-unknown ⇒ 回退全量。
 *   - 文件读取失败：不当作删除，具名 readFailures ⇒ 回退全量（绝不发布缺行产物）。
 *   - 变更检测：逐文件读取并 sha256（可靠变更清单），不用 mtime/size 复用旧事实；
 *     role 与基线不一致（test 规则等 scope 变化）⇒ scope-policy-drift 回退。
 *   - 跨 run 指纹链：输出目录已有前次增量状态时比较 policyFingerprint；调用方也可
 *     显式传入 expectedFingerprint。
 *
 * promoteToSnapshot：输出升级为可被事实消费路径（AutonomyFacts / run 输入固定）识别
 * 的新版本快照——派生 id = sha256(基线 id + policy 指纹 + 全部文件版本 rel→{sha,bytes}
 * + PROMOTE_VERSION)；行内所有 F:/M: 引用重写并写回，factId 由写回后的 locator 重算；
 * snapshot.json 的 source 段按当前文件版本逐 root 重建（含 productionFiles），manifest.json
 * 以 manifestIdOf(derivedId, artifactRefs) 生成。修正 promote 语义时递增 PROMOTE_VERSION，
 * 新产物拿到新 id，不与已被 run 固定的旧派生快照冲突。
 *
 * 输出写入独立 outDir（不修改基线快照）。
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const io = require('./io');
const scope = require('./scope');
const parse = require('./parse');
const ids = require('./ids');
const manifestLib = require('./manifest');

// promote 产物身份版本：进入派生 id 计算。修正 promote 语义时递增。
const PROMOTE_VERSION = 'r2-incremental-promoted-v2';

const INCLUDE_RE = /^[ \t]*#[ \t]*include[ \t]*(<([^>]+)>|"([^"]+)")/gm;

/** 当前解析工具版本（与 bin/fact-snapshot.toolVersions 同源；L1 内容依赖 tree-sitter） */
function currentTreeSitterVersion() {
  const mods = path.join(scope.WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
  try {
    return JSON.parse(fs.readFileSync(path.join(mods, 'tree-sitter', 'package.json'), 'utf8')).version || null;
  } catch (_) { return null; }
}

function sha256Buf(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function countLines(buf) {
  let n = 0;
  for (let i = 0; i < buf.length; i += 1) if (buf[i] === 0x0a) n += 1;
  if (buf.length > 0 && buf[buf.length - 1] !== 0x0a) n += 1;
  return n;
}

/** 从源码文本提取 #include 指令：{spec, kind: 'quoted'|'angle', line} */
function extractIncludes(text) {
  const out = [];
  let m;
  INCLUDE_RE.lastIndex = 0;
  while ((m = INCLUDE_RE.exec(text)) !== null) {
    const spec = m[2] || m[3];
    if (!spec) continue;
    out.push({ spec, kind: m[2] ? 'angle' : 'quoted', line: countLines(Buffer.from(text.slice(0, m.index))) + 1 });
  }
  return out;
}

/**
 * 在范围内解析 include：
 *   1) 相对 includer 目录与父目录（"../x.h"）；
 *   2) 各 root 相对路径（root/spec）；
 *   3) 范围内路径后缀匹配（.../spec 结尾，evidence 可定位）。
 * 返回 {status:'in-scope', rel} | {status:'no-match'}；尖括号/引号语义由调用方判定。
 */
function resolveInclude(spec, includerRel, targetSet, roots) {
  const includerDir = includerRel.includes('/') ? includerRel.slice(0, includerRel.lastIndexOf('/')) : '';
  const specNorm = spec.split('\\').join('/');
  const candidates = [];
  if (includerDir) candidates.push(`${includerDir}/${specNorm}`);
  const upMatch = /^\.\.\/(.*)$/.exec(specNorm);
  if (upMatch) {
    const parent = includerDir.includes('/') ? includerDir.slice(0, includerDir.lastIndexOf('/')) : '';
    candidates.push(`${parent}/${upMatch[1]}`);
  }
  for (const root of roots) candidates.push(`${root}/${specNorm}`);
  for (const cand of candidates) {
    if (targetSet.has(cand)) return { status: 'in-scope', rel: cand };
  }
  for (const t of targetSet) {
    if (t.endsWith(`/${specNorm}`)) return { status: 'in-scope', rel: t, by: 'suffix-match' };
  }
  return { status: 'no-match' };
}

function fileOf(row) {
  return (row.locator && row.locator.file) || (row.sourceRange && row.sourceRange.file)
    || row.file || row.path || null;
}

function tableKey(kind) {
  return kind === 'files' ? (r) => r.path : kind === 'quality' ? (r) => r.id : (r) => r.factId || r.id;
}

function readRows(file) {
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try { rows.push(JSON.parse(line)); } catch (_) { /* 坏行跳过（与 parse.readShard 一致） */ }
  }
  return rows;
}

/** 指纹：scope 级输入（policy 关键字段），用于跨 run 复用前的配置绑定检查 */
function policyFingerprint(policy) {
  const doc = {
    snapshotScope: policy.snapshotScope || null,
    roots: policy.roots,
    sourceExtensions: policy.sourceExtensions,
    testPathPattern: policy.testPathPattern || null,
    testFilePattern: policy.testFilePattern || null,
    limits: policy.limits || null,
    metadataSources: (policy.metadataSources || []).map((s) => ({ kind: s.kind, scope: s.scope, glob: s.glob || null, file: s.file || null }))
  };
  return { sha256: ids.sha256Hex(JSON.stringify(doc)), doc };
}

/**
 * scope 级输入检查（默认全开，不依赖调用方传参）：
 *  1) metadata 源集合：按当前 policy 重新枚举（scope.metadataSources）并与基线
 *     metadata-manifest 的 {rel, sha, kind} 集合比对——glob 收窄/放宽、源增删、内容修改都捕获；
 *  2) compdb part：build-manifest 登记的 sha256 逐一比对（构建输入漂移 ⇒ 回退全量）。
 */
function checkScopeInputs(policy, snapshotDir) {
  const problems = [];
  const metaManifest = JSON.parse(fs.readFileSync(path.join(snapshotDir, 'metadata-manifest.json'), 'utf8'));
  const baseSet = new Map();
  for (const s of metaManifest.sources || []) baseSet.set(s.rel, s);

  const current = [];
  for (const s of scope.metadataSources(policy)) {
    if (!fs.existsSync(s.abs)) { problems.push({ kind: 'metadata', rel: s.rel, reason: 'missing' }); continue; }
    const sha = ids.sha256File(s.abs);
    current.push({ kind: s.kind, scope: s.scope, rel: s.rel, sha256: sha });
  }
  const currentSet = new Map(current.map((s) => [s.rel, s]));
  for (const s of current) {
    const base = baseSet.get(s.rel);
    if (!base) problems.push({ kind: 'metadata', rel: s.rel, reason: 'source-added-not-in-baseline-manifest' });
    else if (base.sha256 !== s.sha256) problems.push({ kind: 'metadata', rel: s.rel, reason: 'sha-mismatch' });
    else if (base.kind !== s.kind) problems.push({ kind: 'metadata', rel: s.rel, reason: 'kind-changed' });
  }
  for (const [rel] of baseSet) {
    if (!currentSet.has(rel)) problems.push({ kind: 'metadata', rel, reason: 'source-removed-from-policy-scope' });
  }

  const buildManifest = JSON.parse(fs.readFileSync(path.join(snapshotDir, 'build-manifest.json'), 'utf8'));
  for (const part of buildManifest.parts || []) {
    if (!part.present || !part.file) continue;
    const abs = path.join(scope.SRC_ROOT, part.file.split('/').join(path.sep));
    if (!fs.existsSync(abs)) { problems.push({ kind: 'compdb', rel: part.file, reason: 'missing' }); continue; }
    const sha = ids.sha256File(abs);
    if (sha !== part.sha256) problems.push({ kind: 'compdb', rel: part.file, reason: 'sha-mismatch' });
  }
  return problems;
}

/**
 * 变更检测：逐文件读取 + sha256（可靠变更清单），并提取 include 图。
 * 读取失败不当作删除：进入 readFailures，由调用方回退全量（不发布缺行产物）。
 * opts.readFile 可注入（受控失败测试）；生产路径为 fs.readFileSync。
 * @returns {{targets:number, unchanged:string[], changed:[], added:[], deleted:[],
 *            readFailures:[], includeEdges:number, includeUnknown:number,
 *            readBytes:number, includeRows:[], fileVersions:Map, roleMismatches:[],
 *            unresolvedQuoted:number}}
 */
function diffAgainstSnapshot(policy, snapshotDir, opts = {}) {
  const readFile = opts.readFile || ((p) => fs.readFileSync(p));
  const baseRows = readRows(path.join(snapshotDir, 'l1', 'files.jsonl'));
  const base = new Map();
  for (const row of baseRows) base.set(row.path, row);

  const roots = policy.roots.map((r) => r.root);
  const targetSet = new Set();
  const list = parse.targets(policy);
  for (const t of list) targetSet.add(t.rel);

  const unchanged = [];
  const changed = [];
  const added = [];
  const deleted = [];
  const readFailures = [];
  const includeRows = [];
  const fileVersions = new Map();
  const roleMismatches = [];
  let readBytes = 0;
  let includeEdges = 0;
  let includeUnknown = 0;

  for (const t of list) {
    let buf;
    try { buf = readFile(t.abs); } catch (e) {
      // 读取失败 ≠ 文件删除：状态无法判明 ⇒ 具名失败，由调用方回退全量，
      // 不得移除旧事实生成看似有效的快照。
      readFailures.push({ rel: t.rel, code: e.code || 'unknown' });
      continue;
    }
    if (typeof buf === 'string') buf = Buffer.from(buf, 'utf8');
    readBytes += buf.length;
    const sha = sha256Buf(buf);
    fileVersions.set(t.rel, { sha256: sha, bytes: buf.length, role: t.role });
    const prev = base.get(t.rel);
    // scope-only 漂移检测：文件字节未变但基线 role 与当前 policy 判定不一致
    // （test 路径/文件名规则变化等）⇒ 不得沿用旧事实。
    if (prev && prev.role && t.role && prev.role !== t.role) {
      roleMismatches.push({ rel: t.rel, baseRole: prev.role, currentRole: t.role });
    }
    if (prev && prev.sha256 === sha) {
      unchanged.push(t.rel);
    } else if (prev) {
      changed.push({ rel: t.rel, oldSha256: prev.sha256, newSha256: sha, bytes: buf.length, buffer: buf });
    } else {
      added.push({ rel: t.rel, newSha256: sha, bytes: buf.length, buffer: buf });
    }
    const text = buf.toString('utf8');
    for (const inc of extractIncludes(text)) {
      const match = inc.kind === 'angle' ? { status: 'no-match' } : resolveInclude(inc.spec, t.rel, targetSet, roots);
      let status;
      if (match.status === 'in-scope') status = 'in-scope';
      else status = inc.kind === 'angle' ? 'external' : 'unresolved';
      if (status === 'in-scope') includeEdges += 1;
      else if (status === 'unresolved') includeUnknown += 1;
      includeRows.push({ file: t.rel, spec: inc.spec, kind: inc.kind, line: inc.line,
        status, resolved: match.rel || null, by: match.by || null });
    }
  }
  const seen = new Set(list.map((t) => t.rel));
  for (const [rel] of base) {
    if (!seen.has(rel)) deleted.push({ rel, reason: 'not-on-disk' });
  }

  return {
    targets: list.length, unchanged, changed, added, deleted, readFailures,
    includeEdges, includeUnknown, includeRows, readBytes,
    fileVersions, roleMismatches,
    unresolvedQuoted: includeRows.filter((r) => r.kind === 'quoted' && r.status === 'unresolved').length
  };
}

function runWorkerBatch(policy, snapshotId, files) {
  return new Promise((resolve, reject) => {
    const shardDir = path.join(scope.TOOL_DIR, 'runtime', 'tmp', `incr-${process.pid}-${Date.now()}`);
    fs.rmSync(shardDir, { recursive: true, force: true });
    fs.mkdirSync(shardDir, { recursive: true });
    const child = require('node:child_process').fork(path.join(__dirname, 'parse-worker.js'), [],
      { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    let counts = null;
    child.on('message', (msg) => { if (msg && msg.type === 'done') counts = msg.counts; });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0 || !counts) return reject(new Error(`worker-exit-${code}`));
      const rows = Object.fromEntries(parse.KINDS.map((kind) => [kind, readRows(path.join(shardDir, `${kind}.jsonl`))]));
      rows.unsupported = readRows(path.join(shardDir, 'unsupported.jsonl'));
      resolve({ rows, counts, shardDir, files: files.length });
    });
    child.send({ shardDir, snapshotId, files });
  });
}

function summarizeDiff(diff) {
  return {
    targets: diff.targets,
    unchanged: diff.unchanged.length,
    changed: diff.changed.map((x) => x.rel),
    added: diff.added.map((x) => x.rel),
    deleted: diff.deleted.map((x) => x.rel)
  };
}

/**
 * 增量构建：以既有快照为基线，把 L1/unsupported 更新到当前磁盘状态。
 * 只写 outDir，不修改基线快照。任何失效判据失败 ⇒ {fallback:true, reason}，
 * 在写盘之前返回（不发布缺行/陈旧产物）。
 */
async function incrementalBuild({ snapshotId, policy, outDir, jobs = 2, opts = {} }) {
  const t0 = Date.now();
  const onUnknownDependency = opts.onUnknownDependency || 'fallback-full';
  const hex = String(snapshotId).replace(/^sha256:/, '');
  const snapshotDir = path.join(scope.FACTS_ROOT, hex);
  if (!fs.existsSync(path.join(snapshotDir, 'l1'))) {
    throw new Error(`snapshot-l1-missing: ${snapshotId}`);
  }
  io.ensureDir(outDir);

  const fingerprint = policyFingerprint(policy);

  // ---- scope 级输入（metadata 源集合 / compdb）----
  const scopeInputProblems = checkScopeInputs(policy, snapshotDir);
  if (scopeInputProblems.length) {
    return {
      fallback: true,
      reason: 'scope-input-changed',
      detail: scopeInputProblems.slice(0, 20),
      reparseFiles: 0,
      elapsedMs: Date.now() - t0,
      policyFingerprint: fingerprint.sha256
    };
  }

  // ---- 跨 run 指纹链：默认绑定 —— 输出目录已有前次增量状态时必须同指纹 ----
  const priorStateFile = path.join(outDir, 'incremental-state.json');
  if (fs.existsSync(priorStateFile)) {
    try {
      const prior = JSON.parse(fs.readFileSync(priorStateFile, 'utf8'));
      if (prior.policyFingerprint && prior.policyFingerprint !== fingerprint.sha256) {
        return {
          fallback: true,
          reason: 'scope-policy-drift',
          detail: [{ kind: 'policy-fingerprint', source: 'prior-incremental-state',
            expected: prior.policyFingerprint, actual: fingerprint.sha256 }],
          reparseFiles: 0,
          elapsedMs: Date.now() - t0,
          policyFingerprint: fingerprint.sha256
        };
      }
    } catch (_) { /* 坏状态文件不阻塞，按无前次处理 */ }
  }
  // 调用方显式传入期望指纹时同样强制（显式约束优先）
  if (opts.expectedFingerprint && opts.expectedFingerprint !== fingerprint.sha256) {
    return {
      fallback: true,
      reason: 'scope-policy-drift',
      detail: [{ kind: 'policy-fingerprint', expected: opts.expectedFingerprint, actual: fingerprint.sha256 }],
      reparseFiles: 0,
      elapsedMs: Date.now() - t0,
      policyFingerprint: fingerprint.sha256
    };
  }

  // ---- 文件级 diff（含 include 提取；这是主要读成本）----
  const diff = diffAgainstSnapshot(policy, snapshotDir, { readFile: opts.readFile });
  const changeCount = diff.changed.length + diff.added.length + diff.deleted.length;

  // ---- 读取失败：状态无法判明 ⇒ 具名回退，绝不发布缺行产物 ----
  if (diff.readFailures.length > 0) {
    return {
      fallback: true,
      reason: 'source-read-failed',
      detail: diff.readFailures.slice(0, 20),
      reparseFiles: 0,
      diffSummary: summarizeDiff(diff),
      elapsedMs: Date.now() - t0,
      policyFingerprint: fingerprint.sha256
    };
  }

  // ---- 解析规则/工具版本绑定（默认比较基线 manifest 与快照 toolVersions）----
  {
    const baseManifestFile = path.join(snapshotDir, 'manifest.json');
    if (fs.existsSync(baseManifestFile)) {
      const baseManifest = JSON.parse(fs.readFileSync(baseManifestFile, 'utf8'));
      if (baseManifest.rulesVersion && baseManifest.rulesVersion !== manifestLib.rulesVersionFor(policy)) {
        return {
          fallback: true,
          reason: 'parse-rules-changed',
          detail: [{ kind: 'rulesVersion', baseline: baseManifest.rulesVersion, current: manifestLib.rulesVersionFor(policy) }],
          reparseFiles: 0,
          elapsedMs: Date.now() - t0,
          policyFingerprint: fingerprint.sha256
        };
      }
    }
    // 正式快照把工具版本写在 snapshot.toolVersions（不是 payload.tools）
    const baseSnapDocForTools = JSON.parse(fs.readFileSync(path.join(snapshotDir, 'snapshot.json'), 'utf8'));
    const baseTools = baseSnapDocForTools.toolVersions || {};
    const currentTreeSitter = currentTreeSitterVersion();
    if (baseTools.treeSitter && currentTreeSitter && baseTools.treeSitter !== currentTreeSitter) {
      return {
        fallback: true,
        reason: 'parse-rules-changed',
        detail: [{ kind: 'treeSitter', baseline: baseTools.treeSitter, current: currentTreeSitter }],
        reparseFiles: 0,
        elapsedMs: Date.now() - t0,
        policyFingerprint: fingerprint.sha256
      };
    }
  }

  // ---- include 依赖失效判定 ----
  const changedRels = new Set([...diff.changed, ...diff.added].map((x) => x.rel));
  const quotedUnresolvedInChanged = diff.includeRows
    .filter((r) => r.kind === 'quoted' && r.status === 'unresolved' && changedRels.has(r.file));
  if (onUnknownDependency === 'fallback-full' && quotedUnresolvedInChanged.length > 0) {
    return {
      fallback: true,
      reason: 'dependency-unknown',
      detail: quotedUnresolvedInChanged.slice(0, 20).map((r) => ({ file: r.file, spec: r.spec, line: r.line })),
      unknownIncludeCount: quotedUnresolvedInChanged.length,
      reparseFiles: 0,
      diffSummary: summarizeDiff(diff),
      elapsedMs: Date.now() - t0,
      policyFingerprint: fingerprint.sha256
    };
  }

  // ---- scope-only 漂移：文件字节未变但 role 判定变化（test 规则等）⇒ 回退全量 ----
  if (diff.roleMismatches.length > 0) {
    return {
      fallback: true,
      reason: 'scope-policy-drift',
      detail: diff.roleMismatches.slice(0, 20),
      reparseFiles: 0,
      diffSummary: summarizeDiff(diff),
      elapsedMs: Date.now() - t0,
      policyFingerprint: fingerprint.sha256
    };
  }

  // ---- 未变更快速路径：零改动 ⇒ 整体复制基线（不做 13 表逐行拼接、不重解析）----
  if (changeCount === 0) {
    fs.cpSync(path.join(snapshotDir, 'l1'), path.join(outDir, 'l1'), { recursive: true });
    if (fs.existsSync(path.join(snapshotDir, 'unsupported.jsonl'))) {
      fs.copyFileSync(path.join(snapshotDir, 'unsupported.jsonl'), path.join(outDir, 'unsupported.jsonl'));
    }
    if (fs.existsSync(path.join(snapshotDir, 'metadata'))) {
      fs.cpSync(path.join(snapshotDir, 'metadata'), path.join(outDir, 'metadata'), { recursive: true });
    }
    io.writeJsonl(path.join(outDir, 'includes.jsonl'),
      diff.includeRows.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line)),
      { key: (r) => `${r.file}:${r.line}:${r.spec}` });
    const tPromoteFast = Date.now();
    let fastDerivedId = null;
    if (opts.promoteToSnapshot) {
      // 快速路径同样支持 promote：复制的表按派生 id 重写（引用重写 + factId 重算 + manifest/来源重建）
      fastDerivedId = `sha256:${ids.sha256Hex(JSON.stringify({
        base: snapshotId, policy: fingerprint.sha256, promoteVersion: PROMOTE_VERSION,
        files: [...diff.fileVersions.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
          .map(([rel, v]) => [rel, v.sha256, v.bytes])
      }))}`;
      promoteRows(outDir, { baseSnapshotId: snapshotId, derivedSnapshotId: fastDerivedId, policy, diff });
    } else {
      fs.copyFileSync(path.join(snapshotDir, 'snapshot.json'), path.join(outDir, 'snapshot.json'));
    }
    const state = {
      stateVersion: 'r2-incremental-state-v1',
      baseSnapshotId: snapshotId,
      policyFingerprint: fingerprint.sha256,
      fastPath: 'unchanged-copied',
      diff: summarizeDiff(diff),
      reparse: { workers: 0, files: 0 },
      promote: { enabled: !!opts.promoteToSnapshot, derivedSnapshotId: fastDerivedId,
        promoteMs: Date.now() - tPromoteFast },
      include: { edges: diff.includeEdges, unknown: diff.includeUnknown, quotedUnresolvedInChanged: 0 },
      costs: { hashPassReadBytes: diff.readBytes, spliceReadBytes: 0, spliceWriteBytes: 0,
        reparseFiles: 0, promoteMs: Date.now() - tPromoteFast, elapsedMs: Date.now() - t0 }
    };
    io.writeJson(path.join(outDir, 'incremental-state.json'), state);
    return {
      fallback: false,
      unchangedOnly: true,
      diffSummary: summarizeDiff(diff),
      reparseFiles: 0,
      spliceStats: {},
      outDir,
      derivedSnapshotId: fastDerivedId,
      costs: state.costs,
      elapsedMs: Date.now() - t0,
      policyFingerprint: fingerprint.sha256
    };
  }

  // ---- 目标重解析（changed + added；deleted 不解析）----
  const reparsed = [];
  const parsedRows = Object.fromEntries([...parse.KINDS, 'unsupported'].map((k) => [k, []]));
  if (changeCount > 0) {
    const targetsByRel = new Map(parse.targets(policy).map((t) => [t.rel, t]));
    const batch = [];
    for (const item of [...diff.changed, ...diff.added]) {
      const t = targetsByRel.get(item.rel);
      if (!t) continue;
      batch.push({ abs: t.abs, rel: t.rel, repo: t.repo, role: t.role, language: t.language });
    }
    const groups = [];
    const perWorker = Math.max(1, Math.ceil(batch.length / Math.max(1, Math.min(jobs, batch.length || 1))));
    for (let i = 0; i < batch.length; i += perWorker) groups.push(batch.slice(i, i + perWorker));
    for (const group of groups) {
      const res = await runWorkerBatch(policy, snapshotId, group);
      for (const kind of [...parse.KINDS, 'unsupported']) parsedRows[kind].push(...res.rows[kind]);
      reparsed.push({ files: group.length, counts: res.counts });
      try { io.removeDir(res.shardDir); } catch (_) { /* ignore */ }
    }
  }

  // ---- L1 拼接：基线行去掉 changed/deleted，合入新行（保持键排序）----
  const affected = new Set([...diff.changed, ...diff.added, ...diff.deleted].map((x) => x.rel));
  const spliceStats = {};
  const l1Out = path.join(outDir, 'l1');
  io.ensureDir(l1Out);
  let spliceReadBytes = 0;
  let spliceWriteBytes = 0;
  for (const kind of parse.KINDS) {
    const srcFile = path.join(snapshotDir, 'l1', `${kind}.jsonl`);
    const srcRows = readRows(srcFile);
    spliceReadBytes += fs.existsSync(srcFile) ? fs.statSync(srcFile).size : 0;
    const kept = srcRows.filter((row) => {
      const f = fileOf(row);
      return !f || !affected.has(f);
    });
    const merged = [...kept, ...parsedRows[kind]];
    const key = tableKey(kind);
    merged.sort((a, b) => {
      const ka = key(a) || '';
      const kb = key(b) || '';
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    const dstFile = path.join(l1Out, `${kind}.jsonl`);
    io.writeJsonl(dstFile, merged, { key });
    spliceWriteBytes += fs.statSync(dstFile).size;
    spliceStats[kind] = { baseRows: srcRows.length, keptRows: kept.length, newRows: parsedRows[kind].length, outRows: merged.length };
  }
  {
    const srcFile = path.join(snapshotDir, 'unsupported.jsonl');
    const srcRows = readRows(srcFile);
    spliceReadBytes += fs.existsSync(srcFile) ? fs.statSync(srcFile).size : 0;
    const kept = srcRows.filter((row) => {
      const f = fileOf(row);
      return !f || !affected.has(f);
    });
    const merged = [...kept, ...parsedRows.unsupported];
    const key = (r) => r.id;
    merged.sort((a, b) => {
      const ka = key(a) || '';
      const kb = key(b) || '';
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    const dstFile = path.join(outDir, 'unsupported.jsonl');
    io.writeJsonl(dstFile, merged, { key });
    spliceWriteBytes += fs.statSync(dstFile).size;
    spliceStats.unsupported = { baseRows: srcRows.length, keptRows: kept.length, newRows: parsedRows.unsupported.length, outRows: merged.length };
  }

  // ---- metadata：源集合一致 ⇒ 原样复制（不一致已在上方回退）----
  if (fs.existsSync(path.join(snapshotDir, 'metadata'))) {
    fs.cpSync(path.join(snapshotDir, 'metadata'), path.join(outDir, 'metadata'), { recursive: true });
  }

  // ---- include 图产物 ----
  io.writeJsonl(path.join(outDir, 'includes.jsonl'), diff.includeRows.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line)),
    { key: (r) => `${r.file}:${r.line}:${r.spec}` });

  // ---- 派生快照身份（promote 模式）：id 由 基线 id + policy 指纹 + 全部文件版本 决定 ----
  let derivedSnapshotId = null;
  let promoteMs = 0;
  if (opts.promoteToSnapshot) {
    const tPromote = Date.now();
    derivedSnapshotId = `sha256:${ids.sha256Hex(JSON.stringify({
      base: snapshotId, policy: fingerprint.sha256, promoteVersion: PROMOTE_VERSION,
      files: [...diff.fileVersions.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
        .map(([rel, v]) => [rel, v.sha256, v.bytes])
    }))}`;
    promoteRows(outDir, { baseSnapshotId: snapshotId, derivedSnapshotId, policy, diff });
    promoteMs = Date.now() - tPromote;
  } else {
    fs.copyFileSync(path.join(snapshotDir, 'snapshot.json'), path.join(outDir, 'snapshot.json'));
  }

  const state = {
    stateVersion: 'r2-incremental-state-v1',
    baseSnapshotId: snapshotId,
    policyFingerprint: fingerprint.sha256,
    diff: summarizeDiff(diff),
    reparse: { workers: reparsed.length, files: reparsed.reduce((a, r) => a + r.files, 0) },
    spliceStats,
    promote: { enabled: !!opts.promoteToSnapshot, derivedSnapshotId, promoteMs },
    include: { edges: diff.includeEdges, unknown: diff.includeUnknown, quotedUnresolvedInChanged: quotedUnresolvedInChanged.length },
    dependencyModel: {
      l1: 'file-local（parse-worker 只读目标文件；由场景对照实证）',
      metadata: 'metadata 源集合 + 逐文件 sha256（默认比对）',
      build: 'build-manifest compdb part sha256，变化回退全量',
      parseRules: 'manifest.rulesVersion + toolVersions.treeSitter（默认比对）',
      quotedUnresolvedPolicy: onUnknownDependency
    },
    costs: {
      hashPassReadBytes: diff.readBytes,
      spliceReadBytes,
      spliceWriteBytes,
      reparseFiles: reparsed.reduce((a, r) => a + r.files, 0),
      promoteMs,
      elapsedMs: Date.now() - t0
    }
  };
  io.writeJson(path.join(outDir, 'incremental-state.json'), state);

  return {
    fallback: false,
    unchangedOnly: changeCount === 0,
    diffSummary: summarizeDiff(diff),
    reparseFiles: reparsed.reduce((a, r) => a + r.files, 0),
    spliceStats,
    outDir,
    derivedSnapshotId,
    costs: state.costs,
    elapsedMs: Date.now() - t0,
    policyFingerprint: fingerprint.sha256
  };
}

/**
 * promote：把增量输出升级为可被事实消费路径（AutonomyFacts / run 输入固定）识别的
 * 新版本快照。派生 id = sha256(基线 id + policy 指纹 + 全部文件版本 rel→{sha,bytes}
 * + PROMOTE_VERSION)。
 *
 * 一致性要求（复审修正）：
 *  1) 行内所有 F:/M: 引用（locator.fn、function、caller 等）先做 snap12 前缀重写
 *     并**写回行**，factId 再由写回后的 locator 整体重算——保证
 *     factId === factIdOf(derivedId, row.kind, 存储的 locator) 可复算；
 *  2) snapshot.json 的 source 清单按当前文件版本逐 root 重建（files/productionFiles/
 *     bytes/sourceManifestHash 与 scope.enumerateRoot 同式），manifest.json 以
 *     manifestIdOf(derivedId, artifactRefs) 生成——作为 run 固定输入时 inputManifestId 合法；
 *  3) build-manifest/metadata-manifest/compdb-win 从基线复制并重写 snapshotId。
 */
function promoteRows(outDir, { baseSnapshotId, derivedSnapshotId, policy, diff }) {
  const baseSnap12 = baseSnapshotId.replace(/^sha256:/, '').slice(0, 12);
  const newSnap12 = derivedSnapshotId.replace(/^sha256:/, '').slice(0, 12);
  const rewriteRefs = (value) => {
    if (typeof value === 'string') {
      return value.split(`F:${baseSnap12}:`).join(`F:${newSnap12}:`)
        .split(`M:${baseSnap12}:`).join(`M:${newSnap12}:`);
    }
    if (Array.isArray(value)) return value.map(rewriteRefs);
    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = rewriteRefs(v);
      return out;
    }
    return value;
  };

  const artifactRefs = ['snapshot.json', 'manifest.json', 'unsupported.jsonl', 'compdb-win.jsonl',
    'build-manifest.json', 'metadata-manifest.json', 'includes.jsonl',
    ...parse.KINDS.map((k) => `l1/${k}.jsonl`)];
  // metadata 表是消费输入，必须逐表列入清单（存在才列）
  const metaDirForRefs = path.join(outDir, 'metadata');
  if (fs.existsSync(metaDirForRefs)) {
    for (const name of fs.readdirSync(metaDirForRefs)) {
      if (name.endsWith('.jsonl')) artifactRefs.push(`metadata/${name}`);
    }
  }

  for (const kind of parse.KINDS) {
    const file = path.join(outDir, 'l1', `${kind}.jsonl`);
    const rows = readRows(file);
    for (const row of rows) {
      const rewritten = rewriteRefs(row);
      rewritten.snapshotId = derivedSnapshotId;
      if (rewritten.factId) {
        rewritten.factId = ids.factIdOf(derivedSnapshotId, rewritten.kind || kind, rewritten.locator || {});
      }
      // 原地替换：rewritten 的 locator/引用字段已持久化，factId 可由存储行复算
      for (const k of Object.keys(row)) delete row[k];
      Object.assign(row, rewritten);
    }
    const key = tableKey(kind);
    rows.sort((a, b) => {
      const ka = key(a) || '';
      const kb = key(b) || '';
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    io.writeJsonl(file, rows, { key });
  }

  // metadata 行：locator 不含 snapshot 引用，metadataId 稳定段只做前缀替换
  const metaDir = path.join(outDir, 'metadata');
  if (fs.existsSync(metaDir)) {
    for (const name of fs.readdirSync(metaDir)) {
      if (!name.endsWith('.jsonl')) continue;
      const file = path.join(metaDir, name);
      const rows = readRows(file);
      for (const row of rows) {
        row.snapshotId = derivedSnapshotId;
        if (row.metadataId) {
          row.metadataId = String(row.metadataId).replace(`M:${baseSnap12}:`, `M:${newSnap12}:`);
        }
      }
      io.writeJsonl(file, rows, { key: (r) => r.metadataId || r.id });
    }
  }

  // compdb-win / build-manifest / metadata-manifest：从基线复制并重写 snapshotId
  const baseDir = path.join(scope.FACTS_ROOT, baseSnapshotId.replace(/^sha256:/, ''));
  for (const rel of ['compdb-win.jsonl', 'build-manifest.json', 'metadata-manifest.json']) {
    const src = path.join(baseDir, rel);
    if (!fs.existsSync(src)) continue;
    if (rel.endsWith('.jsonl')) {
      io.writeJsonl(path.join(outDir, rel), readRows(src), { key: (r) => r.id });
    } else {
      const doc = JSON.parse(fs.readFileSync(src, 'utf8'));
      doc.snapshotId = derivedSnapshotId;
      io.writeJson(path.join(outDir, rel), doc);
    }
  }

  // snapshot.json：source 清单按当前文件版本逐 root 重建（与 enumerateRoot 同式）
  const baseSnapDoc = JSON.parse(fs.readFileSync(path.join(baseDir, 'snapshot.json'), 'utf8'));
  const rootRows = policy.roots.map((r) => {
    const prefix = `${r.root}/`;
    const rels = [...diff.fileVersions.keys()].filter((rel) => rel.startsWith(prefix));
    let bytes = 0;
    let productionFiles = 0;
    const manifestRows = rels.map((rel) => {
      const v = diff.fileVersions.get(rel);
      bytes += v.bytes;
      if (v.role === 'production') productionFiles += 1;
      return `${rel}\u0000${v.sha256}\u0000${v.bytes}`;
    });
    const g = scope.gitState(r.root);
    return {
      root: r.root, repo: r.root, part: r.part,
      head: g.head, dirty: g.dirty, dirtyEntries: g.dirtyEntries,
      files: manifestRows.length, productionFiles, bytes,
      sourceManifestHash: ids.sha256Hex(manifestRows.join('\n'))
    };
  });
  io.writeJson(path.join(outDir, 'snapshot.json'), {
    ...baseSnapDoc,
    snapshotId: derivedSnapshotId,
    scope: policy.snapshotScope || baseSnapDoc.scope,
    roots: rootRows,
    workingTreeDirty: rootRows.some((r) => r.dirty),
    derivedFrom: { baseSnapshotId, kind: PROMOTE_VERSION }
  });

  // manifest.json：manifestId 与产物清单一致（作为 run 固定输入的前提）
  io.writeJson(path.join(outDir, 'manifest.json'), {
    manifestId: ids.manifestIdOf(derivedSnapshotId, artifactRefs.sort()),
    snapshotId: derivedSnapshotId,
    factSchemaVersion: '1',
    rulesVersion: manifestLib.rulesVersionFor(policy),
    obligationVersion: null,
    l6IndexVersion: null,
    verificationRunId: null,
    reportVersion: null,
    createdAt: new Date().toISOString(),
    producer: 'AG0',
    artifactRefs
  });
}

module.exports = {
  incrementalBuild, diffAgainstSnapshot, extractIncludes, resolveInclude,
  policyFingerprint, checkScopeInputs, promoteRows, currentTreeSitterVersion,
  fileOf, tableKey, summarizeDiff, PROMOTE_VERSION
};
