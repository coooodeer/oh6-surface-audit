'use strict';

/**
 * tools/autonomy-r2-scenarios.js —— R2-C/E：受控副本上的多文件增量场景与干净全量对照。
 *
 * 结构：每个样本一个共享受控副本（out/autonomy/incremental/r2/<sample>-r2inc/work，
 * ipc 另加 hilog 副本根以覆盖真实跨组件 include 边）。基线快照建在副本上；
 * 每个场景重置副本 → 变更 → 增量（或按失效策略回退全量）→ 相同最终文件集合上的
 * 干净全量构建 → fact-compare 逐表对照（身份字段按合同归一化）。
 *
 * 场景：unchanged / modified / same-size-same-mtime / added / deleted /
 *       same-component-header / include-removed / metadata-source-change；
 * ipc 专有：cross-component-header、quoted-unresolved-fallback。
 *
 * 用法：node tools/autonomy-r2-scenarios.js --sample=access-token [--scenarios=a,b] [--out=<file>]
 */

const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');

const scopeLib = require('../lib/facts/scope');
const parseLib = require('../lib/facts/parse');
const incremental = require('../lib/facts/incremental');

const TOOL_DIR = path.resolve(__dirname, '..');
const SRC_ROOT = scopeLib.SRC_ROOT;
// 工作副本放仓库外（<workspace>/r2-work）：不进 node --test 发现范围，不污染审计仓 git 状态
const WORKSPACE_ROOT = path.resolve(TOOL_DIR, '..');
const R2_ROOT = path.join(WORKSPACE_ROOT, 'r2-work');
const SCENARIO_ROOT = path.join(R2_ROOT, 'scenarios');

const SAMPLES = {
  'access-token': {
    root: 'base/security/access_token',
    part: 'security',
    baseScope: 'access-token-r2',
    extraRoot: null
  },
  ipc: {
    root: 'foundation/communication/ipc',
    part: 'communication',
    baseScope: 'ipc-r2',
    extraRoot: { root: 'base/hiviewdfx/hilog', copyName: 'hilog', part: 'hiviewdfx' }
  }
};

function parseArgs(argv) {
  const out = { sample: 'access-token', scenarios: null, out: null, promote: false };
  for (const a of argv) {
    if (a.startsWith('--sample=')) out.sample = a.slice('--sample='.length);
    else if (a.startsWith('--scenarios=')) out.scenarios = a.slice('--scenarios='.length).split(',').map((s) => s.trim()).filter(Boolean);
    else if (a.startsWith('--out=')) out.out = a.slice('--out='.length);
    else if (a === '--promote') out.promote = true;
    else throw new Error(`unknown-arg: ${a}`);
  }
  return out;
}

function copyDir(src, dst) {
  fs.rmSync(dst, { recursive: true, force: true });
  fs.cpSync(src, dst, { recursive: true });
}

function workDirs(sampleName, sample) {
  const work = path.join(R2_ROOT, `${sampleName}-r2inc`, 'work');
  const extra = sample.extraRoot
    ? path.join(R2_ROOT, `${sampleName}-r2inc`, 'work-extra', sample.extraRoot.copyName)
    : null;
  return { work, extra };
}

function writeScopePolicy(name, sampleName, sample) {
  const base = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'K', 'policies', `scope-${sample.baseScope}.json`), 'utf8'));
  const { work, extra } = workDirs(sampleName, sample);
  const rel = (abs) => `../r2-work/${scopeLib.posix(path.relative(R2_ROOT, abs))}`;
  const roots = [{ root: rel(work), part: sample.part }];
  if (sample.extraRoot) roots.push({ root: rel(extra), part: sample.extraRoot.part });
  base.roots = roots;
  base.snapshotScope = name;
  // run 合同要求 scope 载荷带 scopeId（schema 必填），逐场景固定
  base.scopeId = name;
  base.description = `R2-C 场景 scope：${name}（受控副本，不指产品树）`;
  const file = path.join(TOOL_DIR, 'K', 'policies', `scope-${name}.json`);
  fs.writeFileSync(file, `${JSON.stringify(base, null, 2)}\n`, 'utf8');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function resetWork(sampleName, sample) {
  const { work, extra } = workDirs(sampleName, sample);
  copyDir(path.join(SRC_ROOT, sample.root.split('/').join(path.sep)), work);
  if (sample.extraRoot) {
    copyDir(path.join(SRC_ROOT, sample.extraRoot.root.split('/').join(path.sep)), extra);
  }
}

function runNode(script, args, label, costs) {
  const t0 = Date.now();
  const r = cp.spawnSync(process.execPath, [path.join(TOOL_DIR, script), ...args],
    { encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  const wallMs = Date.now() - t0;
  if (r.status !== 0) {
    throw new Error(`${label} failed (${r.status}): ${(r.stderr || r.stdout || '').slice(0, 800)}`);
  }
  if (costs) costs.push({ step: label, wallMs });
  return { wallMs, stdout: r.stdout };
}

function snapshotIdOfScope(scopeName) {
  const dirs = fs.readdirSync(scopeLib.FACTS_ROOT).filter((n) => /^[0-9a-f]{64}$/.test(n));
  for (const d of dirs) {
    try {
      const snap = JSON.parse(fs.readFileSync(path.join(scopeLib.FACTS_ROOT, d, 'snapshot.json'), 'utf8'));
      if (snap.scope === scopeName) return snap.snapshotId;
    } catch (_) { /* skip */ }
  }
  return null;
}

function fullRebuild(scopeName, costs) {
  runNode('bin/fact-snapshot.js', [`--scope=${scopeName}`], `snapshot:${scopeName}`, costs);
  const id = snapshotIdOfScope(scopeName);
  if (!id) throw new Error(`snapshot-id-not-found: ${scopeName}`);
  runNode('bin/fact-metadata.js', [`--snapshot=${id}`], `metadata:${scopeName}`, costs);
  runNode('bin/fact-build.js', [`--snapshot=${id}`], `build:${scopeName}`, costs);
  // includes.jsonl：干净全量构建用同一提取器生成，保证与增量产物可对照。
  // 无条件重写：快照目录可能按内容哈希复用（相同最终输入 ⇒ 相同 id），陈旧文件必须覆盖。
  {
    const dir = path.join(scopeLib.FACTS_ROOT, id.replace(/^sha256:/, ''));
    const policy = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'K', 'policies', `scope-${scopeName}.json`), 'utf8'));
    const diff = incremental.diffAgainstSnapshot(policy, dir);
    const io = require('../lib/facts/io');
    io.writeJsonl(path.join(dir, 'includes.jsonl'),
      diff.includeRows.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line)),
      { key: (r) => `${r.file}:${r.line}:${r.spec}` });
  }
  return id;
}

function listFilesUnder(absRoot, exts) {
  const out = [];
  const stack = [absRoot];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of ents) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) { if (!['.git', 'out'].includes(ent.name)) stack.push(p); continue; }
      if (exts && !exts.includes(path.extname(ent.name).toLowerCase())) continue;
      out.push(p);
    }
  }
  return out.sort();
}

/**
 * 选择变更目标：生产 .cpp/.c/.h/.idl，且该 .cpp 的引号 include 全部可在
 * 场景范围（副本根 + 可选 hilog 根）内解析 —— 避免 same-size 场景误触发
 * dependency-unknown 回退。
 */
function pickMutationTargets(sampleName, sample) {
  const { work, extra } = workDirs(sampleName, sample);
  const prodFilter = (p) => !/[/\\](test|tests|unittest|fuzztest|mock|mocks|moduletest|systemtest|benchmark)[/\\]/i.test(p);
  const cpps = listFilesUnder(work, ['.cpp', '.c']).filter(prodFilter).filter((p) => fs.statSync(p).size < 80_000);
  const headers = listFilesUnder(work, ['.h']).filter(prodFilter);
  const idls = listFilesUnder(work, ['.idl']);

  const policy = writeScopePolicy(`${sampleName}-r2inc-target-probe`, sampleName, sample);
  const targetSet = new Set(parseLib.targets(policy).map((t) => t.rel));
  const roots = policy.roots.map((r) => r.root);
  const relOf = (abs) => scopeLib.posix(path.relative(SRC_ROOT, abs));
  const quotedResolvable = (abs) => {
    const rel = relOf(abs);
    const text = fs.readFileSync(abs, 'utf8');
    for (const inc of incremental.extractIncludes(text)) {
      if (inc.kind !== 'quoted') continue;
      if (incremental.resolveInclude(inc.spec, rel, targetSet, roots).status !== 'in-scope') return false;
    }
    return true;
  };
  const cppClean = cpps.filter(quotedResolvable);
  return {
    cpp: cppClean[0] || cpps[0],
    cppSecond: cppClean[1] || cppClean[0] || cpps[1] || cpps[0],
    header: headers[0],
    idl: idls[0],
    rel: relOf
  };
}

const MUTATIONS = {
  unchanged() { return { description: 'no change' }; },
  modified(t) {
    fs.appendFileSync(t.cpp, '\n// r2-scenario-marker\nint32_t r2_scenario_probe(void) { return 42; }\n');
    return { description: `append function to ${t.rel(t.cpp)}` };
  },
  'same-size-same-mtime'(t) {
    const abs = t.cppSecond;
    const st = fs.statSync(abs);
    const buf = fs.readFileSync(abs);
    const idx = buf.indexOf(0x7b);
    if (idx < 0) throw new Error('no-brace-in-target');
    buf[idx] = 0x20;
    fs.writeFileSync(abs, buf);
    fs.utimesSync(abs, st.atime, st.mtime);
    return { description: `same-size same-mtime content change in ${t.rel(abs)}` };
  },
  added(t) {
    const abs = path.join(path.dirname(t.cpp), 'r2_scenario_added.cpp');
    fs.writeFileSync(abs, '// r2 scenario added file\nint r2_added_fn(void) { return 7; }\n');
    return { description: `add ${t.rel(abs)}` };
  },
  deleted(t) {
    const rel = t.rel(t.cppSecond);
    fs.rmSync(t.cppSecond, { force: true });
    return { description: `delete ${rel}` };
  },
  'same-component-header'(t) {
    fs.appendFileSync(t.header, '\n// r2-scenario-header-touch\n');
    return { description: `touch header ${t.rel(t.header)}（file-local 模型：依赖方不重解析）` };
  },
  'include-removed'(t) {
    const abs = t.cpp;
    const text = fs.readFileSync(abs, 'utf8');
    const m = /(^|\n)([ \t]*#[ \t]*include[ \t]*"[^"]+"\r?\n)/.exec(text);
    if (!m) throw new Error('no-quoted-include-to-remove');
    const removed = m[2].trim();
    fs.writeFileSync(abs, text.replace(m[2], ''));
    return { description: `remove include ${removed} from ${t.rel(abs)}` };
  },
  'metadata-source-change'(t) {
    if (!t.idl) return { skipped: 'no-idl-in-sample' };
    fs.appendFileSync(t.idl, '\n// r2-scenario-idl-comment\n');
    return { description: `touch metadata source ${t.rel(t.idl)}（metadata 层变化 ⇒ 回退全量）` };
  }
};

const IPC_MUTATIONS = {
  'same-size-same-mtime': MUTATIONS['same-size-same-mtime'],
  'cross-component-header'(t, sample) {
    const { extra } = workDirs('ipc', sample);
    const headerAbs = path.join(extra, ...sample.extraRoot.headerRel().split('/'));
    fs.appendFileSync(headerAbs, '\n// r2-scenario-cross-component-header\n');
    return { description: `touch cross-component header ${sample.extraRoot.headerRel()}（ipc 源 include 该头，边真实存在）` };
  },
  'quoted-unresolved-fallback'(t) {
    fs.appendFileSync(t.cpp, '\n#include "r2_nonexistent_synthetic_header.h"\nint r2_unknown_dep_fn(void) { return 1; }\n');
    return { description: `add unresolvable quoted include to ${t.rel(t.cpp)}（⇒ dependency-unknown）` };
  }
};

SAMPLES.ipc.extraRoot.headerRel = () => 'interfaces/native/innerkits/include/hilog/log.h';

/** 派生层对照：index 计数/截断账目 + 入口候选与绑定分布（指南 R2-C3 的派生索引/入口/缺口结果）。 */
function compareDerived(resultDir, cleanDir, policy) {
  const factsLib = require('../lib/autonomy/facts');
  const discovery = require('../lib/autonomy/discovery');
  const open = (dir) => {
    const facts = new factsLib.AutonomyFacts(dir, policy);
    const idx = facts.index();
    const anchorsInfo = discovery.buildAnchors(facts, policy);
    const bindingByKind = {};
    for (const [ref, anchor] of anchorsInfo.anchors) {
      if (anchor.kind !== 'idl' && anchor.kind !== 'sa') continue;
      const b = discovery.resolveBinding(ref, { facts, scope: policy, anchors: anchorsInfo.anchors });
      const key = `${anchor.kind}:${b.binding}`;
      bindingByKind[key] = (bindingByKind[key] || 0) + 1;
    }
    return {
      counts: idx.counts,
      truncation: idx.truncation,
      entryKinds: anchorsInfo.stats.entryKinds,
      entriesTotal: anchorsInfo.stats.entries,
      metadataBinding: bindingByKind,
      unsupportedRows: (() => {
        const f = path.join(dir, 'unsupported.jsonl');
        return fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).length : 0;
      })()
    };
  };
  const a = open(resultDir);
  const b = open(cleanDir);
  const diffs = [];
  const cmpMap = (ka, va, vb) => {
    const keys = new Set([...Object.keys(va), ...Object.keys(vb)]);
    for (const k of keys) {
      if ((va[k] || 0) !== (vb[k] || 0)) diffs.push(`${ka}.${k}: ${va[k] || 0} vs ${vb[k] || 0}`);
    }
  };
  cmpMap('index.counts', a.counts, b.counts);
  cmpMap('index.truncation.calls', a.truncation.calls, b.truncation.calls);
  cmpMap('index.truncation.functions', a.truncation.functions, b.truncation.functions);
  cmpMap('entries', { total: a.entriesTotal, ...a.entryKinds }, { total: b.entriesTotal, ...b.entryKinds });
  cmpMap('metadataBinding', a.metadataBinding, b.metadataBinding);
  if (a.unsupportedRows !== b.unsupportedRows) diffs.push(`unsupported: ${a.unsupportedRows} vs ${b.unsupportedRows}`);
  return { equal: diffs.length === 0, diffs: diffs.slice(0, 20), a, b };
}

async function runScenario(sample, sampleName, scenario, baseSnapshotId, basePolicy, t, promote) {
  const workScope = `${sampleName}-r2inc-${scenario}`;
  // 每个场景 scope 都指向同一共享副本（相同最终文件集合）
  writeScopePolicy(workScope, sampleName, sample);
  resetWork(sampleName, sample);

  const mutationSet = IPC_MUTATIONS[scenario] ? IPC_MUTATIONS : MUTATIONS;
  const mutation = mutationSet[scenario] ? mutationSet[scenario](t, sample) : null;
  if (mutation && mutation.skipped) return { scenario, skipped: true, reason: mutation.skipped };

  const costs = [];
  const incrOut = path.join(SCENARIO_ROOT, workScope, 'incr');
  fs.rmSync(incrOut, { recursive: true, force: true });

  let incr;
  const t0 = Date.now();
  try {
    incr = await incremental.incrementalBuild({ snapshotId: baseSnapshotId, policy: basePolicy, outDir: incrOut, jobs: 2,
      opts: { promoteToSnapshot: promote === true } });
  } catch (e) {
    return { scenario, error: `incremental-build: ${e.message}` };
  }
  costs.push({ step: 'incremental', wallMs: Date.now() - t0 });

  let resultDir = incrOut;
  let fallbackFull = null;
  if (incr.fallback) {
    fallbackFull = { reason: incr.reason, detail: incr.detail || null };
    const fbScope = `${workScope}-fb`;
    writeScopePolicy(fbScope, sampleName, sample);
    const id = fullRebuild(fbScope, costs);
    resultDir = path.join(scopeLib.FACTS_ROOT, id.replace(/^sha256:/, ''));
  }

  // 相同最终文件集合上的独立干净全量构建
  const cleanId = fullRebuild(workScope, costs);
  const cleanDir = path.join(scopeLib.FACTS_ROOT, cleanId.replace(/^sha256:/, ''));

  const cmpOut = path.join(SCENARIO_ROOT, workScope, 'compare.json');
  const cmp = require('./fact-compare');
  let cmpResult;
  {
    const orig = process.stdout.write.bind(process.stdout);
    let captured = '';
    process.stdout.write = (c) => { captured += String(c); return true; };
    try { cmp.main([`--a=${resultDir}`, `--b=${cleanDir}`, `--out=${cmpOut}`]); } finally { process.stdout.write = orig; }
    cmpResult = JSON.parse(captured.trim().split('\n').filter(Boolean).pop());
  }

    // 派生层对照（index/入口/绑定分布/缺口行数）
    let derived = null;
    try { derived = compareDerived(resultDir, cleanDir, basePolicy); } catch (e) {
      derived = { equal: false, diffs: [`derived-compare-error: ${e.message}`] };
    }

    return {
      scenario,
      mutation,
      fallbackFull,
      incremental: {
        unchangedOnly: incr.unchangedOnly || false,
        reparseFiles: incr.reparseFiles,
        diffSummary: incr.diffSummary || null,
        costs: incr.costs || null
      },
      cleanBuild: { snapshotId: cleanId, costs },
      promoted: promote === true ? { derivedSnapshotId: incr.derivedSnapshotId || null, promoteMs: incr.costs ? incr.costs.promoteMs : null } : undefined,
      compare: cmpResult,
      derived,
      verdict: cmpResult.allEqual && derived.equal ? 'pass' : 'fail'
    };
}

async function main(argv = []) {
  const args = parseArgs(argv);
  const sample = SAMPLES[args.sample];
  if (!sample) throw new Error(`unknown-sample: ${args.sample}`);
  const sampleName = args.sample;
  const scenarios = args.scenarios || (sampleName === 'ipc'
    ? ['same-size-same-mtime', 'cross-component-header', 'quoted-unresolved-fallback']
    : ['unchanged', 'modified', 'same-size-same-mtime', 'added', 'deleted',
      'same-component-header', 'include-removed', 'metadata-source-change']);

  const baseScopeName = `${sampleName}-r2inc-base`;
  writeScopePolicy(baseScopeName, sampleName, sample);
  resetWork(sampleName, sample);
  const baseCosts = [];
  const baseSnapshotId = fullRebuild(baseScopeName, baseCosts);
  const basePolicy = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'K', 'policies', `scope-${baseScopeName}.json`), 'utf8'));

  const t = pickMutationTargets(sampleName, sample);
  const results = [];
  for (const scenario of scenarios) {
    const run = await runScenario(sample, sampleName, scenario, baseSnapshotId, basePolicy, t, args.promote === true);
    results.push(run);
    process.stdout.write(`${JSON.stringify({ scenario: run.scenario,
      verdict: run.verdict || (run.skipped ? 'skipped' : run.error ? 'error' : 'unknown'),
      reparse: run.incremental ? run.incremental.reparseFiles : null,
      fallback: run.fallbackFull ? run.fallbackFull.reason : null })}\n`);
  }

  const judged = results.filter((r) => r.verdict);
  const allPass = judged.every((r) => r.verdict === 'pass');
  const outFile = args.out || path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', `r2-scenarios-${sampleName}.json`);
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify({
    scenarioRunVersion: 'r2-scenarios-v1',
    sample: sampleName,
    baseSnapshotId,
    baseCosts,
    results,
    allPass
  }, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({ ok: true, allPass, out: path.relative(TOOL_DIR, outFile).split(path.sep).join('/') })}\n`);
  return allPass ? 0 : 2;
}

module.exports = { main, SAMPLES, MUTATIONS, IPC_MUTATIONS };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; })
    .catch((e) => {
      process.stderr.write(`${JSON.stringify({ ok: false, error: e.message, stack: e.stack })}\n`);
      process.exitCode = 1;
    });
}
