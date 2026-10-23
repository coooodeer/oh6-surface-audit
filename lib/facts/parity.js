'use strict';

/**
 * lib/facts/parity.js —— AG0.6 legacy parity。
 *
 * 口径：
 *   - own：out/facts/<id>/l1/{functions,calls}.jsonl（本工具产出）；
 *   - legacy：out/l1/functions.jsonl、out/l1/call-edges.jsonl（旧管线产出，只读，标 source=legacy）。
 *   - 函数按 `repo|file:startLine` 对齐；调用按 callee 名的多重集比较。
 *
 * 纪律：`source=own` 时**完全不读** legacy（loadLegacy 不会被调用）。
 */

const fs = require('fs');
const path = require('path');

const scope = require('./scope');
const { forEachRow } = require('./query');

const LEGACY_DIR = path.join(scope.TOOL_DIR, 'out', 'l1');
const LEGACY_FUNCTIONS = path.join(LEGACY_DIR, 'functions.jsonl');
const LEGACY_CALLS = path.join(LEGACY_DIR, 'call-edges.jsonl');

function bump(map, key, n = 1) {
  map.set(key, (map.get(key) || 0) + n);
}

/** legacy 的 file 是「相对 repo」，自有 facts 的 file 是「相对 OpenHarmony」——对齐时去掉 repo 前缀 */
function repoRelative(repo, file) {
  const f = String(file || '');
  const prefix = `${repo}/`;
  return f.startsWith(prefix) ? f.slice(prefix.length) : f;
}

/** 读自有 facts 的对比视图 */
function loadOwn(dir) {
  const functions = new Set();
  const macroFunctions = new Set();
  const functionRole = new Map();
  const byRepo = new Map();
  forEachRow(path.join(dir, 'l1', 'functions.jsonl'), (r) => {
    const repo = r.locator.repo;
    const k = `${repo}|${repoRelative(repo, r.locator.file)}:${r.locator.startLine}`;
    functions.add(k);
    if (r.macroDefined) macroFunctions.add(k);
    functionRole.set(k, r.role);
    bump(byRepo, repo);
  });
  const fileParse = new Map();
  forEachRow(path.join(dir, 'l1', 'files.jsonl'), (r) => {
    fileParse.set(r.path, r.quality && r.quality.parse);
  });
  const calleeNames = new Map();
  let calls = 0;
  forEachRow(path.join(dir, 'l1', 'calls.jsonl'), (r) => {
    calls += 1;
    bump(calleeNames, r.calleeName);
  });
  return { functions, macroFunctions, functionRole, fileParse, functionsByRepo: byRepo, calls, calleeNames };
}

/** 读 legacy（只读；调用方保证 source=legacy 或 parity 模式） */
function loadLegacy(legacyDir = LEGACY_DIR) {
  const fns = path.join(legacyDir, 'functions.jsonl');
  const callsFile = path.join(legacyDir, 'call-edges.jsonl');
  const functions = new Set();
  const byRepo = new Map();
  if (fs.existsSync(fns)) {
    forEachRow(fns, (r) => {
      const k = `${r.repo}|${r.file}:${r.startLine}`;
      functions.add(k);
      bump(byRepo, r.repo);
    });
  }
  const calleeNames = new Map();
  let calls = 0;
  if (fs.existsSync(callsFile)) {
    forEachRow(callsFile, (r) => {
      calls += 1;
      bump(calleeNames, r.name);
    });
  }
  return { functions, functionsByRepo: byRepo, calls, calleeNames, present: fs.existsSync(fns) };
}

function setDiff(a, b) {
  const out = [];
  for (const x of a) if (!b.has(x)) out.push(x);
  return out;
}

/** own vs legacy：计数、覆盖率、差异分类与样例 */
function compare(own, legacy, opts = {}) {
  const sampleLimit = opts.sampleLimit || 10;
  const ownOnly = setDiff(own.functions, legacy.functions);
  const legacyOnly = setDiff(legacy.functions, own.functions);
  const matched = own.functions.size - ownOnly.length;

  const macroExplained = ownOnly.filter((k) => own.macroFunctions.has(k));
  const macroSet = new Set(macroExplained);
  const restOwn = ownOnly.filter((k) => !macroSet.has(k));
  // 测试代码：legacy 只管生产代码（实测 legacy 里 test 目录仅 15 个函数）
  const testExplained = restOwn.filter((k) => own.functionRole && own.functionRole.get(k) === 'test');
  const testSet = new Set(testExplained);
  const restProd = restOwn.filter((k) => !testSet.has(k));
  const parsePartial = restProd.filter((k) => {
    const [repo, tail] = k.split('|');
    const file = tail.replace(/:\d+$/, '');
    return own.fileParse.get(`${repo}/${file}`) === 'partial';
  });
  const parseSet = new Set(parsePartial);
  const legacyRepo = (k) => k.slice(0, k.indexOf('|'));
  const repoNotInLegacy = restProd.filter((k) => !parseSet.has(k) && (legacy.functionsByRepo.get(legacyRepo(k)) || 0) === 0);
  const repoSet = new Set(repoNotInLegacy);
  const headerFiles = restProd.filter((k) => !parseSet.has(k) && !repoSet.has(k) && /\.(h|hh|hpp|hxx):\d+$/.test(k));
  const headerSet = new Set(headerFiles);
  const ownOnlyUnexplained = restProd.filter((k) => !parseSet.has(k) && !repoSet.has(k) && !headerSet.has(k));

  const legacyOnlyByParse = { partial: 0, full: 0, notInFacts: 0 };
  for (const k of legacyOnly) {
    const [repo, tail] = k.split('|');
    const file = tail.replace(/:\d+$/, '');
    const p = own.fileParse.get(`${repo}/${file}`);
    if (p === undefined) legacyOnlyByParse.notInFacts += 1;
    else if (p === 'partial') legacyOnlyByParse.partial += 1;
    else legacyOnlyByParse.full += 1;
  }

  const namesOwn = [...own.calleeNames.keys()];
  const namesLegacy = new Set(legacy.calleeNames.keys());
  const namesOnlyOwn = namesOwn.filter((n) => !namesLegacy.has(n));
  const namesOnlyLegacy = [...namesLegacy].filter((n) => !own.calleeNames.has(n));
  const union = new Set([...namesOwn, ...namesLegacy]);

  return {
    source: 'own',
    legacyPresent: legacy.present,
    functions: {
      own: own.functions.size,
      legacy: legacy.functions.size,
      matched,
      matchRatioVsLegacy: legacy.functions.size ? Number((matched / legacy.functions.size).toFixed(4)) : null,
      onlyOwn: ownOnly.length,
      onlyLegacy: legacyOnly.length,
      explained: {
        macroDefined: macroExplained.length,
        testFiles: testExplained.length,
        parsePartial: parsePartial.length,
        repoNotInLegacy: repoNotInLegacy.length,
        headerFiles: headerFiles.length,
        remaining: ownOnlyUnexplained.length
      },
      legacyOnlyByParse,
      samples: {
        onlyOwn: ownOnlyUnexplained.slice(0, sampleLimit),
        onlyLegacy: legacyOnly.slice(0, sampleLimit),
        macroDefined: macroExplained.slice(0, sampleLimit)
      },
      byRepo: [...own.functionsByRepo.entries()].map(([repo, n]) => ({ repo, own: n, legacy: legacy.functionsByRepo.get(repo) || 0 }))
    },
    calls: {
      own: own.calls,
      legacy: legacy.calls,
      calleeNameOverlap: union.size ? Number(((namesOwn.filter((n) => namesLegacy.has(n)).length) / union.size).toFixed(4)) : null,
      namesOnlyOwn: namesOnlyOwn.length,
      namesOnlyLegacy: namesOnlyLegacy.length,
      sampleNamesOnlyOwn: namesOnlyOwn.slice(0, sampleLimit),
      sampleNamesOnlyLegacy: namesOnlyLegacy.slice(0, sampleLimit)
    },
    explanations: [
      { reason: 'macro-defined-functions', count: macroExplained.length, note: 'gtest 的 TEST_F/HWTEST_F 形态被自有管线识别为函数，legacy 不计' },
      { reason: 'ast-error-nodes', count: null, note: 'tree-sitter 局部错误节点会让个别函数/调用漏抽；见 quality.json' },
      { reason: 'macro-expansion-not-modeled', count: null, note: '宏分支内的函数/调用两边都不会出现' },
      { reason: 'legacy-scope', count: null, note: 'legacy 只覆盖 D4/R1 域（17,534 函数），本快照覆盖 5 个 root 全部源文件' }
    ]
  };
}

module.exports = { LEGACY_DIR, LEGACY_FUNCTIONS, LEGACY_CALLS, loadOwn, loadLegacy, compare };
