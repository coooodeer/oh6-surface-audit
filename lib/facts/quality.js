'use strict';

/**
 * lib/facts/quality.js —— AG0.5 的纯函数部分（便于单测）。
 * bin/fact-quality.js 只负责读写与 CLI。
 */

const ratio = (a, b) => (b > 0 ? Number((a / b).toFixed(4)) : null);

function summarize(rows) {
  const totals = {
    files: rows.length,
    production: rows.filter((r) => r.role === 'production').length,
    test: rows.filter((r) => r.role === 'test').length,
    parseFull: rows.filter((r) => r.parse === 'full').length,
    parsePartial: rows.filter((r) => r.parse === 'partial').length,
    parseFailed: rows.filter((r) => r.parse === 'failed').length,
    functions: rows.reduce((a, r) => a + ((r.counts && r.counts.functions) || 0), 0),
    calls: rows.reduce((a, r) => a + ((r.counts && r.counts.calls) || 0), 0),
    astCallExpressions: rows.reduce((a, r) => a + (r.astCallExpressions || 0), 0),
    astFunctionDefinitions: rows.reduce((a, r) => a + (r.astFunctionDefinitions || 0), 0),
    macroFunctions: rows.reduce((a, r) => a + (r.macroFunctions || 0), 0),
    cfgUnsupportedEdges: rows.reduce((a, r) => a + (r.cfgUnsupportedEdges || 0), 0)
  };
  const avg = (key) => {
    const xs = rows.map((r) => r[key]).filter((x) => typeof x === 'number');
    return xs.length ? Number((xs.reduce((a, b) => a + b, 0) / xs.length).toFixed(4)) : null;
  };
  return { totals, cfgCoverageAvg: avg('cfgCoverageAvg'), dfgCoverageAvg: avg('dfgCoverageAvg') };
}

/**
 * @param {{totals:object, callsWritten:number, compdb:object, gen:object, cfgAvg:number|null, dfgAvg:number|null}} p
 */
function coverageRows(p) {
  const t = p.totals;
  const compdb = p.compdb || { entries: 0, rootFiles: 0 };
  const gen = p.gen || { referenced: 0, missing: 0 };
  const rows = [
    { metric: 'files', value: t.files, detail: { production: t.production, test: t.test } },
    { metric: 'parse', value: ratio(t.parseFull, t.files), detail: { full: t.parseFull, partial: t.parsePartial, failed: t.parseFailed } },
    { metric: 'compdb-coverage', value: ratio(compdb.rootFiles, t.files), detail: { compdbRootFiles: compdb.rootFiles, sourceFiles: t.files, entries: compdb.entries } },
    { metric: 'generated-headers', value: ratio(gen.referenced - gen.missing, gen.referenced), detail: { referenced: gen.referenced, missing: gen.missing } },
    { metric: 'call-attribution', value: ratio(p.callsWritten, t.astCallExpressions), detail: { callRows: p.callsWritten, perFileSum: t.calls, astCallExpressions: t.astCallExpressions } },
    { metric: 'function-coverage', value: ratio(t.functions - t.macroFunctions, t.astFunctionDefinitions), detail: { functionRows: t.functions, macroFunctions: t.macroFunctions, regularFunctions: t.functions - t.macroFunctions, astFunctionDefinitions: t.astFunctionDefinitions } },
    { metric: 'cfg-coverage', value: p.cfgAvg, detail: { unsupportedEdges: t.cfgUnsupportedEdges } },
    { metric: 'dfg-coverage', value: p.dfgAvg, detail: { note: '函数内最近 def，不建模分支合流/别名' } },
    { metric: 'types-resolution', value: 1, detail: { syntaxOnly: true, exact: 0, note: '无 clang 语义类型；getType --exact 走定向 AST' } },
    { metric: 'macro-expansion', value: 0, detail: { modeled: false, note: 'tree-sitter 不展开宏；宏定义函数体按 TEST_F 形态识别' } }
  ];
  if (p.clang && p.clang.checked > 0) {
    rows.push({ metric: 'clang-sampled', value: ratio(p.clang.checked, t.files), detail: { checked: p.clang.checked, files: t.files, mode: p.clang.mode || null } });
    rows.push({ metric: 'clang-ok', value: ratio(p.clang.ok, p.clang.checked), detail: { ok: p.clang.ok, checked: p.clang.checked, byStatus: p.clang.byStatus || {} } });
  }
  return rows;
}

/** 合并两批 unsupported（按 id 去重，保留先出现的） */
function mergeUnsupported(lists) {
  const seen = new Set();
  const out = [];
  for (const list of lists) {
    for (const row of list) {
      const id = row.id || `${row.reason}:${row.file}:${row.detail ? JSON.stringify(row.detail) : ''}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({ ...row, id });
    }
  }
  return out;
}

function countByReason(rows) {
  const out = {};
  for (const r of rows) out[r.reason] = (out[r.reason] || 0) + 1;
  return out;
}

module.exports = { ratio, summarize, coverageRows, mergeUnsupported, countByReason };
