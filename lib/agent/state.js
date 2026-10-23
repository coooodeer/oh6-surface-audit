'use strict';

/**
 * lib/agent/state.js —— 全 Agent 的统一状态与门禁聚合。
 *
 * campaign 元数据与 gate 定义来自 lib/agent/registry.js：
 *   - 新增 campaign 只需增加 lib/agent/campaigns/<id>.js，自动被发现；
 *   - 新增 gate 只需改 campaign 定义的 gates[]（含 evaluate）；runner 只构造 ctx。
 *
 * 本模块不重写各 campaign 的判定逻辑，只做：
 *   - 读取各 campaign 的 gate summary，归一成统一 gate registry；
 *   - 校验声明状态、gate 数、artifact 是否存在、生成时间是否可解析；
 *   - 汇总 node --test 结果；
 *   - 写 out/report/agent-state.json 与 out/report/agent-gates.md。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { OUT_ROOT, ensureDir, writeJson } = require('../util.js');
const { listCampaigns } = require('./registry.js');

const TOOL_ROOT = path.resolve(__dirname, '..', '..');
const REPORT_DIR = path.join(OUT_ROOT, 'report');

const CAMPAIGNS = Object.freeze(listCampaigns());

const TEST_REPORTS = [
  'out/report/agent-node-test.txt',
  'out/report/p1p2p7p8-node-test.txt'
];

const ANSI_RE = /\x1b\[[0-9;]*m/g;

function absPath(rel, root = TOOL_ROOT) {
  return path.join(root, rel);
}

function readJsonSafe(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return null;
  }
}

function fileInfo(file, root = TOOL_ROOT) {
  const abs = path.isAbsolute(file) ? file : absPath(file, root);
  const rel = path.relative(root, abs).split(path.sep).join('/');
  if (!fs.existsSync(abs)) return { path: rel, exists: false, bytes: 0, mtime: null, sha256: null };
  const st = fs.statSync(abs);
  const buf = fs.readFileSync(abs);
  return {
    path: rel,
    exists: true,
    bytes: st.size,
    mtime: st.mtime.toISOString(),
    sha256: crypto.createHash('sha256').update(buf).digest('hex')
  };
}

function slug(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60) || 'gate';
}

function gateDetail(g) {
  if (g == null) return null;
  const d = g.detail;
  if (d == null) return null;
  if (typeof d === 'string') return d;
  try { return JSON.stringify(d); } catch (_) { return String(d); }
}

function markdownCell(value, max = 260) {
  let s = value == null ? '-' : (typeof value === 'string' ? value : JSON.stringify(value));
  s = s.replace(ANSI_RE, '').replace(/\r?\n/g, ' ').replace(/\|/g, '\\|').trim();
  if (s.length > max) s = `${s.slice(0, max)}…`;
  return s || '-';
}

/**
 * 解析 node --test 文本报告（默认 reporter）。
 * Windows/PowerShell 输出可能带 ANSI；这里先剥离。
 */
function parseTestReportText(text) {
  const clean = String(text || '').replace(ANSI_RE, '');
  const num = (re) => {
    const m = clean.match(re);
    return m ? Number(m[1]) : null;
  };
  let total = num(/(?:^|\n)\s*(?:ℹ|i)\s*tests\s+(\d+)/) ?? num(/tests\s+(\d+)/);
  let passed = num(/(?:^|\n)\s*(?:ℹ|i)\s*pass\s+(\d+)/) ?? num(/pass\s+(\d+)/);
  let failed = num(/(?:^|\n)\s*(?:ℹ|i)\s*fail\s+(\d+)/) ?? num(/fail\s+(\d+)/);
  const durationMs = num(/(?:^|\n)\s*(?:ℹ|i)\s*duration_ms\s+([\d.]+)/) ?? num(/duration_ms\s+([\d.]+)/);
  if (failed == null && total != null && passed != null) failed = Math.max(0, total - passed);
  if (total == null && passed != null && failed != null) total = passed + failed;
  const pass = total != null && failed === 0 && total > 0;
  return { total, passed, failed, durationMs, pass };
}

function collectTests(root, issues) {
  let file = null;
  for (const rel of TEST_REPORTS) {
    if (fs.existsSync(absPath(rel, root))) { file = rel; break; }
  }
  if (!file) {
    issues.push({ campaign: 'tests', code: 'missing-test-report', detail: `none of ${TEST_REPORTS.join(', ')}` });
    return { report: null, exists: false, total: null, passed: null, failed: null, pass: false };
  }
  const text = fs.readFileSync(absPath(file, root), 'utf8');
  const parsed = parseTestReportText(text);
  const info = fileInfo(file, root);
  if (parsed.total == null || parsed.passed == null || parsed.failed == null) {
    issues.push({ campaign: 'tests', code: 'unparsable-test-report', detail: file });
  } else if (parsed.failed > 0) {
    issues.push({ campaign: 'tests', code: 'tests-failed', detail: `${parsed.failed}/${parsed.total} failed` });
  }
  return { report: file, exists: true, ...parsed, sha256: info.sha256, mtime: info.mtime };
}

function collectCampaign(def, root, issues) {
  const summaryAbs = absPath(def.summary, root);
  const summary = readJsonSafe(summaryAbs);
  const info = fileInfo(def.summary, root);
  const rows = [];
  if (!summary) {
    issues.push({ campaign: def.id, code: 'missing-or-invalid-summary', detail: def.summary });
  } else if (!Array.isArray(summary.gates)) {
    issues.push({ campaign: def.id, code: 'missing-gates-array', detail: def.summary });
  } else {
    const names = new Set();
    summary.gates.forEach((g, i) => {
      const name = g && g.name != null ? String(g.name) : `gate-${i + 1}`;
      if (names.has(name)) issues.push({ campaign: def.id, code: 'duplicate-gate-name', detail: name });
      names.add(name);
      rows.push({
        id: (g && g.id) || `${def.id}/${i + 1}-${slug(name)}`,
        key: (g && g.key) || null,
        campaign: def.id,
        name,
        pass: g && g.pass === true,
        detail: gateDetail(g)
      });
    });
  }
  const declared = Boolean(summary && summary.allGatesPass === true);
  const allRowsPass = rows.length > 0 && rows.every((g) => g.pass);
  const countOk = rows.length === def.expectedGates;
  if (rows.length && !countOk) {
    issues.push({ campaign: def.id, code: 'gate-count-mismatch', detail: `expected ${def.expectedGates}, got ${rows.length}` });
  }
  if (summary && declared !== allRowsPass) {
    issues.push({ campaign: def.id, code: 'declared-vs-rows-mismatch', detail: `allGatesPass=${declared}, rowsPass=${allRowsPass}` });
  }
  const generatedAt = summary && summary.generatedAt ? String(summary.generatedAt) : null;
  const generatedMs = generatedAt ? Date.parse(generatedAt) : NaN;
  if (summary && !Number.isFinite(generatedMs)) {
    issues.push({ campaign: def.id, code: 'invalid-generatedAt', detail: generatedAt || 'missing' });
  }
  const artifacts = def.artifacts.map((rel) => fileInfo(rel, root));
  const missing = artifacts.filter((a) => !a.exists).map((a) => a.path);
  if (missing.length) {
    issues.push({ campaign: def.id, code: 'missing-artifacts', detail: missing.join(', ') });
  }
  const pass = Boolean(summary) && declared && allRowsPass && countOk && missing.length === 0 && Number.isFinite(generatedMs);
  return {
    id: def.id,
    name: def.name,
    status: pass ? 'PASS' : 'FAIL',
    pass,
    expectedGates: def.expectedGates,
    gateCount: rows.length,
    passedGates: rows.filter((g) => g.pass).length,
    failedGates: rows.filter((g) => !g.pass).length,
    declaredAllGatesPass: declared,
    rowsAllPass: allRowsPass,
    gateCountOk: countOk,
    generatedAt,
    ageSeconds: Number.isFinite(generatedMs) ? Math.max(0, Math.round((Date.now() - generatedMs) / 1000)) : null,
    summary: info,
    missingArtifacts: missing,
    artifacts,
    gates: rows
  };
}

function readSnapshot(root) {
  const rel = 'out/snapshot.json';
  const abs = absPath(rel, root);
  if (!fs.existsSync(abs)) return null;
  const s = readJsonSafe(abs);
  if (!s) return null;
  return {
    file: rel,
    generatedAt: s.generatedAt || null,
    repos: Array.isArray(s.repos) ? s.repos.length : null,
    repoNames: Array.isArray(s.repos) ? s.repos.map((r) => r.repo).filter(Boolean) : []
  };
}

function collectState(opts = {}) {
  const root = opts.root || TOOL_ROOT;
  const issues = [];
  const campaigns = CAMPAIGNS.map((def) => collectCampaign(def, root, issues));
  const tests = collectTests(root, issues);
  const gates = campaigns.flatMap((c) => c.gates);
  gates.push({
    id: 'tests/node',
    campaign: 'tests',
    name: 'node --test',
    pass: tests.pass === true,
    detail: tests.total == null ? 'missing or unparsable test report' : `${tests.passed}/${tests.total} pass, ${tests.failed} fail`
  });
  const passed = gates.filter((g) => g.pass).length;
  const failed = gates.length - passed;
  const campaignsPassed = campaigns.filter((c) => c.pass).length;
  const allPass = campaigns.every((c) => c.pass) && tests.pass === true && issues.length === 0;
  const state = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    root,
    overall: {
      allPass,
      status: allPass ? 'PASS' : 'FAIL',
      campaignCount: campaigns.length,
      campaignsPassed,
      gates: { total: gates.length, passed, failed },
      tests: { pass: tests.pass === true, total: tests.total, passed: tests.passed, failed: tests.failed, report: tests.report },
      consistencyOk: issues.length === 0
    },
    campaigns,
    tests,
    gates,
    consistency: { ok: issues.length === 0, issues },
    snapshot: readSnapshot(root),
    artifacts: [
      ...campaigns.map((c) => c.summary),
      fileInfo(tests.report || TEST_REPORTS[1], root)
    ]
  };
  return state;
}

function renderGatesMarkdown(state) {
  const lines = [];
  lines.push('# Agent 统一状态与门禁');
  lines.push('');
  lines.push(`生成时间：${state.generatedAt}`);
  lines.push('');
  lines.push(`allGatesPass：**${state.overall.allPass}**`);
  lines.push('');
  lines.push(`- campaigns：${state.overall.campaignsPassed}/${state.overall.campaignCount} 通过`);
  lines.push(`- gates：${state.overall.gates.passed}/${state.overall.gates.total} 通过`);
  lines.push(`- tests：${state.overall.tests.passed}/${state.overall.tests.total} pass，${state.overall.tests.failed} fail`);
  lines.push(`- consistency：${state.consistency.ok ? 'OK' : `${state.consistency.issues.length} issue(s)`}`);
  lines.push('');
  lines.push('## Campaigns');
  lines.push('');
  lines.push('| Campaign | status | gates | generatedAt | summary |');
  lines.push('| --- | --- | ---: | --- | --- |');
  for (const c of state.campaigns) {
    lines.push(`| ${c.name} | ${c.status} | ${c.passedGates}/${c.gateCount} | ${c.generatedAt || '-'} | ${c.summary.path} |`);
  }
  lines.push('');
  lines.push('## Gates');
  lines.push('');
  lines.push('| ID | Campaign | Gate | Pass | Detail |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const g of state.gates) {
    lines.push(`| ${g.id} | ${g.campaign} | ${markdownCell(g.name, 120)} | ${g.pass ? 'PASS' : 'FAIL'} | ${markdownCell(g.detail, 240)} |`);
  }
  lines.push('');
  lines.push('## Consistency');
  lines.push('');
  if (state.consistency.issues.length === 0) {
    lines.push('- none');
  } else {
    for (const i of state.consistency.issues) lines.push(`- **${i.campaign}/${i.code}**: ${i.detail}`);
  }
  lines.push('');
  lines.push('## Test report');
  lines.push('');
  lines.push(`- ${state.tests.report || '(missing)'}`);
  lines.push(`- total=${state.tests.total} passed=${state.tests.passed} failed=${state.tests.failed}`);
  lines.push('');
  if (state.snapshot) {
    lines.push('## Snapshot');
    lines.push('');
    lines.push(`- ${state.snapshot.file} generatedAt=${state.snapshot.generatedAt || '-'} repos=${state.snapshot.repos}`);
    lines.push('');
  }
  return lines.join('\n');
}

function writeState(state, opts = {}) {
  const reportDir = opts.reportDir || REPORT_DIR;
  ensureDir(reportDir);
  const stateFile = path.join(reportDir, 'agent-state.json');
  const gatesFile = path.join(reportDir, 'agent-gates.md');
  writeJson(stateFile, state);
  fs.writeFileSync(gatesFile, renderGatesMarkdown(state), 'utf8');
  return {
    stateFile: path.relative(TOOL_ROOT, stateFile).split(path.sep).join('/'),
    gatesFile: path.relative(TOOL_ROOT, gatesFile).split(path.sep).join('/')
  };
}

function summaryLines(state) {
  return [
    `Agent state: ${state.overall.status}`,
    `campaigns: ${state.campaigns.map((c) => `${c.id} ${c.passedGates}/${c.gateCount} ${c.status}`).join('; ')}`,
    `tests: ${state.overall.tests.passed}/${state.overall.tests.total} pass, ${state.overall.tests.failed} fail`,
    `gates: ${state.overall.gates.passed}/${state.overall.gates.total}`,
    `consistency: ${state.consistency.ok ? 'OK' : state.consistency.issues.length + ' issue(s)'}`
  ];
}

module.exports = {
  TOOL_ROOT,
  REPORT_DIR,
  CAMPAIGNS,
  TEST_REPORTS,
  parseTestReportText,
  collectState,
  renderGatesMarkdown,
  writeState,
  summaryLines,
  readJsonSafe,
  fileInfo,
  absPath
};
