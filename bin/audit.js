'use strict';

const fs = require('fs');
const path = require('path');
const {
  WORKSPACE, SOURCE_ROOT, TOOL_ROOT, OUT_ROOT,
  CPP_EXTS, walk, readJsonl, writeJson, writeJsonl, ensureDir, git
} = require('../lib/util');
const { loadFunctions } = require('../lib/index');
const { enumerateRepo, summarize } = require('../lib/surface');
const { countCompdbFiles } = require('../lib/compdb');
const { runSpecDiff } = require('../lib/specdiff');

const REPOS = [
  'foundation/communication/dsoftbus',
  'base/account/os_account'
];

const COMPDB_PART = {
  'foundation/communication/dsoftbus': 'communication',
  'base/account/os_account': 'account'
};

function shortName(repo) {
  return repo.split('/').slice(-1)[0];
}

function countDirs(root, name) {
  let n = 0;
  const skip = new Set(['.git', 'out', 'third_party', 'prebuilts', 'node_modules']);
  (function rec(dir) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    for (const ent of ents) {
      if (!ent.isDirectory()) continue;
      if (skip.has(ent.name)) continue;
      if (ent.name === name) n += 1;
      rec(path.join(dir, ent.name));
    }
  })(root);
  return n;
}

function snapshot() {
  const fns = loadFunctions(new Set(REPOS));
  const repos = REPOS.map((repo) => {
    const abs = path.join(SOURCE_ROOT, repo);
    const head = (git(repo, ['rev-parse', 'HEAD']) || '').trim() || null;
    const headDate = (git(repo, ['log', '-1', '--format=%cI']) || '').trim() || null;
    const subject = (git(repo, ['log', '-1', '--format=%s']) || '').trim() || null;
    const cpp = walk(abs, { exts: CPP_EXTS }).length;
    const idl = walk(abs, { exts: new Set(['.idl']) }).length;
    const saDirs = countDirs(abs, 'sa_profile');
    const fnCount = (fns.byRepo.get(repo) || []).length;
    return { repo, head, headDate, subject, cppFiles: cpp, idlFiles: idl, saProfileDirs: saDirs, indexedFunctions: fnCount };
  });
  const out = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    workspace: WORKSPACE,
    sourceRoot: SOURCE_ROOT,
    toolRoot: TOOL_ROOT,
    repos
  };
  writeJson(path.join(OUT_ROOT, 'snapshot.json'), out);
  return out;
}

function currentContracts(repo) {
  const file = path.join(TOOL_ROOT, 'result', 'latest', 'contracts', 'entries.jsonl');
  const rows = readJsonl(file);
  const byKind = {};
  const byEvidence = {};
  let total = 0;
  for (const r of rows) {
    const f = (r.origin && r.origin.file) || '';
    if (!f.startsWith(`${repo}/`)) continue;
    total += 1;
    byKind[r.kind] = (byKind[r.kind] || 0) + 1;
    const src = (r.evidence && r.evidence.source) || '(none)';
    byEvidence[src] = (byEvidence[src] || 0) + 1;
  }
  return { total, byKind, byEvidence };
}

function sourceFileList(repo) {
  const abs = path.join(SOURCE_ROOT, repo);
  return walk(abs, { exts: new Set(['.c', '.cc', '.cpp', '.cxx']) }).map((f) => f.rel);
}

/** dsoftbus 的 SoftBusServerStub 用 memberFuncMap_/memberPermissionMap_ 做中心分发 */
function dispatchTable(repo) {
  const rel = 'core/frame/standard/init/src/softbus_server_stub.cpp';
  const abs = path.join(SOURCE_ROOT, repo, rel);
  if (!fs.existsSync(abs)) return null;
  const text = fs.readFileSync(abs, 'utf8');
  const grab = (re) => {
    const s = new Set();
    let m;
    while ((m = re.exec(text)) !== null) s.add(m[1]);
    return s;
  };
  const funcs = grab(/memberFuncMap_\[([A-Za-z_][A-Za-z0-9_]*)\]\s*=/g);
  const perms = grab(/memberPermissionMap_\[([A-Za-z_][A-Za-z0-9_]*)\]\s*=/g);
  const harness = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'ipc-harness-index.jsonl'))
    .filter((r) => (r.file || '').startsWith(`${repo}/`))
    .map((r) => r.codeExpr)
    .filter(Boolean);
  const harnessSet = new Set(harness);
  const overlap = [...harnessSet].filter((c) => funcs.has(c));
  return {
    file: rel,
    funcCodes: funcs.size,
    permCodes: perms.size,
    funcWithoutPermission: [...funcs].filter((c) => !perms.has(c)).length,
    permissionWithoutFunc: [...perms].filter((c) => !funcs.has(c)).length,
    harnessCodes: harnessSet.size,
    harnessOverlapWithDispatch: overlap.length,
    harnessOnlySamples: [...harnessSet].filter((c) => !funcs.has(c)).slice(0, 8)
  };
}

function ledger() {
  const snap = snapshot();
  const fns = loadFunctions(new Set(REPOS));
  const all = [];
  const coverage = [];
  for (const repo of REPOS) {
    const rows = enumerateRepo(repo, fns);
    const sum = summarize(rows, repo);
    const cur = currentContracts(repo);
    const name = shortName(repo);
    const part = COMPDB_PART[repo];
    const srcList = sourceFileList(repo);
    const compdb = part ? countCompdbFiles(part, repo, new Set(srcList)) : null;
    const ledgerCounts = {
      idlMethods: rows.filter((r) => r.channel === 'idl').length,
      dispatchCases: rows.filter((r) => (r.provenance || []).includes('dispatch')).length,
      harnessRows: rows.filter((r) => (r.provenance || []).includes('harness')).length,
      parserFunctions: rows.filter((r) => r.channel === 'parser').length,
      socketFunctions: rows.filter((r) => r.channel === 'socket').length,
      hdiFunctions: rows.filter((r) => r.channel === 'hdi').length,
      broadcastSites: rows.filter((r) => r.channel === 'broadcast').length
    };
    const crossCheck = {
      sourceFilesScanned: srcList.length,
      compdb,
      fileIndexRate: compdb ? compdb.coverageRate : null,
      scanVsCompdbRatio: compdb && compdb.productFiles ? Number((srcList.length / compdb.productFiles).toFixed(4)) : null,
      ledgerCounts,
      currentContracts: cur,
      dispatchTable: dispatchTable(repo),
      notes: [
        'fileIndexRate = compdb 产品源文件中被本次扫描覆盖的比例（交集/compdb）。>1 的 scanVsCompdbRatio 表示扫描面还包含 compdb 之外的条件编译/平台文件。',
        'dispatchCases 只统计仓内 stub；生成式 stub 不在仓内，因此 os_account 的 IPC 主来源是 harness。',
        '当前 contracts 的 IPC 行同时包含 harness 与 IDL 两个来源，二者不是同一身份轴，不能直接相加当分母。'
      ]
    };
    writeJsonl(path.join(OUT_ROOT, 'surface', `${name}.jsonl`), rows);
    const cov = {
      schemaVersion: 1,
      repo,
      generatedAt: new Date().toISOString(),
      snapshot: snap.repos.find((r) => r.repo === repo),
      semantics: {
        expected: '九路入口并集（去重；含 harness）',
        resolved: '有 file/line 与身份',
        contracted: 'resolved 且有 attackerPosition + requiredChecks（本原型按构造等于 resolved）',
        verified: 'contracted 且有实现侧强证据（handler/stub-method/register-func/function-body）',
        weakLink: 'contracted 但只有 harness 调用或 SA 声明等弱证据',
        sdr: 'surface discovery rate = resolved/expected',
        ilr: 'implementation link rate = verified/contracted',
        ecr: 'not measured：语义契约合成（sink/前置条件/攻击者约束）未实现',
        note: '表层台账；linked 不代表控制流闭合或语义证明'
      },
      totals: sum.totals,
      byProvenance: sum.byProvenance,
      byChannel: sum.byChannel,
      currentContracts: cur,
      crossCheck,
      caveats: [
        '复用 oh6-vuln-agent/index/functions.jsonl（2026-10-13 快照）做符号定位，可能与当前 HEAD 轻微漂移',
        'socket/HDI 为调用点启发式，未做网络可达性证明',
        'IDL 的 linked 只表示仓内找到 stub/proxy 文本，不表示配对闭合',
        'SA 的 linked=declared 只表示 profile 声明，不表示实现'
      ]
    };
    writeJson(path.join(OUT_ROOT, 'coverage', `${name}.json`), cov);
    coverage.push(cov);
    all.push(...rows);
  }
  writeJsonl(path.join(OUT_ROOT, 'surface', 'all.jsonl'), all);

  const lines = [];
  lines.push('# Entry ledger / surface coverage');
  lines.push('');
  lines.push(`生成时间：${new Date().toISOString()}`);
  lines.push('');
  lines.push('口径：`expected` = 九路入口并集；`resolved` = 有 file/line 与身份；`verified` = 实现侧强证据（case handler / stub 方法 / register func / 函数体）；`weak-link` = harness 调用或 SA 声明等弱证据。`SDR = resolved/expected`，`ILR = verified/contracted`。');
  lines.push('');
  lines.push('**ECR 本次不报**：`contracted` 目前按构造等于 `resolved`（attackerPosition/requiredChecks 由通道模板统一填充），报 ECR 会得到虚高的 1.0。真正可复算的是 SDR、ILR 和分通道分母。');
  lines.push('');
  lines.push('| repo | expected | resolved | verified | weak-link | SDR | ILR(verified) | weak-link rate | 现有 contracts |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const c of coverage) {
    const t = c.totals;
    lines.push(`| ${c.repo} | ${t.expected} | ${t.resolved} | ${t.verified} | ${t.weakLinked} | ${t.sdr} | ${t.ilr} | ${t.weakLinkRate} | ${c.currentContracts.total} |`);
  }
  lines.push('');
  for (const c of coverage) {
    lines.push(`## ${c.repo}`);
    lines.push('');
    lines.push('| channel | expected | resolved | verified | weak-link | 未链接主因 |');
    lines.push('| --- | ---: | ---: | ---: | ---: | --- |');
    for (const [ch, v] of Object.entries(c.byChannel).sort()) {
      const reasons = Object.entries(v.unlinkedReasons).sort((a, b) => b[1] - a[1]).slice(0, 3)
        .map(([k, n]) => `${k}(${n})`).join('; ') || '-';
      lines.push(`| ${ch} | ${v.expected} | ${v.resolved} | ${v.verified} | ${v.weakLinked} | ${reasons} |`);
    }
    lines.push('');
    lines.push(`来源分布：${Object.entries(c.byProvenance).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k}=${n}`).join(', ')}`);
    lines.push('');
  }
  lines.push('## 独立分母交叉核对');
  lines.push('');
  lines.push('| repo | 扫描源文件 | compdb 产品源文件 | compdb 覆盖率 | 扫描/compdb | IDL 方法 | dispatch case | harness 行 | parser 函数 | 现有 contracts |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const c of coverage) {
    const x = c.crossCheck;
    lines.push(`| ${c.repo} | ${x.sourceFilesScanned} | ${x.compdb ? x.compdb.productFiles : '-'} | ${x.fileIndexRate} | ${x.scanVsCompdbRatio} | ${x.ledgerCounts.idlMethods} | ${x.ledgerCounts.dispatchCases} | ${x.ledgerCounts.harnessRows} | ${x.ledgerCounts.parserFunctions} | ${x.currentContracts.total} |`);
  }
  lines.push('');
  for (const c of coverage) {
    lines.push(`### ${c.repo} 交叉核对`);
    lines.push('');
    lines.push(`- 扫描源文件 ${c.crossCheck.sourceFilesScanned}；compdb 产品源文件 ${c.crossCheck.compdb ? c.crossCheck.compdb.productFiles : 'N/A'}（${c.crossCheck.compdb ? c.crossCheck.compdb.part : '-'}，已排除 out/test/fuzztest/third_party）；compdb 覆盖率 ${c.crossCheck.fileIndexRate}；扫描/compdb ${c.crossCheck.scanVsCompdbRatio}`);
    lines.push(`- 台账来源：${Object.entries(c.byProvenance).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k}=${n}`).join(', ')}`);
    lines.push(`- 现有 contracts 来源：${Object.entries(c.currentContracts.byEvidence).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k}=${n}`).join(', ')}`);
    if (c.crossCheck.dispatchTable) {
      const d = c.crossCheck.dispatchTable;
      lines.push(`- 中心分发表：funcCode=${d.funcCodes}，permissionCode=${d.permCodes}，func 无 permission=${d.funcWithoutPermission}，permission 无 func=${d.permissionWithoutFunc}；harness code=${d.harnessCodes}，与分发表重合=${d.harnessOverlapWithDispatch}`);
    }
    lines.push('');
  }
  lines.push('## 说明');
  lines.push('');
  lines.push('- 现有 `contracts/entries.jsonl` 只覆盖 IPC/NAPI/SA 等部分通道；socket/HDI/parser/broadcast 在现有表里基本没有对应行，因此差距主要来自入口模型，不是扫描失败。');
  lines.push('- `verified` 只证明“找到了实现侧强证据”，不证明权限检查、控制流或数据流闭合。');
  lines.push('- `weak-link` 主要是 harness 调用点和 SA 声明：它们证明入口存在，不证明实现侧。');
  lines.push('- 本次没有实现语义契约合成，所以不报 ECR；SDR 是“枚举出的入口里能定位到身份的比例”，不是“预期入口被契约化的比例”。');
  lines.push('');
  ensureDir(path.join(OUT_ROOT, 'report'));
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'ecr.md'), lines.join('\n'), 'utf8');
  writeJson(path.join(OUT_ROOT, 'summary.json'), {
    generatedAt: new Date().toISOString(),
    snapshot: snap.repos,
    coverage: coverage.map((c) => ({ repo: c.repo, ...c.totals, currentContracts: c.currentContracts.total, crossCheck: c.crossCheck }))
  });
  return { coverage, snap };
}

function specdiff() {
  const r = runSpecDiff({ toolRoot: TOOL_ROOT, outRoot: OUT_ROOT, n: 20 });
  const s = r.summary;
  const lines = [];
  lines.push('# Patch spec 差分验证（20 条）');
  lines.push('');
  lines.push(`生成时间：${new Date().toISOString()}`);
  lines.push('');
  lines.push('这是 SpecAuditor 差分验证的机器可检半边：检查修复是否真的引入了 `witness`（前不存在、后存在）。语义约束是否成立仍需模型判断；当前无 `OH6_LLM_API_KEY`，只生成 `prompts/` 输入包。');
  lines.push('');
  lines.push('| 指标 | 值 |');
  lines.push('| --- | ---: |');
  lines.push(`| 选中 patch | ${s.selected} |`);
  lines.push(`| validated | ${s.validated} |`);
  lines.push(`| validity rate | ${s.validityRate} |`);
  lines.push(`| strict function-level validated | ${s.strictValidated} |`);
  lines.push(`| function-region fallback validated | ${s.functionFallbackValidated} |`);
  lines.push(`| hunk-window validated | ${s.windowValidated} |`);
  lines.push(`| pre-already | ${s.preAlready} |`);
  lines.push(`| post-absent | ${s.postAbsent} |`);
  lines.push(`| pre-missing | ${s.preMissing} |`);
  lines.push(`| post-missing | ${s.postMissing} |`);
  lines.push(`| extract-failed | ${s.extractFailed} |`);
  lines.push(`| fallback region | ${s.fallbackRegion} |`);
  lines.push(`| 输入自报 differentialOk | ${s.recordedDifferentialOk} |`);
  lines.push('');
  lines.push('## 按 family');
  lines.push('');
  lines.push('| family | total | validated |');
  lines.push('| --- | ---: | ---: |');
  for (const [f, v] of Object.entries(s.byFamily).sort()) lines.push(`| ${f} | ${v.total} | ${v.validated} |`);
  lines.push('');
  if (s.failures.length) {
    lines.push('## 未 validated 的条目');
    lines.push('');
    lines.push('| id | repo | file | family | status | reason |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const f of s.failures) lines.push(`| ${f.id} | ${f.repo} | ${f.file} | ${f.family} | ${f.status} | ${f.reason} |`);
    lines.push('');
  }
  lines.push('## 解释');
  lines.push('');
  lines.push('- `validated` 只说明该 patch 的 witness 在前后版本呈“缺失→出现”，这是 seed 可用性的必要条件，不是充分条件。');
  lines.push(`- 其中 ${s.strictValidated} 条是严格函数体区间，${s.windowValidated} 条退化为 hunk ±80 行窗口；后者更弱，但在 diff 定位/多行签名失败时是必要的兜底。`);
  lines.push('- `pre-already`/`post-absent` 可能是 witness 文本在函数体外、hunk 定位偏差，或 patch 实际修改了别的位置；需要人工看 `results.jsonl`。');
  lines.push('- 输入 88 条 `history-invariants` 全部自报 `differentialOk=true`；本实验是对该自报的独立复核。');
  lines.push('');
  fs.writeFileSync(path.join(OUT_ROOT, 'report', 'specdiff.md'), lines.join('\n'), 'utf8');
  return r;
}

const cmd = process.argv[2] || 'all';
if (cmd === 'snapshot') {
  const s = snapshot();
  process.stdout.write(`snapshot: ${s.repos.map((r) => `${r.repo}@${(r.head || '').slice(0, 8)} files=${r.cppFiles}`).join(' | ')}\n`);
} else if (cmd === 'ledger') {
  const r = ledger();
  for (const c of r.coverage) process.stdout.write(`${c.repo}: expected=${c.totals.expected} contracted=${c.totals.contracted} linked=${c.totals.linked} SDR=${c.totals.sdr} ILR=${c.totals.ilr}\n`);
} else if (cmd === 'specdiff') {
  const r = specdiff();
  process.stdout.write(`specdiff: selected=${r.summary.selected} validated=${r.summary.validated} rate=${r.summary.validityRate}\n`);
} else if (cmd === 'all') {
  const s = snapshot();
  process.stdout.write(`snapshot: ${s.repos.length} repos\n`);
  const r = ledger();
  for (const c of r.coverage) process.stdout.write(`${c.repo}: SDR=${c.totals.sdr} ILR=${c.totals.ilr}\n`);
  const d = specdiff();
  process.stdout.write(`specdiff: ${d.summary.validated}/${d.summary.selected} validated\n`);
} else {
  process.stderr.write('usage: node bin/audit.js snapshot|ledger|specdiff|all\n');
  process.exit(2);
}
