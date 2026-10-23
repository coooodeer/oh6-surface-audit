'use strict';

/**
 * spec-prover.js —— 3 条 concrete spec 的义务化试点。
 *
 * 输入：本文件内的 PILOT（手工把 3 条 spec 落成义务）+ 原函数 + 人工变异体。
 * 输出：out/specprover/{results.jsonl,summary.json}、out/report/specprover.md
 *
 * 纪律：
 *   - 原函数只读；变异体写到 out/specprover/mutants/，不改 OpenHarmony/。
 *   - 每条义务只做“可机械检查”的半边；路径敏感/别名分析没做的，写 unproven 或 caveat，不冒充证明。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, '..', 'OpenHarmony');
const OUT = path.join(ROOT, 'out', 'specprover');
const REPORT = path.join(ROOT, 'out', 'report', 'specprover.md');

function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }
function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}
function writeJsonl(file, rows) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''), 'utf8');
}
function writeJson(file, obj) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}
function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text[i] === '\n') n += 1;
  return n;
}
function matchBrace(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i += 1) {
    const c = text[i];
    if (c === '"' || c === "'") {
      const q = c; i += 1;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === q) break;
        i += 1;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i += 1; continue; }
    if (c === '/' && text[i + 1] === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1; i += 1; continue; }
    if (c === '{') depth += 1;
    else if (c === '}') { depth -= 1; if (depth === 0) return i; }
  }
  return -1;
}

/** 找函数定义体（跳过声明/调用） */
function findFunction(text, name) {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`${esc}\\s*\\(`, 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    let i = text.indexOf('(', m.index);
    let depth = 0;
    for (; i < text.length; i += 1) {
      if (text[i] === '(') depth += 1;
      else if (text[i] === ')') { depth -= 1; if (depth === 0) { i += 1; break; } }
    }
    let k = i;
    while (k < text.length && /\s/.test(text[k])) k += 1;
    while (k < text.length && text[k] !== ';' && text[k] !== '{') k += 1;
    if (text[k] !== '{') continue;
    const close = matchBrace(text, k);
    if (close < 0) continue;
    return { name, startLine: lineOf(text, m.index), openLine: lineOf(text, k), endLine: lineOf(text, close), body: text.slice(k, close + 1), openIdx: k, closeIdx: close };
  }
  return null;
}

function findLine(lines, regex, from = 0) {
  for (let i = from; i < lines.length; i += 1) if (regex.test(lines[i])) return i;
  return -1;
}
function findMatchOnLine(line, regex) {
  const m = new RegExp(regex.source, regex.flags.replace('g', '')).exec(line);
  return m ? m.index : -1;
}
function blockAfter(lines, guardIdx) {
  let open = -1;
  for (let i = guardIdx; i < Math.min(lines.length, guardIdx + 4); i += 1) {
    const p = lines[i].indexOf('{');
    if (p >= 0) { open = { line: i, col: p }; break; }
  }
  if (!open) return null;
  const text = lines.slice(open.line).join('\n');
  const close = matchBrace(text, open.col);
  if (close < 0) return null;
  const block = text.slice(0, close + 1);
  const endLine = open.line + block.split('\n').length - 1;
  return { start: open.line, end: endLine, text: block };
}

const PILOT = [
  {
    specId: 'SPEC-INV-HIST-35502e63-c1',
    seedId: 'INV-HIST-35502e63',
    title: 'dsoftbus GetGenUkInstanceByReq：共享实例访问前的判空/锁守卫',
    repo: 'foundation/communication/dsoftbus',
    file: 'core/authentication/userkey/auth_uk_manager.c',
    functionName: 'GetGenUkInstanceByReq',
    obligations: [
      { id: 'A1', kind: 'guard-before-sink', text: 'g_ukNegotiateList 在遍历前判空', guard: 'g_ukNegotiateList\\s*==\\s*NULL', sink: 'LIST_FOR_EACH_ENTRY_SAFE\\s*\\(', requireExit: true },
      { id: 'A2', kind: 'guard-before-sink', text: 'instance 在 memcpy_s 前判空', guard: 'instance\\s*!=\\s*NULL', sink: 'memcpy_s\\s*\\(\\s*instance', requireExit: false },
      { id: 'A3', kind: 'lock-acquire-before-sink', text: '遍历前获得 ukNegotiateList 锁', acquire: 'RequireUkNegotiateListLock\\s*\\(', sink: 'LIST_FOR_EACH_ENTRY_SAFE\\s*\\(' },
      { id: 'A4', kind: 'lock-release-on-return', text: '获取锁后每个成功路径 return 前释放', acquire: 'RequireUkNegotiateListLock\\s*\\(', release: 'ReleaseUkNegotiateListLock\\s*\\(' },
      { id: 'A5', kind: 'guard-branch-exits', text: 'A1 的判空分支必须 return，不得继续', guard: 'g_ukNegotiateList\\s*==\\s*NULL', exit: 'return\\s+SOFTBUS_NO_INIT' }
    ]
  },
  {
    specId: 'SPEC-INV-HIST-298acf58-c1',
    seedId: 'INV-HIST-298acf58',
    title: 'ability_runtime DataAbilityManager::Acquire：共享记录/调度器生命周期守卫',
    repo: 'foundation/ability/ability_runtime',
    file: 'services/abilitymgr/src/data_ability/data_ability_manager.cpp',
    functionName: 'DataAbilityManager::Acquire',
    obligations: [
      { id: 'B1', kind: 'guard-before-sink', text: 'clientAbilityRecord 在解引用前判空', guard: '!\\s*clientAbilityRecord', sink: 'clientAbilityRecord\\s*->', requireExit: true },
      { id: 'B2', kind: 'guard-before-sink', text: 'dataAbilityRecord 在解引用前判空', guard: '!\\s*dataAbilityRecord', sink: 'dataAbilityRecord\\s*->', requireExit: true },
      { id: 'B3', kind: 'guard-before-sink', text: 'scheduler 在返回前判空', guard: '!\\s*scheduler', sink: 'return\\s+scheduler', requireExit: true },
      { id: 'B4', kind: 'lock-acquire-before-sink', text: '修改 dataAbilityRecordsLoaded_ 前持有锁', acquire: 'lock_guard\\s*<\\s*ffrt::mutex\\s*>\\s+locker\\s*\\(\\s*mutex_\\s*\\)', sink: 'dataAbilityRecordsLoaded_\\.(?:find|erase)' }
    ]
  },
  {
    specId: 'SPEC-INV-HIST-99d126b9-c3',
    seedId: 'INV-HIST-99d126b9',
    title: 'os_account UnsubscribeOsAccountConstraints：注销前校验订阅记录存在',
    repo: 'base/account/os_account',
    file: 'services/accountmgr/src/osaccount/os_account_constraint_subscribe_manager.cpp',
    functionName: 'UnsubscribeOsAccountConstraints',
    obligations: [
      { id: 'C1', kind: 'guard-before-sink', text: 'eventListener 在 RemoveDeathRecipient 前判空', guard: 'eventListener\\s*==\\s*nullptr', sink: 'eventListener\\s*->\\s*RemoveDeathRecipient', requireExit: true },
      { id: 'C2', kind: 'lock-acquire-before-sink', text: '修改 constraintRecords_ 前持有锁', acquire: 'lock_guard\\s*<\\s*std::mutex\\s*>\\s+lock\\s*\\(\\s*mutex_\\s*\\)', sink: 'RemoveConstraintFromSubscribeRecord\\s*\\(' },
      { id: 'C3', kind: 'existence-check-before-mutation', text: '修改前按 eventListener_ 找到匹配记录；找不到返回错误', existence: 'recordPtr->eventListener_\\s*!=\\s*eventListener', mutation: 'RemoveConstraintFromSubscribeRecord\\s*\\(', notFound: 'return\\s+ERR_ACCOUNT_COMMON_ACCOUNT_SUBSCRIBE_NOT_FOUND_ERROR' },
      { id: 'C4', kind: 'guard-branch-exits', text: 'C1 的判空分支必须 return，不得继续', guard: 'eventListener\\s*==\\s*nullptr', exit: 'return\\s+ERR_ACCOUNT_COMMON_NULL_PTR_ERROR' }
    ]
  }
];

function absOf(entry, override) {
  if (override) return override;
  return path.join(SRC, entry.repo, entry.file);
}

function evalObligation(o, ctx) {
  const { lines, fn } = ctx;
  const base = fn.openLine - 1; // body lines[0] is the line of '{', absolute line = base+1
  const ev = {};
  const guardIdx = o.guard ? findLine(lines, new RegExp(o.guard)) : -1;
  const sinkRegex = o.sink || o.mutation;
  const sinkIdx = sinkRegex ? findLine(lines, new RegExp(sinkRegex)) : -1;

  if (o.kind === 'guard-before-sink') {
    if (guardIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-missing', evidence: {} };
    if (sinkIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'sink-not-found', evidence: { guardLine: base + guardIdx + 1 } };
    const sameLine = guardIdx === sinkIdx;
    const guardPos = sameLine ? findMatchOnLine(lines[guardIdx], new RegExp(o.guard)) : 0;
    const sinkPos = sameLine ? findMatchOnLine(lines[sinkIdx], new RegExp(o.sink)) : 0;
    ev.guardLine = base + guardIdx + 1;
    ev.sinkLine = base + sinkIdx + 1;
    if (guardIdx > sinkIdx || (sameLine && guardPos >= sinkPos)) {
      return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-after-sink', evidence: ev };
    }
    if (o.requireExit) {
      const block = blockAfter(lines, guardIdx);
      if (!block || !/(return|continue|break|goto)\b/.test(block.text)) {
        return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-without-exit', evidence: ev };
      }
      ev.exitLine = base + block.start + 1;
    }
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'guard-before-sink', evidence: ev };
  }

  if (o.kind === 'guard-branch-exits') {
    if (guardIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'guard-missing', evidence: {} };
    const block = blockAfter(lines, guardIdx);
    ev.guardLine = base + guardIdx + 1;
    if (!block) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'no-guard-block', evidence: ev };
    ev.blockStart = base + block.start + 1;
    ev.blockEnd = base + block.end + 1;
    if (!new RegExp(o.exit).test(block.text)) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'exit-missing', evidence: ev };
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'guard-exits', evidence: ev };
  }

  if (o.kind === 'lock-acquire-before-sink') {
    const acqIdx = findLine(lines, new RegExp(o.acquire));
    if (acqIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'acquire-missing', evidence: {} };
    if (sinkIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'sink-not-found', evidence: { acquireLine: base + acqIdx + 1 } };
    ev.acquireLine = base + acqIdx + 1;
    ev.sinkLine = base + sinkIdx + 1;
    if (acqIdx > sinkIdx) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'acquire-after-sink', evidence: ev };
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'acquire-before-sink', evidence: ev };
  }

  if (o.kind === 'lock-release-on-return') {
    const acqIdx = findLine(lines, new RegExp(o.acquire));
    if (acqIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'acquire-missing', evidence: {} };
    // 排除 acquire 失败分支里的 return（还没拿到锁）
    let failBlock = null;
    for (let i = Math.max(0, acqIdx - 3); i <= acqIdx; i += 1) {
      if (/\bif\s*\(/.test(lines[i]) && /Require|lock|Lock/.test(lines[i])) { failBlock = blockAfter(lines, i); break; }
    }
    const failRange = failBlock ? [failBlock.start, failBlock.end] : null;
    const releases = [];
    for (let i = acqIdx + 1; i < lines.length; i += 1) if (new RegExp(o.release).test(lines[i])) releases.push(i);
    const missing = [];
    for (let i = acqIdx + 1; i < lines.length; i += 1) {
      if (!/\breturn\b/.test(lines[i])) continue;
      if (failRange && i >= failRange[0] && i <= failRange[1]) continue;
      const hasRelease = releases.some((r) => r < i);
      if (!hasRelease) missing.push(base + i + 1);
    }
    ev.acquireLine = base + acqIdx + 1;
    ev.releaseLines = releases.map((i) => base + i + 1);
    if (missing.length) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'return-without-release', evidence: { ...ev, missing } };
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'release-before-each-return', evidence: ev };
  }

  if (o.kind === 'existence-check-before-mutation') {
    const exIdx = findLine(lines, new RegExp(o.existence));
    const mutIdx = findLine(lines, new RegExp(o.mutation));
    if (exIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'existence-check-missing', evidence: {} };
    if (mutIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'mutation-not-found', evidence: { existenceLine: base + exIdx + 1 } };
    const notFoundIdx = findLine(lines, new RegExp(o.notFound), mutIdx);
    ev.existenceLine = base + exIdx + 1;
    ev.mutationLine = base + mutIdx + 1;
    if (exIdx > mutIdx) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'existence-check-after-mutation', evidence: ev };
    if (notFoundIdx < 0) return { id: o.id, kind: o.kind, text: o.text, status: 'disproven', reason: 'not-found-return-missing', evidence: ev };
    ev.notFoundLine = base + notFoundIdx + 1;
    return { id: o.id, kind: o.kind, text: o.text, status: 'proven', reason: 'existence-then-mutate', evidence: ev };
  }

  return { id: o.id, kind: o.kind, text: o.text, status: 'unproven', reason: 'unsupported-obligation-kind', evidence: {} };
}

function prove(entry, filePath, variant) {
  const text = fs.readFileSync(filePath, 'utf8');
  const fn = findFunction(text, entry.functionName);
  if (!fn) return { specId: entry.specId, variant, file: filePath, ok: false, error: 'function-not-found', verdict: 'UNPROVEN', obligations: [] };
  const bodyLines = fn.body.split(/\r?\n/);
  const ctx = { lines: bodyLines, fn };
  const obs = entry.obligations.map((o) => evalObligation(o, ctx));
  const disproven = obs.filter((o) => o.status === 'disproven');
  const unproven = obs.filter((o) => o.status === 'unproven');
  const verdict = disproven.length ? 'VIOLATION' : (unproven.length ? 'UNPROVEN' : 'SATISFIED');
  return {
    specId: entry.specId,
    seedId: entry.seedId,
    title: entry.title,
    variant,
    repo: entry.repo,
    file: entry.file,
    function: entry.functionName,
    functionRange: { start: fn.startLine, end: fn.endLine },
    verdict,
    disproven: disproven.map((o) => ({ id: o.id, reason: o.reason, evidence: o.evidence })),
    unproven: unproven.map((o) => ({ id: o.id, reason: o.reason, evidence: o.evidence })),
    obligations: obs
  };
}

function mutateInFunction(text, functionName, pattern, replacement) {
  const fn = findFunction(text, functionName);
  if (!fn) throw new Error(`function not found: ${functionName}`);
  const body = text.slice(fn.openIdx, fn.closeIdx + 1);
  const present = pattern instanceof RegExp ? pattern.test(body) : body.includes(pattern);
  if (!present) throw new Error(`mutation pattern not found in ${functionName}`);
  const mutatedBody = body.replace(pattern, replacement);
  return text.slice(0, fn.openIdx) + mutatedBody + text.slice(fn.closeIdx + 1);
}

function makeMutants() {
  const dir = path.join(OUT, 'mutants');
  ensureDir(dir);
  const specs = {};
  // A：删除目标函数里的 g_ukNegotiateList 判空块
  const aSrc = path.join(SRC, PILOT[0].repo, PILOT[0].file);
  const aText = fs.readFileSync(aSrc, 'utf8');
  const aBlock = /    if \(g_ukNegotiateList == NULL\) \{\n[\s\S]*?return SOFTBUS_NO_INIT;\n    \}\n/;
  const aMut = mutateInFunction(aText, PILOT[0].functionName, aBlock, '');
  if (/g_ukNegotiateList\s*==\s*NULL/.test(findFunction(aMut, PILOT[0].functionName).body)) throw new Error('mutant A not effective');
  fs.writeFileSync(path.join(dir, 'A_auth_uk_manager.c'), aMut, 'utf8');
  specs.A = path.join(dir, 'A_auth_uk_manager.c');
  // B：删除目标函数里的 clientAbilityRecord 判空块
  const bSrc = path.join(SRC, PILOT[1].repo, PILOT[1].file);
  const bText = fs.readFileSync(bSrc, 'utf8');
  const bBlock = /        if \(!clientAbilityRecord\) \{\n[\s\S]*?return nullptr;\n        \}\n/;
  const bMut = mutateInFunction(bText, PILOT[1].functionName, bBlock, '');
  if (/!\s*clientAbilityRecord/.test(findFunction(bMut, PILOT[1].functionName).body)) throw new Error('mutant B not effective');
  fs.writeFileSync(path.join(dir, 'B_data_ability_manager.cpp'), bMut, 'utf8');
  specs.B = path.join(dir, 'B_data_ability_manager.cpp');
  // C：把目标函数里的 eventListener_ 匹配改成 if (false)
  const cSrc = path.join(SRC, PILOT[2].repo, PILOT[2].file);
  const cText = fs.readFileSync(cSrc, 'utf8');
  const cBlock = 'if (recordPtr->eventListener_ != eventListener) {';
  const cMut = mutateInFunction(cText, PILOT[2].functionName, cBlock, 'if (false) {');
  if (/recordPtr->eventListener_\s*!=\s*eventListener/.test(findFunction(cMut, PILOT[2].functionName).body)) throw new Error('mutant C not effective');
  fs.writeFileSync(path.join(dir, 'C_os_account_constraint.cpp'), cMut, 'utf8');
  specs.C = path.join(dir, 'C_os_account_constraint.cpp');
  return specs;
}

function main() {
  ensureDir(OUT);
  const mutants = makeMutants();
  const results = [];
  for (const entry of PILOT) {
    results.push(prove(entry, absOf(entry), 'original'));
    const key = entry.specId.includes('35502e63') ? 'A' : entry.specId.includes('298acf58') ? 'B' : 'C';
    results.push(prove(entry, mutants[key], `mutant-${key}`));
  }
  writeJsonl(path.join(OUT, 'results.jsonl'), results);
  const summary = {
    generatedAt: new Date().toISOString(),
    specs: PILOT.length,
    original: results.filter((r) => r.variant === 'original').map((r) => ({ specId: r.specId, verdict: r.verdict })),
    mutants: results.filter((r) => r.variant !== 'original').map((r) => ({ specId: r.specId, variant: r.variant, verdict: r.verdict, disproven: r.disproven })),
    discriminative: PILOT.every((entry) => {
      const orig = results.find((r) => r.specId === entry.specId && r.variant === 'original');
      const mut = results.find((r) => r.specId === entry.specId && r.variant !== 'original');
      return orig && mut && orig.verdict === 'SATISFIED' && mut.verdict === 'VIOLATION';
    })
  };
  writeJson(path.join(OUT, 'summary.json'), summary);

  const lines = [];
  lines.push('# 3 条 spec 的义务化试点');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push('| spec | 原函数 | 变异体 |');
  lines.push('| --- | --- | --- |');
  for (const entry of PILOT) {
    const o = results.find((r) => r.specId === entry.specId && r.variant === 'original');
    const m = results.find((r) => r.specId === entry.specId && r.variant !== 'original');
    lines.push(`| ${entry.specId} | ${o ? o.verdict : '?'} | ${m ? m.verdict : '?'} |`);
  }
  lines.push('');
  lines.push(`判别力：${summary.discriminative ? '3/3 原函数 SATISFIED，3/3 变异体 VIOLATION' : '未全部符合预期'}`);
  lines.push('');
  for (const entry of PILOT) {
    lines.push(`## ${entry.specId}`);
    lines.push('');
    lines.push(`- 函数：\`${entry.functionName}\`（${entry.repo}/${entry.file}）`);
    lines.push(`- 义务：${entry.obligations.map((o) => o.id).join(' / ')}`);
    for (const variant of ['original', `mutant-${entry.specId.includes('35502e63') ? 'A' : entry.specId.includes('298acf58') ? 'B' : 'C'}`]) {
      const r = results.find((x) => x.specId === entry.specId && x.variant === variant);
      if (!r) continue;
      lines.push(`- ${variant}：\`${r.verdict}\``);
      for (const o of r.obligations) {
        const ev = Object.entries(o.evidence || {}).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ');
        lines.push(`  - ${o.id} ${o.status}（${o.reason}${ev ? `；${ev}` : ''}）`);
      }
    }
    lines.push('');
  }
  lines.push('## 口径');
  lines.push('');
  lines.push('- 义务是手工从 3 条 concrete spec 落下来的；prover 只做行级/块级检查，不是完整 CFG/别名/路径敏感分析。');
  lines.push('- `lock-release-on-return` 只检查“return 前是否有 release”，并把 acquire 失败分支排除；没有建模异常路径。');
  lines.push('- 变异体只写入 `out/specprover/mutants/`，不改 `OpenHarmony/`；目的是验证 prover 的判别力，不是真实漏洞。');
  lines.push('- `SATISFIED` 只表示当前义务都成立；`VIOLATION` 只表示某条义务被机械反证。两者都不是漏洞报告。');
  lines.push('');
  ensureDir(path.dirname(REPORT));
  fs.writeFileSync(REPORT, lines.join('\n'), 'utf8');
  process.stdout.write(`prover: ${results.filter((r) => r.variant === 'original' && r.verdict === 'SATISFIED').length}/3 original satisfied; discriminative=${summary.discriminative}\n`);
}

main();
