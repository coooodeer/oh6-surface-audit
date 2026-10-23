'use strict';

/**
 * p5-fixtures.js —— 生成/复算 P5 R1 fixtures。
 *
 * 产物：
 *   eval/p5/cases.jsonl
 *   out/p5/fixture-verdicts.jsonl
 *   out/p5/fixture-summary.json
 *
 * R1 历史正例只有 dsoftbus SendMessage 1 条；其余 10 条为 R1 synthetic mutants。
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { WORKSPACE, OUT_ROOT, ensureDir, readJsonl, writeJsonl, writeJson } = require('../lib/util.js');
const { loadL1 } = require('../lib/l1.js');
const { proveP5SourceCase } = require('../lib/prover-p5.js');

const EVAL = path.join(OUT_ROOT, '..', 'eval', 'p5');
const CASE_FILE = path.join(EVAL, 'cases.jsonl');
const DS_REPO = path.join(WORKSPACE, 'OpenHarmony', 'foundation', 'communication', 'dsoftbus');
const DS_FILE = 'core/frame/standard/init/src/softbus_server_stub.cpp';
const DS_FIX = 'dce957f30a4b6066390e1889a224819f88e97ca2';

function gitShow(revPath) {
  return cp.execFileSync('git', ['-C', DS_REPO, 'show', revPath], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function extractFunction(text, needle) {
  const lines = String(text).split(/\r?\n/);
  const start = lines.findIndex((l) => l.includes(needle));
  if (start < 0) return null;
  let open = -1;
  for (let i = start; i < Math.min(lines.length, start + 8); i += 1) {
    if (lines[i].includes('{')) { open = i; break; }
  }
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < lines.length; i += 1) {
    for (const ch of lines[i]) {
      if (ch === '{') depth += 1;
      if (ch === '}') depth -= 1;
    }
    if (depth === 0) return lines.slice(start, i + 1).join('\n');
  }
  return null;
}

function osFunctionSource(l1, file, name) {
  const fn = l1.functionsOfFile('base/account/os_account', file).find((f) => f.name === name);
  if (!fn) throw new Error(`function not found: ${file} ${name}`);
  const lines = l1.sourceLines('base/account/os_account', file);
  return { fn, lines, text: lines.slice(fn.startLine - 1, fn.endLine).join('\n') };
}

function removeLineBlock(lines, startIdx, count) {
  return [...lines.slice(0, startIdx), ...lines.slice(startIdx + count)];
}

function replaceOnce(text, from, to) {
  if (!text.includes(from)) throw new Error(`replace target not found: ${from}`);
  return text.replace(from, to);
}

function moveBlockAfterSink(lines, blockStart, blockCount, sinkRe) {
  const block = lines.slice(blockStart, blockStart + blockCount);
  const rest = removeLineBlock(lines, blockStart, blockCount);
  const sinkIdx = rest.findIndex((l) => sinkRe.test(l));
  if (sinkIdx < 0) throw new Error('sink not found');
  return [...rest.slice(0, sinkIdx + 1), ...block, ...rest.slice(sinkIdx + 1)];
}

function buildHistoricalCase() {
  const preText = gitShow(`${DS_FIX}^:${DS_FILE}`);
  const postText = gitShow(`${DS_FIX}:${DS_FILE}`);
  const pre = extractFunction(preText, 'int32_t SoftBusServerStub::SendMessageInner');
  const post = extractFunction(postText, 'int32_t SoftBusServerStub::SendMessageInner');
  if (!pre || !post) throw new Error('dsoftbus SendMessageInner extraction failed');
  return {
    id: 'P5-GT-01',
    scope: 'R1',
    kind: 'historical',
    repo: 'foundation/communication/dsoftbus',
    file: DS_FILE,
    function: 'SoftBusServerStub::SendMessageInner',
    fixCommit: DS_FIX,
    sinkPattern: 'SendMessage\\s*\\(\\s*channelId',
    checkPattern: 'CheckChannelPermission\\s*\\(',
    requiredArgs: ['channelId', 'channelType'],
    preSource: pre,
    postSource: post,
    expected: { pre: 'VIOLATION', post: 'SATISFIED', violatedObligation: 'O6' }
  };
}

function buildSyntheticCases(l1) {
  const a = osFunctionSource(l1, 'services/accountmgr/src/account_iam/account_iam_service.cpp', 'GetCredentialInfo');
  const b = osFunctionSource(l1, 'services/accountmgr/src/domain_account/domain_account_manager_service.cpp', 'Auth');
  const aLines = a.text.split(/\r?\n/);
  const bLines = b.text.split(/\r?\n/);
  const aCheckIdx = aLines.findIndex((l) => l.includes('CheckPermission(PERMISSION_USE_USER_IDM)'));
  const bCheckIdx = bLines.findIndex((l) => l.includes('CheckPermission(IDomainAccountIpcCode::COMMAND_AUTH)'));
  if (aCheckIdx < 0 || bCheckIdx < 0) throw new Error('synthetic base check not found');
  const aSinkRe = /InnerAccountIAMManager::GetInstance\(\)\.GetCredentialInfo/;
  const bSinkRe = /InnerDomainAccountManager::GetInstance\(\)\.Auth/;
  const cases = [];
  const add = (id, base, sourceKey, mutant, obligation) => {
    cases.push({
      id,
      scope: 'R1',
      kind: 'synthetic',
      repo: 'base/account/os_account',
      file: base.file,
      function: base.name,
      sinkPattern: base.sinkPattern,
      checkPattern: 'CheckPermission\\s*\\(',
      requiredPermission: base.requiredPermission,
      originalSource: base.originalSource,
      mutantSource: mutant,
      expected: { original: 'SATISFIED', mutant: 'VIOLATION', violatedObligation: obligation },
      fixCommit: null
    });
  };
  const baseA = { ...a, name: 'GetCredentialInfo', file: 'services/accountmgr/src/account_iam/account_iam_service.cpp', sinkPattern: aSinkRe.source, requiredPermission: 'PERMISSION_USE_USER_IDM', originalSource: a.text };
  const baseB = { ...b, name: 'Auth', file: 'services/accountmgr/src/domain_account/domain_account_manager_service.cpp', sinkPattern: bSinkRe.source, requiredPermission: 'COMMAND_AUTH', originalSource: b.text };

  // A1 remove check block
  add('P5-GT-02', baseA, 'mutant', removeLineBlock(aLines, aCheckIdx, 3).join('\n'), 'O6');
  // A2 disable check
  add('P5-GT-03', baseA, 'mutant', replaceOnce(a.text, 'if (!CheckPermission(PERMISSION_USE_USER_IDM)) {', 'if (false) {'), 'O6');
  // A3 wrong permission
  add('P5-GT-04', baseA, 'mutant', replaceOnce(a.text, 'PERMISSION_USE_USER_IDM', 'PERMISSION_MANAGE_USER_IDM'), 'O7');
  // A4 remove exit
  add('P5-GT-05', baseA, 'mutant', a.text.replace(/^\s*return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;\s*$/m, ''), 'O8');
  // A5 move check after sink
  add('P5-GT-06', baseA, 'mutant', moveBlockAfterSink(aLines, aCheckIdx, 3, aSinkRe).join('\n'), 'O8');
  // B1 remove check block
  add('P5-GT-07', baseB, 'mutant', removeLineBlock(bLines, bCheckIdx, 4).join('\n'), 'O6');
  // B2 disable exit branch
  add('P5-GT-08', baseB, 'mutant', replaceOnce(b.text, 'if (result != ERR_OK) {', 'if (false) {'), 'O8');
  // B3 wrong command/permission
  add('P5-GT-09', baseB, 'mutant', replaceOnce(b.text, 'COMMAND_AUTH', 'COMMAND_OTHER'), 'O7');
  // B4 remove exit
  add('P5-GT-10', baseB, 'mutant', b.text.replace(/^\s*return result;\s*$/m, ''), 'O8');
  // B5 move check after sink
  add('P5-GT-11', baseB, 'mutant', moveBlockAfterSink(bLines, bCheckIdx, 4, bSinkRe).join('\n'), 'O8');
  return cases;
}

function main() {
  ensureDir(EVAL);
  ensureDir(path.join(OUT_ROOT, 'p5'));
  const l1 = loadL1();
  const cases = [buildHistoricalCase(), ...buildSyntheticCases(l1)];
  writeJsonl(CASE_FILE, cases);
  const verdicts = [];
  let originalOk = 0;
  let mutantOk = 0;
  let historicalPre = 0;
  let historicalPost = 0;
  for (const c of cases) {
    if (c.kind === 'historical') {
      const pre = proveP5SourceCase(c, 'pre');
      const post = proveP5SourceCase(c, 'post');
      verdicts.push({ caseId: c.id, variant: 'pre', claimVerdict: pre.claimVerdict, expected: c.expected.pre, pass: pre.claimVerdict === c.expected.pre, analysis: pre.analysis });
      verdicts.push({ caseId: c.id, variant: 'post', claimVerdict: post.claimVerdict, expected: c.expected.post, pass: post.claimVerdict === c.expected.post, analysis: post.analysis });
      if (pre.claimVerdict === 'VIOLATION') historicalPre += 1;
      if (post.claimVerdict === 'SATISFIED') historicalPost += 1;
    } else {
      const orig = proveP5SourceCase(c, 'original');
      const mut = proveP5SourceCase(c, 'mutant');
      const oOk = orig.claimVerdict === c.expected.original;
      const mOk = mut.claimVerdict === c.expected.mutant;
      if (oOk) originalOk += 1;
      if (mOk) mutantOk += 1;
      verdicts.push({ caseId: c.id, variant: 'original', claimVerdict: orig.claimVerdict, expected: c.expected.original, pass: oOk, analysis: orig.analysis });
      verdicts.push({ caseId: c.id, variant: 'mutant', claimVerdict: mut.claimVerdict, expected: c.expected.mutant, pass: mOk, violatedObligation: c.expected.violatedObligation, analysis: mut.analysis });
    }
  }
  writeJsonl(path.join(OUT_ROOT, 'p5', 'fixture-verdicts.jsonl'), verdicts);
  const summary = {
    generatedAt: new Date().toISOString(),
    cases: cases.length,
    historical: { cases: cases.filter((c) => c.kind === 'historical').length, preViolation: historicalPre, postSatisfied: historicalPost },
    synthetic: { cases: cases.filter((c) => c.kind === 'synthetic').length, originalSatisfied: originalOk, mutantViolation: mutantOk },
    gate: historicalPre === 1 && historicalPost === 1 && originalOk === cases.filter((c) => c.kind === 'synthetic').length && mutantOk === cases.filter((c) => c.kind === 'synthetic').length,
    verdicts: verdicts.map((v) => ({ caseId: v.caseId, variant: v.variant, claimVerdict: v.claimVerdict, expected: v.expected, pass: v.pass }))
  };
  writeJson(path.join(OUT_ROOT, 'p5', 'fixture-summary.json'), summary);
  process.stdout.write(`P5 fixtures: cases=${cases.length} historical pre=${historicalPre}/1 post=${historicalPost}/1 synthetic original=${originalOk}/${summary.synthetic.cases} mutant=${mutantOk}/${summary.synthetic.cases} gate=${summary.gate}\n`);
  if (!summary.gate) {
    for (const v of summary.verdicts.filter((x) => !x.pass)) process.stdout.write(`  FAIL ${v.caseId} ${v.variant} got=${v.claimVerdict} expected=${v.expected}\n`);
    process.exit(2);
  }
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main, buildHistoricalCase, buildSyntheticCases };
