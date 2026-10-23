'use strict';

/**
 * lib/agent/classes.js —— P1–P8 的统一类适配层。
 *
 * 目标：不管类原先属于哪个 campaign，统一输出：
 *   { class, claimId, claim, verdict, tier, productVerdict, productionEligible }
 *
 * 当前实现不重写各类判定逻辑，只读取既有 runner 的 claims/verdicts 产物；
 * 上游 pipeline 可以按 class 选择要跑哪些 campaign。
 */

const fs = require('fs');
const path = require('path');
const AUDIT_ROOT = path.resolve(__dirname, '..', '..');
const { readSource, linesOf } = require('../p1p2p7p8/common.js');
const { tierOfProduct, normalizeTier } = require('../p1p2p7p8/common.js');

const CLASS_IDS = Object.freeze(['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8']);

const CLASS_GROUPS = Object.freeze([
  {
    id: 'p1p2p7p8',
    classes: ['P1', 'P2', 'P7', 'P8'],
    runner: 'bin/run-p1p2p7p8.js',
    args: []
  },
  {
    id: 'p3p4p6',
    classes: ['P3', 'P4', 'P6'],
    runner: 'bin/run-p3p4p6.js',
    args: ['--reuse-l4b', '--reuse-calibration']
  },
  {
    id: 'p5',
    classes: ['P5'],
    runner: 'bin/run-p5.js',
    args: []
  }
]);

const CLAIM_FILES = {
  P1: ['out/p1p2p7p8/claims.jsonl'],
  P2: ['out/p1p2p7p8/claims.jsonl'],
  P7: ['out/p1p2p7p8/claims.jsonl'],
  P8: ['out/p1p2p7p8/claims.jsonl'],
  P3: ['out/l3/p3-claims.jsonl'],
  P4: ['out/l3/p4-claims.jsonl'],
  P6: ['out/l3/p6-claims.jsonl'],
  P5: ['out/p5/claims.jsonl']
};

const VERDICT_FILES = {
  P1: ['out/p1p2p7p8/verdicts.jsonl'],
  P2: ['out/p1p2p7p8/verdicts.jsonl'],
  P7: ['out/p1p2p7p8/verdicts.jsonl'],
  P8: ['out/p1p2p7p8/verdicts.jsonl'],
  P3: ['out/l4a/p3-verdicts.jsonl'],
  P4: ['out/l4a/p4-verdicts.jsonl'],
  P6: ['out/l4a/p6-verdicts.jsonl'],
  P5: ['out/p5/verdicts.jsonl']
};

function readJsonlSafe(rel) {
  const file = path.join(AUDIT_ROOT, rel);
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch (_) { return null; }
  }).filter(Boolean);
}

function verdictIdOf(v) {
  return v && (v.claimId || v.verdictId);
}

function tierOf(v) {
  if (v && typeof v.tier === 'string') return normalizeTier(v.tier);
  return normalizeTier(tierOfProduct(v && v.productVerdict));
}

function isProduction(record) {
  return record && record.productionEligible === true && record.fixture !== true;
}

function loadClassArtifacts(classes = CLASS_IDS) {
  const wanted = new Set(classes);
  const claims = [];
  const verdicts = [];
  const byClaim = new Map();
  for (const cls of CLASS_IDS) {
    if (!wanted.has(cls)) continue;
    for (const rel of CLAIM_FILES[cls]) {
      for (const c of readJsonlSafe(rel)) {
        if (c.class !== cls) continue;
        if (!isProduction(c)) continue;
        claims.push(c);
      }
    }
    for (const rel of VERDICT_FILES[cls]) {
      for (const v of readJsonlSafe(rel)) {
        if (v.class !== cls) continue;
        if (!isProduction(v)) continue;
        verdicts.push(v);
        byClaim.set(verdictIdOf(v), v);
      }
    }
  }
  const records = claims.map((c) => {
    const v = byClaim.get(c.claimId) || null;
    return {
      class: c.class,
      claimId: c.claimId,
      claim: c,
      verdict: v,
      tier: tierOf(v || c),
      productVerdict: (v && v.productVerdict) || c.productVerdict || null,
      productionEligible: isProduction(c)
    };
  });
  return { claims, verdicts, records };
}

function groupForClass(cls) {
  return CLASS_GROUPS.find((g) => g.classes.includes(cls)) || null;
}

function groupsForClasses(classes) {
  const wanted = new Set(classes);
  return CLASS_GROUPS.filter((g) => g.classes.some((c) => wanted.has(c)));
}

const RESIDUAL_TIERS = Object.freeze(['T2-weak-candidate', 'T2-static-confirmed', 'T2-fact-needs-validation', 'T3-instrumentation-gap']);

/**
 * 选语义残差 claim：默认所有 production T2/T3（不是每类固定 2 条）。
 * opts.perClass > 0 时才限流；perClass=0/undefined 表示全量 T2/T3。
 */
function selectGlobalClaims(records, opts = {}) {
  if (typeof opts === 'number') opts = { perClass: opts };
  const tiers = new Set(opts.tiers || RESIDUAL_TIERS);
  const perClass = opts.perClass == null ? 0 : Number(opts.perClass);
  const out = [];
  for (const cls of CLASS_IDS) {
    const rows = records
      .filter((r) => r.class === cls && r.productionEligible && tiers.has(r.tier))
      .sort((a, b) => {
        const rank = (t) => (String(t).startsWith('T2') ? 0 : t === 'T3-instrumentation-gap' ? 1 : 2);
        return rank(a.tier) - rank(b.tier) || String(a.claimId).localeCompare(String(b.claimId));
      });
    out.push(...(perClass > 0 ? rows.slice(0, perClass) : rows));
  }
  return out;
}

function readEvidenceFile(candidates) {
  for (const rel of candidates) {
    if (!rel) continue;
    const text = readSource(rel);
    if (text != null) return { rel: String(rel).split(path.sep).join('/').replace(/^\/+/, ''), text };
  }
  return null;
}

function claimLocation(record) {
  const c = record.claim || {};
  const v = record.verdict || {};
  const entry = c.entry || {};
  const source = c.source || {};
  const sink = c.sink || {};
  const repo = entry.repo || source.repo || c.repo || null;
  const file = sink.file || source.file || v.file || c.file || entry.file || null;
  const line = sink.line || source.line || v.line || c.line || entry.line || null;
  return { repo, file, line, source, sink, entry };
}

function sourceCandidates(repo, file) {
  if (!file) return [];
  const f = String(file).split(path.sep).join('/');
  const out = [];
  if (repo) out.push(`${repo}/${f}`);
  out.push(f);
  if (repo && f.startsWith(`${repo}/`)) out.push(f);
  return [...new Set(out)];
}

function buildEvidence(record) {
  const loc = claimLocation(record);
  const found = readEvidenceFile(sourceCandidates(loc.repo, loc.file));
  const evidence = [];
  if (!found || !loc.line) return { evidence, file: loc.file, line: loc.line, repo: loc.repo };
  const lines = linesOf(found.text);
  const start = Math.max(1, loc.line - 3);
  const end = Math.min(lines.length, loc.line + 3);
  for (let ln = start; ln <= end; ln += 1) {
    evidence.push({
      ref: `E${evidence.length + 1}:L${ln}`,
      file: found.rel,
      line: ln,
      label: ln === loc.line ? 'sink' : 'context',
      text: String(lines[ln - 1] || '').slice(0, 800)
    });
  }
  return { evidence, file: found.rel, line: loc.line, repo: loc.repo };
}

const QUESTIONS = {
  P1: {
    question: 'sink 前是否存在支配性的上界/容量检查，且检查的是同一长度变量/表达式（不是下界、null、事后检查、错变量、死分支）？'
  },
  P2: {
    question: '被捕获对象的生命周期是否有保证（所有权转移、refcount/智能指针、join/wait、纯值捕获），或 release/delete 发生在安全边界内？'
  },
  P3: {
    question: 'producer 调用是否可能返回 nullptr/NULL（new(nothrow)、malloc、失败返回空等）？'
  },
  P4: {
    question: '算术/宽度/截断风险是否已被同一输入量上的检查覆盖，或操作数范围已受约束？'
  },
  P5: {
    question: '服务端是否存在覆盖该 sink 的 caller identity/permission/object identity 检查，而不是只在 client/调用方检查？'
  },
  P6: {
    question: 'payload 中是否包含敏感/受限数据（账号、设备标识、位置、通知内容、应用私有数据等）？'
  },
  P7: {
    question: '同一攻击者输入是否被 literal cap/limiter/有界循环约束（不是仅由输入自身长度有界）？'
  },
  P8: {
    question: '状态写入/释放/返回前是否有支配性的 invariant 守卫，且 invariant 确实适用于该写点？'
  }
};

function buildGlobalPack(record) {
  const c = record.claim || {};
  const v = record.verdict || {};
  const ev = buildEvidence(record);
  const isGap = record.tier === 'T3-instrumentation-gap';
  const mode = isGap ? 'complete-gap' : 'strengthen';
  const q = QUESTIONS[record.class] || { question: '该 claim 的语义义务是否成立？' };
  const question = isGap
    ? `${q.question} 该 claim 当前是 T3（instrumentation gap）：请指出缺什么证据，并尝试从给定证据中补全；不能补全就明确 unresolved。`
    : `${q.question} 该 claim 当前是 T2：请判断现有证据是支持（support）还是反驳（refute）这个 T2，或证据不足（unknown）。`;
  const obligations = (v.obligations || c.obligations || []).map((o) => ({
    id: o.id,
    kind: o.kind,
    status: o.status,
    reason: o.reason || null,
    evidence: o.id === 'O5' || o.id === 'O6'
      ? JSON.stringify(o.evidence || {}).slice(0, 500)
      : null
  }));
  const claimFacts = {};
  for (const k of ['unitId', 'candidateId', 'dosClass', 'invariantPattern', 'invariantAuthority', 'lifespan', 'analysis', 'structure', 'claimReason', 'productReason']) {
    if (c[k] !== undefined && c[k] !== null) claimFacts[k] = c[k];
  }
  if (c.source) {
    claimFacts.source = {};
    for (const k of ['kind', 'api', 'var', 'vars', 'captured', 'captureKind', 'attackerControlled', 'sizeTokens', 'text']) {
      if (c.source[k] !== undefined) claimFacts.source[k] = c.source[k];
    }
  }
  if (c.sink) {
    claimFacts.sink = {};
    for (const k of ['kind', 'callee', 'sizeExpr', 'stateVar', 'lifecycleOp', 'text']) {
      if (c.sink[k] !== undefined) claimFacts.sink[k] = c.sink[k];
    }
  }
  const evidence = ev.evidence.length ? ev.evidence : [{
    ref: 'E1:L1',
    file: ev.file || '',
    line: ev.line || 1,
    label: 'claim-location',
    text: `source=${JSON.stringify(c.source || {})} sink=${JSON.stringify(c.sink || {})}`
  }];
  return {
    id: `GLOBAL-L4B-${record.class}-${record.claimId}`,
    class: record.class,
    claimId: record.claimId,
    tier: record.tier,
    mode,
    productVerdict: record.productVerdict,
    repo: ev.repo || c.entry && c.entry.repo || null,
    file: ev.file || null,
    line: ev.line || null,
    source: c.source || null,
    sink: c.sink || null,
    entry: c.entry || null,
    claimFacts,
    obligations,
    evidence,
    refs: evidence.map((e) => e.ref),
    question,
    schema: '{"assessment":"support|refute|unknown","gapResolution":"completed|partial|unresolved|not-applicable","reason":"<=2 sentences","evidenceRefs":["E1:L12"],"missingEvidence":["..."],"suggestedEvidence":[{"ref":"E1:L12","why":"..."}]}'
  };
}

function buildMessages(pack) {
  const system = [
    '你是 OpenHarmony 静态审计的 L4b 语义证据器。只根据给定证据回答，不猜测。',
    'T2 任务（strengthen）：assessment=support|refute|unknown，判断现有证据支持还是反驳该 T2。',
    'T3 任务（complete-gap）：gapResolution=completed|partial|unresolved，指出缺口并尝试补全。',
    'T2 的 gapResolution 固定 not-applicable；T3 的 assessment 可为 support|refute|unknown。',
    '每个 evidenceRef 必须来自输入 refs；不要引用不存在的行。',
    '不要输出漏洞等级、T1 结论、修复建议或 Markdown；只输出 JSON 对象。',
    `schema: ${pack.schema}`
  ].join('\n');
  const evidence = pack.evidence.map((e) => `${e.ref} [${e.label}] ${e.file || ''}:${e.line || ''}  ${e.text}`).join('\n');
  const user = [
    `class: ${pack.class}`,
    `claimId: ${pack.claimId}`,
    `tier: ${pack.tier}`,
    `mode: ${pack.mode}`,
    `question: ${pack.question}`,
    '',
    `claimFacts: ${JSON.stringify(pack.claimFacts || {})}`,
    `obligations: ${JSON.stringify(pack.obligations)}`,
    '',
    '证据：',
    evidence,
    '',
    `只返回 JSON：${pack.schema}`
  ].join('\n');
  return [{ role: 'system', content: system }, { role: 'user', content: user }];
}

module.exports = {
  CLASS_IDS,
  CLASS_GROUPS,
  RESIDUAL_TIERS,
  CLAIM_FILES,
  VERDICT_FILES,
  readJsonlSafe,
  loadClassArtifacts,
  groupForClass,
  groupsForClasses,
  selectGlobalClaims,
  claimLocation,
  buildEvidence,
  QUESTIONS,
  buildGlobalPack,
  buildMessages
};
