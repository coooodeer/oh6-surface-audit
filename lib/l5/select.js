'use strict';

/**
 * lib/l5/select.js —— 从 production T2/T3 中选择可尝试动态验证的候选。
 *
 * P1/P2/P3/P4/P7 有 host-harness 通道；P5/P6/P8 当前 unsupported。
 * 这里只做选择，不产生任何动态结果。
 */

const path = require('path');
const { ensureDir, writeJson, writeJsonl } = require('../util.js');
const { CLASS_IDS, loadClassArtifacts, claimLocation } = require('../agent/classes.js');
const { OUT_ROOT } = require('../util.js');
const { TEST_PATH_RE } = require('../l7/model.js');

const L5_CLASSES = new Set(['P1', 'P2', 'P3', 'P4', 'P7']);
const HARNESS = {
  P1: { kind: 'function-driver', expectedSignal: 'asan', priority: 10 },
  P2: { kind: 'function-driver', expectedSignal: 'asan', priority: 10 },
  P3: { kind: 'function-driver', expectedSignal: 'ubsan', priority: 20 },
  P4: { kind: 'function-driver', expectedSignal: 'ubsan', priority: 20 },
  P7: { kind: 'timeout-driver', expectedSignal: 'timeout/rss', priority: 30 }
};

function selectCandidates(opts = {}) {
  const loaded = loadClassArtifacts(CLASS_IDS);
  const out = [];
  const unsupported = [];
  for (const record of loaded.records) {
    const cls = record.class;
    const tierOk = String(record.tier || '').startsWith('T2') || record.tier === 'T3-instrumentation-gap';
    if (!tierOk) continue;
    const loc = claimLocation(record);
    if (TEST_PATH_RE.test(String(loc.file || ''))) {
      unsupported.push({ claimId: record.claimId, class: cls, tier: record.tier, reason: 'test-only-path' });
      continue;
    }
    if (!L5_CLASSES.has(cls)) {
      unsupported.push({ claimId: record.claimId, class: cls, tier: record.tier, reason: 'unsupported:needs-integration-harness' });
      continue;
    }
    if (!loc.file || !loc.line) {
      unsupported.push({ claimId: record.claimId, class: cls, tier: record.tier, reason: 'missing-source-location' });
      continue;
    }
    const h = HARNESS[cls];
    out.push({
      candidateId: `L5-${cls}-${String(record.claimId).replace(/[^A-Za-z0-9_-]/g, '_')}`,
      claimId: record.claimId,
      class: cls,
      tier: record.tier,
      repo: loc.repo || null,
      file: loc.file,
      line: loc.line,
      function: (record.claim.entry && record.claim.entry.function) || null,
      harnessKind: h.kind,
      expectedSignal: h.expectedSignal,
      priority: h.priority,
      reason: record.verdict && (record.verdict.productReason || record.verdict.reason) || null
    });
  }
  out.sort((a, b) => a.priority - b.priority || a.class.localeCompare(b.class) || String(a.claimId).localeCompare(String(b.claimId)));
  const capped = opts.limit > 0 ? out.slice(0, opts.limit) : out;
  const summary = {
    generatedAt: new Date().toISOString(),
    total: out.length,
    selected: capped.length,
    byClass: Object.fromEntries([...L5_CLASSES].map((c) => [c, capped.filter((x) => x.class === c).length])),
    byClassAll: Object.fromEntries(CLASS_IDS.map((c) => [c, capped.filter((x) => x.class === c).length])),
    unsupported: unsupported.length,
    unsupportedReasons: unsupported.reduce((m, x) => { m[x.reason] = (m[x.reason] || 0) + 1; return m; }, {})
  };
  const outDir = path.join(OUT_ROOT, 'l5');
  ensureDir(outDir);
  writeJsonl(path.join(outDir, 'candidates.jsonl'), capped);
  writeJsonl(path.join(outDir, 'unsupported.jsonl'), unsupported);
  writeJson(path.join(outDir, 'select-summary.json'), summary);
  return { candidates: capped, unsupported, summary };
}

module.exports = { L5_CLASSES, HARNESS, selectCandidates };
