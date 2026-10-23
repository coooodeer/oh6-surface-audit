'use strict';

/**
 * 把 out/specdiff/live/results.jsonl 并回 out/specdiff/{results.jsonl,summary.json}。
 * 机械字段保持原样，新增 `live` 与 `liveVerdict`；不重新调用模型。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const MECH = path.join(ROOT, 'out', 'specdiff', 'results.jsonl');
const LIVE = path.join(ROOT, 'out', 'specdiff', 'live', 'results.jsonl');
const SUMMARY = path.join(ROOT, 'out', 'specdiff', 'summary.json');

function readJsonl(file) {
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}
function writeJsonl(file, rows) {
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''), 'utf8');
}

const mech = readJsonl(MECH);
const liveRows = readJsonl(LIVE);
const live = new Map(liveRows.map((r) => [r.id, r]));

const merged = mech.map((m) => {
  const l = live.get(m.id);
  if (!l) return m;
  const parsed = l.parsed || null;
  let verdict = 'review';
  if (!l.ok) verdict = 'call-failed';
  else if (m.status === 'validated' && parsed && parsed.preViolates === true && parsed.postSatisfies === true) verdict = 'confirmed';
  else if (m.status === 'pre-already' && parsed && parsed.preViolates === false) verdict = 'seed-invalid';
  return {
    ...m,
    live: {
      ok: l.ok,
      kind: l.kind,
      model: l.model,
      preViolates: parsed ? parsed.preViolates : null,
      postSatisfies: parsed ? parsed.postSatisfies : null,
      reason: parsed ? parsed.reason : null,
      usage: l.usage,
      wallMs: l.wallMs,
      transportAttempts: l.transportAttempts || null
    },
    liveVerdict: verdict
  };
});
writeJsonl(MECH, merged);

const summary = JSON.parse(fs.readFileSync(SUMMARY, 'utf8'));
const ok = liveRows.filter((r) => r.ok);
summary.live = {
  prompts: liveRows.length,
  calls: liveRows.reduce((a, r) => a + ((r.transportAttempts || 1)), 0),
  ok: ok.length,
  confirmed: merged.filter((r) => r.liveVerdict === 'confirmed').length,
  seedInvalid: merged.filter((r) => r.liveVerdict === 'seed-invalid').length,
  review: merged.filter((r) => r.liveVerdict === 'review').length,
  failed: merged.filter((r) => r.liveVerdict === 'call-failed').length,
  promptTokens: ok.reduce((a, r) => a + ((r.usage && r.usage.promptTokens) || 0), 0),
  completionTokens: ok.reduce((a, r) => a + ((r.usage && r.usage.completionTokens) || 0), 0)
};
fs.writeFileSync(SUMMARY, JSON.stringify(summary, null, 2) + '\n', 'utf8');

console.log(JSON.stringify(summary.live, null, 2));
