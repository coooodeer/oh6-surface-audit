'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'out');
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const readJsonl = (p) => fs.readFileSync(p, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

test('calibration: 3 rounds × 20 samples, no false PROVEN-VULN, pass', () => {
  const s = readJson(path.join(OUT, 'report', 'calibration-summary.json'));
  assert.equal(s.rounds.length, 3);
  assert.equal(s.totalSampled, 60);
  assert.equal(s.accepted, 30);
  assert.equal(s.rejected, 30);
  assert.equal(s.programmaticUnsupported, 0);
  assert.equal(s.falseProvenVuln, 0);
  assert.ok(s.semanticReviewed >= 3, `semanticReviewed=${s.semanticReviewed}`);
  assert.equal(s.pass, true);
});

test('calibration: CALIBRATION-LOG.jsonl fields and evidence hashes', () => {
  const rows = readJsonl(path.join(OUT, 'report', 'CALIBRATION-LOG.jsonl'));
  assert.equal(rows.length, 60);
  for (const r of rows) {
    for (const k of ['caseId', 'class', 'originalVerdict', 'evidenceHash', 'reviewVerdict', 'errorType', 'action', 'regressionCase']) {
      assert.ok(Object.prototype.hasOwnProperty.call(r, k), `${r.caseId} missing ${k}`);
    }
    assert.match(r.evidenceHash, /^[0-9a-f]{16}$/);
    assert.ok(['accepted', 'rejected'].includes(r.side));
  }
  assert.ok(rows.some((r) => r.reviewMethod === 'semantic'));
  assert.ok(rows.some((r) => r.holdout === true));
});

test('calibration: report and per-call log exist; no key material', () => {
  assert.ok(fs.existsSync(path.join(OUT, 'report', 'calibration.md')));
  const logFile = path.join(ROOT, 'logs', 'calibration.jsonl');
  assert.ok(fs.existsSync(logFile));
  const text = fs.readFileSync(logFile, 'utf8');
  assert.ok(!/Bearer|authorization|OH6_LLM_API_KEY\s*=/i.test(text));
  const rows = readJsonl(logFile);
  assert.ok(rows.length >= 3);
  for (const r of rows) {
    assert.ok(r.unitId && r.caseId);
    assert.ok(Number.isFinite(r.promptTokens) && Number.isFinite(r.completionTokens));
    assert.ok('contentHash' in r);
  }
});

test('token ledger exists and accounts for L4b + calibration tokens', () => {
  const t = readJson(path.join(OUT, 'report', 'token-ledger.json'));
  assert.ok(t.totalTokens > 0);
  assert.ok(t.l4b.totalTokens > 0);
  assert.ok(t.decisiveClaims >= 100);
  assert.ok(fs.existsSync(path.join(ROOT, 'logs', 'l4b.jsonl')));
});
