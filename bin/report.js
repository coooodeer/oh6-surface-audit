#!/usr/bin/env node
'use strict';

/**
 * bin/report.js —— L7 finding/report/delivery 入口。
 *
 *   node bin/report.js --all
 *   node bin/report.js --all --delivery
 *   node bin/report.js --all --json
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { OUT_ROOT, ensureDir, writeJson, writeJsonl, sha256 } = require('../lib/util.js');
const { buildL7 } = require('../lib/l7/model.js');
const { renderCard, renderIndex, renderExecutive } = require('../lib/l7/render.js');

const REPORT_DIR = path.join(OUT_ROOT, 'report');
const FINDINGS_DIR = path.join(REPORT_DIR, 'findings');
const DELIVERY_DIR = path.join(OUT_ROOT, 'delivery');

function parseArgs(argv) {
  const opts = { all: false, delivery: false, json: false, includeL5: false, help: false };
  for (const a of argv) {
    if (a === '--all') opts.all = true;
    else if (a === '--delivery') opts.delivery = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--include-l5') opts.includeL5 = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

function fileHash(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function requiredCardErrors(card) {
  const errors = [];
  for (const k of ['findingId', 'claimId', 'class', 'tier', 'title', 'component', 'file', 'line', 'weakness', 'evidence', 'obligations', 'attackScenario', 'impact', 'severity', 'remediation', 'status']) {
    if (card[k] === undefined || card[k] === null || card[k] === '') errors.push(k);
  }
  if (!Array.isArray(card.evidence) || card.evidence.length === 0) errors.push('evidence-empty');
  if (!card.severity || !card.severity.level || !card.severity.rationale) errors.push('severity');
  return errors;
}

function buildSummary(data) {
  const cards = data.cards;
  const observations = data.observations;
  const claimIds = new Set();
  for (const c of cards) for (const id of c.claimIds || [c.claimId]) if (id) claimIds.add(id);
  const excluded = data.excluded || [];
  const excludedT2 = excluded.filter((e) => String(e.tier || '').startsWith('T2')).length;
  const excludedT3 = excluded.filter((e) => String(e.tier || '').startsWith('T3')).length;
  const schemaErrors = cards.map((c) => ({ findingId: c.findingId, errors: requiredCardErrors(c) })).filter((x) => x.errors.length);
  const high = cards.filter((c) => c.severity.level === 'high' || c.severity.level === 'critical').length;
  const gates = [
    {
      name: 'l7-card-schema',
      pass: schemaErrors.length === 0,
      detail: schemaErrors.length ? JSON.stringify(schemaErrors.slice(0, 5)) : `${cards.length} cards`
    },
    {
      name: 'l7-coverage',
      pass: claimIds.size + excludedT2 === data.counts.T2 + data.counts.T1 && observations.length + excludedT3 === data.counts.T3,
      detail: `T1/T2 cards=${claimIds.size}+excluded=${excludedT2}/${data.counts.T2 + data.counts.T1}, T3 observations=${observations.length}+excluded=${excludedT3}/${data.counts.T3}`
    },
    {
      name: 'l7-refs-resolve',
      pass: data.unresolved.length === 0,
      detail: `unresolved=${data.unresolved.length}`
    },
    {
      name: 'l7-tier-discipline',
      pass: cards.every((c) => c.tier === 'T1-confirmed' || String(c.tier || '').startsWith('T2'))
        && observations.every((o) => String(o.tier || '').startsWith('T3'))
        && !cards.some((c) => c.tier === 'T1-confirmed' && (!c.reproduction || c.reproduction.kind !== 'dynamic')),
      detail: 'T3/T4 not in cards; T1 requires dynamic reproduction'
    },
    {
      name: 'l7-severity',
      pass: cards.every((c) => c.severity && c.severity.level && c.severity.rationale) && (cards.length === 0 || high < cards.length),
      detail: `high/critical=${high}/${cards.length}`
    },
    {
      name: 'l7-deterministic',
      pass: typeof data.reportHash === 'string' && /^[0-9a-f]{64}$/.test(data.reportHash),
      detail: data.reportHash ? `reportHash=${data.reportHash.slice(0, 12)}…` : 'missing reportHash'
    },
    {
      name: 'l7-delivery',
      pass: fs.existsSync(path.join(DELIVERY_DIR, 'manifest.json')) && fs.existsSync(path.join(DELIVERY_DIR, 'SHA256SUMS')),
      detail: 'out/delivery/manifest.json + SHA256SUMS'
    },
    {
      name: 'l7-report',
      pass: fs.existsSync(path.join(REPORT_DIR, 'FINDINGS.md')) && fs.existsSync(path.join(REPORT_DIR, 'EXECUTIVE-SUMMARY.md')) && fs.existsSync(path.join(REPORT_DIR, 'l7.md')),
      detail: 'FINDINGS.md + EXECUTIVE-SUMMARY.md + l7.md'
    }
  ];
  const summary = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    scope: 'production P1–P8 claims; T1/T2 cards, T3 observations, T4 appendix',
    counts: data.counts,
    cardCount: cards.length,
    observationCount: observations.length,
    excludedCount: excluded.length,
    reportHash: data.reportHash || null,
    unresolved: data.unresolved,
    severity: {
      critical: cards.filter((c) => c.severity.level === 'critical').length,
      high,
      medium: cards.filter((c) => c.severity.level === 'medium').length,
      low: cards.filter((c) => c.severity.level === 'low').length
    },
    gates,
    allGatesPass: gates.every((g) => g.pass)
  };
  return summary;
}

function writeDelivery(cards, observations, summary) {
  ensureDir(DELIVERY_DIR);
  const findingsDir = path.join(DELIVERY_DIR, 'findings');
  ensureDir(findingsDir);
  // 清理旧副本，避免 manifest 收集到 stale 文件；只删 delivery 目录内容。
  for (const f of fs.readdirSync(findingsDir)) fs.rmSync(path.join(findingsDir, f), { force: true, recursive: true });
  for (const f of fs.readdirSync(DELIVERY_DIR)) {
    const p = path.join(DELIVERY_DIR, f);
    if (f === 'findings') continue;
    fs.rmSync(p, { force: true, recursive: true });
  }
  const files = [];
  for (const card of cards) {
    const name = `${card.findingId}.md`;
    const dst = path.join(findingsDir, name);
    fs.writeFileSync(dst, renderCard(card), 'utf8');
    files.push(`findings/${name}`);
  }
  fs.writeFileSync(path.join(DELIVERY_DIR, 'FINDINGS.md'), renderIndex(cards, observations, summary), 'utf8');
  fs.writeFileSync(path.join(DELIVERY_DIR, 'EXECUTIVE-SUMMARY.md'), renderExecutive(summary, cards), 'utf8');
  files.push('FINDINGS.md', 'EXECUTIVE-SUMMARY.md');
  const hashes = [];
  for (const rel of files) {
    const abs = path.join(DELIVERY_DIR, rel);
    hashes.push([fileHash(abs), rel]);
  }
  const manifest = {
    schemaVersion: 1,
    generatedAt: summary.generatedAt,
    counts: summary.counts,
    cardCount: summary.cardCount,
    observationCount: summary.observationCount,
    files: hashes.map(([hash, rel]) => ({ path: rel, sha256: hash }))
  };
  writeJson(path.join(DELIVERY_DIR, 'manifest.json'), manifest);
  fs.writeFileSync(path.join(DELIVERY_DIR, 'SHA256SUMS'), hashes.map(([hash, rel]) => `${hash}  ${rel}`).join('\n') + '\n', 'utf8');
  return { manifest, files: files.length, hashes };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || (!opts.all && !opts.delivery)) {
    process.stdout.write('Usage: node bin/report.js --all [--delivery] [--json] [--include-l5]\n');
    return 0;
  }
  const data = buildL7();
  data.reportHash = sha256([
    JSON.stringify(data.cards.map((c) => [c.findingId, c.tier, c.severity.level, c.evidence.length])),
    JSON.stringify(data.observations.map((o) => [o.observationId, o.reason]))
  ].join('\n'));
  ensureDir(REPORT_DIR);
  ensureDir(FINDINGS_DIR);
  // 旧卡片可清理；只清 findings 下的 .md，保留其他报告。
  for (const f of fs.readdirSync(FINDINGS_DIR)) {
    if (f.endsWith('.md')) fs.rmSync(path.join(FINDINGS_DIR, f), { force: true });
  }
  for (const card of data.cards) {
    fs.writeFileSync(path.join(FINDINGS_DIR, `${card.findingId}.md`), renderCard(card), 'utf8');
  }
  writeJsonl(path.join(REPORT_DIR, 'findings.jsonl'), data.cards);
  writeJsonl(path.join(REPORT_DIR, 'observations.jsonl'), data.observations);
  writeJsonl(path.join(REPORT_DIR, 'excluded.jsonl'), data.excluded || []);
  // 先写报告，再算 gate，避免“报告文件不存在”误报。
  let preliminary = buildSummary(data);
  fs.writeFileSync(path.join(REPORT_DIR, 'FINDINGS.md'), renderIndex(data.cards, data.observations, preliminary), 'utf8');
  fs.writeFileSync(path.join(REPORT_DIR, 'EXECUTIVE-SUMMARY.md'), renderExecutive(preliminary, data.cards), 'utf8');
  if (opts.delivery) writeDelivery(data.cards, data.observations, preliminary);
  let summary = buildSummary(data);
  fs.writeFileSync(path.join(REPORT_DIR, 'l7.md'), renderIndex(data.cards, data.observations, summary), 'utf8');
  summary = buildSummary(data);
  if (opts.delivery) writeDelivery(data.cards, data.observations, summary);
  fs.writeFileSync(path.join(REPORT_DIR, 'FINDINGS.md'), renderIndex(data.cards, data.observations, summary), 'utf8');
  fs.writeFileSync(path.join(REPORT_DIR, 'EXECUTIVE-SUMMARY.md'), renderExecutive(summary, data.cards), 'utf8');
  writeJson(path.join(REPORT_DIR, 'l7-summary.json'), summary);
  if (opts.json) process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  else {
    process.stdout.write(`L7: cards=${data.cards.length}, observations=${data.observations.length}, unresolved=${data.unresolved.length}, gates=${summary.gates.filter((g) => g.pass).length}/${summary.gates.length}, all=${summary.allGatesPass}\n`);
    for (const g of summary.gates) process.stdout.write(`  ${g.pass ? 'PASS' : 'FAIL'} ${g.name}: ${g.detail}\n`);
  }
  return summary.allGatesPass ? 0 : 3;
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (e) {
    process.stderr.write(`${e && e.stack ? e.stack : e}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs, buildSummary, writeDelivery };
