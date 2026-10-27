'use strict';

/**
 * tools/autonomy-blind-eval.js —— 跨组件受控盲测的评分器。
 *
 * 评分时才读取冻结标签 `eval/autonomy/blind-cross-component.json`；运行阶段
 * （cmdRun）只读取 scope/知识/预算，不读取该文件。
 *
 * 输出分开报告：
 *   - blindNomination：无种子提名（reportability candidate/finding）及逐条复核；
 *   - miss / falseExclusion / ambiguityHold：漏提名、错误排除、歧义保持；
 *   - givenMutant：由独立评测器（tools/autonomy-os-account-eval.js 与既有
 *     security-verdict 评测）统计，本工具不合并；
 *   - realFinding：本运行没有真实目标，真实 finding 召回为 null。
 *
 * 用法：node tools/autonomy-blind-eval.js --run=RUN:<id> [--labels=<file>] [--write]
 */

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const storeLib = require('../lib/autonomy/store');
const DEFAULT_LABELS = path.join(root, 'eval', 'autonomy', 'blind-cross-component.json');
const OUT_FILE = path.join(root, 'out', 'autonomy', 'eval', 'blind-cross-component.json');

function sha256(buf) {
  return require('node:crypto').createHash('sha256').update(buf).digest('hex');
}

function parseArgs(argv) {
  const out = { run: null, labels: DEFAULT_LABELS, write: false };
  for (const arg of argv) {
    if (arg.startsWith('--run=')) out.run = arg.slice('--run='.length);
    else if (arg.startsWith('--labels=')) out.labels = path.resolve(arg.slice('--labels='.length));
    else if (arg === '--write') out.write = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else throw new Error(`unknown-arg: ${arg}`);
  }
  return out;
}

function readRows(file) {
  return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}

function score(runArg, labelsFile) {
  if (!runArg) throw new Error('blind-eval-run-required');
  const dir = storeLib.RunStore.resolve(runArg);
  const labelsBuf = fs.readFileSync(labelsFile);
  const labels = JSON.parse(labelsBuf.toString('utf8'));
  const entities = readRows(path.join(dir, 'entities.jsonl'));
  const reports = readRows(path.join(dir, 'report-model.jsonl'));
  const byEntry = new Map(entities.map((row) => [row.entityId, row]));
  const reportByEntry = new Map(reports.filter((row) => row.payload && row.payload.origin === 'entry-scan')
    .map((row) => [row.payload.entryRef, row.payload]));
  if (labels.snapshotId !== JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8')).payload.snapshotId) {
    throw new Error('blind-eval-snapshot-mismatch');
  }

  const rows = labels.cases.map((label) => {
    const matches = entities.filter((row) => row.kind === 'entry' && row.payload &&
      String(row.payload.file || '').endsWith(`/${label.file}`));
    if (matches.length !== 1) throw new Error(`blind-eval-entry-not-unique: ${label.file} (${matches.length})`);
    const entity = matches[0];
    const report = reportByEntry.get(entity.entityId);
    if (!report) throw new Error(`blind-eval-report-missing: ${label.file}`);
    const observed = report.reportability;
    const expected = label.expected;
    const expectedCategory = expected === 'insufficient' ? 'observation' : expected;
    const statusMatch = observed === expectedCategory;
    const observedMissing = Array.isArray(report.missing) ? report.missing : [];
    const observedSecurityFamily = report.securityFamily || null;
    // insufficient 案例的具名原因在 missing 里，不在 securityFamily 字段；
    // 两类都按同一口径比较，避免把“原因在 missing”误算成家族不匹配。
    const securityFamilyMatch = label.expectedSecurityFamily
      ? (observedSecurityFamily === label.expectedSecurityFamily ||
        observedMissing.includes(label.expectedSecurityFamily))
      : (observedSecurityFamily === null);
    return {
      component: label.component,
      interface: label.interface,
      method: label.method,
      file: label.file,
      familyId: label.familyId,
      expected,
      expectedSecurityFamily: label.expectedSecurityFamily,
      observed,
      observedSecurityFamily,
      observedMissing,
      observedOperationRef: report.operationRef || null,
      statusMatch,
      securityFamilyMatch,
      reportability: observed,
      securityProposition: report.securityProposition || null,
      gates: report.gates || []
    };
  });

  const positives = rows.filter((row) => ['candidate', 'finding'].includes(row.expected));
  const excluded = rows.filter((row) => row.expected === 'excluded');
  const insufficient = rows.filter((row) => row.expected === 'insufficient');
  const nominated = rows.filter((row) => ['candidate', 'finding'].includes(row.observed));
  const observedExcluded = rows.filter((row) => row.observed === 'excluded');
  const findings = rows.filter((row) => row.observed === 'finding');

  const metrics = {
    blindVersion: labels.labelsVersion,
    snapshotId: labels.snapshotId,
    corpusVersion: labels.corpusVersion,
    sourceType: labels.sourceType,
    labelSource: labels.labelSource,
    labelAuthority: labels.labelAuthority,
    needsHumanTuning: true,
    runId: JSON.parse(fs.readFileSync(path.join(dir, 'run.json'), 'utf8')).recordId,
    runDir: path.relative(root, dir).split(path.sep).join('/'),
    inputHashes: {
      labelsFile: path.relative(root, labelsFile).split(path.sep).join('/'),
      labelsSha256: sha256(labelsBuf),
      reportModelSha256: sha256(fs.readFileSync(path.join(dir, 'report-model.jsonl')))
    },
    denominators: {
      cases: rows.length,
      components: new Set(rows.map((row) => row.component)).size,
      positiveExpectations: positives.length,
      excludedExpectations: excluded.length,
      insufficientExpectations: insufficient.length
    },
    blindNomination: {
      nominated: nominated.length,
      candidates: rows.filter((row) => row.observed === 'candidate').length,
      findings: findings.length,
      byComponent: rows.reduce((m, row) => {
        if (!['candidate', 'finding'].includes(row.observed)) return m;
        m[row.component] = (m[row.component] || 0) + 1; return m;
      }, {}),
      rows: nominated.map((row) => ({ component: row.component, method: row.method, file: row.file,
        observed: row.observed, securityFamily: row.observedSecurityFamily,
        expected: row.expected }))
    },
    positiveRecall: positives.length
      ? positives.filter((row) => ['candidate', 'finding'].includes(row.observed)).length / positives.length
      : null,
    missedNominations: positives.filter((row) => !['candidate', 'finding'].includes(row.observed))
      .map((row) => ({ file: row.file, expected: row.expected, observed: row.observed })),
    wrongExclusions: rows.filter((row) => row.observed === 'excluded' &&
      !['excluded'].includes(row.expected)).map((row) => ({ file: row.file, expected: row.expected })),
    wrongNominations: rows.filter((row) => ['candidate', 'finding'].includes(row.observed) &&
      !['candidate', 'finding'].includes(row.expected))
      .map((row) => ({ file: row.file, expected: row.expected, observed: row.observed })),
    nominationPrecision: nominated.length
      ? nominated.filter((row) => ['candidate', 'finding'].includes(row.expected)).length / nominated.length
      : null,
    falseExclusionRate: positives.length
      ? positives.filter((row) => row.observed === 'excluded').length / positives.length : null,
    excludedRecall: excluded.length
      ? excluded.filter((row) => row.observed === 'excluded').length / excluded.length : null,
    ambiguityHoldRate: insufficient.length
      ? insufficient.filter((row) => row.observed === 'observation').length / insufficient.length : null,
    falseCertaintyRate: insufficient.length
      ? insufficient.filter((row) => ['excluded', 'finding'].includes(row.observed)).length / insufficient.length : null,
    statusAccuracy: rows.filter((row) => row.statusMatch).length / rows.length,
    securityFamilyAccuracy: rows.filter((row) => row.securityFamilyMatch).length / rows.length,
    realFinding: {
      observedFindings: findings.length,
      realEntryFindings: 0,
      note: '受控语料没有真实入口；真实 finding 召回为 null，与给定变异体/盲测提名分开报告。'
    },
    givenMutant: {
      status: 'separate-evaluator',
      note: '给定变异体判定由 tools/autonomy-os-account-eval.js 与既有 security-verdict 评测统计，本工具不合并。'
    },
    discoveryRecall: null,
    independentAccuracy: null,
    rows
  };
  return metrics;
}

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write('usage: node tools/autonomy-blind-eval.js --run=RUN:<id> [--labels=<file>] [--write]\n');
    return 0;
  }
  const metrics = score(args.run, args.labels);
  const body = `${JSON.stringify(metrics, null, 2)}\n`;
  if (args.write) {
    fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
    fs.writeFileSync(OUT_FILE, body, { encoding: 'utf8' });
    process.stdout.write(`${JSON.stringify({ ok: true, out: path.relative(root, OUT_FILE).split(path.sep).join('/'),
      sha256: sha256(Buffer.from(body, 'utf8')), statusAccuracy: metrics.statusAccuracy,
      positiveRecall: metrics.positiveRecall, nominated: metrics.blindNomination.nominated })}\n`);
  } else {
    process.stdout.write(body);
  }
  return 0;
}

module.exports = { score, main, OUT_FILE };

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
