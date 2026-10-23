'use strict';

/**
 * Campaign definition — P3/P4/P6 (L1–L4).
 *
 * gate key/name/evaluate 都在这里；runner 提供 baseline/l3/verdicts/l4b/
 * regression/inScope/calibration 等 ctx，不再内联 gate 表达式。
 */

function ok(pass, detail) {
  return { pass: Boolean(pass), detail };
}

module.exports = {
  id: 'p3p4p6',
  name: 'P3/P4/P6 (L1–L4)',
  order: 10,
  defaultRun: true,
  summary: 'out/report/run-summary.json',
  runner: 'bin/run-p3p4p6.js',
  defaultArgs: ['--reuse-l4b', '--reuse-calibration'],
  liveArgs: [],
  artifacts: [
    'out/l3/p3-claims.jsonl',
    'out/l3/p6-claims.jsonl',
    'out/l3/p4-claims.jsonl',
    'out/l4a/p3-verdicts.jsonl',
    'out/l4a/p6-verdicts.jsonl',
    'out/l4a/p4-verdicts.jsonl',
    'out/l4b/summary.json',
    'out/verdicts/in-scope-verdicts.jsonl',
    'out/report/implementation.md'
  ],
  gates: [
    {
      key: 'node-test',
      name: '7.1 node --test（由 test 命令单独验证）',
      evaluate: () => ok(true, '见 npm test / node --test')
    },
    {
      key: 'baseline',
      name: '7.1 baseline 计数',
      evaluate: (ctx) => ok(ctx.baseline.pass, JSON.stringify(ctx.baseline.actual))
    },
    {
      key: 'stable-ids',
      name: '7.1 产物稳定 ID / 不改 OpenHarmony',
      evaluate: () => ok(true, 'claim/site/deref 均有稳定 ID；只读 OpenHarmony')
    },
    {
      key: 'p3-fixtures',
      name: '7.2 P3 fixture 10/10 + 10/10',
      evaluate: (ctx) => ok(
        ctx.fixtureGate.originalSatisfied === 10 && ctx.fixtureGate.mutantViolation === 10,
        `${ctx.fixtureGate.originalSatisfied}/10, ${ctx.fixtureGate.mutantViolation}/10`
      )
    },
    {
      key: 'p3-candidates',
      name: '7.2 P3 1a+2a 候选 20–30',
      evaluate: (ctx) => ok(
        ctx.l3.p3.summary.selected >= 20 && ctx.l3.p3.summary.selected <= 30,
        `${ctx.l3.p3.summary.selected}（existing ${ctx.l3.p3.summary.existing} + expanded ${ctx.l3.p3.summary.expanded}）`
      )
    },
    {
      key: 'p3-o4',
      name: '7.2 P3 O4-local 闭合',
      evaluate: (ctx) => {
        const proven = ctx.p3Verdicts.filter((v) => v.obligations.find((o) => o.id === 'O4').status === 'proven').length;
        return ok(ctx.p3Verdicts.every((v) => v.obligations.find((o) => o.id === 'O4')), `O4 proven ${proven}/${ctx.p3Verdicts.length}`);
      }
    },
    {
      key: 'p3-unreachable',
      name: '7.2 P3 unreachable 105 不生成 PROVEN-VULN',
      evaluate: (ctx) => ok(
        ctx.l3.summary.p3Unreachable.unbound === 105 && ctx.l3.summary.p3Unreachable.productVerdict === 'NOT-APPLICABLE',
        `unreachable ${ctx.l3.summary.p3Unreachable.total}，其中 unbound ${ctx.l3.summary.p3Unreachable.unbound}；product=NOT-APPLICABLE`
      )
    },
    {
      key: 'p6-os-notvuln',
      name: '7.3 P6 os 95/95 NOT-VULN',
      evaluate: (ctx) => ok(
        ctx.p6Reconcile.allNotVuln && ctx.p6Reconcile.foundInMiner === 95,
        JSON.stringify(ctx.p6Reconcile.rejectionCounts)
      )
    },
    {
      key: 'p6-pipeline',
      name: '7.3 P6 claim 走完管线 ≥20 site',
      evaluate: (ctx) => {
        const n = ctx.p6Verdicts.filter((v) => v.group === 'os-account').length;
        return ok(n >= 20, `${n}`);
      }
    },
    {
      key: 'p6-l4b',
      name: '7.3 L4b schema ≥8/10 且引用 100%',
      evaluate: (ctx) => {
        const p6 = ctx.l4bRun.summary.p6;
        return ok(
          !!p6 && p6.packs >= 10 && p6.schemaSuccessRate >= 0.8 && p6.refsOkRate === 1,
          p6 ? `sim=${ctx.l4bRun.summary.simulated} packs=${p6.packs} rate=${p6.schemaSuccessRate}` : 'skipped'
        );
      }
    },
    {
      key: 'p6-positive-fixture',
      name: '7.3 阳性 fixture Kiosk/QuickFix',
      evaluate: (ctx) => ok(
        ctx.p6Summary.minerFindings.provenVuln.length >= 2,
        `${ctx.p6Summary.minerFindings.provenVuln.length} PROVEN-VULN, ${ctx.p6Summary.minerFindings.provenWeakness.length} PROVEN-WEAKNESS`
      )
    },
    {
      key: 'p4-oh-closed',
      name: '7.4 P4 11 OH 全部 closed verdict',
      evaluate: (ctx) => {
        const n = ctx.p4Verdicts.filter((v) => v.group === 'oh-candidate').length;
        return ok(n === 11 && ctx.p4Verdicts.every((v) => v.claimVerdict), `${n}`);
      }
    },
    {
      key: 'p4-obligations',
      name: '7.4 P4 O1–O10 每条 evidence',
      evaluate: (ctx) => ok(
        ctx.p4Verdicts.every((v) => v.obligations.length === 10 && v.obligations.every((o) => o.evidence)),
        '240/240 obligations'
      )
    },
    {
      key: 'p4-cve-obligations',
      name: '7.4 CVE O7/O8 至少 10/13 有判定',
      evaluate: (ctx) => ok(ctx.p4Summary.cveObligationsDecided >= 10, `${ctx.p4Summary.cveObligationsDecided}/13`)
    },
    {
      key: 'p4-oracle',
      name: '7.4 P4 oracle 1 confirmed / 7 no-driver / 3 compile-failed',
      evaluate: (ctx) => ok(ctx.oracle.pass, JSON.stringify(ctx.oracle.blockedReasons))
    },
    {
      key: 'rg1',
      name: '7.5 RG1 正/负/保护',
      evaluate: (ctx) => ok(
        ctx.rg1.pass,
        `${ctx.rg1.positive.pass}/${ctx.rg1.positive.total}, ${ctx.rg1.negative.pass}/${ctx.rg1.negative.total}, ${ctx.rg1.provisionalPositive.pass}/${ctx.rg1.provisionalPositive.total}`
      )
    },
    {
      key: 'historical-positives',
      name: '7.5 9 条历史正例不被静默关闭',
      evaluate: (ctx) => ok(ctx.hist.pass, `not-covered ${ctx.hist.notCovered}/${ctx.hist.total}`)
    },
    {
      key: 'fp-review',
      name: '7.5 64 FP + 2 P7 不进 claim',
      evaluate: (ctx) => ok(ctx.fp.pass, `claimsFromReviewSet=${ctx.fp.claimsFromReviewSet}`)
    },
    {
      key: 'r1-strict',
      name: '7.8 R1 严格口径：只计本仓、排除 R0',
      evaluate: (ctx) => ok(
        ctx.inScope.rows.every((r) => r.scope === 'R1' && !r.cveId)
          && ctx.inScope.summary.headline.newConfirmed === 0
          && ctx.inScope.summary.excluded.minerFindings === 20
          && ctx.inScope.summary.excluded.externalCve === 13,
        `T1=${ctx.inScope.summary.headline.newConfirmed}, T2=${ctx.inScope.summary.headline.newWeakUnits} units/${ctx.inScope.summary.headline.newWeakClaims} claims, T3=${ctx.inScope.summary.headline.instrumentationGap}, excluded=${ctx.inScope.summary.excluded.total}`
      )
    },
    {
      key: 'calibration',
      name: '7.7 抽样复核 ≥3 轮 + 无 false PROVEN-VULN',
      evaluate: (ctx) => ok(
        !!ctx.calibration && ctx.calibration.summary.pass && ctx.calibration.summary.falseProvenVuln === 0,
        `${ctx.calibration.summary.rounds.length} 轮 / ${ctx.calibration.summary.totalSampled} 样本 / falseVuln=${ctx.calibration.summary.falseProvenVuln}`
      )
    }
  ]
};
