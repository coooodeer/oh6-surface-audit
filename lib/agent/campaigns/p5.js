'use strict';

/**
 * Campaign definition — P5 (R1).
 *
 * gate key/name/evaluate 都在这里；runner 只加载 audit/fixtures/claims/
 * verdicts/calibration/旧回归结果等 ctx。
 */

function ok(pass, detail) {
  return { pass: Boolean(pass), detail };
}

module.exports = {
  id: 'p5',
  name: 'P5 (R1)',
  order: 30,
  defaultRun: false,
  summary: 'out/report/p5-run-summary.json',
  runner: 'bin/run-p5.js',
  defaultArgs: [],
  liveArgs: [],
  artifacts: [
    'out/p5/claims.jsonl',
    'out/p5/verdicts.jsonl',
    'out/p5/summary.json',
    'out/verdicts/p5-in-scope-verdicts.jsonl',
    'out/verdicts/p5-summary.json',
    'out/report/p5-implementation.md'
  ],
  gates: [
    {
      key: 'r1-units',
      name: 'P5-1 R1 候选拆分',
      evaluate: (ctx) => ok(
        !!ctx.audit && ctx.audit.units.r1Aggregates === 32 && ctx.audit.units.uniqueEntries === 288 && ctx.audit.units.units === 289,
        ctx.audit ? `R1 ${ctx.audit.units.r1Aggregates}, unique ${ctx.audit.units.uniqueEntries}, units ${ctx.audit.units.units}` : 'no audit'
      )
    },
    {
      key: 'direction',
      name: 'P5-2 方向判定',
      evaluate: (ctx) => ok(
        !!ctx.audit && ctx.audit.units.direction.service === 228 && ctx.audit.units.direction.callback === 61 && !ctx.audit.units.direction.unknown,
        ctx.audit ? JSON.stringify(ctx.audit.units.direction) : '-'
      )
    },
    {
      key: 'pairing',
      name: 'P5-3 service pairing',
      evaluate: (ctx) => {
        const pairing = ctx.audit && ctx.audit.pairing;
        const singleRate = pairing && pairing.singleService ? pairing.singleServiceResolved / pairing.singleService : 1;
        const multiRate = pairing && pairing.multiService ? pairing.multiServiceResolved / pairing.multiService : 0;
        return ok(
          !!pairing && pairing.serviceResolvedRate >= 0.8 && singleRate >= 0.8 && multiRate >= 0.5,
          pairing ? `all ${pairing.serviceResolved}/${pairing.service} (${pairing.serviceResolvedRate}); single ${pairing.singleServiceResolved}/${pairing.singleService}; multi ${pairing.multiServiceResolved}/${pairing.multiService}` : '-'
        );
      }
    },
    {
      key: 'checks-paths',
      name: 'P5-4 权限检查/路径',
      evaluate: (ctx) => {
        const paths = ctx.audit && ctx.audit.paths;
        return ok(
          !!paths && paths.pathScoped >= 10 && paths.truncated === 0,
          paths ? `pathScoped ${paths.pathScoped}/${paths.service}, noCheck ${paths.noCheckOnPath}, truncated ${paths.truncated}` : '-'
        );
      }
    },
    {
      key: 'fixtures',
      name: 'P5-5 fixtures 1/1 + 10/10',
      evaluate: (ctx) => ok(
        !!ctx.fixtures && ctx.fixtures.gate === true,
        ctx.fixtures ? `historical ${ctx.fixtures.historical.preViolation}/1 + ${ctx.fixtures.historical.postSatisfied}/1; synthetic ${ctx.fixtures.synthetic.originalSatisfied}/10 + ${ctx.fixtures.synthetic.mutantViolation}/10` : '-'
      )
    },
    {
      key: 'claims',
      name: 'P5-6 claims 20–40 + O1–O10',
      evaluate: (ctx) => {
        const claims = ctx.claims || [];
        const allObligations = claims.length >= 20 && claims.length <= 40
          && claims.every((c) => c.obligations && c.obligations.length === 10 && c.obligations.every((o) => o.id && o.kind && o.status && o.evidence));
        return ok(allObligations, claims.length ? `${claims.length} claims, ${claims.length * 10} obligations` : 'none');
      }
    },
    {
      key: 'no-pv',
      name: 'P5-7 无 O10 不升 PROVEN-VULN',
      evaluate: (ctx) => {
        const claims = ctx.claims || [];
        const noPvWithoutO10 = claims.every((c) => c.productVerdict !== 'PROVEN-VULN'
          || (c.obligations.find((o) => o.id === 'O10') || {}).status === 'proven');
        return ok(noPvWithoutO10, `T1=${claims.filter((c) => c.productVerdict === 'PROVEN-VULN').length}`);
      }
    },
    {
      key: 'l4b',
      name: 'P5-8 L4b schema ≥8/10 + refs 100%',
      evaluate: (ctx) => ok(
        !!ctx.l4b && ctx.l4b.gate === true,
        ctx.l4b ? `sim=${ctx.l4b.simulated} packs=${ctx.l4b.packs} ok=${ctx.l4b.ok} schema=${ctx.l4b.schemaSuccessRate} refs=${ctx.l4b.refsOkRate}` : '-'
      )
    },
    {
      key: 'calibration',
      name: 'P5-9 3 轮校准 + false PV=0',
      evaluate: (ctx) => ok(
        !!ctx.calibration && ctx.calibration.pass === true && ctx.calibration.falseProvenVuln === 0,
        ctx.calibration ? `${ctx.calibration.rounds.length} rounds, ${ctx.calibration.totalSampled} samples, false=${ctx.calibration.falseProvenVuln}` : '-'
      )
    },
    {
      key: 'r1-stats',
      name: 'P5-10 R1 统计',
      evaluate: (ctx) => ok(
        !!ctx.p5Summary && ctx.p5Summary.claims.total === (ctx.claims || []).length && ctx.p5Summary.excluded.outOfR1P5Candidates === 73,
        ctx.p5Summary ? `T1=${ctx.p5Summary.headline.newConfirmed} T2=${ctx.p5Summary.headline.newWeak} T3=${ctx.p5Summary.headline.conditions} T4=${ctx.p5Summary.headline.negative}; excluded=${ctx.p5Summary.excluded.outOfR1P5Candidates}` : '-'
      )
    },
    {
      key: 'regression',
      name: 'P5-11 现有 P6/P3/P4 回归',
      evaluate: (ctx) => ok(
        !!ctx.oldRun && ctx.oldRun.allGatesPass === true,
        ctx.oldRun ? `${ctx.oldRun.gates.filter((g) => g.pass).length}/${ctx.oldRun.gates.length}` : 'no run-summary'
      )
    },
    {
      key: 'no-human',
      name: 'P5-12 no needs-human/pending',
      evaluate: (ctx) => ok(ctx.noHuman, 'P5 claims/verdicts clean')
    },
    {
      key: 'report',
      name: 'P5-13 报告文件',
      evaluate: (ctx) => ok(
        ctx.reportExists,
        'p5-implementation.md'
      )
    }
  ]
};
