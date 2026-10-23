'use strict';

/**
 * Campaign definition — P1/P2/P7/P8 (D4 static).
 *
 * gate 的 key/name/evaluate 都在这里；runner 只提供 ctx（事实、claims、fixtures、
 * calibration、报告检查结果等），不再内联 gate 表达式。
 */

function ok(pass, detail) {
  return { pass: Boolean(pass), detail };
}

module.exports = {
  id: 'p1p2p7p8',
  name: 'P1/P2/P7/P8 (D4 static)',
  order: 20,
  defaultRun: true,
  summary: 'out/report/p1p2p7p8-run-summary.json',
  runner: 'bin/run-p1p2p7p8.js',
  defaultArgs: [],
  liveArgs: [],
  artifacts: [
    'out/p1p2p7p8/data-audit.json',
    'out/p1p2p7p8/claims.jsonl',
    'out/p1p2p7p8/verdicts.jsonl',
    'out/p1p2p7p8/summary.json',
    'out/report/p1p2p7p8-implementation.md',
    'out/report/P1P2P7P8-CALIBRATION-LOG.jsonl'
  ],
  gates: [
    {
      key: 'code-artifacts',
      name: 'code-artifacts',
      evaluate: (ctx) => ok(ctx.codeArtifacts, 'lib/p1p2p7p8 + bin/p1p2p7p8-*.js present')
    },
    {
      key: 'audit-baseline',
      name: 'audit-baseline',
      evaluate: (ctx) => ok(
        ctx.audit && ctx.audit.baselineMatches === true
          && ctx.d4Roots.every((r) => ctx.audit.d4Distribution[r] && ctx.audit.d4Distribution[r].total > 0),
        ctx.audit ? `D4 ${JSON.stringify(ctx.audit.candidateCounts)} baseline=${ctx.audit.baselineMatches}` : 'no audit'
      )
    },
    {
      key: 'utf8-clean',
      name: 'utf8-clean',
      evaluate: (ctx) => ok(ctx.utf8.pass, ctx.utf8.bad)
    },
    {
      key: 'candidate-origin',
      name: 'candidate-origin',
      evaluate: (ctx) => ok(ctx.audit.candidateOrigin.pass, ctx.audit.candidateOrigin.checks)
    },
    {
      key: 'p1-gate',
      name: 'p1-gate',
      evaluate: (ctx) => {
        const s = ctx.p1Fixture.summary;
        const pass = ctx.p1Seed && ctx.p1Total >= 8 && ctx.p1LocalProduct >= 2
          && s.positiveFixtures >= 5 && s.negativeFixtures >= 5
          && s.historyPositive.validated >= 2 && s.gate
          && ctx.p1Claims.every((c) => c.productVerdict !== 'PROVEN-VULN');
        return ok(pass, { seed: ctx.p1Seed, claims: ctx.p1Total, localProduct: ctx.p1LocalProduct, fixtureGate: s.gate });
      }
    },
    {
      key: 'p2-gate',
      name: 'p2-gate',
      evaluate: (ctx) => {
        const s = ctx.p2Fixture.summary;
        const pass = ctx.p2Seed && ctx.p2Total >= 8 && ctx.p2Local >= 6 && ctx.p2Repos.length >= 2
          && s.positiveFixtures >= 5 && s.negativeFixtures >= 5
          && s.historyPositive.validated >= 1 && s.gate
          && ctx.p2Claims.every((c) => c.productVerdict !== 'PROVEN-VULN')
          && ctx.p2Claims.filter((c) => !c.fixture && String(c.tier || '').startsWith('T2')).every((c) => {
            const u = ctx.p2.units.find((x) => x.unitId === c.unitId);
            return u && ['dangling-reference', 'free-without-anchor'].includes(u.lifetime.classification);
          });
        return ok(pass, { seed: ctx.p2Seed, claims: ctx.p2Total, local: ctx.p2Local, repos: ctx.p2Repos, fixtureGate: s.gate });
      }
    },
    {
      key: 'p7-gate',
      name: 'p7-gate',
      evaluate: (ctx) => {
        const claims = ctx.p7Claims;
        const pass = claims.length === 24
          && ['unbounded-loop', 'unbounded-alloc', 'blocking-hold', 'amplification'].every((cls) => {
            const n = claims.filter((c) => {
              if (c.fixture) return cls === 'amplification';
              const u = ctx.p7.units.find((x) => x.unitId === c.unitId);
              return u && u.dosClass === cls;
            }).length;
            return n >= 6;
          })
          && ctx.p7Amp.length + ctx.p7AmpFixture.length >= 6
          && ctx.p7Fixture.external.summary.gate
          && !claims.some((c) => c.productVerdict === 'PROVEN-VULN')
          && claims.filter((c) => c.tier === 'T3-instrumentation-gap').every((c) => {
            const v = ctx.verdicts.find((x) => x.verdictId === c.claimId);
            return v && v.gapReason;
          });
        return ok(pass, { claims: claims.length, tiers: ctx.p7Tiers, ampReal: ctx.p7Amp.length, ampFixture: ctx.p7AmpFixture.length, external: ctx.p7Fixture.external.summary });
      }
    },
    {
      key: 'p8-gate',
      name: 'p8-gate',
      evaluate: (ctx) => {
        const claims = ctx.p8Claims;
        const pass = claims.length === 24 && ctx.p8Patterns.size >= 3
          && ctx.p8Fixture.historyLocal.summary.validated >= 4
          && !claims.some((c) => c.productVerdict === 'PROVEN-VULN')
          && claims.every((c) => {
            const u = ctx.p8.units.find((x) => x.unitId === c.unitId);
            return u && u.invariant.authority && u.source && u.sink;
          })
          && claims.filter((c) => c.tier === 'T3-instrumentation-gap').every((c) => {
            const v = ctx.verdicts.find((x) => x.verdictId === c.claimId);
            return v && v.gapReason;
          });
        return ok(pass, { claims: claims.length, patterns: [...ctx.p8Patterns], tiers: ctx.p8Tiers, local: ctx.p8Fixture.historyLocal.summary.validated });
      }
    },
    {
      key: 'fixtures',
      name: 'fixtures',
      evaluate: (ctx) => ok(ctx.fixtures.gate === true, {
        P1: ctx.p1Fixture.summary.gate,
        P2: ctx.p2Fixture.summary.gate,
        P7: ctx.p7Fixture.summary.gate,
        P8: ctx.p8Fixture.summary.gate
      })
    },
    {
      key: 'calibration',
      name: 'calibration',
      evaluate: (ctx) => ok(
        ctx.calibration.pass === true && ctx.calibration.rounds.length === 3
          && ctx.calibration.totalSampled === 60 && ctx.calibration.falseProvenVuln === 0
          && ctx.calibration.boundaryCovered === true,
        { rounds: ctx.calibration.rounds.length, samples: ctx.calibration.totalSampled, passed: ctx.calibration.passed, falsePV: ctx.calibration.falseProvenVuln, boundary: ctx.calibration.boundaryCovered }
      )
    },
    {
      key: 'no-proven-vuln',
      name: 'no-proven-vuln',
      evaluate: (ctx) => ok(ctx.noPv && ctx.t1Zero && ctx.summary.headline.T1 === 0, { noPv: ctx.noPv, t1Zero: ctx.t1Zero })
    },
    {
      key: 'regression',
      name: 'regression',
      evaluate: (ctx) => ok(ctx.regression.p3p4p6 && ctx.regression.p5 && ctx.regression.p5T1Zero, ctx.regression)
    },
    {
      key: 'report',
      name: 'report',
      evaluate: (ctx) => ok(ctx.reportMissing.length === 0, { missing: ctx.reportMissing })
    },
    {
      key: 'no-human-pending',
      name: 'no-human-pending',
      evaluate: (ctx) => ok(ctx.human.pass, ctx.human.bad)
    },
    {
      key: 'production-scope',
      name: 'production-scope',
      evaluate: (ctx) => ok(
        ctx.claims.filter((c) => !c.fixture).every((c) => c.productionEligible === true && ctx.isD4(c.entry && c.entry.repo))
          && ctx.claims.filter((c) => c.fixture).every((c) => c.productionEligible === false)
          && ctx.claims.every((c) => !c.inTarget || c.productionEligible === true),
        'non-fixture claims are D4 production; fixture not production'
      )
    }
  ]
};
