'use strict';

/**
 * Campaign definition — Global L4b (P1–P8).
 *
 * 这是“全类 L4b”的 gate 容器：runner 是 `bin/agent.js audit --reuse`，
 * 读取上游各 campaign 的 claims/verdicts，统一做语义复核，写
 * out/report/global-l4b-summary.json。
 */

function ok(pass, detail) {
  return { pass: Boolean(pass), detail };
}

module.exports = {
  id: 'global-l4b',
  name: 'Global L4b (P1–P8)',
  order: 40,
  defaultRun: false,
  summary: 'out/report/global-l4b-summary.json',
  runner: 'bin/agent.js',
  defaultArgs: ['audit', '--reuse', '--no-state'],
  liveArgs: ['audit', '--reuse', '--no-state', '--l4b=live'],
  artifacts: [
    'out/global/l4b/results.jsonl',
    'out/global/l4b/claims-refined.jsonl',
    'out/global/l4b/verdicts-refined.jsonl',
    'out/report/global-l4b.md'
  ],
  gates: [
    {
      key: 'class-coverage',
      name: 'global-l4b class coverage',
      evaluate: (ctx) => {
        const s = ctx.globalL4b;
        const classes = (s && s.classes) || [];
        const requested = (s && s.requestedClasses) || classes.map((c) => c.class);
        const rows = requested.map((id) => classes.find((c) => c.class === id)).filter(Boolean);
        const perClass = (s && s.perClass) || 0;
        const pass = rows.length === requested.length && rows.every((c) => {
          if (c.eligible === 0) return true;
          if (perClass > 0) return c.selected > 0 && c.reviewed === c.selected;
          return c.selected === c.eligible && c.reviewed === c.selected;
        });
        return ok(pass, requested.map((id) => {
          const c = rows.find((x) => x.class === id);
          return `${id}:${c ? c.selected : 0}/${c ? c.eligible : 0}`;
        }).join(', '));
      }
    },
    {
      key: 'schema',
      name: 'global-l4b schema',
      evaluate: (ctx) => {
        const t = ctx.globalL4b && ctx.globalL4b.totals;
        return ok(Boolean(t && t.selected > 0 && t.errors === 0), t ? `${t.reviewed}/${t.selected} ok, errors=${t.errors}` : 'missing summary');
      }
    },
    {
      key: 'no-t1',
      name: 'global-l4b no T1 / O10 stable',
      evaluate: (ctx) => {
        const t = ctx.globalL4b && ctx.globalL4b.totals;
        return ok(Boolean(t && t.t1 === 0), t ? `t1=${t.t1}` : 'missing summary');
      }
    },
    {
      key: 'artifacts',
      name: 'global-l4b artifacts',
      evaluate: (ctx) => ok(ctx.globalArtifacts === true, 'out/global/l4b/*.jsonl')
    },
    {
      key: 'report',
      name: 'global-l4b report',
      evaluate: (ctx) => ok(ctx.globalReport === true, 'out/report/global-l4b.md')
    }
  ]
};
