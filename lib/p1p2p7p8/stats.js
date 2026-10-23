'use strict';

/**
 * stats.js —— P1/P2/P7/P8 统计、verdict 行与实现报告。
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, writeJson, writeJsonl } = require('./common');

const D4_ROOTS = [
  'base/account/os_account',
  'foundation/communication/dsoftbus',
  'foundation/communication/ipc',
  'base/notification/eventhandler',
  'base/accesscontrol/sandbox_manager'
];

function gapReason(claim) {
  const reasons = [];
  for (const o of claim.obligations || []) {
    if (o.status === 'unproven' && !['O10', 'O7', 'O8', 'O9'].includes(o.id)) {
      reasons.push(`${o.id}:${o.reason || 'unproven'}`);
    }
  }
  if (claim.claimReason) reasons.unshift(claim.claimReason);
  return reasons.join(';') || claim.productReason || null;
}

function buildVerdicts(claims) {
  return claims.map((c) => {
    const tier = c.tier;
    return {
      verdictId: c.claimId,
      class: c.class,
      unitId: c.unitId,
      candidateId: c.candidateId,
      repo: (c.entry && c.entry.repo) || (c.productionEligible ? null : 'eval/p1p2p7p8'),
      file: (c.sink && c.sink.file) || null,
      line: (c.sink && c.sink.line) || null,
      tier,
      counted: tier === 'T2-weak-candidate' || tier === 'T3-instrumentation-gap',
      claimVerdict: c.claimVerdict,
      productVerdict: c.productVerdict,
      productionEligible: c.productionEligible === true,
      fixture: c.fixture === true,
      origin: c.origin,
      novelty: c.novelty,
      t1Eligible: false,
      gapReason: tier === 'T3-instrumentation-gap' ? gapReason(c) : null,
      obligations: (c.obligations || []).map((o) => ({ id: o.id, status: o.status, reason: o.reason || null })),
      evidenceRefs: c.evidenceRefs || []
    };
  });
}

function countTiers(rows) {
  const out = { T1: 0, T2: 0, T3: 0, T4: 0, T5: 0 };
  for (const r of rows) {
    const k = r.tier.slice(0, 2);
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function fixtureClassSummary(fx) {
  const s = fx.summary;
  return {
    synthetic: { total: s.synthetic.total, passed: s.synthetic.passed, failed: s.synthetic.failed },
    historyLocal: s.historyLocal ? {
      requested: s.historyLocal.requested,
      validated: s.historyLocal.validated,
      passed: s.historyLocal.passed,
      preAlready: s.historyLocal.preAlready || 0,
      unavailable: s.historyLocal.unavailable || []
    } : null,
    historyPositive: s.historyPositive ? {
      requested: s.historyPositive.requested,
      validated: s.historyPositive.validated,
      passed: s.historyPositive.passed,
      unavailable: s.historyPositive.unavailable || []
    } : null,
    external: s.external || null,
    positiveFixtures: s.positiveFixtures || null,
    negativeFixtures: s.negativeFixtures || null,
    localValidated: s.localValidated || null,
    localRepos: s.localRepos || null,
    gate: s.gate === true
  };
}

function buildSummary({ candidates, facts, fixtures, claims, verdicts, selectedP7, selectedP8, externalValidation }) {
  const byClass = {};
  const claimByClass = {};
  for (const c of claims) {
    if (!claimByClass[c.class]) claimByClass[c.class] = [];
    claimByClass[c.class].push(c);
  }
  const verdictByClass = {};
  for (const v of verdicts) {
    if (!verdictByClass[v.class]) verdictByClass[v.class] = [];
    verdictByClass[v.class].push(v);
  }
  const classInfo = {
    P1: { facts: facts.P1, fixtures: fixtures.classes.P1, selected: facts.P1.units },
    P2: { facts: facts.P2, fixtures: fixtures.classes.P2, selected: facts.P2.units },
    P7: { facts: facts.P7, fixtures: fixtures.classes.P7, selected: selectedP7 },
    P8: { facts: facts.P8, fixtures: fixtures.classes.P8, selected: selectedP8 }
  };
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    const info = classInfo[cls];
    const rows = verdictByClass[cls] || [];
    const fxRows = (claimByClass[cls] || []).filter((c) => c.fixture);
    byClass[cls] = {
      realD4Candidates: info.facts.summary.realD4Candidates,
      selectedClaimsUnits: info.selected.length,
      fixtureCases: fxRows.length,
      claims: rows.length,
      realClaims: rows.filter((r) => !r.fixture).length,
      fixtureClaims: rows.filter((r) => r.fixture).length,
      tiers: countTiers(rows),
      t1Eligible: false,
      obligations: rows.reduce((a, r) => {
        for (const o of r.obligations) {
          if (!a[o.id]) a[o.id] = { proven: 0, disproven: 0, unproven: 0 };
          a[o.id][o.status] = (a[o.id][o.status] || 0) + 1;
        }
        return a;
      }, {}),
      fixtures: fixtureClassSummary(info.fixtures),
      recallGap: Boolean(info.facts.summary.candidateRecallGap),
      recallNote: info.facts.summary.recallNote || null
    };
  }
  const rootCounts = {};
  for (const root of D4_ROOTS) rootCounts[root] = { P1: 0, P2: 0, P7: 0, P8: 0, total: 0 };
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    for (const u of classInfo[cls].selected) {
      const root = u.componentRoot;
      if (!rootCounts[root]) rootCounts[root] = { P1: 0, P2: 0, P7: 0, P8: 0, total: 0 };
      rootCounts[root][cls] += 1;
      rootCounts[root].total += 1;
    }
  }
  const tiers = countTiers(verdicts);
  const o10 = {
    unproven: claims.filter((c) => (c.obligations || []).some((o) => o.id === 'O10' && o.status === 'unproven')).length,
    total: claims.length,
    note: 'O10 固定 unproven（l5-deferred）；本目标不实现 L5，T1 固定 0'
  };
  return {
    generatedAt: new Date().toISOString(),
    scope: {
      name: 'D4',
      roots: D4_ROOTS,
      note: '只统计 5 个组件根；out-of-D4 只作 fixture/上下文，不计入 D4'
    },
    candidates: {
      source: 'oh6-vuln-agent/result/latest/candidates.jsonl',
      totalInFile: candidates.length,
      d4: {
        P1: facts.P1.summary.realD4Candidates,
        P2: facts.P2.summary.realD4Candidates,
        P7: facts.P7.summary.realD4Candidates,
        P8: facts.P8.summary.realD4Candidates
      },
      baseline: { P1: 1, P2: 1, P7: 660, P8: 821 },
      baselineMatches: facts.P1.summary.realD4Candidates >= 1 && facts.P7.summary.realD4Candidates === 660 && facts.P8.summary.realD4Candidates === 821
    },
    classes: byClass,
    d4Distribution: rootCounts,
    headline: { T1: 0, T2: tiers.T2, T3: tiers.T3, T4: tiers.T4, T5: tiers.T5 },
    t1Eligible: false,
    o10,
    fixtures: {
      gate: fixtures.gate,
      classes: {
        P1: fixtureClassSummary(fixtures.classes.P1),
        P2: fixtureClassSummary(fixtures.classes.P2),
        P7: fixtureClassSummary(fixtures.classes.P7),
        P8: fixtureClassSummary(fixtures.classes.P8)
      }
    },
    externalCve: externalValidation ? {
      production: false,
      validationOk: externalValidation.ok === true,
      count: externalValidation.count,
      note: 'external-cve 只作义务/裁决校准，不映射 target，不产生 codeState，不进入 D4'
    } : null,
    gaps: [
      facts.P1.summary.candidateRecallGap ? `P1 real D4 candidates=${facts.P1.summary.realD4Candidates} < 8; fixture 补齐，不伪造 target` : null,
      facts.P2.summary.candidateRecallGap ? `P2 real D4 candidates=${facts.P2.summary.realD4Candidates}` : null,
      'P7 amplification 只有 1 条 D4 候选；其余 5 条 claims 来自 fixture，fixture 不进入 D4 统计',
      'P7 amplification ratio 是 static-proxy，不是实测放大比',
      'P8 INV-PAT-LIFECYCLE 是本目标补充的第三种 pattern，authority 指向本地 lifetime-guard-added 42 条；P8 invariant 判据仍偏弱，无校验调用不等于漏洞',
      'O10 固定 unproven：没有 L5 动态 oracle，T1 固定 0 不是漏报，是范围外',
      'P1 本地 bounds-check-added 两条产品样本中 INV-HIST-85cc873e 的 witness 在父函数已存在（pre-already），只有 INV-HIST-bb00b84c 是真正 pre/post 正对照',
      'P1/P2 recall：P1 D4 7 条、P2 D4 12 条；不扩到 D4 外，不用 fixture 冒充 target；recall gap 以具名方式记录',
      '没有 fake PV：R1/D4 的 PROVEN-VULN=0，T1=0 只因为 L5 deferred'
    ].filter(Boolean),
    artifacts: [
      'out/p1p2p7p8/data-audit.json',
      'out/p1p2p7p8/p1-candidates.jsonl',
      'out/p1p2p7p8/p2-candidates.jsonl',
      'out/p1p2p7p8/claims.jsonl',
      'out/p1p2p7p8/verdicts.jsonl',
      'out/p1p2p7p8/summary.json',
      'out/report/p1p2p7p8-implementation.md'
    ]
  };
}

function renderReport(summary, verdicts) {
  const l = [];
  l.push('# P1/P2/P7/P8 静态发现实现报告');
  l.push('');
  l.push(`生成时间：${summary.generatedAt}`);
  l.push('');
  l.push('## 1 范围与口径');
  l.push('');
  l.push('- 范围 **D4**：' + summary.scope.roots.map((r) => `\`${r}\``).join('、') + '。');
  l.push('- 只做静态发现：L1 facts/index/candidates → L3 claim（O1–O10）→ L4a 确定性 prover → T2/T3/T4 + fixture。');
  l.push('- **不实现 L5–L7**；O10 固定 `unproven`（`l5-deferred`），`t1Eligible=false`，因此 **T1=0**。');
  l.push('- T2=PROVEN-WEAKNESS、T3=CONDITIONS-NOT-MET、T4=NOT-VULN、T5=NOT-APPLICABLE；不产生 PROVEN-VULN。');
  l.push('- P8 覆盖 3 种 invariant pattern：STATE-GUARD / RETURN-CONTRACT / LIFECYCLE；invariant 适用性由写点与守卫独立核对。');
  l.push('- P1/P2 的 recall 缺口单独记录，不用 out-of-D4 候选填充，也不伪造 target 候选。');
  l.push('');
  l.push('## 2 候选与 claims');
  l.push('');
  l.push('| 类 | D4 候选 | 选中 claims units | fixture cases | claims | T1 | T2 | T3 | T4 | T5 |');
  l.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    const c = summary.classes[cls];
    l.push(`| ${cls} | ${c.realD4Candidates} | ${c.selectedClaimsUnits} | ${c.fixtureCases} | ${c.claims} | ${c.tiers.T1} | ${c.tiers.T2} | ${c.tiers.T3} | ${c.tiers.T4} | ${c.tiers.T5} |`);
  }
  l.push('');
  l.push('`realD4Candidates` 与 `fixtureCases` 分开计数；fixture 不进入 D4 统计，也不进入生产 O10。');
  l.push('');
  l.push('## 3 D4 分布（选中 claims 的组件根）');
  l.push('');
  l.push('| 组件根 | P1 | P2 | P7 | P8 | 合计 |');
  l.push('| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const [root, c] of Object.entries(summary.d4Distribution)) {
    l.push(`| ${root} | ${c.P1} | ${c.P2} | ${c.P7} | ${c.P8} | ${c.total} |`);
  }
  l.push('');
  l.push('## 4 Fixtures');
  l.push('');
  for (const cls of ['P1', 'P2', 'P7', 'P8']) {
    const f = summary.fixtures.classes[cls];
    l.push(`### ${cls}`);
    l.push('');
    l.push(`- synthetic：${f.synthetic.passed}/${f.synthetic.total} 通过。`);
    if (f.positiveFixtures != null) l.push(`- 正例 ${f.positiveFixtures} / 负例 ${f.negativeFixtures}。`);
    if (f.historyLocal) l.push(`- history-local：${f.historyLocal.validated}/${f.historyLocal.requested} 可提取，${f.historyLocal.passed} 通过，pre-already ${f.historyLocal.preAlready}。`);
    if (f.historyPositive) l.push(`- history-positive：${f.historyPositive.validated}/${f.historyPositive.requested} 可提取，${f.historyPositive.passed} 通过。`);
    if (f.external) l.push(`- external-cve：${f.external.passed}/${f.external.total} 通过，validationOk=${f.external.validationOk}（production=false）。`);
    if (f.localRepos) l.push(`- 本地组件覆盖：${f.localRepos.join('、')}。`);
    l.push(`- gate：${f.gate ? 'PASS' : 'FAIL'}。`);
    l.push('');
  }
  l.push('## 5 O10 / T1 纪律');
  l.push('');
  l.push(`- O10 unproven：${summary.o10.unproven}/${summary.o10.total}。`);
  l.push('- T1=0 的原因是 L5 deferred，不是漏报；没有动态 oracle 时不把静态证据写成 PROVEN-VULN。');
  l.push('- fixture 的 pre/post/mutant 只用于校准 detector/prover，不写入生产 O10。');
  l.push('');
  l.push('## 6 已知缺口');
  l.push('');
  for (const g of summary.gaps) l.push(`- ${g}`);
  l.push('');
  l.push('## 7 Verdict 明细');
  l.push('');
  l.push('| verdictId | class | tier | claim | product | production | gap |');
  l.push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const v of verdicts) {
    l.push(`| ${v.verdictId} | ${v.class} | ${v.tier} | ${v.claimVerdict} | ${v.productVerdict} | ${v.productionEligible} | ${v.gapReason || '-'} |`);
  }
  l.push('');
  return l.join('\n');
}

function writeOutputs({ facts, claims, verdicts, summary }) {
  const dir = path.join(OUT_ROOT, 'p1p2p7p8');
  const reportDir = path.join(OUT_ROOT, 'report');
  ensureDir(dir); ensureDir(reportDir);
  writeJsonl(path.join(dir, 'claims.jsonl'), claims);
  writeJsonl(path.join(dir, 'verdicts.jsonl'), verdicts);
  writeJson(path.join(dir, 'summary.json'), summary);
  fs.writeFileSync(path.join(reportDir, 'p1p2p7p8-implementation.md'), renderReport(summary, verdicts), 'utf8');
  return {
    claims: claims.length,
    verdicts: verdicts.length,
    files: ['out/p1p2p7p8/claims.jsonl', 'out/p1p2p7p8/verdicts.jsonl', 'out/p1p2p7p8/summary.json', 'out/report/p1p2p7p8-implementation.md']
  };
}

module.exports = { D4_ROOTS, buildVerdicts, buildSummary, renderReport, writeOutputs, countTiers, gapReason };
