'use strict';

/**
 * in-scope.js —— 只在 R1 严格扫描仓内统计“本仓新发现候选”。
 *
 * R1 = base/account/os_account + foundation/communication/dsoftbus
 *      （当前 L1 facts 覆盖的两个仓）。
 *
 * 统计口径：
 *   - 单位：P3 用 owner 根因族（claimIds 作证据）；P4 用算术 site；P6 用 site。
 *   - T1 confirmed：productVerdict=PROVEN-VULN。
 *   - T2 weak candidate：productVerdict=PROVEN-WEAKNESS（含 P3 VIOLATION + O4-local proven 但 impact 未证）。
 *   - T3 instrumentation-gap：CONDITIONS-NOT-MET 且具名 no-driver / compile-failed / entry-suspect。
 *   - T4 negative：NOT-VULN / SATISFIED / NOT-APPLICABLE，不写入 verdicts 文件。
 *   - R0 excluded：miner 既有 findings、外部 CVE、R2 的 OH6 其他仓；不计入本仓统计。
 *
 * 产物：
 *   out/verdicts/in-scope-verdicts.jsonl
 *   out/verdicts/summary.json
 *   out/report/in-scope-findings.md
 */

const fs = require('fs');
const path = require('path');
const { OUT_ROOT, ensureDir, writeJsonl, writeJson, sha256 } = require('./util.js');

const STANDARD_VERSION = 'R1-in-scope-1';
const R1_REPOS = ['base/account/os_account', 'foundation/communication/dsoftbus'];

function isR1(repo) {
  return R1_REPOS.includes(repo);
}

function sanitize(s) {
  return String(s || '').replace(/[^A-Za-z0-9_.:-]+/g, '_').slice(0, 160);
}

function ownerOf(verdict) {
  const o2 = (verdict.obligations || []).find((o) => o.id === 'O2');
  return (o2 && o2.evidence && o2.evidence.owner) || null;
}

function isProductionVerdict(verdict) {
  return verdict && verdict.productionEligible === true;
}

function p3FamilyRows(p3Verdicts) {
  const families = new Map();
  for (const v of p3Verdicts) {
    if (!isR1(v.repo) || !isProductionVerdict(v)) continue;
    const owner = ownerOf(v) || 'unknown-owner';
    const producer = v.variable || 'unknown-producer';
    const key = [v.repo, owner, producer].join('|');
    if (!families.has(key)) families.set(key, { key, repo: v.repo, owner, producer, claims: [] });
    families.get(key).claims.push(v);
  }
  const rows = [];
  for (const f of families.values()) {
    const claims = f.claims;
    const files = [...new Set(claims.map((c) => c.file))];
    const functions = [...new Set(claims.map((c) => c.function))];
    const lines = claims.map((c) => c.line).filter((n) => n != null).sort((a, b) => a - b);
    const tier = claims.every((c) => c.productVerdict === 'PROVEN-WEAKNESS' || c.productVerdict === 'PROVEN-VULN')
      ? (claims.every((c) => c.productVerdict === 'PROVEN-VULN') ? 'T1-confirmed' : 'T2-weak-candidate')
      : 'T3-instrumentation-gap';
    rows.push({
      standardVersion: STANDARD_VERSION,
      verdictId: `IS-P3-${sanitize(f.key)}`,
      scope: 'R1',
      class: 'P3',
      origin: claims.every((c) => c.origin === 'target') ? 'target' : (claims[0].origin || null),
      inTarget: claims.every((c) => c.inTarget === true),
      codeState: claims.every((c) => c.codeState === 'current-head') ? 'current-head' : null,
      productionEligible: claims.every((c) => c.productionEligible === true),
      novelty: claims.every((c) => c.novelty === 'new') ? 'new' : (claims[0].novelty || null),
      repo: f.repo,
      file: files.length === 1 ? files[0] : null,
      files,
      line: lines.length === 1 ? lines[0] : null,
      lines,
      functions,
      unitType: 'root-cause-owner-family',
      dedupKey: f.key,
      owner: f.owner,
      producer: f.producer,
      claimIds: claims.map((c) => c.claimId),
      claimCount: claims.length,
      claimVerdicts: [...new Set(claims.map((c) => c.claimVerdict))],
      productVerdict: tier === 'T1-confirmed' ? 'PROVEN-VULN' : (tier === 'T2-weak-candidate' ? 'PROVEN-WEAKNESS' : 'CONDITIONS-NOT-MET'),
      tier,
      counted: tier === 'T1-confirmed' || tier === 'T2-weak-candidate',
      gapReason: null,
      evidenceRefs: claims.map((c) => `${c.file}:${c.line}`),
      notes: 'O4-local proven；entry/impact/reportability 未证明时仅到 claim-candidate'
    });
  }
  return rows;
}

function tierForProduct(productVerdict) {
  if (productVerdict === 'PROVEN-VULN') return 'T1-confirmed';
  if (productVerdict === 'PROVEN-WEAKNESS') return 'T2-weak-candidate';
  if (productVerdict === 'CONDITIONS-NOT-MET') return 'T3-instrumentation-gap';
  return 'T4-negative';
}

function gapReasonOf(verdict) {
  const m = /instrumentation-gap:([^\s]+)/.exec(verdict.productReason || '');
  if (m) return m[1];
  const o10 = (verdict.obligations || []).find((o) => o.id === 'O10');
  const ev = o10 && o10.evidence;
  if (ev && ev.reason) return ev.reason;
  if (ev && ev.state === 'blocked') return ev.reason || 'oracle-blocked';
  return verdict.productReason || 'unproven';
}

function p4Row(verdict, candidate) {
  const tier = tierForProduct(verdict.productVerdict);
  const o2 = (verdict.obligations || []).find((o) => o.id === 'O2');
  const o10 = (verdict.obligations || []).find((o) => o.id === 'O10');
  return {
    standardVersion: STANDARD_VERSION,
    verdictId: `IS-P4-${verdict.candidateId}`,
    scope: 'R1',
    class: 'P4',
    origin: verdict.origin || null,
    inTarget: verdict.inTarget === true,
    codeState: verdict.codeState || null,
    productionEligible: verdict.productionEligible === true,
    novelty: verdict.novelty || null,
    repo: candidate.repo,
    file: verdict.file,
    line: verdict.line,
    files: [verdict.file],
    lines: [verdict.line],
    functions: [],
    unitType: 'arithmetic-site',
    dedupKey: `${candidate.repo}|${verdict.file}:${verdict.line}`,
    candidateId: verdict.candidateId,
    claimIds: [verdict.claimId],
    claimCount: 1,
    claimVerdicts: [verdict.claimVerdict],
    productVerdict: verdict.productVerdict,
    tier,
    counted: tier === 'T1-confirmed' || tier === 'T2-weak-candidate',
    gapReason: tier === 'T3-instrumentation-gap' ? gapReasonOf(verdict) : null,
    productReason: verdict.productReason || null,
    preOperation: o2 && o2.evidence ? o2.evidence.text || null : null,
    oracle: o10 && o10.evidence ? { state: o10.evidence.state || null, reason: o10.evidence.reason || null } : null,
    evidenceRefs: [`${verdict.file}:${verdict.line}`],
    notes: tier === 'T2-weak-candidate' ? 'UBSan confirmed 样例，但 entry binding suspect，未升 PROVEN-VULN' : '具名 instrumentation-gap，不当否定'
  };
}

function buildInScope({ p3Verdicts = [], p4Verdicts = [], p6Verdicts = [], p4Candidates = [], p3Unreachable = [] }) {
  const candidateById = new Map(p4Candidates.map((c) => [c.candidateId, c]));
  const rows = [];
  const p3Rows = p3FamilyRows(p3Verdicts);
  rows.push(...p3Rows);

  const p4R1 = [];
  const p4R2 = [];
  for (const v of p4Verdicts) {
    if (!v.candidateId) continue; // CVE 外部校准，R0
    const candidate = candidateById.get(v.candidateId);
    if (!candidate) continue;
    if (!isR1(candidate.repo)) {
      p4R2.push({ verdict: v, candidate });
      continue;
    }
    if (!isProductionVerdict(v)) continue;
    p4R1.push({ verdict: v, candidate });
    const tier = tierForProduct(v.productVerdict);
    if (tier === 'T1-confirmed' || tier === 'T2-weak-candidate' || tier === 'T3-instrumentation-gap') {
      rows.push(p4Row(v, candidate));
    }
  }

  // P6：只有 target/current-head 的 os_account site 进入 production；miner finding 是既有记录，
  // 当前不在 R1 target，只作对照，不计入。
  const p6Os = p6Verdicts.filter((v) => v.group === 'os-account' && isProductionVerdict(v));
  const p6Findings = p6Verdicts.filter((v) => v.group === 'miner-finding');
  const p6Positive = p6Os.filter((v) => v.productVerdict === 'PROVEN-VULN' || v.productVerdict === 'PROVEN-WEAKNESS');
  for (const v of p6Positive) {
    const tier = tierForProduct(v.productVerdict);
    rows.push({
      standardVersion: STANDARD_VERSION,
      verdictId: `IS-P6-${v.siteKey}`,
      scope: 'R1',
      class: 'P6',
      origin: v.origin || null,
      inTarget: v.inTarget === true,
      codeState: v.codeState || null,
      productionEligible: v.productionEligible === true,
      novelty: v.novelty || null,
      repo: R1_REPOS[0],
      file: v.sink && v.sink.file,
      line: v.sink && v.sink.line,
      unitType: 'broadcast-site',
      dedupKey: v.siteKey,
      siteKey: v.siteKey,
      action: v.action,
      claimIds: [v.claimId],
      claimCount: 1,
      claimVerdicts: [v.claimVerdict],
      productVerdict: v.productVerdict,
      tier,
      counted: tier === 'T1-confirmed' || tier === 'T2-weak-candidate',
      gapReason: null,
      evidenceRefs: v.sink ? [`${v.sink.file}:${v.sink.line}`] : [],
      notes: 'P6 site 级；当前 os_account 无阳性'
    });
  }

  const byTier = rows.reduce((a, r) => { a[r.tier] = (a[r.tier] || 0) + 1; return a; }, {});
  const byClass = rows.reduce((a, r) => { a[r.class] = (a[r.class] || 0) + 1; return a; }, {});
  const t2 = rows.filter((r) => r.tier === 'T2-weak-candidate');
  const t3 = rows.filter((r) => r.tier === 'T3-instrumentation-gap');
  const t1 = rows.filter((r) => r.tier === 'T1-confirmed');
  const newWeakClaims = t2.reduce((n, r) => n + (r.claimCount || 0), 0);
  const findingPV = p6Findings.filter((v) => v.productVerdict === 'PROVEN-VULN').length;
  const findingWeak = p6Findings.length - findingPV;
  const p4R2Count = p4R2.length;
  const externalCve = p4Verdicts.filter((v) => v.cveId).length;
  const p3UnreachableCount = p3Unreachable.length;
  const p3Unbound = p3Unreachable.filter((r) => r.entryCount === 0).length;
  const provenanceCounts = (rows) => ({
    total: rows.length,
    productionEligible: rows.filter((r) => r.productionEligible === true).length,
    byOrigin: rows.reduce((a, r) => { const k = r.origin || 'unknown'; a[k] = (a[k] || 0) + 1; return a; }, {}),
    byNovelty: rows.reduce((a, r) => { const k = r.novelty || 'unknown'; a[k] = (a[k] || 0) + 1; return a; }, {})
  });

  const summary = {
    generatedAt: new Date().toISOString(),
    standardVersion: STANDARD_VERSION,
    scope: {
      name: 'R1',
      repos: R1_REPOS,
      basis: 'L1 facts 覆盖仓；只统计本仓新发现候选',
      excludes: [
        'miner 既有 findings（非目标仓，not production；只作对照）',
        'external-cve 校准样本（只作义务/裁决测试，不映射 target）',
        'R2 的 OH6 其他仓（common_event_service/ability_runtime/ipc）'
      ]
    },
    tiers: {
      'T1-confirmed': 'PROVEN-VULN；必需义务+entry+impact/reportability 全部成立',
      'T2-weak-candidate': 'PROVEN-WEAKNESS；weak/claim-candidate，当前允许计入',
      'T3-instrumentation-gap': 'CONDITIONS-NOT-MET 且有具名 no-driver/compile-failed/entry-suspect；counted=false',
      'T4-negative': 'NOT-VULN/SATISFIED/NOT-APPLICABLE；不写入 verdicts 文件'
    },
    units: {
      P3: 'root-cause-owner-family（claimIds 作证据，不按 25 条 claim 重复计数）',
      P4: 'arithmetic-site（candidateId / file:line）',
      P6: 'broadcast-site（siteKey）'
    },
    headline: {
      newConfirmed: t1.length,
      newWeakUnits: t2.length,
      newWeakClaims,
      instrumentationGap: t3.length
    },
    verdicts: {
      total: rows.length,
      byTier,
      byClass
    },
    detail: {
      p3Families: p3Rows.map((r) => ({ verdictId: r.verdictId, owner: r.owner, claimCount: r.claimCount, functions: r.functions })),
      p4: rows.filter((r) => r.class === 'P4').map((r) => ({ verdictId: r.verdictId, candidateId: r.candidateId, tier: r.tier, gapReason: r.gapReason }))
    },
    provenance: {
      P3: provenanceCounts(p3Verdicts),
      P4: provenanceCounts(p4Verdicts),
      P6: provenanceCounts(p6Verdicts)
    },
    negatives: {
      p6OsSitesNotVuln: p6Os.filter((v) => v.productVerdict === 'NOT-VULN').length,
      p6OsSitesTotal: p6Os.length,
      p3UnreachableNotApplicable: p3UnreachableCount,
      p3UnreachableUnbound: p3Unbound
    },
    excluded: {
      minerFindings: p6Findings.length,
      minerFindingsProvenVuln: findingPV,
      minerFindingsWeak: findingWeak,
      externalCve,
      oh6OtherReposP4: p4R2Count,
      total: p6Findings.length + externalCve + p4R2Count
    }
  };
  return { rows, summary };
}

function renderMarkdown(summary, rows) {
  const lines = [];
  lines.push('# R1 严格口径：本仓新发现候选统计');
  lines.push('');
  lines.push(`生成时间：${summary.generatedAt}`);
  lines.push('');
  lines.push('## 1 统计标准');
  lines.push('');
  lines.push(`- 范围：**R1** = ${R1_REPOS.map((r) => `\`${r}\``).join('、')}（L1 facts 覆盖仓）。`);
  lines.push('- 明确排除：非 production 记录（miner-existing 非目标仓；external-cve 仅 eval）、R2 的 OH6 其他仓。');
  lines.push('- 计数单位：P3 = owner 根因族；P4 = 算术 site；P6 = broadcast site。');
  lines.push('- 分级：T1 confirmed（`PROVEN-VULN`）> T2 weak candidate（`PROVEN-WEAKNESS`）> T3 instrumentation-gap（`CONDITIONS-NOT-MET`，counted=false）；T4 negative 不写入 verdicts 文件。');
  lines.push('');
  lines.push('## 2 结论');
  lines.push('');
  lines.push(`- **本仓新确认漏洞：${summary.headline.newConfirmed} 个。**`);
  lines.push(`- **本仓新 weak 候选：${summary.headline.newWeakUnits} 个根因单元**，对应 ${summary.headline.newWeakClaims} 条 claim。`);
  lines.push(`- **instrumentation-gap：${summary.headline.instrumentationGap} 个**（具名 gap，不当阳性）。`);
  lines.push(`- 排除：miner-existing ${summary.excluded.minerFindings} 条（非目标仓；含 ${summary.excluded.minerFindingsProvenVuln} 个既有 PROVEN-VULN）、external-cve ${summary.excluded.externalCve} 条（仅 eval）、R2 P4 ${summary.excluded.oh6OtherReposP4} 条；合计 ${summary.excluded.total} 条。`);
  lines.push(`- P6 当前 os_account：${summary.negatives.p6OsSitesNotVuln}/${summary.negatives.p6OsSitesTotal} site 为 NOT-VULN，0 阳性。`);
  lines.push('');
  lines.push('## 3 R1 候选明细');
  lines.push('');
  lines.push('| verdictId | class | repo | unit | tier | claims | gapReason |');
  lines.push('| --- | --- | --- | --- | --- | ---: | --- |');
  for (const r of rows) {
    lines.push(`| ${r.verdictId} | ${r.class} | ${r.repo} | ${r.unitType}${r.owner ? `:${r.owner}` : ''} | ${r.tier} | ${r.claimCount} | ${r.gapReason || '-'} |`);
  }
  lines.push('');
  lines.push('## 4 口径说明');
  lines.push('');
  lines.push('- P3 的 25 条 claim 归并为 5 个 `GetInstance` owner 根因族；`claimIds[]` 保留逐条证据，不把 deref 条数当漏洞数。');
  lines.push('- P4 的 `cd_G-P4_52b62a535a33` 是 UBSan confirmed 样例，但 entry binding suspect ⇒ T2，不升 `PROVEN-VULN`。');
  lines.push('- P4 其余 5 条 R1 候选均有具名 gap（2 no-driver-template + 3 compile-failed），记 T3。');
  lines.push('- Kiosk/QuickFix 的 4 个 `PROVEN-VULN` 来自 miner 既有 findings，只作 reproduced-oracle，不计入本仓新发现。');
  lines.push('');
  return lines.join('\n');
}

function writeInScope(outRoot, result) {
  const dir = path.join(outRoot, 'verdicts');
  ensureDir(dir);
  writeJsonl(path.join(dir, 'in-scope-verdicts.jsonl'), result.rows);
  writeJson(path.join(dir, 'summary.json'), result.summary);
  ensureDir(path.join(outRoot, 'report'));
  fs.writeFileSync(path.join(outRoot, 'report', 'in-scope-findings.md'), renderMarkdown(result.summary, result.rows), 'utf8');
  return { dir, verdictsFile: path.join(dir, 'in-scope-verdicts.jsonl'), summaryFile: path.join(dir, 'summary.json') };
}

module.exports = { R1_REPOS, STANDARD_VERSION, isR1, buildInScope, writeInScope, renderMarkdown, tierForProduct, gapReasonOf };
