'use strict';

/**
 * lib/autonomy/report.js —— report-model 与 C/O/F 渲染（P6）。
 *
 * 硬规则（§3.1）：
 *   binding=supported 且 check=refuted  ⇒ candidate
 *   binding=supported 且 check=supported ⇒ observation
 *   binding=insufficient                ⇒ observation
 *   其他                                ⇒ observation
 *
 * `finding` 在 MVP **不产出**：`FINDINGS.md` 为空并写明原因（无 runtime witness）。
 * `report --run` 只从已提交记录重建，**不重新裁决**。
 */

const fs = require('fs');
const path = require('path');

const ids = require('./ids');
const jsonl = require('./jsonl');
const state = require('./state');

const REPORT_VERSION = '1';

function byTask(rows) {
  const m = new Map();
  for (const r of rows) {
    const t = r.payload ? r.payload.taskId : r.taskId;
    if (!m.has(t)) m.set(t, []);
    m.get(t).push(r);
  }
  return m;
}

function questionMap(questions) {
  const m = new Map();
  for (const q of questions) m.set(q.payload.questionId, q.payload);
  return m;
}

function assessmentByQuestion(assessments) {
  const m = new Map();
  for (const a of assessments) m.set(a.payload.questionId, a.payload);
  return m;
}

/** 由已提交记录构建报告模型（纯函数） */
function buildReportModel({ tasks, questions, assessments, missing, manifestId, snapshotId, architectureVersion, staticProof, staticProofs }) {
  const staticScan = ['1.0.15-static-scan', '1.0.16-static-scan'].includes(architectureVersion);
  const arbitrationScan = ['1.0.18-static-arbitration', '1.0.19-autonomous-static'].includes(architectureVersion);
  const securityVerdict = ['1.0.20-security-verdict', '1.0.21-sa-method-verdict',
    '1.0.22-ipc-code-verdict', '1.0.23-rust-ipc-code-verdict'].includes(architectureVersion);
  const suiteScan = arbitrationScan || securityVerdict || architectureVersion === '1.0.17-static-scan';
  const experiment = ['1.0.1-auth-experiment', '1.0.2-auth-experiment',
    '1.0.3-vertical-experiment', '1.0.4-vertical-experiment',
    '1.0.5-vertical-experiment', '1.0.6-vertical-experiment',
    '1.0.7-vertical-experiment', '1.0.8-vertical-experiment',
    '1.0.9-vertical-experiment', '1.0.10-vertical-experiment',
    '1.0.11-vertical-experiment', '1.0.12-vertical-experiment',
    '1.0.13-vertical-experiment', '1.0.14-static-experiment',
     '1.0.15-static-scan', '1.0.16-static-scan', '1.0.17-static-scan',
     '1.0.18-static-arbitration', '1.0.19-autonomous-static',
     '1.0.20-security-verdict', '1.0.21-sa-method-verdict',
     '1.0.22-ipc-code-verdict', '1.0.23-rust-ipc-code-verdict'].includes(architectureVersion);
  const qById = questionMap(questions);
  const aByQ = assessmentByQuestion(assessments);
  const missById = new Map(missing.map((m) => [m.payload.missingId, m.payload]));
  const qsByTask = new Map();
  for (const q of questions) {
    if (!qsByTask.has(q.payload.taskId)) qsByTask.set(q.payload.taskId, []);
    qsByTask.get(q.payload.taskId).push(q.payload);
  }

  const rows = [];
  for (const task of [...tasks].sort((a, b) => (a.payload.taskId < b.payload.taskId ? -1 : 1))) {
    const t = task.payload;
    const qs = qsByTask.get(t.taskId) || [];
    const bindingQ = qs.find((q) => q.kind === 'binding') || null;
    const checkQ = qs.find((q) => q.kind === 'check-presence') || null;
    const permissionQ = qs.find((q) => q.kind === 'permission-argument-match') || null;
    const suitePermissionQ = qs.find((q) => q.kind === 'static-permission-match') || null;
    const contractQ = qs.find((q) => q.kind === 'static-contract') || null;
    const contractA = contractQ ? aByQ.get(contractQ.questionId) || null : null;
    const domQ = qs.find((q) => q.kind === 'dominance') || null;
    const bindingA = bindingQ ? aByQ.get(bindingQ.questionId) || null : null;
    const checkA = checkQ ? aByQ.get(checkQ.questionId) || null : null;
    const domA = domQ ? aByQ.get(domQ.questionId) || null : null;

    const bindingStatus = bindingA ? bindingA.decision : (bindingQ ? bindingQ.status : 'insufficient');
    const checkStatus = checkA ? checkA.decision : (checkQ ? checkQ.status : 'insufficient');

    let reportability;
    if (!bindingQ || !checkQ) reportability = architectureVersion === '1.0.14-static-experiment' || staticScan || suiteScan
      ? 'observation' : 'excluded';
    else if (bindingStatus === 'supported' && checkStatus === 'refuted') reportability = 'candidate';
    else if (bindingStatus === 'supported' && checkStatus === 'supported') reportability = 'observation';
    else if (bindingStatus === 'insufficient' || bindingStatus === 'conflict') reportability = 'observation';
    else reportability = 'observation';

    const allMissingIds = ids.uniqueSorted(qs.flatMap((q) => [
      ...q.missingRefs, ...(aByQ.get(q.questionId) || { missingRefs: [] }).missingRefs
    ]));
    const reasons = ids.uniqueSorted(allMissingIds.map((id) => {
      const rec = missById.get(id);
      return rec ? rec.reasonCode : 'unknown-missing';
    }));

    const evidenceRefs = ids.uniqueSorted(qs.flatMap((q) =>
      (aByQ.get(q.questionId) || { evidenceRefs: [] }).evidenceRefs));

    if (experiment && reportability === 'candidate' &&
        (t.origin !== 'entry-scan' || !t.operationRef || reasons.includes('delegated-check-unproven') ||
         reasons.includes('delegation-incomplete'))) reportability = 'observation';

    const proof = suiteScan ? staticProofs?.[t.taskId] : t.taskId === staticProof?.taskId ? staticProof.staticProof : null;
    if (architectureVersion === '1.0.14-static-experiment' && t.origin === 'entry-scan' &&
        ['finding', 'excluded'].includes(proof?.status) &&
        permissionQ && aByQ.get(permissionQ.questionId)?.decision ===
          (proof.status === 'finding' ? 'refuted' : 'supported')) reportability = proof.status;
    if (suiteScan && !securityVerdict && t.origin === 'entry-scan' && ['finding', 'excluded'].includes(proof?.status) &&
        t.operationRef === proof.operationRef && aByQ.get(contractQ?.questionId)?.decision ===
          (proof.status === 'finding' ? 'refuted' : 'supported')) reportability = proof.status;
    if (arbitrationScan && t.origin === 'entry-scan' && t.operationRef === proof?.operationRef &&
        ((proof?.status === 'excluded' && contractA?.decision === 'conflict' &&
          reasons.includes('prover-model-conflict')) ||
         (proof?.status === 'insufficient' && contractA?.decision === 'insufficient' &&
          reasons.includes('static-contract-suspect')))) reportability = 'candidate';
    // 1.0.20 双命题：出口等级由 securityDecision 裁决决定，契约差异只降不到 observation 之下。
    // candidate 沿用候选纪律：必须绑定具体操作（operationRef）；操作未绑定时即使有
    // 模型反例也保持 observation，缺口里保留 model-supported-suspect 供后续取证。
    let securityCounterexample = null;
    if (securityVerdict && t.origin === 'entry-scan') {
      const secQ = qs.find((q) => q.kind === 'security-decision') || null;
      const secA = secQ ? aByQ.get(secQ.questionId) || null : null;
      const suspectCandidate = secA?.decision === 'insufficient' &&
        (reasons.includes('prover-model-conflict') || reasons.includes('model-supported-suspect') ||
         proof?.status === 'candidate' || reasons.includes('policy-anchor-doc-only') ||
         reasons.includes('acl-enabled-obtainability-deployment-dependent') ||
         reasons.includes('permission-obtainable-by-subject'));
      if (['finding', 'excluded'].includes(proof?.status) && t.operationRef === proof.operationRef &&
          secA?.decision === (proof.status === 'finding' ? 'supported' : 'refuted')) {
        reportability = proof.status;
      } else if (suspectCandidate && t.operationRef) {
        reportability = 'candidate';
        if (secA?.modelCallRef) securityCounterexample = secA.rationale;
      } else reportability = 'observation';
    }

    const semantic = {
      taskId: t.taskId,
      entryRef: t.anchorRefs[0],
      ...(experiment ? { origin: t.origin } : {}),
      reportability,
      decision: reportability === 'finding' ? (securityVerdict ? 'supported' : 'refuted') :
        reportability === 'excluded' && proof ? (securityVerdict ? 'refuted' : 'supported') :
          arbitrationScan && reportability === 'candidate' && contractA?.decision === 'conflict' ? 'conflict' : 'insufficient',
      ...(arbitrationScan && reportability === 'candidate' && contractA?.modelCallRef
        ? { counterexampleRationale: contractA.rationale } : {}),
      ...(securityVerdict && reportability === 'candidate' && securityCounterexample
        ? { counterexampleRationale: securityCounterexample } : {}),
      ...(arbitrationScan && reportability === 'candidate' && proof?.operationRef
        ? { operationRef: proof.operationRef } : {}),
      ...(reportability === 'finding' || (reportability === 'excluded' && proof) ||
          (securityVerdict && reportability === 'candidate')
        ? { verificationStatus: 'static-only', assurance: proof.assurance,
          normRef: proof.normRef, reviewRef: proof.reviewRef, operationRef: proof.operationRef,
           ...(suiteScan && !securityVerdict ? { findingFamily: proof.family } : {}),
          ...(securityVerdict ? {
            securityFamily: proof.security?.family || undefined,
            ...(proof.security?.subject ? { securitySubject: proof.security.subject.description,
              securityProposition: proof.security.proposition } : {}),
            ...(proof.gates ? { gates: proof.gates } : {}),
            ...(proof.security?.anchor ? { anchorBasis: proof.security.anchor.basis } : {})
          } : { expectedPermission: proof.expectedPermission,
            observedPermission: proof.observedPermission }),
          limitation: proof.limitation } : {}),
      ...(securityVerdict && proof?.contract ? {
        contractDeviation: proof.contract.family === 'compliant' ? 'none'
          : (proof.contract.family || proof.contract.status),
        ...(proof.contract.status === 'not-applicable' ? {} : {
          expectedPermission: proof.expectedPermission,
          observedPermission: proof.observedPermission || 'unresolved' })
      } : {}),
       ...((suiteScan ? suitePermissionQ : permissionQ) ? { permissionArgument: {
         questionId: (suiteScan ? suitePermissionQ : permissionQ).questionId,
         decision: aByQ.get((suiteScan ? suitePermissionQ : permissionQ).questionId)?.decision || 'insufficient',
         evidenceRefs: aByQ.get((suiteScan ? suitePermissionQ : permissionQ).questionId)?.evidenceRefs || []
      } } : {}),
      missing: architectureVersion === '1.0.14-static-experiment' &&
        ['finding', 'excluded'].includes(reportability) ? [] : reasons,
      evidenceRefs,
      manifestId,
      snapshotId
    };
    rows.push({
      reportId: ids.reportId('report-model', semantic),
      ...semantic
    });
  }

  rows.sort((a, b) => (a.reportId < b.reportId ? -1 : a.reportId > b.reportId ? 1 : 0));

  const counts = {
    tasks: rows.length,
    candidate: rows.filter((r) => r.reportability === 'candidate').length,
    observation: rows.filter((r) => r.reportability === 'observation').length,
    excluded: rows.filter((r) => r.reportability === 'excluded').length,
    finding: rows.filter((r) => r.reportability === 'finding').length
  };
  const missingByReason = {};
  for (const r of rows) for (const reason of r.missing) missingByReason[reason] = (missingByReason[reason] || 0) + 1;
  const sortedMissing = {};
  for (const k of Object.keys(missingByReason).sort()) sortedMissing[k] = missingByReason[k];

  const summary = {
     reportVersion: securityVerdict ? '7' : arbitrationScan ? '6' : suiteScan ? '5' : staticScan ? '4' : architectureVersion === '1.0.14-static-experiment'
      ? '3' : experiment ? '2' : REPORT_VERSION,
    snapshotId,
    manifestId,
    counts,
    missingByReason: sortedMissing,
     findingClosedReason: securityVerdict
       ? (counts.finding ? null : '本次门禁与主体证据未取得满足 securityDecision 门槛的安全发现；契约差异见 OBSERVATIONS，不足不等于安全。')
       : suiteScan
       ? (counts.finding ? null : '本次知识套件与局部静态证明未产 finding；不足不等于安全。')
       : staticScan
      ? '通用范围扫描没有加载已发布适用规范和限定静态证明；0 finding 不代表无问题。'
      : architectureVersion === '1.0.14-static-experiment'
      ? (counts.finding ? null : '本轮没有满足已批准规范与局部静态证据链的发现；不代表安全。')
      : 'MVP 不产出 finding：没有 runtime witness，静态证据不足以支撑「已证漏洞」；本文件的空不是「无问题」，而是「未证」。',
    semanticHash: ids.semanticHash(rows),
    rows
  };
  return summary;
}

function recordizeReportModel(summary, manifestId, preserveCreatedAt) {
  const records = summary.rows.map((row) => state.makeRecord({
    recordId: row.reportId,
    recordType: 'report-model',
    manifestId,
    producer: state.PRODUCERS.report,
    dependencyRefs: [row.taskId, row.entryRef, ...row.evidenceRefs],
    payload: row,
    createdAt: preserveCreatedAt ? preserveCreatedAt.get(row.reportId) : undefined
  }));
  records.sort((a, b) => (a.recordId < b.recordId ? -1 : a.recordId > b.recordId ? 1 : 0));
  return records;
}

/** 复用上次已提交记录的 createdAt，使 `report` 的产物逐字节稳定（语义哈希本就排除它） */
function previousCreatedAt(store) {
  const file = store.file('report-model.jsonl');
  const map = new Map();
  if (!fs.existsSync(file)) return map;
  for (const row of jsonl.readJsonl(file).rows) {
    if (row && row.recordId && row.createdAt) map.set(row.recordId, row.createdAt);
  }
  return map;
}

function mdTable(headers, rows) {
  const esc = (v) => String(v === null || v === undefined ? '' : v).replace(/\|/g, '\\|').replace(/\n/g, ' ');
  return [
    `| ${headers.join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
    ...rows.map((r) => `| ${r.map(esc).join(' | ')} |`)
  ].join('\n');
}

function renderCandidates(summary, detailById) {
  const rows = summary.rows.filter((r) => r.reportability === 'candidate');
  const head = [
    '# CANDIDATES',
    '',
    summary.reportVersion === '7'
      ? '> **candidate 不是漏洞。** 它表示：已绑定具体操作的入口存在经证据门接受的疑点（模型反例或锚点不足的安全命题），尚缺主体—路径—锚点的决定性证据；契约差异本身不产生 candidate。'
      : ['2', '4', '6'].includes(summary.reportVersion)
      ? '> **candidate 不是漏洞。** 本实验要求入口、具体操作与缺口；一跳委托中的检查不证明有效。'
      : '> **candidate 不是漏洞。** 它只表示「入口绑定到唯一实现体，且实现体内**直接调用**中没看到词表内的校验调用」。',
    ''
  ];
  if (!rows.length) {
    return [...head, summary.reportVersion === '7'
      ? '本轮没有 candidate；操作未绑定的模型反例保留在 observation 的具名缺口中。'
      : '本轮没有 candidate。实验版未绑定具体操作时，此结果不表示没有风险或有召回能力。', ''].join('\n');
  }
  return [
    ...head,
    mdTable(
      summary.reportVersion === '7' ? ['entryRef', '实现体', '位置', '操作', '缺失', '模型反例'] :
        summary.reportVersion === '6' ? ['entryRef', '实现体', '位置', '缺失', '模型反例'] :
        ['entryRef', '实现体', '位置', '缺失'],
      rows.map((r) => {
        const d = detailById.get(r.entryRef) || {};
        return [r.entryRef, d.label || '', d.location || '',
          ...(summary.reportVersion === '7' ? [r.operationRef || 'unbound'] : []),
          r.missing.join(', '),
          ...(['6', '7'].includes(summary.reportVersion) ? [r.counterexampleRationale || ''] : [])];
      })
    ),
    ''
  ].join('\n');
}

function renderObservations(summary, detailById) {
  const rows = summary.rows.filter((r) => r.reportability === 'observation');
  const head = [
    '# OBSERVATIONS',
    '',
    summary.reportVersion === '7'
      ? '> observation = 契约差异（文档/声明与实现不一致）、门禁或路径不可判定、或仅覆盖缺口；契约差异不是安全结论。'
      : ['2', '4'].includes(summary.reportVersion)
      ? '> observation = 覆盖抽样、无具体操作、委托检查待证或绑定不足；不是安全结论。'
      : '> observation = 有检查调用但不证明有效，或入口未绑定到唯一实现体。',
    ''
  ];
  if (!rows.length) return [...head, '本轮没有 observation。', ''].join('\n');
  const deviationRows = summary.reportVersion === '7'
    ? summary.rows.filter((r) => r.contractDeviation && !['none', 'unknown', 'not-applicable'].includes(r.contractDeviation))
    : [];
  return [
    ...head,
    mdTable(
      ['entryRef', '标签', '位置', '缺失'],
      rows.map((r) => {
        const d = detailById.get(r.entryRef) || {};
        return [r.entryRef, d.label || '', d.location || '', r.missing.join(', ')];
      })
    ),
    ...(deviationRows.length ? [
      '', '## 契约差异（contractDeviation，非安全结论）', '',
      mdTable(['entryRef', '差异家族', '文档要求', '实际检查'],
        deviationRows.map((r) => {
          const d = detailById.get(r.entryRef) || {};
          return [r.entryRef, r.contractDeviation, r.expectedPermission || '', r.observedPermission || ''];
        })), ''
    ] : []),
    ''
  ].join('\n');
}

function renderFindings(summary) {
  if (summary.reportVersion === '4') {
    return ['# STATIC FINDINGS', '', summary.findingClosedReason, ''].join('\n');
  }
  if (summary.reportVersion === '7') {
    const rows = summary.rows.filter((r) => r.reportability === 'finding');
    return ['# SECURITY FINDINGS (static-only)', '', rows.length
      ? '> 安全 finding：具体不应获准的主体经实际门禁到达限定操作的完整静态证据链；不声明设备复现或可利用性。'
      : summary.findingClosedReason, '',
    ...rows.flatMap((r) => [
      `## ${r.entryRef}`, '',
      `- 结论：Security Finding (${r.verificationStatus}; ${r.assurance})`,
      `- 家族：${r.securityFamily}`,
      `- 规范：${r.normRef} / ${r.reviewRef}`,
      `- 操作：${r.operationRef}`,
      `- 主体：${r.securitySubject}`,
      `- 命题：${r.securityProposition}`,
      `- 策略锚点：${r.anchorBasis}`,
      `- 门禁：${(r.gates || []).map((g) => `${g.kind}@${g.line}${g.permission ? `(${g.permission})` : ''}`).join(', ') || 'none recognized'}`,
      `- 契约差异：${r.contractDeviation}`,
      `- 局限：${r.limitation}`, ''
    ])].join('\n');
  }
  if (['3', '6'].includes(summary.reportVersion)) {
    const rows = summary.rows.filter((r) => r.reportability === 'finding');
    return ['# STATIC FINDINGS', '', rows.length
      ? '> 静态权限契约不一致；不声明设备复现或可利用性。' : summary.findingClosedReason, '',
    ...rows.flatMap((r) => [
      `## ${r.entryRef}`, '',
      `- 结论：Static Finding (${r.verificationStatus}; ${r.assurance})`,
      `- 规范：${r.normRef} / ${r.reviewRef}`,
      `- 操作：${r.operationRef}`,
      `- 文档要求：${r.expectedPermission}`,
      `- 实际检查：${r.observedPermission}`,
      `- 权限实参证据：${r.permissionArgument?.evidenceRefs.join(', ') || 'none'}`,
      `- 局限：${r.limitation}`, ''
    ])].join('\n');
  }
  return [
    '# FINDINGS',
    '',
    '空。',
    '',
    `原因：${summary.findingClosedReason}`,
    '',
    '- MVP 的 `verify` 只登记计划并返回 `blocked`，不执行设备/host 验证；',
    '- 因此没有任何 runtime witness；没有 witness 就不出 finding（红线 §8.4）；',
    '- `Q-dominance` 恒为 `insufficient`（`dominance-unproven`）。',
    ''
  ].join('\n');
}

function renderReportMd(summary, meta) {
  const lines = [
    `# 自主审计 MVP 试点报告（${meta.scopeId}）`,
    '',
    `- runId：\`${meta.runId}\``,
    `- snapshotId：\`${summary.snapshotId}\``,
    `- inputManifestId：\`${meta.inputManifestId}\``,
    `- mode：\`${meta.mode}\``,
    `- tasks：${summary.counts.tasks}（candidate ${summary.counts.candidate} / observation ${summary.counts.observation} / excluded ${summary.counts.excluded} / finding ${summary.counts.finding}）`,
    `- report-model 语义哈希：\`${summary.semanticHash}\``,
    '',
    '## 这是什么，不是什么',
    '',
    '这是「问题 → 证据 → 裁决 → 报告」骨架的**可跑通验证**，不是漏洞清单。',
    summary.reportVersion === '7'
      ? '双命题语义：contractDeviation 只登记声明与实现的差异（observation 级）；finding 需要"具体主体经实际门禁到达限定操作"的完整静态证据链与合格策略锚点。'
      : summary.reportVersion === '4'
      ? '每个缺口都带具名原因（`missingByReason`）；本轮未加载已发布规范，不能作静态权限契约裁决。'
      : '每个缺口都带具名原因（`missingByReason`），没有 runtime witness 就不出 finding。',
    '',
    ...(summary.reportVersion === '7' ? [
      '## 双命题子问题（1.0.20）', '',
      '| 问题 | 命题 | 判定 |',
      '|---|---|---|',
      '| `Q-binding` | 入口能否绑定到唯一实现？ | 名称 + owner 段匹配；多候选/找不到 ⇒ insufficient |',
      '| `Q-contract-deviation` | 文档权限契约声明与实现是否一致？ | 一致 ⇒ supported；差异 ⇒ refuted（仅契约差异，非安全结论）；不可比 ⇒ insufficient |',
      '| `Q-security-decision` | 所构造的具体主体能否经实际门禁到达限定敏感操作？ | 全部门禁拒绝该主体 ⇒ refuted（scoped excluded）；主体到达且有合格策略锚点 ⇒ supported（finding）；锚点不足或路径未闭合 ⇒ insufficient |',
      '| `Q-dominance` | 校验是否支配敏感操作、对象是否一致？ | 本问题本身**恒 insufficient**（missing=dominance-unproven）；门禁与拒绝分支的有界支配判定在 security-decision 命题内进行，不改变本问题状态 |',
      ''
    ] : [
      '## 三个固定子问题', '',
      '| 问题 | 命题 | MVP 判定 |',
      '|---|---|---|',
      '| `Q-binding` | 入口能否绑定到唯一实现？ | 名称 + owner 段匹配；多候选/找不到 ⇒ insufficient |',
      '| `Q-check` | 实现体内是否有权限/身份校验调用？ | 词表命中 ⇒ supported；未命中且绑定成功 ⇒ refuted |',
      '| `Q-dominance` | 校验是否支配敏感操作、对象是否一致？ | **恒 insufficient**（missing=dominance-unproven） |',
      ''
    ]),
    '',
    '## 缺口分布',
    '',
    summary.missingByReason && Object.keys(summary.missingByReason).length
      ? mdTable(['reasonCode', 'tasks'], Object.keys(summary.missingByReason).map((k) => [k, summary.missingByReason[k]]))
      : '（无）',
    '',
    '## 计数口径',
    '',
    ...(summary.reportVersion === '7' ? [
      '- `candidate` = 已绑定具体操作的入口存在经证据门接受的疑点（模型反例或锚点不足的安全命题），尚缺主体—路径—锚点决定性证据；操作未绑定时保持 observation。',
      '- `observation` = 契约差异、门禁或路径不可判定、或仅覆盖缺口；契约差异不是安全结论。',
      '- `excluded` 仅排除所限定的主体与路径命题，不代表入口整体安全。',
      '- `finding` 为 static-only 安全发现（具体主体经实际门禁到达限定操作 + 合格策略锚点）。'
    ] : [
      ['2', '3', '4'].includes(summary.reportVersion)
        ? '- `candidate` = 已绑定入口和具体操作、直接校验调用未命中且无一跳委托检查或取证不完整；仍非漏洞。当前未绑定具体操作，不能评估召回。'
        : '- `candidate` = binding supported **且** check refuted；',
      '- `observation` = 有检查调用（不证明有效）**或** 绑定不足；',
      ['3', '6'].includes(summary.reportVersion) ? '- `finding` 为 static-only 权限契约发现，不证明设备影响。'
        : summary.reportVersion === '4' ? '- `finding` 为 0：本轮未加载已发布规范；不排除可由其他静态证据支持的发现。'
          : '- `finding` 恒为 0：无 runtime witness。'
    ]),
    ...(meta.vertical ? [
      '', '## 纵向授权实验', '',
      `- taskId：` + meta.vertical.taskId,
      `- normRef：` + (meta.vertical.normRef || 'unavailable') +
        (summary.reportVersion === '3' ? '（Builder-LLM 来源，已发布）' : '（规范提案，未发布）'),
      `- 入口到操作：` + (meta.vertical.operationCallsites || []).map((x) =>
        `${x.ref} (${x.resolution})`).join(', '),
      ...(meta.vertical.operationCandidates ? [
        `- 源码限定操作候选：` + meta.vertical.operationCandidates.map((x) =>
          `${x.targetRef} (${x.status}; ${x.source.file}:${x.source.line})`).join(', ') +
          '；目标仍未证明。'
      ] : []),
      `- 反证：` + (meta.vertical.checkRefs || []).join(', '),
      `- 结论：` + meta.vertical.status + ' / ' + (meta.vertical.reason || 'none'),
      ...(meta.vertical.permissionArgument ? [
        '- 权限参数局部比较：' + (summary.rows.find((r) => r.taskId === meta.vertical.taskId)?.permissionArgument?.decision || 'insufficient') +
          '（' + (meta.vertical.permissionArgument.observedPermission || 'unknown') +
          ' / 文档 ' + (meta.vertical.permissionArgument.expectedPermission || 'unknown') + '）；不代表规范适用或授权效果。'
      ] : []),
      summary.reportVersion === '3'
        ? '- 静态裁决只涵盖权限契约与局部限定目标，不证明设备运行影响或整体授权安全。'
        : '- 此实验不证明完整 IPC 路径、操作目标或运行影响。'
    ] : []),
    ''
  ];
  return lines.join('\n');
}

/**
 * 写报告三件套 + report-model + manifest + checksums。
 * @param {object} store RunStore
 * @param {{scopeId:string, mode:string, inputManifestId:string, detailById?:Map}} meta
 */
function writeReport(store, meta) {
  const tasks = store.readRecords('task').rows;
  const questions = store.readRecords('question').rows;
  const assessments = store.readRecords('assessment').rows;
  const missing = store.readRecords('missing').rows;

  const summary = buildReportModel({
    tasks,
    questions,
    assessments,
    missing,
    manifestId: store.manifestId,
    snapshotId: store.run.payload.snapshotId,
    architectureVersion: store.run.payload.architectureVersion,
    staticProof: fs.existsSync(store.file('vertical-analysis.json'))
      ? JSON.parse(fs.readFileSync(store.file('vertical-analysis.json'), 'utf8')) : null,
    staticProofs: fs.existsSync(store.file('static-proofs.json'))
      ? JSON.parse(fs.readFileSync(store.file('static-proofs.json'), 'utf8')) : null
  });

  const records = recordizeReportModel(summary, store.manifestId, previousCreatedAt(store));
  jsonl.writeJsonl(store.file('report-model.jsonl'), records);
  store.writeJson('report-model.json', {
    reportVersion: summary.reportVersion,
    snapshotId: summary.snapshotId,
    manifestId: summary.manifestId,
    counts: summary.counts,
    missingByReason: summary.missingByReason,
    findingClosedReason: summary.findingClosedReason,
    semanticHash: summary.semanticHash
  });

  const detailById = meta.detailById || new Map();
  store.writeText('CANDIDATES.md', renderCandidates(summary, detailById));
  store.writeText('OBSERVATIONS.md', renderObservations(summary, detailById));
  store.writeText('FINDINGS.md', renderFindings(summary));
  store.writeText('report.md', renderReportMd(summary, {
    runId: store.runId,
    scopeId: meta.scopeId || store.run.payload.scopeId,
    mode: meta.mode || store.run.payload.mode,
    inputManifestId: meta.inputManifestId || store.run.payload.inputManifestId,
    vertical: fs.existsSync(store.file('vertical-analysis.json'))
      ? JSON.parse(fs.readFileSync(store.file('vertical-analysis.json'), 'utf8')) : null
  }));

  const artifacts = [
    'report-model.jsonl',
    'report-model.json',
    'CANDIDATES.md',
    'OBSERVATIONS.md',
    'FINDINGS.md',
    'report.md'
  ];
  store.updateManifest({ artifactRefs: artifacts, counts: summary.counts, semanticHash: summary.semanticHash });
  const checksums = store.writeChecksums({ counts: summary.counts, semanticHash: summary.semanticHash });
  return { summary, artifacts, records, artifactRefs: Object.keys(checksums.files) };
}

module.exports = {
  REPORT_VERSION,
  buildReportModel,
  recordizeReportModel,
  writeReport,
  renderCandidates,
  renderObservations,
  renderFindings,
  renderReportMd
};
