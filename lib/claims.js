'use strict';

/**
 * claims.js —— L3：把 seed/事实升级为可执行 claim。
 *
 * 口径：
 *   - claim 只是“待验证命题”，L3 不写 PROVEN-VULN；
 *   - 每条 obligation 必须有 id/kind/status/evidence；status 只允许
 *     proven|disproven|unproven|invalid；
 *   - P6 判定单位是 site（不是 action）；
 *   - P3 候选 = 现有 reachable potential 5 条 + 1a/2a 扩充后 owner-aware 可解析的 20 条；
 *     其余 reachable-unbound 逐条记 owner/type/guard 原因；
 *   - P4 的 O2 只从 pre/removed 行取 operation。
 */

const OBLIGATION_STATUS = new Set(['proven', 'disproven', 'unproven', 'invalid']);
const { ORIGINS, CODE_STATES, classify } = require('./candidate-origin.js');
const { isR1 } = require('./in-scope.js');

function repoOfFile(file) {
  return String(file || '').split('/').filter(Boolean).slice(0, 3).join('/');
}

function provenanceFor({ origin, repo, inTarget, codeState, constructed = false, regression = false }) {
  const target = inTarget == null ? isR1(repo) : inTarget === true;
  const c = classify({ origin, inTarget: target, codeState: codeState == null ? null : codeState, constructed, regression });
  if (c.errors.length) throw new Error(`provenance: ${c.errors.join(',')}`);
  return {
    origin: c.origin,
    inTarget: c.inTarget,
    codeState: c.codeState,
    constructed: c.constructed,
    productionEligible: c.productionEligible,
    novelty: c.novelty
  };
}

let rg1NegativeCache = null;
function rg1NegativeActions() {
  if (rg1NegativeCache) return rg1NegativeCache;
  try {
    const fs = require('fs');
    const path = require('path');
    const { WORKSPACE } = require('./util.js');
    const spec = JSON.parse(fs.readFileSync(path.join(WORKSPACE, 'oh6-vuln-agent', 'spec', 'rg1.json'), 'utf8'));
    rg1NegativeCache = new Set((spec.negative || []).flatMap((n) => n.actions || []));
  } catch (_) {
    rg1NegativeCache = new Set();
  }
  return rg1NegativeCache;
}

function obligation(id, kind, evidence = {}) {
  return { id, kind, status: 'unproven', evidence };
}

function stableClaimId(prefix, key) {
  return `${prefix}-${String(key).replace(/[^A-Za-z0-9_.:-]+/g, '_')}`;
}

function isActionSet(w) {
  return /^set(action|code)$/i.test(String(w.setter || w.key || '')) || String(w.key || '') === 'SetAction';
}

function writeSummary(writes) {
  const list = (writes || []).map((w) => ({
    setter: w.setter || null,
    kind: w.kind || null,
    key: w.key == null ? null : w.key,
    line: w.line == null ? null : w.line,
    resolved: w.substitutionStatus || w.status || null,
    classified: w.classified ? w.classified.kind : null,
    value: w.resolvedValueExpr || w.rawValueExpr || w.value || null
  }));
  return {
    count: list.length,
    resolved: list.filter((w) => w.resolved === 'resolved').length,
    unresolved: list.filter((w) => w.resolved && w.resolved !== 'resolved').length,
    classifiedUnresolved: list.filter((w) => w.classified === 'unresolved').length,
    keys: [...new Set(list.map((w) => w.key).filter(Boolean))],
    writes: list
  };
}

/** P6：单个 site 的 L3 claim */
function buildP6Claim(l1, site, opts = {}) {
  const gate = l1.minerGate(site.siteKey) || {};
  const slice = l1.minerSlice(site.siteKey) || null;
  const finding = l1.minerFinding(site.siteKey) || null;
  const rejection = l1.minerRejection(site.siteKey) || null;
  const verdict = gate.verdict || {};
  const siteWrites = (site.payloadWrites || []).length ? site.payloadWrites : (slice && slice.writes) || [];
  const payloadWrites = siteWrites.filter((w) => !isActionSet(w));
  const actionSetWrites = siteWrites.filter((w) => isActionSet(w));
  const summary = writeSummary(payloadWrites);
  const records = (site.src && site.src.recordIds) || [];
  const claimGroup = opts.group || (finding ? 'miner-finding' : 'os-account');
  const sink = site.sink || {};
  const claimRepo = repoOfFile(sink.file);
  const claimOrigin = claimGroup === 'miner-finding' ? ORIGINS.MINER_EXISTING : ORIGINS.TARGET;
  const claimInTarget = isR1(claimRepo);
  const provenance = provenanceFor({
    origin: claimOrigin,
    repo: claimRepo,
    inTarget: claimInTarget,
    codeState: claimInTarget ? CODE_STATES.CURRENT_HEAD : null
  });
  const sourceLoc = {
    siteKey: site.siteKey,
    siteId: site.siteId == null ? null : site.siteId,
    recordId: records[0] == null ? null : records[0],
    recordIds: records,
    action: site.action,
    actionExpr: site.actionExpr || null,
    eventClass: site.eventClass || null,
    payloadWrites: summary.writes,
    actionSetWrites: actionSetWrites.length
  };
  return {
    claimId: stableClaimId('L3-P6', site.siteKey),
    class: 'P6',
    group: claimGroup,
    ...provenance,
    entry: {
      kind: 'broadcast-site',
      siteKey: site.siteKey,
      siteId: site.siteId == null ? null : site.siteId,
      action: site.action,
      recordId: records[0] == null ? null : records[0],
      recordIds: records,
      carrier: site.carrier || null,
      thirdPartyReachability: site.thirdPartyReachability || null
    },
    source: sourceLoc,
    sink: {
      file: sink.file || null,
      function: sink.function || null,
      line: sink.line == null ? null : sink.line,
      api: sink.api || null,
      root: site.root || null,
      callChain: site.callChain || []
    },
    obligations: [
      obligation('O1', 'action-resolved', {
        action: site.action,
        actionExpr: site.actionExpr || null,
        actionDerived: verdict.c1_action_derived === true,
        gateC1: gate.C1 === undefined ? null : gate.C1
      }),
      obligation('O2', 'receiver-undirected', {
        c2State: gate.C2 || null,
        c2Unspecified: verdict.C2_recipient_unspecified,
        c2Detail: verdict.C2_detail || null,
        providerReachability: site.thirdPartyReachability || null,
        receiverReasons: site.reachabilityReasons || []
      }),
      obligation('O3', 'no-subscriber-permission', {
        c3State: gate.C3 || null,
        c3NoPermission: verdict.C3_no_subscriber_permission,
        c3Detail: verdict.C3_detail || null,
        subscriberPermissions: site.subscriberPermissions || [],
        directedSubscriberUids: site.directedSubscriberUids || []
      }),
      obligation('O4', 'payload-write-present', {
        payloadWriteCount: summary.count,
        actionSetWriteCount: actionSetWrites.length,
        sliceStatus: slice ? slice.status : null,
        extractionComplete: !!slice && slice.status === 'resolved'
      }),
      obligation('O5', 'payload-value-resolved', {
        writes: summary.writes,
        resolved: summary.resolved,
        unresolved: summary.unresolved,
        classifiedUnresolved: summary.classifiedUnresolved
      }),
      obligation('O6', 'sensitive-entity-hit', {
        findingId: finding ? finding.findingId : null,
        matchType: finding ? finding.matchType : null,
        matchStrength: finding ? (finding.sensitiveEntity && finding.sensitiveEntity.strength) || finding.matchStrength || null : null,
        entity: finding ? finding.sensitiveEntity : null,
        rejectionCode: rejection ? rejection.code : null
      }),
      obligation('O7', 'entity-direction-output', {
        matchType: finding ? finding.matchType : null,
        direction: finding ? 'output' : null
      }),
      obligation('O8', 'restricted-permission-basis', {
        permissionBasis: finding && finding.sensitiveEntity ? finding.sensitiveEntity.permissionBasis : null,
        permission: finding && finding.sensitiveEntity ? finding.sensitiveEntity.permission : null,
        restrictedApiHits: (site.payloadWrites || [])
          .map((w) => w.classified && w.classified.member)
          .filter(Boolean)
          .slice(0, 10)
      }),
      obligation('O9', 'caller-component-consistency', {
        receiverConstraints: site.receiverConstraints || null,
        providerReachability: site.thirdPartyReachability || null,
        componentData: null
      }),
      obligation('O10', 'slice-closure', {
        status: slice ? slice.status : null,
        frontier: slice ? slice.frontier || [] : [],
        windowTruncated: site.windowTruncated === true,
        analysisStatus: site.analysisStatus || null
      })
    ],
    status: 'claim'
  };
}

/** P6：全部 os_account site（95）+ miner finding site（正例） */
function buildP6Claims(l1, l2, opts = {}) {
  const claims = [];
  const seen = new Set();
  for (const site of l2.p6Sites()) {
    if (seen.has(site.siteKey)) continue;
    seen.add(site.siteKey);
    claims.push(buildP6Claim(l1, site, { group: 'os-account' }));
  }
  if (opts.includeFindings !== false) {
    const rg1Negatives = rg1NegativeActions();
    for (const finding of l1.minerFindings()) {
      const site = l1.minerSite(finding.siteKey);
      if (!site || seen.has(site.siteKey)) continue;
      // §7.5：RG1 负例不得进 claim/正文；miner finding 里的 N5（通知弹窗）是
      // confirmed FP，剔除；os_account 95 site 仍保留（NOT-VULN 对账需要）。
      if (opts.excludeRegressionNegatives !== false && rg1Negatives.has(finding.action)) continue;
      seen.add(site.siteKey);
      claims.push(buildP6Claim(l1, site, { group: 'miner-finding' }));
    }
  }
  return claims;
}

/** P3：claim 构造 */
function buildP3Claim(l1, l2, derefClass, probe, producerEval) {
  const fn = derefClass.functionId ? l1.getFunctionById(derefClass.functionId) : null;
  const provenance = provenanceFor({ origin: ORIGINS.TARGET, repo: probe.repo, codeState: CODE_STATES.CURRENT_HEAD });
  return {
    claimId: stableClaimId('L3-P3', probe.id),
    class: 'P3',
    group: derefClass.entryBinding,
    ...provenance,
    derefId: probe.id,
    entry: {
      kind: 'deref-entry',
      entryKey: derefClass.entryKey,
      entryBinding: derefClass.entryBinding,
      functionId: derefClass.functionId,
      function: probe.function,
      repo: probe.repo,
      file: probe.file,
      line: probe.line,
      depth: derefClass.depth,
      reachable: derefClass.reachable,
      functionRange: fn ? [fn.startLine, fn.endLine] : probe.functionRange || null
    },
    source: {
      kind: 'deref',
      repo: probe.repo,
      file: probe.file,
      line: probe.line,
      text: probe.text,
      kindDetail: probe.kind || null,
      signature: probe.signature || (fn && fn.signature) || null
    },
    sink: {
      kind: 'deref',
      file: probe.file,
      line: probe.line,
      text: probe.text
    },
    producer: {
      name: probe.producer || null,
      owner: producerEval.evidence.owner || null,
      functionId: producerEval.evidence.functionId || null,
      file: producerEval.evidence.file || null,
      startLine: producerEval.evidence.startLine || null,
      returnType: producerEval.evidence.returnType || null,
      pointerLike: producerEval.evidence.pointerLike === true,
      nullablePattern: producerEval.evidence.nullablePattern === true
    },
    obligations: [
      obligation('O1', 'entry-reachable', {
        reachable: derefClass.reachable,
        entryBinding: derefClass.entryBinding,
        entryKey: derefClass.entryKey,
        depth: derefClass.depth
      }),
      obligation('O2', 'producer-may-null', producerEval.evidence),
      obligation('O3', 'guard-before-deref', { derefLine: probe.line, guardBefore: probe.guardBefore }),
      obligation('O4', 'deref-in-path-local', { derefLine: probe.line, text: probe.text })
    ],
    status: 'claim'
  };
}

/**
 * P3 候选选择（1a + 2a）：
 *   1) 现有 5 条 reachable potential 必选；
 *   2) 1a 重分类后的 reachable-unbound 中，producerMayNull && !guardBefore && typeKnown 的 26 条上界，
 *      经 2a owner-aware 校验后保留 proven 的 20 条；
 *   3) 其余逐条写原因。
 */
function selectP3Candidates(l1, l2) {
  const reachable = l2.reachableDerefs();
  const claims = [];
  const ledger = [];
  const selected = new Set();
  for (const cls of reachable) {
    const probe = l1.derefById(cls.id);
    const isExisting = probe.status === 'potential-violation';
    const shape = !!(probe.producerMayNull && !probe.guardBefore && probe.typeKnown);
    if (!isExisting && !shape) {
      ledger.push({
        derefId: cls.id,
        repo: cls.repo,
        file: cls.file,
        line: cls.line,
        entryBinding: cls.entryBinding,
        producer: probe.producer,
        selected: false,
        reason: !probe.producerMayNull ? 'producer-may-null-not-established'
          : (probe.guardBefore ? 'guard-present' : (!probe.typeKnown ? 'type-unknown' : 'not-in-expansion-shape'))
      });
      continue;
    }
    const producerEval = l2.resolveProducer(cls.repo, probe);
    if (!isExisting && producerEval.status !== 'proven') {
      ledger.push({
        derefId: cls.id,
        repo: cls.repo,
        file: cls.file,
        line: cls.line,
        entryBinding: cls.entryBinding,
        producer: probe.producer,
        owner: producerEval.evidence.owner || null,
        selected: false,
        reason: `owner-aware-${producerEval.status}:${producerEval.reason || producerEval.status}`
      });
      continue;
    }
    const claim = buildP3Claim(l1, l2, cls, probe, producerEval);
    claims.push(claim);
    selected.add(cls.id);
    ledger.push({
      derefId: cls.id,
      repo: cls.repo,
      file: cls.file,
      line: cls.line,
      entryBinding: cls.entryBinding,
      producer: probe.producer,
      owner: claim.producer.owner,
      selected: true,
      reason: isExisting ? 'existing-claim-seed' : '1a+2a-expanded'
    });
  }
  return { claims, ledger, summary: {
    reachable: reachable.length,
    unboundReclassified: reachable.filter((r) => l1.derefById(r.id).entryCount === 0).length,
    selected: claims.length,
    existing: claims.filter((c) => (l1.derefById(c.derefId) || {}).status === 'potential-violation').length,
    expanded: claims.filter((c) => (l1.derefById(c.derefId) || {}).status !== 'potential-violation').length,
    callgraphNameOnly: claims.filter((c) => c.entry.entryBinding === 'callgraph-name-only').length,
    upperBoundShape: reachable.filter((r) => {
      const p = l1.derefById(r.id);
      return p.status === 'potential-violation' || (p.producerMayNull && !p.guardBefore && p.typeKnown);
    }).length
  } };
}

function removedLinesFromDiff(diff) {
  return String(diff || '').split(/\r?\n/).filter((l) => /^-[^-]/.test(l)).map((l) => l.slice(1));
}

function addedLinesFromDiff(diff) {
  return String(diff || '').split(/\r?\n/).filter((l) => /^\+[^+]/.test(l)).map((l) => l.slice(1));
}

function operationLineFromRemoved(removed) {
  const candidates = removed.filter((l) => /[+*]|\s-\s|-\s*\w|\w\s*-/.test(l) && /(size|len|count|off|idx|alloc|malloc|memcpy|index|\*)/i.test(l));
  return candidates.length ? candidates[0].trim() : null;
}

function buildP4CandidateClaim(candidate) {
  const provenance = provenanceFor({ origin: ORIGINS.TARGET, repo: candidate.repo, codeState: CODE_STATES.CURRENT_HEAD });
  return {
    claimId: stableClaimId('L3-P4', candidate.candidateId),
    class: 'P4',
    group: 'oh-candidate',
    ...provenance,
    candidateId: candidate.candidateId,
    entry: {
      kind: 'arithmetic-site',
      entryId: candidate.entryId || null,
      repo: candidate.repo,
      file: candidate.file,
      line: candidate.line,
      binding: candidate.binding || null,
      entryBinding: candidate.entryBinding || null,
      entry: candidate.entry || null
    },
    source: {
      kind: 'pre-operation',
      file: candidate.file,
      line: candidate.line,
      text: candidate.originText,
      sizeExpr: candidate.sizeExpr,
      operation: candidate.operation || null
    },
    sink: candidate.sink || null,
    obligations: [
      obligation('O1', 'entry-resolved', { binding: candidate.binding, entryBinding: candidate.entryBinding, entry: candidate.entry || null }),
      obligation('O2', 'operation-site', { preLine: candidate.originText, sizeExpr: candidate.sizeExpr, line: candidate.line }),
      obligation('O3', 'operation-kind', { sizeExpr: candidate.sizeExpr, declared: candidate.operation || null }),
      obligation('O4', 'operand-result-types', { typeHints: candidate.typeHints || [], widthMix: candidate.widthMix || [] }),
      obligation('O5', 'sink-relation', { sizeExpr: candidate.sizeExpr, context: candidate.originText }),
      obligation('O6', 'unsafe-arithmetic', { sizeExpr: candidate.sizeExpr, typeHints: candidate.typeHints || [] }),
      obligation('O7', 'check-implication', { boundCheckInWindow: candidate.boundCheckInWindow === true }),
      obligation('O8', 'check-integrity', { boundCheckInWindow: candidate.boundCheckInWindow === true }),
      obligation('O9', 'fix-kind', { candidate: true }),
      obligation('O10', 'oracle', { oracle: candidate.oracle || null })
    ],
    status: 'claim'
  };
}

function buildP4CveClaim(cve) {
  const removed = removedLinesFromDiff(cve.diff);
  const added = addedLinesFromDiff(cve.diff);
  const opLine = operationLineFromRemoved(removed);
  const provenance = provenanceFor({ origin: ORIGINS.EXTERNAL_CVE, inTarget: false, codeState: null });
  return {
    claimId: stableClaimId('L3-P4-CVE', cve.cveId),
    class: 'P4',
    group: 'cve-calibration',
    ...provenance,
    cveId: cve.cveId,
    cwe: cve.cwe,
    entry: {
      kind: 'external-function',
      repo: cve.repo || null,
      file: cve.file || null,
      function: cve.function || null,
      binding: 'external',
      entryBinding: 'external-patch-sample'
    },
    source: {
      kind: 'pre-operation',
      file: cve.file || null,
      function: cve.function || null,
      line: cve.check && cve.check.line ? cve.check.line : null,
      text: opLine,
      removedLines: removed,
      addedLines: added,
      preSource: cve.preSource || null,
      postSource: cve.postSource || null
    },
    sink: cve.sink || null,
    obligations: [
      obligation('O1', 'entry-resolved', { binding: 'external', entryBinding: 'external-patch-sample' }),
      obligation('O2', 'operation-site', { removedLines: removed, line: opLine }),
      obligation('O3', 'operation-kind', { declared: cve.operation || null, diff: cve.diff || null }),
      obligation('O4', 'operand-result-types', { typeHints: cve.typeHints || [] }),
      obligation('O5', 'sink-relation', { sink: cve.sink || null, diff: cve.diff || null }),
      obligation('O6', 'unsafe-arithmetic', { cwe: cve.cwe, diff: cve.diff || null }),
      obligation('O7', 'check-implication', { check: cve.check || null, diff: cve.diff || null }),
      obligation('O8', 'check-integrity', { check: cve.check || null, diff: cve.diff || null }),
      obligation('O9', 'fix-kind', { diff: cve.diff || null, addedLines: added }),
      obligation('O10', 'oracle', { oracle: cve.oracle || null })
    ],
    status: 'claim'
  };
}

function buildP4Claims(candidates, cvePatches) {
  return [
    ...candidates.map(buildP4CandidateClaim),
    ...cvePatches.map(buildP4CveClaim)
  ];
}

function buildAllClaims(l1, l2, inputs) {
  const p3 = selectP3Candidates(l1, l2);
  const p6 = buildP6Claims(l1, l2);
  const p4 = buildP4Claims(inputs.p4Candidates || [], inputs.p4CvePatches || []);
  return { p3, p6, p4 };
}

function assertClaimShape(claim) {
  const errors = [];
  if (!claim.claimId) errors.push('missing claimId');
  if (!['P3', 'P4', 'P6'].includes(claim.class)) errors.push('bad class');
  if (!Array.isArray(claim.obligations) || !claim.obligations.length) errors.push('missing obligations');
  for (const ob of claim.obligations || []) {
    if (!ob.id || !ob.kind) errors.push(`obligation ${ob.id || '?'} missing id/kind`);
    if (!OBLIGATION_STATUS.has(ob.status)) errors.push(`obligation ${ob.id} bad status ${ob.status}`);
    if (!ob.evidence || typeof ob.evidence !== 'object') errors.push(`obligation ${ob.id} missing evidence`);
  }
  return errors;
}

module.exports = {
  OBLIGATION_STATUS,
  obligation,
  stableClaimId,
  buildP3Claim,
  buildP6Claim,
  buildP6Claims,
  selectP3Candidates,
  buildP4CandidateClaim,
  buildP4CveClaim,
  buildP4Claims,
  buildAllClaims,
  assertClaimShape,
  removedLinesFromDiff,
  addedLinesFromDiff,
  operationLineFromRemoved
};
