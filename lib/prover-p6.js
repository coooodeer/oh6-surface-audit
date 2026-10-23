'use strict';

/**
 * prover-p6.js —— P6 的 L4a 确定性 prover（O1–O10）。
 *
 * 语义直接对应 miner 的 C1–C4/T7（不含 public-api gate）：
 *   C1 -> O1 action-resolved
 *   C2 -> O2 receiver-undirected（definite/possible/none）
 *   C3 -> O3 no-subscriber-permission（definite/possible/none）
 *   C4 -> O4/O5/O6/O7
 *   T7 -> O8/O9
 *   切片质量 -> O10
 *
 * 判定不是通用 any-disproven：只有 definite 的接收侧/权限/命中缺失才是否定；
 * possible/unknown 落 unproven，继续 C4 或 CONDITIONS-NOT-MET。
 */

const { OBLIGATION_STATUS } = require('./claims.js');

const OK = 'proven';
const NO = 'disproven';
const UNK = 'unproven';

function setStatus(ob, status, extra = {}) {
  ob.status = status;
  if (extra.reason) ob.reason = extra.reason;
  if (extra.evidence) ob.evidence = { ...(ob.evidence || {}), ...extra.evidence };
  return ob;
}

function isActionSet(w) {
  return String(w.setter || '').toLowerCase() === 'setaction' || String(w.key || '') === 'SetAction';
}

function payloadWrites(site, slice) {
  const list = (site.payloadWrites || []).length ? site.payloadWrites : (slice && slice.writes) || [];
  return list.filter((w) => !isActionSet(w));
}

function payloadResolution(writes) {
  const resolved = writes.filter((w) => {
    const s = w.substitutionStatus || w.status;
    return s === 'resolved' || s === undefined || s === null;
  });
  return { total: writes.length, resolved: resolved.length, allResolved: writes.length > 0 && resolved.length === writes.length };
}

function entityMatchesForWrites(l1, writes) {
  const matches = [];
  for (const w of writes) {
    const cls = w.classified || {};
    if (cls.objectType) {
      // Type-2：敏感类实例。必须类名精确相等，不能只按成员名跨类匹配。
      for (const entity of l1.sensitiveEntitiesBySymbol(cls.objectType)) {
        if (entity.kind !== 'class') continue;
        if (entity.matchEligible && entity.matchEligible.value === false) continue;
        matches.push({
          kind: 'type2',
          entityId: entity.entityId,
          symbol: entity.symbol,
          member: cls.member || null,
          strength: entity.strength || 'weak',
          eligible: true,
          line: w.line
        });
      }
    }
    if (cls.objectType && cls.member) {
      // Type-1：敏感字段。字段的 owner 必须与 payload 读点的对象类型一致；
      // 只按 member 名匹配会把 DomainAccountEventData::status 错配到 JSAsyncContextOutput::status。
      for (const entity of l1.sensitiveEntitiesByMember(cls.member)) {
        const ownerMatches = entity.owner === cls.objectType
          || String(entity.symbol || '').startsWith(`${cls.objectType}::`);
        if (!ownerMatches) continue;
        if (entity.matchEligible && entity.matchEligible.value === false) continue;
        matches.push({
          kind: 'type1',
          entityId: entity.entityId,
          symbol: entity.symbol,
          member: entity.member,
          strength: entity.strength || 'weak',
          eligible: true,
          line: w.line
        });
      }
    }
  }
  return matches;
}

/** 单条 P6 claim 的 O1–O10 */
function evaluateP6Obligations(claim, l1) {
  const siteKey = claim.entry.siteKey;
  const site = l1.minerSite(siteKey);
  const gate = l1.minerGate(siteKey) || {};
  const verdict = gate.verdict || {};
  const slice = l1.minerSlice(siteKey);
  const finding = l1.minerFinding(siteKey);
  const rejection = l1.minerRejection(siteKey);
  const obs = {};
  for (const ob of claim.obligations) obs[ob.id] = ob;

  // O1 action-resolved
  const action = (site && site.action) || null;
  const derived = verdict.c1_action_derived === true;
  if (action) {
    setStatus(obs.O1, OK, {
      evidence: { action, actionDerived: derived, siteKey },
      reason: derived ? 'action-derived-observation-only' : undefined
    });
    obs.O1.observationOnly = derived;
  } else {
    setStatus(obs.O1, UNK, { reason: 'action-missing', evidence: { siteKey } });
  }

  // O2 receiver-undirected
  const c2 = gate.C2 || (verdict.C2_recipient_state || null);
  if (c2 === 'definite') {
    setStatus(obs.O2, NO, { reason: 'receiver-directed', evidence: { c2, reasons: gate.reasons || [] } });
  } else if (c2 === 'none') {
    setStatus(obs.O2, OK, { evidence: { c2, c2Unspecified: verdict.C2_recipient_unspecified === true } });
  } else {
    setStatus(obs.O2, UNK, { reason: c2 ? 'receiver-possible' : 'receiver-state-missing', evidence: { c2 } });
  }

  // O3 no-subscriber-permission
  const c3 = gate.C3 || (verdict.C3_permission_state || null);
  if (c3 === 'definite') {
    setStatus(obs.O3, NO, {
      reason: 'subscriber-permission-required',
      evidence: {
        c3,
        eventRequiresPermission: !!(verdict.C3_detail && verdict.C3_detail.eventRequiresPermission),
        subscriberPermissions: (site && site.subscriberPermissions) || []
      }
    });
  } else if (c3 === 'none') {
    setStatus(obs.O3, OK, { evidence: { c3, c3NoPermission: verdict.C3_no_subscriber_permission === true } });
  } else {
    setStatus(obs.O3, UNK, { reason: c3 ? 'permission-possible' : 'permission-state-missing', evidence: { c3 } });
  }

  // O4 payload-write-present
  const writes = payloadWrites(site, slice);
  if (writes.length > 0) {
    setStatus(obs.O4, OK, { evidence: { payloadWriteCount: writes.length } });
  } else if (slice && slice.status === 'resolved') {
    setStatus(obs.O4, NO, { reason: 'no-payload-write-extraction-complete', evidence: { payloadWriteCount: 0 } });
  } else {
    setStatus(obs.O4, UNK, { reason: 'payload-extraction-incomplete', evidence: { payloadWriteCount: 0 } });
  }

  // O5 payload-value-resolved
  if (writes.length === 0) {
    setStatus(obs.O5, UNK, { reason: 'no-payload-write', evidence: {} });
  } else {
    const res = payloadResolution(writes);
    if (res.allResolved) setStatus(obs.O5, OK, { evidence: { ...res } });
    else setStatus(obs.O5, UNK, { reason: 'payload-value-partial', evidence: { ...res } });
  }

  // O6 sensitive-entity-hit
  const matches = entityMatchesForWrites(l1, writes);
  if (finding) {
    const strength = (finding.sensitiveEntity && finding.sensitiveEntity.strength) || finding.matchStrength || null;
    if (strength === 'exact' || strength === 'strong') {
      setStatus(obs.O6, OK, {
        evidence: {
          findingId: finding.findingId,
          matchType: finding.matchType,
          strength,
          entityId: finding.sensitiveEntity && finding.sensitiveEntity.entityId,
          matchCount: matches.length
        }
      });
      obs.O6.weak = false;
    } else if (strength === 'weak') {
      setStatus(obs.O6, OK, {
        evidence: { findingId: finding.findingId, matchType: finding.matchType, strength, matchCount: matches.length }
      });
      obs.O6.weak = true;
    } else {
      setStatus(obs.O6, UNK, { reason: 'finding-strength-missing', evidence: { findingId: finding.findingId, matchType: finding.matchType } });
    }
  } else if (rejection && rejection.code === 'C4_no_sensitive_payload') {
    const strong = matches.filter((m) => m.strength === 'exact' || m.strength === 'strong');
    if (strong.length) {
      setStatus(obs.O6, OK, {
        reason: 'entity-match-differs-from-miner-rejection',
        evidence: { rejectionCode: rejection.code, matches: strong.slice(0, 5) }
      });
      obs.O6.weak = false;
    } else {
      setStatus(obs.O6, NO, {
        reason: 'C4_no_sensitive_payload',
        evidence: { rejectionCode: rejection.code, matchCount: matches.length }
      });
    }
  } else if (writes.length === 0) {
    setStatus(obs.O6, UNK, { reason: 'no-write-to-match', evidence: {} });
  } else if (slice && slice.status === 'resolved') {
    const strong = matches.filter((m) => m.strength === 'exact' || m.strength === 'strong');
    const weak = matches.filter((m) => m.strength === 'weak');
    if (strong.length) {
      setStatus(obs.O6, OK, { evidence: { matches: strong.slice(0, 5), matchCount: matches.length } });
      obs.O6.weak = false;
    } else if (weak.length) {
      setStatus(obs.O6, OK, { evidence: { matches: weak.slice(0, 5), matchCount: matches.length } });
      obs.O6.weak = true;
    } else {
      setStatus(obs.O6, NO, { reason: 'no-sensitive-entity-match', evidence: { matchCount: 0 } });
    }
  } else {
    setStatus(obs.O6, UNK, { reason: 'sensitivity-unresolved', evidence: { matchCount: matches.length } });
  }

  // O7 entity-direction-output
  if (finding) {
    const mt = String(finding.matchType || '');
    const inputSide = /input|direction-mismatch/.test(mt);
    if (inputSide) setStatus(obs.O7, NO, { reason: 'entity-input-side', evidence: { matchType: mt } });
    else setStatus(obs.O7, OK, { evidence: { matchType: mt, direction: 'output' } });
  } else if (obs.O6.status === NO) {
    setStatus(obs.O7, UNK, { reason: 'no-entity-hit', evidence: {} });
  } else {
    setStatus(obs.O7, UNK, { reason: 'direction-unknown', evidence: {} });
  }

  // O8 restricted-permission-basis
  if (finding) {
    const ent = finding.sensitiveEntity || {};
    const basis = ent.permissionBasis || null;
    const perm = ent.permission || null;
    const hasBasis = basis === 'permission-expression' || basis === 'systemapi'
      || !!(perm && (perm.expression || perm.systemApi === true));
    if (hasBasis) {
      setStatus(obs.O8, OK, { evidence: { permissionBasis: basis, expression: perm && perm.expression, systemApi: perm && perm.systemApi } });
    } else {
      setStatus(obs.O8, UNK, { reason: 'restricted-permission-basis-missing', evidence: { permissionBasis: basis } });
    }
  } else {
    const c3Detail = verdict.C3_detail || {};
    const hasPerm = !!(c3Detail.eventRequiresPermission || (site.subscriberPermissions || []).length);
    setStatus(obs.O8, hasPerm ? OK : UNK, {
      reason: hasPerm ? undefined : 'not-a-restricted-permission-site',
      evidence: { eventRequiresPermission: !!c3Detail.eventRequiresPermission, subscriberPermissions: (site && site.subscriberPermissions) || [] }
    });
  }

  // O9 caller-component-consistency
  setStatus(obs.O9, UNK, {
    reason: 'component-data-missing',
    evidence: { receiverConstraints: site && site.receiverConstraints, providerReachability: site && site.thirdPartyReachability }
  });

  // O10 slice-closure
  if (slice && slice.status === 'resolved') setStatus(obs.O10, OK, { evidence: { status: slice.status } });
  else if (slice && slice.status === 'partial') setStatus(obs.O10, UNK, { reason: 'slice-partial', evidence: { status: slice.status } });
  else setStatus(obs.O10, UNK, { reason: 'slice-unresolved', evidence: { status: slice ? slice.status : null } });

  return claim.obligations;
}

function get(obs, id) {
  return obs.find((o) => o.id === id) || { status: 'unproven', evidence: {} };
}

/**
 * P6 判定（按 C1–C4/T7 语义）。
 */
function p6Verdict(obligations) {
  const o = (id) => get(obligations, id);
  const O1 = o('O1'); const O2 = o('O2'); const O3 = o('O3'); const O4 = o('O4');
  const O5 = o('O5'); const O6 = o('O6'); const O7 = o('O7'); const O8 = o('O8');
  const O9 = o('O9'); const O10 = o('O10');
  if (O1.status === NO || O1.status === 'invalid') return { claimVerdict: 'NOT-APPLICABLE', reason: 'action-unresolved' };
  if (O2.status === NO) return { claimVerdict: 'NOT-VULN', reason: 'receiver-directed' };
  if (O3.status === NO) return { claimVerdict: 'NOT-VULN', reason: 'subscriber-permission-required' };
  if (O4.status === NO) return { claimVerdict: 'NOT-VULN', reason: 'no-payload-write' };
  if (O6.status === NO) return { claimVerdict: 'NOT-VULN', reason: 'no-sensitive-entity-hit' };
  if (O7.status === NO) return { claimVerdict: 'NOT-VULN', reason: 'entity-input-side' };
  if (O9.status === NO) return { claimVerdict: 'NOT-VULN', reason: 'caller-component-mismatch' };
  if (O6.status === OK && O6.weak) return { claimVerdict: 'PROVEN-WEAKNESS', reason: 'weak-sensitive-hit' };
  if (O10.status !== OK) return { claimVerdict: 'UNPROVEN', reason: 'slice-not-closed' };
  if (O8.status !== OK) return { claimVerdict: 'UNPROVEN', reason: 'restricted-permission-basis-missing' };
  if (O5.status !== OK) return { claimVerdict: 'UNPROVEN', reason: 'payload-value-unresolved' };
  if (O6.status === OK && O7.status === OK) return { claimVerdict: 'VIOLATION', reason: 'sensitive-output-reachable' };
  return { claimVerdict: 'UNPROVEN', reason: 'obligations-not-satisfied' };
}

function productForP6(claimVerdict, obligations, opts = {}) {
  const o = (id) => get(obligations, id);
  if (claimVerdict === 'VIOLATION') {
    const O1 = o('O1');
    const required = ['O2', 'O3', 'O4', 'O5', 'O6', 'O7', 'O8', 'O10'];
    const allOk = required.every((id) => o(id).status === 'proven');
    if (O1.observationOnly) return { productVerdict: 'PROVEN-WEAKNESS', reason: 'action-derived-observation-only' };
    if (!allOk) return { productVerdict: 'CONDITIONS-NOT-MET', reason: 'unproven-obligation' };
    if (opts.impactNotAssessed) return { productVerdict: 'PROVEN-WEAKNESS', reason: 'impact-not-assessed' };
    return { productVerdict: 'PROVEN-VULN', reason: 'all-required-proven' };
  }
  if (claimVerdict === 'PROVEN-WEAKNESS') return { productVerdict: 'PROVEN-WEAKNESS', reason: 'weak-hit' };
  if (claimVerdict === 'SATISFIED') return { productVerdict: 'NOT-VULN', reason: 'check-satisfied' };
  if (claimVerdict === 'NOT-VULN') return { productVerdict: 'NOT-VULN', reason: 'negative-obligation' };
  if (claimVerdict === 'NOT-APPLICABLE') return { productVerdict: 'NOT-APPLICABLE', reason: 'not-applicable' };
  return { productVerdict: 'CONDITIONS-NOT-MET', reason: 'unproven' };
}

function proveP6Claim(claim, l1, opts = {}) {
  const obligations = evaluateP6Obligations(claim, l1);
  const v = p6Verdict(obligations);
  const p = productForP6(v.claimVerdict, obligations, opts);
  return {
    claimId: claim.claimId,
    class: 'P6',
    group: claim.group,
    origin: claim.origin || null,
    inTarget: claim.inTarget === true,
    codeState: claim.codeState || null,
    productionEligible: claim.productionEligible === true,
    novelty: claim.novelty || null,
    siteKey: claim.entry.siteKey,
    action: claim.entry.action,
    sink: claim.sink,
    entry: claim.entry,
    obligations,
    claimVerdict: v.claimVerdict,
    reason: v.reason,
    productVerdict: p.productVerdict,
    productReason: p.reason
  };
}

function proveP6Claims(claims, l1, opts = {}) {
  return claims.map((c) => proveP6Claim(c, l1, opts));
}

/** 与 miner 624 站点/95 rejections 对账 */
function reconcileWithMiner(l1, l2, verdicts) {
  const osSites = l2.p6Sites();
  const byKey = new Map(verdicts.map((v) => [v.siteKey, v]));
  const missingSite = osSites.filter((s) => !l1.minerSite(s.siteKey)).map((s) => s.siteKey);
  const notNotVuln = [];
  const reasonMismatch = [];
  const expected = new Map();
  for (const site of osSites) {
    const rej = l1.minerRejection(site.siteKey);
    expected.set(site.siteKey, rej ? rej.code : null);
  }
  for (const site of osSites) {
    const v = byKey.get(site.siteKey);
    if (!v) {
      notNotVuln.push({ siteKey: site.siteKey, reason: 'no-verdict' });
      continue;
    }
    const exp = expected.get(site.siteKey);
    if (v.claimVerdict !== 'NOT-VULN') {
      notNotVuln.push({ siteKey: site.siteKey, claimVerdict: v.claimVerdict, expected: exp });
    } else if (exp) {
      const reasonOk = (exp === 'C4_no_sensitive_payload' && /sensitive|payload/.test(v.reason))
        || (exp === 'C3_event_requires_permission' && v.reason === 'subscriber-permission-required')
        || (exp === 'C3_subscriber_permission_required' && v.reason === 'subscriber-permission-required');
      if (!reasonOk) reasonMismatch.push({ siteKey: site.siteKey, expected: exp, actual: v.reason });
    }
  }
  const rejectionCounts = {};
  for (const site of osSites) {
    const rej = l1.minerRejection(site.siteKey);
    if (rej) rejectionCounts[rej.code] = (rejectionCounts[rej.code] || 0) + 1;
  }
  return {
    osSites: osSites.length,
    foundInMiner: osSites.length - missingSite.length,
    missingSite,
    rejectionCounts,
    allNotVuln: notNotVuln.length === 0,
    notNotVuln,
    reasonMismatch,
    findings: l1.minerFindings().length
  };
}

function summarizeP6Verdicts(rows) {
  const countBy = (field) => rows.reduce((a, r) => { a[r[field]] = (a[r[field]] || 0) + 1; return a; }, {});
  const os = rows.filter((r) => r.group === 'os-account');
  const findings = rows.filter((r) => r.group === 'miner-finding');
  const obligationStatus = {};
  for (const r of rows) {
    for (const ob of r.obligations) {
      if (!obligationStatus[ob.id]) obligationStatus[ob.id] = {};
      obligationStatus[ob.id][ob.status] = (obligationStatus[ob.id][ob.status] || 0) + 1;
    }
  }
  return {
    total: rows.length,
    byGroup: countBy('group'),
    claimVerdict: countBy('claimVerdict'),
    productVerdict: countBy('productVerdict'),
    osAccount: { total: os.length, verdicts: os.reduce((a, r) => { a[r.claimVerdict] = (a[r.claimVerdict] || 0) + 1; return a; }, {}) },
    minerFindings: {
      total: findings.length,
      verdicts: findings.reduce((a, r) => { a[r.claimVerdict] = (a[r.claimVerdict] || 0) + 1; return a; }, {}),
      provenVuln: findings.filter((r) => r.productVerdict === 'PROVEN-VULN').map((r) => r.siteKey),
      provenWeakness: findings.filter((r) => r.productVerdict === 'PROVEN-WEAKNESS').map((r) => r.siteKey)
    },
    obligationStatus
  };
}

/** eval/p6/cases.jsonl：接收侧三态与 case 标签对齐 */
function receiverThirdPartyForCase(c) {
  if ((c.directedSubscriberUids || []).length) return false;
  if ((c.subscriberPermissions || []).length) return false;
  if (c.thirdPartyReachability !== 'reachable') return false;
  return true;
}

function checkEvalCases(cases) {
  const rows = cases.map((c) => {
    const actual = receiverThirdPartyForCase(c);
    return {
      id: c.id,
      variant: c.variant,
      expected: c.expected ? c.expected.receiverThirdParty : null,
      actual,
      pass: !c.expected || actual === c.expected.receiverThirdParty
    };
  });
  const byVariant = {};
  for (const r of rows) {
    if (!byVariant[r.variant]) byVariant[r.variant] = { total: 0, pass: 0 };
    byVariant[r.variant].total += 1;
    if (r.pass) byVariant[r.variant].pass += 1;
  }
  return { rows, byVariant, pass: rows.every((r) => r.pass) };
}

module.exports = {
  evaluateP6Obligations,
  p6Verdict,
  productForP6,
  proveP6Claim,
  proveP6Claims,
  reconcileWithMiner,
  summarizeP6Verdicts,
  payloadWrites,
  entityMatchesForWrites,
  receiverThirdPartyForCase,
  checkEvalCases
};
