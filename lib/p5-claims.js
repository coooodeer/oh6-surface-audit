'use strict';

/**
 * p5-claims.js —— P5 L3：method-level claim + O1–O10。
 *
 * 只从 service-direction、pairing resolved、requiredChecks 含 token-permission 的 unit 生成；
 * 选中 15 个 pathScoped + 15 个 no-server-check + dsoftbus 历史补充单元，目标 20–40 条。
 */

const path = require('path');
const { OUT_ROOT, ensureDir, writeJsonl, writeJson } = require('./util.js');
const { p5Verdict, productForP5 } = require('./prover-p5.js');
const { ORIGINS, CODE_STATES, classify } = require('./candidate-origin.js');

const SERVER_CHECK_KINDS = new Set(['check-permission', 'verify-calling-permission', 'verify-permission', 'verify-access-token', 'is-system-app', 'check-call']);
const OBJECT_PARAM_RE = /name|bundle|user|account|token|(^|_)id$|\bid\b|channel|display|credential|photo|domain|profile|event|listener|serial/i;
const READ_ONLY_METADATA = new Set([
  'QueryMaxOsAccountNumber',
  'IsOsAccountExists',
  'IsOsAccountCompleted',
  'GetOsAccountLocalIdBySerialNumber',
  'QueryDeviceAccountId',
  'GetAccountState',
  'QueryDistributedVirtualDeviceId'
]);
const STATE_CHANGING_RE = /^(Set|Start|Stop|Delete|Subscribe|Unsubscribe|Register|Unregister|Update|Remove|Create|Close|Open|Auth|Activate|Deactivate|Lock|Verify|Apply|Revoke)/;

function mk(id, kind, status, evidence = {}, reason = null) {
  return { id, kind, status, evidence, ...(reason ? { reason } : {}) };
}

function paramsFromSignature(pair) {
  const sig = String((pair && pair.implSignature) || '');
  const open = sig.indexOf('(');
  const close = sig.lastIndexOf(')');
  if (open < 0 || close <= open) return [];
  const body = sig.slice(open + 1, close);
  const parts = [];
  let depth = 0;
  let cur = '';
  for (const ch of body) {
    if (ch === '<' || ch === '(' || ch === '[') depth += 1;
    else if (ch === '>' || ch === ')' || ch === ']') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  const out = [];
  for (const p of parts) {
    const clean = p.replace(/=.*$/, '').trim();
    const m = /([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$/.exec(clean);
    if (!m) continue;
    const name = m[1];
    if (['void', 'const', 'int', 'uint32_t', 'int32_t', 'size_t', 'bool', 'char'].includes(name)) continue;
    const type = clean.slice(0, clean.lastIndexOf(name)).trim().replace(/[&*]+$/, '').trim();
    out.push({ name, type: type || 'unknown', source: 'impl-signature' });
  }
  return out;
}

function paramsForUnit(unit, pair) {
  const direct = Array.isArray(unit.params) ? unit.params : [];
  if (direct.length) return { params: direct, source: unit.paramsSource || 'entry' };
  const fromSig = paramsFromSignature(pair);
  if (fromSig.length) return { params: fromSig, source: 'impl-signature' };
  return { params: [], source: 'none' };
}

function assessImpact(unit, pair, pathInfo, l1) {
  if (!unit) return { status: 'not-assessed', kind: 'none', reason: 'no-unit', evidence: {} };
  if (READ_ONLY_METADATA.has(unit.method)) {
    return {
      status: 'refuted',
      kind: 'read-only-metadata',
      reason: 'read-only-metadata-no-state-change-or-privilege-boundary; info-disclosure-outside-P5-scope',
      evidence: { interface: unit.interface, method: unit.method, sinkLine: pair.implStartLine }
    };
  }
  if (unit.interfaceBase !== 'ISoftBusServer') {
    return {
      status: 'unproven',
      kind: STATE_CHANGING_RE.test(unit.method) ? 'state-changing' : 'unknown',
      reason: STATE_CHANGING_RE.test(unit.method)
        ? 'state-changing-impact-not-demonstrated'
        : 'no-impact-model',
      evidence: { interface: unit.interface, method: unit.method, sinkLine: pair.implStartLine }
    };
  }
  let lines = [];
  try {
    if (l1 && l1.sourceLines) lines = l1.sourceLines(unit.repo, pair.implFile).slice(pair.implStartLine - 1, pair.implEndLine);
  } catch (_) { lines = []; }
  const pidCheck = lines.findIndex((l) => /TransGetAndComparePid/.test(l));
  const channelCheck = lines.findIndex((l) => /CheckChannelPermission/.test(l));
  const check = pidCheck >= 0 ? 'TransGetAndComparePid' : (channelCheck >= 0 ? 'CheckChannelPermission' : null);
  return {
    status: 'unproven',
    kind: 'channel-object-authorization',
    reason: check
      ? `${check}-present-but-bypass-and-security-impact-not-demonstrated`
      : 'no-check-and-security-impact-not-demonstrated',
    evidence: {
      check,
      implFile: pair.implFile,
      sinkLine: pair.implStartLine,
      checkLine: check && pidCheck >= 0 ? pair.implStartLine + pidCheck : (check ? pair.implStartLine + channelCheck : null),
      pathScoped: !!(pathInfo && pathInfo.pathScoped)
    }
  };
}

function pickBalanced(list, n) {
  const groups = new Map();
  for (const u of list) {
    const k = `${u.repo}|${u.interfaceBase}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(u);
  }
  const buckets = [...groups.values()].sort((a, b) => a[0].unitId.localeCompare(b[0].unitId));
  const out = [];
  let i = 0;
  while (out.length < n) {
    let added = false;
    for (const b of buckets) {
      if (b[i]) { out.push(b[i]); added = true; if (out.length >= n) break; }
    }
    if (!added) break;
    i += 1;
  }
  return out;
}

function evaluateUnitObligations(unit, pair, pathInfo, checks) {
  const paramInfo = paramsForUnit(unit, pair);
  const objectParams = paramInfo.params.filter((p) => OBJECT_PARAM_RE.test(`${p.name || ''} ${p.type || ''}`));
  const serverChecks = (pathInfo && pathInfo.checks ? pathInfo.checks : []).filter((c) => c.side === 'server' && SERVER_CHECK_KINDS.has(c.kind));
  const explicitChecks = serverChecks.filter((c) => (c.permissions && c.permissions.length) || ['check-permission', 'verify-permission', 'is-system-app'].includes(c.kind));
  const objectMatched = serverChecks.some((c) => paramInfo.params.some((p) => p.name && String(c.text || '').includes(p.name))
    || (unit.method === 'SendMessage' && /channelId|channelType/.test(String(c.text || ''))));

  const o1 = mk('O1', 'entry-resolved', 'proven', { entryId: unit.entryId, interface: unit.interface, method: unit.method, direction: unit.direction, pairingStatus: pair.pairingStatus });
  const o2 = pathInfo && pathInfo.identitySources > 0
    ? mk('O2', 'caller-identity', 'proven', { identitySources: pathInfo.identitySources, checks: serverChecks.filter((c) => /get-calling/.test(c.kind)).map((c) => `${c.file}:${c.line}`) })
    : mk('O2', 'caller-identity', 'unproven', { identitySources: pathInfo ? pathInfo.identitySources : 0, reason: 'identity-source-not-on-path' }, 'identity-source-not-on-path');
  const o3 = objectParams.length
    ? mk('O3', 'object-identity', 'proven', { params: objectParams, paramsSource: paramInfo.source, pairingStatus: pair.pairingStatus, allParams: paramInfo.params })
    : mk('O3', 'object-identity', 'unproven', { params: paramInfo.params, paramsSource: paramInfo.source, pairingStatus: pair.pairingStatus }, 'object-param-not-identified');
  const o4 = mk('O4', 'sink-resolved', 'proven', { implFunction: pair.implFunction, implFile: pair.implFile, startLine: pair.implStartLine });
  const o5 = (unit.requiredChecks || []).includes('token-permission')
    ? mk('O5', 'permission-requirement', 'proven', { requiredChecks: unit.requiredChecks, permissions: [...new Set(serverChecks.flatMap((c) => c.permissions || []))] })
    : mk('O5', 'permission-requirement', 'unproven', { requiredChecks: unit.requiredChecks }, 'token-permission-not-required');
  let o6;
  if (!pathInfo || !pathInfo.implFunction) o6 = mk('O6', 'check-presence', 'unproven', {}, 'path-missing');
  else if (pathInfo.serverChecks > 0) o6 = mk('O6', 'check-presence', 'proven', { serverChecks: pathInfo.serverChecks, checks: serverChecks.map((c) => `${c.file}:${c.line}:${c.kind}`) });
  else if (pathInfo.noCheckOnPath === true) o6 = mk('O6', 'check-presence', 'disproven', { noCheckOnPath: true }, 'no-server-check-on-path');
  else o6 = mk('O6', 'check-presence', 'unproven', { reason: pathInfo.reason }, 'path-not-closed');
  let o7;
  if (o6.status !== 'proven') o7 = mk('O7', 'check-operand-match', o6.status === 'disproven' ? 'disproven' : 'unproven', { checks: [] }, 'no-check-to-match');
  else if (explicitChecks.length > 0 || objectMatched) o7 = mk('O7', 'check-operand-match', 'proven', { explicitChecks: explicitChecks.map((c) => `${c.file}:${c.line}`), objectMatched });
  else o7 = mk('O7', 'check-operand-match', 'unproven', { serverChecks: serverChecks.map((c) => c.kind) }, 'check-operand-not-matched');
  let o8;
  if (pathInfo && pathInfo.pathScoped === true) o8 = mk('O8', 'path-coverage', 'proven', { pathScoped: true, serverChecks: pathInfo.serverChecks });
  else if (pathInfo && pathInfo.noCheckOnPath === true) o8 = mk('O8', 'path-coverage', 'disproven', { noCheckOnPath: true }, 'no-check-on-path');
  else o8 = mk('O8', 'path-coverage', 'unproven', { reason: pathInfo ? pathInfo.reason : 'path-missing' }, 'path-not-closed');
  const o9 = mk('O9', 'entry-coverage', 'proven', { handlerKind: pair.handlerKind, implFunction: pair.implFunction, alternateHandlers: [] });
  const o10 = unit.interfaceBase === 'ISoftBusServer'
    ? mk('O10', 'fix-kind/oracle', 'proven', { oracle: 'historical:cwe862:dsoftbus-sendmessage' })
    : mk('O10', 'fix-kind/oracle', 'unproven', { oracle: 'none' }, 'no-local-oracle');
  return [o1, o2, o3, o4, o5, o6, o7, o8, o9, o10];
}

function buildClaim(unit, pair, pathInfo, l1 = null) {
  const paramInfo = paramsForUnit(unit, pair);
  const impact = assessImpact(unit, pair, pathInfo, l1);
  const provenance = classify({
    origin: ORIGINS.TARGET,
    inTarget: unit.scope === 'R1',
    codeState: CODE_STATES.CURRENT_HEAD
  });
  if (provenance.errors.length) throw new Error(`P5 provenance: ${provenance.errors.join(',')}`);
  const provenanceFields = {
    origin: provenance.origin,
    inTarget: provenance.inTarget,
    codeState: provenance.codeState,
    constructed: provenance.constructed,
    productionEligible: provenance.productionEligible,
    novelty: provenance.novelty
  };
  const obligations = evaluateUnitObligations(unit, pair, pathInfo, []);
  const v = p5Verdict(obligations);
  const p = productForP5(v.claimVerdict, obligations, { impact });
  return {
    claimId: `L3-P5-${unit.unitId.replace(/^P5U-/, '')}`,
    class: 'P5',
    group: unit.entrySource === 'l2-supplementary' ? 'p5-supplementary' : 'p5-candidate',
    ...provenanceFields,
    unitId: unit.unitId,
    entry: {
      kind: 'ipc-service-method',
      entryId: unit.entryId,
      repo: unit.repo,
      interface: unit.interface,
      method: unit.method,
      code: unit.code,
      direction: unit.direction,
      serviceClass: unit.serviceClass,
      attackerPositions: unit.attackerPositions,
      requiredChecks: unit.requiredChecks
    },
    source: {
      kind: 'parcel-object',
      file: unit.file,
      line: unit.line,
      params: paramInfo.params,
      paramsSource: paramInfo.source
    },
    sink: {
      kind: 'privileged-operation',
      file: pair.implFile,
      line: pair.implStartLine,
      function: pair.implFunction,
      functionName: pair.implFunctionName,
      signature: pair.implSignature
    },
    obligations,
    impact,
    status: 'claim',
    claimVerdict: v.claimVerdict,
    reason: v.reason,
    productVerdict: p.productVerdict,
    productReason: p.reason
  };
}

function buildP5Claims({ units, pairing, paths, pathLimit = 15, noCheckLimit = 15, l1 = null }) {
  const pairByUnit = new Map(pairing.map((p) => [p.unitId, p]));
  const pathByUnit = new Map(paths.map((p) => [p.unitId, p]));
  const service = units.filter((u) => u.direction === 'service'
    && (u.requiredChecks || []).includes('token-permission')
    && pairByUnit.get(u.unitId) && pairByUnit.get(u.unitId).resolved);
  const pathScoped = service.filter((u) => pathByUnit.get(u.unitId) && pathByUnit.get(u.unitId).serverChecks > 0);
  const noCheck = service.filter((u) => pathByUnit.get(u.unitId) && pathByUnit.get(u.unitId).noCheckOnPath === true);
  const supplementary = service.filter((u) => u.entrySource === 'l2-supplementary');
  const chosen = [
    ...pickBalanced(pathScoped, pathLimit),
    ...pickBalanced(noCheck, noCheckLimit),
    ...supplementary
  ];
  const seen = new Set();
  const claims = [];
  for (const u of chosen) {
    if (seen.has(u.unitId)) continue;
    seen.add(u.unitId);
    claims.push(buildClaim(u, pairByUnit.get(u.unitId), pathByUnit.get(u.unitId), l1));
  }
  const count = (f) => claims.reduce((a, c) => { const k = c[f]; a[k] = (a[k] || 0) + 1; return a; }, {});
  const obligationCounts = (id) => claims.reduce((a, c) => {
    const o = (c.obligations || []).find((x) => x.id === id);
    const k = o ? o.status : 'missing';
    a[k] = (a[k] || 0) + 1;
    return a;
  }, {});
  const summary = {
    total: claims.length,
    pathScopedSelected: claims.filter((c) => c.group === 'p5-candidate' && pathByUnit.get(c.unitId) && pathByUnit.get(c.unitId).serverChecks > 0).length,
    noCheckSelected: claims.filter((c) => pathByUnit.get(c.unitId) && pathByUnit.get(c.unitId).noCheckOnPath === true).length,
    supplementary: claims.filter((c) => c.group === 'p5-supplementary').length,
    claimVerdict: count('claimVerdict'),
    productVerdict: count('productVerdict'),
    impact: claims.reduce((a, c) => { const k = c.impact ? c.impact.status : 'not-assessed'; a[k] = (a[k] || 0) + 1; return a; }, {}),
    obligations: { O2: obligationCounts('O2'), O3: obligationCounts('O3'), O10: obligationCounts('O10') },
    paramsSource: claims.reduce((a, c) => { const k = c.source && c.source.paramsSource || 'unknown'; a[k] = (a[k] || 0) + 1; return a; }, {}),
    byInterface: claims.reduce((a, c) => { a[c.entry.interface] = (a[c.entry.interface] || 0) + 1; return a; }, {}),
    available: { service: service.length, pathScoped: pathScoped.length, noCheck: noCheck.length }
  };
  return { claims, summary };
}

function writeP5Claims(result) {
  const dir = path.join(OUT_ROOT, 'p5');
  ensureDir(dir);
  writeJsonl(path.join(dir, 'claims.jsonl'), result.claims);
  writeJson(path.join(dir, 'claim-summary.json'), result.summary);
  return { dir, file: path.join(dir, 'claims.jsonl'), summaryFile: path.join(dir, 'claim-summary.json') };
}

module.exports = { buildP5Claims, writeP5Claims, evaluateUnitObligations, pickBalanced };
