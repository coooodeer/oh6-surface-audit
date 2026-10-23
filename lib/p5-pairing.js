'use strict';

/**
 * p5-pairing.js —— P5 method unit -> service impl / handler 配对（R1）。
 *
 * 当前可用事实：
 *   - os_account 的 service 类：AppAccountManagerService / DomainAccountManagerService /
 *     AccountMgrService / AccountIAMService / OsAccountManagerService；
 *   - L1 functions 有 signature（含 Class::method），owner 字段不一定有；
 *   - dsoftbus 的 SendMessage 从 L2 verified entry 补充，handler 是 SoftBusServerStub::SendMessageInner。
 *
 * 纪律：每个 null 必须带 reason；callback 不进入 pairing 分母。
 */

const path = require('path');
const { ensureDir, writeJsonl, writeJson, OUT_ROOT } = require('./util.js');
const { SERVICE_CLASS } = require('./p5-units.js');

function splitParams(sig) {
  const s = String(sig || '');
  const open = s.indexOf('(');
  if (open < 0) return [];
  let depth = 0;
  let close = -1;
  for (let i = open; i < s.length; i += 1) {
    if (s[i] === '(') depth += 1;
    else if (s[i] === ')') { depth -= 1; if (depth === 0) { close = i; break; } }
  }
  if (close < 0) return [];
  const inner = s.slice(open + 1, close).trim();
  if (!inner) return [];
  const parts = [];
  let last = 0;
  depth = 0;
  for (let i = 0; i < inner.length; i += 1) {
    const c = inner[i];
    if (c === '(' || c === '<' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === '>' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) { parts.push(inner.slice(last, i).trim()); last = i + 1; }
  }
  parts.push(inner.slice(last).trim());
  return parts.filter(Boolean);
}

function classMethodRegex(cls, method) {
  const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|::)${esc(cls)}::${esc(method)}\\s*\\(`);
}

class P5Pairer {
  constructor(l1, entries = []) {
    this.l1 = l1;
    this.entryById = new Map(entries.map((e) => [e.id, e]));
    this.functionsByRepo = new Map();
  }

  functionsOf(repo) {
    if (!this.functionsByRepo.has(repo)) {
      this.functionsByRepo.set(repo, this.l1.functions().rows.filter((f) => f.repo === repo));
    }
    return this.functionsByRepo.get(repo);
  }

  candidatesFor(unit, serviceClass, method) {
    const list = this.functionsOf(unit.repo);
    if (unit.handler) {
      const handlerName = String(unit.handler).split('::').pop();
      const handlerClass = String(unit.handler).includes('::') ? String(unit.handler).split('::').slice(0, -1).join('::') : null;
      const hits = list.filter((f) => f.name === handlerName
        && (!handlerClass || f.signature.includes(`${handlerClass}::${handlerName}`)));
      if (hits.length) return { hits, basis: 'l2-handler' };
    }
    const re = classMethodRegex(serviceClass, method);
    const exact = list.filter((f) => re.test(f.signature) || (f.owner === serviceClass && f.name === method));
    if (exact.length) return { hits: exact, basis: 'class-method' };
    const byName = list.filter((f) => f.name === method);
    return { hits: byName, basis: 'name-only' };
  }

  pair(unit) {
    const base = {
      unitId: unit.unitId,
      entryId: unit.entryId,
      repo: unit.repo,
      module: unit.module,
      interface: unit.interface,
      method: unit.method,
      code: unit.code,
      direction: unit.direction,
      entrySource: unit.entrySource,
      candidateEntryCount: unit.candidateEntryCount == null ? null : unit.candidateEntryCount
    };
    if (unit.direction === 'callback') {
      return { ...base, pairingStatus: 'not-applicable', resolved: false, reason: 'callback-direction', confidence: 0, stubFile: null, proxyFile: null, implFile: null, implFunction: null, dispatchLine: null, handlerKind: 'callback' };
    }
    if (unit.direction === 'unknown') {
      return { ...base, pairingStatus: 'gap', resolved: false, reason: unit.directionReason || 'direction-unknown', confidence: 0, stubFile: null, proxyFile: null, implFile: null, implFunction: null, dispatchLine: null, handlerKind: null };
    }
    const serviceClass = unit.serviceClass || SERVICE_CLASS[unit.interfaceBase];
    if (!serviceClass) {
      return { ...base, pairingStatus: 'gap', resolved: false, reason: 'service-class-unknown', confidence: 0, stubFile: null, proxyFile: null, implFile: null, implFunction: null, dispatchLine: null, handlerKind: null };
    }
    if (!unit.method && !unit.handler) {
      return { ...base, pairingStatus: 'gap', resolved: false, reason: 'method-missing', confidence: 0, stubFile: null, proxyFile: null, implFile: null, implFunction: null, dispatchLine: null, handlerKind: null };
    }
    const method = unit.method || 'SendMessage';
    const { hits, basis } = this.candidatesFor(unit, serviceClass, method);
    if (!hits.length) {
      return { ...base, pairingStatus: 'gap', resolved: false, reason: basis === 'name-only' ? 'impl-function-not-found' : 'service-method-not-found', confidence: 0, stubFile: null, proxyFile: null, implFile: null, implFunction: null, dispatchLine: null, handlerKind: null, serviceClass };
    }
    const idlParamCount = Array.isArray(unit.params) ? unit.params.length : null;
    let chosen = hits;
    let overload = false;
    if (hits.length > 1 && idlParamCount != null) {
      const byCount = hits.filter((f) => splitParams(f.signature).length === idlParamCount);
      if (byCount.length === 1) chosen = byCount;
      else if (byCount.length > 1) { chosen = byCount; overload = true; }
      else { chosen = hits; overload = true; }
    } else if (hits.length > 1) {
      overload = true;
    }
    const fn = chosen[0];
    const confidence = overload ? 0.6 : (basis === 'name-only' ? 0.6 : 1.0);
    return {
      ...base,
      pairingStatus: overload ? 'resolved-overload' : 'resolved',
      resolved: true,
      reason: overload ? 'overload-ambiguous-first-match' : null,
      confidence,
      pairingBasis: basis,
      serviceClass,
      stubFile: null,
      proxyFile: null,
      implFile: fn.file,
      implFunction: fn.functionId,
      implFunctionName: fn.name,
      implOwner: (String(fn.signature).split('::')[0] || null),
      implStartLine: fn.startLine,
      implEndLine: fn.endLine,
      implSignature: fn.signature,
      implParamCount: splitParams(fn.signature).length,
      overloadCandidates: hits.length > 1 ? hits.map((f) => `${f.file}:${f.startLine}`) : [],
      dispatchLine: null,
      handlerKind: unit.handler ? 'l2-handler' : 'service-method'
    };
  }
}

function pairUnits(units, l1, entries) {
  const pairer = new P5Pairer(l1, entries);
  const rows = units.map((u) => pairer.pair(u));
  const service = rows.filter((r) => r.direction === 'service');
  const resolved = service.filter((r) => r.resolved);
  const singleService = service.filter((r) => r.entrySource === 'candidate' && r.candidateEntryCount === 1);
  const multiService = service.filter((r) => r.entrySource === 'candidate' && r.candidateEntryCount > 1);
  const callbacks = rows.filter((r) => r.direction === 'callback');
  const unknown = rows.filter((r) => r.direction === 'unknown');
  const summary = {
    total: rows.length,
    service: service.length,
    callback: callbacks.length,
    unknown: unknown.length,
    serviceResolved: resolved.length,
    serviceGap: service.length - resolved.length,
    serviceResolvedRate: service.length ? Number((resolved.length / service.length).toFixed(3)) : 0,
    overload: resolved.filter((r) => r.pairingStatus === 'resolved-overload').length,
    singleService: singleService.length,
    singleServiceResolved: singleService.filter((r) => r.resolved).length,
    multiService: multiService.length,
    multiServiceResolved: multiService.filter((r) => r.resolved).length,
    byStatus: rows.reduce((a, r) => { a[r.pairingStatus] = (a[r.pairingStatus] || 0) + 1; return a; }, {}),
    gaps: service.filter((r) => !r.resolved).reduce((a, r) => { a[r.reason] = (a[r.reason] || 0) + 1; return a; }, {})
  };
  return { rows, summary };
}

function writePairing(result) {
  const dir = path.join(OUT_ROOT, 'p5');
  ensureDir(dir);
  writeJsonl(path.join(dir, 'pairing.jsonl'), result.rows);
  writeJson(path.join(dir, 'pairing-summary.json'), result.summary);
  return { dir, file: path.join(dir, 'pairing.jsonl'), summaryFile: path.join(dir, 'pairing-summary.json') };
}

module.exports = { P5Pairer, splitParams, pairUnits, writePairing };
