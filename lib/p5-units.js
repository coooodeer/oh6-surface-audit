'use strict';

/**
 * p5-units.js —— P5 R1 候选 -> method-level unit + 方向判定。
 *
 * 关键纪律：
 *   - 32 个聚合候选只作召回容器，禁止直接生成 verdict；
 *   - 每个 unit 按 entryId 去重；
 *   - 方向只分 service/callback/unknown；callback 不进入 P5 claim；
 *   - 73 个 out-of-R1 候选不进入 units，只允许作为 calibration 样本。
 */

const { R1_REPOS, isR1 } = require('./in-scope.js');

const CALLBACK_INTERFACES = new Set([
  'IAppAccountEvent',
  'IAppAccountAuthenticator',
  'IAppAccountAuthenticatorCallback',
  'IDistributedAccountEvent',
  'IGetCredInfoCallback',
  'IGetEnrolledIdCallback',
  'IGetSetPropCallback',
  'IIDMCallback',
  'IOsAccountConstraintEvent',
  'IOsAccountEvent',
  'IOsAccountStateReplyCallback',
  'IPreRemoteAuthCallback',
  'IDomainAccountPlugin',
  'IDomainAccountCallback',
  'ISoftBusClient'
]);

const OBJECT_PARAM_RE = /name|bundle|user|account|token|(^|_)id$|channel|display|credential|photo|domain|profile/i;

function paramsFromHandlerBody(l1, repo, file, handler, line) {
  if (!l1 || !l1.functionsOfFile || !repo || !file) return [];
  const shortHandler = String(handler || '').split('::').pop();
  const fn = l1.functionsOfFile(repo, file).find((f) => f.name === handler || f.name === shortHandler || f.startLine === line);
  if (!fn) return [];
  let lines = [];
  try { lines = l1.sourceLines(repo, file).slice(fn.startLine - 1, fn.endLine); } catch (_) { return []; }
  const out = [];
  const re = /\b(int32_t|uint32_t|int64_t|uint64_t|pid_t|uid_t|std::string|char)\s*&?\s*([A-Za-z_]\w*)\s*;/g;
  for (let li = 0; li < lines.length; li += 1) {
    let m;
    while ((m = re.exec(lines[li])) !== null) {
      const name = m[2];
      if (!OBJECT_PARAM_RE.test(name)) continue;
      if (out.some((p) => p.name === name)) continue;
      out.push({ name, type: m[1], source: 'l2-handler-body', line: fn.startLine + li });
    }
  }
  return out;
}

const SERVICE_CLASS = {
  IAppAccount: 'AppAccountManagerService',
  IDomainAccount: 'DomainAccountManagerService',
  IAccount: 'AccountMgrService',
  IAccountIAM: 'AccountIAMService',
  IOsAccount: 'OsAccountManagerService',
  ISoftBusServer: 'SoftBusServerStub'
};

function repoOfModule(module) {
  if (!module) return null;
  if (module === 'base/account/os_account') return 'base/account/os_account';
  if (module === 'foundation/communication/dsoftbus') return 'foundation/communication/dsoftbus';
  if (module.startsWith('base/')) return module;
  if (module.startsWith('foundation/')) return module;
  return module;
}

function interfaceOf(entry) {
  const o = entry && entry.origin ? entry.origin : {};
  if (o.interfaceName) return o.interfaceName;
  if (o.interfaceToken) return o.interfaceToken;
  const site = String((entry && entry.site) || '');
  const m = /^(?:idl|ipc):([^:]+)::/.exec(site);
  return m ? m[1] : null;
}

function interfaceBase(iface) {
  return String(iface || '').split('.').pop();
}

function methodFromCode(codeExpr) {
  const m = /COMMAND_([A-Z0-9_]+)/.exec(String(codeExpr || ''));
  if (!m) return null;
  let s = m[1].replace(/_(?:IN|OUT)(?:_[A-Z0-9_]+)?$/, '');
  s = s.toLowerCase().replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function methodOf(entry) {
  const o = entry && entry.origin ? entry.origin : {};
  if (o.method) return o.method;
  return methodFromCode(o.codeExpr);
}

function directionFor(iface, method) {
  const base = interfaceBase(iface);
  if (method && /^On[A-Z]/.test(method)) return { direction: 'callback', reason: 'callback-method-prefix' };
  if (CALLBACK_INTERFACES.has(base)) return { direction: 'callback', reason: 'callback-interface' };
  if (SERVICE_CLASS[base]) return { direction: 'service', reason: 'service-interface', serviceClass: SERVICE_CLASS[base] };
  return { direction: 'unknown', reason: 'interface-direction-unknown' };
}

function codeOf(entry) {
  const o = entry && entry.origin ? entry.origin : {};
  return o.explicitCode || o.codeExpr || (entry.identity && entry.identity.code) || null;
}

function fileOf(entry) {
  const o = entry && entry.origin ? entry.origin : {};
  return o.file || (entry.site && entry.site.file) || null;
}

function lineOf(entry) {
  const o = entry && entry.origin ? entry.origin : {};
  return o.line || (entry.site && entry.site.line) || null;
}

function buildP5Units({ candidates = [], entries = [], l2Entries = [], l1 = null }) {
  const entryById = new Map(entries.map((e) => [e.id, e]));
  const r1Candidates = candidates.filter((c) => isR1(repoOfModule(c.origin && c.origin.module) || c.componentRoot));
  const outOfR1 = candidates.length - r1Candidates.length;
  const candidatesByEntry = new Map();
  for (const c of r1Candidates) {
    for (const id of c.entryIds || []) {
      if (!candidatesByEntry.has(id)) candidatesByEntry.set(id, []);
      candidatesByEntry.get(id).push(c);
    }
  }
  const units = [];
  const seen = new Set();
  for (const [entryId, cands] of candidatesByEntry.entries()) {
    const entry = entryById.get(entryId);
    if (!entry) continue;
    if (seen.has(entryId)) continue;
    seen.add(entryId);
    const iface = interfaceOf(entry);
    const method = methodOf(entry);
    const dir = directionFor(iface, method);
    const module = (cands[0].origin && cands[0].origin.module) || cands[0].componentRoot || null;
    const repo = repoOfModule(module);
    units.push({
      unitId: `P5U-${entryId}`,
      scope: 'R1',
      class: 'P5',
      candidateIds: [...new Set(cands.map((c) => c.candidateId))],
      candidateEntryCount: (cands[0].entryIds || []).length,
      primaryCandidateId: cands[0].candidateId,
      entryId,
      entrySource: 'candidate',
      repo,
      module,
      interface: iface,
      interfaceBase: interfaceBase(iface),
      method,
      code: codeOf(entry),
      file: fileOf(entry),
      line: lineOf(entry),
      direction: dir.direction,
      directionReason: dir.reason,
      serviceClass: dir.serviceClass || null,
      attackerPositions: [...new Set(cands.flatMap((c) => c.attackerPosition || []))],
      requiredChecks: entry.required_checks || [],
      reachability: entry.reachability || null,
      params: (entry.origin && entry.origin.params) || [],
      explicitCode: (entry.origin && entry.origin.explicitCode) || null,
      originArtifact: (entry.origin && entry.origin.artifact) || null
    });
  }

  // R1 补充：dsoftbus SendMessage 在 P5 候选池里没有 service 单元（候选是 ISoftBusClient callback），
  // 但它是本地 CWE-862 历史正例。允许从 L2 verified entry 补一个 method-level unit，
  // 标 entrySource=l2-supplementary，不混入候选计数。
  const supp = (l2Entries || []).find((e) => /SERVER_SESSION_SENDMSG$/.test(e.entryKey)
    && e.site && String(e.site.file || '').includes('softbus_server_stub.cpp'));
  if (supp && !units.some((u) => u.entryId === supp.entryKey)) {
    units.push({
      unitId: `P5U-SUPP-${supp.entryKey.replace(/[^A-Za-z0-9]+/g, '_')}`,
      scope: 'R1',
      class: 'P5',
      candidateIds: [],
      primaryCandidateId: null,
      entryId: supp.entryKey,
      entrySource: 'l2-supplementary',
      repo: 'foundation/communication/dsoftbus',
      module: 'foundation/communication/dsoftbus',
      interface: 'OHOS.ISoftBusServer',
      interfaceBase: 'ISoftBusServer',
      method: 'SendMessage',
      code: (supp.identity && supp.identity.code) || 'SERVER_SESSION_SENDMSG',
      file: supp.site.file,
      line: supp.site.line,
      direction: 'service',
      directionReason: 'l2-verified-entry',
      serviceClass: 'SoftBusServerStub',
      attackerPositions: (supp.attackerPosition || []).slice(),
      requiredChecks: supp.requiredChecks || [],
      reachability: null,
      params: paramsFromHandlerBody(l1, 'foundation/communication/dsoftbus', supp.site.file, (supp.identity && supp.identity.handler) || null, supp.site.line),
      paramsSource: 'l2-handler-body',
      explicitCode: (supp.identity && supp.identity.code) || null,
      originArtifact: 'out/l2/entries.jsonl',
      handler: (supp.identity && supp.identity.handler) || null
    });
  }

  const directionCounts = units.reduce((a, u) => { a[u.direction] = (a[u.direction] || 0) + 1; return a; }, {});
  const byInterface = units.reduce((a, u) => { a[u.interfaceBase] = (a[u.interfaceBase] || 0) + 1; return a; }, {});
  return {
    units,
    summary: {
      totalP5Candidates: candidates.length,
      r1Aggregates: r1Candidates.length,
      outOfR1Aggregates: outOfR1,
      r1SingleEntryAggregates: r1Candidates.filter((c) => (c.entryIds || []).length === 1).length,
      r1MultiEntryAggregates: r1Candidates.filter((c) => (c.entryIds || []).length > 1).length,
      uniqueEntries: units.filter((u) => u.entrySource === 'candidate').length,
      units: units.length,
      supplementary: units.filter((u) => u.entrySource === 'l2-supplementary').length,
      direction: directionCounts,
      byInterface,
      serviceUnits: units.filter((u) => u.direction === 'service').length,
      callbackUnits: units.filter((u) => u.direction === 'callback').length,
      unknownUnits: units.filter((u) => u.direction === 'unknown').length,
      singleServiceUnits: units.filter((u) => u.direction === 'service' && u.entrySource === 'candidate' && u.candidateEntryCount === 1).length,
      multiServiceUnits: units.filter((u) => u.direction === 'service' && u.entrySource === 'candidate' && u.candidateEntryCount > 1).length,
      singleCallbackUnits: units.filter((u) => u.direction === 'callback' && u.entrySource === 'candidate' && u.candidateEntryCount === 1).length
    }
  };
}

module.exports = {
  CALLBACK_INTERFACES,
  SERVICE_CLASS,
  repoOfModule,
  interfaceOf,
  interfaceBase,
  methodFromCode,
  methodOf,
  directionFor,
  buildP5Units
};
