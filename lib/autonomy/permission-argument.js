'use strict';

const fs = require('node:fs');
const path = require('node:path');
const ids = require('./ids');
const knowledgeLib = require('./knowledge');
const vertical = require('./vertical');

const DELEGATES = Object.freeze({ SetPolicyAsync: 'SetPolicy', UnSetPolicyAsync: 'UnSetPolicy' });

function compare(facts, anchor, binding, knowledge) {
  const unknown = (reason) => ({ status: 'insufficient', reason });
  const delegate = anchor && DELEGATES[anchor.method];
  if (anchor?.kind !== 'idl' || !delegate || binding?.binding !== 'resolved' || !binding.bound ||
      !knowledge?.norm || knowledge.norm.source?.file !== knowledgeLib.DOC ||
      knowledge.norm.header?.file !== knowledgeLib.HEADER ||
      !knowledge.norm.appliesTo?.includes(delegate)) return unknown('permission-argument-scope-unresolved');
  const local = vertical.selectEvidence(facts, binding.bound, delegate);
  if (local.status !== 'observed') return unknown(local.reason);
  if (local.checkRefs.length !== 1 || local.truncated) return unknown('permission-check-ambiguous');
  const call = facts.index().calls.find((item) => item.factId === local.checkRefs[0]);
  if (!call || call.caller !== local.calleeRef || call.argc !== 2 ||
      call.line < local.callee.startLine || call.line > local.callee.endLine) {
    return unknown('permission-check-ambiguous');
  }
  const line = local.text.split(/\r?\n/)[call.line - local.callee.startLine];
  const match = /^\s*if\s*\(\s*!\s*CheckPermission\s*\(\s*callingTokenId\s*,\s*([A-Z][A-Z0-9_]*)\s*\)\s*\)\s*\{\s*$/.exec(line || '');
  if (!match) return unknown('permission-argument-unresolved');
  const doc = fs.readFileSync(path.join(facts.sourceRoot, ...knowledgeLib.DOC.split('/')));
  const source = knowledge.norm.source;
  const sourceLine = doc.toString('utf8').split(/\r?\n/)[source.line - 1];
  if (ids.sha256Hex(doc) !== source.sha256 || sourceLine?.trim() !== source.text ||
      !source.text.includes(knowledge.norm.permission)) return unknown('permission-norm-stale');
  const header = facts.verifyFile(knowledgeLib.HEADER);
  if (!header.ok || header.actual !== knowledge.norm.header.sha256) return unknown('stale-input');
  const text = fs.readFileSync(path.join(facts.sourceRoot, ...knowledgeLib.HEADER.split('/')), 'utf8');
  const declarations = text.split(/\r?\n/).map((row) =>
    /^\s*const\s+std::string\s+([A-Z][A-Z0-9_]*)\s*=\s*"([^"]+)"\s*;\s*$/.exec(row))
    .filter((row) => row && row[1] === match[1]);
  if (declarations.length !== 1) return unknown('permission-constant-unresolved');
  const observedPermission = declarations[0][2];
  return { status: observedPermission === knowledge.norm.permission ? 'supported' : 'refuted',
    reason: null, entryRef: anchor.entityId, delegateRef: local.calleeRef, checkRef: call.factId,
    file: local.callee.file, line: call.line, symbol: match[1], observedPermission,
    expectedPermission: knowledge.norm.permission, normRef: knowledge.norm.normId,
    headerRef: knowledge.norm.header.factRef };
}

module.exports = { compare };
