'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ids = require('./ids');

const DOC = 'base/accesscontrol/sandbox_manager/README_zh.md';
const HEADER = 'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/include/service/sandbox_manager_const.h';
const PERMISSION = 'ohos.permission.SET_SANDBOX_POLICY';
const PERSIST_PERMISSION = 'ohos.permission.FILE_ACCESS_PERSIST';
const PROPOSAL_DIR = path.resolve(__dirname, '..', '..', 'out', 'autonomy', 'knowledge', 'proposals');
const PUBLISHED_DIR = path.resolve(__dirname, '..', '..', 'K', 'norms');
const PERSIST_METHODS = Object.freeze([
  'UnSetPolicy', 'UnSetPolicyAsync', 'PersistPolicy', 'UnPersistPolicy',
  'StartAccessingPolicy', 'StopAccessingPolicy', 'CheckPolicy',
  'PersistPolicyByTokenId', 'UnPersistPolicyByTokenId', 'UnSetAllPolicyByToken',
  'CleanPersistPolicyByPath', 'CleanPolicyByUserId', 'StartAccessingByTokenId',
  'SetPolicyByBundleName'
]);

function loadAuthorization(facts) {
  const root = facts.sourceRoot;
  const docFile = path.join(root, ...DOC.split('/'));
  const doc = fs.readFileSync(docFile);
  const lines = doc.toString('utf8').split(/\r?\n/);
  const matches = lines.map((text, i) => ({ text, line: i + 1 }))
    .filter((row) => row.text.includes('SetPolicy接口调用者须具有') && row.text.includes(PERMISSION));
  if (matches.length !== 1) throw new Error('authorization-norm-missing-or-ambiguous');
  const verified = facts.verifyFile(HEADER);
  if (!verified.ok) throw new Error(`authorization-header-${verified.reason}`);
  const header = fs.readFileSync(path.join(root, ...HEADER.split('/')), 'utf8');
  if (!header.includes(`SET_POLICY_PERMISSION_NAME = "${PERMISSION}"`)) {
    throw new Error('authorization-permission-constant-mismatch');
  }
  const docSha256 = ids.sha256Hex(doc);
  const source = { file: DOC, line: matches[0].line, sha256: docSha256, text: matches[0].text.trim() };
  const normId = `NORM:${ids.sha256Hex(ids.canonicalJson({ source, permission: PERMISSION })).slice(0, 16)}`;
  return {
    snapshotId: facts.snapshotId,
    knowledgeVersion: `sha256:${ids.sha256Hex(ids.canonicalJson({ source, headerSha256: verified.actual }))}`,
    norm: {
      normId, state: 'proposed', kind: 'authorization', source, permission: PERMISSION,
      header: { file: HEADER, sha256: verified.actual, factRef: verified.record.factId },
      appliesTo: ['SetPolicy'],
      limitation: 'The README names SetPolicy, not SetPolicyAsync; delegation does not auto-approve applicability.'
    }
  };
}

function loadPersistenceAuthorization(facts) {
  const root = facts.sourceRoot;
  const doc = fs.readFileSync(path.join(root, ...DOC.split('/')));
  const matches = doc.toString('utf8').split(/\r?\n/).map((text, i) => ({ text, line: i + 1 }))
    .filter((row) => row.text.includes('除SetPolicy、CheckPersistPolicy接口外') &&
      row.text.includes(PERSIST_PERMISSION));
  if (matches.length !== 1) throw new Error('persistence-norm-missing-or-ambiguous');
  const verified = facts.verifyFile(HEADER);
  if (!verified.ok) throw new Error(`persistence-header-${verified.reason}`);
  const header = fs.readFileSync(path.join(root, ...HEADER.split('/')), 'utf8');
  if (!header.includes(`ACCESS_PERSIST_PERMISSION_NAME = "${PERSIST_PERMISSION}"`)) {
    throw new Error('persistence-permission-constant-mismatch');
  }
  const source = { file: DOC, line: matches[0].line, sha256: ids.sha256Hex(doc), text: matches[0].text.trim() };
  const normId = `NORM:${ids.sha256Hex(ids.canonicalJson({ source, permission: PERSIST_PERMISSION })).slice(0, 16)}`;
  return { snapshotId: facts.snapshotId,
    knowledgeVersion: `sha256:${ids.sha256Hex(ids.canonicalJson({ source, headerSha256: verified.actual }))}`,
    norm: { normId, state: 'proposed', kind: 'authorization', source, permission: PERSIST_PERMISSION,
      header: { file: HEADER, sha256: verified.actual, factRef: verified.record.factId },
      appliesTo: ['UnSetPolicy'],
      limitation: 'The README describes other interfaces generally; async delegation and exceptions require independent review.' } };
}

function proposalFor(facts, permission) {
  if (permission === PERMISSION) return loadAuthorization(facts);
  if (permission === PERSIST_PERMISSION) return loadPersistenceAuthorization(facts);
  throw new Error('authorization-norm-unsupported');
}

function reviewAuthorization(proposal, review, trustedPublicKey) {
  const builder = review?.authority === 'builder-llm-review';
  let verified = false;
  try { if (builder) {
    verified = review.origin === 'builder-llm' && review.generatedBy === 'builder-llm' &&
      review.needsHumanTuning === true && !review.signature && !review.keyId;
  } else {
    if (trustedPublicKey?.type === 'private' ||
        /-----BEGIN .*PRIVATE KEY-----/.test(String(trustedPublicKey || ''))) {
      throw new Error('private-key-not-a-trust-anchor');
    }
    const key = trustedPublicKey?.type === 'public' ? trustedPublicKey : crypto.createPublicKey(trustedPublicKey);
    const keyId = `KEY:${ids.sha256Hex(key.export({ type: 'spki', format: 'der' })).slice(0, 16)}`;
    const { signature, ...signed } = review || {};
    verified = key.asymmetricKeyType === 'ed25519' && review.keyId === keyId &&
      typeof signature === 'string' && signature.length === 88 &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(signature) &&
      crypto.verify(null, Buffer.from(ids.canonicalJson(signed)), key, Buffer.from(signature, 'base64'));
  }
  } catch (_) { verified = false; }
  if (!proposal || !proposal.norm || proposal.norm.state !== 'proposed' ||
      !verified ||
      !review || (!builder && review.origin !== 'external-human-review') ||
      !/^[A-Za-z0-9_.-]{3,80}$/.test(String(review.reviewer || '')) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(String(review.reviewedAt || '')) ||
      review.decision !== 'accepted' ||
      review.normId !== proposal.norm.normId ||
      review.proposalVersion !== proposal.knowledgeVersion ||
      review.snapshotId !== proposal.snapshotId ||
      !Array.isArray(review.appliesTo) || review.appliesTo[0] !== proposal.norm.appliesTo[0] ||
       (builder ? (review.appliesTo[1] !== `${proposal.norm.appliesTo[0]}Async` ||
         new Set(review.appliesTo).size !== review.appliesTo.length ||
         (proposal.norm.permission === PERMISSION
           ? review.appliesTo.length !== 2
           : review.appliesTo.some((method) => !PERSIST_METHODS.includes(method))) ||
         (typeof review.applicabilityRationale === 'string'
           ? review.appliesTo.length !== 2 || review.applicabilityRationale.trim().length < 12
           : !review.applicabilityRationale || review.appliesTo.some((method) =>
             typeof review.applicabilityRationale[method] !== 'string' ||
             review.applicabilityRationale[method].trim().length < 12)))
        : review.appliesTo.length !== 1) ||
      typeof review.rationale !== 'string' || review.rationale.trim().length < 12) {
    throw new Error('authorization-review-invalid-or-stale');
  }
  const record = { ...review };
  const reviewHash = ids.sha256Hex(ids.canonicalJson(record));
  return {
    snapshotId: proposal.snapshotId,
    knowledgeVersion: `sha256:${ids.sha256Hex(ids.canonicalJson({
      proposalVersion: proposal.knowledgeVersion, reviewHash }))}`,
    norm: { ...proposal.norm, state: 'accepted', appliesTo: record.appliesTo,
      ...(builder ? { authority: 'builder-llm-review', generatedBy: 'builder-llm', needsHumanTuning: true } : {}),
      reviewRef: `REVIEW:${reviewHash.slice(0, 16)}` },
    review: { ...record, reviewRef: `REVIEW:${reviewHash.slice(0, 16)}`, sha256: reviewHash }
  };
}

function applicability(knowledge, method, exactDelegate) {
  if (knowledge.norm.state === 'accepted' && knowledge.norm.authority === 'builder-llm-review') {
    const applies = knowledge.norm.appliesTo.includes(method) &&
      (method.endsWith('Async') ? knowledge.norm.appliesTo.includes(exactDelegate) : true);
    return { status: applies ? 'applicable' : 'not-applicable', normRef: knowledge.norm.normId,
      ...(applies ? {} : { reason: 'outside-reviewed-method-or-delegation' }) };
  }
  if (knowledge.norm.permission === PERSIST_PERMISSION) {
    if (method === 'UnSetPolicy') return { status: 'applicable', normRef: knowledge.norm.normId };
    if (method === 'UnSetPolicyAsync' && exactDelegate === 'UnSetPolicy') {
      return { status: 'unknown', normRef: knowledge.norm.normId, reason: 'async-delegation-requires-review' };
    }
    return { status: 'not-applicable', normRef: knowledge.norm.normId, reason: 'outside-pilot-method' };
  }
  if (method === 'SetPolicy') return { status: 'applicable', normRef: knowledge.norm.normId };
  if (method === 'SetPolicyAsync' && exactDelegate === 'SetPolicy') {
    return { status: 'unknown', normRef: knowledge.norm.normId, reason: 'async-delegation-requires-review' };
  }
  return { status: 'not-applicable', normRef: knowledge.norm.normId, reason: 'outside-literal-method' };
}

function writeProposal(proposal) {
  if (proposal.norm.state !== 'proposed' || !/^sha256:[0-9a-f]{64}$/.test(proposal.knowledgeVersion)) {
    throw new Error('knowledge-proposal-invalid');
  }
  fs.mkdirSync(PROPOSAL_DIR, { recursive: true });
  const file = path.join(PROPOSAL_DIR, `${proposal.knowledgeVersion.slice(7)}.json`);
  const body = `${JSON.stringify(proposal, null, 2)}\n`;
  try { fs.writeFileSync(file, body, { encoding: 'utf8', flag: 'wx' }); }
  catch (e) {
    if (e.code !== 'EEXIST' || fs.readFileSync(file, 'utf8') !== body) throw e;
  }
  return file;
}

function publishAuthorization(proposal, review, trustedPublicKey, facts) {
  const current = proposalFor(facts, proposal?.norm?.permission);
  if (ids.canonicalJson(proposal) !== ids.canonicalJson(current)) {
    throw new Error('knowledge-proposal-stale');
  }
  const accepted = reviewAuthorization(proposal, review, trustedPublicKey);
  const dir = path.join(PUBLISHED_DIR, accepted.knowledgeVersion.slice(7));
  const file = path.join(dir, 'knowledge.json');
  const body = `${JSON.stringify(accepted, null, 2)}\n`;
  fs.mkdirSync(PUBLISHED_DIR, { recursive: true });
  try { fs.mkdirSync(dir); }
  catch (e) {
    if (e.code !== 'EEXIST' || !fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== body) throw e;
    return { file, knowledge: accepted, created: false };
  }
  fs.writeFileSync(file, body, { encoding: 'utf8', flag: 'wx' });
  return { file, knowledge: accepted, created: true };
}

function loadPublished(file, trustedPublicKey, facts) {
  const abs = path.resolve(file);
  if (!abs.startsWith(PUBLISHED_DIR + path.sep) || path.basename(abs) !== 'knowledge.json' ||
      !/^[0-9a-f]{64}$/.test(path.basename(path.dirname(abs)))) {
    throw new Error('knowledge-version-path-invalid');
  }
  const stored = JSON.parse(fs.readFileSync(abs, 'utf8'));
  const { reviewRef, sha256, ...signedReview } = stored.review || {};
  const expected = reviewAuthorization(proposalFor(facts, stored.norm?.permission), signedReview, trustedPublicKey);
  if (expected.knowledgeVersion.slice(7) !== path.basename(path.dirname(abs)) ||
      ids.canonicalJson(stored) !== ids.canonicalJson(expected)) {
    throw new Error('knowledge-version-invalid-or-stale');
  }
  return expected;
}

function loadKnowledgeSuite(files, facts) {
  if (!Array.isArray(files) || files.length !== 2) throw new Error('knowledge-suite-requires-two-versions');
  const versions = files.map((file) => loadPublished(file, null, facts));
  if (new Set(versions.map((k) => k.norm.normId)).size !== 2 ||
      versions.some((k) => k.norm.authority !== 'builder-llm-review') ||
      ![PERMISSION, PERSIST_PERMISSION].every((permission) =>
        versions.some((k) => k.norm.permission === permission))) {
    throw new Error('knowledge-suite-duplicate-or-incomplete');
  }
  const byMethod = new Map();
  for (const knowledge of versions) {
    for (const method of knowledge.norm.appliesTo) {
      if (byMethod.has(method)) throw new Error(`knowledge-suite-method-conflict: ${method}`);
      byMethod.set(method, knowledge);
    }
  }
  return { versions, byMethod, knowledgeVersion: `sha256:${ids.sha256Hex(ids.canonicalJson(
    versions.map((k) => k.knowledgeVersion).sort()))}` };
}

module.exports = { loadAuthorization, loadPersistenceAuthorization, reviewAuthorization, applicability, writeProposal,
  publishAuthorization, loadPublished, loadKnowledgeSuite, PROPOSAL_DIR, PUBLISHED_DIR, DOC, HEADER, PERMISSION };
