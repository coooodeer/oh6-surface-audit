'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ids = require('./ids');

/**
 * 受校验的 pilot 来源描述符（指南 §24.28 阶段 A / 1.0.29）。
 * 文档原文及其哈希是来源事实；审核后的 appliesTo 是适用范围；本表只描述
 * "到哪里定位一条文档声明及其常量头"，不再把方法集合散落为代码常量。
 * reviewedMethods 是该来源 Builder 审核时允许覆盖的方法全集（历史审核验证数据）。
 */
const PILOT_SOURCES = Object.freeze([
  Object.freeze({
    id: 'sandbox-manager-setpolicy',
    errorCode: 'authorization',
    docFile: 'base/accesscontrol/sandbox_manager/README_zh.md',
    docNeedles: Object.freeze(['SetPolicy接口调用者须具有']),
    permission: 'ohos.permission.SET_SANDBOX_POLICY',
    headerFile: 'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/include/service/sandbox_manager_const.h',
    headerConstantSymbol: 'SET_POLICY_PERMISSION_NAME',
    proposalAppliesTo: Object.freeze(['SetPolicy']),
    proposalLimitation: 'The README names SetPolicy, not SetPolicyAsync; delegation does not auto-approve applicability.',
    reviewedMethods: null
  }),
  Object.freeze({
    id: 'sandbox-manager-persistence',
    errorCode: 'persistence',
    docFile: 'base/accesscontrol/sandbox_manager/README_zh.md',
    docNeedles: Object.freeze(['除SetPolicy、CheckPersistPolicy接口外']),
    permission: 'ohos.permission.FILE_ACCESS_PERSIST',
    headerFile: 'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/include/service/sandbox_manager_const.h',
    headerConstantSymbol: 'ACCESS_PERSIST_PERMISSION_NAME',
    proposalAppliesTo: Object.freeze(['UnSetPolicy']),
    proposalLimitation: 'The README describes other interfaces generally; async delegation and exceptions require independent review.',
    reviewedMethods: Object.freeze([
      'UnSetPolicy', 'UnSetPolicyAsync', 'PersistPolicy', 'UnPersistPolicy',
      'StartAccessingPolicy', 'StopAccessingPolicy', 'CheckPolicy',
      'PersistPolicyByTokenId', 'UnPersistPolicyByTokenId', 'UnSetAllPolicyByToken',
      'CleanPersistPolicyByPath', 'CleanPolicyByUserId', 'StartAccessingByTokenId',
      'SetPolicyByBundleName'
    ])
  })
]);

/**
 * 第二组件（base/account/os_account, IAccountIAM）的来源描述符（E1）。
 * 文档声明来自源码树内的系统 API 参考；文档位于五根事实快照之外，由本提案把
 * 文档 sha256 + 声明行文本固定进 knowledgeVersion，发布/复算时重新核对。
 * 章节锚点定位到 `### <method>` 小节，再取该小节内声明该权限的行；同一 API 的
 * callback/promise 两个小节重复声明时取首个声明行并在审核说明中登记。
 */
const OS_ACCOUNT_SOURCES = Object.freeze([
  Object.freeze({
    id: 'os-account-manage-idm',
    docSet: 'os-account-iam',
    errorCode: 'os-account-manage-idm',
    docFile: 'docs/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md',
    docSectionAnchor: '### openSession',
    permission: 'ohos.permission.MANAGE_USER_IDM',
    headerFile: 'base/account/os_account/services/accountmgr/src/account_iam/account_iam_service.cpp',
    headerConstantSymbol: 'PERMISSION_MANAGE_USER_IDM',
    proposalAppliesTo: Object.freeze(['OpenSession', 'CloseSession', 'AddCredential', 'UpdateCredential',
      'Cancel', 'DelCred', 'DelUser']),
    proposalLimitation: 'The system API reference declares the permission for the JS openSession/closeSession/addCredential/updateCredential/cancel/delCred/delUser APIs; IDL method names differ only in capitalization and the native client forwards to IAccountIAM. Applicability is a Builder-LLM mapping, not a human review.',
    reviewedMethods: Object.freeze(['OpenSession', 'CloseSession', 'AddCredential', 'UpdateCredential',
      'Cancel', 'DelCred', 'DelUser'])
  }),
  Object.freeze({
    id: 'os-account-use-idm',
    docSet: 'os-account-iam',
    errorCode: 'os-account-use-idm',
    docFile: 'docs/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md',
    docSectionAnchor: '### getEnrolledId',
    permission: 'ohos.permission.USE_USER_IDM',
    headerFile: 'base/account/os_account/services/accountmgr/src/account_iam/account_iam_service.cpp',
    headerConstantSymbol: 'PERMISSION_USE_USER_IDM',
    proposalAppliesTo: Object.freeze(['GetEnrolledId']),
    proposalLimitation: 'Only getEnrolledId is covered: the JS getAuthInfo API maps to IDL GetCredentialInfo but the name mapping is not declared in the same document section, so GetCredentialInfo remains uncovered rather than being silently mapped.',
    reviewedMethods: Object.freeze(['GetEnrolledId'])
  }),
  Object.freeze({
    id: 'os-account-auth-internal',
    docSet: 'os-account-iam',
    errorCode: 'os-account-auth-internal',
    docFile: 'docs/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md',
    docSectionAnchor: '### getAvailableStatus',
    permission: 'ohos.permission.ACCESS_USER_AUTH_INTERNAL',
    headerFile: 'base/account/os_account/services/accountmgr/src/account_iam/account_iam_service.cpp',
    headerConstantSymbol: 'PERMISSION_ACCESS_USER_AUTH_INTERNAL',
    proposalAppliesTo: Object.freeze(['PrepareRemoteAuth', 'AuthUser', 'CancelAuth', 'GetAvailableStatus',
      'GetProperty', 'GetPropertyByCredentialId', 'SetProperty']),
    proposalLimitation: 'The permission declaration is anchored at the getAvailableStatus section; the other six methods are reviewed as the same user-auth-internal family by the Builder, whose own sections declare the same permission.',
    reviewedMethods: Object.freeze(['PrepareRemoteAuth', 'AuthUser', 'CancelAuth', 'GetAvailableStatus',
      'GetProperty', 'GetPropertyByCredentialId', 'SetProperty'])
  }),
  Object.freeze({
    id: 'os-account-distributed-manage',
    docSet: 'os-account-account',
    errorCode: 'os-account-distributed-manage',
    docFile: 'docs/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-distributed-account-sys.md',
    docSectionAnchor: '### setOsAccountDistributedInfoByLocalId',
    permission: 'ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS',
    headerFile: 'base/account/os_account/services/accountmgr/src/account_mgr_service.cpp',
    headerConstantSymbol: 'PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS',
    proposalAppliesTo: Object.freeze(['SetOsAccountDistributedInfo']),
    proposalLimitation: 'The system API reference names the JS setOsAccountDistributedInfoByLocalId API; the IDL method SetOsAccountDistributedInfo differs only by the ByLocalId suffix, and the native service forwards to OhosAccountStateChange. Applicability is a Builder-LLM mapping, not a human review; the operation candidate remains ambiguous because two OhosAccountStateChange overloads share argc 3.',
    reviewedMethods: Object.freeze(['SetOsAccountDistributedInfo'])
  })
]);

/**
 * 第三组件（base/notification/common_event_service, ICommonEvent）来源描述符。
 * CES 的权限字面量写在实现函数体内（const std::string permission = "..."），
 * 没有头文件常量；headerConstantSymbol 为 null 时只校验实现文件哈希，不校验常量。
 */
const CES_SOURCES = Object.freeze([
  Object.freeze({
    id: 'ces-remove-sticky',
    docSet: 'ces-icommonevent',
    errorCode: 'ces-remove-sticky',
    docFile: 'docs/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-commonEventManager-sys.md',
    docSectionAnchor: '## commonEventManager.removeStickyCommonEvent',
    permission: 'ohos.permission.COMMONEVENT_STICKY',
    headerFile: 'base/notification/common_event_service/services/src/common_event_manager_service.cpp',
    headerConstantSymbol: null,
    proposalAppliesTo: Object.freeze(['RemoveStickyCommonEvent']),
    proposalLimitation: 'The system API reference declares COMMONEVENT_STICKY for removeStickyCommonEvent; the IDL method is RemoveStickyCommonEvent. The permission is an inline string literal in the implementation, so no header constant is registered and the contract comparison is expected to stay insufficient until inline literals are modeled.',
    reviewedMethods: Object.freeze(['RemoveStickyCommonEvent'])
  })
]);

const CES_ANI_SOURCE = Object.freeze({ ...CES_SOURCES[0],
  snapshotId: 'sha256:dfef986b671e1f51be558bab1389cd69bf04529bd1355e6f2f444a99d72fb359',
  sourceSalt: 'ces-ani-r3-v1' });

/**
 * 跨组件受控盲测语料（snapshotId 13f40945…）的知识描述符。
 * proposal/norm 的哈希默认只含文档+头文件；同一文档在不同快照下会撞同名提案，
 * 因此盲测描述符显式带 sourceSalt + snapshotId，只影响该快照的 proposal 选择。
 */
const BLIND_SOURCES = Object.freeze([
  Object.freeze({
    id: 'blind-sandbox-set',
    docSet: 'blind-corpus',
    errorCode: 'blind-sandbox-set',
    snapshotId: 'sha256:13f40945a59d89f3635c164ffe472367d36ab248d5e068245641a2c90e0e052e',
    sourceSalt: 'blind-cross-component-v1',
    docFile: 'base/accesscontrol/sandbox_manager/README_zh.md',
    docNeedles: Object.freeze(['SetPolicy接口调用者须具有']),
    permission: 'ohos.permission.SET_SANDBOX_POLICY',
    headerFile: 'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/include/service/sandbox_manager_const.h',
    headerConstantSymbol: 'SET_POLICY_PERMISSION_NAME',
    proposalAppliesTo: Object.freeze(['SetPolicy']),
    proposalLimitation: '受控盲测语料：真实文档声明 + 受控变异体实现；只用于盲测流程，不外推为真实组件结论。',
    reviewedMethods: null
  }),
  Object.freeze({
    id: 'blind-sandbox-persist',
    docSet: 'blind-corpus',
    errorCode: 'blind-sandbox-persist',
    snapshotId: 'sha256:13f40945a59d89f3635c164ffe472367d36ab248d5e068245641a2c90e0e052e',
    sourceSalt: 'blind-cross-component-v1',
    docFile: 'base/accesscontrol/sandbox_manager/README_zh.md',
    docNeedles: Object.freeze(['除SetPolicy、CheckPersistPolicy接口外']),
    permission: 'ohos.permission.FILE_ACCESS_PERSIST',
    headerFile: 'base/accesscontrol/sandbox_manager/services/sandbox_manager/main/cpp/include/service/sandbox_manager_const.h',
    headerConstantSymbol: 'ACCESS_PERSIST_PERMISSION_NAME',
    proposalAppliesTo: Object.freeze(['UnSetPolicy']),
    proposalLimitation: '受控盲测语料：只覆盖 UnSetPolicy 的受控变异体；不外推为真实组件结论。',
    reviewedMethods: Object.freeze(['UnSetPolicy'])
  }),
  Object.freeze({
    id: 'blind-os-account-manage',
    docSet: 'blind-corpus',
    errorCode: 'blind-os-account-manage',
    snapshotId: 'sha256:13f40945a59d89f3635c164ffe472367d36ab248d5e068245641a2c90e0e052e',
    sourceSalt: 'blind-cross-component-v1',
    docFile: 'docs/zh-cn/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md',
    docSectionAnchor: '### openSession',
    permission: 'ohos.permission.MANAGE_USER_IDM',
    headerFile: 'base/account/os_account/services/accountmgr/src/account_iam/account_iam_service.cpp',
    headerConstantSymbol: 'PERMISSION_MANAGE_USER_IDM',
    proposalAppliesTo: Object.freeze(['OpenSession']),
    proposalLimitation: '受控盲测语料：只覆盖 OpenSession 的受控变异体；不外推为真实组件结论。',
    reviewedMethods: Object.freeze(['OpenSession'])
  })
]);

const ALL_SOURCES = Object.freeze([...PILOT_SOURCES, ...OS_ACCOUNT_SOURCES, ...CES_SOURCES,
  CES_ANI_SOURCE, ...BLIND_SOURCES]);

const DOC_SETS = Object.freeze({
  'sandbox-manager-pilot': Object.freeze({ SetPolicy: PILOT_SOURCES[0], UnSetPolicy: PILOT_SOURCES[1] }),
  'os-account-iam': Object.freeze({
    MANAGE_USER_IDM: OS_ACCOUNT_SOURCES[0],
    USE_USER_IDM: OS_ACCOUNT_SOURCES[1],
    ACCESS_USER_AUTH_INTERNAL: OS_ACCOUNT_SOURCES[2]
  }),
  'os-account-account': Object.freeze({
    MANAGE_DISTRIBUTED_ACCOUNTS: OS_ACCOUNT_SOURCES[3]
  }),
  'ces-icommonevent': Object.freeze({
    COMMONEVENT_STICKY: CES_SOURCES[0]
  }),
  'ces-ani-icommonevent': Object.freeze({ COMMONEVENT_STICKY: CES_ANI_SOURCE }),
  'blind-corpus': Object.freeze({
    SetPolicy: BLIND_SOURCES[0],
    UnSetPolicy: BLIND_SOURCES[1],
    MANAGE_USER_IDM: BLIND_SOURCES[2]
  })
});

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const PROPOSAL_DIR = path.resolve(__dirname, '..', '..', 'out', 'autonomy', 'knowledge', 'proposals');
const PUBLISHED_DIR = path.resolve(__dirname, '..', '..', 'K', 'norms');

function sourceByPermission(permission, facts) {
  const candidates = ALL_SOURCES.filter((source) => source.permission === permission);
  if (facts && facts.snapshotId) {
    const bound = candidates.find((source) => source.snapshotId === facts.snapshotId);
    if (bound) return bound;
  }
  return candidates.find((source) => !source.snapshotId) || candidates[0] || null;
}

function sourceForDocSet(docSet, normKey) {
  const set = DOC_SETS[docSet];
  return set && set[normKey] ? set[normKey] : null;
}

/** 文档声明定位：优先章节锚点（第二组件），否则沿用 pilot 的单行精确匹配。 */
function locateDocDeclaration(lines, source) {
  if (!source.docSectionAnchor) {
    const matches = lines.map((text, i) => ({ text, line: i + 1 }))
      .filter((row) => source.docNeedles.every((needle) => row.text.includes(needle)) &&
        row.text.includes(source.permission));
    if (matches.length !== 1) throw new Error(`${source.errorCode}-norm-missing-or-ambiguous`);
    return { row: matches[0], candidateCount: 1 };
  }
  const anchorIndex = lines.findIndex((text) => text.includes(source.docSectionAnchor));
  if (anchorIndex < 0) throw new Error(`${source.errorCode}-norm-missing-or-ambiguous`);
  let end = lines.length;
  for (let i = anchorIndex + 1; i < lines.length; i += 1) {
    // 任意 2-3 级标题都结束当前小节（CES 文档用 ##，os_account 用 ###）。
    if (/^#{2,3}\s/.test(lines[i])) { end = i; break; }
  }
  const matches = [];
  for (let i = anchorIndex; i < end; i += 1) {
    if (!lines[i].includes(source.permission)) continue;
    if (source.docNeedles && !source.docNeedles.every((needle) => lines[i].includes(needle))) continue;
    matches.push({ text: lines[i], line: i + 1 });
  }
  if (!matches.length) throw new Error(`${source.errorCode}-norm-missing-or-ambiguous`);
  return { row: matches[0], candidateCount: matches.length };
}

/** 从描述符定位文档声明行并生成提案；文档/头文件漂移即抛错。 */
function loadFromSource(facts, source) {
  const root = facts.sourceRoot;
  const doc = fs.readFileSync(path.join(root, ...source.docFile.split('/')));
  const lines = doc.toString('utf8').split(/\r?\n/);
  const located = locateDocDeclaration(lines, source);
  const verified = facts.verifyFile(source.headerFile);
  if (!verified.ok) throw new Error(`${source.errorCode}-header-${verified.reason}`);
  if (source.headerConstantSymbol) {
    const header = fs.readFileSync(path.join(root, ...source.headerFile.split('/')), 'utf8');
    const constantRe = new RegExp(`${escapeRegExp(source.headerConstantSymbol)}\\s*(?:\\[\\s*\\])?\\s*=\\s*"` +
      `${escapeRegExp(source.permission)}"`);
    if (!constantRe.test(header)) {
      throw new Error(`${source.errorCode}-permission-constant-mismatch`);
    }
  }
  const docSha256 = ids.sha256Hex(doc);
  const docSource = { file: source.docFile, line: located.row.line, sha256: docSha256,
    text: located.row.text.trim(), ...(located.candidateCount > 1
      ? { duplicateDeclarations: located.candidateCount } : {}) };
  // sourceSalt 只给同一文档在不同快照下的受控知识使用；默认无 salt，历史版本哈希不变。
  const salt = source.sourceSalt ? { sourceSalt: source.sourceSalt } : {};
  return {
    snapshotId: facts.snapshotId,
    knowledgeVersion: `sha256:${ids.sha256Hex(ids.canonicalJson({ source: docSource, headerSha256: verified.actual, ...salt }))}`,
    norm: {
      normId: `NORM:${ids.sha256Hex(ids.canonicalJson({ source: docSource, permission: source.permission, ...salt })).slice(0, 16)}`,
      state: 'proposed', kind: 'authorization', source: docSource, permission: source.permission,
      header: { file: source.headerFile, sha256: verified.actual, factRef: verified.record.factId },
      appliesTo: [...source.proposalAppliesTo],
      limitation: source.proposalLimitation
    }
  };
}

function loadAuthorization(facts) {
  return loadFromSource(facts, PILOT_SOURCES[0]);
}

function loadPersistenceAuthorization(facts) {
  return loadFromSource(facts, PILOT_SOURCES[1]);
}

function loadFromDocSet(facts, docSet, normKey) {
  const source = sourceForDocSet(docSet, normKey);
  if (!source) throw new Error(`authorization-norm-unsupported:${docSet}/${normKey}`);
  return loadFromSource(facts, source);
}

function proposalFor(facts, permission) {
  const source = sourceByPermission(permission, facts);
  if (!source) throw new Error('authorization-norm-unsupported');
  return loadFromSource(facts, source);
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
  // 适用方法集合按来源描述符校验：reviewedMethods 为数组时接受其任意非空去重子集
  // （第二组件与 pilot persistence 来源）；为 null 时沿用 pilot 的 method + Async 二元规则。
  const source = proposal?.norm ? sourceByPermission(proposal.norm.permission) : null;
  const reviewedMethods = source ? source.reviewedMethods : undefined;
  const appliesTo = Array.isArray(review?.appliesTo) ? review.appliesTo : null;
  const uniqueApplies = appliesTo && new Set(appliesTo).size === appliesTo.length &&
    appliesTo.length > 0 && appliesTo.every((method) => typeof method === 'string');
  const firstMatches = appliesTo && proposal?.norm && appliesTo[0] === proposal.norm.appliesTo[0];
  let appliesOk = false;
  if (builder && uniqueApplies && firstMatches) {
    if (Array.isArray(reviewedMethods)) {
      appliesOk = appliesTo.every((method) => reviewedMethods.includes(method));
    } else {
      appliesOk = appliesTo.length === 2 && appliesTo[1] === `${proposal.norm.appliesTo[0]}Async`;
    }
  } else if (!builder) {
    appliesOk = appliesTo && appliesTo.length === 1 && appliesTo[0] === proposal?.norm?.appliesTo?.[0];
  }
  // applicabilityRationale 只约束 Builder 自审（外部签名评审沿用其原有字段集）。
  const rationaleOk = !builder || (appliesTo && (typeof review?.applicabilityRationale === 'string'
    ? review.applicabilityRationale.trim().length >= 12
    : review?.applicabilityRationale && typeof review.applicabilityRationale === 'object' &&
      appliesTo.every((method) => typeof review.applicabilityRationale[method] === 'string' &&
        review.applicabilityRationale[method].trim().length >= 12)));
  if (!proposal || !proposal.norm || proposal.norm.state !== 'proposed' ||
      !verified ||
      !review || (!builder && review.origin !== 'external-human-review') ||
      !/^[A-Za-z0-9_.-]{3,80}$/.test(String(review.reviewer || '')) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(String(review.reviewedAt || '')) ||
      review.decision !== 'accepted' ||
      review.normId !== proposal.norm.normId ||
      review.proposalVersion !== proposal.knowledgeVersion ||
      review.snapshotId !== proposal.snapshotId ||
      !appliesOk || !rationaleOk ||
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
  // 未发布提案的回退适用性：只覆盖试点描述符里带 reviewedMethods 的来源（persistence）。
  const source = sourceByPermission(knowledge.norm.permission);
  if (source && source.reviewedMethods) {
    if (method === source.proposalAppliesTo[0]) return { status: 'applicable', normRef: knowledge.norm.normId };
    if (method === `${source.proposalAppliesTo[0]}Async` && exactDelegate === source.proposalAppliesTo[0]) {
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

/** 通用套件加载：≥1 个已发布 Builder 规范，按方法去重，冲突拒绝；不固定规范数量或权限集合。 */
function loadKnowledgeSuite(files, facts) {
  if (!Array.isArray(files) || files.length < 1) throw new Error('knowledge-suite-requires-published-versions');
  const versions = files.map((file) => loadPublished(file, null, facts));
  if (new Set(versions.map((k) => k.norm.normId)).size !== versions.length ||
      versions.some((k) => k.norm.authority !== 'builder-llm-review')) {
    throw new Error('knowledge-suite-duplicate-or-unreviewed');
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

module.exports = { PILOT_SOURCES, OS_ACCOUNT_SOURCES, ALL_SOURCES, DOC_SETS,
  sourceByPermission, sourceForDocSet, loadFromSource, loadFromDocSet,
  loadAuthorization, loadPersistenceAuthorization,
  reviewAuthorization, applicability, writeProposal,
  publishAuthorization, loadPublished, loadKnowledgeSuite, proposalFor, PROPOSAL_DIR, PUBLISHED_DIR };
