'use strict';

/**
 * securityDecision 的预期策略锚点（指南 §15.4 双命题裁决，§24.28 阶段 A/B）。
 *
 * 锚点材料登记在 K/policies/autonomy-security-anchors.json；快照外的外部文件
 * （权限定义元数据、SA profile）按登记的 sha256 固定：加载时重新哈希核对，
 * 漂移即抛错，不产生部分结果。本模块只提供"锚点事实 + 推导说明"，
 * 不确立任何具体入口的预期授权策略——那由 static-proof 的双命题裁决
 * 组合锚点与具体主体后给出，文档/Builder 假设仍受 candidate 上限约束。
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ids = require('./ids');

const ANCHORS_FILE = path.resolve(__dirname, '..', '..', 'K', 'policies', 'autonomy-security-anchors.json');

function sha256Bytes(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function readPinned(facts, rel, expectedSha256) {
  const abs = path.isAbsolute(String(rel)) ? String(rel)
    : path.join(facts.sourceRoot, ...String(rel).split('/'));
  if (!fs.existsSync(abs)) throw new Error(`policy-anchor-missing:${rel}`);
  const buf = fs.readFileSync(abs);
  const actual = sha256Bytes(buf);
  if (actual !== expectedSha256) throw new Error(`policy-anchor-stale:${rel}`);
  return buf;
}

/**
 * 加载并校验锚点文档。
 * @returns {{policyId:string, anchorsSha256:string, permissionDefinitions:object,
 *            saProfile:object, subjectModel:object, derivation:object}}
 */
function load(facts, anchorsPath = ANCHORS_FILE) {
  const anchorsSha256 = sha256Bytes(fs.readFileSync(anchorsPath));
  const doc = JSON.parse(fs.readFileSync(anchorsPath, 'utf8'));
  if (!doc.permissionDefinitions || !doc.saProfile) throw new Error('policy-anchor-document-invalid');

  const permDocBuf = readPinned(facts, doc.permissionDefinitions.file, doc.permissionDefinitions.sha256);
  const definitions = JSON.parse(permDocBuf.toString('utf8'));
  const rows = definitions.definePermissions || definitions.permissions || [];
  const wanted = new Set(doc.permissionDefinitions.permissions || []);
  const entries = {};
  for (const row of rows) {
    if (!wanted.has(row.name)) continue;
    if (entries[row.name]) throw new Error(`policy-anchor-duplicate-permission:${row.name}`);
    entries[row.name] = {
      availableLevel: row.availableLevel, availableType: row.availableType,
      grantMode: row.grantMode, since: row.since,
      provisionEnable: row.provisionEnable === true
    };
  }
  const missing = [...wanted].filter((name) => !entries[name]);
  if (missing.length) throw new Error(`policy-anchor-permission-absent:${missing.join(',')}`);

  const saBuf = readPinned(facts, doc.saProfile.file, doc.saProfile.sha256);
  const saProfile = JSON.parse(saBuf.toString('utf8'));
  const sa = (saProfile.systemability || [])[0] || {};
  if (saProfile.process !== doc.saProfile.process || String(sa.name) !== String(doc.saProfile.systemAbilityId)) {
    throw new Error('policy-anchor-sa-profile-mismatch');
  }

  return {
    policyId: doc.policyId,
    anchorsSha256,
    anchorsFile: path.isAbsolute(anchorsPath) ? anchorsPath.split(path.sep).join('/')
      : path.relative(path.resolve(__dirname, '..', '..'), anchorsPath).split(path.sep).join('/'),
    permissionDefinitions: {
      file: doc.permissionDefinitions.file, sha256: doc.permissionDefinitions.sha256, entries
    },
    saProfile: {
      file: doc.saProfile.file, sha256: doc.saProfile.sha256, process: saProfile.process,
      systemAbilityId: sa.name, libpath: sa.libpath || null
    },
    subjectModel: doc.permissionDefinitions.normalApplicationSubject,
    derivation: {
      permissionDefinitions: doc.permissionDefinitions.derivation,
      saProfile: doc.saProfile.derivation
    },
    docOnlyPolicyCap: doc.docOnlyPolicyCap
  };
}

/**
 * normal-application 主体能否持有某权限（按锚点元数据的有界推导；不推导集合包含）。
 * §24.28 复核修正：availableLevel 高于主体等级时，若 provisionEnable（ACL）开启，
 * 权限仍可经受限权限申请路径获得，获得性依赖部署签名配置——静态快照无法判定，
 * 返回 unknown，不得据此支撑安全 finding。
 */
function subjectCanHold(policy, permission) {
  const entry = policy.permissionDefinitions.entries[permission];
  if (!entry) return { status: 'unknown', reason: 'permission-not-anchored' };
  const levelExcluded = policy.subjectModel.cannotHoldPermissionsOfLevels.includes(entry.availableLevel);
  if (levelExcluded && entry.provisionEnable === false) {
    return { status: 'no', basis: `${entry.availableLevel}/${entry.availableType}/acl-disabled` };
  }
  if (levelExcluded) {
    return { status: 'unknown', reason: 'acl-enabled-obtainability-deployment-dependent',
      basis: `${entry.availableLevel}/${entry.availableType}/acl-enabled` };
  }
  return { status: 'yes', basis: `${entry.availableLevel}/${entry.availableType}` };
}

/**
 * 预期策略锚点是否足以支撑"主体缺该权限即不应获准"的安全 finding：
 * 仅当等级排除且 ACL 未使能时成立；文档/Builder 假设与 ACL 依赖部署的权限一律
 * 返回 candidate 上限。
 */
function anchorQualifies(policy, permission) {
  const hold = subjectCanHold(policy, permission);
  if (hold.status === 'no') {
    return { qualified: true, cap: null, basis: hold.basis,
      derivation: policy.derivation.permissionDefinitions };
  }
  if (hold.status === 'unknown') {
    return { qualified: false, cap: policy.docOnlyPolicyCap || 'candidate',
      reason: hold.reason || 'permission-not-anchored' };
  }
  return { qualified: false, cap: policy.docOnlyPolicyCap || 'candidate',
    reason: 'permission-obtainable-by-subject' };
}

function fingerprint(policy) {
  return ids.sha256Hex(ids.canonicalJson({
    policyId: policy.policyId, anchorsSha256: policy.anchorsSha256
  }));
}

module.exports = { load, subjectCanHold, anchorQualifies, fingerprint, ANCHORS_FILE };
