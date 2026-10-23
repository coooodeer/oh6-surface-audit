'use strict';

/**
 * candidate-origin.js —— 候选来源 / production 资格的单一判定。
 *
 * 简化模型（用户 2026-10-18 确认）：
 *   - 本地来源：target / historical-positive / miner-existing / oracle-fixture；
 *   - external-cve 只允许出现在 eval/external-cve，用于测试义务编排/裁决，
 *     永远不映射到当前扫描范围，永远不 production。
 *   - codeState 只对本地记录判：current-head / fixed / snapshot-only；
 *   - productionEligible = inTarget && codeState=current-head && !constructed
 *     且 origin 必须是本地来源。
 *
 * 这是“资格判定”，不是漏洞判定；productionEligible 仍要过 L3/L4。
 */

const ORIGINS = Object.freeze({
  TARGET: 'target',
  HISTORICAL_POSITIVE: 'historical-positive',
  MINER_EXISTING: 'miner-existing',
  ORACLE_FIXTURE: 'oracle-fixture',
  EXTERNAL_CVE: 'external-cve'
});

const LOCAL_ORIGINS = new Set([
  ORIGINS.TARGET,
  ORIGINS.HISTORICAL_POSITIVE,
  ORIGINS.MINER_EXISTING
]);

const CODE_STATES = Object.freeze({
  CURRENT_HEAD: 'current-head',
  FIXED: 'fixed',
  SNAPSHOT_ONLY: 'snapshot-only'
});

const NOVELTY = Object.freeze({
  NEW: 'new',
  KNOWN_REPRODUCED: 'known-reproduced',
  REGRESSION: 'regression',
  NOT_APPLICABLE: 'not-applicable'
});

// 兼容现有 group 字符串；新代码应直接写 origin。
const LEGACY_GROUP_ORIGIN = Object.freeze({
  'oh-candidate': ORIGINS.TARGET,
  'os-account': ORIGINS.TARGET,
  'p5-candidate': ORIGINS.TARGET,
  'p5-supplementary': ORIGINS.TARGET,
  'callgraph-name-only': ORIGINS.TARGET,
  'cve-calibration': ORIGINS.EXTERNAL_CVE,
  'miner-finding': ORIGINS.MINER_EXISTING,
  'external-cve': ORIGINS.EXTERNAL_CVE,
  'oracle-fixture': ORIGINS.ORACLE_FIXTURE
});

function originOf(record = {}) {
  if (record.originKind && Object.values(ORIGINS).includes(record.originKind)) return record.originKind;
  if (record.origin && ORIGINS[String(record.origin).toUpperCase().replace(/-/g, '_')]) {
    return String(record.origin);
  }
  if (Object.values(ORIGINS).includes(record.origin)) return record.origin;
  if (record.group && LEGACY_GROUP_ORIGIN[record.group]) return LEGACY_GROUP_ORIGIN[record.group];
  return null;
}

function isLocalOrigin(origin) {
  return LOCAL_ORIGINS.has(origin);
}

function isConstructed(record = {}) {
  return record.constructed === true
    || record.origin === ORIGINS.ORACLE_FIXTURE
    || record.group === 'oracle-fixture';
}

function inTarget(record = {}) {
  return record.inTarget === true || record.in_target === true;
}

function codeStateOf(record = {}) {
  const s = record.codeState || record.code_state;
  return Object.values(CODE_STATES).includes(s) ? s : null;
}

function productionEligible(record = {}) {
  const origin = originOf(record);
  if (!isLocalOrigin(origin)) return false;
  if (isConstructed(record)) return false;
  if (!inTarget(record)) return false;
  if (codeStateOf(record) !== CODE_STATES.CURRENT_HEAD) return false;
  return true;
}

function noveltyFor(record = {}) {
  const origin = originOf(record);
  if (!productionEligible(record)) return NOVELTY.NOT_APPLICABLE;
  if (origin === ORIGINS.TARGET) return NOVELTY.NEW;
  if (origin === ORIGINS.MINER_EXISTING) return NOVELTY.KNOWN_REPRODUCED;
  if (origin === ORIGINS.HISTORICAL_POSITIVE) {
    return record.regression === true ? NOVELTY.REGRESSION : NOVELTY.KNOWN_REPRODUCED;
  }
  return NOVELTY.NOT_APPLICABLE;
}

function classify(record = {}) {
  const origin = originOf(record);
  const errors = [];
  if (!origin) errors.push('unknown-origin');
  if (origin === ORIGINS.EXTERNAL_CVE) {
    if (record.inTarget === true) errors.push('external-cve-must-not-map-to-target');
    if (record.codeState) errors.push('external-cve-must-not-have-codeState');
    if (record.productionEligible === true) errors.push('external-cve-must-not-be-production');
  }
  if (origin === ORIGINS.ORACLE_FIXTURE && record.constructed !== true) errors.push('oracle-fixture-must-be-constructed');
  if (isLocalOrigin(origin) && record.codeState && !Object.values(CODE_STATES).includes(record.codeState)) errors.push('bad-codeState');
  if (productionEligible(record) && !inTarget(record)) errors.push('production-without-inTarget');
  return {
    origin,
    codeState: codeStateOf(record),
    inTarget: inTarget(record),
    constructed: isConstructed(record),
    productionEligible: productionEligible(record),
    novelty: noveltyFor(record),
    errors
  };
}

function assertProduction(record, label = 'candidate') {
  const c = classify(record);
  if (!c.productionEligible) {
    throw new Error(`${label}: not productionEligible (${c.errors.join(',') || c.origin + '/' + c.codeState})`);
  }
  return c;
}

module.exports = {
  ORIGINS,
  LOCAL_ORIGINS,
  CODE_STATES,
  NOVELTY,
  LEGACY_GROUP_ORIGIN,
  originOf,
  isLocalOrigin,
  isConstructed,
  inTarget,
  codeStateOf,
  productionEligible,
  noveltyFor,
  classify,
  assertProduction
};
