'use strict';

/**
 * lib/autonomy/ids.js —— 自治层的确定性标识。
 *
 * 纪律（AUTONOMY-MVP-GOAL-GUIDE §5.2）：
 *   - 复用 lib/facts/ids.js 的 canonicalJson/sha256Hex/manifestIdOf，**不改 AG0**；
 *   - 内容 ID 一律 `PREFIX:<16hex>`，16hex = sha256(canonicalJson({kind, payload}))[0:16]；
 *   - payload 只放语义字段：**时间戳、耗时、绝对路径、随机量一律不进 payload**；
 *   - `createdAt` 不参与语义哈希（`semanticHash` 前先 `stripCreatedAt`）。
 */

const base = require('../facts/ids');

const { canonicalJson, sha256Hex, manifestIdOf, shortSnap } = base;

const PREFIXES = Object.freeze({
  fact: 'F',
  entity: 'ENT',
  relation: 'REL',
  task: 'TASK',
  question: 'Q',
  missing: 'MISS',
  evidence: 'EVID',
  context: 'CTX',
  assessment: 'ASSESS',
  run: 'RUN',
  report: 'R',
  modelCall: 'CALL'
});

const PREFIX_KEYS = Object.freeze(Object.keys(PREFIXES).map((k) => PREFIXES[k]));

function prefixOf(target) {
  const key = String(target || '');
  if (Object.prototype.hasOwnProperty.call(PREFIXES, key)) return PREFIXES[key];
  if (PREFIX_KEYS.includes(key)) return key;
  throw new Error(`ids: unknown prefix target ${JSON.stringify(target)}`);
}

/** 内容 ID：同 kind + 同 payload ⇒ 同 ID；payload 里不得有时间/耗时。 */
function contentId(target, kind, payload) {
  if (!kind || typeof kind !== 'string') throw new Error('ids: kind required');
  const prefix = prefixOf(target);
  return `${prefix}:${sha256Hex(canonicalJson({ kind, payload })).slice(0, 16)}`;
}

const entityId = (kind, payload) => contentId('entity', kind, payload);
const relationId = (kind, payload) => contentId('relation', kind, payload);
const taskId = (kind, payload) => contentId('task', kind, payload);
const questionId = (kind, payload) => contentId('question', kind, payload);
const missingId = (kind, payload) => contentId('missing', kind, payload);
const evidenceId = (kind, payload) => contentId('evidence', kind, payload);
const contextId = (kind, payload) => contentId('context', kind, payload);
const assessmentId = (kind, payload) => contentId('assessment', kind, payload);
const runId = (kind, payload) => contentId('run', kind, payload);
const reportId = (kind, payload) => contentId('report', kind, payload);
const modelCallId = (kind, payload) => contentId('modelCall', kind, payload);

/** 校验 ID 形状；非法一律抛错（不静默接受）。 */
function assertId(value, target) {
  const prefix = prefixOf(target);
  const re = new RegExp(`^${prefix}:[0-9a-f]{16}$`);
  if (typeof value !== 'string' || !re.test(value)) {
    throw new Error(`ids: bad ${prefix} id ${JSON.stringify(value)}`);
  }
  return value;
}

function isId(value, target) {
  try {
    assertId(value, target);
    return true;
  } catch (_) {
    return false;
  }
}

/** 深度移除 `createdAt` 键（数组/对象递归，保持其它键） */
function stripCreatedAt(value) {
  if (Array.isArray(value)) return value.map(stripCreatedAt);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) {
      if (k === 'createdAt') continue;
      out[k] = stripCreatedAt(value[k]);
    }
    return out;
  }
  return value;
}

/** 语义哈希：`sha256:<64hex>`，排除 createdAt。 */
function semanticHash(value) {
  return `sha256:${sha256Hex(canonicalJson(stripCreatedAt(value)))}`;
}

/** runId 的目录名（Windows 不允许 ':'）：`RUN:<hex>` → `RUN-<hex>` */
function runDirName(id) {
  const v = String(id || '');
  if (!/^RUN:[0-9a-f]{16}$/.test(v)) throw new Error(`ids: bad run id ${JSON.stringify(id)}`);
  return v.replace(':', '-');
}

/** `RUN-<hex>` / `RUN:<hex>` / 目录名 → 规范 runId */
function normalizeRunId(value) {
  const v = String(value || '');
  if (/^RUN:[0-9a-f]{16}$/.test(v)) return v;
  if (/^RUN-[0-9a-f]{16}$/.test(v)) return v.replace('-', ':');
  return null;
}

/** 去重 + 升序（集合字段一律排序） */
function uniqueSorted(values) {
  return [...new Set((values || []).filter((v) => v !== undefined && v !== null && v !== ''))].sort();
}

module.exports = {
  PREFIXES,
  canonicalJson,
  sha256Hex,
  shortSnap,
  manifestIdOf,
  prefixOf,
  contentId,
  entityId,
  relationId,
  taskId,
  questionId,
  missingId,
  evidenceId,
  contextId,
  assessmentId,
  runId,
  reportId,
  modelCallId,
  assertId,
  isId,
  stripCreatedAt,
  semanticHash,
  runDirName,
  normalizeRunId,
  uniqueSorted
};
