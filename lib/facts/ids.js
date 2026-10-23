'use strict';

/**
 * lib/facts/ids.js —— snapshotId / factId / metadataId 的确定性标识。
 *
 * 旧事实层 ID 格式（此处实现即合同；新 Agent 只读复用）：
 *   - canonicalJson: 键排序、无空白、拒绝非有限数字；同一对象永远同一串。
 *   - snapshotId = "sha256:" + sha256(canonicalJson(snapshotPayload))
 *   - factId     = "F:<snap12>:<kind>:<stableId>"，stableId = sha256(canonicalJson(locator))[0:16]
 *   - metadataId = "M:<snap12>:<kind>:<stableId>"
 */

const crypto = require('crypto');
const fs = require('fs');

/** 确定性 JSON：键排序、无缩进、undefined 丢弃、非有限数字报错。 */
function canonicalJson(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'string') return JSON.stringify(value);
  if (t === 'undefined') return 'null';
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  if (t === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new Error(`canonicalJson: unsupported type ${t}`);
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function sha256File(absPath) {
  return crypto.createHash('sha256').update(fs.readFileSync(absPath)).digest('hex');
}

/** 快照载荷 → snapshotId（不含时间戳/绝对路径） */
function snapshotIdOf(payload) {
  return `sha256:${sha256Hex(canonicalJson(payload))}`;
}

/** "sha256:<64hex>" → 12 位短号；也接受裸 hex */
function shortSnap(snapshotId) {
  const hex = String(snapshotId || '').replace(/^sha256:/, '');
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`shortSnap: bad snapshotId ${snapshotId}`);
  return hex.slice(0, 12);
}

function stableIdOf(locator) {
  return sha256Hex(canonicalJson(locator)).slice(0, 16);
}

function factIdOf(snapshotId, kind, locator) {
  if (!/^[a-z][a-z-]*$/.test(String(kind))) throw new Error(`factIdOf: bad kind ${kind}`);
  return `F:${shortSnap(snapshotId)}:${kind}:${stableIdOf(locator)}`;
}

function metadataIdOf(snapshotId, kind, locator) {
  return `M:${shortSnap(snapshotId)}:${kind}:${stableIdOf(locator)}`;
}

/** 产物 manifestId：AM-<16hex>，由 snapshotId + 产物清单决定。 */
function manifestIdOf(snapshotId, artifactRefs) {
  return `AM-${sha256Hex(canonicalJson({ snapshotId, artifactRefs: [...artifactRefs].sort() })).slice(0, 16)}`;
}

module.exports = {
  canonicalJson,
  sha256Hex,
  sha256File,
  snapshotIdOf,
  shortSnap,
  stableIdOf,
  factIdOf,
  metadataIdOf,
  manifestIdOf
};
