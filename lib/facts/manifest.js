'use strict';

/**
 * lib/facts/manifest.js —— 产物清单维护。
 * 任何阶段新增产物都要调用 updateManifest，保证 manifestId/artifactRefs 与磁盘一致。
 */

const fs = require('fs');
const path = require('path');
const ids = require('./ids');
const io = require('./io');

function updateManifest(dir, extraRefs, producer = 'AG0') {
  const file = path.join(dir, 'manifest.json');
  if (!fs.existsSync(file)) throw new Error(`manifest-missing: ${file}`);
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  const set = new Set([...(m.artifactRefs || []), ...(extraRefs || [])]);
  const artifactRefs = [...set].sort();
  const next = {
    ...m,
    artifactRefs,
    manifestId: ids.manifestIdOf(m.snapshotId, artifactRefs),
    producer,
    createdAt: new Date().toISOString()
  };
  io.writeJson(file, next);
  return next;
}

const PARSE_RULES_VERSION = 'K-1.0.0';
const ARKTS_PARSE_RULES_VERSION = 'K-1.1.1-arkts-default-namespace';
const RUST_PARSE_RULES_VERSION = 'K-1.2.0-rust-ast-probe';
const rulesVersionFor = (policy) => policy.sourceExtensions.includes('.ets')
  ? ARKTS_PARSE_RULES_VERSION
  : policy.sourceExtensions.includes('.rs') ? RUST_PARSE_RULES_VERSION : PARSE_RULES_VERSION;

module.exports = { updateManifest, PARSE_RULES_VERSION, ARKTS_PARSE_RULES_VERSION,
  RUST_PARSE_RULES_VERSION, rulesVersionFor };
