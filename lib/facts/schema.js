'use strict';

/**
 * lib/facts/schema.js —— 最小 JSON Schema 校验器（不引第三方依赖）。
 *
 * 支持子集：type（含数组）、required、enum、pattern、items、properties、minimum。
 * 校验入口：
 *   validateFact(row)      —— 公共字段 + K/schemas/facts-v1.json 的 kinds[<kind>]
 *   validateMetadata(row)  —— K/schemas/metadata-v1.json
 *   validateManifest(row)  —— K/schemas/manifest-v1.json
 */

const fs = require('fs');
const path = require('path');

const SCHEMA_DIR = path.resolve(__dirname, '..', '..', 'K', 'schemas');

function loadSchema(name) {
  const file = path.join(SCHEMA_DIR, `${String(name).replace(/\.json$/, '')}.json`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const TYPES = {
  string: (v) => typeof v === 'string',
  number: (v) => typeof v === 'number' && Number.isFinite(v),
  integer: (v) => Number.isInteger(v),
  boolean: (v) => typeof v === 'boolean',
  object: (v) => v !== null && typeof v === 'object' && !Array.isArray(v),
  array: (v) => Array.isArray(v),
  null: (v) => v === null
};

function typeOk(value, type) {
  const list = Array.isArray(type) ? type : [type];
  return list.some((t) => (TYPES[t] ? TYPES[t](value) : true));
}

function validateValue(value, spec, at, errors) {
  if (!spec || typeof spec !== 'object') return;
  if (spec.type && !typeOk(value, spec.type)) {
    errors.push(`${at}: expected type ${Array.isArray(spec.type) ? spec.type.join('|') : spec.type}`);
    return;
  }
  if (spec.enum && !spec.enum.includes(value)) errors.push(`${at}: not in enum (${JSON.stringify(value)})`);
  if (typeof value === 'string' && spec.pattern && !new RegExp(spec.pattern).test(value)) {
    errors.push(`${at}: pattern mismatch (${value.slice(0, 60)})`);
  }
  if (typeof value === 'number' && typeof spec.minimum === 'number' && value < spec.minimum) {
    errors.push(`${at}: below minimum ${spec.minimum}`);
  }
  if (Array.isArray(value) && spec.items) {
    value.forEach((v, i) => validateValue(v, spec.items, `${at}[${i}]`, errors));
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const req of spec.required || []) {
      if (!(req in value)) errors.push(`${at}.${req}: required`);
    }
    for (const [k, sub] of Object.entries(spec.properties || {})) {
      if (k in value) validateValue(value[k], sub, `${at}.${k}`, errors);
    }
  }
}

function validateAgainst(schema, value, rootPath = '$') {
  const errors = [];
  validateValue(value, schema, rootPath, errors);
  return { ok: errors.length === 0, errors };
}

function validateFact(row) {
  const schema = loadSchema('facts-v1');
  const errors = [];
  validateValue(row, schema.common, '$', errors);
  const kindSpec = schema.kinds[row && row.kind];
  if (row && row.kind && !kindSpec) errors.push(`$.kind: unknown kind '${row.kind}'`);
  if (kindSpec) validateValue(row, kindSpec, '$', errors);
  return { ok: errors.length === 0, errors };
}

function validateMetadata(row) {
  return validateAgainst(loadSchema('metadata-v1'), row);
}

function validateManifest(row) {
  return validateAgainst(loadSchema('manifest-v1'), row);
}

module.exports = { loadSchema, validateAgainst, validateFact, validateMetadata, validateManifest };
