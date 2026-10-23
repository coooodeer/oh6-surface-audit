'use strict';

/**
 * lib/autonomy/schema.js —— JSON Schema 受限子集校验器（无第三方依赖，无 pip/npm 安装）。
 *
 * 支持的关键字（够 MVP 的 7+1 张 schema 用）：
 *   type / required / properties / additionalProperties / items / enum / const
 *   oneOf / anyOf / minItems / maxItems / minLength / maxLength / pattern / minimum / maximum
 *
 * 不支持的关键字**不静默接受**：遇到未知关键字直接报 `unsupported-keyword`，
 * 避免"看起来校验了其实没校验"。
 */

const fs = require('fs');

const SUPPORTED = new Set([
  '$schema', 'title', 'description', '$comment', 'definitions',
  'type', 'required', 'properties', 'additionalProperties', 'items', 'enum', 'const',
  'oneOf', 'anyOf', 'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength',
  'pattern', 'minimum', 'maximum'
]);

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function typeMatches(expected, value) {
  const actual = typeOf(value);
  if (expected === 'number') return actual === 'number' || actual === 'integer';
  if (expected === 'integer') return actual === 'integer';
  return actual === expected;
}

function validate(schema, value, pathStr = '$') {
  const errors = [];
  walk(schema, value, pathStr, errors);
  return { valid: errors.length === 0, errors };
}

function walk(schema, value, at, errors) {
  if (!schema || typeof schema !== 'object') return;
  for (const key of Object.keys(schema)) {
    if (!SUPPORTED.has(key)) {
      errors.push({ path: at, keyword: 'unsupported-keyword', message: `schema keyword not supported: ${key}` });
      return;
    }
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => typeMatches(t, value))) {
      errors.push({ path: at, keyword: 'type', message: `expected ${types.join('|')}, got ${typeOf(value)}` });
      return;
    }
  }
  if (schema.const !== undefined && JSON.stringify(schema.const) !== JSON.stringify(value)) {
    errors.push({ path: at, keyword: 'const', message: `expected const ${JSON.stringify(schema.const)}` });
  }
  if (schema.enum && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) {
    errors.push({ path: at, keyword: 'enum', message: `not in enum: ${JSON.stringify(value)}` });
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push({ path: at, keyword: 'minLength', message: `length ${value.length} < ${schema.minLength}` });
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push({ path: at, keyword: 'maxLength', message: `length ${value.length} > ${schema.maxLength}` });
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
      errors.push({ path: at, keyword: 'pattern', message: `does not match ${schema.pattern}` });
    }
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push({ path: at, keyword: 'minimum', message: `${value} < ${schema.minimum}` });
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push({ path: at, keyword: 'maximum', message: `${value} > ${schema.maximum}` });
    }
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push({ path: at, keyword: 'minItems', message: `items ${value.length} < ${schema.minItems}` });
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push({ path: at, keyword: 'maxItems', message: `items ${value.length} > ${schema.maxItems}` });
    }
    if (schema.uniqueItems) {
      const seen = new Set();
      for (const v of value) {
        const k = JSON.stringify(v);
        if (seen.has(k)) errors.push({ path: at, keyword: 'uniqueItems', message: `duplicate item ${k}` });
        seen.add(k);
      }
    }
    if (schema.items) value.forEach((v, i) => walk(schema.items, v, `${at}[${i}]`, errors));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const props = schema.properties || {};
    for (const key of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, key)) {
        errors.push({ path: at, keyword: 'required', message: `missing required property: ${key}` });
      }
    }
    for (const key of Object.keys(value)) {
      if (Object.prototype.hasOwnProperty.call(props, key)) {
        walk(props[key], value[key], `${at}.${key}`, errors);
      } else if (schema.additionalProperties === false) {
        errors.push({ path: at, keyword: 'additionalProperties', message: `unexpected property: ${key}` });
      } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        walk(schema.additionalProperties, value[key], `${at}.${key}`, errors);
      }
    }
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((s) => validate(s, value).valid).length;
    if (matches !== 1) {
      errors.push({ path: at, keyword: 'oneOf', message: `expected exactly 1 match, got ${matches}` });
    }
  }
  if (schema.anyOf) {
    const matches = schema.anyOf.filter((s) => validate(s, value).valid).length;
    if (matches === 0) errors.push({ path: at, keyword: 'anyOf', message: 'no branch matched' });
  }
}

/** 读 K/schemas/autonomy-<name>-v1.json */
function loadSchema(schemaDir, name) {
  const file = `${schemaDir}/autonomy-${name}-v1.json`.split('/').join(require('path').sep);
  if (!fs.existsSync(file)) throw new Error(`schema-missing: ${file}`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function assertValid(schema, value, label) {
  const res = validate(schema, value);
  if (!res.valid) {
    const e = new Error(`schema-invalid: ${label}: ${res.errors.map((x) => `${x.path} ${x.keyword} ${x.message}`).join('; ')}`);
    e.code = 'schema-invalid';
    e.errors = res.errors;
    throw e;
  }
  return value;
}

module.exports = { validate, loadSchema, assertValid, SUPPORTED, typeOf };
