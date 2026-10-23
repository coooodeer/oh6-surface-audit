'use strict';

/**
 * lib/agent/registry.js —— 全 Agent 的 campaign / gate 共享注册表。
 *
 * 设计：
 *   - 每个 campaign 一个定义文件：lib/agent/campaigns/<id>.js；
 *   - 本模块启动时自动 require 该目录下所有 *.js，无需再改 state.js / agent.js；
 *   - gate 定义（key/name/order/evaluate）在 campaign 定义里，runner 只提供 ctx；
 *   - runGates() 执行 evaluator，buildGates() 保留给 raw gateResults 兼容/测试；
 */

const fs = require('fs');
const path = require('path');

const CAMPAIGN_DIR = path.join(__dirname, 'campaigns');
const registry = new Map();
let loaded = false;

function assertString(value, field, id) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`campaign ${id || '?'}: ${field} must be a non-empty string`);
  }
}

function validateCampaign(def) {
  if (!def || typeof def !== 'object') throw new Error('campaign definition must be an object');
  const id = def.id;
  assertString(id, 'id');
  assertString(def.name, 'name', id);
  assertString(def.summary, 'summary', id);
  assertString(def.runner, 'runner', id);
  if (registry.has(id)) throw new Error(`campaign ${id}: duplicate id`);
  if (!Array.isArray(def.gates) || def.gates.length === 0) {
    throw new Error(`campaign ${id}: gates must be a non-empty array`);
  }
  const gateKeys = new Set();
  const gateNames = new Set();
  for (const g of def.gates) {
    if (!g || typeof g !== 'object') throw new Error(`campaign ${id}: gate must be an object`);
    assertString(g.key, 'gate.key', id);
    assertString(g.name, 'gate.name', id);
    if (typeof g.evaluate !== 'function') throw new Error(`campaign ${id}: gate ${g.key} must define evaluate(ctx)`);
    if (gateKeys.has(g.key)) throw new Error(`campaign ${id}: duplicate gate key ${g.key}`);
    if (gateNames.has(g.name)) throw new Error(`campaign ${id}: duplicate gate name ${g.name}`);
    gateKeys.add(g.key);
    gateNames.add(g.name);
  }
  return {
    ...def,
    expectedGates: def.gates.length,
    defaultRun: def.defaultRun !== false,
    order: Number.isFinite(def.order) ? def.order : 100
  };
}

function registerCampaign(def) {
  const normalized = validateCampaign(def);
  registry.set(normalized.id, normalized);
  return normalized;
}

function loadCampaigns() {
  if (loaded) return;
  loaded = true;
  const files = fs.readdirSync(CAMPAIGN_DIR, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.js'))
    .map((e) => e.name)
    .sort();
  for (const file of files) {
    // eslint-disable-next-line global-require, import/no-dynamic-require
    const def = require(path.join(CAMPAIGN_DIR, file));
    registerCampaign(def);
  }
}

function listCampaigns() {
  loadCampaigns();
  return [...registry.values()].sort((a, b) => a.order - b.order || a.id.localeCompare(b.id));
}

function getCampaign(id) {
  loadCampaigns();
  return registry.get(id) || null;
}

function listCampaignIds() {
  return listCampaigns().map((c) => c.id);
}

function defaultCampaignIds() {
  return listCampaigns().filter((c) => c.defaultRun).map((c) => c.id);
}

function resolveCampaignIds(value) {
  const all = listCampaignIds();
  if (!value) return defaultCampaignIds();
  if (value === 'all') return all;
  const ids = String(value).split(',').map((x) => x.trim()).filter(Boolean);
  for (const id of ids) {
    if (!all.includes(id)) throw new Error(`unknown campaign: ${id}; expected one of ${all.join(',')} or all`);
  }
  return ids;
}

function gateSpecs(campaignId) {
  const def = getCampaign(campaignId);
  if (!def) throw new Error(`unknown campaign: ${campaignId}`);
  return def.gates;
}

/**
 * 把 runner 提供的 {key: {pass, detail}} 映射成统一 gate 行。
 * - 缺失 key：FAIL，detail 明确写 missing gate result；
 * - 多余 key：忽略，但可通过 auditGateResults 检查。
 */
function buildGates(campaignId, results = {}) {
  const def = getCampaign(campaignId);
  if (!def) throw new Error(`unknown campaign: ${campaignId}`);
  return def.gates.map((spec) => {
    const r = results && results[spec.key];
    return {
      id: `${def.id}/${spec.key}`,
      key: spec.key,
      campaign: def.id,
      name: spec.name,
      pass: Boolean(r && r.pass === true),
      detail: r && Object.prototype.hasOwnProperty.call(r, 'detail') ? r.detail : 'missing gate result'
    };
  });
}

/**
 * 用 campaign 定义里的 evaluate(ctx) 执行 gate；runner 只提供 ctx。
 * 单个 evaluator 抛错不会中断其他 gate，而是显式 FAIL。
 */
function runGates(campaignId, ctx = {}) {
  const def = getCampaign(campaignId);
  if (!def) throw new Error(`unknown campaign: ${campaignId}`);
  return def.gates.map((spec) => {
    let r;
    try {
      r = spec.evaluate(ctx);
    } catch (e) {
      r = { pass: false, detail: `evaluator-error:${e && e.message ? e.message : String(e)}` };
    }
    if (!r || typeof r.pass !== 'boolean') {
      r = { pass: false, detail: r && r.detail ? r.detail : 'missing evaluator result' };
    }
    return {
      id: `${def.id}/${spec.key}`,
      key: spec.key,
      campaign: def.id,
      name: spec.name,
      pass: r.pass === true,
      detail: Object.prototype.hasOwnProperty.call(r, 'detail') ? r.detail : null
    };
  });
}

function auditGateResults(campaignId, results = {}) {
  const def = getCampaign(campaignId);
  if (!def) throw new Error(`unknown campaign: ${campaignId}`);
  const expected = new Set(def.gates.map((g) => g.key));
  const actual = new Set(Object.keys(results || {}));
  return {
    missing: [...expected].filter((k) => !actual.has(k)),
    extra: [...actual].filter((k) => !expected.has(k))
  };
}

loadCampaigns();

module.exports = {
  CAMPAIGN_DIR,
  registerCampaign,
  listCampaigns,
  getCampaign,
  listCampaignIds,
  defaultCampaignIds,
  resolveCampaignIds,
  gateSpecs,
  buildGates,
  runGates,
  auditGateResults
};
