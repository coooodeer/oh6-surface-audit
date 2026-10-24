'use strict';

/**
 * lib/autonomy/doctor.js —— 只读环境/能力检查。
 *
 * 纪律（§6/P1）：
 *   - **不发网络请求**：网关只报配置字段是否存在，不探测、不握手；
 *   - **密钥只报布尔**：`OH6_LLM_API_KEY` 是否存在，长度也不打印（避免侧信道与泄漏）；
 *   - **WSL 只报**：不 spawn `wsl`，只看 `wsl.exe` 是否存在；
 *   - 任一必需项失败 ⇒ ok=false，但**仍输出完整 JSON**（便于运维定位），退出码由 CLI 决定。
 */

const fs = require('fs');
const path = require('path');

const factsLib = require('./facts');
const platform = require('./platform');
const { LLM_CONFIG, defaultConfigPath } = require('./model');

const TOOL_DIR = path.resolve(__dirname, '..', '..');
const WORKSPACE = path.resolve(TOOL_DIR, '..');

const WSL_EXE = 'C:\\Windows\\System32\\wsl.exe';

function check(id, pass, detail, extra) {
  return { id, pass: !!pass, detail, ...(extra || {}) };
}

function safeJson(file) {
  try {
    return { ok: true, value: JSON.parse(fs.readFileSync(file, 'utf8')) };
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

/**
 * @param {{scopePath:string}} opts scopePath 是 CLI 的 --scope（policy 文件路径）
 */
function runDoctor(opts = {}) {
  platform.requireWindowsNative();
  const checks = [];
  const scopePath = path.isAbsolute(opts.scopePath || '')
    ? opts.scopePath
    : path.join(TOOL_DIR, String(opts.scopePath || ''));

  checks.push(check('node-version', /^v\d+\.\d+\.\d+/.test(process.version), process.version));

  if (!scopePath || !fs.existsSync(scopePath)) {
    checks.push(check('scope-policy', false, `missing: ${opts.scopePath || '(none)'}`));
  } else {
    const sc = safeJson(scopePath);
    if (!sc.ok) {
      checks.push(check('scope-policy', false, `unparsable: ${sc.error}`));
    } else {
      const v = sc.value;
      const okShape = !!(v.scopeId && Array.isArray(v.roots) && v.roots.length && v.checkVocabulary);
      checks.push(check('scope-policy', okShape, okShape ? `${v.scopeId} (${v.roots.length} root)` : 'missing scopeId/roots/checkVocabulary', {
        scopeId: v.scopeId || null
      }));
    }
  }

  const scopeDoc = fs.existsSync(scopePath) ? safeJson(scopePath) : { ok: false };
  const scope = scopeDoc.ok ? scopeDoc.value : null;

  const budgetPath = opts.budgetPath
    ? (path.isAbsolute(opts.budgetPath) ? opts.budgetPath : path.join(TOOL_DIR, opts.budgetPath))
    : path.join(TOOL_DIR, 'K', 'policies', 'autonomy-pilot-budget.json');
  if (!fs.existsSync(budgetPath)) {
    checks.push(check('budget-policy', false, `missing: ${path.relative(TOOL_DIR, budgetPath)}`));
  } else {
    const b = safeJson(budgetPath);
    const keys = ['maxModelRequests', 'maxToolCalls', 'maxInputTokens', 'maxOutputTokens', 'maxWallSeconds',
      'maxTasks', 'maxTaskModelRequests', 'maxTaskToolCalls', 'maxConcurrentTools', 'maxConcurrentModels'];
    const present = b.ok && b.value && b.value.budget ? keys.filter((k) => Number.isInteger(b.value.budget[k])) : [];
    checks.push(check('budget-policy', b.ok && present.length === keys.length,
      b.ok ? `${present.length}/${keys.length} budget keys` : `unparsable: ${b.error}`));
  }

  // facts 快照
  const wantedSnapshot = (opts.snapshot && opts.snapshot !== 'latest') ? opts.snapshot : (scope && scope.snapshotId) || 'latest';
  let facts = null;
  try {
    facts = factsLib.AutonomyFacts.open({ snapshot: wantedSnapshot, scope });
    checks.push(check('facts-snapshot', true, facts.snapshotId, { snapshotId: facts.snapshotId }));
  } catch (e) {
    checks.push(check('facts-snapshot', false, `${e.code || 'error'}: ${e.message}`));
  }

  if (scope && scope.snapshotId && facts && scope.snapshotId !== facts.snapshotId) {
    checks.push(check('facts-snapshot-pinned', false, `scope pins ${scope.snapshotId} but resolved ${facts.snapshotId}`));
  } else if (facts) {
    checks.push(check('facts-snapshot-pinned', true, scope && scope.snapshotId ? 'scope snapshot matches' : 'not pinned in scope'));
  }

  if (facts) {
    const st = facts.tableStatus();
    checks.push(check('facts-tables', st.missing.length === 0,
      st.missing.length ? `missing: ${st.missing.join(',')}` : `${st.tables.length} l1 tables present`));
    const metaMissing = st.metadata.filter((m) => !m.present).map((m) => m.name);
    checks.push(check('facts-metadata', metaMissing.length === 0,
      metaMissing.length ? `missing: ${metaMissing.join(',')}` : `${st.metadata.length} metadata tables present`));
    const m = facts.manifest();
    checks.push(check('facts-manifest', /^AM-[0-9a-f]{16}$/.test(m.manifestId || ''), m.manifestId || '(none)'));
    checks.push(check('facts-src-root', fs.existsSync(factsLib.SRC_ROOT), factsLib.SRC_ROOT.replace(WORKSPACE, '.')));
  } else {
    checks.push(check('facts-tables', false, 'skipped: no snapshot'));
    checks.push(check('facts-metadata', false, 'skipped: no snapshot'));
    checks.push(check('facts-manifest', false, 'skipped: no snapshot'));
    checks.push(check('facts-src-root', fs.existsSync(factsLib.SRC_ROOT), factsLib.SRC_ROOT.replace(WORKSPACE, '.')));
  }

  // 网关配置（只读字段，不请求）
  const keyEnv = 'OH6_LLM_API_KEY';
  let gateway = { configured: false, baseUrl: null, model: null, responseFormat: null, apiKeyEnv: keyEnv };
  const configPath = opts.configPath || defaultConfigPath();
  if (fs.existsSync(configPath)) {
    const cfg = safeJson(configPath);
    if (cfg.ok) {
      gateway = {
        configured: !!(cfg.value.baseUrl && cfg.value.model),
        baseUrl: cfg.value.baseUrl || null,
        model: cfg.value.model || null,
        responseFormat: cfg.value.responseFormat === null ? null : (cfg.value.responseFormat ? cfg.value.responseFormat.type : null),
        apiKeyEnv: cfg.value.apiKeyEnv || keyEnv
      };
    }
  }
  checks.push(check('llm-gateway-config', gateway.configured,
    gateway.configured ? `${gateway.baseUrl} model=${gateway.model}` : 'autonomy model config missing or incomplete',
    { gateway }));
  const keyPresent = !!process.env[gateway.apiKeyEnv || keyEnv];
  checks.push(check('llm-api-key', true, keyPresent ? 'present (boolean only)' : 'absent (live mode will fail explicitly)', {
    apiKeyEnv: gateway.apiKeyEnv || keyEnv,
    present: keyPresent
  }));

  const wslPresent = process.platform === 'win32' ? fs.existsSync(WSL_EXE) : fs.existsSync('/usr/bin/wslpath');
  checks.push(check('wsl-installed', true, wslPresent ? 'wsl.exe present (not invoked)' : 'not installed (not required by MVP)', {
    installed: wslPresent
  }));

  const hardFail = checks.filter((c) => !c.pass).map((c) => c.id);
  const capabilities = {
    doctor: true,
    index: !!(facts && facts.missingTables().length === 0),
    runOff: !!(facts && facts.missingTables().length === 0),
    runMock: true,
    runLive: !!(facts && gateway.configured && keyPresent),
    check: true,
    report: true,
    verify: false,
    unsupportedTools: ['collectEvidence', 'inspectLifetime', 'traceValue', 'checkSource']
  };

  return {
    tool: 'autonomy-doctor',
    version: '1',
    generatedAt: new Date().toISOString(),
    platform: { node: process.version, platform: process.platform, arch: process.arch },
    scopeId: scope ? scope.scopeId : null,
    snapshotId: facts ? facts.snapshotId : null,
    inputManifestId: facts ? facts.manifest().manifestId : null,
    factsDir: facts ? path.relative(TOOL_DIR, facts.dir).split(path.sep).join('/') : null,
    gateway,
    apiKeyEnv: gateway.apiKeyEnv || keyEnv,
    apiKeyPresent: keyPresent,
    wslInstalled: wslPresent,
    checks,
    hardFail,
    ok: hardFail.length === 0,
    capabilities,
    networkRequests: 0
  };
}

module.exports = { runDoctor, LLM_CONFIG };
