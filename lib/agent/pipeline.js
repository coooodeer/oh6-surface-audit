'use strict';

/**
 * lib/agent/pipeline.js —— 全类统一入口。
 *
 * 目标：同一命令覆盖 P1–P8：
 *   node bin/agent.js audit --classes=all
 *   node bin/agent.js audit --classes=P1,P2,P7,P8
 *
 * 上游 runner 仍按原 campaign 运行（P1/P2/P7/P8、P3/P4/P6、P5），
 * 然后统一加载 claims/verdicts，再跑 global L4b。
 */

const path = require('path');
const { spawnSync } = require('child_process');
const { CLASS_IDS, groupsForClasses } = require('./classes.js');
const { runGlobalL4b } = require('./l4b-global.js');

const ROOT = path.resolve(__dirname, '..', '..');

function normalizeClasses(value) {
  if (!value || value === 'all') return [...CLASS_IDS];
  const ids = String(value).split(',').map((x) => x.trim()).filter(Boolean);
  const bad = ids.filter((x) => !CLASS_IDS.includes(x));
  if (bad.length) throw new Error(`unknown class: ${bad.join(',')}; expected ${CLASS_IDS.join(',')} or all`);
  return [...new Set(ids)];
}

function runGroup(group, opts = {}) {
  if (opts.reuse) {
    process.stdout.write(`[audit] reuse ${group.id}\n`);
    return 0;
  }
  process.stdout.write(`\n[audit] run ${group.id}: node ${group.runner} ${group.args.join(' ')}\n`);
  const r = spawnSync(process.execPath, [path.join(ROOT, group.runner), ...group.args], {
    cwd: ROOT,
    stdio: 'inherit'
  });
  const status = typeof r.status === 'number' ? r.status : 1;
  if (r.error) process.stderr.write(`[audit] ${group.id} spawn error: ${r.error.message}\n`);
  process.stdout.write(`[audit] ${group.id}: ${status === 0 ? 'PASS' : `FAIL (exit ${status})`}\n`);
  return status;
}

async function runAudit(opts = {}) {
  const classes = normalizeClasses(opts.classes);
  const groups = groupsForClasses(classes);
  let failed = false;
  for (const group of groups) {
    const status = runGroup(group, opts);
    if (status !== 0) { failed = true; break; }
  }
  if (failed) {
    return { failed: true, classes, summary: null };
  }
  const summary = await runGlobalL4b({
    // global L4b 始终对 P1–P8 全类生效；--classes 只控制上游要重跑哪些类。
    classes: [...CLASS_IDS],
    perClass: opts.perClass == null ? 0 : opts.perClass,
    mode: opts.l4bMode || 'auto'
  });
  return { failed: false, classes, summary };
}

module.exports = { ROOT, normalizeClasses, runGroup, runAudit };
