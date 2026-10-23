'use strict';

/**
 * agent.js —— 全 Agent 的统一入口。
 *
 * 用法：
 *   node bin/agent.js status [--json] [--strict]
 *   node bin/agent.js gates  [--strict]
 *   node bin/agent.js run [--campaigns=all|p3p4p6,p5,p1p2p7p8] [--live-l4b] [--with-tests]
 *
 * 设计：
 *   - 不重写 campaign 判定逻辑；调用既有 runner / 读取既有 gate summary。
 *   - 统一状态写 out/report/agent-state.json 与 out/report/agent-gates.md。
 *   - status/gates 只聚合，不跑 campaign；run 才执行。
 *   - 默认 run 只跑确定性 campaign（p3p4p6 + p1p2p7p8）；p5 需要 L4b/key，显式 --campaigns=all。
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  CAMPAIGNS, TOOL_ROOT, REPORT_DIR,
  collectState, writeState, summaryLines, parseTestReportText
} = require('../lib/agent/state');
const { resolveCampaignIds } = require('../lib/agent/registry');
const { runAudit } = require('../lib/agent/pipeline');

const ROOT = TOOL_ROOT;

function usage() {
  return [
    'Usage:',
    '  node bin/agent.js status [--json] [--strict]',
    '  node bin/agent.js gates  [--strict]',
    '  node bin/agent.js audit  [--classes=all|P1,P2,P7,P8] [--reuse] [--l4b=auto|mock|live] [--per-class=0] [--with-l5] [--with-report]',
    '  node bin/agent.js l5',
    '  node bin/agent.js report',
    '  node bin/agent.js run [--campaigns=all|p3p4p6,p1p2p7p8,p5,global-l4b,l5,l7] [--live-l4b] [--with-tests]',
    '',
    'status: aggregate existing campaign gate summaries + node --test report; write agent-state.json',
    'gates : same aggregation; --strict exits 3 when any gate fails',
    'audit : unified P1–P8 chain; global L4b covers all T2/T3 (--per-class=0); --classes only selects upstream',
    'l5    : L5 select/fixtures/target/promote/report; default target',
    'report: L7 findings + delivery (--delivery)',
    'run   : run selected campaigns, optionally node --test, then aggregate',
    '',
    'default run campaigns: p3p4p6,p1p2p7p8',
    'p3p4p6 defaults to --reuse-l4b --reuse-calibration; --live-l4b runs live L4b',
    'p5 is only included with --campaigns=all or explicitly; it may require OH6_LLM_API_KEY'
  ].join('\n');
}

function parseFlags(argv) {
  const opts = {
    cmd: 'status',
    json: false,
    strict: false,
    withTests: false,
    liveL4b: false,
    withL5: false,
    withReport: false,
    campaigns: null,
    classes: null,
    reuse: false,
    l4bMode: 'auto',
    perClass: 0,
    noState: false,
    help: false
  };
  const rest = argv.slice();
  if (rest[0] && !rest[0].startsWith('-')) opts.cmd = rest.shift();
  for (const arg of rest) {
    if (arg === '--json') opts.json = true;
    else if (arg === '--strict') opts.strict = true;
    else if (arg === '--with-tests') opts.withTests = true;
    else if (arg === '--with-l5') opts.withL5 = true;
    else if (arg === '--with-report') opts.withReport = true;
    else if (arg === '--live-l4b') opts.liveL4b = true;
    else if (arg === '--reuse') opts.reuse = true;
    else if (arg === '--no-state') opts.noState = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg.startsWith('--campaigns=')) opts.campaigns = arg.slice('--campaigns='.length);
    else if (arg.startsWith('--campaign=')) opts.campaigns = arg.slice('--campaign='.length);
    else if (arg.startsWith('--classes=')) opts.classes = arg.slice('--classes='.length);
    else if (arg.startsWith('--class=')) opts.classes = arg.slice('--class='.length);
    else if (arg.startsWith('--l4b=')) opts.l4bMode = arg.slice('--l4b='.length);
    else if (arg.startsWith('--per-class=')) opts.perClass = Number(arg.slice('--per-class='.length));
    else if (arg === 'help') opts.cmd = 'help';
    else throw new Error(`unknown argument: ${arg}`);
  }
  return opts;
}

function campaignIds(value) {
  return resolveCampaignIds(value);
}

function runCampaign(def, opts) {
  const args = (def.id === 'p3p4p6' && opts.liveL4b) ? (def.liveArgs || []) : (def.defaultArgs || []);
  process.stdout.write(`\n[agent] run ${def.id}: node ${def.runner} ${args.join(' ')}\n`);
  const r = spawnSync(process.execPath, [path.join(ROOT, def.runner), ...args], {
    cwd: ROOT,
    stdio: 'inherit'
  });
  const status = typeof r.status === 'number' ? r.status : 1;
  if (r.error) process.stderr.write(`[agent] ${def.id} spawn error: ${r.error.message}\n`);
  process.stdout.write(`[agent] ${def.id}: ${status === 0 ? 'PASS' : `FAIL (exit ${status})`}\n`);
  return status;
}

function runStage(label, script, args = []) {
  process.stdout.write(`\n[agent] ${label}: node bin/${script} ${args.join(' ')}\n`);
  const r = spawnSync(process.execPath, [path.join(ROOT, 'bin', script), ...args], { cwd: ROOT, stdio: 'inherit' });
  const status = typeof r.status === 'number' ? r.status : 1;
  if (r.error) process.stderr.write(`[agent] ${label} spawn error: ${r.error.message}\n`);
  process.stdout.write(`[agent] ${label}: ${status === 0 ? 'PASS' : `FAIL (exit ${status})`}\n`);
  return status;
}

function runL5Chain() {
  let failed = false;
  for (const [label, args] of [
    ['l5 select', ['--select']],
    ['l5 target', ['--target']],
    ['l5 report', ['--report']]
  ]) {
    if (runStage(label, 'l5.js', args) !== 0) failed = true;
  }
  return !failed;
}

function runTests() {  process.stdout.write('\n[agent] run node --test\n');
  const outFile = path.join(REPORT_DIR, 'agent-node-test.txt');
  fs.mkdirSync(REPORT_DIR, { recursive: true });
  const r = spawnSync(process.execPath, ['--test'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 600000
  });
  const stdout = r.stdout || '';
  const stderr = r.stderr || '';
  const text = `${stdout}${stdout && !stdout.endsWith('\n') ? '\n' : ''}${stderr}${stderr && !stderr.endsWith('\n') ? '\n' : ''}`;
  fs.writeFileSync(outFile, text, 'utf8');
  const parsed = parseTestReportText(text);
  const status = (typeof r.status === 'number' && r.status === 0 && parsed.pass) ? 0 : (typeof r.status === 'number' ? r.status : 1);
  process.stdout.write(`[agent] tests: ${parsed.passed}/${parsed.total} pass, ${parsed.failed} fail -> ${status === 0 ? 'PASS' : 'FAIL'}\n`);
  if (r.error) process.stderr.write(`[agent] test spawn error: ${r.error.message}\n`);
  return status;
}

function emit(state, opts) {
  const written = writeState(state);
  if (opts.json) {
    process.stdout.write(`${JSON.stringify(state, null, 2)}\n`);
  } else {
    for (const line of summaryLines(state)) process.stdout.write(`[agent] ${line}\n`);
    process.stdout.write(`[agent] state: ${written.stateFile}\n`);
    process.stdout.write(`[agent] gates: ${written.gatesFile}\n`);
    if (state.consistency.issues.length) {
      for (const i of state.consistency.issues) process.stdout.write(`[agent] issue ${i.campaign}/${i.code}: ${i.detail}\n`);
    }
  }
  if (opts.strict && !state.overall.allPass) process.exitCode = 3;
  return state;
}

function main() {
  let opts;
  try {
    opts = parseFlags(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`${e.message}\n\n${usage()}\n`);
    process.exit(2);
  }
  if (opts.help || opts.cmd === 'help') {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (opts.cmd === 'status' || opts.cmd === 'gates') {
    const state = collectState();
    emit(state, opts);
    return;
  }
  if (opts.cmd === 'audit') {
    runAudit({
      classes: opts.classes,
      reuse: opts.reuse,
      l4bMode: opts.l4bMode,
      perClass: opts.perClass
    }).then((r) => {
      if (r.failed) {
        process.stderr.write('[agent] audit: upstream pipeline failed\n');
        process.exitCode = 3;
        return;
      }
      const s = r.summary;
      process.stdout.write(`\n[agent] global L4b: ${s.totals.reviewed}/${s.totals.selected} reviewed, changes=${s.totals.verdictChanges}, simulated=${s.simulated}, gates=${s.gates.filter((g) => g.pass).length}/${s.gates.length}, all=${s.allGatesPass}\n`);
      let stageFailed = false;
      if (opts.withL5) {
        if (!runL5Chain()) stageFailed = true;
      }
      if (opts.withReport) {
        if (runStage('l7 report', 'report.js', ['--all', '--delivery']) !== 0) stageFailed = true;
      }
      if (stageFailed) process.exitCode = 3;
      if (opts.noState) return;
      const state = collectState();
      emit(state, { ...opts, strict: true });
    }).catch((e) => {
      process.stderr.write(`[agent] audit error: ${e && e.stack ? e.stack : e}\n`);
      process.exit(1);
    });
    return;
  }
  if (opts.cmd === 'l5') {
    const ok = runL5Chain();
    const state = collectState();
    emit(state, { ...opts, strict: true });
    if (!ok) process.exitCode = 3;
    return;
  }
  if (opts.cmd === 'report') {
    const ok = runStage('l7 report', 'report.js', ['--all', '--delivery']) === 0;
    const state = collectState();
    emit(state, { ...opts, strict: true });
    if (!ok) process.exitCode = 3;
    return;
  }
  if (opts.cmd === 'run') {
    let ids;
    try {
      ids = campaignIds(opts.campaigns);
    } catch (e) {
      process.stderr.write(`${e.message}\n`);
      process.exit(2);
    }
    let failed = false;
    for (const id of ids) {
      const def = CAMPAIGNS.find((c) => c.id === id);
      if (!def) { process.stderr.write(`[agent] unknown campaign ${id}\n`); failed = true; break; }
      const status = runCampaign(def, opts);
      if (status !== 0) { failed = true; break; }
    }
    if (!failed && opts.withTests) {
      const status = runTests();
      if (status !== 0) failed = true;
    }
    const state = collectState();
    emit(state, { ...opts, strict: true });
    if (failed && state.overall.allPass) {
      // 理论上不应出现；防止 run 失败但旧 summary 仍 PASS 时静默退出 0。
      process.exitCode = 3;
    }
    return;
  }
  process.stderr.write(`unknown command: ${opts.cmd}\n\n${usage()}\n`);
  process.exit(2);
}

if (require.main === module) {
  try { main(); } catch (e) { process.stderr.write(`${e && e.stack ? e.stack : e}\n`); process.exit(1); }
}

module.exports = { main, parseFlags, campaignIds, runCampaign, runTests };
