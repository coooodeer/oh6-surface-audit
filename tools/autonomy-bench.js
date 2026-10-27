'use strict';

/**
 * tools/autonomy-bench.js —— 零依赖 Node CLI 基准外壳。
 *
 * 用法：
 *   node tools/autonomy-bench.js --out=<file> [--label=<text>] -- <script> [args...]
 *
 * 以 `node --require tools/autonomy-bench-preload.js <script> [args...]` 启动目标，
 * stdio 全量继承（不捕获管道）；子进程退出后读取 preload 指标，合并
 * label/command/exitCode 写回同一个 --out 文件（pretty JSON，UTF-8 无 BOM）。
 *
 * 例：
 *   node tools/autonomy-bench.js --out=out/autonomy/bench/x.json --label=cold-index -- \
 *     bin/autonomy.js index --snapshot=latest --scope=K/policies/autonomy-pilot-scope.json
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const TOOL_DIR = path.resolve(__dirname, '..');
const PRELOAD = path.join(__dirname, 'autonomy-bench-preload.js');
const SCHEMA = 'autonomy-bench-v1';
const USAGE = 'usage: node tools/autonomy-bench.js --out=<file> [--label=<text>] -- <script> [args...]';

function parseArgs(argv) {
  const parsed = { out: null, label: null, script: null, args: [] };
  let i = 0;
  for (; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--') break;
    if (!arg.startsWith('--')) return { error: `unexpected argument before --: ${arg}` };
    const eq = arg.indexOf('=');
    const name = eq < 0 ? arg.slice(2) : arg.slice(2, eq);
    const value = eq < 0 ? null : arg.slice(eq + 1);
    if (name !== 'out' && name !== 'label') return { error: `unknown flag: ${arg}` };
    if (value === null || value === '') {
      return { error: `--${name} requires a value (--${name}=<value>)` };
    }
    if (name === 'out') parsed.out = value;
    else parsed.label = value;
  }
  if (i >= argv.length) return { error: 'missing -- separator before the target script' };
  const rest = argv.slice(i + 1);
  if (rest.length === 0) return { error: 'missing target script after --' };
  parsed.script = rest[0];
  parsed.args = rest.slice(1);
  if (!parsed.out) return { error: 'missing required --out=<file>' };
  return parsed;
}

// 仓库内路径打印为 POSIX 风格相对路径；仓库外（含跨盘）保留绝对路径。
function displayPath(file) {
  const rel = path.relative(TOOL_DIR, file);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return file.split(path.sep).join('/');
  return rel.split(path.sep).join('/');
}

function statFingerprint(file) {
  try {
    const st = fs.statSync(file);
    return { mtimeMs: st.mtimeMs, size: st.size };
  } catch (_) {
    return null;
  }
}

function runTarget(script, args, metricsOut) {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const child = spawn(process.execPath, ['--require', PRELOAD, script, ...args], {
      stdio: 'inherit',
      env: { ...process.env, OH6_BENCH_METRICS_OUT: metricsOut }
    });
    child.on('error', (err) => settle({ code: null, signal: null, error: err }));
    child.on('close', (code, signal) => settle({ code, signal, error: null }));
  });
}

function readMetrics(file, before) {
  const after = statFingerprint(file);
  if (!after) return { metrics: null, error: `metrics file not written (${displayPath(file)})` };
  // 目标没写指标时，--out 可能残留上一次运行的文件；mtime/size 未变则视为未写。
  if (before && after.mtimeMs === before.mtimeMs && after.size === before.size) {
    return { metrics: null, error: 'metrics file was not rewritten by the target process' };
  }
  try {
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      return { metrics: null, error: 'metrics file is not a JSON object' };
    }
    return { metrics: doc, error: null };
  } catch (err) {
    return { metrics: null, error: `metrics file is unreadable: ${err.message}` };
  }
}

function buildDoc(label, command, exitCode, metrics, error) {
  if (!metrics) {
    return {
      schema: SCHEMA,
      label,
      command: command.slice(),
      exitCode,
      error,
      bench: { label, command: command.slice(), exitCode, error }
    };
  }
  return {
    ...metrics,
    label,
    command: command.slice(),
    exitCode: exitCode === null ? (metrics.exitCode ?? null) : exitCode,
    bench: { label, command: command.slice(), exitCode }
  };
}

function numberOrNull(doc, key) {
  return doc && typeof doc[key] === 'number' ? doc[key] : null;
}

function fsNumberOrNull(doc, key) {
  return doc && doc.fs && typeof doc.fs[key] === 'number' ? doc.fs[key] : null;
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.error) {
    process.stderr.write(`autonomy-bench: ${parsed.error}\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }

  const outFile = path.isAbsolute(parsed.out) ? parsed.out : path.resolve(TOOL_DIR, parsed.out);
  try {
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
  } catch (err) {
    process.stderr.write(`autonomy-bench: cannot create output directory for ${displayPath(outFile)}: ${err.message}\n`);
    process.exitCode = 1;
    return;
  }

  const before = statFingerprint(outFile);
  const command = [process.execPath, '--require', PRELOAD, parsed.script, ...parsed.args];
  const result = await runTarget(parsed.script, parsed.args, outFile);
  if (result.error) {
    process.stderr.write(`autonomy-bench: cannot start target: ${result.error.message}\n`);
  }
  const exitCode = typeof result.code === 'number' ? result.code : null;
  const read = result.error
    ? { metrics: null, error: `target failed to start: ${result.error.message}` }
    : readMetrics(outFile, before);
  const doc = buildDoc(parsed.label, command, exitCode, read.metrics, read.error);

  try {
    fs.writeFileSync(outFile, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
  } catch (err) {
    process.stderr.write(`autonomy-bench: cannot write ${displayPath(outFile)}: ${err.message}\n`);
    process.exitCode = 1;
    return;
  }

  const summary = {
    ok: read.metrics !== null && exitCode === 0,
    label: parsed.label,
    exitCode,
    wallMs: numberOrNull(doc, 'wallMs'),
    cpuUserMs: numberOrNull(doc, 'cpuUserMs'),
    cpuSystemMs: numberOrNull(doc, 'cpuSystemMs'),
    sampledPeakRssBytes: numberOrNull(doc, 'sampledPeakRssBytes'),
    readBytes: fsNumberOrNull(doc, 'readBytes'),
    writeBytes: fsNumberOrNull(doc, 'writeBytes'),
    out: displayPath(outFile)
  };
  process.stdout.write(`${JSON.stringify(summary)}\n`);
  process.exitCode = exitCode === null ? 1 : exitCode;
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`autonomy-bench: ${err && err.stack ? err.stack : err}\n`);
    process.exitCode = 1;
  });
}

module.exports = { parseArgs, main };
