'use strict';

/**
 * tools/autonomy-bench-preload.js —— Node CLI 基准的零依赖预加载探针。
 *
 * 由 tools/autonomy-bench.js 以 `node --require <本文件> <script> [args...]` 注入。
 * 只做旁路观测，不改变宿主行为：
 *   - 记录启动墙钟/CPU，每 50ms 采样 RSS 峰值（timer.unref()，不拖住事件循环）；
 *   - 统计 fs.readFileSync/readSync/writeFileSync/appendFileSync/openSync/createReadStream；
 *   - 退出时同步写 OH6_BENCH_METRICS_OUT，自身写入不计入统计；写失败只警告一次，
 *     不改变宿主退出码。
 *
 * 指标 schema：autonomy-bench-v1。
 */

const fs = require('fs');

const SCHEMA = 'autonomy-bench-v1';
const PATCH_FLAG = Symbol.for('oh6.autonomy.bench.preload');

const startedAtMs = Date.now();
const startedAt = new Date(startedAtMs).toISOString();
const startWallNs = process.hrtime.bigint();
const startCpu = process.cpuUsage();

const counters = {
  readBytes: 0,
  readCalls: 0,
  writeBytes: 0,
  writeCalls: 0,
  opens: 0
};

// Node 的公开 fs 实现会互相调用（appendFileSync→writeFileSync、Buffer
// writeFileSync→openSync）。只在最外层计数，避免同一笔 I/O 被重复统计。
let fsDepth = 0;

// 打补丁前先保存原始写函数：退出落盘直接用它，不经过计数器，避免递归统计。
const savedWriteFileSync = fs.writeFileSync;

let rssTimer = null;
let sampledPeakRss = 0;
let metricsWritten = false;
let warned = false;

function sampleRss() {
  try {
    const rss = process.memoryUsage().rss;
    if (rss > sampledPeakRss) sampledPeakRss = rss;
  } catch (_) {
    // 采样失败不影响宿主
  }
}

function warnOnce(err) {
  if (warned) return;
  warned = true;
  try {
    const detail = err && err.message ? err.message : String(err);
    process.stderr.write(`autonomy-bench-preload: metrics not written: ${detail}\n`);
  } catch (_) {
    // stderr 都不可写时只能放弃
  }
}

function encodingOf(options) {
  if (typeof options === 'string') return options;
  if (options && typeof options === 'object' && typeof options.encoding === 'string') return options.encoding;
  return 'utf8';
}

function writtenByteLength(data, options) {
  if (typeof data === 'string') return Buffer.byteLength(data, encodingOf(options));
  if (data instanceof ArrayBuffer) return data.byteLength;
  if (ArrayBuffer.isView(data)) return data.byteLength;
  return 0;
}

function callFs(original, thisArg, args) {
  const outermost = fsDepth === 0;
  fsDepth += 1;
  try {
    const value = Reflect.apply(original, thisArg, args);
    return { outermost, value };
  } finally {
    fsDepth -= 1;
  }
}

function roundedMs(ns) {
  return Math.round((Number(ns) / 1e6) * 1000) / 1000;
}

function finish() {
  if (metricsWritten) return;
  metricsWritten = true;
  if (rssTimer) {
    clearInterval(rssTimer);
    rssTimer = null;
  }
  const out = process.env.OH6_BENCH_METRICS_OUT;
  if (!out) return;
  sampleRss();
  try {
    const cpu = process.cpuUsage(startCpu);
    const finishedAt = new Date().toISOString();
    let maxRssBytes = null;
    try {
      maxRssBytes = process.resourceUsage().maxRSS * 1024;
    } catch (_) {
      maxRssBytes = null;
    }
    const metrics = {
      schema: SCHEMA,
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      pid: process.pid,
      startedAt,
      finishedAt,
      wallMs: roundedMs(process.hrtime.bigint() - startWallNs),
      cpuUserMs: Math.round(cpu.user) / 1000,
      cpuSystemMs: Math.round(cpu.system) / 1000,
      maxRssBytes,
      sampledPeakRssBytes: sampledPeakRss,
      fs: {
        readBytes: counters.readBytes,
        readCalls: counters.readCalls,
        writeBytes: counters.writeBytes,
        writeCalls: counters.writeCalls,
        opens: counters.opens
      },
      argv: process.argv.slice(1),
      exitCode: process.exitCode ?? null
    };
    savedWriteFileSync(out, `${JSON.stringify(metrics, null, 2)}\n`, 'utf8');
  } catch (err) {
    warnOnce(err);
  }
}

function install() {
  if (fs[PATCH_FLAG]) return;
  Object.defineProperty(fs, PATCH_FLAG, { value: true, enumerable: false, configurable: false });

  const originalReadFileSync = fs.readFileSync;
  fs.readFileSync = function readFileSyncCounted(...args) {
    const { outermost, value } = callFs(originalReadFileSync, this, args);
    if (outermost) {
      try {
        counters.readCalls += 1;
        counters.readBytes += Buffer.isBuffer(value)
          ? value.length
          : Buffer.byteLength(String(value), 'utf8');
      } catch (_) {
        // 观测失败不改变宿主行为
      }
    }
    return value;
  };

  const originalReadSync = fs.readSync;
  fs.readSync = function readSyncCounted(...args) {
    const { outermost, value } = callFs(originalReadSync, this, args);
    if (outermost) {
      try {
        if (typeof value === 'number') {
          counters.readCalls += 1;
          counters.readBytes += value;
        }
      } catch (_) {
        // ignore
      }
    }
    return value;
  };

  function patchWrite(name) {
    const original = fs[name];
    fs[name] = function writeCounted(...args) {
      const { outermost, value } = callFs(original, this, args);
      if (outermost) {
        try {
          counters.writeCalls += 1;
          counters.writeBytes += writtenByteLength(args[1], args[2]);
        } catch (_) {
          // ignore
        }
      }
      return value;
    };
  }
  patchWrite('writeFileSync');
  patchWrite('appendFileSync');

  const originalOpenSync = fs.openSync;
  fs.openSync = function openSyncCounted(...args) {
    const { outermost, value } = callFs(originalOpenSync, this, args);
    if (outermost) counters.opens += 1;
    return value;
  };

  // 只计流的打开次数；不监听/包裹 data 事件，避免改变背压与消费行为。
  const originalCreateReadStream = fs.createReadStream;
  fs.createReadStream = function createReadStreamCounted(...args) {
    const { outermost, value } = callFs(originalCreateReadStream, this, args);
    if (outermost) counters.opens += 1;
    return value;
  };

  sampleRss();
  rssTimer = setInterval(sampleRss, 50);
  if (typeof rssTimer.unref === 'function') rssTimer.unref();

  process.on('exit', () => {
    try {
      finish();
    } catch (err) {
      warnOnce(err);
    }
  });
}

install();
