'use strict';

/**
 * lib/autonomy/store.js —— run 目录、事件账本、checkpoint 原子写、证据归档、校验和。
 *
 * 关键纪律：
 *   - 单写者、append-only `events.jsonl`；seq 从 1 连续递增；
 *   - Windows 原子替换：checkpoint 先写 `<name>.tmp` 再 `rename`，失败保留旧文件（不产生空窗）；
 *   - 所有 JSONL 覆盖写都按 recordId 排序去重（Map 顺序漂移会破坏确定性）；
 *   - `checksums.json` 不包含自身。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ids = require('./ids');
const jsonl = require('./jsonl');
const state = require('./state');

const TOOL_DIR = path.resolve(__dirname, '..', '..');
// 实验隔离（EXPANSION-PLAN E0/E2）：设置 OH6_AUTONOMY_ROOT 时把 run/index 写入
// 独立根目录，用于冷路径测量且不触碰既有索引与 run；未设置时行为不变。
const AUTONOMY_ROOT = process.env.OH6_AUTONOMY_ROOT
  ? path.resolve(process.env.OH6_AUTONOMY_ROOT)
  : path.join(TOOL_DIR, 'out', 'autonomy');

const RECORD_FILES = Object.freeze({
  task: 'tasks.jsonl',
  question: 'questions.jsonl',
  missing: 'missing.jsonl',
  'tool-result': 'tool-results.jsonl',
  assessment: 'assessments.jsonl',
  context: 'contexts.jsonl',
  'report-model': 'report-model.jsonl',
  event: 'events.jsonl'
});

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeJson(file, obj) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function sha256File(abs) {
  return crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
}

function sha256Text(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

function sanitizeSnapshotId(snapshotId) {
  const s = String(snapshotId || '').replace(/^sha256:/, '');
  if (!/^[0-9a-f]{64}$/.test(s)) throw new Error(`store: bad snapshotId ${snapshotId}`);
  return `sha256-${s}`;
}

/** 原子写：先 .tmp 再 rename；rename 失败时保留旧文件并抛错。 */
function atomicWrite(file, text) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, text, 'utf8');
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) { /* ignore */ }
    const err = new Error(`store: atomic rename failed for ${path.basename(file)}: ${e.message}`);
    err.code = 'atomic-write-failed';
    throw err;
  }
}

/** 按 recordId 排序去重后覆盖写 */
function writeRecordsFile(file, records) {
  const seen = new Set();
  const out = [];
  let duplicates = 0;
  for (const r of records) {
    const key = r.recordId || r.seq;
    if (key !== undefined && seen.has(key)) { duplicates += 1; continue; }
    if (key !== undefined) seen.add(key);
    out.push(r);
  }
  out.sort((a, b) => {
    const ka = String(a.recordId || a.seq || '');
    const kb = String(b.recordId || b.seq || '');
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  jsonl.writeJsonl(file, out);
  return { written: out.length, duplicates, file };
}

let runCreateSeq = 0;

class RunStore {
  constructor(dir) {
    this.dir = dir;
    this.runFile = path.join(dir, 'run.json');
    if (!fs.existsSync(this.runFile)) throw new Error(`store: run.json missing in ${dir}`);
    this.run = readJson(this.runFile);
    this.runId = this.run.recordId;
    this.manifestId = this.run.manifestId;
    this._nextSeq = null;
  }

  static dirFor(runId) {
    return path.join(AUTONOMY_ROOT, ids.runDirName(runId));
  }

  /**
   * 建 run 目录并写 run.json / manifest.json / 空账本。
   * @param {{scopeId:string, snapshotId:string, inputManifestId:string, mode:string,
   *          capabilityProfile:string, budget:object, manifestId:string, startedAt?:string}} o
   */
  static create(o) {
    const startedAt = o.startedAt || state.nowIso();
    // runId 不参与任何语义哈希，因此允许带非确定的唯一化字段；
    // 目的是**绝不**让两个并发/同毫秒运行写进同一目录（会静默互相覆盖）。
    let runId = null;
    let dir = null;
    for (let attempt = 0; attempt < 10000; attempt += 1) {
      runCreateSeq += 1;
      const candidate = ids.runId('run', {
        scopeId: o.scopeId,
        snapshotId: o.snapshotId,
        mode: o.mode,
        budget: o.budget,
        startedAt,
        nonce: `${process.pid}:${runCreateSeq}:${attempt}`
      });
      const d = RunStore.dirFor(candidate);
      if (!fs.existsSync(d)) { runId = candidate; dir = d; break; }
    }
    if (!runId) throw new Error('store: could not allocate a unique run directory');
    ensureDir(dir);
    const payload = {
      runId,
      architectureVersion: o.architectureVersion || state.ARCHITECTURE_VERSION,
      schemaVersion: state.SCHEMA_VERSION,
      inputManifestId: o.inputManifestId,
      snapshotId: o.snapshotId,
      scopeId: o.scopeId,
      knowledgeVersion: o.knowledgeVersion || null,
      ...(o.modelId ? { modelId: o.modelId } : {}),
      mode: o.mode,
      capabilityProfile: o.capabilityProfile,
      budget: o.budget
    };
    const record = state.makeRecord({
      recordId: runId,
      recordType: 'run',
      manifestId: o.manifestId,
      producer: state.PRODUCERS.store,
      dependencyRefs: [o.inputManifestId],
      payload,
      createdAt: startedAt
    });
    writeJson(path.join(dir, 'run.json'), record);
    writeJson(path.join(dir, 'manifest.json'), {
      manifestId: o.manifestId,
      runId,
      snapshotId: o.snapshotId,
      inputManifestId: o.inputManifestId,
      scopeId: o.scopeId,
      mode: o.mode,
      startedAt,
      architectureVersion: o.architectureVersion || state.ARCHITECTURE_VERSION,
      knowledgeVersion: o.knowledgeVersion || null,
      ...(o.modelId ? { modelId: o.modelId } : {}),
      artifactRefs: []
    });
    for (const f of Object.values(RECORD_FILES)) {
      const p = path.join(dir, f);
      if (!fs.existsSync(p)) fs.writeFileSync(p, '', 'utf8');
    }
    const store = new RunStore(dir);
    store.acquireLock();
    return store;
  }

  static resolve(runArg) {
    const raw = String(runArg || '');
    if (!raw) throw new Error('store: --run required');
    const norm = ids.normalizeRunId(raw);
    if (norm) {
      const dir = RunStore.dirFor(norm);
      if (fs.existsSync(dir)) return dir;
      throw new Error(`store: run not found: ${norm}`);
    }
    const abs = path.isAbsolute(raw) ? raw : path.join(TOOL_DIR, raw);
    if (fs.existsSync(path.join(abs, 'run.json'))) return abs;
    const base = path.join(AUTONOMY_ROOT, raw);
    if (fs.existsSync(path.join(base, 'run.json'))) return base;
    throw new Error(`store: run not found: ${raw}`);
  }

  static list() {
    if (!fs.existsSync(AUTONOMY_ROOT)) return [];
    return fs.readdirSync(AUTONOMY_ROOT)
      .filter((n) => /^RUN-[0-9a-f]{16}$/.test(n))
      .filter((n) => fs.existsSync(path.join(AUTONOMY_ROOT, n, 'run.json')))
      .sort()
      .map((n) => {
        const rec = readJson(path.join(AUTONOMY_ROOT, n, 'run.json'));
        return { runId: rec.recordId, dir: path.join(AUTONOMY_ROOT, n), createdAt: rec.createdAt, payload: rec.payload };
      });
  }

  file(name) {
    return path.join(this.dir, name);
  }

  acquireLock({ afterCrash = false } = {}) {
    const file = this.file('run.lock');
    if (afterCrash) {
      const previous = readJson(file);
      if (previous.runId !== this.runId || !Number.isInteger(previous.pid) ||
          !/^[0-9a-f]{32}$/.test(previous.nonce || '')) throw new Error('store: invalid run lock');
      // 真实 writer 只会写入 process.pid > 0。非正 pid 是崩溃 fixture 的确定性
      // “已死 owner”标记：Windows 上 PID 可能被无关进程复用，若 fixture 保留真实
      // pid，resume 会把复用者误判为原 writer（默认并发测试的瞬时失败来源）。
      // 生产路径仍对真实 pid 做存活检查，不降低并发写保护。
      if (previous.pid > 0) {
        try {
          process.kill(previous.pid, 0);
          throw new Error('store: original writer may still be running');
        } catch (e) {
          if (e.code !== 'ESRCH') throw e;
        }
      }
      fs.renameSync(file, this.file(`run.lock.stale-${previous.nonce}`));
    }
    const owner = { runId: this.runId, pid: process.pid,
      nonce: crypto.randomBytes(16).toString('hex'), startedAt: state.nowIso() };
    fs.writeFileSync(file, `${JSON.stringify(owner)}\n`, { encoding: 'utf8', flag: 'wx' });
    this.lockOwner = owner;
    return owner;
  }

  releaseLock() {
    if (!this.lockOwner) return;
    const file = this.file('run.lock');
    const current = readJson(file);
    if (current.nonce !== this.lockOwner.nonce || current.pid !== process.pid) {
      throw new Error('store: run lock owner changed');
    }
    fs.unlinkSync(file);
    this.lockOwner = null;
  }

  recordPath(recordType) {
    const f = RECORD_FILES[recordType];
    if (!f) throw new Error(`store: unknown record type ${recordType}`);
    return path.join(this.dir, f);
  }

  readRecords(recordType) {
    const res = jsonl.readJsonl(this.recordPath(recordType));
    return res;
  }

  writeRecords(recordType, records) {
    return writeRecordsFile(this.recordPath(recordType), records);
  }

  appendRecord(recordType, record) {
    jsonl.appendJsonl(this.recordPath(recordType), record);
  }

  readEvents() {
    return jsonl.readJsonl(this.recordPath('event'));
  }

  nextSeq() {
    if (this._nextSeq === null) {
      const res = this.readEvents();
      const max = res.rows.reduce((m, r) => (typeof r.seq === 'number' && r.seq > m ? r.seq : m), 0);
      this._nextSeq = max;
    }
    this._nextSeq += 1;
    return this._nextSeq;
  }

  /** 追加事件（assign seq + actionId 由 seq/task/kind 派生的内容哈希） */
  appendEvent({ kind, taskId = null, from = null, to = null, detail = {} }) {
    const seq = this.nextSeq();
    const at = state.nowIso();
    const event = {
      seq,
      actionId: `ACT:${ids.sha256Hex(ids.canonicalJson({ runId: this.runId, seq, kind, taskId })).slice(0, 16)}`,
      runId: this.runId,
      taskId,
      kind,
      from,
      to,
      at,
      detail
    };
    jsonl.appendJsonl(this.recordPath('event'), event);
    return event;
  }

  writeCheckpoint(checkpoint) {
    const file = this.file(path.join('checkpoints', 'state.json'));
    atomicWrite(file, `${JSON.stringify({ ...checkpoint, throughSeq: this._nextSeq }, null, 2)}\n`);
    return file;
  }

  readCheckpoint() {
    const file = this.file(path.join('checkpoints', 'state.json'));
    if (!fs.existsSync(file)) return null;
    return readJson(file);
  }

  archiveEvidence(record) {
    const dir = this.file('evidence');
    ensureDir(dir);
    const file = path.join(dir, `${record.recordId.replace(':', '-')}.json`);
    writeJson(file, record);
    const sha = sha256File(file);
    return { file, sha256: sha, bytes: fs.statSync(file).size };
  }

  appendToolLedger(entry) {
    jsonl.appendJsonl(this.file('tool-ledger.jsonl'), entry);
  }

  appendModelLedger(entry) {
    jsonl.appendJsonl(this.file('model-ledger.jsonl'), entry);
  }

  writeModelCall(callId, record) {
    const dir = this.file('model-calls');
    ensureDir(dir);
    const file = path.join(dir, `${callId.replace(':', '-')}.json`);
    writeJson(file, record);
    return file;
  }

  /** 计算 run 目录内所有产物的 sha256（不含 checksums.json 自身与 *.tmp） */
  computeChecksums() {
    const out = {};
    const walk = (dir, prefix) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
        const abs = path.join(dir, ent.name);
        const rel = prefix ? `${prefix}/${ent.name}` : ent.name;
        if (ent.isDirectory()) { walk(abs, rel); continue; }
        if (!ent.isFile()) continue;
        if (rel === 'checksums.json' || ent.name.endsWith('.tmp') || ent.name.startsWith('run.lock')) continue;
        out[rel.split(path.sep).join('/')] = { sha256: sha256File(abs), bytes: fs.statSync(abs).size };
      }
    };
    walk(this.dir, '');
    return out;
  }

  writeChecksums(extra = {}) {
    const files = this.computeChecksums();
    const prevFile = this.file('checksums.json');
    let carried = {};
    if (fs.existsSync(prevFile)) {
      try {
        const prev = readJson(prevFile);
        for (const k of ['counts', 'semanticHash', 'verification']) {
          if (prev[k] !== undefined && extra[k] === undefined) carried[k] = prev[k];
        }
      } catch (_) { carried = {}; }
    }
    const payload = {
      algorithm: 'sha256',
      runId: this.runId,
      snapshotId: this.run.payload.snapshotId,
      generatedAt: state.nowIso(),
      fileCount: Object.keys(files).length,
      files,
      ...carried,
      ...extra
    };
    writeJson(this.file('checksums.json'), payload);
    return payload;
  }

  updateManifest(patch) {
    const file = this.file('manifest.json');
    const cur = readJson(file);
    writeJson(file, { ...cur, ...patch });
  }

  /** 写 UTF-8 文本产物（固定 '\\n'，无 BOM） */
  writeText(name, text) {
    const file = this.file(name);
    ensureDir(path.dirname(file));
    const body = String(text).replace(/\r\n/g, '\n');
    fs.writeFileSync(file, body.endsWith('\n') ? body : `${body}\n`, 'utf8');
    return file;
  }

  /** 写 JSON 产物（固定 JSON.stringify(null, 2) + '\\n'） */
  writeJson(name, obj) {
    const file = this.file(name);
    writeJson(file, obj);
    return file;
  }

  readJson(name) {
    return readJson(this.file(name));
  }

  readText(name) {
    return fs.readFileSync(this.file(name), 'utf8');
  }
}

/** index 产物目录按快照与作用域内容隔离；无 fingerprint 保留历史路径。 */
function indexPath(snapshotId, scopeFingerprint) {
  const base = path.join(AUTONOMY_ROOT, 'index', sanitizeSnapshotId(snapshotId));
  return scopeFingerprint ? path.join(base, scopeFingerprint) : base;
}

module.exports = {
  AUTONOMY_ROOT,
  TOOL_DIR,
  RECORD_FILES,
  RunStore,
  indexPath,
  sanitizeSnapshotId,
  writeJson,
  readJson,
  ensureDir,
  atomicWrite,
  writeRecordsFile,
  sha256File,
  sha256Text
};
