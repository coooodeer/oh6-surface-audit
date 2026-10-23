'use strict';

/**
 * lib/facts/io.js —— AG0 产物读写。
 *
 * 纪律：
 *   - JSONL 必须排序 + 去重（按 factId/id），并返回 duplicates 计数；
 *   - JSON 固定 `JSON.stringify(obj, null, 2) + "\n"`；
 *   - 一律 UTF-8 无 BOM（fs 默认）。
 */

const fs = require('fs');
const path = require('path');

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

const defaultKey = (r) => r.factId || r.metadataId || r.id || r.path;

/**
 * 写 JSONL：按 key 去重（保留第一条）→ 按 key 升序 → 每行一个 JSON。
 * @returns {{written:number, duplicates:number, file:string}}
 */
function writeJsonl(file, rows, opts = {}) {
  const keyOf = opts.key || defaultKey;
  const seen = new Set();
  const out = [];
  let duplicates = 0;
  for (const row of rows) {
    const k = keyOf(row);
    if (k === undefined || k === null || k === '') { out.push(row); continue; }
    if (seen.has(k)) { duplicates += 1; continue; }
    seen.add(k);
    out.push(row);
  }
  out.sort((a, b) => {
    const ka = String(keyOf(a) ?? '');
    const kb = String(keyOf(b) ?? '');
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, out.map((r) => JSON.stringify(r)).join('\n') + (out.length ? '\n' : ''), 'utf8');
  return { written: out.length, duplicates, file };
}

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      try { return JSON.parse(line); } catch (_) { return null; }
    })
    .filter(Boolean);
}

/** 递归删除（用于清理 runtime/tmp 与旧 snapshot）。Windows 上子进程句柄可能短暂占用，用 retry 兜底。 */
function removeDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}

module.exports = { ensureDir, writeJson, readJson, writeJsonl, readJsonl, removeDir };
