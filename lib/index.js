'use strict';

const fs = require('fs');
const path = require('path');
const { TOOL_ROOT, readJsonl } = require('./util');

/**
 * 复用 oh6-vuln-agent/index/functions.jsonl 作为符号表。
 * 注意：该索引是 2026-10-13 的快照，与当前 OpenHarmony 工作树可能有轻微漂移；
 * 本原型只把它当“文件名→函数区间”的近似，用于把调用点归入函数、识别 parser 函数。
 */
function loadFunctions(filterRoots) {
  const file = path.join(TOOL_ROOT, 'index', 'functions.jsonl');
  const rows = readJsonl(file);
  const byRepoFile = new Map();
  const byRepo = new Map();
  for (const r of rows) {
    if (!r || !r.root || !r.file) continue;
    if (filterRoots && !filterRoots.has(r.root)) continue;
    const key = `${r.root}\u0000${r.file}`;
    if (!byRepoFile.has(key)) byRepoFile.set(key, []);
    byRepoFile.get(key).push(r);
    if (!byRepo.has(r.root)) byRepo.set(r.root, []);
    byRepo.get(r.root).push(r);
  }
  for (const list of byRepoFile.values()) {
    list.sort((a, b) => a.startLine - b.startLine || a.endLine - b.endLine);
  }
  return {
    rows,
    byRepoFile,
    byRepo,
    counts: {
      total: rows.length,
      roots: byRepo.size,
      files: byRepoFile.size
    }
  };
}

/** 取包含该行的最内层函数；找不到返回 null */
function enclosing(fns, repo, file, line) {
  const list = fns.byRepoFile.get(`${repo}\u0000${file}`);
  if (!list) return null;
  let best = null;
  for (const f of list) {
    if (f.startLine > line) break;
    if (line <= f.endLine && (!best || f.endLine - f.startLine < best.endLine - best.startLine)) best = f;
  }
  return best;
}

function functionsOf(fns, repo) {
  return fns.byRepo.get(repo) || [];
}

module.exports = { loadFunctions, enclosing, functionsOf };
