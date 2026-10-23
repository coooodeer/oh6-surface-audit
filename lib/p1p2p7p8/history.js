'use strict';

/**
 * history.js —— 本地历史安全记录（data/facts/history-invariants.jsonl）的 fixture 提取。
 *
 * 只做：
 *   - 按 family/patternClass 过滤；
 *   - 剔除 test/tests/unittest/fuzztest 路径（产品 fixture 纪律）；
 *   - 用 git show 取 pre/post 源码，用 diff hunk + regionAround 对齐函数/窗口；
 *   - 用 witness 做“前无、后有”核对，并生成 mutant（post 去掉 witness 行）。
 *
 * 本地记录只作 fixture/校准，不进入生产 O10，不计入 D4 发现统计。
 */

const path = require('path');
const { git, readJsonl, norm } = (() => {
  const util = require('../util');
  const specdiff = require('../specdiff');
  return { git: util.git, readJsonl: util.readJsonl, norm: specdiff.norm };
})();
const { regionAround, parseHunks } = require('../specdiff');
const { TOOL_ROOT } = require('./common');

function windowAround(text, line, radius = 80) {
  if (!text) return null;
  const lines = String(text).split(/\r?\n/);
  const idx = Math.max(1, Math.min(lines.length, line || 1)) - 1;
  const a = Math.max(0, idx - radius);
  const b = Math.min(lines.length - 1, idx + radius);
  return { start: a + 1, end: b + 1, text: lines.slice(a, b + 1).join('\n'), fallback: true, kind: 'hunk-window' };
}

const HISTORY_FILE = path.join(TOOL_ROOT, 'data', 'facts', 'history-invariants.jsonl');

const TEST_PATH_RE = /\/(test|tests|unittest|fuzztest)\//;

function isProductPath(file) {
  return Boolean(file) && !TEST_PATH_RE.test(String(file));
}

function loadHistoryRows(filter = {}) {
  const rows = readJsonl(HISTORY_FILE);
  return rows.filter((r) => {
    if (!r || !r.id || !r.repo || !r.sha || !r.file) return false;
    if (filter.family && r.family !== filter.family) return false;
    if (filter.families && !filter.families.includes(r.family)) return false;
    if (filter.cls && !(r.patternClass || []).includes(filter.cls)) return false;
    if (filter.ids && !filter.ids.includes(r.id)) return false;
    if (filter.productOnly && !isProductPath(r.file)) return false;
    return true;
  });
}

function stripWitnessLine(text, witness) {
  const w = norm(witness);
  if (!w) return text;
  return String(text)
    .split(/\r?\n/)
    .filter((line) => !norm(line).includes(w))
    .join('\n');
}

function hasWitness(text, witness) {
  const w = norm(witness);
  return Boolean(w) && norm(text).includes(w);
}

/**
 * 提取一条历史记录的 pre/post/mutant 函数窗口。
 * @returns {{id, repo, sha, file, family, witness, status, reason, preSource, postSource, mutantSource, pre, post, mutant}}
 */
function extractHistorySample(row, opts = {}) {
  const rec = {
    id: row.id,
    repo: row.repo,
    sha: row.sha,
    file: row.file,
    family: row.family,
    patternClass: row.patternClass || [],
    witness: row.witness,
    status: 'fixture-unavailable',
    reason: null,
    preSource: null,
    postSource: null,
    mutantSource: null,
    pre: null,
    post: null,
    mutant: null
  };
  if (!isProductPath(row.file) && opts.productOnly !== false) {
    rec.reason = 'test-or-fuzz-path';
    return rec;
  }
  const diff = git(row.repo, ['diff', '--unified=0', `${row.sha}^`, row.sha, '--', row.file]);
  const preText = git(row.repo, ['show', `${row.sha}^:${row.file}`]);
  const postText = git(row.repo, ['show', `${row.sha}:${row.file}`]);
  if (preText == null) { rec.reason = 'pre-missing'; return rec; }
  if (postText == null) { rec.reason = 'post-missing'; return rec; }
  const hunks = parseHunks(diff);
  if (!hunks.length) { rec.reason = 'diff-no-hunk'; return rec; }
  const w = norm(row.witness);
  const candidates = [];
  for (let hi = 0; hi < hunks.length; hi += 1) {
    const h = hunks[hi];
    const preRegion = regionAround(preText, h.oldStart);
    const postRegion = regionAround(postText, h.newStart);
    if (preRegion && postRegion) {
      const preHas = w ? norm(preRegion.text).includes(w) : false;
      const postHas = w ? norm(postRegion.text).includes(w) : true;
      candidates.push({ hi, h, preRegion, postRegion, preHas, postHas, kind: 'function' });
      if (preHas || !postHas) {
        const preW = windowAround(preText, h.oldStart, 80);
        const postW = windowAround(postText, h.newStart, 80);
        if (preW && postW) {
          const preHasW = w ? norm(preW.text).includes(w) : false;
          const postHasW = w ? norm(postW.text).includes(w) : true;
          if (!preHasW && postHasW) {
            candidates.push({ hi, h, preRegion: preW, postRegion: postW, preHas: preHasW, postHas: postHasW, kind: 'hunk-window' });
          }
        }
      }
    }
  }
  if (!candidates.length) { rec.reason = 'region-extract-failed'; return rec; }
  const best = candidates.find((c) => !c.preHas && c.postHas)
    || candidates.find((c) => c.postHas)
    || candidates.find((c) => c.preHas)
    || candidates[0];
  let preSource = best.preRegion.text;
  let preRegion = best.preRegion;
  let preHas = best.preHas;
  // 有些修复是把旧函数拆成新函数：按 scope 里的函数名回找旧函数，才能做同函数对照。
  if (opts.scopeFunction) {
    const name = String(opts.scopeFunction);
    const preLines = String(preText).split(/\r?\n/);
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    let at = preLines.findIndex((l) => new RegExp(`::\\s*${esc}\\s*\\(`).test(l));
    if (at < 0) at = preLines.findIndex((l) => new RegExp(`(^|\\s)${esc}\\s*\\(`).test(l));
    if (at >= 0) {
      const r = regionAround(preText, at + 1);
      if (r) {
        preSource = r.text;
        preRegion = r;
        preHas = hasWitness(preSource, row.witness);
      }
    }
  }
  // 头部/整类样本只保留 witness 附近窗口，避免拿整个文件冒充函数窗口。
  if (opts.centerOnWitness !== false) {
    const postLines = String(best.postRegion.text).split(/\r?\n/);
    const wi = row.witness ? postLines.findIndex((l) => norm(l).includes(norm(row.witness))) : -1;
    if (best.postRegion.text.length > 6000) {
      const anchorLine = wi >= 0 ? wi + best.postRegion.start : best.postRegion.start;
      const w = windowAround(postText, anchorLine, 60);
      if (w) {
        rec.postSource = w.text;
        rec.post = { hunk: best.hi, line: best.h.newStart, start: w.start, end: w.end, fallback: true, kind: 'witness-window', hasWitness: hasWitness(w.text, row.witness) };
      }
    }
    if (preSource.length > 6000) {
      let anchor = best.h.oldStart;
      if (preHas && row.witness) {
        const preLines = String(preSource).split(/\r?\n/);
        const pi = preLines.findIndex((l) => norm(l).includes(norm(row.witness)));
        if (pi >= 0) anchor = preRegion.start + pi;
      }
      const w = windowAround(preText, anchor, 60);
      if (w) {
        preSource = w.text;
        preRegion = w;
        preHas = hasWitness(preSource, row.witness);
      }
    }
  }
  rec.preSource = preSource;
  if (!rec.postSource) rec.postSource = best.postRegion.text;
  rec.pre = {
    hunk: best.hi,
    line: best.h.oldStart,
    start: preRegion.start,
    end: preRegion.end,
    fallback: preRegion.fallback,
    kind: preRegion.kind || best.kind,
    hasWitness: preHas
  };
  if (!rec.post) {
    rec.post = {
      hunk: best.hi,
      line: best.h.newStart,
      start: best.postRegion.start,
      end: best.postRegion.end,
      fallback: best.postRegion.fallback,
      kind: best.kind,
      hasWitness: best.postHas
    };
  }
  rec.mutantSource = stripWitnessLine(rec.postSource, row.witness);
  rec.mutant = {
    source: 'post-minus-witness',
    hasWitness: hasWitness(rec.mutantSource, row.witness),
    changed: rec.mutantSource !== rec.postSource
  };
  if (preHas) {
    rec.status = 'pre-already';
    rec.reason = 'witness-present-in-pre';
  } else if (!rec.post.hasWitness) {
    rec.status = 'post-absent';
    rec.reason = 'witness-not-found-in-post-region';
  } else if (rec.mutantSource === rec.postSource) {
    rec.status = 'mutant-unchanged';
    rec.reason = 'witness-line-could-not-be-removed';
  } else {
    rec.status = 'validated';
    rec.reason = 'pre-absent-post-present';
  }
  return rec;
}

function selectHistorySamples({ family, cls, limit = 20, prefer = [], productOnly = true }) {
  const rows = loadHistoryRows({ family, cls, productOnly });
  const selected = [];
  const byId = new Map(rows.map((r) => [r.id, r]));
  for (const id of prefer) {
    if (byId.has(id) && !selected.some((x) => x.id === id)) selected.push(byId.get(id));
  }
  const rest = rows.filter((r) => !selected.some((x) => x.id === r.id))
    .sort((a, b) => String(a.repo).localeCompare(String(b.repo)) || String(a.id).localeCompare(String(b.id)));
  // 跨 repo 轮转，避免全落在一个部件
  const byRepo = new Map();
  for (const r of rest) {
    if (!byRepo.has(r.repo)) byRepo.set(r.repo, []);
    byRepo.get(r.repo).push(r);
  }
  let i = 0;
  while (selected.length < limit) {
    let added = false;
    for (const list of byRepo.values()) {
      if (i < list.length) {
        selected.push(list[i]);
        added = true;
        if (selected.length >= limit) break;
      }
    }
    if (!added) break;
    i += 1;
  }
  return selected;
}

/** 对一批历史记录逐个提取；返回提取结果和统计。 */
function extractHistoryFixtures(rows, opts = {}) {
  const samples = rows.map((r) => extractHistorySample(r, opts));
  const byStatus = samples.reduce((a, s) => { a[s.status] = (a[s.status] || 0) + 1; return a; }, {});
  return {
    samples,
    summary: {
      requested: rows.length,
      validated: samples.filter((s) => s.status === 'validated').length,
      byStatus: byStatus,
      unavailable: samples.filter((s) => s.status !== 'validated').map((s) => ({ id: s.id, status: s.status, reason: s.reason }))
    }
  };
}

module.exports = {
  HISTORY_FILE, TEST_PATH_RE, isProductPath, loadHistoryRows, extractHistorySample,
  selectHistorySamples, extractHistoryFixtures, stripWitnessLine, hasWitness
};
