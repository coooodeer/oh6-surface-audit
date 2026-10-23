'use strict';

const path = require('path');
const { writeJson, writeJsonl, readJsonl, git, ensureDir } = require('./util');

function norm(s) {
  return String(s || '').replace(/\s+/g, ' ').trim();
}

function matchBrace(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i += 1) {
    const c = text[i];
    if (c === '"' || c === "'") {
      const q = c;
      i += 1;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === q) break;
        i += 1;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1;
      i += 1;
      continue;
    }
    if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

const CONTROL = /^(if|for|while|switch|catch|else|do|try|namespace)\b/;

/**
 * 取包含 line（1-based）的函数体；失败则 hunk ±30 行。
 * 返回 { start, end, text, fallback }
 */
function regionAround(text, line, radius = 30) {  if (!text) return null;
  const lines = text.split(/\r?\n/);
  const idx = Math.max(1, Math.min(lines.length, line)) - 1;
  let start = -1;
  for (let i = idx; i >= Math.max(0, idx - 200); i -= 1) {
    const t = lines[i].trim();
    if (!t || t.startsWith('//') || t.startsWith('*')) continue;
    if (CONTROL.test(t)) continue;
    if (!t.includes('(')) continue;
    if (t.endsWith(';')) continue;
    const next = (lines[i + 1] || '').trim();
    if (!t.includes('{') && !next.startsWith('{')) continue;
    start = i;
    break;
  }
  if (start < 0) {
    const a = Math.max(0, idx - radius);
    const b = Math.min(lines.length - 1, idx + radius);
    return { start: a + 1, end: b + 1, text: lines.slice(a, b + 1).join('\n'), fallback: true };
  }
  let open = -1;
  for (let i = start; i < Math.min(lines.length, start + 6); i += 1) {
    const p = lines[i].indexOf('{');
    if (p >= 0) { open = { line: i, col: p }; break; }
  }
  if (!open) {
    const a = Math.max(0, idx - radius);
    const b = Math.min(lines.length - 1, idx + radius);
    return { start: a + 1, end: b + 1, text: lines.slice(a, b + 1).join('\n'), fallback: true };
  }
  const prefix = lines.slice(0, open.line).join('\n').length + (open.line ? 1 : 0);
  const close = matchBrace(text, prefix + open.col);
  if (close < 0) {
    const a = Math.max(0, idx - radius);
    const b = Math.min(lines.length - 1, idx + radius);
    return { start: a + 1, end: b + 1, text: lines.slice(a, b + 1).join('\n'), fallback: true };
  }
  const endLine = text.slice(0, close).split('\n').length;
  if (endLine - start < 2) {
    const a = Math.max(0, idx - radius);
    const b = Math.min(lines.length - 1, idx + radius);
    return { start: a + 1, end: b + 1, text: lines.slice(a, b + 1).join('\n'), fallback: true };
  }
  return { start: start + 1, end: endLine, text: lines.slice(start, endLine).join('\n'), fallback: false };
}

/** hunk 局部窗口：函数边界抽取失败时的兜底，半径默认 80 行 */
function windowAround(text, line, radius = 80) {
  if (!text) return null;
  const lines = text.split(/\r?\n/);
  const idx = Math.max(1, Math.min(lines.length, line)) - 1;
  const a = Math.max(0, idx - radius);
  const b = Math.min(lines.length - 1, idx + radius);
  return { start: a + 1, end: b + 1, text: lines.slice(a, b + 1).join('\n'), fallback: true, kind: 'hunk-window' };
}

function parseHunks(diff) {
  const out = [];
  for (const line of String(diff || '').split(/\r?\n/)) {
    const m = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/.exec(line);
    if (!m) continue;
    out.push({
      oldStart: Number(m[1]),
      oldCount: Number(m[2] || 1),
      newStart: Number(m[3]),
      newCount: Number(m[4] || 1)
    });
  }
  return out;
}

function selectSeeds(rows, n = 20) {
  const withWitness = rows.filter((r) => r && r.witness && r.repo && r.sha && r.file);
  const product = withWitness.filter((r) => !/\/(test|tests|unittest|fuzztest)\//.test(r.file));
  const pool = product.length >= n ? product : withWitness;
  const byRepo = new Map();
  for (const r of pool) {
    if (!byRepo.has(r.repo)) byRepo.set(r.repo, []);
    byRepo.get(r.repo).push(r);
  }
  for (const list of byRepo.values()) list.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const repos = [...byRepo.keys()].sort();
  const out = [];
  let i = 0;
  while (out.length < n && i < 10000) {
    let added = false;
    for (const repo of repos) {
      const list = byRepo.get(repo);
      if (i < list.length) {
        out.push(list[i]);
        added = true;
        if (out.length >= n) break;
      }
    }
    if (!added) break;
    i += 1;
  }
  return out;
}

function runSpecDiff({ toolRoot, outRoot, n = 20 }) {
  const rows = readJsonl(path.join(toolRoot, 'data', 'facts', 'history-invariants.jsonl'));
  const seeds = selectSeeds(rows, n);
  const results = [];
  const promptsDir = path.join(outRoot, 'specdiff', 'prompts');
  ensureDir(promptsDir);

  for (const s of seeds) {
    const diff = git(s.repo, ['diff', '--unified=0', `${s.sha}^`, s.sha, '--', s.file]);
    const preText = git(s.repo, ['show', `${s.sha}^:${s.file}`]);
    const postText = git(s.repo, ['show', `${s.sha}:${s.file}`]);
    const rec = {
      id: s.id,
      repo: s.repo,
      sha: s.sha,
      date: s.date,
      file: s.file,
      family: s.family,
      entity: s.entity,
      witness: s.witness,
      recordedDifferentialOk: s.differentialOk === true,
      status: null,
      reason: null,
      hunks: parseHunks(diff),
      pre: null,
      post: null,
      witnessNormalized: norm(s.witness)
    };

    if (preText === null) {
      rec.status = 'pre-missing';
      rec.reason = 'parent-version-not-readable';
      results.push(rec);
      continue;
    }
    if (postText === null) {
      rec.status = 'post-missing';
      rec.reason = 'post-version-not-readable';
      results.push(rec);
      continue;
    }
    const w = rec.witnessNormalized;
    const candidates = [];
    for (let hi = 0; hi < rec.hunks.length; hi += 1) {
      const h = rec.hunks[hi];
      const preRegion = regionAround(preText, h.oldStart);
      const postRegion = regionAround(postText, h.newStart);
      if (!preRegion || !postRegion) continue;
      const preHas = norm(preRegion.text).includes(w);
      const postHas = norm(postRegion.text).includes(w);
      candidates.push({ hi, h, preRegion, postRegion, preHas, postHas, kind: 'function' });
      if (!(!preHas && postHas)) {
        const preW = windowAround(preText, h.oldStart, 80);
        const postW = windowAround(postText, h.newStart, 80);
        if (preW && postW) {
          const preHasW = norm(preW.text).includes(w);
          const postHasW = norm(postW.text).includes(w);
          if (!preHasW && postHasW) {
            candidates.push({ hi, h, preRegion: preW, postRegion: postW, preHas: preHasW, postHas: postHasW, kind: 'hunk-window' });
          }
        }
      }
    }
    if (!candidates.length) {
      rec.status = 'extract-failed';
      rec.reason = 'no-region';
      results.push(rec);
      continue;
    }
    // 优先选“前无、后有”的 hunk；否则优先 post 有 witness；最后取第一个 hunk
    const best = candidates.find((c) => !c.preHas && c.postHas)
      || candidates.find((c) => c.postHas)
      || candidates.find((c) => c.preHas)
      || candidates[0];
    rec.pre = {
      hunk: best.hi, line: best.h.oldStart, start: best.preRegion.start, end: best.preRegion.end,
      fallback: best.preRegion.fallback, kind: best.kind, hasWitness: best.preHas, chars: best.preRegion.text.length
    };
    rec.post = {
      hunk: best.hi, line: best.h.newStart, start: best.postRegion.start, end: best.postRegion.end,
      fallback: best.postRegion.fallback, kind: best.kind, hasWitness: best.postHas, chars: best.postRegion.text.length
    };
    rec.hunkCount = rec.hunks.length;

    if (best.preHas) {
      rec.status = 'pre-already';
      rec.reason = 'witness-present-in-pre';
    } else if (!best.postHas) {
      rec.status = 'post-absent';
      rec.reason = 'witness-not-found-in-post-region';
    } else {
      rec.status = 'validated';
      rec.reason = 'pre-absent-post-present';
    }
    results.push(rec);

    // 供 live 模型验证的输入包；本次不调用模型
    writeJson(path.join(promptsDir, `${s.id}.json`), {
      id: s.id,
      task: 'spec-differential-validation',
      instructions: '判定 pre 是否违反规范、post 是否满足规范；只输出 JSON {preViolates, postSatisfies, reason}。',
      spec: { entity: s.entity, constraint: s.constraint, witness: s.witness, family: s.family },
      pre: { repo: s.repo, sha: `${s.sha}^`, file: s.file, line: best.h.oldStart, region: best.preRegion },
      post: { repo: s.repo, sha: s.sha, file: s.file, line: best.h.newStart, region: best.postRegion },
      liveModelRun: false,
      reason: 'OH6_LLM_API_KEY absent'
    });
  }

  const count = (st) => results.filter((r) => r.status === st).length;
  const byRegionKind = {};
  for (const r of results) {
    const k = (r.pre && r.pre.kind) || 'none';
    byRegionKind[k] = (byRegionKind[k] || 0) + 1;
  }
  const strictValidated = results.filter((r) => r.status === 'validated'
    && r.pre && r.pre.kind === 'function' && !r.pre.fallback && !r.post.fallback).length;
  const windowValidated = results.filter((r) => r.status === 'validated'
    && r.pre && r.pre.kind === 'hunk-window').length;
  const functionFallbackValidated = results.filter((r) => r.status === 'validated'
    && r.pre && r.pre.kind === 'function' && (r.pre.fallback || r.post.fallback)).length;
  const byFamily = {};
  for (const r of results) {
    byFamily[r.family] = byFamily[r.family] || { total: 0, validated: 0 };
    byFamily[r.family].total += 1;
    if (r.status === 'validated') byFamily[r.family].validated += 1;
  }
  const summary = {
    generatedAt: new Date().toISOString(),
    selected: results.length,
    validated: count('validated'),
    validityRate: results.length ? Number((count('validated') / results.length).toFixed(4)) : null,
    strictValidated,
    windowValidated,
    functionFallbackValidated,
    byRegionKind,
    preAlready: count('pre-already'),
    postAbsent: count('post-absent'),
    preMissing: count('pre-missing'),
    postMissing: count('post-missing'),
    extractFailed: count('extract-failed'),
    fallbackRegion: results.filter((r) => (r.pre && r.pre.fallback) || (r.post && r.post.fallback)).length,
    recordedDifferentialOk: results.filter((r) => r.recordedDifferentialOk).length,
    modelRun: false,
    modelRunReason: 'OH6_LLM_API_KEY absent; prompts/ contains the exact live inputs',
    byFamily,
    failures: results.filter((r) => r.status !== 'validated').map((r) => ({
      id: r.id, repo: r.repo, file: r.file, family: r.family, status: r.status, reason: r.reason
    }))
  };
  writeJsonl(path.join(outRoot, 'specdiff', 'results.jsonl'), results);
  writeJson(path.join(outRoot, 'specdiff', 'summary.json'), summary);
  return { results, summary };
}

module.exports = { selectSeeds, parseHunks, regionAround, runSpecDiff, norm };
