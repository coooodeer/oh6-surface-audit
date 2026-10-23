'use strict';

/**
 * facts-p2.js —— P2 数据适配：async-captures → 生命周期窗口事实。
 *
 * 只做静态事实：
 *   - 捕获类型（raw-pointer / this / reference / value / smart）；
 *   - 异步体是否自己 delete/free 捕获变量（所有权转移）；
 *   - 函数内是否有 free/delete/close、join/wait、锁、shared_ptr/sptr；
 *   - `lifecycleEvidence: 'syntactic'` 固定留痕。
 *
 * 纪律：存在 async capture 本身不是 UAF；必须给出 lifetime anchor 或所有权证据。
 */

const path = require('path');
const fs = require('fs');
const {
  D4_ROOTS, isD4, readSource, sourceRelPath, linesOf, enclosingFunction,
  stripLine, isCommentLine, mentions, mentionsAny, hasLifecycleOp, hasLifetimeAnchor,
  provenanceOf, sha256, readJsonlSafe, TOOL_ROOT, SOURCE_ROOT
} = require('./common');
const { entryForRoot, loadEntriesByRoot } = require('./facts-p1');

const WINDOW = 80;
const LIFECYCLE_KIND = {
  'ownership-transfer': 'captured-object-freed-inside-async-body',
  'refcount-hold': 'smart-pointer-or-refcount-capture',
  'blocking-wait': 'join-or-wait-covers-async-body',
  'value-capture': 'non-pointer-capture',
  'dangling-reference': 'reference-capture-dangles-after-frame-exit',
  'free-without-anchor': 'free-delete-in-window-without-lifetime-anchor',
  'anchor-inconclusive': 'lock-anchor-does-not-prove-captured-object-lifetime',
  'no-lifecycle-evidence': 'capture-without-lifetime-evidence'
};

function captureList(rec) {
  const out = new Set((rec.captured || []).filter(Boolean));
  const arg = String(rec.firstArg || rec.text || '');
  const m = /\[([^\]]*)\]/.exec(arg);
  if (m) {
    for (const part of m[1].split(',')) {
      const p = part.trim();
      if (!p) continue;
      if (p.startsWith('&')) out.add(p.slice(1).trim());
      else if (p.includes('=')) out.add(p.split('=')[0].trim());
      else out.add(p);
    }
  }
  if (/\bthis\b/.test(arg)) out.add('this');
  return [...out].filter((x) => x && x !== '=');
}

const TYPE_CACHE = new Map();
const HEADER_EXT = new Set(['.h', '.hpp', '.hh']);

function walkHeaders(dir, out, depth = 0) {
  if (depth > 8 || out.length > 30000) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const ent of entries) {
    if (out.length > 30000) break;
    if (ent.name === '.git' || ent.name === 'out' || ent.name === 'node_modules'
      || ent.name === 'test' || ent.name === 'tests' || ent.name === 'unittest'
      || ent.name === 'fuzztest') continue;
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) walkHeaders(p, out, depth + 1);
    else if (HEADER_EXT.has(path.extname(ent.name))) out.push(p);
  }
}

/**
 * 从同仓头文件里找捕获变量的声明类型。
 * 这是事实层修正：lambda 捕获 `parcel.callback` 时，类型声明通常在另一文件；
 * 只看 lambda 所在函数体必然把它误判成 raw-pointer。
 */
function inferCaptureType(root, vars, sourceFile = '') {
  if (!root || !vars.length) return null;
  const key = `${root}\u0000${vars.join(',')}\u0000${path.dirname(sourceFile)}`;
  if (TYPE_CACHE.has(key)) return TYPE_CACHE.get(key);
  const headers = [];
  walkHeaders(path.join(SOURCE_ROOT, root), headers);
  const srcDir = path.dirname(String(sourceFile || '')).split(/[\\/]/).filter(Boolean);
  const depthScore = (rel) => {
    const parts = String(rel).split(/[\\/]/).filter(Boolean);
    let n = 0;
    while (n < srcDir.length && n < parts.length && srcDir[n] === parts[n]) n += 1;
    return n;
  };
  const candidates = [];
  for (const v of vars) {
    const esc = v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const smartRe = new RegExp(`\\b(?:std::)?(?:sptr|shared_ptr|weak_ptr|unique_ptr)\\s*<[^;\\n]+>\\s+${esc}\\b`);
    for (const file of headers) {
      let text;
      try { text = fs.readFileSync(file, 'utf8'); } catch (_) { continue; }
      const m = text.match(smartRe);
      if (m) {
        const rel = path.relative(path.join(SOURCE_ROOT, root), file);
        candidates.push({ kind: 'smart', var: v, declaration: m[0].trim(), file: rel, score: depthScore(rel) });
      }
    }
  }
  if (candidates.length) {
    candidates.sort((a, b) => b.score - a.score);
    const found = candidates[0];
    TYPE_CACHE.set(key, found);
    return found;
  }
  for (const v of vars) {
    const esc = v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const fnPtrRe = new RegExp(`\\(\\s*\\*\\s*${esc}\\s*\\)`);
    for (const file of headers) {
      let text;
      try { text = fs.readFileSync(file, 'utf8'); } catch (_) { continue; }
      const m = text.match(fnPtrRe);
      if (m) {
        const found = {
          kind: 'function-pointer',
          var: v,
          declaration: m[0].trim(),
          file: path.relative(path.join(SOURCE_ROOT, root), file)
        };
        TYPE_CACHE.set(key, found);
        return found;
      }
    }
  }
  TYPE_CACHE.set(key, null);
  return null;
}

function captureKind(rec, vars, bodyText, typeHint = null) {
  const arg = String(rec.firstArg || rec.text || '');
  if (/\bthis\b/.test(arg)) return 'this';
  if (/\[[^\]]*&/.test(arg)) return 'reference';
  if (typeHint && typeHint.kind === 'smart') return 'smart';
  if (typeHint && typeHint.kind === 'function-pointer') return 'function-pointer';
  const allValue = vars.length > 0 && vars.every((v) => {
    const re = new RegExp(`\\b(?:int|int32_t|uint32_t|uint64_t|int64_t|bool|size_t|long)\\s+${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
    return re.test(bodyText);
  });
  if (allValue) return 'value';
  if (vars.some((v) => new RegExp(`\\b(?:std::)?(?:shared_ptr|weak_ptr|sptr|unique_ptr)<[^>]*>\\s*${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(bodyText))) return 'smart';
  return 'raw-pointer';
}

function lambdaBody(lines, captureIdx) {
  const start = captureIdx;
  let end = Math.min(lines.length - 1, captureIdx + 24);
  for (let i = captureIdx; i <= end; i += 1) {
    const s = stripLine(lines[i]);
    if (/\}\s*\)\s*(?:\.detach\(\))?\s*;/.test(s) || /\}\s*\)\s*;/.test(s)) { end = i; break; }
  }
  return { startLine: start + 1, endLine: end + 1, text: lines.slice(start, end + 1).join('\n') };
}

function analyzeCapture({ root, file, rec, fn, lines, entry }) {
  if (!fn || !lines.length) return null;
  const body = lines.slice(fn.startLine - 1, fn.endLine);
  const idx = rec.line - fn.startLine;
  if (idx < 0 || idx >= body.length) return null;
  const vars = captureList(rec);
  if (!vars.length) return null;
  const typeHint = inferCaptureType(root, vars, file);
  const kind = captureKind(rec, vars, body.join('\n'), typeHint);
  if (kind === 'value') {
    // 纯值捕获不构成生命周期面；仍保留为候选，但 T4 而不是 T2。
  }
  const lam = lambdaBody(body, idx);
  const windowText = body.slice(idx, Math.min(body.length, idx + WINDOW)).join('\n');
  const afterText = body.slice(idx).join('\n');
  const freeInsideLambda = /\bdelete\s+[A-Za-z_]|\bdelete\s*\[|\bfree\s*\(/.test(lam.text);
  const freeOps = [];
  for (let i = idx; i < Math.min(body.length, idx + WINDOW); i += 1) {
    const s = stripLine(body[i]);
    if (!hasLifecycleOp(s)) continue;
    if (isCommentLine(body[i])) continue;
    freeOps.push({ line: fn.startLine + i, text: s.trim().slice(0, 200), insideLambda: i <= (lam.endLine - fn.startLine) });
  }
  const hasJoin = /\bjoin\s*\(|\.join\s*\(/.test(afterText);
  const hasWait = /\bwait\s*\(|\.wait\s*\(|condvar/.test(afterText);
  const hasLock = /lock_guard|unique_lock|AutoLock/.test(windowText);
  const selfAssigned = vars.some((v) => new RegExp(`\\b${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*(?:this->)?GetSelf\\s*\\(`).test(body.join('\n'))
    || new RegExp(`(?:shared_ptr|sptr|weak_ptr)<[^>]*>\\s*${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(body.join('\n')));
  const detached = /\.detach\s*\(\)/.test(windowText) || rec.kind === 'std-thread';
  let classification;
  if (freeInsideLambda) classification = 'ownership-transfer';
  else if (kind === 'value') classification = 'value-capture';
  else if (selfAssigned || kind === 'smart') classification = 'refcount-hold';
  else if (hasJoin || hasWait) classification = 'blocking-wait';
  else if (kind === 'reference' && detached) classification = 'dangling-reference';
  else if (freeOps.length && !hasLock && !selfAssigned) classification = 'free-without-anchor';
  else if (hasLock) classification = 'anchor-inconclusive';
  else classification = 'no-lifecycle-evidence';
  const verdictHint = ['ownership-transfer', 'value-capture', 'refcount-hold', 'blocking-wait'].includes(classification)
    ? 'SATISFIED'
    : (['dangling-reference', 'free-without-anchor'].includes(classification) ? 'VIOLATION' : 'UNPROVEN');
  const unitId = `P2U-${sha256(`${root}\u0000${file}\u0000${rec.line}\u0000${vars.join(',')}`).slice(0, 12)}`;
  const record = {
    candidateId: `cd_P2_${sha256(`${root}\u0000${file}\u0000${rec.line}\u0000${vars.join(',')}`).slice(0, 12)}`,
    class: 'P2',
    generator: 'G-P2+async-window',
    unitId,
    originKind: 'target',
    inTarget: true,
    codeState: 'current-head',
    constructed: false,
    componentRoot: root,
    file,
    line: rec.line,
    source: {
      kind: rec.kind,
      api: rec.api,
      text: String(rec.text || '').trim().slice(0, 300),
      captured: vars,
      captureKind: kind,
      captureType: typeHint,
      firstArg: String(rec.firstArg || '').slice(0, 300)
    },
    origin: {
      file,
      line: rec.line,
      kind: rec.kind,
      api: rec.api,
      text: String(rec.text || '').trim().slice(0, 300)
    },
    signal: {
      asyncKind: rec.kind,
      asyncApi: rec.api,
      captured: vars,
      captureKind: kind,
      captureType: typeHint,
      captureLine: rec.line,
      windowLines: WINDOW,
      blockingWaitInWindow: hasJoin || hasWait,
      lifecycleEvidence: 'syntactic'
    },
    sink: freeOps[0] || null,
    lifetime: {
      captureKind: kind,
      captureType: typeHint,
      captured: vars,
      ownershipTransfer: freeInsideLambda,
      freeInsideLambda,
      freeOps: freeOps.slice(0, 6),
      refcountHold: selfAssigned || kind === 'smart',
      blockingWait: hasJoin || hasWait,
      lockInWindow: hasLock,
      detached,
      classification,
      classificationReason: LIFECYCLE_KIND[classification],
      lifecycleEvidence: 'syntactic',
      window: { radius: WINDOW, function: { name: fn.name, startLine: fn.startLine, endLine: fn.endLine } },
      lambda: { startLine: fn.startLine + lam.startLine - 1, endLine: fn.startLine + lam.endLine - 1 }
    },
    verdictHint,
    analysis: {
      bounded: verdictHint === 'SATISFIED',
      classification,
      freeInsideLambda,
      afterCaptureLines: WINDOW,
      functionVisible: true
    },
    entry: entry || { id: null, kind: null, repo: root, file: null, line: null, bindingScope: 'unknown' },
    evidenceRefs: [`index/async-captures.jsonl#${file}:${rec.line}`, `OpenHarmony/${root}/${file}#L${rec.line}`],
    provenance: null
  };
  record.provenance = provenanceOf(record);
  return record;
}

function existingSeed(candidates) {
  return (candidates || []).find((c) => c && c.patternClass === 'P2') || null;
}

function buildP2Facts(opts = {}) {
  const captures = opts.captures || readJsonlSafe(path.join(TOOL_ROOT, 'index', 'async-captures.jsonl'));
  const seed = existingSeed(opts.candidates);
  const { functionsIndex, d4RootsForFile } = require('./common');
  functionsIndex();
  const units = [];
  const seen = new Set();
  for (const rec of captures) {
    if (!rec || !rec.file) continue;
    const roots = d4RootsForFile(rec.file).filter(isD4);
    if (!roots.length) continue;
    const hasCaptures = (rec.captured && rec.captured.length)
      || /\bthis\b/.test(String(rec.firstArg || ''))
      || /\[[^\]]*&/.test(String(rec.firstArg || rec.text || ''))
      || /\[[^\]]+\]/.test(String(rec.firstArg || rec.text || ''));
    if (!hasCaptures) continue;
    const text = readSource(sourceRelPath(roots[0], rec.file));
    if (text == null) continue;
    const lines = linesOf(text);
    for (const root of roots) {
      const fn = enclosingFunction(root, rec.file, rec.line);
      if (!fn) continue;
      const key = `${root}\u0000${rec.file}\u0000${rec.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const unit = analyzeCapture({ root, file: rec.file, rec, fn, lines, entry: entryForRoot(root) });
      if (unit) units.push(unit);
    }
  }
  // seed 保留原 candidateId。
  if (seed) {
    const root = seed.componentRoot;
    const fullFile = sourceRelPath(root, seed.origin.file);
    const file = fullFile.startsWith(`${root}/`) ? fullFile.slice(root.length + 1) : fullFile;
    const fn = enclosingFunction(root, file, seed.origin.line);
    const text = readSource(fullFile);
    if (fn && text != null) {
      const rec = {
        line: seed.origin.line,
        kind: seed.origin.kind,
        api: seed.origin.api,
        text: seed.origin.text,
        captured: (seed.signal && seed.signal.captured) || [],
        firstArg: (seed.signal && seed.signal.firstArg) || ''
      };
      const unit = analyzeCapture({
        root, file, rec, fn, lines: linesOf(text),
        entry: {
          id: seed.entryId, kind: 'napi', repo: root, file, line: seed.origin.line,
          bindingScope: seed.signal && seed.signal.entryBinding === 'module-inherited-entry' ? 'module-inherited' : 'path-scoped'
        }
      });
      if (unit) {
        unit.candidateId = seed.candidateId;
        unit.generator = 'G-P2';
        unit.isSeed = true;
        unit.originCandidate = { candidateId: seed.candidateId, entryId: seed.entryId, signal: seed.signal };
        const idx = units.findIndex((u) => u.componentRoot === root && u.file === file && u.line === seed.origin.line);
        if (idx >= 0) units[idx] = unit;
        else units.unshift(unit);
      }
    }
  }
  units.sort((a, b) => (b.isSeed ? 1 : 0) - (a.isSeed ? 1 : 0)
    || a.componentRoot.localeCompare(b.componentRoot) || a.file.localeCompare(b.file) || a.line - b.line);
  const byRoot = units.reduce((a, u) => { a[u.componentRoot] = (a[u.componentRoot] || 0) + 1; return a; }, {});
  const byClass = units.reduce((a, u) => { const k = u.lifetime.classification; a[k] = (a[k] || 0) + 1; return a; }, {});
  const tiers = units.reduce((a, u) => { a[u.verdictHint] = (a[u.verdictHint] || 0) + 1; return a; }, {});
  return {
    units,
    summary: {
      class: 'P2',
      windowLines: WINDOW,
      realD4Candidates: units.length,
      seedPresent: Boolean(seed),
      byRoot,
      byClassification: byClass,
      verdictHints: tiers,
      candidateRecallGap: units.length < 8,
      recallNote: units.length < 8 ? 'real D4 P2 units < 8; fixtures fill the calibration set' : null,
      lifecycleEvidence: 'syntactic'
    }
  };
}

module.exports = { WINDOW, LIFECYCLE_KIND, captureList, captureKind, analyzeCapture, buildP2Facts };
