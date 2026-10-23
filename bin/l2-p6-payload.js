'use strict';

/**
 * l2-p6-payload.js —— P6 源码级 payload grounding。
 * 从 publish 调用点附近抽 SetData/SetCode/SetParameters/SetAction 的实参，
 * 替代不可靠的 broadcast-actions.params。
 *
 * 输出：out/l2/p6-payload.jsonl、out/l2/p6-payload-summary.json
 */

const fs = require('fs');
const path = require('path');
const { SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, writeJson, ensureDir } = require('../lib/util.js');

const ACTIONS = path.join(OUT_ROOT, 'l2', 'actions.jsonl');
const OUT = path.join(OUT_ROOT, 'l2', 'p6-payload.jsonl');

function stripPrefix(f) { return String(f || '').replace(/^OpenHarmony\//, ''); }

function extractArgs(text, start) {
  // 从 '(' 后开始，取到匹配的 ')'；支持简单嵌套
  let depth = 0;
  let out = '';
  for (let i = start; i < text.length; i += 1) {
    const c = text[i];
    if (c === '(') depth += 1;
    else if (c === ')') {
      if (depth === 0) break;
      depth -= 1;
    }
    if (depth === 0) out += c;
  }
  return out;
}

function splitArgs(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const c of s) {
    if (c === '(' || c === '{' || c === '[') depth += 1;
    if (c === ')' || c === '}' || c === ']') depth -= 1;
    if (c === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function cleanExpr(e) {
  return String(e || '').replace(/\s+/g, ' ').trim();
}

function isUseful(expr) {
  const e = cleanExpr(expr);
  if (!e) return false;
  if (/^["'].*["']$/.test(e)) {
    // 字符串字面量：排除 action 常量
    return !/COMMON_EVENT|usual\.event|EventFwk|notification\.event|^["']-?\d+["']$/.test(e);
  }
  if (/^-?\d+$/.test(e)) return false;
  if (/COMMON_EVENT|usual\.event|EventFwk|CommonEventSupport/.test(e)) return false;
  if (/^(nullptr|NULL|true|false)$/.test(e)) return false;
  return /[A-Za-z_]/.test(e);
}

function main() {
  ensureDir(path.dirname(OUT));
  const actions = readJsonl(ACTIONS);
  const fns = readJsonl(path.join(OUT_ROOT, 'l1', 'functions.jsonl'));
  const fnByFile = new Map();
  for (const f of fns) {
    const k = `${f.repo}\u0000${f.file}`;
    if (!fnByFile.has(k)) fnByFile.set(k, []);
    fnByFile.get(k).push(f);
  }
  for (const list of fnByFile.values()) list.sort((a, b) => a.startLine - b.startLine);
  const cache = new Map();
  const rows = [];
  for (const a of actions) {
    const file = stripPrefix(a.sink && a.sink.file);
    const line = a.sink && a.sink.line;
    const repo = file.split('/').slice(0, 3).join('/');
    const rel = file.startsWith(`${repo}/`) ? file.slice(repo.length + 1) : file;
    let lines = cache.get(`${repo}\u0000${rel}`);
    if (!lines) {
      try { lines = fs.readFileSync(path.join(SOURCE_ROOT, repo, rel), 'utf8').split(/\r?\n/); } catch (_) { lines = null; }
      cache.set(`${repo}\u0000${rel}`, lines);
    }
    const setters = [];
    if (lines && line) {
      const list = fnByFile.get(`${repo}\u0000${rel}`) || [];
      const fn = list.find((f) => f.startLine <= line && f.endLine >= line) || null;
      const a0 = fn ? Math.max(0, fn.startLine - 1) : Math.max(0, line - 60);
      const b0 = fn ? Math.min(lines.length, fn.endLine) : Math.min(lines.length, line + 40);
      const windowLines = lines.slice(a0, b0);
      const windowText = windowLines.join('\n');
      const re = /\.?(SetParam|SetData|SetCode|SetParameters|SetAction|SetWant|PublishCommonEventData|PublishCommonEvent)\s*\(/g;
      let m;
      while ((m = re.exec(windowText)) !== null) {
        const start = m.index + m[0].length;
        const argsText = extractArgs(windowText, start);
        const args = splitArgs(argsText);
        const offsetLine = windowText.slice(0, m.index).split('\n').length - 1;
        setters.push({
          setter: m[1],
          line: a0 + offsetLine + 1,
          args: args.map(cleanExpr).filter(Boolean)
        });
        if (setters.length >= 20) break;
      }
    }
    const payloadCandidates = [];
    for (const s of setters) {
      if (s.setter === 'SetAction' || s.setter === 'PublishCommonEvent' || s.setter === 'PublishCommonEventData') continue;
      if (s.setter === 'SetParam' && s.args.length >= 2) {
        const key = cleanExpr(s.args[0]).replace(/^["']|["']$/g, '');
        const value = cleanExpr(s.args[1]);
        if (isUseful(key) || isUseful(value)) {
          payloadCandidates.push({ setter: s.setter, line: s.line, key, value, expr: key || value });
        }
        continue;
      }
      for (const arg of s.args) {
        if (!isUseful(arg)) continue;
        payloadCandidates.push({ setter: s.setter, line: s.line, key: null, value: cleanExpr(arg), expr: cleanExpr(arg) });
      }
    }
    // 去重
    const seen = new Set();
    const unique = [];
    for (const p of payloadCandidates) {
      const k = `${p.setter}:${p.expr}`;
      if (seen.has(k)) continue;
      seen.add(k);
      unique.push(p);
    }
    rows.push({
      recordId: a.recordId,
      action: a.action,
      sink: a.sink,
      analysisStatus: a.analysisStatus,
      thirdPartyReachability: a.thirdPartyReachability,
      subscriberPermissions: a.subscriberPermissions,
      directedSubscriberUids: a.directedSubscriberUids,
      setters,
      payloadCandidates: unique,
      payloadNames: unique.map((p) => p.expr)
    });
  }
  writeJsonl(OUT, rows);
  const summary = {
    generatedAt: new Date().toISOString(),
    actions: rows.length,
    actionsWithSetters: rows.filter((r) => r.setters.length).length,
    actionsWithPayload: rows.filter((r) => r.payloadCandidates.length).length,
    payloadItems: rows.reduce((a, r) => a + r.payloadCandidates.length, 0),
    setterCounts: rows.flatMap((r) => r.setters).reduce((a, s) => { a[s.setter] = (a[s.setter] || 0) + 1; return a; }, {}),
    sample: rows.filter((r) => r.payloadCandidates.length).slice(0, 5).map((r) => ({ action: r.action, payload: r.payloadNames, setters: r.setters.map((s) => s.setter) }))
  };
  writeJson(path.join(OUT_ROOT, 'l2', 'p6-payload-summary.json'), summary);
  process.stdout.write(`p6 payload: actions=${summary.actions} withSetters=${summary.actionsWithSetters} withPayload=${summary.actionsWithPayload} items=${summary.payloadItems}\n`);
}

main();
