'use strict';

/**
 * l1-facts.js —— L1 的 P3/P6 最小事实层（dsoftbus + CES）。
 *
 * 输入：index/functions.jsonl + 源码
 * 输出：out/l1/functions.jsonl
 *   {repo,file,name,owner,signature,startLine,endLine,bodyHash,bodyLines,
 *    bodyTokens[], calls[{name,line}], guards[{expr,line}], publishes[{api,line}]}
 *
 * 这不是完整 AST/CFG；先把 P3/P6 需要的 body token、直接调用、guard、publish 建起来。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TOOL_ROOT, SOURCE_ROOT, readJsonl, writeJsonl, ensureDir } = require('../lib/util.js');

const ROOTS = [
  'foundation/communication/dsoftbus',
  'base/account/os_account'
];
const OUT = path.join(__dirname, '..', 'out', 'l1', 'functions.jsonl');

const STOP = new Set(('the a an of to in for on with and or is are be as by at from this that it its ' +
  'if then else return void const static std auto int bool char size t uint32 uint64 int32 int64 ' +
  'shared ptr unique mutex lock guard nullptr true false new delete public private protected ' +
  'switch case break continue while do sizeof').split(/\s+/));

function sha(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex'); }
function tokenize(s) {
  return String(s || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9_]+/)
    .flatMap((t) => t.split('_'))
    .filter((t) => t.length >= 3 && !STOP.has(t));
}

function extractCalls(text) {
  const re = /\b([A-Za-z_]\w*)\s*\(/g;
  const out = [];
  const seen = new Set();
  let m;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    if (['if', 'for', 'while', 'switch', 'sizeof', 'return', 'catch'].includes(name)) continue;
    const line = text.slice(0, m.index).split('\n').length;
    const key = `${name}:${line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name, line });
    if (out.length >= 120) break;
  }
  return out;
}

function extractGuards(text) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const t = lines[i].trim();
    const m = /^(?:else\s+)?if\s*\((.*)\)/.exec(t);
    if (!m) continue;
    out.push({ expr: m[1].trim().slice(0, 300), line: i + 1 });
    if (out.length >= 80) break;
  }
  return out;
}

function main() {
  ensureDir(path.dirname(OUT));
  const fns = readJsonl(path.join(TOOL_ROOT, 'index', 'functions.jsonl')).filter((f) => ROOTS.includes(f.root));
  const byFile = new Map();
  for (const f of fns) {
    const key = `${f.root}\u0000${f.file}`;
    if (!byFile.has(key)) byFile.set(key, []);
    byFile.get(key).push(f);
  }
  const rows = [];
  let filesRead = 0;
  let filesMissing = 0;
  for (const [key, list] of byFile) {
    const [root, file] = key.split('\u0000');
    const abs = path.join(SOURCE_ROOT, root, file);
    let lines;
    try {
      lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
      filesRead += 1;
    } catch (_) {
      filesMissing += 1;
      continue;
    }
    for (const f of list) {
      const a = Math.max(0, f.startLine - 1);
      const b = Math.min(lines.length, f.endLine);
      const body = lines.slice(a, b).join('\n');
      const tokens = [...new Set(tokenize(body))].slice(0, 240);
      const calls = extractCalls(body);
      const guards = extractGuards(body);
      const publishes = calls.filter((c) => /^Publish\w*Event$/i.test(c.name) || /PublishCommonEvent/i.test(c.name));
      rows.push({
        repo: root,
        file,
        name: f.name,
        owner: f.owner || null,
        signature: (f.signature && f.signature.text) || null,
        startLine: f.startLine,
        endLine: f.endLine,
        bodyHash: sha(body),
        bodyLines: b - a,
        bodyTokens: tokens,
        calls,
        guards,
        publishes
      });
    }
  }
  writeJsonl(OUT, rows);
  const byRepo = {};
  for (const r of rows) byRepo[r.repo] = (byRepo[r.repo] || 0) + 1;
  process.stdout.write(`l1 facts: ${rows.length} functions, filesRead=${filesRead}, missing=${filesMissing}, byRepo=${JSON.stringify(byRepo)}\n`);
}

main();
