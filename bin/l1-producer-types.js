'use strict';

/**
 * l1-producer-types.js —— 从函数声明抽返回类型，给 P3 producer 可空性用。
 * 输出 out/l1/producers.jsonl
 */

const fs = require('fs');
const path = require('path');
const { SOURCE_ROOT, OUT_ROOT, readJsonl, writeJsonl, ensureDir } = require('../lib/util.js');

const L1 = path.join(OUT_ROOT, 'l1', 'functions.jsonl');
const OUT = path.join(OUT_ROOT, 'l1', 'producers.jsonl');

function main() {
  ensureDir(path.dirname(OUT));
  const fns = readJsonl(L1);
  const byFile = new Map();
  for (const f of fns) {
    const k = `${f.repo}\u0000${f.file}`;
    if (!byFile.has(k)) byFile.set(k, []);
    byFile.get(k).push(f);
  }
  const rows = [];
  const fileLines = new Map();
  for (const f of fns) {
    const k = `${f.repo}\u0000${f.file}`;
    let lines = fileLines.get(k);
    if (!lines) {
      try { lines = fs.readFileSync(path.join(SOURCE_ROOT, f.repo, f.file), 'utf8').split(/\r?\n/); } catch (_) { lines = null; }
      fileLines.set(k, lines);
    }
    if (!lines) continue;
    const a = Math.max(0, f.startLine - 5);
    const headLines = lines.slice(a, Math.min(lines.length, f.startLine + 3));
    const esc = f.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const lineRe = new RegExp(`^([A-Za-z_][\\w:<>,\\s]*?(?:\\s*[*&])?)\\s*(?:[A-Za-z_]\\w*::)*${esc}\\s*\\(`);
    let ret = null;
    for (const line of headLines) {
      const m = lineRe.exec(line.trim());
      if (m) { ret = m[1].replace(/\s+/g, ' ').trim(); break; }
    }
    if (!ret) {
      const head = headLines.join(' ');
      const re = new RegExp(`([A-Za-z_][\\w:<>,\\s]*?(?:\\s*[*&])?)\\s*(?:[A-Za-z_]\\w*::)*${esc}\\s*\\(`);
      const m = re.exec(head);
      ret = m ? m[1].replace(/\s+/g, ' ').trim() : null;
    }
    // 去掉 leading 控制关键字/修饰符
    if (ret) ret = ret.replace(/^(?:inline|static|virtual|explicit|constexpr|friend)\s+/, '').trim();
    const pointerLike = !!ret && /\*|shared_ptr|weak_ptr|unique_ptr|sptr|optional/.test(ret);
    rows.push({
      functionId: `${f.repo}|${f.file}:${f.startLine}`,
      repo: f.repo,
      file: f.file,
      name: f.name,
      owner: f.owner || null,
      startLine: f.startLine,
      signature: f.signature || null,
      returnType: ret,
      pointerLike,
      typeKnown: !!ret
    });
  }
  writeJsonl(OUT, rows);
  const known = rows.filter((r) => r.typeKnown).length;
  const pointer = rows.filter((r) => r.pointerLike).length;
  process.stdout.write(`producer types: ${rows.length} functions, typeKnown=${known}, pointerLike=${pointer}\n`);
}

main();
