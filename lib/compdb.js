'use strict';

const fs = require('fs');
const path = require('path');
const { SOURCE_ROOT, writeJson } = require('./util');

/**
 * 从 compdb 里数“构建可见的源文件”（只读，流式）。
 * 用途：给文件索引率一个独立分母，而不是用扫描器自己的文件清单。
 */
function countCompdbFiles(part, repo, scannedRelSet) {
  const file = path.join(SOURCE_ROOT, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
  if (!fs.existsSync(file)) return { part, file, present: false, total: 0, repoTu: 0, repoFiles: 0, uniqueFiles: 0, productFiles: 0, coveredByScan: null, coverageRate: null };
  const text = fs.readFileSync(file, 'utf8');
  const re = /"file"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  const all = new Set();
  const repoSet = new Set();
  const productSet = new Set();
  const coveredSet = new Set();
  let repoTu = 0;
  let productTu = 0;
  let coveredByScan = 0;
  let m;
  const needle = `/${repo}/`;
  const isProduct = (p) => !/\/(out|test|tests|unittest|fuzztest|third_party)\//.test(p);
  const scanned = scannedRelSet || null;
  while ((m = re.exec(text)) !== null) {
    let p;
    try { p = JSON.parse(`"${m[1]}"`); } catch (_) { continue; }
    p = String(p).replace(/\\/g, '/');
    all.add(p);
    if (p.includes(needle) || p.startsWith(`${repo}/`)) {
      repoTu += 1;
      repoSet.add(p);
      if (isProduct(p)) {
        productTu += 1;
        productSet.add(p);
        if (scanned) {
          const idx = p.indexOf(`${repo}/`);
          const rel = idx >= 0 ? p.slice(idx + repo.length + 1) : p;
          if (!coveredSet.has(p)) {
            coveredSet.add(p);
            if (scanned.has(rel)) coveredByScan += 1;
          }
        }
      }
    }
  }
  return {
    part,
    file: path.relative(SOURCE_ROOT, file).split(path.sep).join('/'),
    present: true,
    total: all.size,
    repoTu,
    repoFiles: repoSet.size,
    productTu,
    productFiles: productSet.size,
    coveredByScan: scanned ? coveredByScan : null,
    coverageRate: scanned && productSet.size ? Number((coveredByScan / productSet.size).toFixed(4)) : null,
    samples: [...productSet].slice(0, 5)
  };
}

module.exports = { countCompdbFiles };
