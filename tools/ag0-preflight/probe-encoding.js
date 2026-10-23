'use strict';
/* 探针：目标树里是否存在非 UTF-8 源文件（Node 的 'utf8' 会静默替换成 U+FFFD）。 */
const fs = require('fs');
const path = require('path');

const SRC = path.resolve(__dirname, '..', '..', '..', 'OpenHarmony');
const ROOTS = ['base/account/os_account', 'foundation/communication/dsoftbus', 'foundation/communication/ipc',
  'base/notification/eventhandler', 'base/accesscontrol/sandbox_manager'];
const SKIP = new Set(['.git', 'node_modules', 'third_party', 'prebuilts', 'out', 'build']);

function walk(d, acc) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) { if (!SKIP.has(e.name)) walk(p, acc); continue; }
    if (e.isFile() && /\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(e.name)) acc.push(p);
  }
}

const files = [];
for (const r of ROOTS) walk(path.join(SRC, r.split('/').join(path.sep)), files);

const dec = new TextDecoder('utf-8', { fatal: true });
let invalid = 0;
const samples = [];
for (const f of files) {
  const buf = fs.readFileSync(f);
  // 跳过 BOM（不存在，但防御）
  try { dec.decode(buf); } catch (_) {
    invalid += 1;
    if (samples.length < 8) samples.push(path.relative(SRC, f).split(path.sep).join('/'));
  }
}
console.log(JSON.stringify({ files: files.length, nonUtf8: invalid, samples }, null, 2));
