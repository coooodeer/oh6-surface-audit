'use strict';
/* 对同一批 "sink 调用" 事实族，比较 weggli 查询召回与 tree-sitter AST 计数。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const MOD = path.join(WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
const Parser = require(path.join(MOD, 'tree-sitter'));
const Cpp = require(path.join(MOD, 'tree-sitter-cpp'));
const C = require(path.join(MOD, 'tree-sitter-c'));

const ROOTS = ['base/account/os_account', 'foundation/communication/dsoftbus', 'foundation/communication/ipc',
  'base/notification/eventhandler', 'base/accesscontrol/sandbox_manager'];
const SKIP = new Set(['.git', 'node_modules', 'third_party', 'prebuilts', 'out', 'build']);
const CALLEES = ['memcpy', 'malloc', 'snprintf'];

const toWsl = (p) => {
  const abs = path.resolve(p);
  const m = /^([A-Za-z]):\\(.*)$/.exec(abs);
  return m ? `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}` : abs.replace(/\\/g, '/');
};

function walk(dir, acc) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP.has(e.name)) walk(p, acc); continue; }
    if (e.isFile() && /\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(e.name)) acc.push(p);
  }
}

const files = [];
for (const r of ROOTS) walk(path.join(SRC, r.split('/').join(path.sep)), files);

const parser = new Parser();
const counts = Object.fromEntries(CALLEES.map((c) => [c, 0]));
for (const abs of files) {
  const text = fs.readFileSync(abs, 'utf8');
  parser.setLanguage(abs.toLowerCase().endsWith('.c') ? C : Cpp);
  const tree = parser.parse(text, null, { bufferSize: 1024 * 1024 });
  const stack = [tree.rootNode];
  while (stack.length) {
    const n = stack.pop();
    if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      const name = fn ? fn.text.replace(/\s+/g, '') : '';
      for (const c of CALLEES) {
        if (name === c || name.endsWith(`::${c}`) || name.endsWith(`.${c}`) || name.endsWith(`->${c}`)) counts[c] += 1;
      }
    }
    for (let i = 0; i < n.namedChildCount; i += 1) stack.push(n.namedChild(i));
  }
}

const W = '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit/tools/weggli-eval/weggli/target/release/weggli';
const SRC_WSL = toWsl(SRC);
const sh = ['#!/bin/bash', `W=${W}`, `SRC=${SRC_WSL}`];
const rootsWsl = ROOTS.map((r) => `"$SRC/${r}"`).join(' ');
for (const c of CALLEES) {
  const pat = c === 'memcpy' ? 'memcpy(_,_,_)' : (c === 'malloc' ? 'malloc(_)' : 'snprintf(_,_,_)');
  // weggli 只接受单个 PATH，必须逐 root 调用
  sh.push(`tot=0; for r in ${rootsWsl}; do n=$("$W" -X '${pat}' "$r" -e cpp -e cc -e h -e hpp 2>/dev/null | grep -cE '^/mnt/'); tot=$((tot+n)); done; echo "${c}|cpp|$tot"`);
  sh.push(`totc=0; for r in ${rootsWsl}; do m=$("$W" '${pat}' "$r" -e c -e h 2>/dev/null | grep -cE '^/mnt/'); totc=$((totc+m)); done; echo "${c}|c|$totc"`);
}
const sp = path.join(__dirname, 'run7.sh');
fs.writeFileSync(sp, sh.join('\n') + '\n');
const t0 = Date.now();
const out = cp.spawnSync('wsl.exe', ['-d', 'Ubuntu-22.04', '--', 'bash', toWsl(sp)], { encoding: 'utf8', maxBuffer: 1 << 28 }).stdout || '';
const ms = Date.now() - t0;
console.log(JSON.stringify({ treeSitterCounts: counts, weggliRuns: out.trim().split(/\r?\n/), weggliTotalMs: ms }, null, 2));
