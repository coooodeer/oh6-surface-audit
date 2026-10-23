'use strict';
/* 对比 weggli 函数枚举与 tree-sitter function_definition 计数（同一批文件）。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const WORKSPACE = path.resolve(__dirname, '..', '..', '..');
const SRC = path.join(WORKSPACE, 'OpenHarmony');
const MOD = path.join(WORKSPACE, 'oh6-framework-want-leak-miner', 'node_modules');
const Parser = require(path.join(MOD, 'tree-sitter'));
const Cpp = require(path.join(MOD, 'tree-sitter-cpp'));
const C = require(path.join(MOD, 'tree-sitter-c'));

const toWsl = (p) => {
  const abs = path.resolve(p);
  const m = /^([A-Za-z]):\\(.*)$/.exec(abs);
  return m ? `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}` : abs.replace(/\\/g, '/');
};

const FILES = [
  'base/notification/eventhandler/frameworks/eventhandler/src/event_handler.cpp',
  'base/accesscontrol/sandbox_manager/frameworks/inner_api/sandbox_manager/src/sandbox_manager_kit.cpp',
  'base/account/os_account/frameworks/osaccount/core/src/os_account.cpp',
  'base/account/os_account/frameworks/appaccount/native/src/app_account.cpp',
  'foundation/communication/dsoftbus/core/bus_center/lnn/lane_hub/lane_manager/src/lnn_lane.c'
];

const W = '/mnt/d/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit/tools/weggli-eval/weggli/target/release/weggli';
const SRC_WSL = toWsl(SRC);

const parser = new Parser();
const rows = [];
for (const rel of FILES) {
  const text = fs.readFileSync(path.join(SRC, rel.split('/').join(path.sep)), 'utf8');
  parser.setLanguage(rel.endsWith('.c') ? C : Cpp);
  const tree = parser.parse(text, null, { bufferSize: 1024 * 1024 });
  let n = 0;
  const stack = [tree.rootNode];
  while (stack.length) {
    const x = stack.pop();
    if (x.type === 'function_definition') n += 1;
    for (let i = 0; i < x.namedChildCount; i += 1) stack.push(x.namedChild(i));
  }
  rows.push({ rel, ts: n, hasError: tree.rootNode.hasError });
}

const sh = ['#!/bin/bash', `W=${W}`, `SRC=${SRC_WSL}`];
for (const r of rows) {
  const isC = r.rel.endsWith('.c');
  const modeFlag = isC ? '' : '-X';
  const extFlags = isC ? '-e c' : '-e cpp -e h -e hpp';
  sh.push(`n=$("$W" ${modeFlag} '_ $fn(_) {_;}' "$SRC/${r.rel}" ${extFlags} 2>/dev/null | grep -cE '^/mnt/'); echo "${r.rel}|$n"`);
}
const scriptPath = path.join(__dirname, 'run6.sh');
fs.writeFileSync(scriptPath, sh.join('\n') + '\n');
const out = cp.spawnSync('wsl.exe', ['-d', 'Ubuntu-22.04', '--', 'bash', toWsl(scriptPath)], { encoding: 'utf8' }).stdout || '';
const weggli = new Map(out.trim().split(/\r?\n/).filter(Boolean).map((l) => { const i = l.lastIndexOf('|'); return [l.slice(0, i), Number(l.slice(i + 1))]; }));
for (const r of rows) {
  console.log(JSON.stringify({ file: r.rel.split('/').pop(), ts: r.ts, weggli: weggli.get(r.rel), hasError: r.hasError }));
}
