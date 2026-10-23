'use strict';
/* 临时探针：clang -dM -E（宏表）与 -ast-dump-filter（定向 AST）成本。用完删除。
 * 注意：bash -c 内联命令在本环境会把 $ 吃掉，必须落 .sh 文件执行。 */
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { buildArgs } = require('../../lib/facts/cmdline');

const SRC = path.resolve(__dirname, '..', '..', '..', 'OpenHarmony');
const TMP = path.join(__dirname, 'misc2');
const toWsl = (p) => {
  const abs = path.resolve(p);
  const m = /^([A-Za-z]):\\(.*)$/.exec(abs);
  return m ? `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, '/')}` : abs.replace(/\\/g, '/');
};
const TMP_WSL = toWsl(TMP);
const SRC_WSL = toWsl(SRC);
const WSL_CWD = `${SRC_WSL}/out/rk3568`;
const CLANG = `${SRC_WSL}/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang++`;

const files = {
  ipc: `${SRC_WSL}/foundation/communication/ipc/ipc/native/src/core/framework/shm_invoker.cpp`,
  eventhandler: `${SRC_WSL}/base/notification/eventhandler/frameworks/eventhandler/src/event_handler.cpp`,
  dsoftbus: `${SRC_WSL}/foundation/communication/dsoftbus/core/bus_center/lnn/lane_hub/lane_manager/src/lnn_lane_link_p2p.c`,
};
const PARTS = ['account', 'communication', 'notification', 'accesscontrol'];

function findCommand(absFile) {
  for (const part of PARTS) {
    const file = path.join(SRC, 'out', 'rk3568', 'compdb_parts', part, 'compile_commands.json');
    const text = fs.readFileSync(file, 'utf8');
    const at = text.indexOf(`"file": "${absFile}"`);
    if (at < 0) continue;
    const s = text.lastIndexOf('{"directory"', at);
    const e = text.indexOf('"}', text.indexOf('"_strategy"', at));
    return JSON.parse(text.slice(s, e + 2)).command;
  }
  return null;
}

function main() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });
  const jobs = [];
  for (const [label, abs] of Object.entries(files)) {
    const command = findCommand(abs);
    if (!command) { jobs.push({ label, missing: true }); continue; }
    const { args } = buildArgs(command);
    const variants = {
      syntax: [...args, '-fsyntax-only'],
      dm: [...args, '-dM', '-E'],
      astFiltered: [...args, '-fsyntax-only', '-Xclang', '-ast-dump=json', '-Xclang', '-ast-dump-filter=Handle']
    };
    for (const [vk, vargs] of Object.entries(variants)) {
      const name = `${label}-${vk}`;
      fs.writeFileSync(path.join(TMP, `${name}.bin`), Buffer.from(vargs.join('\0') + '\0', 'utf8'));
      jobs.push({ label, name, args: vargs.length });
    }
  }
  const sh = ['#!/bin/bash', `cd ${WSL_CWD}`, `echo -n > ${TMP_WSL}/status.txt`];
  for (const j of jobs) {
    if (!j.name) continue;
    sh.push(`( s=$(date +%s%N); mapfile -d '' -t A < ${TMP_WSL}/${j.name}.bin; ${CLANG} "\${A[@]}" > ${TMP_WSL}/${j.name}.out 2> ${TMP_WSL}/${j.name}.err; c=$?; e=$(date +%s%N); echo "${j.name} $c $(( (e-s)/1000000 ))" >> ${TMP_WSL}/status.txt ) &`);
  }
  sh.push('wait');
  fs.writeFileSync(path.join(TMP, 'run.sh'), sh.join('\n') + '\n');
  const r = cp.spawnSync('wsl.exe', ['-d', 'Ubuntu-22.04', '--', 'bash', `${TMP_WSL}/run.sh`], { encoding: 'utf8', timeout: 1800000 });
  const st = new Map(fs.readFileSync(path.join(TMP, 'status.txt'), 'utf8').trim().split(/\r?\n/).map((l) => l.split(' ')));
  const out = {};
  for (const j of jobs) {
    if (!j.name) { out[j.label] = { missing: true }; continue; }
    const rec = st.get(j.name) || ['', '', ''];
    const outFile = path.join(TMP, `${j.name}.out`);
    const errFile = path.join(TMP, `${j.name}.err`);
    const outText = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : '';
    const errText = fs.existsSync(errFile) ? fs.readFileSync(errFile, 'utf8').replace(/\u001b\[[0-9;]*m/g, '') : '';
    out[j.name] = {
      exit: Number(rec[1]),
      ms: Number(rec[2]),
      outBytes: fs.existsSync(outFile) ? fs.statSync(outFile).size : 0,
      macros: outText.split(/\n/).filter((l) => l.startsWith('#define')).length,
      outHead: outText.slice(0, 120).replace(/\n/g, ' | '),
      errHead: errText.split(/\r?\n/).filter(Boolean).slice(0, 2)
    };
  }
  console.log(JSON.stringify({ wslExit: r.status, jobs: out }, null, 2));
}

main();
