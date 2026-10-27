'use strict';

const fs = require('node:fs');
const { RunStore } = require('../../lib/autonomy/store');

// 与 crash-after-vertical-task.js 相同：确定性写“已死 owner”pid=-1，避免 Windows
// 复用崩溃进程 pid 让 resume 误判 writer 仍存活；真实 pid 的存活检查保持不变。
function markDeadOwner(store) {
  const file = store.file('run.lock');
  const lock = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, `${JSON.stringify({ ...lock, pid: -1 })}\n`, { encoding: 'utf8' });
}

const original = RunStore.prototype.appendEvent;
RunStore.prototype.appendEvent = function appendEventAndStop(event) {
  const written = original.call(this, event);
  if (event.kind === 'tool-intent') {
    markDeadOwner(this);
    fs.writeSync(1, JSON.stringify({ runId: this.runId, dir: this.dir }) + '\n');
    process.exit(71);
  }
  return written;
};

const v2 = process.argv.includes('--experiment=vertical-v2');
require('../../bin/autonomy').main(['run', `--experiment=${v2 ? 'vertical-v2' : 'vertical-v1'}`, '--mode=off',
  '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
  `--task=${v2 ? 'TASK:ce534608cd00a85c' : 'TASK:108bcc806d3fc6f0'}`]).then((code) => { process.exitCode = code; });
