'use strict';

const fs = require('node:fs');
const { RunStore } = require('../../lib/autonomy/store');
const original = RunStore.prototype.appendEvent;
RunStore.prototype.appendEvent = function appendEventAndStop(event) {
  const written = original.call(this, event);
  if (event.kind === 'tool-intent') {
    fs.writeSync(1, JSON.stringify({ runId: this.runId, dir: this.dir }) + '\n');
    process.exit(71);
  }
  return written;
};

const v2 = process.argv.includes('--experiment=vertical-v2');
require('../../bin/autonomy').main(['run', `--experiment=${v2 ? 'vertical-v2' : 'vertical-v1'}`, '--mode=off',
  '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
  `--task=${v2 ? 'TASK:ce534608cd00a85c' : 'TASK:108bcc806d3fc6f0'}`]).then((code) => { process.exitCode = code; });
