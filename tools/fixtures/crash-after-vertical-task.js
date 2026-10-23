'use strict';

const { RunStore } = require('../../lib/autonomy/store');
const original = RunStore.prototype.writeCheckpoint;
RunStore.prototype.writeCheckpoint = function writeCheckpointAndStop(checkpoint) {
  const result = original.call(this, checkpoint);
  if (checkpoint.tasks.done === 1 && checkpoint.lastTaskId && !checkpoint.stoppedReason) {
    require('node:fs').writeSync(1, `${JSON.stringify({ runId: this.runId, dir: this.dir })}\n`);
    process.exit(71);
  }
  return result;
};

const replayRun = process.argv.slice(2).find((arg) => /^--replay-run=RUN:[0-9a-f]{16}$/.test(arg));
const v2 = process.argv.includes('--experiment=vertical-v2');
require('../../bin/autonomy').main(['run', `--experiment=${v2 ? 'vertical-v2' : 'vertical-v1'}`,
  `--mode=${replayRun ? 'replay' : 'off'}`, ...(replayRun ? [replayRun] : []),
  '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
  `--task=${v2 ? 'TASK:ce534608cd00a85c' : 'TASK:108bcc806d3fc6f0'}`]).then((code) => { process.exitCode = code; });
