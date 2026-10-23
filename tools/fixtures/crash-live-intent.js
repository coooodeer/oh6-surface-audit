'use strict';

const { RunStore } = require('../../lib/autonomy/store');
const { ModelGateway } = require('../../lib/autonomy/model');

const store = RunStore.create({ scopeId: 'crash-fixture', snapshotId: `sha256:${'a'.repeat(64)}`,
  inputManifestId: 'AM-aaaaaaaaaaaaaaaa', manifestId: 'AM-aaaaaaaaaaaaaaaa',
  mode: 'live', capabilityProfile: 'model-enabled', budget: {} });
const gateway = new ModelGateway({ mode: 'live', modelOverride: 'cn:fixture', store,
  budget: { reserveModel: () => {}, settleModel: () => {} } });
gateway._transport = { keyPresent: () => true, send: () => {
  process.stdout.write(`${JSON.stringify({ runId: store.runId, dir: store.dir })}\n`);
  return new Promise(() => {});
} };
gateway.invoke({ purpose: 'crash-fixture', taskId: 'TASK:aaaaaaaaaaaaaaaa',
  contextId: 'CTX:aaaaaaaaaaaaaaaa', messages: [] });
setInterval(() => {}, 1000);
