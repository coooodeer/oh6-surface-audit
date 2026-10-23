'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const ids = require('../lib/autonomy/ids');
const knowledge = require('../lib/autonomy/knowledge');
const factsLib = require('../lib/autonomy/facts');
const discovery = require('../lib/autonomy/discovery');
const scope = require('../K/policies/autonomy-pilot-scope.json');

const root = path.join(__dirname, '..');
function cli(...args) {
  return spawnSync(process.execPath, ['bin/autonomy.js', ...args], { cwd: root, encoding: 'utf8' });
}

test('signed review publishes an immutable version; forged or stale inputs do not', () => {
  const proposalPath = path.join(knowledge.PROPOSAL_DIR,
    `${knowledge.loadAuthorization(require('../lib/autonomy/facts').AutonomyFacts.open({
      snapshot: require('../K/policies/autonomy-pilot-scope.json').snapshotId,
      scope: require('../K/policies/autonomy-pilot-scope.json') })).knowledgeVersion.slice(7)}.json`);
  const existed = fs.existsSync(proposalPath);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-review-test-'));
  const reviewDir = path.join(root, 'K', 'reviews');
  const reviewFile = path.join(reviewDir, `test-${crypto.randomBytes(8).toString('hex')}.json`);
  const internalKey = path.join(reviewDir, `test-${crypto.randomBytes(8).toString('hex')}.pub`);
  const staleFile = path.join(knowledge.PROPOSAL_DIR, `test-stale-${crypto.randomBytes(8).toString('hex')}.json`);
  let publishedDir;
  let runDir;
  try {
    const proposed = cli('knowledge', 'propose', '--scope=K/policies/autonomy-pilot-scope.json',
      '--doc-set=sandbox-manager-pilot');
    assert.equal(proposed.status, 0, proposed.stderr);
    const proposal = JSON.parse(fs.readFileSync(proposalPath, 'utf8'));
    assert.equal(proposal.norm.state, 'proposed');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const keyFile = path.join(temp, 'reviewer.pub.pem');
    fs.writeFileSync(keyFile, publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');
    const fields = { origin: 'external-human-review', reviewer: 'test-reviewer',
      reviewedAt: new Date().toISOString(), decision: 'accepted', normId: proposal.norm.normId,
      proposalVersion: proposal.knowledgeVersion, snapshotId: proposal.snapshotId,
      appliesTo: ['SetPolicy'], rationale: 'Test-only signed review of the literal README requirement.',
      keyId: `KEY:${ids.sha256Hex(publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16)}` };
    const signed = { ...fields, signature: crypto.sign(null,
      Buffer.from(ids.canonicalJson(fields)), privateKey).toString('base64') };
    fs.mkdirSync(reviewDir, { recursive: true });
    fs.writeFileSync(reviewFile, JSON.stringify(signed), 'utf8');
    const direct = cli('run', '--experiment=vertical-v1', '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      `--knowledge-review=${reviewFile}`, `--review-public-key=${keyFile}`);
    assert.equal(direct.status, 2);
    assert.match(direct.stderr, /published --knowledge version/);
    const args = ['knowledge', 'publish', '--scope=K/policies/autonomy-pilot-scope.json',
      `--proposal=${proposalPath}`, `--approval-file=${reviewFile}`, `--review-public-key=${keyFile}`];
    const first = cli(...args);
    assert.equal(first.status, 0, first.stderr);
    const out = JSON.parse(first.stdout);
    assert.equal(out.created, true);
    publishedDir = path.dirname(path.resolve(root, out.file));
    const content = fs.readFileSync(path.join(publishedDir, 'knowledge.json'), 'utf8');
    assert.equal(JSON.parse(content).norm.state, 'accepted');
    const again = cli(...args);
    assert.equal(again.status, 0, again.stderr);
    assert.equal(JSON.parse(again.stdout).created, false);
    assert.equal(fs.readFileSync(path.join(publishedDir, 'knowledge.json'), 'utf8'), content);

    const run = cli('run', '--experiment=vertical-v1', '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--task=TASK:108bcc806d3fc6f0', `--knowledge=${path.join(publishedDir, 'knowledge.json')}`,
      `--review-public-key=${keyFile}`);
    assert.equal(run.status, 0, run.stderr);
    const runOut = JSON.parse(run.stdout);
    runDir = path.resolve(root, runOut.runDir);
    assert.equal(cli('check', `--run=${runOut.runId}`).status, 0);
    const used = JSON.parse(fs.readFileSync(path.join(runDir, 'vertical-knowledge.json'), 'utf8'));
    assert.equal(used.norm.state, 'accepted');
    const analysis = JSON.parse(fs.readFileSync(path.join(runDir, 'vertical-analysis.json'), 'utf8'));
    assert.equal(analysis.applicability.status, 'unknown');
    assert.equal(runOut.counts.finding, 0);

    fs.writeFileSync(reviewFile, JSON.stringify({ ...signed, appliesTo: ['SetPolicyAsync'] }), 'utf8');
    assert.equal(cli(...args).status, 2);
    fs.writeFileSync(reviewFile, JSON.stringify(signed), 'utf8');
    assert.equal(cli(...args.slice(0, -1), `--review-public-key=${path.join(root, 'README.md')}`).status, 2);
    fs.writeFileSync(internalKey, publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');
    const linkedDir = path.join(temp, 'linked-reviews');
    try {
      fs.symlinkSync(reviewDir, linkedDir, 'junction');
      const linked = cli(...args.slice(0, -1), `--review-public-key=${path.join(linkedDir, path.basename(internalKey))}`);
      assert.equal(linked.status, 2);
      assert.match(linked.stderr, /outside the workspace/);
    } catch (e) {
      if (e.code !== 'EPERM' && e.code !== 'EACCES') throw e;
    }
    fs.writeFileSync(staleFile, JSON.stringify({ ...proposal, knowledgeVersion: `sha256:${'c'.repeat(64)}` }), 'utf8');
    assert.equal(cli(...args.map((arg) => arg.startsWith('--proposal=') ? `--proposal=${staleFile}` : arg)).status, 2);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
    if (fs.existsSync(reviewFile)) fs.unlinkSync(reviewFile);
    if (fs.existsSync(internalKey)) fs.unlinkSync(internalKey);
    if (fs.existsSync(staleFile)) fs.unlinkSync(staleFile);
    if (!existed && fs.existsSync(proposalPath)) fs.unlinkSync(proposalPath);
    if (runDir && runDir.startsWith(path.resolve(root, 'out', 'autonomy') + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(runDir))) fs.rmSync(runDir, { recursive: true, force: true });
    if (publishedDir && publishedDir.startsWith(path.resolve(knowledge.PUBLISHED_DIR) + path.sep) &&
        /^[0-9a-f]{64}$/.test(path.basename(publishedDir))) fs.rmSync(publishedDir, { recursive: true, force: true });
  }
});

test('second norm requires a matching signed review and fresh source at publication and use', () => {
  const facts = factsLib.AutonomyFacts.open({ snapshot: scope.snapshotId, scope });
  const proposal = knowledge.loadPersistenceAuthorization(facts);
  const proposalPath = path.join(knowledge.PROPOSAL_DIR, `${proposal.knowledgeVersion.slice(7)}.json`);
  const existed = fs.existsSync(proposalPath);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-persistence-review-'));
  const reviewDir = path.join(root, 'K', 'reviews');
  const reviewFile = path.join(reviewDir, `test-${crypto.randomBytes(8).toString('hex')}.json`);
  let publishedDir;
  let runDir;
  try {
    const proposed = cli('knowledge', 'propose', '--scope=K/policies/autonomy-pilot-scope.json',
      '--doc-set=sandbox-manager-pilot', '--norm=UnSetPolicy');
    assert.equal(proposed.status, 0, proposed.stderr);
    assert.deepEqual(JSON.parse(fs.readFileSync(proposalPath, 'utf8')), proposal);
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const keyFile = path.join(temp, 'reviewer.pub.pem');
    fs.writeFileSync(keyFile, publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');
    const fields = { origin: 'external-human-review', reviewer: 'test-reviewer',
      reviewedAt: new Date().toISOString(), decision: 'accepted', normId: proposal.norm.normId,
      proposalVersion: proposal.knowledgeVersion, snapshotId: proposal.snapshotId,
      appliesTo: ['UnSetPolicy'], rationale: 'Test-only review of the literal persistence requirement.',
      keyId: `KEY:${ids.sha256Hex(publicKey.export({ type: 'spki', format: 'der' })).slice(0, 16)}` };
    const sign = (record) => ({ ...record, signature: crypto.sign(null,
      Buffer.from(ids.canonicalJson(record)), privateKey).toString('base64') });
    fs.mkdirSync(reviewDir, { recursive: true });
    fs.writeFileSync(reviewFile, JSON.stringify(sign(fields)), 'utf8');
    const publishArgs = ['knowledge', 'publish', '--scope=K/policies/autonomy-pilot-scope.json',
      `--proposal=${proposalPath}`, `--approval-file=${reviewFile}`, `--review-public-key=${keyFile}`];
    assert.throws(() => knowledge.reviewAuthorization(proposal,
      sign({ ...fields, appliesTo: ['SetPolicy'] }), publicKey), /invalid-or-stale/);
    const first = cli(...publishArgs);
    assert.equal(first.status, 0, first.stderr);
    publishedDir = path.dirname(path.resolve(root, JSON.parse(first.stdout).file));
    const publishedFile = path.join(publishedDir, 'knowledge.json');
    assert.equal(cli(...publishArgs).status, 0);
    assert.equal(knowledge.loadPublished(publishedFile, publicKey, facts).norm.appliesTo[0], 'UnSetPolicy');
    const entry = [...discovery.buildAnchors(facts, scope).anchors.values()]
      .find((anchor) => anchor.kind === 'idl' && anchor.method === 'UnSetPolicyAsync');
    const taskId = ids.taskId('task', { origin: 'entry-scan', anchorRefs: [entry.entityId] });
    const run = cli('run', '--experiment=vertical-v2', '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      `--task=${taskId}`, `--knowledge=${publishedFile}`, `--review-public-key=${keyFile}`);
    assert.equal(run.status, 0, run.stderr);
    const runOut = JSON.parse(run.stdout);
    runDir = path.resolve(root, runOut.runDir);
    assert.equal(cli('check', `--run=${runOut.runId}`).status, 0);
    assert.equal(JSON.parse(fs.readFileSync(path.join(runDir, 'vertical-analysis.json'), 'utf8'))
      .applicability.status, 'unknown');
    const wrongEntry = cli('run', '--experiment=vertical-v1', '--mode=off',
      '--scope=K/policies/autonomy-pilot-scope.json', '--budget=K/policies/autonomy-pilot-budget.json',
      '--task=TASK:108bcc806d3fc6f0', `--knowledge=${publishedFile}`, `--review-public-key=${keyFile}`);
    assert.equal(wrongEntry.status, 2);
    assert.match(wrongEntry.stderr, /knowledge-norm-entry-mismatch/);
    const wrong = knowledge.loadAuthorization(facts);
    assert.throws(() => knowledge.publishAuthorization(wrong, sign(fields), publicKey, facts),
      /invalid-or-stale/);
    fs.writeFileSync(reviewFile, JSON.stringify(sign({ ...fields, appliesTo: ['SetPolicy'] })), 'utf8');
    assert.equal(cli(...publishArgs).status, 2);
    const stale = Object.create(facts);
    stale.sourceRoot = temp;
    for (const rel of [knowledge.DOC, knowledge.HEADER]) {
      const dest = path.join(temp, ...rel.split('/'));
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.join(facts.sourceRoot, ...rel.split('/')), dest);
    }
    const docFile = path.join(temp, ...knowledge.DOC.split('/'));
    fs.writeFileSync(docFile, fs.readFileSync(docFile, 'utf8').replace('FILE_ACCESS_PERSIST', 'FILE_ACCESS_CHANGE'), 'utf8');
    assert.throws(() => knowledge.publishAuthorization(proposal, sign(fields), publicKey, stale),
      /persistence-norm-missing-or-ambiguous/);
    assert.throws(() => knowledge.loadPublished(publishedFile, publicKey, stale),
      /persistence-norm-missing-or-ambiguous/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
    if (fs.existsSync(reviewFile)) fs.unlinkSync(reviewFile);
    if (!existed && fs.existsSync(proposalPath)) fs.unlinkSync(proposalPath);
    if (runDir && runDir.startsWith(path.resolve(root, 'out', 'autonomy') + path.sep) &&
        /^RUN-[0-9a-f]{16}$/.test(path.basename(runDir))) fs.rmSync(runDir, { recursive: true, force: true });
    if (publishedDir && publishedDir.startsWith(path.resolve(knowledge.PUBLISHED_DIR) + path.sep) &&
        /^[0-9a-f]{64}$/.test(path.basename(publishedDir))) fs.rmSync(publishedDir, { recursive: true, force: true });
  }
});
