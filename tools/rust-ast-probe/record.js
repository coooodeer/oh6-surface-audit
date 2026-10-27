'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const readline = require('node:readline');

const auditRoot = path.resolve(__dirname, '../..');
const workspace = path.resolve(auditRoot, '..');
const inventory = path.join(auditRoot, 'out/autonomy/inventory/r1-refresh/r1-files.jsonl');
const output = path.join(auditRoot, 'out/autonomy/rust-probe/asset-ast-inventory.json');
// shortcut: this probe uses the local Windows build; add a platform selector for Linux execution.
const binary = path.join(auditRoot, 'out/autonomy/rust-ast-probe-target/debug/oh6-rust-ast-probe.exe');
const sha256 = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

async function main() {
  const files = [];
  const lines = readline.createInterface({ input: fs.createReadStream(inventory, 'utf8') });
  for await (const line of lines) {
    const row = JSON.parse(line);
    if (row.c === '@ohos/asset' && row.l === 'rust' && row.r === 'production-code') files.push(row.p);
  }
  files.sort();
  if (files.length !== 54 || !fs.existsSync(binary)) throw new Error('asset-rust-input-or-probe-missing');
  const result = cp.spawnSync(binary, files.map((file) => path.join(workspace, 'OpenHarmony', file)),
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0 || result.error) {
    throw new Error(`rust-ast-parse-failed: ${result.error?.message || result.stderr}`);
  }
  const rows = result.stdout.trim().split('\n').map((line) => {
    const [absolute, kind, name, lineNumber, endLine, ctx, argc] = line.trimEnd().split('\t');
    const file = path.relative(path.join(workspace, 'OpenHarmony'), absolute).split(path.sep).join('/');
    if (!files.includes(file) || !/^\d+$/.test(lineNumber) || !kind || !name ||
        !/^\d*$/.test(endLine || '') || !/^\d*$/.test(argc || '')) {
      throw new Error(`rust-ast-row-invalid: ${line}`);
    }
    return { file, kind, name, line: Number(lineNumber),
      ...(endLine ? { endLine: Number(endLine) } : {}),
      ...(ctx ? { ctx } : {}), ...(argc ? { argc: Number(argc) } : {}) };
  });
  const ipc = 'base/security/asset/frameworks/ipc/src/lib.rs';
  const stub = 'base/security/asset/services/core_service/src/stub.rs';
  const service = 'base/security/asset/services/core_service/src/lib.rs';
  const query = 'base/security/asset/services/core_service/src/operations/operation_query.rs';
  const expected = ['Add->add', 'Remove->remove', 'Update->update', 'PreQuery->pre_query',
    'Query->query', 'PostQuery->post_query', 'QuerySyncResult->query_sync_result'];
  const enums = rows.filter((r) => r.file === ipc && r.kind === 'ipc-enum');
  const arms = rows.filter((r) => r.file === stub && r.kind === 'ipc-arm');
  const calls = rows.filter((r) => r.file === stub && r.kind === 'ipc-call');
  if (enums.length !== 7 || arms.length !== 7 || calls.length !== 7 ||
      rows.some((r) => r.file === stub && r.kind === 'ipc-unresolved') ||
      expected.some((name) => calls.filter((r) => r.name === name).length !== 1) ||
      enums.some((r) => arms.filter((arm) => arm.name === r.name).length !== 1)) {
    throw new Error('asset-ipc-dispatch-unresolved');
  }
  for (const [file, kind, name] of [
    [service, 'execute-call', 'AssetService::query->operations::query'],
    [query, 'try-call', 'query->check_arguments'],
    [query, 'tail-call', 'check_arguments->common::check_system_permission']
  ]) {
    if (rows.filter((r) => r.file === file && r.kind === kind && r.name === name).length !== 1) {
      throw new Error(`asset-query-edge-unresolved: ${name}`);
    }
  }
  const dispatchCall = rows.find((r) => r.file === stub && r.kind === 'ipc-call' && r.name === 'Query->query');
  if (!dispatchCall || dispatchCall.ctx !== 'on_remote_request' || dispatchCall.argc !== 2) {
    throw new Error('asset-ipc-call-context-unresolved');
  }
  const gates = rows.filter((r) => r.kind === 'asset-gate');
  const unresolvedGates = rows.filter((r) => r.kind === 'asset-gate-unresolved' || r.kind === 'asset-gate-noblock');
  if (gates.length !== 1 || gates[0].name !== 'UserId->system-app,permission,uid' || unresolvedGates.length !== 0) {
    throw new Error('asset-gate-unresolved');
  }
  const doc = {
    kind: 'offline-rust-ast-inventory',
    source: 'out/autonomy/inventory/r1-refresh/r1-files.jsonl',
    sourceSha256: sha256(inventory),
    tool: { sourceSha256: sha256(path.join(__dirname, 'src/main.rs')),
      recorderSha256: sha256(__filename),
      binarySha256: sha256(binary), cargoLockSha256: sha256(path.join(__dirname, 'Cargo.lock')) },
    files: files.map((file) => ({ file, sha256: sha256(path.join(workspace, 'OpenHarmony', file)) })),
    rows,
    limits: 'Rows are file/kind/name/line/endLine/ctx/argc TSV; syntax rows include cfg(test) and unresolved variants; seven enum/arm edges, three Query syntax edges and the check_system_permission gate shape (asset-gate) are checked for uniqueness. Macro expansion, GN variant, FFI identity, gate dominance and security verdict are not proven.'
  };
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
  console.log(JSON.stringify({ output: path.relative(auditRoot, output), files: files.length,
    rows: rows.length, ipcEdges: calls.length, query: calls.find((r) => r.name === 'Query->query') }));
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
