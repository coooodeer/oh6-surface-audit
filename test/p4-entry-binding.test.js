'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'out');

test('P4 entry-binding: R1 6 candidates; no fake O1 proof', () => {
  const s = JSON.parse(fs.readFileSync(path.join(OUT, 'p4', 'entry-binding.json'), 'utf8'));
  assert.equal(s.scope, 'R1');
  assert.equal(s.candidates, 6);
  assert.equal(s.byStatus.proven || 0, 0);
  assert.equal(s.byStatus.unproven, 5);
  assert.equal(s.byStatus.suspect, 1);
  const ubsan = s.rows.find((r) => r.candidateId === 'cd_G-P4_52b62a535a33');
  assert.ok(ubsan);
  assert.equal(ubsan.status, 'suspect');
  assert.equal(ubsan.entryMatched, false);
  assert.ok(ubsan.ipcPath.length > 0);
  assert.equal(ubsan.candidateOracle.state, 'confirmed');
});

test('P4 entry-binding report exists', () => {
  const md = fs.readFileSync(path.join(OUT, 'report', 'p4-entry-binding.md'), 'utf8');
  assert.match(md, /no-ipc-call-path/);
  assert.match(md, /cd_G-P4_52b62a535a33/);
});
