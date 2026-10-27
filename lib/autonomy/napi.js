'use strict';

const fs = require('fs');
const path = require('path');

// Only the registration -> Init -> literal descriptor macro shape is modeled.
function exportsOf(facts, row, binding) {
  const file = row.sourceFile;
  if (!facts.verifyFile(file).ok) return [];
  const idx = facts.index();
  if (idx.truncated?.functions || idx.truncated?.calls) return [];
  const text = fs.readFileSync(path.join(facts.sourceRoot, ...file.split('/')), 'utf8');
  const moduleName = row.payload?.module;
  const struct = row.payload?.struct;
  if (!/^[A-Za-z_]\w*$/.test(struct || '')) return [];
  const lines = text.split(/\r?\n/);
  const register = idx.calls.some((call) => call.sourceRange?.file === file &&
    call.calleeName === 'napi_module_register' && call.line === row.sourceLine);
  const moduleBlock = new RegExp(`\\b(?:static\\s+)?napi_module\\s+${struct}\\s*=\\s*\\{([\\s\\S]*?)\\n\\};`)
    .exec(text)?.[1];
  const initName = /\.nm_register_func\s*=\s*([A-Za-z_]\w*)\s*,/.exec(moduleBlock || '')?.[1];
  if (!register || !new RegExp(`napi_module_register\\s*\\(\\s*&\\s*${struct}\\s*\\)`).test(lines[row.sourceLine - 1] || '') ||
      !initName || !moduleBlock.includes(`.nm_modname = "${moduleName}"`)) return [];
  const init = idx.functions.filter((fn) => fn.name === initName &&
    fn.sourceRange?.file === file && fn.role === 'production');
  if (init.length !== 1 || !idx.calls.some((call) => call.caller === init[0].factId &&
    call.calleeName === 'napi_define_properties')) return [];
  const exports = [];
  for (const call of idx.calls.filter((item) => item.caller === init[0].factId &&
    item.calleeName === 'DECLARE_NAPI_FUNCTION' && item.sourceRange?.file === file)) {
    const match = /DECLARE_NAPI_FUNCTION\s*\(\s*"([^"]+)"\s*,\s*([A-Za-z_]\w*)\s*\)/.exec(lines[call.line - 1] || '');
    if (!match) continue;
    const candidates = idx.functions.filter((fn) => fn.name === match[2] &&
      fn.role === 'production' && fn.sourceRange?.file.startsWith(binding.handlerRoot + '/') &&
      String(fn.qualified || '') === `${binding.qualifiedPrefix}${match[2]}`);
    exports.push({ kind: 'napi-export', module: moduleName, method: match[1], file,
      line: call.line, metadataRef: row.metadataId, factRef: candidates.length === 1 ? candidates[0].factId : null,
      handler: match[2], registration: { file, line: row.sourceLine, initRef: init[0].factId,
        descriptorRef: call.factId, candidateCount: candidates.length },
      handlerCandidates: candidates.map((fn) => ({ name: fn.name, qualified: fn.qualified,
        file: fn.sourceRange.file, startLine: fn.startLine, factRef: fn.factId })) });
  }
  return exports;
}

module.exports = { exportsOf };
