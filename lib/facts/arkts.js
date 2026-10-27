'use strict';

const path = require('path');
const crypto = require('crypto');
const ids = require('./ids');

const MODULE = path.join(__dirname, '..', '..', '..', 'oh6-framework-want-leak-miner', 'node_modules', 'typescript');

// shortcut: TS rejects ArkTS `export default namespace`; replace only its keyword until an ArkTS parser is available.
function normalizeDefaultNamespace(text) {
  return text.replace(/^([ \t]*export[ \t]+)default(?=[ \t]+namespace[ \t]+[$\w]+)/gm,
    (_, prefix) => `${prefix}       `);
}

function extract({ file, snapshotId, text, sha256, bytes, lines, buckets, unsupported }) {
  const ts = require(MODULE);
  const source = ts.createSourceFile(file.rel, normalizeDefaultNamespace(text), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const diagnostics = source.parseDiagnostics.map((d) => ({
    line: source.getLineAndCharacterOfPosition(d.start || 0).line + 1,
    code: d.code
  }));
  const quality = { parse: diagnostics.length ? 'partial' : 'full', resolution: 'syntax-only', errorNodes: diagnostics.length };
  const base = { snapshotId, role: file.role, producer: 'AG0', schemaVersion: '1' };
  const lineOf = (pos) => source.getLineAndCharacterOfPosition(pos).line + 1;
  const fileLocator = { repo: file.repo, file: file.rel };
  buckets.files.push({ ...base, factId: ids.factIdOf(snapshotId, 'file', fileLocator), kind: 'file',
    locator: fileLocator, sourceRange: { file: file.rel, startLine: 1, endLine: lines || 1 },
    quality, path: file.rel, repo: file.repo, bytes, lines, sha256, language: 'arkts' });

  const counts = { functions: 0, calls: 0 };
  function visit(node, owner) {
    const exported = ts.isFunctionDeclaration(node) && node.name && node.body &&
      node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (exported) {
      const startLine = lineOf(node.getStart(source));
      const endLine = lineOf(node.end);
      if (diagnostics.some((d) => d.line >= startLine && d.line <= endLine)) {
        unsupported.push({ id: `U:arkts-function:${file.rel}:${startLine}`, kind: 'function',
          reason: 'ast-error-nodes', file: file.rel, detail: { startLine, endLine } });
      } else {
        const name = node.name.text;
        const qualified = [...owner, name].join('::');
        const locator = { repo: file.repo, file: file.rel, startLine, name: qualified };
        const factId = ids.factIdOf(snapshotId, 'function', locator);
        const fnQuality = { parse: 'full', resolution: 'syntax-only', errorNodes: 0 };
        buckets.functions.push({ ...base, factId, kind: 'function', locator,
          sourceRange: { file: file.rel, startLine, endLine }, quality: fnQuality,
          name, owner: owner.join('::'), qualified,
          signature: text.slice(node.getStart(source), node.body.getStart(source)).replace(/\s+/g, ' ').trim().slice(0, 400),
          startLine, endLine, bodyHash: crypto.createHash('sha256').update(node.body.getText(source)).digest('hex'),
          argc: node.parameters.length, isTest: file.role === 'test', language: 'arkts', exported: true });
        counts.functions += 1;
        function calls(n) {
          if (ts.isCallExpression(n)) {
            const calleeName = ts.isIdentifier(n.expression) ? n.expression.text
              : ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : null;
            if (calleeName) {
              const line = lineOf(n.getStart(source));
              const column = source.getLineAndCharacterOfPosition(n.getStart(source)).character + 1;
              const callLocator = { repo: file.repo, file: file.rel, line, column, caller: qualified, callee: calleeName };
              buckets.calls.push({ ...base, factId: ids.factIdOf(snapshotId, 'call', callLocator), kind: 'call',
                locator: callLocator, sourceRange: { file: file.rel, startLine: line, endLine: line },
                quality: { parse: 'full', resolution: 'name-only', errorNodes: 0 },
                caller: factId, callerName: qualified, calleeName, callee: null, line, column, argc: n.arguments.length });
              counts.calls += 1;
            }
          }
          ts.forEachChild(n, calls);
        }
        calls(node.body);
      }
    }
    if (ts.isModuleDeclaration(node)) owner = [...owner, node.name.text];
    ts.forEachChild(node, (child) => visit(child, owner));
  }
  visit(source, []);
  buckets.quality.push({ id: `Q:${file.rel}`, file: file.rel, repo: file.repo,
    role: file.role, language: 'arkts', parse: quality.parse, errorNodes: diagnostics.length,
    bytes, lines, counts, macroFunctions: 0, cfgCoverageAvg: null, dfgCoverageAvg: null,
    cfgUnsupportedEdges: 0, astCallExpressions: null, astFunctionDefinitions: null });
  if (diagnostics.length) unsupported.push({ id: `U:arkts:${file.rel}`, kind: 'file',
    reason: 'ast-error-nodes', file: file.rel, detail: { diagnostics } });
}

module.exports = { extract, normalizeDefaultNamespace };
