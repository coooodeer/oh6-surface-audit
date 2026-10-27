'use strict';

/**
 * tools/autonomy-r2-sa-chain.js —— R2-D2：4 个未绑定 SA 的可验证归属链。
 *
 * 链条：sa profile（saId + libpath + process）
 *   → 1) 构建目标：BUILD.gn 中 ohos_shared_library("<X>")，X = libpath 去 lib/.z.so
 *   → 2) saId 证据：生产源码中的 ID 常量定义（#define/constexpr/static const = saId）
 *      或 REGISTER_SYSTEM_ABILITY_BY_ID(<Cls>, <CONST>) 的常量回解
 *   → 3) 注册/实现：MakeAndRegisterAbility / REGISTER_SYSTEM_ABILITY 系调用
 * 链条闭合 ⇒ saChain=closed（entry 仍标 unbound-method：SA 无方法体可绑）；
 * 缺口保持 unbound 并具名缺失步骤。不把“存在同名函数”当服务实现。
 *
 * 只读。输出 --out（默认 out/autonomy/inventory/r2-sa-chain.json）。
 *
 * 用法：node tools/autonomy-r2-sa-chain.js [--scope=access-token-r2] [--out=<file>]
 */

const fs = require('node:fs');
const path = require('node:path');

const factsLib = require('../lib/autonomy/facts');
const scopeLib = require('../lib/facts/scope');

const TOOL_DIR = path.resolve(__dirname, '..');
const SRC_ROOT = scopeLib.SRC_ROOT;

function parseArgs(argv) {
  const out = { scope: 'access-token-r2', out: null };
  for (const a of argv) {
    if (a.startsWith('--scope=')) out.scope = a.slice('--scope='.length);
    else if (a.startsWith('--out=')) out.out = a.slice('--out='.length);
    else throw new Error(`unknown-arg: ${a}`);
  }
  return out;
}

function listTextFiles(rootAbs, exts) {
  const out = [];
  const stack = [rootAbs];
  while (stack.length) {
    const dir = stack.pop();
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of ents) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!['.git', 'out', 'test', 'tests', 'unittest', 'fuzztest', 'mock', 'moduletest'].includes(ent.name)) stack.push(p);
        continue;
      }
      if (exts.some((e) => p.toLowerCase().endsWith(e))) out.push(p);
    }
  }
  return out;
}

function relOf(abs) {
  return scopeLib.posix(path.relative(SRC_ROOT, abs));
}

function analyzeSa(saRow, componentRoot) {
  const payload = saRow.payload || {};
  const saId = payload.saId;
  const library = payload.library || '';
  const targetName = library.replace(/^lib/, '').replace(/\.z\.so$/, '');
  const rootAbs = path.join(SRC_ROOT, componentRoot.split('/').join(path.sep));

  // 步骤 1：构建目标
  const buildFiles = listTextFiles(rootAbs, ['build.gn']);
  const buildHits = [];
  for (const bf of buildFiles) {
    const text = fs.readFileSync(bf, 'utf8');
    const re = new RegExp(`ohos_shared_library\\(\\s*"${targetName}"\\s*\\)`);
    if (re.test(text)) buildHits.push(relOf(bf));
  }

  // 步骤 2+3：saId 证据与注册调用（仅生产源码）
  const srcFiles = listTextFiles(rootAbs, ['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp']);
  const idConstantHits = [];
  const registerHits = [];
  const idConstNames = [];
  for (const sf of srcFiles) {
    const text = fs.readFileSync(sf, 'utf8');
    const rel = relOf(sf);
    // (a) 常量定义 = saId
    const constRe = new RegExp(`(?:define|constexpr[^=]*|static\\s+const\\s+[^=]*?)\\s([A-Z][A-Z0-9_]+)\\s*=\\s*${saId}\\b`, 'g');
    let m;
    while ((m = constRe.exec(text)) !== null) {
      idConstantHits.push({ file: rel, kind: 'constant-def', name: m[1] });
      idConstNames.push(m[1]);
    }
    // (b) REGISTER_SYSTEM_ABILITY[_BY_ID](<Cls>, <Const or saId>)
    const regRe = /REGISTER_SYSTEM_ABILITY(?:_BY_ID)?\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_0-9]+)\s*/g;
    while ((m = regRe.exec(text)) !== null) {
      registerHits.push({ file: rel, macro: m[0].split('(')[0].trim(), cls: m[1], idOrConst: m[2] });
      idConstNames.push(m[2]);
    }
    // (c) MakeAndRegisterAbility / AddSystemAbility
    if (/MakeAndRegisterAbility\s*\(/.test(text)) registerHits.push({ file: rel, macro: 'MakeAndRegisterAbility' });
  }
  // REGISTER 的常量回解：常量名 → saId 定义（同组件内）
  for (const hit of registerHits) {
    if (/^\d+$/.test(hit.idOrConst)) {
      if (Number(hit.idOrConst) === saId) hit.idResolved = saId;
      continue;
    }
    if (idConstantHits.some((c) => c.name === hit.idOrConst)) hit.idResolved = saId;
    else {
      // 常量定义可能在组件外/系统头：本工具范围内记 unresolved-constant
      hit.idResolved = null;
      hit.idResolutionNote = `constant ${hit.idOrConst} not defined in component production sources`;
    }
  }
  // 组件外常量回解（跨组件依赖边界）：samgr 的 system_ability_definition.h 是 OH 的
  // SA ID 全局定义点；命中则链条闭合但标记 closed-external（依赖组件外头文件证据）。
  const externalConstant = { file: 'foundation/systemabilitymgr/samgr/interfaces/innerkits/samgr_proxy/include/system_ability_definition.h', hits: [] };
  {
    const abs = path.join(SRC_ROOT, externalConstant.file.split('/').join(path.sep));
    if (fs.existsSync(abs)) {
      const text = fs.readFileSync(abs, 'utf8');
      const lineRe = new RegExp(`\\b([A-Z][A-Z0-9_]+)\\s*=\\s*${saId}\\b`, 'g');
      let m;
      const lines = text.split('\n');
      while ((m = lineRe.exec(text)) !== null) {
        const lineNo = text.slice(0, m.index).split('\n').length;
        externalConstant.hits.push({ name: m[1], line: lineNo });
        for (const hit of registerHits) {
          if (hit.idOrConst === m[1] && !hit.idResolved) {
            hit.idResolved = saId;
            hit.idResolutionNote = `constant defined in cross-component header ${externalConstant.file}:${lineNo}`;
          }
        }
      }
    }
  }
  const externalResolved = externalConstant.hits.length > 0
    && registerHits.some((h) => h.idResolved === saId && String(h.idResolutionNote || '').includes('cross-component'));
  const idEvidence = idConstantHits.filter((h) => true);
  const registerWithResolvedId = registerHits.filter((h) => h.idResolved === saId
    || (h.macro === 'MakeAndRegisterAbility' && idEvidence.length > 0));

  const steps = {
    buildTarget: { expected: `ohos_shared_library("${targetName}")`, found: buildHits, ok: buildHits.length > 0 },
    saIdEvidence: { saId, hits: idEvidence.slice(0, 6), ok: idEvidence.length > 0 },
    registration: { hits: registerHits.slice(0, 8), resolvedWithSaId: registerWithResolvedId.slice(0, 4),
      ok: registerWithResolvedId.length > 0 },
    externalConstant
  };
  const gaps = [];
  if (!steps.buildTarget.ok) gaps.push('build-target-not-found');
  if (!steps.saIdEvidence.ok && !externalResolved) gaps.push('saId-constant-not-found-in-production-sources');
  if (!steps.registration.ok) gaps.push('registration-call-not-resolved-to-saId');
  const chainStatus = gaps.length === 0 ? (externalResolved ? 'closed-external' : 'closed') : 'gap';
  return {
    saId,
    library,
    process: payload.process,
    profileFile: saRow.sourceFile,
    saChain: chainStatus,
    gaps,
    steps,
    binding: 'unbound',
    note: 'SA 无方法体可绑（metadata-only 入口）；saChain=closed 表示 profile→构建目标→ID 常量→注册'
      + ' 的归属链闭合；closed-external 表示 ID 常量定义在组件外头（跨组件依赖边界，逐条登记）；'
      + '均不等于入口已安全裁决。'
  };
}

function main(argv = []) {
  const args = parseArgs(argv);
  const policy = JSON.parse(fs.readFileSync(path.join(TOOL_DIR, 'K', 'policies', `scope-${args.scope}.json`), 'utf8'));
  const facts = factsLib.AutonomyFacts.open({ snapshot: 'latest', scope: policy });
  const idx = facts.index();
  const componentRoot = policy.roots[0].root;
  const rows = idx.metadata.sa.map((row) => analyzeSa(row, componentRoot));
  const closed = rows.filter((r) => r.saChain === 'closed').length;

  const result = {
    experimentVersion: 'r2-sa-chain-v1',
    generatedAt: new Date().toISOString(),
    scope: args.scope,
    snapshotId: facts.snapshotId,
    totalSa: rows.length,
    closed,
    gap: rows.length - closed,
    rows,
    note: '每条链的步骤证据可定位（文件相对路径 + 常量名/宏）；缺口保持 unbound。'
  };
  const outFile = args.out || path.join(TOOL_DIR, 'out', 'autonomy', 'inventory', 'r2-sa-chain.json');
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    ok: true, totalSa: rows.length, closed,
    rows: rows.map((r) => ({ saId: r.saId, library: r.library, saChain: r.saChain, gaps: r.gaps })),
    out: path.relative(TOOL_DIR, outFile).split(path.sep).join('/')
  })}\n`);
  return 0;
}

module.exports = { main, analyzeSa };

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`);
    process.exitCode = 1;
  }
}
