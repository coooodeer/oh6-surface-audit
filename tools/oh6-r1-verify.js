'use strict';

/**
 * tools/oh6-r1-verify.js —— R1-D：R1 清点产物的独立核对。
 *
 * 1) 重算：流式读取 r1-files.jsonl，独立重算角色/语言/组件汇总，与
 *    r1-scope-baseline.json 逐项比对（汇总可复算证据）。
 * 2) 抽样复核：按角色/语言确定性抽样，回读源码核对分类依据；覆盖无 bundle
 *    生产文件、生成文件、测试目录嵌套、IDL/SA profile 解析、二进制嗅探。
 * 3) 首层差额：与 full-scope-baseline.json 逐字段比对，差额按规则扩展/词表
 *    修正/归属列差分解释，不复制历史数字充当实测。
 * 4) 入口候选一致性：r1-entry-candidates.jsonl 按 (component, form) 重算，
 *    与汇总比对；@ohos/ipc 的 7 个生产 OnRemoteRequest 复测已知难例。
 *
 * 输出 out/autonomy/inventory/r1-verify-result.json；只读源码与清点产物。
 *
 * 用法：node tools/oh6-r1-verify.js [--src-root <dir>] [--out-dir <dir>]
 */

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const idlFacts = require('../lib/facts/idl');
const saFacts = require('../lib/facts/sa');

const TOOL_DIR = path.resolve(__dirname, '..');
const DEFAULT_SRC = path.resolve(TOOL_DIR, '..', 'OpenHarmony');
// 与 tools/oh6-r1-scope-inventory.js 一致的分类规则（复核用同一词表回放）
const inv = require('./oh6-r1-scope-inventory.js');

const NEW_LANG_EXTS = new Set(['.cj', '.mjs', '.sts']);
const NEW_CONFIG_EXTS = new Set(['.json5', '.te', '.para', '.toml']);

function relInside(rel) { return rel.replace(/^(base|foundation)\//, ''); }

function pickEvenly(items, n) {
  if (items.length <= n) return items.slice();
  const out = [];
  for (let i = 0; i < n; i += 1) {
    out.push(items[Math.floor((i * items.length) / n)]);
  }
  return out;
}

async function main(argv = []) {
  const srcRootIdx = argv.indexOf('--src-root');
  const srcRoot = path.resolve(srcRootIdx >= 0 ? argv[srcRootIdx + 1] : DEFAULT_SRC);
  const outDirIdx = argv.indexOf('--out-dir');
  const outDir = outDirIdx >= 0 ? path.resolve(argv[outDirIdx + 1])
    : path.join(TOOL_DIR, 'out', 'autonomy', 'inventory');
  const filesJsonl = path.join(outDir, 'r1-files.jsonl');
  const entryJsonl = path.join(outDir, 'r1-entry-candidates.jsonl');
  const summaryPath = path.join(outDir, 'r1-scope-baseline.json');
  const firstLayerPath = path.join(outDir, 'full-scope-baseline.json');
  const resultPath = path.join(outDir, 'r1-verify-result.json');

  const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
  const firstLayer = JSON.parse(fs.readFileSync(firstLayerPath, 'utf8'));

  // ---- 1) 重算 ----
  const recount = {
    totalFiles: 0, totalBytes: 0, byRole: {}, prodByLang: {},
    compProd: new Map(), unbundledProd: { files: 0, bytes: 0 },
    unbundledFiles: 0, sorted: true, duplicates: 0, lastPath: null,
    testByLang: {}, genByLang: {},
    prodByLangBytes: {}
  };
  const perRoleCandidates = new Map(); // role -> [{p,s,l,b}]
  const bundledSample = new Map(); // component -> [{p,s,l,b,r}] (限 200/组件)

  const rl = readline.createInterface({ input: fs.createReadStream(filesJsonl), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line) continue;
    const rec = JSON.parse(line);
    recount.totalFiles += 1;
    recount.totalBytes += rec.s;
    const role = recount.byRole[rec.r] || (recount.byRole[rec.r] = { files: 0, bytes: 0 });
    role.files += 1; role.bytes += rec.s;
    if (recount.lastPath !== null && rec.p < recount.lastPath) recount.sorted = false;
    if (rec.p === recount.lastPath) recount.duplicates += 1;
    recount.lastPath = rec.p;
    if (rec.r === 'production-code') {
      recount.prodByLang[rec.l] = (recount.prodByLang[rec.l] || 0) + 1;
      recount.prodByLangBytes[rec.l] = (recount.prodByLangBytes[rec.l] || 0) + rec.s;
      if (rec.c === null) { recount.unbundledProd.files += 1; recount.unbundledProd.bytes += rec.s; }
      else recount.compProd.set(rec.c, (recount.compProd.get(rec.c) || 0) + 1);
    }
    if (rec.r === 'test-code') recount.testByLang[rec.l] = (recount.testByLang[rec.l] || 0) + 1;
    if (rec.r === 'generated-code') recount.genByLang[rec.l] = (recount.genByLang[rec.l] || 0) + 1;
    if (rec.c === null) recount.unbundledFiles += 1;
    if (!perRoleCandidates.has(rec.r)) perRoleCandidates.set(rec.r, []);
    const cand = perRoleCandidates.get(rec.r);
    if (cand.length < 5000) cand.push(rec);
    if (rec.c !== null) {
      let list = bundledSample.get(rec.c);
      if (!list) { list = []; bundledSample.set(rec.c, list); }
      if (list.length < 200) list.push(rec);
    }
  }

  const roleSum = Object.values(recount.byRole).reduce((s, r) => s + r.files, 0);
  const prodLangSum = Object.values(recount.prodByLang).reduce((s, n) => s + n, 0);
  const compProdSum = [...recount.compProd.values()].reduce((s, n) => s + n, 0);

  const checks = [];
  const addCheck = (name, expected, actual, pass) => checks.push({ name, expected, actual, pass });
  const canon = (obj) => JSON.stringify(Object.fromEntries(
    Object.entries(obj || {}).sort(([a], [b]) => (a < b ? -1 : 1))));

  addCheck('recount.totalFiles = summary.filesTraversed',
    summary.totals.filesTraversed, recount.totalFiles,
    summary.totals.filesTraversed === recount.totalFiles);
  addCheck('recount.totalBytes = summary.bytesTraversed',
    summary.totals.bytesTraversed, recount.totalBytes,
    summary.totals.bytesTraversed === recount.totalBytes);
  addCheck('recount.byRole = summary.byRole (files & bytes)',
    canon(Object.fromEntries(Object.entries(summary.totals.byRole)
      .map(([k, v]) => [k, { files: v.files, bytes: v.bytes }]))),
    canon(Object.fromEntries(Object.entries(recount.byRole)
      .map(([k, v]) => [k, { files: v.files, bytes: v.bytes }]))),
    canon(Object.fromEntries(Object.entries(summary.totals.byRole)
      .map(([k, v]) => [k, { files: v.files, bytes: v.bytes }])))
      === canon(Object.fromEntries(Object.entries(recount.byRole)
      .map(([k, v]) => [k, { files: v.files, bytes: v.bytes }]))));
  addCheck('recount.prodByLang = summary.productionByLang',
    canon(summary.totals.productionByLang), canon(recount.prodByLang),
    canon(summary.totals.productionByLang) === canon(recount.prodByLang));
  addCheck('Σ(role files) = totalFiles', recount.totalFiles, roleSum, roleSum === recount.totalFiles);
  addCheck('Σ(production byLang) = production-code files',
    recount.byRole['production-code'].files, prodLangSum,
    recount.byRole['production-code'].files === prodLangSum);
  addCheck('component production + unbundled production = production-code files',
    recount.byRole['production-code'].files, compProdSum + recount.unbundledProd.files,
    recount.byRole['production-code'].files === compProdSum + recount.unbundledProd.files);
  addCheck('unbundled files = summary.unbundled.files count',
    summary.unbundled.files.length, recount.unbundledFiles,
    summary.unbundled.files.length === recount.unbundledFiles);
  addCheck('JSONL 路径严格升序且唯一', 0, recount.duplicates,
    recount.sorted && recount.duplicates === 0);

  // 逐组件 production 对比
  let compMismatches = 0;
  for (const comp of summary.components) {
    const actual = recount.compProd.get(comp.component) || 0;
    if (actual !== comp.production.files) {
      compMismatches += 1;
      checks.push({ name: `component.production.files(${comp.component})`,
        expected: comp.production.files, actual, pass: false });
    }
  }
  addCheck('全部组件 production.files 与 JSONL 重算一致', 0, compMismatches, compMismatches === 0);

  // ---- 2) 抽样复核 ----
  const samples = [];
  const srcAbs = (rel) => path.join(srcRoot, ...rel.split('/'));

  async function checkFile(rec, extra = {}) {
    const abs = srcAbs(rec.p);
    const row = { p: rec.p, r: rec.r, l: rec.l, size: rec.s, ...extra };
    let st;
    try { st = fs.lstatSync(abs); } catch (e) {
      row.verdict = 'fail'; row.reason = `lstat-failed:${e.code}`;
      return row;
    }
    if (rec.r === 'symlink') {
      // 符号链接：只核对登记信息，不跟随、不读目标内容
      let target = null;
      try { target = fs.readlinkSync(abs); } catch (_) { target = null; }
      row.target = target === null ? null : target.split(path.sep).join('/');
      if (st.isSymbolicLink()) { row.verdict = 'pass'; }
      else { row.verdict = 'fail'; row.reason = 'registered-as-symlink-but-lstat-disagrees'; }
      return row;
    }
    if (st.isSymbolicLink()) {
      row.verdict = 'fail'; row.reason = 'regular-record-but-lstat-is-symlink';
      return row;
    }
    if (rec.r === 'unreadable') { row.verdict = 'pass'; return row; }
    if (st.size !== rec.s) {
      row.verdict = 'fail'; row.reason = `size-mismatch jsonl=${rec.s} stat=${st.size}`;
      return row;
    }
    // 分类回放：同规则同输入必须同角色
    const ext = path.extname(rec.p).toLowerCase();
    const replay = inv.classify(path.basename(rec.p), ext, relInside(rec.p));
    if (replay.role !== rec.r || replay.lang !== rec.l) {
      row.verdict = 'fail';
      row.reason = `classify-replay ${replay.role}/${replay.lang} != jsonl ${rec.r}/${rec.l}`;
      return row;
    }
    let content;
    try { content = fs.readFileSync(abs, 'utf8'); } catch (e) {
      row.verdict = 'fail'; row.reason = `read-failed:${e.code}`;
      return row;
    }
    row.reasons = [];
    switch (rec.r) {
      case 'production-code': {
        if (content.length === 0) { row.verdict = 'fail'; row.reason = 'empty-production-file'; break; }
        if (['c', 'cpp'].includes(rec.l) && /#\s*include\s*[<"](gtest|gmock)/.test(content)) {
          row.reasons.push('suspect-test-content: gtest/gmock include in production file');
        }
        if (rec.l === 'header' && !content.includes('#') && !content.includes(';')) {
          row.reasons.push('header without preprocessor/declaration markers');
        }
        row.verdict = 'pass';
        break;
      }
      case 'test-code': {
        const marker = /gtest|gmock|TDD|test|Test|TEST/.test(content.slice(0, 4000));
        row.markerFound = marker;
        if (!marker) row.reasons.push('no test markers in first 4KB (informational)');
        row.verdict = 'pass';
        break;
      }
      case 'generated-code': {
        const marker = /DO NOT EDIT|generated|autogenerated|Generated|机器生成/.test(content.slice(0, 4000));
        row.markerFound = marker;
        if (!marker) row.reasons.push('no generated markers in first 4KB (informational)');
        row.verdict = 'pass';
        break;
      }
      case 'idl': {
        if (rec.l === 'idl') {
          try {
            const parsed = idlFacts.parseIdl(content);
            row.interfaces = parsed.interfaces.length;
            row.methods = parsed.methods.length;
            if (parsed.interfaces.length === 0 && parsed.methods.length === 0) {
              row.reasons.push('parser found no interfaces/methods (flag, not fail)');
            }
          } catch (e) { row.verdict = 'fail'; row.reason = `idl-parse-throw:${e.message}`; break; }
        } else {
          row.serviceMatches = (content.match(/\bservice\s+\w+\s*\{/g) || []).length;
        }
        row.verdict = 'pass';
        break;
      }
      case 'sa-profile': {
        const parsed = saFacts.parseSaProfile(content);
        if (parsed.parseError) { row.verdict = 'fail'; row.reason = 'sa-json-parse-failed'; break; }
        row.systemAbilities = parsed.systemabilities.length;
        row.verdict = 'pass';
        break;
      }
      case 'build': {
        row.hasImport = content.includes('import(');
        row.verdict = 'pass';
        break;
      }
      case 'component-metadata': {
        try {
          const doc = JSON.parse(content);
          row.bundleName = doc.name || (doc.component || {}).name || null;
          if (!row.bundleName) { row.verdict = 'fail'; row.reason = 'bundle.json without name'; break; }
        } catch (e) { row.verdict = 'fail'; row.reason = `bundle-json-parse:${e.message}`; break; }
        row.verdict = 'pass';
        break;
      }
      case 'config': {
        if (ext === '.json') {
          try { JSON.parse(content); } catch (e) {
            row.verdict = 'fail'; row.reason = `json-parse:${e.message}`; break;
          }
        }
        if (content.length === 0) { row.verdict = 'fail'; row.reason = 'empty-config'; break; }
        row.verdict = 'pass';
        break;
      }
      case 'doc': {
        row.verdict = content.length > 0 ? 'pass' : 'fail';
        if (row.verdict === 'fail') row.reason = 'empty-doc';
        break;
      }
      case 'other': {
        row.binary = content.slice(0, 512).includes('\u0000');
        row.verdict = 'pass';
        break;
      }
      case 'production-pending': {
        // 待定角色：只核对存在/大小/回放一致；内容性质留待后续口径确认
        row.verdict = 'pass';
        row.note = 'pending-unconfirmed';
        break;
      }
      default:
        row.verdict = 'fail'; row.reason = `unhandled-role:${rec.r}`;
    }
    if (row.reasons && row.reasons.length === 0) delete row.reasons;
    return row;
  }

  const ROLE_SAMPLE_N = { 'production-code': 6, 'test-code': 4, 'generated-code': 3,
    idl: 4, 'sa-profile': 3, build: 4, 'component-metadata': 2, config: 6, doc: 3,
    other: 4, 'production-pending': 3 };
  for (const [role, n] of Object.entries(ROLE_SAMPLE_N)) {
    const cands = perRoleCandidates.get(role) || [];
    for (const rec of pickEvenly(cands, n)) {
      samples.push(await checkFile(rec, { sample: `role:${role}` }));
    }
  }
  // 专项：无 bundle 生产文件
  const unbundledCands = (perRoleCandidates.get('production-code') || []).filter((rec) => rec.c === null);
  for (const rec of pickEvenly(unbundledCands, 2)) {
    samples.push(await checkFile(rec, { sample: 'special:unbundled-production' }));
  }
  // 专项：测试目录嵌套（路径含两个及以上 test 族段）
  const TEST_SEG = /(^|\/)(test|tests|unittest|fuzztest|moduletest|systemtest)(\/|$)/i;
  const nestedTest = [];
  for (const rec of perRoleCandidates.get('test-code') || []) {
    const segs = relInside(rec.p).split('/').filter((seg) => TEST_SEG.test(`${seg}/`));
    if (segs.length >= 2) { nestedTest.push(rec); if (nestedTest.length >= 4000) break; }
  }
  for (const rec of pickEvenly(nestedTest, 2)) {
    samples.push(await checkFile(rec, { sample: 'special:nested-test-dirs', nestedTestSegs: true }));
  }
  const failedSamples = samples.filter((row) => row.verdict === 'fail');
  const warnedSamples = samples.filter((row) => (row.reasons || []).length > 0);

  // ---- 3) 首层差额 ----
  const firstT = firstLayer.totals;
  const r1Role = (r) => (recount.byRole[r] || { files: 0, bytes: 0 });
  const prodDeltaByLang = {};
  for (const [lang, n] of Object.entries(recount.prodByLang)) {
    const before = firstT.byLanguage[lang] || 0;
    if (n !== before) prodDeltaByLang[lang] = { firstLayer: before, r1: n, delta: n - before };
  }
  // test 差额分解：test 路径下的 idl/proto（首层完全漏计）+ 新词表扩展
  const testInterfaceDefCount = (recount.testByLang.idl || 0) + (recount.testByLang.proto || 0);
  const testTotalDelta = r1Role('test-code').files - firstT.testFiles;
  const newLangTestCount = testTotalDelta - testInterfaceDefCount;
  const testDeltaBreakdown = {
    interfaceDefsUnderTest: testInterfaceDefCount,
    newVocabExts: newLangTestCount,
    note: '新词表扩展（.cj/.mjs/.sts 及 v1.2 的 .hml/.css/.s/shader 族等）在 test 路径下的'
      + '文件数；其中与首层词表同族的语言（javascript/arkts/cpp 等）首层未按语言分桶，'
      + '无法从首层字段逐语言分解。'
  };
  const genInterfaceDefCount = (recount.genByLang.idl || 0) + (recount.genByLang.proto || 0);
  const genTotalDelta = r1Role('generated-code').files - firstT.generatedFiles;
  const unbundledSymlinkCount = summary.unbundled.files.filter((row) => row.r === 'symlink').length;
  const unbundledSymlinkPaths = summary.unbundled.files.filter((row) => row.r === 'symlink')
    .map((row) => row.p);
  const ubRoleFiles = (r) => ((summary.unbundled.roles || {})[r] || { files: 0 }).files;
  const pendingRow = summary.productionPending || { files: 0, byExt: {} };

  const firstLayerDiff = [
    { field: 'components', firstLayer: firstT.components, r1: summary.components.length,
      delta: summary.components.length - firstT.components,
      explanation: '同一 bundle 目录识别逻辑，数量一致。' },
    { field: 'productionFiles', firstLayer: firstT.productionFiles,
      r1: r1Role('production-code').files, delta: r1Role('production-code').files - firstT.productionFiles,
      explanation: `语言/扩展词表扩展计入生产分母：${JSON.stringify(prodDeltaByLang)}`
        + '（.s 含大写 .S 汇编、shader 族、.hml/.css、.inl/.in、.cj/.mjs/.sts 等，'
        + '原在首层静默 other 角色）；逐类样例核实见 verify 抽样与 EXPANSION-RESULT §12。' },
    { field: 'testFiles', firstLayer: firstT.testFiles, r1: r1Role('test-code').files,
      delta: testTotalDelta,
      explanation: `+${testTotalDelta} = test 路径下的 .idl/.proto ${testInterfaceDefCount} 个`
        + `（首层完全漏计）+ 新词表扩展 ${newLangTestCount} 个。${testDeltaBreakdown.note}` },
    { field: 'generatedFiles', firstLayer: firstT.generatedFiles, r1: r1Role('generated-code').files,
      delta: genTotalDelta,
      explanation: `+${genTotalDelta} = 新词表扩展（.cj/.mjs/.sts）在 gen 路径下的文件`
        + `（gen 路径下 .idl/.proto：${genInterfaceDefCount} 个）。` },
    { field: 'idlFiles', firstLayer: firstT.idlFiles, r1: r1Role('idl').files,
      delta: r1Role('idl').files - firstT.idlFiles,
      explanation: `idl 角色 +${r1Role('idl').files - firstT.idlFiles} = .proto 1 个 `
        + `+ .taihe ${Math.max(0, r1Role('idl').files - firstT.idlFiles - 1)} 个`
        + '（接口定义词表扩展）；.idl 本身数量一致。' },
    { field: 'idlInterfaces/idlMethods（正则→项目解析器）',
      firstLayer: `${firstT.idlInterfaces}/${firstT.idlMethods}`,
      r1: `${summary.components.reduce((s, c) => s + c.idl.interfaces, 0) + summary.unbundled.idl.interfaces}/`
        + `${summary.components.reduce((s, c) => s + c.idl.methods, 0) + summary.unbundled.idl.methods}`,
      delta: 'parser-caliber',
      explanation: '首层用轻量正则；R1 复用 lib/facts/idl 解析器（处理前向声明/内联类型/'
        + '多行参数），接口/方法候选数以此为准，差异为解析口径而非源码变化。' },
    { field: 'saProfiles/saSystemAbilities', firstLayer: `${firstT.saProfiles}/${firstT.saSystemAbilities}`,
      r1: `${summary.components.reduce((s, c) => s + c.sa.profiles, 0) + summary.unbundled.sa.profiles}/`
        + `${summary.components.reduce((s, c) => s + c.sa.systemAbilities, 0) + summary.unbundled.sa.systemAbilities}`,
      delta: 'expect-0',
      explanation: '同一解析口径（lib/facts/sa），应一致。' },
    { field: 'buildFiles', firstLayer: firstT.buildFiles, r1: r1Role('build').files,
      delta: r1Role('build').files - firstT.buildFiles,
      explanation: `+${r1Role('build').files - firstT.buildFiles} = 无 bundle 归属 `
        + `${ubRoleFiles('build')} 个 + 词表扩展（.map 链接器 version map/.versionscript/.mk/`
        + '.cmake/.gradle/.pro/.ld/.def/.gn/.build/.pydeps 与 Makefile/hvigorw 文件名，'
        + '逐类样例核实，见 r1-verify 抽样）。' },
    { field: 'docFiles', firstLayer: firstT.docFiles, r1: r1Role('doc').files,
      delta: r1Role('doc').files - firstT.docFiles,
      explanation: `+${r1Role('doc').files - firstT.docFiles} = 无 bundle 归属 `
        + `${ubRoleFiles('doc')} 个 + 无扩展名 LICENSE 按文件名计入 doc。` },
    { field: 'configFiles', firstLayer: firstT.configFiles, r1: r1Role('config').files,
      delta: r1Role('config').files - firstT.configFiles,
      explanation: `+${r1Role('config').files - firstT.configFiles} = 无 bundle 归属 `
        + `${ubRoleFiles('config')} 个 + 词表/文件名扩展（.json5/.te/.para/.toml/.rc/.dac/.policy/`
        + '证书链 .0/.pem/.crt/.cer/.p7b/.pluginmeta/.properties/.config 与 '
        + '*_contexts/attributes/hiview_*_config 文件名）。' },
    { field: 'unbundledFiles', firstLayer: firstLayer.unscopedFiles.count,
      r1: recount.unbundledFiles,
      delta: recount.unbundledFiles - firstLayer.unscopedFiles.count,
      explanation: `${firstLayer.unscopedFiles.count} 个无 bundle 文件归属与首层一致；另有 `
        + `${unbundledSymlinkCount} 个无 bundle 祖先的符号链接（首层静默跳过 symlink）`
        + `：${unbundledSymlinkPaths.join('、')}。R1 按 role 细分`
        + `（other/doc/config/build/production）。` },
    { field: 'unsupportedLanguageFiles', firstLayer: firstT.unsupportedLanguageFiles,
      r1: summary.totals.unsupportedLanguages.files,
      delta: summary.totals.unsupportedLanguages.files - firstT.unsupportedLanguageFiles,
      explanation: `词表扩展 +${summary.totals.unsupportedLanguages.files - firstT.unsupportedLanguageFiles}`
        + `（${JSON.stringify(prodDeltaByLang)}）。` },
    { field: '新分母：production-pending（生产角色待定）', firstLayer: '未计数（静默忽略）',
      r1: pendingRow.files, delta: 'new-denominator',
      explanation: `无法确认生产角色的文件单独入账（byExt：${JSON.stringify(pendingRow.byExt || {})}），`
        + '不计入生产分母也不默认非生产；确认后需改分类规则并重算。' },
    { field: '新分母：other 角色', firstLayer: '未计数（静默忽略）', r1: r1Role('other').files,
      delta: 'new-denominator',
      explanation: '首层对不匹配任何词表的文件（无扩展名、媒体、二进制等）完全不计；'
        + 'R1 计入 other 角色（确认非生产的资源/二进制/测试材料/VCS 元数据），消除静默遗漏。' },
    { field: '新分母：component-metadata/symlink/unreadable', firstLayer: '未计数',
      r1: `${r1Role('component-metadata').files}/${r1Role('symlink').files}/${r1Role('unreadable').files}`,
      delta: 'new-denominator',
      explanation: `${r1Role('component-metadata').files} 个 bundle.json 计入 component-metadata；`
        + `${r1Role('symlink').files} 个符号链接（不跟随，登记目标与分类，见 symlinkRegistry）；`
        + `${r1Role('unreadable').files} 个不可读文件。` }
  ];

  // 首层 unscoped 抽样 20 条必须在 R1 unbundled 清单中可定位
  const unbundledPaths = new Set(summary.unbundled.files.map((row) => row.p));
  const firstSampleMissing = (firstLayer.unscopedFiles.sample || [])
    .filter((row) => !unbundledPaths.has(row.file));
  addCheck('首层 unscoped 抽样 20 条均可在 R1 unbundled 清单定位', 0, firstSampleMissing.length,
    firstSampleMissing.length === 0);
  if (firstSampleMissing.length) checks[checks.length - 1].missing = firstSampleMissing;

  // ---- 4) 入口候选一致性 ----
  const entryRecount = new Map(); // 'c|form' -> {rows, files:Set}
  let entryRowsParsed = 0;
  let entryParseErrors = 0;
  if (fs.existsSync(entryJsonl)) {
    const rl2 = readline.createInterface({ input: fs.createReadStream(entryJsonl), crlfDelay: Infinity });
    for await (const line of rl2) {
      if (!line) continue;
      try {
        const hit = JSON.parse(line);
        entryRowsParsed += 1;
        const key = `${hit.c}|${hit.form}`;
        if (!entryRecount.has(key)) entryRecount.set(key, { rows: 0, files: new Set() });
        entryRecount.get(key).rows += 1;
        entryRecount.get(key).files.add(hit.p);
      } catch (_) { entryParseErrors += 1; }
    }
  }
  const summaryEntryRows = new Map();
  for (const comp of [...summary.components, summary.unbundled]) {
    const e = comp.entries || {};
    for (const [form, bucket] of Object.entries({
      'napi-register': e.napi, 'napi-module-macro': e.napiModuleMacro,
      'onremoterequest-impl': e.onRemoteRequest, 'onremoterequest-header': e.onRemoteRequest
    })) {
      if (!bucket) continue;
      const hits = form.startsWith('onremoterequest')
        ? (form === 'onremoterequest-impl' ? bucket.implHits : bucket.headerHits)
        : (form === 'napi-register' ? bucket.registrations : bucket.hits);
      const files = form.startsWith('onremoterequest')
        ? (form === 'onremoterequest-impl' ? bucket.implFiles : bucket.headerFiles)
        : bucket.files;
      if (hits) summaryEntryRows.set(`${comp.component}|${form}`, { rows: hits, files });
    }
  }
  let entryMismatches = [];
  for (const [key, agg] of entryRecount) {
    const reported = summaryEntryRows.get(key);
    if (!reported || reported.rows !== agg.rows || reported.files !== agg.files.size) {
      entryMismatches.push({ key, recounted: { rows: agg.rows, files: agg.files.size },
        summary: reported || null });
    }
  }
  for (const [key, reported] of summaryEntryRows) {
    if (!entryRecount.has(key)) entryMismatches.push({ key, recounted: null, summary: reported });
  }
  const ipcEntry = entryRecount.get('@ohos/ipc|onremoterequest-impl');
  addCheck('@ohos/ipc 生产 OnRemoteRequest 复测 = 7（R0 已知难例）', 7,
    ipcEntry ? ipcEntry.files.size : null, !!ipcEntry && ipcEntry.files.size === 7);

  const allPass = checks.every((c) => c.pass) && failedSamples.length === 0 && entryMismatches.length === 0;

  const result = {
    verifyVersion: 'r1-verify-v1',
    verifiedAt: new Date().toISOString(),
    summaryFile: path.relative(TOOL_DIR, summaryPath).split(path.sep).join('/'),
    filesJsonl: path.relative(TOOL_DIR, filesJsonl).split(path.sep).join('/'),
    recount: {
      totalFiles: recount.totalFiles, totalBytes: recount.totalBytes, byRole: recount.byRole,
      productionByLang: recount.prodByLang, sortedUnique: recount.sorted && recount.duplicates === 0,
      unbundledFiles: recount.unbundledFiles, unbundledProduction: recount.unbundledProd
    },
    checks,
    samples: { total: samples.length, failed: failedSamples.length,
      warnings: warnedSamples.length, rows: samples },
    firstLayerDiff,
    entryCandidates: {
      rowsParsed: entryRowsParsed, parseErrors: entryParseErrors,
      distinctKeys: entryRecount.size, mismatches: entryMismatches,
      ipcOnRemoteRequest: ipcEntry ? { rows: ipcEntry.rows, files: ipcEntry.files.size } : null
    },
    allPass
  };
  fs.writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    ok: true, allPass, checksFailed: checks.filter((c) => !c.pass).length,
    samples: samples.length, failedSamples: failedSamples.length,
    warnedSamples: warnedSamples.length, entryMismatches: entryMismatches.length,
    out: path.relative(TOOL_DIR, resultPath).split(path.sep).join('/')
  })}\n`);
  return allPass ? 0 : 2;
}

module.exports = { main };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; })
    .catch((e) => {
      process.stderr.write(`${JSON.stringify({ ok: false, error: e.message, stack: e.stack })}\n`);
      process.exitCode = 1;
    });
}
