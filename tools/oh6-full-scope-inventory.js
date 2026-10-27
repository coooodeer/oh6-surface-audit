'use strict';

/**
 * tools/oh6-full-scope-inventory.js —— FULL-SCOPE-ROADMAP 第一层“范围基线”的只读清点。
 *
 * 只做文件系统清点，不解析 AST、不建事实、不跑审计：
 *   - 主范围：OpenHarmony/base、OpenHarmony/foundation；
 *   - 按最近 bundle.json 归属组件；区分生产代码 / 测试 / 生成 / 构建 / 文档 / 配置；
 *   - 语言直方图；IDL 文件/接口/方法；SA profile/systemability；
 *   - 明确记录未做项：函数/操作/构建变体/依赖/入口绑定（避免把文件清点冒充已审计）。
 * 输出 JSON + Markdown 到 out/autonomy/inventory/，不修改产品源码。
 *
 * 用法：node tools/oh6-full-scope-inventory.js [--json-only]
 */

const fs = require('node:fs');
const path = require('node:path');

const TOOL_DIR = path.resolve(__dirname, '..');
const WORKSPACE = path.resolve(TOOL_DIR, '..');
const SRC_ROOT = path.join(WORKSPACE, 'OpenHarmony');
const ROOTS = ['base', 'foundation'];
const OUT_DIR = path.join(TOOL_DIR, 'out', 'autonomy', 'inventory');
const OUT_JSON = path.join(OUT_DIR, 'full-scope-baseline.json');
const OUT_MD = path.join(OUT_DIR, 'full-scope-baseline.md');

const CODE_EXT = new Set(['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx']);
const TEST_RE = /(^|\/)(test|tests|unittest|fuzztest|mock|mocks|moduletest|systemtest|benchmark|benchmarks|example|examples|sample|samples)(\/|$)/i;
const GEN_RE = /(^|\/)(gen|generated|out)(\/|$)/i;
const DOC_EXT = new Set(['.md', '.txt', '.rst']);
const BUILD_NAMES = new Set(['BUILD.gn', 'bundle.json']);
const CONFIG_EXT = new Set(['.json', '.xml', '.yaml', '.yml', '.cfg', '.conf', '.ini']);
const OTHER_LANG = new Map([
  ['.js', 'javascript'], ['.ts', 'typescript'], ['.ets', 'arkts'], ['.rs', 'rust'],
  ['.py', 'python'], ['.sh', 'shell'], ['.go', 'go'], ['.java', 'java'], ['.kt', 'kotlin']
]);

function statSafe(abs) {
  try { return fs.statSync(abs); } catch (_) { return null; }
}

function listBundleDirs() {
  const dirs = [];
  const stack = ROOTS.map((root) => path.join(SRC_ROOT, root));
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    if (entries.some((entry) => entry.isFile() && entry.name === 'bundle.json')) dirs.push(dir);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'out') continue;
      stack.push(path.join(dir, entry.name));
    }
  }
  return dirs.sort((a, b) => a.length - b.length);
}

function bundleInfo(abs) {
  try {
    const doc = JSON.parse(fs.readFileSync(abs, 'utf8'));
    const component = doc.component || {};
    const deps = component.deps || {};
    return {
      name: doc.name || component.name || null,
      version: doc.version || null,
      label: doc.label || null,
      subsystem: component.subsystem || null,
      features: Array.isArray(component.features) ? component.features : [],
      adaptedSystemType: Array.isArray(component.adapted_system_type) ? component.adapted_system_type : [],
      depsComponents: Array.isArray(deps.components) ? deps.components : [],
      depsThirdParty: Array.isArray(deps.third_party) ? deps.third_party : []
    };
  } catch (_) { return { name: null, version: null, label: null, error: 'bundle-unparsable' }; }
}

function componentFor(abs, bundleDirs) {
  let match = null;
  for (const dir of bundleDirs) {
    if (abs === dir || abs.startsWith(`${dir}${path.sep}`)) match = dir;
  }
  return match;
}

function langOf(ext) {
  if (ext === '.c') return 'c';
  if (ext === '.cc' || ext === '.cpp' || ext === '.cxx') return 'cpp';
  if (['.h', '.hh', '.hpp', '.hxx'].includes(ext)) return 'header';
  return OTHER_LANG.get(ext) || 'other';
}

function scanBundleDirs(bundleDirs) {
  const bundles = new Map();
  for (const dir of bundleDirs) {
    const file = path.join(dir, 'bundle.json');
    const st = statSafe(file);
    bundles.set(dir, { dir, rel: path.relative(SRC_ROOT, dir).split(path.sep).join('/'),
      bytes: st ? st.size : 0, ...bundleInfo(file) });
  }
  return bundles;
}

function parseIdl(text) {
  const interfaces = [];
  const methods = [];
  const ifaceRe = /interface\s+([A-Za-z_][\w.]*)\s*(?::[^{]+)?\{/g;
  const methodRe = /^\s*(?:\[[^\]]*\]\s*)?(?:void|int|long|short|boolean|bool|float|double|String|unsigned\s+\w+|signed\s+\w+|IRemoteObject|[A-Za-z_][\w:<>,\s]*?\s*\*?)\s+([A-Za-z_]\w*)\s*\(/gm;
  let match;
  while ((match = ifaceRe.exec(text)) !== null) interfaces.push(match[1]);
  while ((match = methodRe.exec(text)) !== null) methods.push(match[1]);
  return { interfaces, methods };
}

function parseSaProfile(text) {
  try {
    const doc = JSON.parse(text);
    const list = Array.isArray(doc.systemability) ? doc.systemability : [];
    return { process: doc.process || null, systemAbilities: list.map((row) => row && row.name).filter(Boolean) };
  } catch (_) { return { process: null, systemAbilities: [], error: 'sa-profile-unparsable' }; }
}

function emptyComponent(bundle) {
  return {
    component: bundle.name || bundle.rel,
    root: bundle.rel,
    bundleJson: path.relative(SRC_ROOT, path.join(bundle.dir, 'bundle.json')).split(path.sep).join('/'),
    bundleBytes: bundle.bytes,
    subsystem: bundle.subsystem || null,
    production: { files: 0, bytes: 0, byLang: {} },
    test: { files: 0, bytes: 0 },
    generated: { files: 0, bytes: 0 },
    idl: { files: 0, interfaces: 0, methods: 0, interfacesDetail: [] },
    sa: { profiles: 0, systemAbilities: 0, detail: [] },
    build: { files: 0, features: bundle.features ? bundle.features.length : 0,
      adaptedSystemType: bundle.adaptedSystemType || [], compdbPart: 'unknown', compdb: 'unknown' },
    deps: { declaredComponents: bundle.depsComponents || [], declaredThirdParty: bundle.depsThirdParty || [],
      externalComponents: [] },
    docs: { files: 0 },
    config: { files: 0 },
    unsupportedLanguages: { files: 0, byLang: {} },
    status: 'not-analyzed',
    reasons: [
      'functions-and-operations-not-extracted',
      'build-variants-not-inventoried',
      'entry-binding-not-run',
      'dependencies-not-inventoried'
    ]
  };
}

function main(argv) {
  const jsonOnly = argv.includes('--json-only');
  const started = Date.now();
  const bundleDirs = listBundleDirs();
  const bundles = scanBundleDirs(bundleDirs);
  const components = new Map();
  const componentRows = () => [...components.values()];
  const totals = {
    components: bundles.size,
    productionFiles: 0, productionBytes: 0, testFiles: 0, testBytes: 0,
    generatedFiles: 0, idlFiles: 0, idlInterfaces: 0, idlMethods: 0,
    saProfiles: 0, saSystemAbilities: 0, buildFiles: 0, docFiles: 0, configFiles: 0,
    unsupportedLanguageFiles: 0,
    byLanguage: {}, byUnsupportedLanguage: {}
  };
  const unscoped = [];
  const stack = ROOTS.map((root) => ({ dir: path.join(SRC_ROOT, root), root }));
  while (stack.length) {
    const { dir } = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'out') continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) { stack.push({ dir: abs }); continue; }
      if (!entry.isFile()) continue;
      const rel = path.relative(SRC_ROOT, abs).split(path.sep).join('/');
      const relInside = rel.replace(/^(base|foundation)\//, '');
      const st = statSafe(abs);
      if (!st) continue;
      const ext = path.extname(entry.name).toLowerCase();
      const bundleDir = componentFor(abs, bundleDirs);
      const bundle = bundleDir ? bundles.get(bundleDir) : null;
      let row = null;
      if (bundle) {
        if (!components.has(bundleDir)) components.set(bundleDir, emptyComponent(bundle));
        row = components.get(bundleDir);
      } else {
        unscoped.push({ file: rel, bytes: st.size });
      }
      const addProduction = (lang) => {
        if (!row) return;
        row.production.files += 1; row.production.bytes += st.size;
        row.production.byLang[lang] = (row.production.byLang[lang] || 0) + 1;
      };
      if (CODE_EXT.has(ext) || OTHER_LANG.has(ext)) {
        const isTest = TEST_RE.test(`/${relInside}`);
        const isGen = GEN_RE.test(`/${relInside}`);
        const lang = langOf(ext);
        if (isTest) {
          if (!row) continue;
          row.test.files += 1; row.test.bytes += st.size;
          totals.testFiles += 1; totals.testBytes += st.size;
        } else if (isGen) {
          if (!row) continue;
          row.generated.files += 1; row.generated.bytes += st.size;
          totals.generatedFiles += 1;
        } else {
          addProduction(lang);
          totals.byLanguage[lang] = (totals.byLanguage[lang] || 0) + 1;
          // 当前事实层只解析 C/C++；其他语言计入生产分母但标 unsupported-language，
          // 不能因为“有文件”就声称这些语言已被抽取或审计。
          if (!['c', 'cpp', 'header'].includes(lang)) {
            if (row) {
              row.unsupportedLanguages.files += 1;
              row.unsupportedLanguages.byLang[lang] = (row.unsupportedLanguages.byLang[lang] || 0) + 1;
            }
            totals.unsupportedLanguageFiles += 1;
            totals.byUnsupportedLanguage[lang] = (totals.byUnsupportedLanguage[lang] || 0) + 1;
          }
        }
        if (!isTest && !isGen) {
          totals.productionFiles += 1;
          totals.productionBytes += st.size;
        }
      } else if (ext === '.idl') {
        if (TEST_RE.test(`/${relInside}`) || GEN_RE.test(`/${relInside}`)) continue;
        let parsed = { interfaces: [], methods: [] };
        try { parsed = parseIdl(fs.readFileSync(abs, 'utf8')); } catch (_) { /* 读失败保留 0 */ }
        if (row) {
          row.idl.files += 1; row.idl.interfaces += parsed.interfaces.length;
          row.idl.methods += parsed.methods.length;
          row.idl.interfacesDetail.push({ file: rel, interfaces: parsed.interfaces, methods: parsed.methods.length });
        }
        totals.idlFiles += 1; totals.idlInterfaces += parsed.interfaces.length; totals.idlMethods += parsed.methods.length;
      } else if (entry.name === 'BUILD.gn' || ext === '.gni') {
        if (row) { row.build.files += 1; totals.buildFiles += 1; }
      } else if (entry.name === 'bundle.json') {
        // 已计入组件元数据，不重复计构建文件
      } else if (relInside.includes('/sa_profile/') && ext === '.json') {
        let parsed = { process: null, systemAbilities: [] };
        try { parsed = parseSaProfile(fs.readFileSync(abs, 'utf8')); } catch (_) { /* ignore */ }
        if (row) {
          row.sa.profiles += 1; row.sa.systemAbilities += parsed.systemAbilities.length;
          row.sa.detail.push({ file: rel, process: parsed.process, systemAbilities: parsed.systemAbilities });
        }
        totals.saProfiles += 1; totals.saSystemAbilities += parsed.systemAbilities.length;
      } else if (DOC_EXT.has(ext)) {
        if (row) { row.docs.files += 1; totals.docFiles += 1; }
      } else if (CONFIG_EXT.has(ext)) {
        if (row) { row.config.files += 1; totals.configFiles += 1; }
      }
    }
  }

  // 没有 bundle.json 归属的文件不能静默消失：代码类单列 (no bundle.json) 账本。
  const unbundled = {
    files: unscoped.length, production: { files: 0, bytes: 0, byLang: {} },
    test: { files: 0, bytes: 0 }, generated: { files: 0 }, idl: { files: 0, methods: 0 },
    build: { files: 0 }, docs: { files: 0 }, config: { files: 0 },
    sample: unscoped.slice(0, 20).map((row) => row.file),
    reasons: ['no-bundle-json-ancestor', 'not-assigned-to-component', 'not-analyzed']
  };
  for (const item of unscoped) {
    const ext = path.extname(item.file).toLowerCase();
    const inside = item.file.replace(/^(base|foundation)\//, '');
    const isTest = TEST_RE.test(`/${inside}`);
    const isGen = GEN_RE.test(`/${inside}`);
    if (CODE_EXT.has(ext) || OTHER_LANG.has(ext)) {
      if (isTest) { unbundled.test.files += 1; unbundled.test.bytes += item.bytes; }
      else if (isGen) unbundled.generated.files += 1;
      else {
        const lang = langOf(ext);
        unbundled.production.files += 1; unbundled.production.bytes += item.bytes;
        unbundled.production.byLang[lang] = (unbundled.production.byLang[lang] || 0) + 1;
      }
    } else if (ext === '.idl' && !isTest && !isGen) {
      unbundled.idl.files += 1;
      try {
        const parsed = parseIdl(fs.readFileSync(path.join(SRC_ROOT, ...item.file.split('/')), 'utf8'));
        unbundled.idl.methods += parsed.methods.length;
      } catch (_) { /* keep 0 */ }
    } else if (ext === '.gni' || path.basename(item.file) === 'BUILD.gn') unbundled.build.files += 1;
    else if (DOC_EXT.has(ext)) unbundled.docs.files += 1;
    else if (CONFIG_EXT.has(ext)) unbundled.config.files += 1;
  }

  totals.productionByClass = {
    c: totals.byLanguage.c || 0,
    cpp: totals.byLanguage.cpp || 0,
    header: totals.byLanguage.header || 0,
    otherLanguages: totals.unsupportedLanguageFiles
  };
  const compdbDir = path.join(SRC_ROOT, 'out', 'rk3568', 'compdb_parts');  const compdbParts = [];
  if (fs.existsSync(compdbDir)) {
    for (const name of fs.readdirSync(compdbDir).sort()) {
      const file = path.join(compdbDir, name, 'compile_commands.json');
      const st = statSafe(file);
      if (st) compdbParts.push({ part: name, bytes: st.size });
    }
  }
  // 构建变体/compdb：只按 subsystem 名称做存在性映射；features 是构建开关清单，
  // 具体变体组合仍需构建配置解析，标 not-inventoried。
  const partNames = new Set(compdbParts.map((row) => row.part));
  const componentNames = new Set(componentRows().map((row) => row.component));
  const externalDeps = new Map();
  let componentsWithCompdb = 0;
  let totalFeatures = 0;
  for (const row of componentRows()) {
    if (row.subsystem && partNames.has(row.subsystem)) {
      row.build.compdbPart = row.subsystem;
      row.build.compdb = 'part-present';
      componentsWithCompdb += 1;
    } else {
      row.build.compdbPart = row.subsystem || null;
      row.build.compdb = 'part-absent-or-unknown';
    }
    totalFeatures += row.build.features;
    for (const dep of row.deps.declaredComponents) {
      if (componentNames.has(dep)) continue;
      row.deps.externalComponents.push(dep);
      externalDeps.set(dep, (externalDeps.get(dep) || 0) + 1);
    }
  }
  totals.componentsWithCompdbPart = componentsWithCompdb;
  totals.buildFeatures = totalFeatures;
  totals.declaredExternalComponents = externalDeps.size;
  totals.declaredExternalComponentRefs = [...externalDeps.values()].reduce((sum, n) => sum + n, 0);

  const result = {
    inventoryVersion: 'full-scope-baseline-v1',
    scannedAt: new Date().toISOString(),
    roots: ROOTS,
    sourceRoot: 'OpenHarmony',
    elapsedMs: Date.now() - started,
    tool: path.relative(TOOL_DIR, __filename).split(path.sep).join('/'),
    exclusions: {
      paths: ['.git', 'node_modules', 'out'],
      testPattern: TEST_RE.source,
      generatedPattern: GEN_RE.source,
      note: '测试/生成/文档/配置计入各自列，不计生产代码分母；函数/操作/构建变体/依赖/绑定未提取。'
    },
    totals,
    compdb: { parts: compdbParts, componentCoverage: 'mapped-by-subsystem-name', note: '只登记 part 存在与大小，未逐组件扫描 GB 级 compdb。' },
    buildVariants: {
      declaredFeatures: totalFeatures,
      componentsWithCompdbPart: componentsWithCompdb,
      note: 'features 是 bundle.json 声明的构建开关；实际变体组合/宏仍需构建配置解析，未提取。'
    },
    dependencies: {
      declaredExternalComponents: externalDeps.size,
      declaredExternalComponentRefs: [...externalDeps.values()].reduce((sum, n) => sum + n, 0),
      top: [...externalDeps.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40)
        .map(([component, refs]) => ({ component, refs })),
      note: '只清点 bundle.json 的 deps.components；未审计这些依赖，也未清点 include/链接级依赖。'
    },
    components: componentRows().sort((a, b) => b.production.files - a.production.files),
    unbundled,
    unscopedFiles: { count: unscoped.length, sample: unscoped.slice(0, 20) },
    notRun: {
      functions: '需要逐组件事实提取；本轮未做，函数分母未知',
      operations: '需要入口绑定与操作识别；本轮未做',
      entryBinding: '只清点 IDL/SA 入口，未运行绑定',
      buildVariants: 'compdb part 未映射到组件，变体分母未知',
      dependencies: 'base/foundation 外的必要依赖未清点',
      securityAssessment: '未做任何安全裁决；不得称已审计'
    }
  };
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_JSON, `${JSON.stringify(result, null, 2)}\n`, 'utf8');

  if (!jsonOnly) {
    const top = result.components.slice(0, 40);
    const lines = [
      '# OpenHarmony base/foundation 全范围基线（第一层）',
      '',
      `生成时间：${result.scannedAt}`,
      `扫描耗时：${result.elapsedMs} ms`,
      '',
      '## 总量',
      '',
      '| 项 | 数量 |',
      '|---|---:|',
      `| 组件（bundle.json） | ${totals.components} |`,
      `| 生产代码文件 | ${totals.productionFiles} |`,
      `| 生产代码字节 | ${totals.productionBytes} |`,
      `| 测试代码文件 | ${totals.testFiles} |`,
      `| 生成代码文件 | ${totals.generatedFiles} |`,
      `| IDL 文件 / 接口 / 方法 | ${totals.idlFiles} / ${totals.idlInterfaces} / ${totals.idlMethods} |`,
      `| SA profile / systemability | ${totals.saProfiles} / ${totals.saSystemAbilities} |`,
      `| 构建文件 | ${totals.buildFiles} |`,
      `| bundle 声明 features | ${totals.buildFeatures} |`,
      `| 有 compdb part 的组件 | ${totals.componentsWithCompdbPart} / ${totals.components} |`,
      `| 声明外部依赖组件（去重/引用） | ${totals.declaredExternalComponents} / ${totals.declaredExternalComponentRefs} |`,
      `| 非 C/C++ 生产文件（未支持语言） | ${totals.unsupportedLanguageFiles}（${Object.entries(totals.byUnsupportedLanguage).map(([k, v]) => `${k}:${v}`).join(', ') || 'none'}） |`,
      '',
      '## 生产文件最多的组件（前 40）',
      '',
      '| 组件 | 生产文件 | 字节 | C | C++ | 头文件 | IDL 方法 | SA |',
      '|---|---:|---:|---:|---:|---:|---:|---:|',
      ...top.map((row) => `| ${row.component} | ${row.production.files} | ${row.production.bytes} | ` +
        `${row.production.byLang.c || 0} | ${row.production.byLang.cpp || 0} | ` +
        `${row.production.byLang.header || 0} | ${row.idl.methods} | ${row.sa.systemAbilities} |`),
      '',
      '## 声明依赖（只清点，未审计）',
      '',
      `- 去重外部组件：${totals.declaredExternalComponents}；引用总数：${totals.declaredExternalComponentRefs}`,
      '- 前 20：' + (result.dependencies.top.slice(0, 20).map((row) => `${row.component}(${row.refs})`).join(', ') || 'none'),
      '- 说明：只解析 `bundle.json` 的 `deps.components`；include/链接级依赖与依赖审计未做。',
      '',
      '## 无 bundle.json 归属的文件（不静默丢弃）',
      '',
      `- 文件数：${unbundled.files}`,
      `- 生产代码：${unbundled.production.files} 文件 / ${unbundled.production.bytes} 字节 ` +
        `(${Object.entries(unbundled.production.byLang).map(([k, v]) => `${k}:${v}`).join(', ') || 'none'})`,
      `- IDL：${unbundled.idl.files} 文件 / ${unbundled.idl.methods} 方法`,
      `- 测试/生成：${unbundled.test.files} / ${unbundled.generated.files}`,
      '- 原因：没有 bundle.json 祖先，未归入组件；单列且标记 not-analyzed。',
      '',
      '## 明确未做（不得称已审计）',
      '',
      ...Object.entries(result.notRun).map(([key, value]) => `- **${key}**：${value}`),
      '',
      `完整组件表见 \`${path.relative(TOOL_DIR, OUT_JSON).split(path.sep).join('/')}\`。`
    ];
    fs.writeFileSync(OUT_MD, `${lines.join('\n')}\n`, 'utf8');
  }
  process.stdout.write(`${JSON.stringify({ ok: true, out: path.relative(TOOL_DIR, OUT_JSON).split(path.sep)
    .join('/'), markdown: jsonOnly ? null : path.relative(TOOL_DIR, OUT_MD).split(path.sep).join('/'),
    elapsedMs: result.elapsedMs, totals, compdbParts: compdbParts.length,
    unscopedFiles: unscoped.length })}\n`);
  return 0;
}

module.exports = { main };

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) { process.stderr.write(`${JSON.stringify({ ok: false, error: e.message })}\n`); process.exitCode = 1; }
}
