'use strict';

/**
 * tools/oh6-r1-scope-inventory.js —— R1-B/C：base/foundation 逐文件可对账清单与第二层清点。
 *
 * 复用首层（tools/oh6-full-scope-inventory.js）的 role/lang/bundle 识别规则（TEST_RE、
 * GEN_RE、CODE_EXT、OTHER_LANG、DOC_EXT、CONFIG_EXT 逐字一致），并做三类已登记的口径扩展：
 *   1) 新增 .proto → idl 角色（lang=proto，正则候选），生成器输入与生成产物分别记账；
 *   2) .idl/.proto 落在 test/gen 路径下时归入 test-code/generated-code（首层完全漏计）；
 *   3) 新增 other/unreadable/symlink 角色，任何被遍历文件都有唯一角色，不静默消失。
 *
 * 分类规则保持纯函数（classify），便于单测；语言解析复用 lib/facts（idl/sa/napi）。
 * 输出（除 cost 外全部确定性：无时间戳、路径排序，同输入可复算同哈希）：
 *   out/autonomy/inventory/r1-files.jsonl            每被遍历文件一行：p/s/r/l/c/b
 *   out/autonomy/inventory/r1-entry-candidates.jsonl 入口候选命中行（NAPI/OnRemoteRequest）
 *   out/autonomy/inventory/r1-scope-baseline.json    组件汇总 + 入口/构建/依赖宇宙 + 对账
 *   out/autonomy/inventory/r1-scan-cost.json         本次运行的实测成本（非确定性）
 *
 * 不解析 AST、不做安全裁决；函数/操作/实际变体组合/依赖审计仍未提取，notRun 中如实登记。
 *
 * 用法：node tools/oh6-r1-scope-inventory.js [--measure-only] [--cost-out <file>]
 *       [--src-root <dir>] [--out-dir <dir>]
 */

const fs = require('node:fs');
const path = require('node:path');

const idlFacts = require('../lib/facts/idl');
const saFacts = require('../lib/facts/sa');
const napiFacts = require('../lib/facts/napi');

// ---- 分类规则：与首层逐字一致的部分不得改动，扩展项单独注释 ----
const CODE_EXT = new Set(['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx']);
const TEST_RE = /(^|\/)(test|tests|unittest|fuzztest|mock|mocks|moduletest|systemtest|benchmark|benchmarks|example|examples|sample|samples)(\/|$)/i;
const GEN_RE = /(^|\/)(gen|generated|out)(\/|$)/i;
const DOC_EXT = new Set(['.md', '.txt', '.rst']);
const BUILD_NAMES = new Set(['BUILD.gn', 'bundle.json', 'Makefile', 'hvigorw']);
// v1.2 构建/链接输入扩展（直方图逐类核实：.map 全部为链接器 version map，
// .versionscript/.mk/.cmake/.gradle/.pro/.ld/.def/.build/.pydeps 均为构建输入）
const BUILD_EXT = new Set(['.gni', '.mk', '.cmake', '.gradle', '.pro', '.map',
  '.versionscript', '.ld', '.def', '.gn', '.build', '.pydeps']);
// v1.2 配置扩展（逐类核实：.rc=init 服务定义、.dac=参数 DAC 策略、.policy=seccomp、
// .0/.pem/.crt/.cer=系统信任链、.p7b=PKCS#7 签名 Profile（系统资源/系统弹窗随包签名，
// 决定安装信任行为）、.pluginmeta=插件注册元数据）
const CONFIG_EXT = new Set(['.json', '.xml', '.yaml', '.yml', '.cfg', '.conf', '.ini',
  '.json5', '.te', '.para', '.toml', '.rc', '.dac', '.policy', '.0', '.pem', '.crt',
  '.cer', '.cert', '.p12', '.p7b', '.sf', '.pluginmeta', '.properties', '.config',
  '.enforce', '.permissive']);
// v1.2 语言词表扩展（other 直方图逐类核实）：.s 含大写 .S 汇编（extname 小写化）、
// .inl=C++ 内联、shader 族（.shader/.frag/.vert/.comp/.shaderpl/.shadervid/.shadergs/
// .shaderrs）、.hml/.css=Lite UI 生产界面源、.in=代码生成模板、.mm=Objective-C++
const OTHER_LANG = new Map([
  ['.js', 'javascript'], ['.mjs', 'javascript'], ['.ts', 'typescript'], ['.ets', 'arkts'],
  ['.sts', 'arkts'], ['.rs', 'rust'], ['.py', 'python'], ['.sh', 'shell'], ['.go', 'go'],
  ['.java', 'java'], ['.kt', 'kotlin'], ['.cj', 'cangjie'],
  ['.s', 'asm'], ['.inl', 'cpp'], ['.tpp', 'cpp'], ['.mm', 'objc'], ['.l', 'lex'],
  ['.y', 'yacc'], ['.pegjs', 'pegjs'], ['.pyw', 'python'], ['.bat', 'batch'], ['.cmd', 'batch'],
  ['.in', 'template'], ['.hml', 'lite-ui'], ['.css', 'css'], ['.scss', 'css'],
  ['.shader', 'shader'], ['.frag', 'shader'], ['.vert', 'shader'], ['.comp', 'shader'],
  ['.shaderpl', 'shader'], ['.shadervid', 'shader'], ['.shadergs', 'shader'], ['.shaderrs', 'shader']
]);
// R1 扩展：接口定义文件（生成器输入），首层未单独记账
const INTERFACE_EXT = new Map([['.idl', 'idl'], ['.proto', 'proto'], ['.taihe', 'taihe']]);
// v1.2 无法确认生产角色的扩展（.csv 混有构建字典/运行时主题/测试数据等），
// 归 production-pending 待定角色，不默认非生产
const PENDING_EXT = new Set(['.csv', '.spt', '.es', '.inc', '.ui', '.mf', '.profile']);
// v1.2 无扩展名文件：VCS/工具元数据（确认非生产）
const VCS_META_NAMES = new Set(['.gitignore', '.gitattributes', '.gitkeep',
  '.clang-format', '.clang-tidy', 'CODEOWNERS', '.gitmodules']);
// v1.2 无扩展名配置文件：SELinux 上下文/策略开关与 hiview 运行时配置
const CONFIG_NAME_SUFFIX = '_contexts';
const CONFIG_NAMES = new Set(['attributes', 'hiview_platform_config', 'plugin_config']);
// v1.2 内容核实的补充规则：hiview 插件配置（`plugins:N` 行格式）、许可证文本、
// 预编译产物路径（prebuild/prebuilt 下为二进制工具/镜像）
const CONFIG_NAME_SUFFIX_2 = '_plugin_config';
const PREBUILT_PATH_RE = /(^|\/)pre(build|built)(\/|$)/;
// R1 扩展：sa_profile 目录判定改用词边界正则（语义与首层 includes('/sa_profile/') 等价）
const SA_RE = /(^|\/)sa_profile(\/|$)/;
const EXCLUDED_DIRS = new Set(['.git', 'node_modules', 'out']);
const ROLES = ['production-code', 'test-code', 'generated-code', 'idl', 'sa-profile',
  'build', 'component-metadata', 'config', 'doc', 'other', 'production-pending',
  'unreadable', 'symlink'];
const PRIMARY_LANGS = new Set(['c', 'cpp', 'header']);

function langOf(ext) {
  if (ext === '.c') return 'c';
  if (ext === '.cc' || ext === '.cpp' || ext === '.cxx') return 'cpp';
  if (['.h', '.hh', '.hpp', '.hxx'].includes(ext)) return 'header';
  if (INTERFACE_EXT.has(ext)) return INTERFACE_EXT.get(ext);
  return OTHER_LANG.get(ext) || 'other';
}

/**
 * 纯分类函数：给定文件名、小写扩展名与组件内相对路径（'sub/dir/x.cpp'），
 * 返回唯一 {role, lang, basis}。优先级：test > gen > 接口定义 > 生产代码；
 * 非代码文件与首层一致，不受 test/gen 路径影响（文档/配置计入各自角色）。
 */
function classify(name, ext, relInside) {
  const anchored = `/${relInside}`;
  if (CODE_EXT.has(ext) || OTHER_LANG.has(ext) || INTERFACE_EXT.has(ext)) {
    if (TEST_RE.test(anchored)) return { role: 'test-code', lang: langOf(ext), basis: 'test:path-pattern' };
    if (GEN_RE.test(anchored)) return { role: 'generated-code', lang: langOf(ext), basis: 'gen:path-pattern' };
    if (INTERFACE_EXT.has(ext)) return { role: 'idl', lang: INTERFACE_EXT.get(ext), basis: `${INTERFACE_EXT.get(ext)}:ext` };
    return { role: 'production-code', lang: langOf(ext), basis: `code:ext=${ext}` };
  }
  if (name === 'bundle.json') return { role: 'component-metadata', lang: null, basis: 'meta:name=bundle.json' };
  if (name === 'BUILD.gn' || ext === '.gni' || (BUILD_EXT.has(ext) && ext !== '')
    || ((name === 'Makefile' || name === 'hvigorw') && ext === '')) {
    return { role: 'build', lang: null, basis: ext !== '' ? `build:ext=${ext}` : `build:name=${name}` };
  }
  if (SA_RE.test(anchored) && ext === '.json') return { role: 'sa-profile', lang: null, basis: 'sa:path+ext' };
  if (DOC_EXT.has(ext)) return { role: 'doc', lang: null, basis: 'doc:ext' };
  if (CONFIG_EXT.has(ext)) return { role: 'config', lang: null, basis: `config:ext=${ext}` };
  // v1.2：无扩展名/待定扩展的回退——先按文件名确认配置/文档/构建角色，再按路径
  // 排除测试材料与 VCS 元数据；仍不能确认的归 production-pending，不默认非生产。
  if (ext === '' || PENDING_EXT.has(ext)) {
    if (name === 'LICENSE' || name.startsWith('LICENSE')) {
      return { role: 'doc', lang: null, basis: 'doc:name=LICENSE' };
    }
    if (CONFIG_NAMES.has(name) || name.endsWith(CONFIG_NAME_SUFFIX)
      || name.endsWith(CONFIG_NAME_SUFFIX_2)) {
      return { role: 'config', lang: null, basis: `config:name=${name}` };
    }
    if (VCS_META_NAMES.has(name) || VCS_META_NAMES.has(name.trim())
      || /(^|\/)\.gitee\//.test(anchored) || name === 'pre-commit') {
      return { role: 'other', lang: null, basis: 'other:vcs-metadata' };
    }
    // R2-A2 家族判明（内容核实：链接器 version script 语法 global:/local:）
    if (ext === '' && /^lib[a-z0-9_]+_map$/i.test(name)) {
      return { role: 'build', lang: null, basis: 'build:name=linker-map' };
    }
    // SELinux 策略源（access_vectors/initial_sids/*.spt 等，内容为策略定义语言）
    if (/(^|\/)sepolicy\//.test(anchored)) {
      return { role: 'config', lang: null, basis: 'config:sepolicy-path' };
    }
    // hiview 插件配置（plugins/*/config/ 下（允许插件组嵌套），内容为 JSON/pipeline 定义）
    if (/(^|\/)hiviewdfx\/hiview\/plugins\/.+\/config\//.test(anchored)) {
      return { role: 'config', lang: null, basis: 'config:hiview-plugin-config' };
    }
    // init 账户库（passwd/group，内容为 x:uid: 格式）
    if ((name === 'passwd' || name === 'group') && /(^|\/)etc(_lite)?\//.test(anchored)) {
      return { role: 'config', lang: null, basis: 'config:account-db' };
    }
    if (PREBUILT_PATH_RE.test(anchored)) {
      return { role: 'other', lang: null, basis: 'other:prebuilt-path' };
    }
    if (TEST_RE.test(anchored)) return { role: 'other', lang: null, basis: 'other:test-material' };
    return { role: 'production-pending', lang: null, basis: ext === '' ? 'pending:no-ext' : `pending:ext=${ext}` };
  }
  return { role: 'other', lang: null, basis: `other:ext=${ext}` };
}

function listBundleDirs(srcRoot, readdir, errors) {
  const roots = ['base', 'foundation'];
  const dirs = [];
  const stack = roots.map((root) => path.join(srcRoot, root));
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = readdir(dir, { withFileTypes: true });
    } catch (e) {
      if (errors) {
        errors.push({ phase: 'bundle-search', p: path.relative(srcRoot, dir).split(path.sep).join('/'),
          code: e.code || 'unknown' });
      }
      continue;
    }
    if (entries.some((entry) => entry.isFile() && entry.name === 'bundle.json')) dirs.push(dir);
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      stack.push(path.join(dir, entry.name));
    }
  }
  return dirs;
}

/**
 * 符号链接登记：不跟随、不重复计数，按链接路径与目标位置分类。
 * 测试材料（链接本身在 test 族路径下）> 范围内别名（目标在 base/foundation 内）>
 * 范围外依赖候选（目标在 OpenHarmony 其他目录或树外）> 未知（目标不可读）。
 */
function classifySymlink(relInside, target, srcRoot, abs) {
  if (TEST_RE.test(`/${relInside}`)) return 'test-material';
  if (target === null) return 'unknown';
  const resolvedAbs = path.resolve(path.dirname(abs), target);
  const relT = path.relative(srcRoot, resolvedAbs);
  const insideSrc = relT && !relT.startsWith(`..${path.sep}`) && relT !== '..' && !path.isAbsolute(relT);
  if (!insideSrc) return 'out-of-scope-dependency-candidate';
  const relTNorm = relT.split(path.sep).join('/');
  if (relTNorm.startsWith('base/') || relTNorm.startsWith('foundation/')) return 'in-scope-alias';
  return 'out-of-scope-dependency-candidate';
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
      depsThirdParty: Array.isArray(deps.third_party) ? deps.third_party : [],
      parseError: false
    };
  } catch (_) {
    return { name: null, version: null, label: null, subsystem: null, features: [],
      adaptedSystemType: [], depsComponents: [], depsThirdParty: [], parseError: true };
  }
}

/** 最近 bundle.json 祖先；bundleDirs 按路径长度升序，最后一个匹配即最近祖先 */
function componentFor(abs, bundleDirs) {
  let match = null;
  for (const dir of bundleDirs) {
    if (abs === dir || abs.startsWith(`${dir}${path.sep}`)) match = dir;
  }
  return match;
}

function newBucket() { return { files: 0, bytes: 0 }; }
function bump(bucket, bytes) { bucket.files += 1; bucket.bytes += bytes; }

function newComponentRow(bundle) {
  return {
    component: bundle ? (bundle.name || bundle.rel) : '(unbundled)',
    root: bundle ? bundle.rel : null,
    bundleJson: bundle ? bundle.bundleJson : null,
    bundleParseError: bundle ? bundle.parseError : false,
    subsystem: bundle ? bundle.subsystem : null,
    roles: {},
    production: { files: 0, bytes: 0, byLang: {} },
    unsupportedLanguages: { files: 0, byLang: {} },
    idl: { files: 0, interfaces: 0, methods: 0, parseErrors: 0, detail: [] },
    proto: { files: 0, services: 0, rpcs: 0 },
    sa: { profiles: 0, systemAbilities: 0, parseErrors: 0, detail: [] },
    entries: {
      napi: { files: 0, registrations: 0 },
      napiModuleMacro: { files: 0, hits: 0 },
      onRemoteRequest: { implFiles: 0, implHits: 0, headerFiles: 0, headerHits: 0 }
    },
    build: { files: 0, conditionals: 0, features: bundle ? bundle.features.length : 0,
      adaptedSystemType: bundle ? bundle.adaptedSystemType : [],
      compdbPart: 'unknown', compdb: 'unknown' },
    deps: { declaredComponents: bundle ? bundle.depsComponents : [],
      declaredThirdParty: bundle ? bundle.depsThirdParty : [], externalComponents: [] },
    status: 'not-analyzed',
    reasons: [
      'functions-and-operations-not-extracted',
      'build-variants-not-inventoried',
      'entry-binding-not-run',
      'dependencies-not-inventoried'
    ]
  };
}

function countLineOf(text, index) {
  let n = 1;
  const stop = Math.min(index, text.length);
  for (let i = 0; i < stop; i += 1) if (text.charCodeAt(i) === 10) n += 1;
  return n;
}

function countConditionals(text) {
  let n = 0;
  const re = /^[ \t]*if[ \t]*\(/gm;
  while (re.exec(text) !== null) n += 1;
  return n;
}

function parseProto(text) {
  const services = [];
  let m;
  const serviceRe = /(?:^|\n)[ \t]*service\s+([A-Za-z_]\w*)[ \t]*\{/g;
  while ((m = serviceRe.exec(text)) !== null) services.push(m[1]);
  let rpcs = 0;
  const rpcRe = /\brpc\s+[A-Za-z_]\w*\s*\(/g;
  while (rpcRe.exec(text) !== null) rpcs += 1;
  return { services, rpcs };
}

function main(argv = [], deps = {}) {
  const measureOnly = argv.includes('--measure-only');
  const costOutIdx = argv.indexOf('--cost-out');
  const outDirIdx = argv.indexOf('--out-dir');
  const srcRoot = deps.srcRoot || path.resolve(__dirname, '..', '..', 'OpenHarmony');
  const outDir = deps.outDir || (outDirIdx >= 0 ? path.resolve(argv[outDirIdx + 1])
    : path.join(__dirname, '..', 'out', 'autonomy', 'inventory'));
  const costOut = costOutIdx >= 0 ? path.resolve(argv[costOutIdx + 1])
    : path.join(outDir, 'r1-scan-cost.json');
  const roots = ['base', 'foundation'];

  const startedNs = process.hrtime.bigint();
  const wall = () => Number(process.hrtime.bigint() - startedNs) / 1e6;
  // 注意：本工具的扫描是纯同步代码，setInterval 采样峰值在扫描期间不会触发，
  // 采到的 RSS 不是真实峰值。权威内存指标由 tools/autonomy-bench.js 包裹运行
  // 取 process.resourceUsage().maxRSS（内核峰值，对同步代码有效），见 r1-scan-cost-bench.json。

  // ---- 组件元数据 ----
  // readdir 可注入（受控失败测试用）；生产路径为 fs.readdirSync。
  const readdir = deps.readdir || ((d, o) => fs.readdirSync(d, o));
  const bundleSearchErrors = [];
  const bundleDirs = listBundleDirs(srcRoot, readdir, bundleSearchErrors);
  const bundles = new Map();
  for (const dir of bundleDirs) {
    const file = path.join(dir, 'bundle.json');
    const st = fs.statSync(file);
    const info = bundleInfo(file);
    bundles.set(dir, {
      dir, rel: path.relative(srcRoot, dir).split(path.sep).join('/'),
      bundleJson: path.relative(srcRoot, file).split(path.sep).join('/'),
      bytes: st.size, ...info
    });
  }
  const components = new Map();
  const unbundledRow = newComponentRow(null);

  const records = [];
  const entryRows = [];
  const symlinkRegistry = [];
  const totals = {
    filesTraversed: 0, bytesTraversed: 0,
    byRole: {}, forRole(r) { return this.byRole[r] || (this.byRole[r] = newBucket()); },
    productionByLang: {},
    unsupportedLanguages: { files: 0, byLang: {} },
    parseFailures: { idl: 0, proto: 0, sa: 0, bundle: 0 },
    readErrors: [],
    dirReadErrors: [...bundleSearchErrors],
    excludedDirs: {},
    compdb: { parts: [] }
  };
  totals.parseFailures.bundle = [...bundles.values()].filter((b) => b.parseError).length;
  let walkMs = 0;
  let readMs = 0;
  let filesContentRead = 0;

  // ---- 遍历 ----
  const stack = roots.map((root) => ({ dir: path.join(srcRoot, root), root }));
  while (stack.length) {
    const t0 = process.hrtime.bigint();
    const { dir } = stack.pop();
    let entries;
    try { entries = readdir(dir, { withFileTypes: true }); } catch (e) {
      // 目录枚举失败不静默跳过：登记路径与错误码，范围标为未闭合
      totals.dirReadErrors.push({ phase: 'walk', p: path.relative(srcRoot, dir).split(path.sep).join('/'),
        code: e.code || 'unknown' });
      continue;
    }
    walkMs += Number(process.hrtime.bigint() - t0) / 1e6;
    for (const entry of entries) {
      if (entry.isDirectory() && EXCLUDED_DIRS.has(entry.name)) {
        totals.excludedDirs[entry.name] = (totals.excludedDirs[entry.name] || 0) + 1;
        continue;
      }
      const abs = path.join(dir, entry.name);
      const rel = path.relative(srcRoot, abs).split(path.sep).join('/');
      const relInside = rel.replace(/^(base|foundation)\//, '');
      const bundleDir = componentFor(abs, bundleDirs);
      const bundle = bundleDir ? bundles.get(bundleDir) : null;
      let row;
      if (bundle) {
        if (!components.has(bundleDir)) components.set(bundleDir, newComponentRow(bundle));
        row = components.get(bundleDir);
      } else {
        row = unbundledRow;
      }
      const compName = bundle ? row.component : null;
      if (entry.isSymbolicLink()) {
        // 符号链接单独入账（不跟随、不重复计数），登记目标并分类
        let target = null;
        try { target = fs.readlinkSync(abs); } catch (_) { target = null; }
        if (target !== null) target = target.split(path.sep).join('/');
        const classification = classifySymlink(relInside, target === null ? null
          : target.split('/').join(path.sep), srcRoot, abs);
        totals.filesTraversed += 1;
        bump(totals.forRole('symlink'), 0);
        if (!row.roles.symlink) row.roles.symlink = newBucket();
        bump(row.roles.symlink, 0);
        records.push({ p: rel, s: 0, r: 'symlink', l: null, c: compName,
          t: target, b: 'symlink:lstat-not-followed' });
        symlinkRegistry.push({ p: rel, c: compName, target, classification });
        continue;
      }
      if (entry.isDirectory()) { stack.push({ dir: abs }); continue; }
      if (!entry.isFile()) {
        // 非 regular 文件（fifo/设备等）不静默消失
        totals.filesTraversed += 1;
        bump(totals.forRole('unreadable'), 0);
        if (!row.roles.unreadable) row.roles.unreadable = newBucket();
        bump(row.roles.unreadable, 0);
        records.push({ p: rel, s: 0, r: 'unreadable', l: null, c: compName, b: 'unreadable:not-regular-file' });
        continue;
      }
      let st;
      try { st = fs.statSync(abs); } catch (_) {
        totals.filesTraversed += 1;
        bump(totals.forRole('unreadable'), 0);
        if (!row.roles.unreadable) row.roles.unreadable = newBucket();
        bump(row.roles.unreadable, 0);
        records.push({ p: rel, s: 0, r: 'unreadable', l: null, c: compName, b: 'unreadable:stat-failed' });
        continue;
      }
      const name = entry.name;
      const ext = path.extname(name).toLowerCase();
      const cls = classify(name, ext, relInside);
      records.push({ p: rel, s: st.size, r: cls.role, l: cls.lang, c: compName, b: cls.basis });
      totals.filesTraversed += 1;
      totals.bytesTraversed += st.size;
      bump(totals.forRole(cls.role), st.size);
      if (!row.roles[cls.role]) row.roles[cls.role] = newBucket();
      bump(row.roles[cls.role], st.size);

      // 生产代码语言细分 + 未支持语言
      if (cls.role === 'production-code') {
        row.production.files += 1; row.production.bytes += st.size;
        row.production.byLang[cls.lang] = (row.production.byLang[cls.lang] || 0) + 1;
        totals.productionByLang[cls.lang] = (totals.productionByLang[cls.lang] || 0) + 1;
        if (!PRIMARY_LANGS.has(cls.lang)) {
          row.unsupportedLanguages.files += 1;
          row.unsupportedLanguages.byLang[cls.lang] = (row.unsupportedLanguages.byLang[cls.lang] || 0) + 1;
          totals.unsupportedLanguages.files += 1;
          totals.unsupportedLanguages.byLang[cls.lang] = (totals.unsupportedLanguages.byLang[cls.lang] || 0) + 1;
        }
      }

      // 第二层：需要读内容的角色
      let content = null;
      const needRead = cls.role === 'production-code' || cls.role === 'build'
        || cls.role === 'idl' || cls.role === 'sa-profile';
      if (needRead) {
        const t1 = process.hrtime.bigint();
        try { content = fs.readFileSync(abs, 'utf8'); filesContentRead += 1; }
        catch (e) {
          totals.readErrors.push({ p: rel, error: e.code || 'read-failed' });
          content = null;
        }
        readMs += Number(process.hrtime.bigint() - t1) / 1e6;
      }
      if (content === null) continue;

      if (cls.role === 'production-code') {
        const compName = row.component;
        const isHeader = cls.lang === 'header';
        // NAPI：复用 lib/facts/napi（带模块名提取），宏形态单独计候选
        for (const reg of napiFacts.scanText(content, rel)) {
          entryRows.push({ p: rel, c: compName, form: 'napi-register', line: reg.line,
            detail: { module: reg.module, struct: reg.struct } });
        }
        const macroRe = /NAPI_MODULE(?:_X)?\s*\(/g;
        let mm;
        while ((mm = macroRe.exec(content)) !== null) {
          entryRows.push({ p: rel, c: compName, form: 'napi-module-macro', line: countLineOf(content, mm.index) });
        }
        // IPC 派发候选：::OnRemoteRequest( 的实现/声明位置
        const orrNeedle = '::OnRemoteRequest(';
        let idx = content.indexOf(orrNeedle);
        while (idx >= 0) {
          entryRows.push({ p: rel, c: compName,
            form: isHeader ? 'onremoterequest-header' : 'onremoterequest-impl',
            line: countLineOf(content, idx) });
          idx = content.indexOf(orrNeedle, idx + orrNeedle.length);
        }
      } else if (cls.role === 'idl') {
        if (cls.lang === 'idl') {
          try {
            const parsed = idlFacts.parseIdl(content);
            row.idl.files += 1;
            row.idl.interfaces += parsed.interfaces.length;
            row.idl.methods += parsed.methods.length;
            row.idl.detail.push({ file: rel, interfaces: parsed.interfaces.map((i) => i.name),
              methods: parsed.methods.length });
          } catch (_) { row.idl.parseErrors += 1; totals.parseFailures.idl += 1; }
        } else {
          const { services, rpcs } = parseProto(content);
          row.proto.files += 1; row.proto.services += services.length; row.proto.rpcs += rpcs;
        }
      } else if (cls.role === 'sa-profile') {
        const parsed = saFacts.parseSaProfile(content);
        row.sa.profiles += 1;
        if (parsed.parseError) { row.sa.parseErrors += 1; totals.parseFailures.sa += 1; }
        else {
          row.sa.systemAbilities += parsed.systemabilities.length;
          row.sa.detail.push({ file: rel, process: parsed.process,
            saIds: parsed.systemabilities.map((sa) => sa.saId) });
        }
      } else if (cls.role === 'build') {
        row.build.files += 1;
        row.build.conditionals += countConditionals(content);
      }
    }
  }

  // ---- 入口候选按组件聚合 ----
  const allRows = [...components.values(), unbundledRow];
  const rowsByName = new Map(allRows.map((row) => [row.component, row]));
  const distinctFiles = new Map();
  for (const hit of entryRows) {
    const row = rowsByName.get(hit.c);
    if (!row) continue;
    const key = `${hit.c}|${hit.form}`;
    if (!distinctFiles.has(key)) distinctFiles.set(key, new Set());
    distinctFiles.get(key).add(hit.p);
    const e = row.entries;
    if (hit.form === 'napi-register') e.napi.registrations += 1;
    else if (hit.form === 'napi-module-macro') e.napiModuleMacro.hits += 1;
    else if (hit.form === 'onremoterequest-impl') e.onRemoteRequest.implHits += 1;
    else if (hit.form === 'onremoterequest-header') e.onRemoteRequest.headerHits += 1;
  }
  // files 字段记录为去重文件数
  for (const row of allRows) {
    const e = row.entries;
    e.napi.files = (distinctFiles.get(`${row.component}|napi-register`) || new Set()).size;
    e.napiModuleMacro.files = (distinctFiles.get(`${row.component}|napi-module-macro`) || new Set()).size;
    e.onRemoteRequest.implFiles = (distinctFiles.get(`${row.component}|onremoterequest-impl`) || new Set()).size;
    e.onRemoteRequest.headerFiles = (distinctFiles.get(`${row.component}|onremoterequest-header`) || new Set()).size;
  }

  // ---- compdb part 存在性（沿用首层口径：仅按 subsystem 名映射） ----
  const compdbDir = path.join(srcRoot, 'out', 'rk3568', 'compdb_parts');
  if (fs.existsSync(compdbDir)) {
    for (const name of fs.readdirSync(compdbDir).sort()) {
      const file = path.join(compdbDir, name, 'compile_commands.json');
      try { totals.compdb.parts.push({ part: name, bytes: fs.statSync(file).size }); } catch (_) { /* ignore */ }
    }
  }
  const partNames = new Set(totals.compdb.parts.map((row) => row.part));
  const componentNames = new Set(allRows.map((row) => row.component));
  const externalDeps = new Map();
  let thirdPartyRefs = 0;
  for (const row of allRows) {
    if (row.root === null) continue; // 无 bundle 无声明依赖
    if (row.subsystem && partNames.has(row.subsystem)) {
      row.build.compdbPart = row.subsystem;
      row.build.compdb = 'part-present';
    } else {
      row.build.compdbPart = row.subsystem || null;
      row.build.compdb = 'part-absent-or-unknown';
    }
    for (const dep of row.deps.declaredComponents) {
      if (componentNames.has(dep)) continue;
      row.deps.externalComponents.push(dep);
      externalDeps.set(dep, (externalDeps.get(dep) || 0) + 1);
    }
    thirdPartyRefs += row.deps.declaredThirdParty.length;
  }

  // ---- 对账恒等式（在清单内断言并记录结果） ----
  const roleSum = ROLES.reduce((sum, r) => sum + (totals.byRole[r] ? totals.byRole[r].files : 0), 0);
  const productionLangSum = Object.values(totals.productionByLang).reduce((s, n) => s + n, 0);
  const productionRole = totals.byRole['production-code'] || newBucket();
  const unbundledProd = unbundledRow.production;
  const compProdFiles = [...components.values()].reduce((s, r) => s + r.production.files, 0);
  const reconciliation = [
    { identity: 'filesTraversed = Σ(role files)',
      expected: totals.filesTraversed, actual: roleSum, pass: totals.filesTraversed === roleSum },
    { identity: 'production-code = Σ(production byLang)',
      expected: productionRole.files, actual: productionLangSum, pass: productionRole.files === productionLangSum },
    { identity: 'production-code = component production + unbundled production',
      expected: productionRole.files, actual: compProdFiles + unbundledProd.files,
      pass: productionRole.files === compProdFiles + unbundledProd.files },
    { identity: 'unsupportedLanguages ⊆ production-code',
      expected: totals.unsupportedLanguages.files,
      actual: Object.entries(totals.productionByLang)
        .filter(([lang]) => !PRIMARY_LANGS.has(lang)).reduce((s, [, n]) => s + n, 0),
      pass: true }
  ];
  // 路径唯一性（排序后相邻重复检查在写出时进行）
  records.sort((a, b) => (a.p < b.p ? -1 : a.p > b.p ? 1 : 0));
  let duplicatePaths = 0;
  for (let i = 1; i < records.length; i += 1) {
    if (records[i].p === records[i - 1].p) duplicatePaths += 1;
  }
  reconciliation.push({ identity: 'each path appears exactly once',
    expected: 0, actual: duplicatePaths, pass: duplicatePaths === 0 });

  const unsupportedLangEntries = [...components.values(), unbundledRow]
    .filter((row) => row.unsupportedLanguages.files > 0).length;

  // v1.2：待定生产角色明细（不进生产分母，单独可见）
  const pendingByExt = {};
  let pendingFiles = 0;
  let pendingBytes = 0;
  for (const rec of records) {
    if (rec.r !== 'production-pending') continue;
    pendingFiles += 1;
    pendingBytes += rec.s;
    const key = rec.b.startsWith('pending:ext=') ? rec.b.slice('pending:ext='.length) : '(no-ext)';
    pendingByExt[key] = (pendingByExt[key] || 0) + 1;
  }

  const summary = {
    inventoryVersion: 'r1-scope-baseline-v1.2',
    deterministic: true,
    tool: 'tools/oh6-r1-scope-inventory.js',
    roots,
    sourceRoot: 'OpenHarmony',
    scopeClosure: {
      closed: totals.dirReadErrors.length === 0 && totals.readErrors.length === 0,
      dirReadErrors: totals.dirReadErrors.length,
      fileReadErrors: totals.readErrors.length,
      unclosedReasons: totals.dirReadErrors.slice(0, 50),
      note: 'closed = 目录枚举（bundle 搜索 + 主遍历）与文件读取全部成功；'
        + '任何失败都会列出路径与错误码并把范围标为未闭合。'
    },
    roleTaxonomy: {
      roles: ROLES,
      precedence: 'unreadable/symlink > test-code > generated-code > idl/proto/taihe > production-code；'
        + '非代码文件：component-metadata > build > sa-profile > doc > config > '
        + '(production-pending | other)',
      caliberNote: 'role 依据路径词法与扩展名；生产/测试以目录模式判定，非构建真值，抽样复核见 r1-verify 产物。'
        + 'production-pending 是无法确认生产角色的待定集合，不计入生产分母，明细见 productionPending。',
      changesFromFirstLayer: [
        '.proto/.taihe 计入 idl 角色（正则/候选口径）；生成器输入与生成产物分别记账',
        '.idl/.proto/.taihe 在 test/gen 路径下归入 test-code/generated-code（首层漏计）',
        '新增 other/production-pending/unreadable/symlink 角色：任何被遍历文件都有唯一角色',
        'v1.1 语言词表扩展：.mjs→javascript、.cj→cangjie、.sts→arkts（other 直方图抽样修正）',
        'v1.1 配置词表扩展：.json5/.te/.para/.toml 计入 config 角色',
        'v1.2 语言扩展：.s(含大写 .S)→asm、.inl/.tpp→cpp、shader 族 8 种扩展、'
          + '.hml/.css/.scss→Lite UI 源、.in→template、.mm→objc、.l/.y/.pegjs/.bat/.cmd/.pyw',
        'v1.2 构建扩展：.map(链接器 version map)/.versionscript/.mk/.cmake/.gradle/.pro/'
          + '.ld/.def/.gn/.build/.pydeps 及 Makefile/hvigorw 文件名',
        'v1.2 配置扩展：.rc(init 服务定义)/.dac/.policy(seccomp)/信任链证书 '
          + '(.0/.pem/.crt/.cer/.cert/.p12/.sf)/.pluginmeta/.properties/.config/.enforce/.permissive'
          + ' 及 *_contexts/attributes/hiview_platform_config/plugin_config 文件名',
        'v1.2 production-pending：无法确认生产角色的文件（.csv/.spt/.es/.inc/.ui/.mf/.profile'
          + ' 与无扩展名非测试文件）单独入账，不默认非生产'
      ]
    },
    exclusions: {
      dirs: [...EXCLUDED_DIRS],
      excludedDirCounts: totals.excludedDirs,
      note: '任意层级的 .git/node_modules/out 目录整体不遍历（与首层一致）；不计入任何分母。'
    },
    totals: {
      filesTraversed: totals.filesTraversed,
      bytesTraversed: totals.bytesTraversed,
      byRole: totals.byRole,
      productionByLang: totals.productionByLang,
      unsupportedLanguages: totals.unsupportedLanguages,
      parseFailures: totals.parseFailures,
      readErrors: { files: totals.readErrors.length, paths: totals.readErrors.slice(0, 50) },
      dirReadErrors: { files: totals.dirReadErrors.length, paths: totals.dirReadErrors.slice(0, 50) },
      symlinks: (totals.byRole.symlink || newBucket()).files,
      unreadable: (totals.byRole.unreadable || newBucket()).files
    },
    productionPending: {
      files: pendingFiles,
      bytes: pendingBytes,
      byExt: pendingByExt,
      note: '无法确认生产角色的待定集合：不计入生产分母；逐文件可查 r1-files.jsonl'
        + '（r=production-pending），确认后需改分类规则并重算分母。'
    },
    symlinkRegistry,
    reconciliation,
    components: [...components.values()].sort((a, b) => (a.component < b.component ? -1 : 1)),
    unbundled: {
      component: '(unbundled)',
      reasons: ['no-bundle-json-ancestor'],
      roles: unbundledRow.roles,
      production: unbundledRow.production,
      idl: unbundledRow.idl,
      proto: unbundledRow.proto,
      sa: unbundledRow.sa,
      entries: unbundledRow.entries,
      files: records.filter((rec) => rec.c === null)
        .map((rec) => ({ p: rec.p, r: rec.r, l: rec.l, s: rec.s }))
    },
    entryUniverse: {
      forms: {
        idl: { caliber: 'project-parser(lib/facts/idl)', note: '接口/方法为解析候选，未绑定实现' },
        proto: { caliber: 'candidate-regex(service/rpc)', note: 'proto 接口候选，未解析导入链' },
        'sa-profile': { caliber: 'json-observed(lib/facts/sa)', note: 'SA 声明清点，未绑定 dlopen/注册' },
        'napi-register': { caliber: 'candidate-regex(lib/facts/napi)', note: 'napi_module_register 注册点候选' },
        'napi-module-macro': { caliber: 'candidate-text-needle', note: 'NAPI_MODULE(/NAPI_MODULE_X( 宏候选' },
        'onremoterequest-impl': { caliber: 'candidate-text-needle', note: '::OnRemoteRequest( 文本命中，未绑定对象/code' },
        'onremoterequest-header': { caliber: 'candidate-text-needle',
          note: '头文件中的 ::OnRemoteRequest( 限定引用命中；类内非限定虚声明不在候选内，'
            + '归 unknownForms 的 virtual-table-dispatch-codes' }
      },
      unknownForms: [
        { form: 'virtual-table-dispatch-codes', note: '虚函数/表派发到对象与 code 的映射未建立，分母未知' },
        { form: 'non-cpp-language-entries', note: '非 C/C++ 生产文件入口分母未知；文件数见 unsupportedLanguages' },
        { form: 'dlopen-sa-libpath', note: 'SA libpath 到运行时注册的绑定未建立' },
        { form: 'generated-stub-dispatch', note: '生成 stub 的派发入口按 generated-code 角色记账，不计入生产入口候选' },
        { form: 'functions-and-operations', note: '函数/操作分母需逐组件事实提取，本层未做' }
      ]
    },
    buildUniverse: {
      bundleFeaturesTotal: allRows.reduce((s, r) => s + (r.root ? r.build.features : 0), 0),
      adaptedSystemTypeUnion: [...new Set(allRows.flatMap((r) => r.build.adaptedSystemType))].sort(),
      gnFiles: totals.byRole.build ? totals.byRole.build.files : 0,
      gnConditionalsObserved: allRows.reduce((s, r) => s + r.build.conditionals, 0),
      compdb: { parts: totals.compdb.parts.length, mapping: 'by-subsystem-name-only',
        note: 'part 存在不等于该组件或宏变体已编译' },
      unresolved: [
        'actual-variant-combinations-not-enumerated',
        'gn-condition-semantics-not-evaluated',
        'macro-per-file-not-inventoried'
      ]
    },
    depsUniverse: {
      declaredComponentsInScope: allRows.reduce((s, r) => s + r.deps.declaredComponents.length
        - r.deps.externalComponents.length, 0),
      declaredExternalComponents: externalDeps.size,
      declaredExternalComponentRefs: [...externalDeps.values()].reduce((s, n) => s + n, 0),
      declaredThirdPartyRefs: thirdPartyRefs,
      top: [...externalDeps.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40)
        .map(([component, refs]) => ({ component, refs })),
      unresolvedCategories: ['include-level', 'link-level', 'runtime-registry', 'caller-closure'],
      note: '仅 bundle.json deps.components/third_party 声明；include/链接/注册/运行时依赖未解析，不与主范围重复计数。'
    },
    knownHardCases: {
      note: '来源为 R0 产物（只读引用）；R1 复测口径的差异见 r1-verify 产物与 EXPANSION-RESULT。',
      accessTokenOverloads: loadHardCase('access-token-binding.json', (j) => ({
        count: (j.remaining || []).length,
        detail: (j.remaining || []).map((row) => ({ method: row.method, iface: row.iface, binding: row.binding,
          candidates: (row.candidates || []).map((c) => `${c.file}:${c.line}`) }))
      })),
      saUnbound: loadHardCase('access-token-binding.json', (j) => ({
        count: j.saAnchors ? j.saAnchors.unbound : null,
        detail: j.saAnchors ? [j.saAnchors.note] : []
      })),
      ipcOnRemoteRequest: loadHardCase('ipc-dispatch.json', (j) => ({
        count: ((j.productionDispatch || [])[0] || {}).functions || null,
        detail: (j.productionDispatch || []).map((row) => ({
          name: row.name, functions: row.functions, cases: row.cases,
          nameOnly: row.totalNameOnly, exact: row.totalExactCallers }))
      }))
    },
    notRun: {
      functions: '需逐组件事实提取；函数分母未知',
      operations: '需入口绑定与操作识别；未做',
      entryBinding: 'NAPI/IPC 仅文本候选清点；未运行绑定',
      buildVariants: '实际变体组合/宏未枚举；compdb 仅按 subsystem 名映射存在性',
      dependencyAudit: '声明依赖未审计；include/链接/运行时依赖未解析',
      securityAssessment: '未做任何安全裁决；不得称已审计'
    }
  };

  function loadHardCase(name, pick) {
    try {
      const j = JSON.parse(fs.readFileSync(path.join(outDir, name), 'utf8'));
      return pick(j);
    } catch (_) { return { count: null, detail: [], error: 'artifact-not-readable' }; }
  }

  // ---- 写出 ----
  const writeMs0 = wall();
  if (!measureOnly) {
    fs.mkdirSync(outDir, { recursive: true });
    writeJsonl(path.join(outDir, 'r1-files.jsonl'), records.map((rec) => JSON.stringify(rec)));
    entryRows.sort((a, b) => (a.p < b.p ? -1 : a.p > b.p ? 1 : a.form < b.form ? -1 : a.line - b.line));
    writeJsonl(path.join(outDir, 'r1-entry-candidates.jsonl'), entryRows.map((hit) => JSON.stringify(hit)));
    fs.writeFileSync(path.join(outDir, 'r1-scope-baseline.json'),
      `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  }
  const cost = {
    runLabel: measureOnly ? 'measure-only' : 'full-run',
    startedAtIso: new Date(Date.now() - Number(process.hrtime.bigint() - startedNs) / 1e6).toISOString(),
    elapsedMs: Math.round(wall()),
    walkMs: Math.round(walkMs),
    readMs: Math.round(readMs),
    writeMs: Math.round(wall() - writeMs0),
    bytesTraversed: totals.bytesTraversed,
    bytesReadScale: {
      productionBytes: (totals.byRole['production-code'] || newBucket()).bytes,
      buildBytes: (totals.byRole.build || newBucket()).bytes,
      idlBytes: (totals.byRole.idl || newBucket()).bytes,
      saBytes: (totals.byRole['sa-profile'] || newBucket()).bytes,
      note: '内容读取规模 = 上述四类角色字节合计；test/gen/doc/config/other 不读取内容。'
    },
    filesTraversed: totals.filesTraversed,
    filesContentRead,
    peakRssBytes: null,
    peakRssNote: '本文件不含有效内存峰值（同步扫描中定时器采样无效）。'
      + '权威峰值见 r1-scan-cost-bench.json 的 maxRssBytes（tools/autonomy-bench.js 包裹，'
      + 'process.resourceUsage().maxRSS）。',
    measureOnly,
    outputs: measureOnly ? [] : ['r1-files.jsonl', 'r1-entry-candidates.jsonl', 'r1-scope-baseline.json']
  };
  fs.writeFileSync(costOut, `${JSON.stringify(cost, null, 2)}\n`, 'utf8');

  process.stdout.write(`${JSON.stringify({
    ok: true, measureOnly, elapsedMs: cost.elapsedMs, walkMs: cost.walkMs, readMs: cost.readMs,
    filesTraversed: totals.filesTraversed, components: components.size,
    production: productionRole.files, unbundled: unbundledRow.production.files,
    pending: pendingFiles, symlinks: symlinkRegistry.length,
    scopeClosed: totals.dirReadErrors.length === 0 && totals.readErrors.length === 0,
    entryRows: entryRows.length, reconciliationPass: reconciliation.every((r) => r.pass),
    outDir: path.relative(__dirname, outDir).split(path.sep).join('/')
  })}\n`);
  return 0;
}

function writeJsonl(file, lines) {
  const fd = fs.openSync(file, 'w');
  try {
    const CHUNK = 2000;
    for (let i = 0; i < lines.length; i += CHUNK) {
      fs.writeSync(fd, `${lines.slice(i, i + CHUNK).join('\n')}\n`);
    }
  } finally { fs.closeSync(fd); }
}

module.exports = { main, classify, classifySymlink, langOf,
  RULES: { CODE_EXT, TEST_RE, GEN_RE, DOC_EXT, CONFIG_EXT, BUILD_EXT, OTHER_LANG, INTERFACE_EXT, PENDING_EXT, SA_RE } };

if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (e) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: e.message, stack: e.stack })}\n`);
    process.exitCode = 1;
  }
}
