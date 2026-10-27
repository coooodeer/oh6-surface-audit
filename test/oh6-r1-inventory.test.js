'use strict';

/**
 * test/oh6-r1-inventory.test.js —— R1 清点工具的直接测试。
 *
 * 覆盖：
 *   - classify() 优先级：test > gen > 接口定义 > 生产；v1.2 词表（.s/.S 汇编、shader 族、
 *     .taihe、.map→build、.rc/.dac→config、.hml/.css、.inl、LICENSE/Makefile/*_contexts
 *     文件名规则、无扩展名 corpus→other、无扩展名生产路径→production-pending）。
 *   - classifySymlink()：测试材料 / 范围内别名 / 范围外依赖候选 / 未知。
 *   - 端到端 fixture：生产/测试/生成/无 bundle/解析失败/入口候选/待定角色/符号链接登记。
 *   - 目录枚举失败可见（deps.readdir 注入 EACCES）：bundle 搜索与主遍历都登记，
 *     scopeClosure.closed=false。
 *   - 对账恒等式与确定性：同输入两次运行 r1-files.jsonl 字节一致。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const inventory = require('../tools/oh6-r1-scope-inventory.js');
const { classify, classifySymlink } = inventory;

function writeTree(root) {
  const w = (rel, content) => {
    const abs = path.join(root, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  };
  // 两棵根目录都要存在，否则缺失根会正确地把范围标为未闭合
  fs.mkdirSync(path.join(root, 'foundation'), { recursive: true });
  // 组件 A：完整形态
  w('base/compA/bundle.json', JSON.stringify({
    name: '@ohos/compa', component: { subsystem: 'testsub', features: ['fea_a'],
      adapted_system_type: ['standard'],
      deps: { components: ['hilog', '@ohos/compa'], third_party: ['openssl'] } }
  }));
  w('base/compA/BUILD.gn', 'import("//build/ohos.gni")\nif (is_ohos) {\n  ohos_shared_library("x") {}\n}\n');
  w('base/compA/src/main.cpp',
    '#include <cstdio>\nstatic napi_module g_m = {};\n'
    + 'namespace demo { int Foo::OnRemoteRequest(uint32_t code) { return 0; } }\n'
    + 'int main() { napi_module_register(&g_m); return 0; }\n');
  w('base/compA/src/stub.h', '#pragma once\nnamespace demo { int OnRemoteRequest(uint32_t code); }\n'
    + 'int call_fwd(uint32_t c) { return demo::OnRemoteRequest(c); }\n');
  w('base/compA/src/vector.s', '.globl demo_asm\ndemo_asm:\n  ret\n');
  // Windows 大小写不敏感：.S 与 .s 不能同目录，放 asm/ 下模拟大写汇编
  w('base/compA/src/asm/vector.S', '#include <asm.h>\n.globl demo_asm_pp\n');
  w('base/compA/src/inline_impl.inl', 'inline int impl(int x) { return x; }\n');
  w('base/compA/assets/skybox.frag', 'precision mediump float;\nvoid main() {}\n');
  w('base/compA/assets/bloom.comp', '#version 320 es\nvoid main() {}\n');
  w('base/compA/idl/ohos.demo.taihe', 'interface OHOS.Demo.ITaihe { Ping(): void; }\n');
  w('base/compA/linker/libsandbox.map', 'LIBSANDBOX {\n  global:\n    sandbox_init;\n};\n');
  w('base/compA/linker/libx.versionscript', 'LIBX_1.0 { global: x_init; };\n');
  w('base/compA/etc/demo_service.rc', 'service demo /system/bin/demo\n    seclabel u:r:demo:s0\n');
  w('base/compA/param/account.para.dac', 'demo:param = 1 # u:r:demo:s0\n');
  w('base/compA/sepolicy/file_contexts', '/system/bin/demo u:object_r:demo_exec:s0\n');
  w('base/compA/LICENSE', 'Apache License 2.0\n');
  w('base/compA/Makefile', 'all:\n\techo demo\n');
  w('base/compA/conf/settings.csv', 'k,v\na,1\n');
  w('base/compA/unknownfile', 'unclassified content');
  w('base/compA/noext', 'plain file without extension');
  w('base/compA/test/unittest/t.cpp', '#include <gtest/gtest.h>\nTEST(a, b) { ASSERT_EQ(1, 1); }\n');
  w('base/compA/test/t.idl', 'interface OHOS.Demo.IFoo { void Ping(); }\n');
  w('base/compA/test/fuzztest/x_fuzzer/corpus/init', 'fuzz seed data');
  w('base/compA/gen/g.cpp', '// generated\nvoid gen_fn() {}\n');
  w('base/compA/sa_profile/sa.json', JSON.stringify({ process: 'demo',
    systemability: [{ name: 4101, libpath: 'libdemo.z.so' }] }));
  w('base/compA/sa_profile/bad.json', '{not json');
  w('base/compA/ifoo.idl', 'package OHOS.Demo;\ninterface OHOS.Demo.IBar {\n'
    + '    void Poke([in] int x);\n}\n');
  w('base/compA/svc.proto', 'syntax = "proto3";\nservice DemoSvc { rpc Ping(PingReq) returns (PingRsp); }\n');
  w('base/compA/conf.json', '{"cfg": true}');
  w('base/compA/conf.json5', '{ cfg5: true }');
  w('base/compA/allowed.te', 'allow demo_t demo_data_file:file { read };\n');
  w('base/compA/params.para', 'demo.param = 1\n');
  w('base/compA/docs/readme.md', '# demo\n');
  w('base/compA/logo.png', 'not-a-real-png');
  // 组件 B：bundle.json 解析失败（name 缺失 → 用相对路径当组件名）
  w('base/compB/bundle.json', '{ broken json');
  w('base/compB/src/b.cpp', 'int b() { return 1; }\n');
  // 无 bundle 归属
  w('base/noBundle/src/orphan.cpp', 'int orphan() { return 2; }\n');
  w('base/noBundle/data.bin', '\u0000\u0001\u0002bin');
  w('base/noBundle/Makefile', 'all:\n\techo orphan\n');
}

test('classify 优先级与 v1.2 词表', () => {
  assert.deepStrictEqual(classify('x.cpp', '.cpp', 'test/unittest/x.cpp'),
    { role: 'test-code', lang: 'cpp', basis: 'test:path-pattern' });
  assert.deepStrictEqual(classify('t.idl', '.idl', 'test/t.idl'),
    { role: 'test-code', lang: 'idl', basis: 'test:path-pattern' });
  assert.deepStrictEqual(classify('g.idl', '.idl', 'gen/g.idl'),
    { role: 'generated-code', lang: 'idl', basis: 'gen:path-pattern' });
  assert.deepStrictEqual(classify('x.cpp', '.cpp', 'src/x.cpp'),
    { role: 'production-code', lang: 'cpp', basis: 'code:ext=.cpp' });
  assert.deepStrictEqual(classify('svc.proto', '.proto', 'src/svc.proto'),
    { role: 'idl', lang: 'proto', basis: 'proto:ext' });
  assert.deepStrictEqual(classify('ohos.demo.taihe', '.taihe', 'idl/ohos.demo.taihe'),
    { role: 'idl', lang: 'taihe', basis: 'taihe:ext' });
  assert.deepStrictEqual(classify('getcontext_x86_64.S', '.s', 'src/registers/getcontext_x86_64.S'),
    { role: 'production-code', lang: 'asm', basis: 'code:ext=.s' });
  assert.deepStrictEqual(classify('bloom.comp', '.comp', 'assets/shaders/bloom.comp'),
    { role: 'production-code', lang: 'shader', basis: 'code:ext=.comp' });
  assert.deepStrictEqual(classify('skybox.frag', '.frag', 'assets/skybox.frag'),
    { role: 'production-code', lang: 'shader', basis: 'code:ext=.frag' });
  assert.deepStrictEqual(classify('index.hml', '.hml', 'js/widget/pages/index/index.hml'),
    { role: 'production-code', lang: 'lite-ui', basis: 'code:ext=.hml' });
  assert.deepStrictEqual(classify('index.hml', '.hml', 'test/resource/hap/index.hml'),
    { role: 'test-code', lang: 'lite-ui', basis: 'test:path-pattern' });
  assert.deepStrictEqual(classify('output_p.inl', '.inl', 'frameworks/vsnprintf/output_p.inl'),
    { role: 'production-code', lang: 'cpp', basis: 'code:ext=.inl' });
  assert.deepStrictEqual(classify('libsandbox_manager_sdk.map', '.map', 'interfaces/libsandbox_manager_sdk.map'),
    { role: 'build', lang: null, basis: 'build:ext=.map' });
  assert.deepStrictEqual(classify('librawfile.versionscript', '.versionscript', 'frameworks/librawfile.versionscript'),
    { role: 'build', lang: null, basis: 'build:ext=.versionscript' });
  assert.deepStrictEqual(classify('sandbox_manager_service.rc', '.rc', 'services/sandbox_manager_service.rc'),
    { role: 'config', lang: null, basis: 'config:ext=.rc' });
  assert.deepStrictEqual(classify('account.para.dac', '.dac', 'param/account.para.dac'),
    { role: 'config', lang: null, basis: 'config:ext=.dac' });
  assert.deepStrictEqual(classify('app.seccomp.policy', '.policy', 'seccomp_policy/app.seccomp.policy'),
    { role: 'config', lang: null, basis: 'config:ext=.policy' });
  // 真实样例：SystemResources.p7b 为 PKCS#7 签名 Profile（OID 1.2.840.113549.1.7.2），
  // 随系统资源发布并决定安装信任行为；v1.2 曾漏配该扩展致 296 个落入 other
  assert.deepStrictEqual(classify('SystemResources.p7b', '.p7b', 'systemres/SystemResources.p7b'),
    { role: 'config', lang: null, basis: 'config:ext=.p7b' });
  assert.deepStrictEqual(classify('LICENSE', '', 'LICENSE'),
    { role: 'doc', lang: null, basis: 'doc:name=LICENSE' });
  assert.deepStrictEqual(classify('LICENSE_Fonts', '', 'system_resources/LICENSE_Fonts'),
    { role: 'doc', lang: null, basis: 'doc:name=LICENSE' });
  assert.deepStrictEqual(classify('eventloggerso_plugin_config', '', 'plugins/eventlogger/config/eventloggerso_plugin_config'),
    { role: 'config', lang: null, basis: 'config:name=eventloggerso_plugin_config' });
  assert.deepStrictEqual(classify('zic', '', 'data/prebuild/tool/linux/zic'),
    { role: 'other', lang: null, basis: 'other:prebuilt-path' });
  // R2-A2 家族判明（内容核实的真实样例）
  assert.deepStrictEqual(classify('libprivacy_map', '', 'services/privacymanager/libprivacy_map'),
    { role: 'build', lang: null, basis: 'build:name=linker-map' });
  assert.deepStrictEqual(classify('access_vectors', '', 'sepolicy/base/system/access_vectors'),
    { role: 'config', lang: null, basis: 'config:sepolicy-path' });
  assert.deepStrictEqual(classify('glb_perm_def.spt', '.spt', 'sepolicy/base/public/glb_perm_def.spt'),
    { role: 'config', lang: null, basis: 'config:sepolicy-path' });
  assert.deepStrictEqual(classify('EventloggerPipeline', '', 'base/hiviewdfx/hiview/plugins/eventlogger/config/EventloggerPipeline'),
    { role: 'config', lang: null, basis: 'config:hiview-plugin-config' });
  assert.deepStrictEqual(classify('passwd', '', 'services/etc/passwd'),
    { role: 'config', lang: null, basis: 'config:account-db' });
  assert.deepStrictEqual(classify('pre-commit', '', 'hooks/pre-commit'),
    { role: 'other', lang: null, basis: 'other:vcs-metadata' });
  assert.deepStrictEqual(classify('prefabrication', '', 'etc/libphonenumber/prefabrication'),
    { role: 'production-pending', lang: null, basis: 'pending:no-ext' });
  assert.deepStrictEqual(classify('Makefile', '', 'build/Makefile'),
    { role: 'build', lang: null, basis: 'build:name=Makefile' });
  assert.deepStrictEqual(classify('file_contexts', '', 'sepolicy/file_contexts'),
    { role: 'config', lang: null, basis: 'config:name=file_contexts' });
  assert.deepStrictEqual(classify('.gitignore', '', '.gitignore'),
    { role: 'other', lang: null, basis: 'other:vcs-metadata' });
  assert.deepStrictEqual(classify('init', '', 'test/fuzztest/x_fuzzer/corpus/init'),
    { role: 'other', lang: null, basis: 'other:test-material' });
  assert.deepStrictEqual(classify('unknownfile', '', 'services/unknownfile'),
    { role: 'production-pending', lang: null, basis: 'pending:no-ext' });
  assert.deepStrictEqual(classify('settings.csv', '.csv', 'conf/settings.csv'),
    { role: 'production-pending', lang: null, basis: 'pending:ext=.csv' });
  assert.deepStrictEqual(classify('allowed.te', '.te', 'sepolicy/allowed.te'),
    { role: 'config', lang: null, basis: 'config:ext=.te' });
  assert.deepStrictEqual(classify('tool.cj', '.cj', 'src/tool.cj'),
    { role: 'production-code', lang: 'cangjie', basis: 'code:ext=.cj' });
  assert.deepStrictEqual(classify('sa.json', '.json', 'sa_profile/sa.json'),
    { role: 'sa-profile', lang: null, basis: 'sa:path+ext' });
});

test('classifySymlink 四类判定', () => {
  const srcRoot = 'D:/tree/OpenHarmony';
  // 测试材料：链接本身在 test 路径下（优先于目标位置）
  assert.strictEqual(classifySymlink('x/test/fuzztest/c/corpus/H264.mp4', '../media/H264.mp4',
    srcRoot, path.join(srcRoot, 'base/x/test/fuzztest/c/corpus/H264.mp4')), 'test-material');
  // 范围内别名：目标在 base/ 下
  assert.strictEqual(classifySymlink('services/init/include/init_cmdexecutor.h', 'init_cmdexecutor_real.h',
    srcRoot, path.join(srcRoot, 'base/startup/init/services/init/include/init_cmdexecutor.h')),
  'in-scope-alias');
  // 范围外依赖候选：目标在 OpenHarmony 其他目录（如 third_party）
  assert.strictEqual(classifySymlink('mindspore', '../../third_party/mindspore',
    srcRoot, path.join(srcRoot, 'foundation/ai/mindspore')), 'out-of-scope-dependency-candidate');
  // 范围外依赖候选：目标在树外
  assert.strictEqual(classifySymlink('ext', 'D:/elsewhere/lib', srcRoot,
    path.join(srcRoot, 'base/x/ext')), 'out-of-scope-dependency-candidate');
  // 未知：目标不可读
  assert.strictEqual(classifySymlink('x', null, srcRoot, path.join(srcRoot, 'base/x/x')), 'unknown');
});

test('端到端 fixture：角色计数、解析失败、入口候选、待定角色、符号链接、对账与确定性',
  { concurrency: false }, () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-r1-inv-'));
    const srcRoot = path.join(tmp, 'src');
    const outDir = path.join(tmp, 'out');
    writeTree(srcRoot);
    let symlinkOk = false;
    try {
      fs.symlinkSync('src/main.cpp', path.join(srcRoot, 'base', 'compA', 'link.cpp'), 'file');
      symlinkOk = true;
    } catch (_) { /* 平台不支持则跳过 symlink 断言 */ }

    const r1 = JSON.parse(runCapture(() => inventory.main(['--cost-out', path.join(outDir, 'c1.json')],
      { srcRoot, outDir })));
    const summary = JSON.parse(fs.readFileSync(path.join(outDir, 'r1-scope-baseline.json'), 'utf8'));
    const t = summary.totals;

    const expect = {
      'production-code': 9, // main.cpp stub.h vector.s vector.S inline_impl.inl skybox.frag
                            // bloom.comp orphan.cpp b.cpp
      'test-code': 2,       // t.cpp + t.idl（corpus/init 无扩展名→other:test-material）
      'generated-code': 1,
      idl: 3,               // ifoo.idl + svc.proto + ohos.demo.taihe
      'sa-profile': 2,      // sa.json + bad.json
      build: 5,             // BUILD.gn + .map + .versionscript + compA/Makefile + noBundle/Makefile
      'component-metadata': 2,
      config: 7,            // conf.json conf.json5 allowed.te params.para .rc .dac file_contexts
      doc: 2,               // readme.md + LICENSE
      other: 3,             // logo.png data.bin corpus/init
      'production-pending': 3 // settings.csv unknownfile noext
    };
    assert.strictEqual(t.filesTraversed, symlinkOk ? 40 : 39);
    for (const [role, n] of Object.entries(expect)) {
      assert.strictEqual((t.byRole[role] || { files: 0 }).files, n, `role ${role}`);
    }
    assert.strictEqual((t.byRole.symlink || { files: 0 }).files, symlinkOk ? 1 : 0);
    assert.strictEqual(summary.scopeClosure.closed, true);

    // 生产语言与未支持语言
    assert.strictEqual(t.productionByLang.cpp, 4); // main.cpp orphan.cpp b.cpp inline_impl.inl
    assert.strictEqual(t.productionByLang.header, 1);
    assert.strictEqual(t.productionByLang.asm, 2);
    assert.strictEqual(t.productionByLang.shader, 2);
    assert.strictEqual(t.unsupportedLanguages.files, 4); // asm×2 + shader×2

    // 解析失败单独计数，不静默
    assert.strictEqual(t.parseFailures.sa, 1);
    assert.strictEqual(t.parseFailures.bundle, 1);

    // 待定角色单独可见
    assert.strictEqual(summary.productionPending.files, 3);
    assert.strictEqual(summary.productionPending.byExt['(no-ext)'], 2);
    assert.strictEqual(summary.productionPending.byExt['.csv'], 1);

    // 无 bundle 归属：生产 1、other 1（bin）、build 1（Makefile）
    assert.strictEqual(summary.unbundled.production.files, 1);
    const unbundledPaths = new Set(summary.unbundled.files.map((row) => row.p));
    assert.ok(unbundledPaths.has('base/noBundle/src/orphan.cpp'));
    assert.ok(unbundledPaths.has('base/noBundle/data.bin'));
    assert.ok(unbundledPaths.has('base/noBundle/Makefile'));
    assert.strictEqual(summary.unbundled.files.length, 3);

    // 符号链接登记：目标 + 分类
    if (symlinkOk) {
      assert.strictEqual(summary.symlinkRegistry.length, 1);
      const reg = summary.symlinkRegistry[0];
      assert.strictEqual(reg.p, 'base/compA/link.cpp');
      assert.strictEqual(reg.classification, 'in-scope-alias');
      assert.ok(String(reg.target).includes('main.cpp'));
      const line = fs.readFileSync(path.join(outDir, 'r1-files.jsonl'), 'utf8')
        .split('\n').filter(Boolean).map((l) => JSON.parse(l)).find((j) => j.p === 'base/compA/link.cpp');
      assert.strictEqual(line.t, 'src/main.cpp');
    }

    // 入口候选：NAPI 注册、OnRemoteRequest 实现/头文件声明
    const compA = summary.components.find((c) => c.component === '@ohos/compa');
    assert.ok(compA, 'component A by bundle name');
    assert.strictEqual(compA.entries.napi.registrations, 1);
    assert.strictEqual(compA.entries.onRemoteRequest.implHits, 1);
    assert.strictEqual(compA.entries.onRemoteRequest.headerHits, 1);
    assert.strictEqual(compA.build.conditionals, 1); // BUILD.gn 中 1 个 if(
    assert.strictEqual(compA.deps.externalComponents.join(','), 'hilog'); // 自依赖计入自身

    // IDL/SA/解析
    assert.strictEqual(compA.idl.interfaces, 1);
    assert.strictEqual(compA.idl.methods, 1);
    assert.strictEqual(compA.proto.services, 1);
    assert.strictEqual(compA.proto.rpcs, 1);
    assert.strictEqual(compA.sa.profiles, 2);
    assert.strictEqual(compA.sa.systemAbilities, 1);
    assert.strictEqual(compA.sa.parseErrors, 1);

    // 对账恒等式全部通过
    assert.ok(summary.reconciliation.every((row) => row.pass),
      JSON.stringify(summary.reconciliation.filter((row) => !row.pass)));

    // JSONL 行数 = filesTraversed，无 bundle 文件 c=null
    const lines = fs.readFileSync(path.join(outDir, 'r1-files.jsonl'), 'utf8')
      .split('\n').filter(Boolean);
    assert.strictEqual(lines.length, t.filesTraversed);
    const orphan = lines.map((l) => JSON.parse(l)).find((j) => j.p === 'base/noBundle/src/orphan.cpp');
    assert.strictEqual(orphan.c, null);
    assert.strictEqual(orphan.r, 'production-code');

    // 入口候选 JSONL
    const entryLines = fs.readFileSync(path.join(outDir, 'r1-entry-candidates.jsonl'), 'utf8')
      .split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const forms = new Set(entryLines.map((row) => row.form));
    assert.ok(forms.has('napi-register') && forms.has('onremoterequest-impl')
      && forms.has('onremoterequest-header'));
    const orr = entryLines.find((row) => row.form === 'onremoterequest-impl');
    assert.strictEqual(orr.line, 3);
    assert.strictEqual(orr.c, '@ohos/compa');

    // 确定性：同输入两次运行，r1-files.jsonl 与 r1-scope-baseline.json 字节一致
    const firstFiles = crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(outDir, 'r1-files.jsonl'))).digest('hex');
    const firstSummary = crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(outDir, 'r1-scope-baseline.json'))).digest('hex');
    const outDir2 = path.join(tmp, 'out2');
    runCapture(() => inventory.main(['--cost-out', path.join(outDir2, 'c2.json')],
      { srcRoot, outDir: outDir2 }));
    assert.strictEqual(crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(outDir2, 'r1-files.jsonl'))).digest('hex'), firstFiles);
    assert.strictEqual(crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(outDir2, 'r1-scope-baseline.json'))).digest('hex'), firstSummary);

    // stdout 汇总自洽
    assert.strictEqual(r1.reconciliationPass, true);
    assert.strictEqual(r1.components, 2);
    assert.strictEqual(r1.scopeClosed, true);

    fs.rmSync(tmp, { recursive: true, force: true });
  });

test('目录枚举失败可见：bundle 搜索与主遍历都登记且范围标为未闭合', { concurrency: false }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'oh6-r1-inv-fail-'));
  const srcRoot = path.join(tmp, 'src');
  const outDir = path.join(tmp, 'out');
  writeTree(srcRoot);
  const lockedDir = path.join(srcRoot, 'base', 'compA', 'locked');
  fs.mkdirSync(lockedDir, { recursive: true });
  fs.writeFileSync(path.join(lockedDir, 'hidden.cpp'), 'int hidden() { return 3; }\n');
  const failingReaddir = (dir, opts) => {
    if (path.dirname(dir) === lockedDir || dir === lockedDir) {
      const e = new Error(`EACCES: permission denied, scandir '${dir}'`);
      e.code = 'EACCES';
      throw e;
    }
    return fs.readdirSync(dir, opts);
  };

  const r1 = JSON.parse(runCapture(() => inventory.main(['--cost-out', path.join(outDir, 'c.json')],
    { srcRoot, outDir, readdir: failingReaddir })));
  const summary = JSON.parse(fs.readFileSync(path.join(outDir, 'r1-scope-baseline.json'), 'utf8'));

  assert.strictEqual(summary.scopeClosure.closed, false);
  const lockedRows = summary.scopeClosure.unclosedReasons.filter((row) => row.p.endsWith('compA/locked'));
  assert.strictEqual(lockedRows.length, 2);
  assert.deepStrictEqual(new Set(lockedRows.map((row) => row.phase)), new Set(['bundle-search', 'walk']));
  for (const row of lockedRows) {
    assert.strictEqual(row.code, 'EACCES');
  }
  assert.strictEqual(summary.totals.dirReadErrors.files, 2);
  assert.strictEqual(r1.scopeClosed, false);
  // hidden.cpp 未被遍历：这是未闭合的直接后果，不得进入任何分母
  const lines = fs.readFileSync(path.join(outDir, 'r1-files.jsonl'), 'utf8');
  assert.ok(!lines.includes('hidden.cpp'));

  fs.rmSync(tmp, { recursive: true, force: true });
});

function runCapture(fn) {
  const orig = process.stdout.write.bind(process.stdout);
  let captured = '';
  process.stdout.write = (chunk) => { captured += String(chunk); return true; };
  try {
    assert.strictEqual(fn(), 0);
  } finally {
    process.stdout.write = orig;
  }
  return captured.trim().split('\n').filter(Boolean).pop();
}
