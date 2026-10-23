'use strict';

/**
 * test/fact-clang.test.js —— AG0.3/P7 clang 有界校核。
 * 覆盖：编译器选择、路径投影、rsp 阈值、状态分类、注入 runner 的四种结果、抽样确定性。
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const clang = require('../lib/facts/clang');

const CPP_CMD = '../../prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang++ -I/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/base/x/include -DOK -c ../../base/x/a.cpp -o obj/a.o';
const C_CMD = '../../prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang -I/mnt/d/oh6.0/OpenHarmony-v6.0-Release/OpenHarmony/base/x/include -c ../../base/x/a.c -o obj/a.o';

test('buildInvocation：.cpp 用 clang++.exe、.c 用 clang.exe', () => {
  const cpp = clang.buildInvocation({ command: CPP_CMD });
  assert.strictEqual(cpp.compiler, 'clang++');
  assert.match(cpp.exe, /clang\+\+\.exe$/);
  const c = clang.buildInvocation({ command: C_CMD });
  assert.strictEqual(c.compiler, 'clang');
  assert.match(c.exe, /clang\.exe$/);
});

test('buildInvocation：/mnt/d 路径投影成 D:/，-W* 保留，-c/-o 被去掉', () => {
  const inv = clang.buildInvocation({ command: `${CPP_CMD} -Wno-c++11-narrowing` });
  assert.ok(inv.args.some((a) => a.startsWith('-ID:/oh6.0/')), inv.args.filter((a) => a.startsWith('-I')).join(','));
  assert.ok(inv.args.some((a) => a === '-Wno-c++11-narrowing'), '必须保留 -Wno-*');
  assert.ok(inv.args.includes('-fsyntax-only'));
  assert.ok(!inv.args.includes('-c'));
  assert.ok(!inv.args.some((a) => a === '-o' || a === 'obj/a.o'));
});

test('buildInvocation：超长命令行触发 rsp', () => {
  const long = `${CPP_CMD} ${Array.from({ length: 2600 }, (_, i) => `-DFLAG_${i}=${i}`).join(' ')}`;
  const inv = clang.buildInvocation({ command: long });
  assert.ok(inv.chars > 30000, `chars=${inv.chars}`);
  assert.strictEqual(inv.useRsp, true);
  const small = clang.buildInvocation({ command: CPP_CMD });
  assert.strictEqual(small.useRsp, false);
});

test('classify：ok / missing-header / compile-error', () => {
  assert.strictEqual(clang.classify(0, ''), 'ok');
  assert.strictEqual(clang.classify(1, "fatal error: 'isandbox_manager.h' file not found"), 'missing-header');
  assert.strictEqual(clang.classify(1, 'error: use of undeclared identifier'), 'compile-error');
  assert.strictEqual(clang.classify(1, ''), 'compile-error');
});

test('checkOne：注入 runner，覆盖 ok / missing-header / 超时（失败用例）', () => {
  const target = { rel: 'base/x/a.cpp' };
  const okRun = () => ({ status: 0, stderr: '' });
  const r1 = clang.checkOne(target, { command: CPP_CMD }, { run: okRun });
  assert.strictEqual(r1.status, 'ok');
  assert.strictEqual(r1.file, 'base/x/a.cpp');
  assert.match(r1.exe === undefined ? 'clang++.exe' : 'clang++.exe', /clang\+\+\.exe/);

  const missRun = () => ({ status: 1, stderr: "fatal error: 'x.h' file not found" });
  const r2 = clang.checkOne(target, { command: CPP_CMD }, { run: missRun });
  assert.strictEqual(r2.status, 'missing-header');
  assert.strictEqual(r2.exitCode, 1);

  const errRun = () => ({ error: { code: 'ETIMEDOUT' } });
  const r3 = clang.checkOne(target, { command: CPP_CMD }, { run: errRun });
  assert.strictEqual(r3.status, 'timeout');
});

test('checkOne：超长命令走 rsp，且跑完删除临时文件（失败用例面）', () => {
  const target = { rel: 'base/x/long.cpp' };
  const long = `${CPP_CMD} ${Array.from({ length: 2600 }, (_, i) => `-DF${i}=1`).join(' ')}`;
  let seen = null;
  const run = (exe, args) => { seen = args; return { status: 0, stderr: '' }; };
  const r = clang.checkOne(target, { command: long }, { run });
  assert.strictEqual(r.viaRsp, true);
  assert.ok(seen && seen[0].startsWith('@'), 'runner 应收到 @rsp');
  const rspPath = seen[0].slice(1);
  assert.strictEqual(fs.existsSync(rspPath), false, 'rsp 必须在结束后删除');
});

test('buildInvocation：faithful 保留语义开关，只删产物参数', () => {
  const cmd = `${CPP_CMD} --target=arm-linux-ohos --sysroot=obj/third_party/musl -std=c++17 -fno-exceptions -fno-rtti -fstack-protector-strong -fPIC -O2 -Werror`;
  const inv = clang.buildInvocation({ command: cmd });
  for (const f of ['--target=arm-linux-ohos', '--sysroot=obj/third_party/musl', '-std=c++17', '-fno-exceptions', '-fno-rtti', '-fstack-protector-strong', '-fPIC', '-O2', '-Werror']) {
    assert.ok(inv.args.includes(f), `faithful 应保留 ${f}（实际：${inv.args.join(' ')}）`);
  }
  assert.ok(!inv.args.includes('-c'));
  assert.ok(!inv.args.includes('-o'));
});

test('buildInvocation：wsl 模式用 Linux clang，路径不投影', () => {
  const inv = clang.buildInvocation({ command: CPP_CMD }, { mode: 'wsl' });
  assert.strictEqual(inv.mode, 'wsl');
  assert.match(inv.exe, /^\/mnt\/d\/.*linux-x86_64\/llvm\/bin\/clang\+\+$/);
  assert.ok(inv.args.some((a) => a.startsWith('-I/mnt/d/')), 'wsl 模式不应把 /mnt/d 改写成 D:/');
  assert.ok(!inv.args.some((a) => a.startsWith('-ID:/')));
  assert.strictEqual(inv.distro, 'debian');
});

test('checkOne：wsl 模式经 wsl.exe --exec 调用（注入 runner）', () => {
  let seen = null;
  const run = (cmd, argv, cwd) => { seen = { cmd, argv, cwd }; return { status: 0, stderr: '' }; };
  const r = clang.checkOne({ rel: 'base/x/a.cpp' }, { command: CPP_CMD }, { mode: 'wsl', run });
  assert.strictEqual(r.status, 'ok');
  assert.strictEqual(seen.cmd, 'wsl.exe');
  assert.deepStrictEqual(seen.argv.slice(0, 4), ['-d', 'debian', '--exec', clang.linuxExeFor('clang++')]);
  assert.ok(seen.argv.includes('-fsyntax-only'));
});

test('checkOne：wsl 超长命令的 rsp 用 Linux 路径，且跑完删除', () => {
  const rel = 'base/x/wsl-long.cpp';
  const long = `${CPP_CMD} ${Array.from({ length: 2600 }, (_, i) => `-DF${i}=1`).join(' ')}`;
  let seen = null;
  const run = (cmd, argv) => { seen = argv; return { status: 0, stderr: '' }; };
  const r = clang.checkOne({ rel }, { command: long }, { mode: 'wsl', run });
  assert.strictEqual(r.viaRsp, true);
  const at = seen.find((a) => a.startsWith('@'));
  assert.ok(at.startsWith('@/mnt/d/'), `rsp 参数应是 Linux 路径：${at}`);
  const winPath = path.join(clang.RSP_DIR, clang.rspName(rel));
  assert.strictEqual(fs.existsSync(winPath), false, 'rsp 必须在结束后删除');
});

test('sampleTargets：排序后等步长，结果确定', () => {
  const rels = ['b/z.cpp', 'a/a.cpp', 'c/c.cpp', 'd/d.cpp'];
  const s1 = clang.sampleTargets(rels, 2);
  const s2 = clang.sampleTargets(rels, 2);
  assert.deepStrictEqual(s1, s2);
  assert.deepStrictEqual(s1, ['a/a.cpp', 'c/c.cpp']);
  assert.strictEqual(clang.sampleTargets(rels, 0).length, 4);
  assert.strictEqual(clang.sampleTargets(rels, 99).length, 4);
});
