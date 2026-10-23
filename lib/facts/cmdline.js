'use strict';
/* 临时探针：compdb command 恢复（shell 转义 + 破碎 -D 粘合）。用完并入 AG0 实现或删除。 */

/** 按空白切分，保留转义与引号语义（不 unescape，标记交给后续步骤）。 */
function rawSplit(s) {
  const toks = [];
  let cur = '';
  let quote = null;
  let has = false;
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (quote) {
      cur += c;
      if (c === quote && s[i - 1] !== '\\') quote = null;
      has = true;
      continue;
    }
    if (c === '\\' && i + 1 < s.length) {
      cur += c + s[i + 1];
      i += 1;
      has = true;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; cur += c; has = true; continue; }
    if (c === ' ' || c === '\t') { if (has) { toks.push(cur); cur = ''; has = false; } continue; }
    cur += c; has = true;
  }
  if (has) toks.push(cur);
  return toks;
}

/** 去掉 shell 转义：\<char> -> <char>，双引号内同样处理；单引号内保持原样。 */
function unescape(tok) {
  let out = '';
  let quote = null;
  for (let i = 0; i < tok.length; i += 1) {
    const c = tok[i];
    if (quote === "'") { if (c === "'") quote = null; else out += c; continue; }
    if (c === '\\' && i + 1 < tok.length) { out += tok[i + 1]; i += 1; continue; }
    if (c === '"') { if (quote === '"') quote = null; else quote = '"'; continue; }
    if (c === "'" && !quote) { quote = "'"; continue; }
    out += c;
  }
  return out;
}

/** 破碎 -D：`-DNAME\$ =\$ \"V\"`（真实空格）-> `-DNAME="V"` */
function normalizeDefines(rawToks) {
  const out = [];
  let merged = 0;
  for (let i = 0; i < rawToks.length; i += 1) {
    const t = rawToks[i];
    if (t.startsWith('-D') && t.endsWith('\\$')) {
      let parts = [t.slice(0, -2)];
      let j = i + 1;
      while (j < rawToks.length) {
        const n = rawToks[j];
        if (n.startsWith('-')) break;
        const strip = n.endsWith('\\$') ? n.slice(0, -2) : n;
        parts.push(strip);
        j += 1;
        if (!n.endsWith('\\$')) break;
      }
      out.push(unescape(parts.join('')));
      merged += 1;
      i = j - 1;
      continue;
    }
    out.push(unescape(t));
  }
  return { args: out, merged };
}

const DROP_WITH_ARG = new Set(['-o', '-MF', '-MT', '-MQ', '-include-pch', '--serialize-diagnostics', '-mllvm', '-Xclang', '-Xassembler', '-Xpreprocessor', '-Xlinker']);
const DROP = [
  /^-MMD$/, /^-MD$/, /^-c$/, /^-pipe$/, /^-O/, /^-g\b/, /^-gdwarf/, /^-ggnu/, /^-flto$/, /^-fsanitize=/, /^-fPIE$/, /^-fno-ident$/,
  /^-fdata-sections$/, /^-ffunction-sections$/, /^-fomit-frame-pointer$/, /^-fvisibility/, /^-enable-trivial/, /^-ftrivial-auto-var-init/,
  /^-fno-common$/, /^-fdebug/, /^-fno-exceptions$/, /^--param/, /^-[mM](?!arch)/, /^-fmacro-prefix-map/, /^-fdebug-compilation-dir/,
  /^-fcrash-diagnostics/, /^-fstandalone-debug/, /^-fcoverage/, /^-fprofile/, /^-fstack-protector/,
];

/**
 * faithful 模式：只删「产物/进度」类参数，保留一切可能影响语义的开关。
 * 依据：AGENT-ARCHITECTURE-GUIDE §4.3 明确要求不得复用过宽的删除规则
 * （target / sysroot / 宏 / ABI / 异常模式都可能改变结论）。
 */
const FAITHFUL_DROP_WITH_ARG = new Set(['-o', '-MF', '-MT', '-MQ', '-MJ', '--serialize-diagnostics']);
const FAITHFUL_DROP = new Set(['-c', '-MMD', '-MD', '-pipe']);

/** compdb command -> { compiler, args }（args 不含编译器自身与目标文件） */
function buildArgs(command, opts = {}) {
  const faithful = opts.faithful === true;
  const { args: toks, merged } = normalizeDefines(rawSplit(command));
  const compiler = toks[0]; // 必须沿用 compdb 自己的编译器：clang 用于 .c，clang++ 用于 .cpp
  const out = [];
  const dropped = [];
  for (let i = 1; i < toks.length; i += 1) {
    const t = toks[i];
    if (faithful) {
      if (FAITHFUL_DROP_WITH_ARG.has(t)) { dropped.push(t, toks[i + 1]); i += 1; continue; }
      if (FAITHFUL_DROP.has(t)) { dropped.push(t); continue; }
      out.push(t);
      continue;
    }
    if (DROP_WITH_ARG.has(t)) { dropped.push(t, toks[i + 1]); i += 1; continue; }
    if (DROP.some((re) => re.test(t))) { dropped.push(t); continue; }
    if (/^-D/.test(t) && !/^-D[A-Za-z_][A-Za-z0-9_$]*(=.*)?$/s.test(t)) { dropped.push(t); continue; }
    out.push(t);
  }
  return { compiler, args: out, dropped, mergedDefines: merged };
}

module.exports = { rawSplit, unescape, normalizeDefines, buildArgs };
