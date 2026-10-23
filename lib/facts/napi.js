'use strict';

/**
 * lib/facts/napi.js —— NAPI 注册点（AG0.2）。
 *
 * 5 个 root 内没有 .d.ts / module.json5，NAPI 只以 C/C++ 代码形态存在：
 *   static napi_module g_module = { .nm_modname = "...", ... };
 *   napi_module_register(&g_module);
 * 这里只做注册点识别（模块名 + 位置），不做 entry 绑定（那是 AG1 的事）。
 */

function lineOfIndex(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text[i] === '\n') n += 1;
  return n;
}

/** @returns {{module:string|null, struct:string, line:number, file:string}[]} */
function scanText(text, fileRel) {
  const rows = [];
  const reg = /napi_module_register\s*\(\s*&?\s*([A-Za-z_]\w*)\s*\)/g;
  let m;
  while ((m = reg.exec(text)) !== null) {
    const struct = m[1];
    const declRe = new RegExp(`napi_module\\s+${struct}\\s*=\\s*\\{`);
    const decl = declRe.exec(text);
    let modname = null;
    if (decl) {
      const tail = text.slice(decl.index, decl.index + 1200);
      const nm = /\.nm_modname\s*=\s*"([^"]+)"/.exec(tail) || /nm_modname\s*=\s*"([^"]+)"/.exec(tail);
      if (nm) modname = nm[1];
    }
    rows.push({ module: modname, struct, line: lineOfIndex(text, m.index), file: fileRel });
  }
  return rows;
}

module.exports = { scanText, lineOfIndex };
