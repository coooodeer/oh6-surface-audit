'use strict';

/**
 * lib/facts/idl.js —— OHOS IDL 的受限解析器（AG0.2）。
 *
 * 覆盖 5 个 root 内实测的语法子集：
 *   package / interface / interface_token / sequenceable / rawdata /
 *   [ipccode 0xNN] / oneway / 方法签名（含多行参数）。
 * 不做表达式求值，不猜 token：没有 interface_token 且没有 ipccode 时 token=null。
 */

/** 去注释但保留行号：块注释替换为等长空白，行注释整行清空。 */
function stripComments(text) {
  const noBlock = text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
  return noBlock
    .split(/\r?\n/)
    .map((line) => {
      const i = line.indexOf('//');
      return i >= 0 ? line.slice(0, i) : line;
    })
    .join('\n');
}

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text[i] === '\n') n += 1;
  return n;
}

function parseParams(raw) {
  const out = [];
  const body = String(raw || '').trim();
  if (!body) return out;
  for (const part of body.split(',')) {
    const t = part.trim();
    if (!t) continue;
    const dirMatch = /^\[(in|out|inout)\]\s*/i.exec(t);
    const dir = dirMatch ? dirMatch[1].toLowerCase() : null;
    const rest = dirMatch ? t.slice(dirMatch[0].length) : t;
    const m = /^(.*?)\s+([A-Za-z_]\w*)$/.exec(rest.trim());
    if (m) out.push({ direction: dir, type: m[1].trim(), name: m[2] });
    else out.push({ direction: dir, type: rest.trim(), name: null });
  }
  return out;
}

/**
 * 解析一个 IDL 文件。
 * @returns {{package:string|null, interfaceTokens:string[], sequenceables:string[],
 *            rawdata:string[], interfaces:{name:string,line:number}[], methods:object[]}}
 */
function parseIdl(text) {
  const src = stripComments(text);
  const lines = src.split(/\r?\n/);
  const result = { package: null, interfaceTokens: [], sequenceables: [], rawdata: [], interfaces: [], methods: [] };
  let iface = null;
  let depth = 0;
  let pending = '';
  let pendingLine = 0;

  const flush = () => {
    if (!pending || !iface) { pending = ''; return; }
    const decl = pending.replace(/\s+/g, ' ').trim();
    pending = '';
    const attrMatch = /^\[([^\]]*)\]\s*(.*)$/.exec(decl);
    const attrs = attrMatch ? attrMatch[1] : '';
    const rest = attrMatch ? attrMatch[2] : decl;
    const ipcMatch = /ipccode\s+(0x[0-9a-fA-F]+|\d+)/.exec(attrs);
    const onewayAttr = /\boneway\b/.test(attrs);
    const mm = /^(?:oneway\s+)?([A-Za-z_][\w:<>,\.[\]\s]*?)\s+([A-Za-z_]\w*)\s*\(([^;]*)\)\s*;$/.exec(rest.trim());
    if (!mm) return;
    result.methods.push({
      interface: iface.name,
      package: result.package,
      method: mm[2],
      returnType: mm[1].trim(),
      params: parseParams(mm[3]),
      ipcCode: ipcMatch ? (ipcMatch[1].startsWith('0x') ? parseInt(ipcMatch[1], 16) : parseInt(ipcMatch[1], 10)) : null,
      oneway: onewayAttr || /^oneway\s+/.test(rest.trim()),
      line: pendingLine
    });
  };

  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    const t = raw.trim();
    if (!t) continue;
    const top = /^(package|import|sequenceable|rawdata|interface_token|option_stub_hooks)\b/.exec(t);
    if (top && !iface) {
      if (top[1] === 'package') result.package = (/^package\s+([\w.]+)\s*;/.exec(t) || [])[1] || null;
      else if (top[1] === 'interface_token') result.interfaceTokens.push((/^interface_token\s+([\w.]+)\s*;/.exec(t) || [])[1] || '');
      else if (top[1] === 'sequenceable') result.sequenceables.push((/^sequenceable\s+([\w.]+)\s*;/.exec(t) || [])[1] || '');
      else if (top[1] === 'rawdata') result.rawdata.push((/^rawdata\s+([\w.]+)\s*;/.exec(t) || [])[1] || '');
      continue;
    }
    if (!iface) {
      const im = /^interface\s+([\w.]+)(?:\s+extends\s+[\w.]+)?\s*([{;]?)/.exec(t);
      if (im) {
        // `interface X.Y;` 是前向声明，不进入 interface 作用域
        if (im[2] === ';' || (t.endsWith(';') && !t.includes('{'))) continue;
        iface = { name: im[1], line: i + 1 };
        result.interfaces.push(iface);
        depth = (t.match(/\{/g) || []).length - (t.match(/\}/g) || []).length;
        if (depth <= 0) depth = 1;
        pending = '';
      }
      continue;
    }
    // 在 interface 内
    if (t === '}' || /^}\s*;?$/.test(t)) {
      depth -= 1;
      flush();
      if (depth <= 0) iface = null;
      continue;
    }
    // 内联类型定义（struct/enum/union）整行跳过，不污染方法累积
    if (/^(struct|enum|union)\b/.test(t)) {
      flush();
      depth += (t.match(/\{/g) || []).length - (t.match(/\}/g) || []).length;
      continue;
    }
    const opens = (t.match(/\{/g) || []).length;
    const closes = (t.match(/\}/g) || []).length;
    if (pending) pending += ` ${t}`;
    else { pending = t; pendingLine = i + 1; }
    if (pending.includes(';')) flush();
    depth += opens - closes;
  }
  return result;
}

/** 把解析结果摊平成方法级记录（供 metadata/idl.jsonl） */
function toRows(parsed, fileRel) {
  const token = parsed.interfaceTokens.length === 1 ? parsed.interfaceTokens[0]
    : parsed.interfaceTokens.length > 1 ? parsed.interfaceTokens[parsed.interfaceTokens.indexOf(parsed.interfaceTokens.find((t) => t))] : null;
  return parsed.methods.filter((m) => m.interface).map((m) => {
    const ipcCode = m.ipcCode;
    return {
      interface: m.interface,
      package: m.package || null,
      descriptor: m.interface ? (m.package ? m.package : null) : null,
      method: m.method,
      returnType: m.returnType,
      paramCount: m.params.length,
      params: m.params,
      ipcCode,
      oneway: m.oneway,
      interfaceToken: parsed.interfaceTokens[0] || null,
      token: parsed.interfaceTokens[0] || (ipcCode !== null ? `0x${ipcCode.toString(16)}` : null),
      tokenSource: parsed.interfaceTokens[0] ? 'interface_token' : (ipcCode !== null ? 'ipccode' : 'absent'),
      file: fileRel,
      line: m.line
    };
  });
}

module.exports = { stripComments, lineOf, parseParams, parseIdl, toRows };
