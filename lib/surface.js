'use strict';

const path = require('path');
const { SOURCE_ROOT, TOOL_ROOT, CPP_EXTS, walk, readText, readJsonl, lineOf } = require('./util');
const { enclosing, functionsOf } = require('./index');

const IDL_EXTS = new Set(['.idl']);

function readLines(abs) {
  const r = readText(abs);
  if (!r.text) return null;
  return r.text.split(/\r?\n/);
}

function matchBrace(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i += 1) {
    const c = text[i];
    if (c === '"' || c === "'") {
      const q = c;
      i += 1;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === q) break;
        i += 1;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i += 1;
      i += 1;
      continue;
    }
    if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** 递归找名为 name 的目录（不进入 .git/out/third_party） */
function findDirs(root, name) {
  const out = [];
  const skip = new Set(['.git', 'out', 'third_party', 'prebuilts', 'node_modules']);
  function rec(dir) {
    let ents;
    try { ents = require('fs').readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    for (const ent of ents) {
      if (!ent.isDirectory()) continue;
      if (skip.has(ent.name)) continue;
      const abs = path.join(dir, ent.name);
      if (ent.name === name) out.push(abs);
      else rec(abs);
    }
  }
  rec(root);
  return out;
}

function baseEntry(o) {
  return {
    entryKey: o.entryKey,
    channel: o.channel,
    repo: o.repo,
    kind: o.kind,
    identity: o.identity || {},
    site: o.site || { file: null, line: null, symbol: null },
    provenance: o.provenance || [],
    attackerPosition: o.attackerPosition || [],
    requiredChecks: o.requiredChecks || [],
    controlledInputs: o.controlledInputs || [],
    implLink: o.implLink || { status: 'unresolved', reason: 'not-checked' },
    confidence: o.confidence || 'heuristic'
  };
}

// ------------------------------------------------------------------ IDL

function scanIdl(repo, abs, stubText) {
  const out = [];
  for (const f of walk(abs, { exts: IDL_EXTS })) {
    const { text } = readText(f.abs);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    let iface = null;
    let depth = 0;
    let pending = '';
    let pendingLine = 0;
    for (let i = 0; i < lines.length; i += 1) {
      const t = lines[i].trim();
      if (!t || t.startsWith('//') || t.startsWith('*')) continue;
      if (!iface) {
        const im = /^interface\s+([\w.]+)(?:\s+extends\s+[\w.]+)?\s*\{?/.exec(t);
        if (im) {
          iface = im[1];
          depth = (t.match(/\{/g) || []).length - (t.match(/\}/g) || []).length;
          pending = '';
        }
        continue;
      }
      if (t === '}') {
        depth -= 1;
        pending = '';
        if (depth <= 0) iface = null;
        continue;
      }
      if (/^(enum|struct|union|typedef|sequenceable|import|interface_token|option_stub_hooks)\b/.test(t)) {
        pending = '';
        continue;
      }
      if (pending) pending += ` ${t}`;
      else {
        pending = t;
        pendingLine = i + 1;
      }
      if (!pending.includes(';')) continue;
      const decl = pending.replace(/\s+/g, ' ').trim();
      pending = '';
      const mm = /^(?:oneway\s+)?([A-Za-z_][\w:<>,.\[\]\s]*?)\s+([A-Za-z_]\w*)\s*\(([^;]*)\)\s*;/.exec(decl);
      if (!mm) continue;
      const method = mm[2];
      const hasImpl = stubText && (stubText.includes(iface) || stubText.includes(method));
      const hasMethod = stubText && stubText.includes(method);
      out.push(baseEntry({
        entryKey: `idl:${repo}:${iface}:${method}`,
        channel: 'idl',
        repo,
        kind: 'ipc-idl',
        identity: { interface: iface, method },
        site: { file: f.rel, line: pendingLine, symbol: iface },
        provenance: ['idl'],
        attackerPosition: ['third-party-app'],
        requiredChecks: ['token-permission', 'parcel-bounds', 'type-tag'],
        controlledInputs: ['parcel'],
        implLink: hasMethod
          ? { status: 'verified', file: null, line: null, reason: 'stub-or-proxy-name-match' }
          : hasImpl
            ? { status: 'related', file: null, line: null, reason: 'stub-or-proxy-interface-match' }
            : { status: 'unresolved', reason: 'no-stub-or-proxy-in-repo' },
        confidence: 'resolved'
      }));
    }
  }
  return out;
}

// ------------------------------------------------------------- dispatch

/** 找 `name(...) { ... }` 的函数体；跳过只有声明/调用的出现 */
function findFunctionBody(text, name) {
  const re = new RegExp(`\\b${name}\\s*\\(`, 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    let i = text.indexOf('(', m.index);
    let depth = 0;
    for (; i < text.length; i += 1) {
      if (text[i] === '(') depth += 1;
      else if (text[i] === ')') {
        depth -= 1;
        if (depth === 0) { i += 1; break; }
      }
    }
    while (i < text.length && /\s/.test(text[i])) i += 1;
    if (text[i] !== '{') continue;
    const close = matchBrace(text, i);
    if (close > i) return { open: i, close, body: text.slice(i, close + 1) };
  }
  return null;
}

function scanDispatch(repo, abs) {
  const out = [];
  for (const f of walk(abs, { exts: CPP_EXTS })) {
    if (!/_stub\.(cpp|cc|cxx)$/i.test(f.rel) && !f.rel.includes('stub')) continue;
    const { text } = readText(f.abs);
    if (!text || !text.includes('OnRemoteRequest') || !text.includes('MessageParcel')) continue;
    const tokenM = /interface_token\s+["']([^"']+)["']/.exec(text)
      || /GetDescriptor[^;{]*?u?"([^"]+)"/.exec(text);
    const token = (tokenM && tokenM[1])
      || (/client_stub/i.test(f.rel) ? 'OHOS.ISoftBusClient' : null)
      || (/server_stub/i.test(f.rel) ? 'OHOS.ISoftBusServer' : null);
    const fn = findFunctionBody(text, 'OnRemoteRequest');
    if (!fn) continue;
    const body = fn.body;
    const cases = [];
    const sw = body.indexOf('switch');
    if (sw >= 0) {
      const open = body.indexOf('{', sw);
      if (open >= 0) {
        const close = matchBrace(body, open);
        if (close > open) {
          const swBody = body.slice(open, close + 1);
          const re = /\bcase\s+([^:]+):/g;
          let m;
          while ((m = re.exec(swBody)) !== null) {
            const code = m[1].trim().replace(/\s+/g, ' ');
            const after = swBody.slice(m.index + m[0].length, m.index + m[0].length + 320);
            const hm = /\b([A-Za-z_]\w*)\s*\(/.exec(after);
            const handler = hm && !['if', 'switch', 'return', 'break', 'case', 'for', 'while'].includes(hm[1]) ? hm[1] : null;
            cases.push({ code, handler, index: fn.open + open + m.index });
          }
        }
      }
    }
    if (!cases.length) {
      const re = /\bif\s*\(\s*code\s*==\s*([A-Za-z_][\w:]*)\s*\)/g;
      let m;
      while ((m = re.exec(body)) !== null) cases.push({ code: m[1], handler: null, index: fn.open + m.index });
    }
    for (const c of cases) {
      const line = lineOf(text, c.index);
      out.push(baseEntry({
        entryKey: `ipc:${repo}:${token || f.rel}:${c.code}`,
        channel: 'ipc',
        repo,
        kind: 'ipc-remote',
        identity: { token, code: c.code },
        site: { file: f.rel, line, symbol: 'OnRemoteRequest' },
        provenance: ['dispatch'],
        attackerPosition: ['third-party-app', 'system-app'],
        requiredChecks: ['token-permission', 'parcel-bounds', 'type-tag'],
        controlledInputs: ['code', 'parcel'],
        implLink: c.handler
          ? { status: 'verified', file: f.rel, line, handler: c.handler, reason: 'case-handler-in-stub' }
          : { status: 'related', file: f.rel, line, reason: 'case-without-handler-name' },
        confidence: c.handler ? 'verified' : 'heuristic'
      }));
    }
  }
  return out;
}

// ------------------------------------------------------- dispatch maps

/**
 * 函数表/权限表分发（dsoftbus SoftBusServerStub）：
 *   memberFuncMap_[CODE] = &Class::Handler;
 *   memberPermissionMap_[CODE] = PERM;
 * 这是 switch 之外的第二类分发形态；不解析它会把整个 server 面漏掉。
 */
function scanDispatchMaps(repo, abs) {
  const out = [];
  for (const f of walk(abs, { exts: CPP_EXTS })) {
    const { text } = readText(f.abs, 4 * 1024 * 1024);
    if (!text || !text.includes('memberFuncMap_[')) continue;
    const tokenM = /interface_token\s+["']([^"']+)["']/.exec(text)
      || /GetDescriptor[^;{]*?u?"([^"]+)"/.exec(text);
    // 描述符在基类/头文件时，用文件名给出可复核的 hint（dsoftbus 的命名是稳定的）
    const token = (tokenM && tokenM[1])
      || (/client_stub/i.test(f.rel) ? 'OHOS.ISoftBusClient' : null)
      || (/server_stub/i.test(f.rel) ? 'OHOS.ISoftBusServer' : null);
    const funcs = new Map();
    const perms = new Map();
    let m;
    const fre = /memberFuncMap_\[([A-Za-z_][A-Za-z0-9_]*)\]\s*=\s*&([A-Za-z_][\w:]*)\s*;/g;
    while ((m = fre.exec(text)) !== null) funcs.set(m[1], { handler: m[2], index: m.index });
    const pre = /memberPermissionMap_\[([A-Za-z_][A-Za-z0-9_]*)\]\s*=\s*([A-Za-z_][\w:]*)\s*;/g;
    while ((m = pre.exec(text)) !== null) perms.set(m[1], { permission: m[2], index: m.index });
    for (const [code, v] of funcs) {
      const p = perms.get(code) || null;
      out.push(baseEntry({
        entryKey: `ipc:${repo}:${token || f.rel}:${code}`,
        channel: 'ipc',
        repo,
        kind: 'ipc-remote',
        identity: { token, code, handler: v.handler, permission: p ? p.permission : null },
        site: { file: f.rel, line: lineOf(text, v.index), symbol: v.handler },
        provenance: ['dispatch-map'],
        attackerPosition: ['third-party-app', 'system-app'],
        requiredChecks: p ? ['token-permission', 'parcel-bounds', 'type-tag'] : ['parcel-bounds', 'type-tag'],
        controlledInputs: ['code', 'parcel'],
        implLink: { status: 'verified', file: f.rel, line: lineOf(text, v.index), handler: v.handler, reason: 'function-table-handler' },
        confidence: 'verified'
      }));
    }
  }
  return out;
}

// ------------------------------------------------------------------- SA

function scanSa(repo, abs) {
  const out = [];
  const dirs = findDirs(abs, 'sa_profile');
  for (const dir of dirs) {
    for (const f of walk(dir, { exts: new Set(['.json']), skipDirs: new Set() })) {
      const { text } = readText(f.abs);
      if (!text) continue;
      let doc;
      try { doc = JSON.parse(text); } catch (_) { continue; }
      const list = Array.isArray(doc.systemability) ? doc.systemability : [];
      for (const s of list) {
        if (!s || s.name === undefined) continue;
        const saId = String(s.name);
        const line = Math.max(1, text.split(/\r?\n/).findIndex((l) => l.includes(`"${saId}"`)) + 1);
        out.push(baseEntry({
          entryKey: `sa:${repo}:${saId}`,
          channel: 'sa',
          repo,
          kind: 'config-policy',
          identity: { saId, process: doc.process || null },
          site: { file: path.relative(abs, f.abs).split(path.sep).join('/'), line, symbol: doc.process || null },
          provenance: ['sa_profile'],
          attackerPosition: ['system-app', 'third-party-app'],
          requiredChecks: ['sa-access-permission'],
          controlledInputs: [],
          implLink: doc.process
            ? { status: 'declared', file: null, line: null, reason: 'sa-profile-process' }
            : { status: 'unresolved', reason: 'no-process-field' },
          confidence: 'verified'
        }));
      }
    }
  }
  return out;
}

// ----------------------------------------------------------------- NAPI

const NAPI_RE = /napi_module_register\s*\(|NAPI_MODULE\s*\(|nm_register_func\s*=/;
const MODNAME_RE = /\.\s*nm_modname\s*=\s*"([^"]+)"/;
const REGFUNC_RE = /\.\s*nm_register_func\s*=\s*([A-Za-z_][\w:]*)/;

function scanNapi(repo, abs) {
  const out = [];
  for (const f of walk(abs, { exts: CPP_EXTS })) {
    const { text } = readText(f.abs);
    if (!text || !NAPI_RE.test(text)) continue;
    const modname = (MODNAME_RE.exec(text) || [])[1] || null;
    const regfunc = (REGFUNC_RE.exec(text) || [])[1] || null;
    const macro = /NAPI_MODULE\s*\(/.test(text);
    const regIdx = Math.max(0, text.indexOf('napi_module_register'));
    const line = lineOf(text, regIdx);
    const declare = (text.match(/DECLARE_NAPI_(?:STATIC_)?(?:FUNCTION|METHOD|GETTER|SETTER|PROPERTY)\s*\(\s*"([^"]+)"/g) || []).length;
    const create = (text.match(/napi_create_function\s*\(/g) || []).length;
    const identity = modname || path.basename(f.rel, path.extname(f.rel));
    out.push(baseEntry({
      entryKey: `napi:${repo}:${identity}`,
      channel: 'napi',
      repo,
      kind: 'napi',
      identity: { module: modname, identity, registration: regfunc || (macro ? 'NAPI_MODULE' : null) },
      site: { file: f.rel, line, symbol: regfunc },
      provenance: ['napi-registration'],
      attackerPosition: ['third-party-app'],
      requiredChecks: ['argc', 'arg-type', 'length'],
      controlledInputs: ['js-args'],
      implLink: (regfunc || macro)
        ? { status: 'verified', file: f.rel, line, reason: 'registration-func' }
        : { status: 'related', file: f.rel, line, reason: 'module-only' },
      confidence: regfunc || macro ? 'verified' : 'heuristic'
    }));
    if (declare + create > 0) out[out.length - 1].identity.exportCount = declare + create;
  }
  return out;
}

// ------------------------------------------------------- socket / HDI

function scanCallSites(repo, abs, spec, fns) {
  const out = [];
  const seen = new Map();
  for (const f of walk(abs, { exts: CPP_EXTS })) {
    const { text } = readText(f.abs);
    if (!text) continue;
    const lines = text.split(/\r?\n/);
    const re = new RegExp(spec.regex.source, spec.regex.flags.includes('g') ? spec.regex.flags : `${spec.regex.flags}g`);
    let m;
    while ((m = re.exec(text)) !== null) {
      const line = lineOf(text, m.index);
      const lineText = lines[line - 1] || '';
      if (spec.filter && !spec.filter(m, lineText, text)) continue;
      const api = typeof spec.apiOf === 'function' ? spec.apiOf(m) : m[1];
      const fn = enclosing(fns, repo, f.rel, line);
      const key = fn ? `fn:${repo}:${f.rel}:${fn.name}` : `fn:${repo}:${f.rel}:${line}`;
      if (!seen.has(key)) {
        seen.set(key, baseEntry({
          entryKey: key,
          channel: spec.channel,
          repo,
          kind: spec.kind,
          identity: { api: fn ? api : api, function: fn ? fn.name : null },
          site: { file: f.rel, line, symbol: fn ? fn.name : null },
          provenance: [spec.channel],
          attackerPosition: spec.attackerPosition,
          requiredChecks: spec.requiredChecks,
          controlledInputs: spec.controlledInputs,
          implLink: fn
            ? { status: 'verified', file: f.rel, line, reason: 'enclosing-function' }
            : { status: 'related', file: f.rel, line, reason: 'no-enclosing-function' },
          confidence: fn ? 'verified' : 'heuristic'
        }));
      }
      const e = seen.get(key);
      e.identity.apis = Array.from(new Set([...(e.identity.apis || []), api]));
      e.siteSamples = (e.siteSamples || []).concat([{ file: f.rel, line, api }]).slice(0, 5);
    }
  }
  for (const e of seen.values()) out.push(e);
  return out;
}

function scanSockets(repo, abs, fns) {
  return scanCallSites(repo, abs, {
    channel: 'socket',
    kind: 'socket',
    regex: /\b(accept4|accept|recvfrom|recvmsg|listen|bind)\s*\(/g,
    filter: (m, lineText) => {
      if (m[1] === 'bind' && !/sockaddr|AF_|SOCK_|socket\s*\(/.test(lineText)) return false;
      if (/std::bind|\.bind\s*\(|->bind\s*\(/.test(lineText)) return false;
      if (/^\s*\/\//.test(lineText)) return false;
      return true;
    },
    apiOf: (m) => m[1],
    attackerPosition: ['untrusted-remote'],
    requiredChecks: ['length', 'auth'],
    controlledInputs: ['socket-bytes']
  }, fns);
}

function scanHdi(repo, abs, fns) {
  return scanCallSites(repo, abs, {
    channel: 'hdi',
    kind: 'hdi',
    regex: /\b(HdfDeviceIoCommand|IDeviceIoService)\b|\bioctl\s*\(/g,
    filter: (m, lineText) => !/^\s*\/\//.test(lineText),
    apiOf: (m) => m[1] || 'ioctl',
    attackerPosition: ['untrusted-peripheral'],
    requiredChecks: ['length', 'cmd-validation'],
    controlledInputs: ['cmd', 'buffer']
  }, fns);
}

// --------------------------------------------------------------- parser

function scanParsers(repo, fns) {
  const out = [];
  const nameRe = /^(Parse|Decode|Unmarshal|Unpack|Deserialize|ReadFrom|FromJson|FromString)/;
  for (const f of functionsOf(fns, repo)) {
    if (!nameRe.test(f.name || '')) continue;
    const sig = (f.signature && f.signature.text) || '';
    if (!/[*]|Parcel|vector<|uint8_t|char|size_t/.test(sig)) continue;
    out.push(baseEntry({
      entryKey: `parser:${repo}:${f.file}:${f.name}:${f.startLine}`,
      channel: 'parser',
      repo,
      kind: 'parser',
      identity: { function: f.name },
      site: { file: f.file, line: f.startLine, symbol: f.name },
      provenance: ['function-index'],
      attackerPosition: ['local-file-provider'],
      requiredChecks: ['input-length', 'parcel-bounds'],
      controlledInputs: ['file-bytes'],
      implLink: { status: 'verified', file: f.file, line: f.startLine, reason: 'function-in-index' },
      confidence: 'resolved'
    }));
  }
  return out;
}

// ------------------------------------------------------------ broadcast

function scanBroadcasts(repo, abs, fns) {
  const out = [];
  const seen = new Map();
  for (const f of walk(abs, { exts: CPP_EXTS })) {
    const { text } = readText(f.abs);
    if (!text || !/Publish(?:Common)?Event\s*\(/.test(text)) continue;
    const lines = text.split(/\r?\n/);
    const re = /Publish(?:Common)?Event\s*\(/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const line = lineOf(text, m.index);
      const fn = enclosing(fns, repo, f.rel, line);
      const before = lines.slice(Math.max(0, line - 31), line).join('\n');
      const action = (/"(usual\.event\.[A-Za-z0-9_.]+)"/.exec(before) || [])[1]
        || (/"(COMMON_EVENT_[A-Z0-9_]+)"/.exec(before) || [])[1]
        || null;
      const key = fn ? `bcast:${repo}:${f.rel}:${fn.name}` : `bcast:${repo}:${f.rel}:${line}`;
      if (!seen.has(key)) {
        seen.set(key, baseEntry({
          entryKey: key,
          channel: 'broadcast',
          repo,
          kind: 'broadcast-publish',
          identity: { action, function: fn ? fn.name : null },
          site: { file: f.rel, line, symbol: fn ? fn.name : null },
          provenance: ['publish-call'],
          attackerPosition: ['third-party-app'],
          requiredChecks: ['subscriber-permission'],
          controlledInputs: [],
          implLink: fn
            ? { status: 'verified', file: f.rel, line, reason: 'enclosing-function' }
            : { status: 'related', file: f.rel, line, reason: 'no-enclosing-function' },
          confidence: fn ? 'verified' : 'heuristic'
        }));
      }
      const e = seen.get(key);
      if (action && !e.identity.action) e.identity.action = action;
      e.siteSamples = (e.siteSamples || []).concat([{ file: f.rel, line, action }]).slice(0, 5);
    }
  }
  for (const e of seen.values()) out.push(e);
  return out;
}

// ------------------------------------------------------------- harness

/**
 * harness 事实是 IPC 入口的独立来源（既有 miner 的 fuzz 调用点）。
 * 它给出 token + codeExpr，但没有实现侧；与 dispatch 共用 `ipc:<repo>:<token>:<code>` 键，
 * 以便合并同一入口的多个来源。
 */
function scanHarness(repo) {
  const rows = readJsonl(path.join(TOOL_ROOT, 'data', 'facts', 'ipc-harness-index.jsonl'));
  const out = [];
  for (const r of rows) {
    if (!r || !r.file || !r.file.startsWith(`${repo}/`)) continue;
    if (!r.interfaceToken || !r.codeExpr) continue;
    out.push(baseEntry({
      entryKey: `ipc:${repo}:${r.interfaceToken}:${r.codeExpr}`,
      channel: 'ipc',
      repo,
      kind: 'ipc-remote',
      identity: { token: r.interfaceToken, code: r.codeExpr },
      site: { file: r.file, line: r.line || 1, symbol: null },
      provenance: ['harness'],
      attackerPosition: ['third-party-app', 'system-app'],
      requiredChecks: ['token-permission', 'parcel-bounds', 'type-tag'],
      controlledInputs: ['code', 'parcel'],
      implLink: { status: 'related', file: r.file, line: r.line || 1, reason: 'harness-invocation' },
      confidence: 'heuristic'
    }));
  }
  return out;
}

// ------------------------------------------------------------- aggregate

function dedupe(rows) {
  const map = new Map();
  for (const r of rows) {
    if (!map.has(r.entryKey)) {
      map.set(r.entryKey, r);
      continue;
    }
    const e = map.get(r.entryKey);
    e.provenance = Array.from(new Set([...(e.provenance || []), ...(r.provenance || [])]));
    if (!e.implLink || e.implLink.status === 'unresolved') e.implLink = r.implLink;
    if ((!e.site || !e.site.line) && r.site) e.site = r.site;
    if (!e.identity.action && r.identity && r.identity.action) e.identity.action = r.identity.action;
    e.duplicates = (e.duplicates || 0) + 1;
  }
  return [...map.values()];
}

function isResolved(e) {
  return !!(e.site && e.site.file && e.site.line > 0 && e.identity && Object.keys(e.identity).length);
}
function isContracted(e) {
  return isResolved(e) && (e.attackerPosition || []).length > 0 && (e.requiredChecks || []).length > 0;
}
function isLinked(e) {
  return !!(e.implLink && e.implLink.status === 'verified');
}
function isWeakLinked(e) {
  return !!(e.implLink && ['related', 'declared'].includes(e.implLink.status));
}
function isVerified(e) {
  return !!(e.implLink && e.implLink.status === 'verified');
}

function summarize(rows, repo) {
  const by = {};
  const byProvenance = {};
  let multiSource = 0;
  for (const r of rows) {
    const c = (by[r.channel] = by[r.channel] || {
      expected: 0, resolved: 0, contracted: 0, linked: 0, weakLinked: 0, verified: 0,
      unresolvedReasons: {}, unlinkedReasons: {}
    });
    c.expected += 1;
    if ((r.provenance || []).length > 1) multiSource += 1;
    for (const p of r.provenance || []) byProvenance[p] = (byProvenance[p] || 0) + 1;
    if (isResolved(r)) c.resolved += 1;
    else {
      const reason = !r.site || !r.site.file ? 'no-site' : !r.site.line ? 'no-line' : 'no-identity';
      c.unresolvedReasons[reason] = (c.unresolvedReasons[reason] || 0) + 1;
    }
    if (isContracted(r)) c.contracted += 1;
    else c.unresolvedReasons['not-contracted'] = (c.unresolvedReasons['not-contracted'] || 0) + 1;
    if (isLinked(r)) c.linked += 1;
    else {
      if (isWeakLinked(r)) c.weakLinked += 1;
      const reason = (r.implLink && r.implLink.reason) || 'no-impl';
      c.unlinkedReasons[reason] = (c.unlinkedReasons[reason] || 0) + 1;
    }
    if (isVerified(r)) c.verified += 1;
  }
  const t = { expected: 0, resolved: 0, contracted: 0, linked: 0, weakLinked: 0, verified: 0 };
  for (const c of Object.values(by)) for (const k of Object.keys(t)) t[k] += c[k];
  const rate = (a, b) => (b ? Number((a / b).toFixed(4)) : null);
  return {
    repo,
    totals: {
      ...t,
      multiSource,
      // SDR = 本次枚举出的入口里，有 file/line 与身份的占比。
      // 注意：这不是 ECR；语义契约合成（sink/前置条件/攻击者约束）尚未实现，
      // 因此 `contracted` 目前按构造等于 `resolved`，ECR 会虚高到 1.0。
      sdr: rate(t.resolved, t.expected),
      ilr: rate(t.linked, t.contracted),
      weakLinkRate: rate(t.weakLinked, t.contracted),
      linkVerifiedRate: rate(t.verified, t.contracted),
      ecr: null,
      ecrReason: 'contract-synthesis-not-implemented; contracted==resolved by construction'
    },
    byProvenance,
    byChannel: by
  };
}

function enumerateRepo(repo, fns) {
  const abs = path.join(SOURCE_ROOT, repo);
  const { walk } = require('./util');
  // 预扫 stub/proxy 文本，供 IDL 判定实现侧
  let stubText = '';
  for (const f of walk(abs, { exts: CPP_EXTS })) {
    if (!/stub|proxy|interface_code/i.test(f.rel)) continue;
    const { text } = readText(f.abs, 4 * 1024 * 1024);
    if (text && stubText.length < 8 * 1024 * 1024) stubText += `\n${text}`;
  }
  const rows = [];
  rows.push(...scanIdl(repo, abs, stubText));
  rows.push(...scanDispatch(repo, abs));
  rows.push(...scanDispatchMaps(repo, abs));
  rows.push(...scanHarness(repo));
  rows.push(...scanSa(repo, abs));
  rows.push(...scanNapi(repo, abs));
  rows.push(...scanSockets(repo, abs, fns));
  rows.push(...scanHdi(repo, abs, fns));
  rows.push(...scanParsers(repo, fns));
  rows.push(...scanBroadcasts(repo, abs, fns));
  return dedupe(rows);
}

module.exports = {
  enumerateRepo, summarize, isResolved, isContracted, isLinked, isVerified,
  scanIdl, scanDispatch, scanSa, scanNapi, scanSockets, scanHdi, scanParsers, scanBroadcasts
};
