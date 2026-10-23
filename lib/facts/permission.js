'use strict';

/**
 * lib/facts/permission.js —— permission 元数据（AG0.2）。
 *
 * 两类来源：
 *   1) root 内 dsoftbus 的接口→进程表：{INTERFACE_NAME, PROCESS_NAME:[...]}
 *   2) root 外权威表 permission_definitions.json：{definePermissions:[{name, grantMode, availableLevel, ...}]}
 *      —— 必须标 source=external-authority。
 */

function lineOfNeedle(text, needle, from = 0) {
  const idx = text.indexOf(needle, from);
  if (idx < 0) return null;
  let n = 1;
  for (let i = 0; i < idx; i += 1) if (text[i] === '\n') n += 1;
  return n;
}

/** dsoftbus：接口名 → 允许调用的进程列表 */
function parseInterfaceProcessTable(text, fileRel) {
  let json;
  try { json = JSON.parse(text); } catch (_) { return []; }
  if (!Array.isArray(json)) return [];
  return json
    .filter((e) => e && e.INTERFACE_NAME)
    .map((e) => ({
      name: e.INTERFACE_NAME,
      kind: 'interface-process-map',
      processes: Array.isArray(e.PROCESS_NAME) ? e.PROCESS_NAME : [],
      file: fileRel,
      line: lineOfNeedle(text, `"${e.INTERFACE_NAME}"`) || 1
    }));
}

/** 官方权限定义表 */
function parsePermissionDefinitions(text, fileRel) {
  let json;
  try { json = JSON.parse(text); } catch (_) { return []; }
  const list = Array.isArray(json.definePermissions) ? json.definePermissions : [];
  return list
    .filter((p) => p && p.name)
    .map((p) => ({
      name: p.name,
      level: p.availableLevel || null,
      grantMode: p.grantMode || null,
      availableType: p.availableType || null,
      since: typeof p.since === 'number' ? p.since : null,
      deprecated: p.deprecated || null,
      file: fileRel,
      line: lineOfNeedle(text, `"${p.name}"`) || 1
    }));
}

module.exports = { parseInterfaceProcessTable, parsePermissionDefinitions, lineOfNeedle };
