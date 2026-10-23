'use strict';

/**
 * lib/facts/sa.js —— SA profile 解析（AG0.2）。
 * 形态：{process, systemability:[{name, libpath, run-on-create, ..., start-on-demand:{commonevent:[{name}]}}]}
 */

function lineOfNeedle(text, needle, from = 0) {
  const idx = text.indexOf(needle, from);
  if (idx < 0) return null;
  let n = 1;
  for (let i = 0; i < idx; i += 1) if (text[i] === '\n') n += 1;
  return n;
}

/** @returns {{process:string|null, systemabilities:object[]}} */
function parseSaProfile(text) {
  let json;
  try { json = JSON.parse(text); } catch (_) { return { process: null, systemabilities: [], parseError: true }; }
  const list = Array.isArray(json.systemability) ? json.systemability : [];
  return {
    process: json.process || null,
    systemabilities: list.map((sa) => ({
      saId: typeof sa.name === 'number' ? sa.name : Number(sa.name),
      library: sa.libpath || null,
      runOnCreate: sa['run-on-create'] === true,
      distributed: sa.distributed === true,
      events: (((sa['start-on-demand'] || {}).commonevent) || []).map((e) => e && e.name).filter(Boolean)
    }))
  };
}

function saRows(text, fileRel) {
  const parsed = parseSaProfile(text);
  return parsed.systemabilities.map((sa) => ({
    saId: sa.saId,
    process: parsed.process,
    library: sa.library,
    runOnCreate: sa.runOnCreate,
    distributed: sa.distributed,
    file: fileRel,
    line: lineOfNeedle(text, `"name": ${sa.saId}`) || lineOfNeedle(text, `"name":${sa.saId}`) || 1
  }));
}

function cesRows(text, fileRel) {
  const parsed = parseSaProfile(text);
  const rows = [];
  for (const sa of parsed.systemabilities) {
    for (const action of sa.events) {
      rows.push({ action, provider: sa.saId, process: parsed.process, file: fileRel, line: lineOfNeedle(text, action) || 1 });
    }
  }
  return rows;
}

module.exports = { parseSaProfile, saRows, cesRows, lineOfNeedle };
