'use strict';

/**
 * lib/autonomy/jsonl.js —— 安全 JSONL 读写。
 *
 * 为什么不用 `lib/facts/query.js#forEachRow`：
 *   它按 1 MiB 块 `buf.toString('utf8')` 切行，**多字节字符跨块会被截断**（AG0 已知坑，§9）。
 *   本模块用 `StringDecoder` 持有半个字符，跨块不丢字节；坏行**计数上报**而不是静默跳过。
 *
 * 契约：
 *   - readJsonl(file) → {rows, malformed:[{line,reason,preview}], bytes, lines, tailPartial}
 *   - readJsonl(file,{strict:true}) 有坏行 ⇒ 抛 code='malformed-record'
 *   - writeJsonl(file, rows) 固定 `JSON.stringify` + '\n'，UTF-8 无 BOM
 *   - tailPartial：文件末尾没有换行且末行不完整 ⇒ true（`check` 用于 tail-partial 判定）
 */

const fs = require('fs');
const path = require('path');
const { StringDecoder } = require('string_decoder');

const CHUNK = 256 * 1024;

function makeErr(code, message, extra) {
  const e = new Error(message);
  e.code = code;
  if (extra) Object.assign(e, extra);
  return e;
}

/**
 * 流式逐行读 JSONL（StringDecoder 保证跨块 UTF-8 完整）。
 * @param {string} file
 * @param {{onRow?:function, strict?:boolean, needle?:string, needles?:string[], maxRows?:number}} [opts]
 *   needle/needles：行内子串预过滤（只对命中的行做 JSON.parse），用于大文件按仓库裁剪。
 */
function readJsonl(file, opts = {}) {
  const result = { rows: [], malformed: [], bytes: 0, lines: 0, tailPartial: false, file };
  if (!fs.existsSync(file)) {
    result.missing = true;
    if (opts.strict) throw makeErr('missing-file', `jsonl: missing file ${file}`, { file });
    return result;
  }
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(CHUNK);
  const decoder = new StringDecoder('utf8');
  let carry = '';
  let lastByte = -1;
  const needles = opts.needles && opts.needles.length ? opts.needles : (opts.needle ? [opts.needle] : null);
  const maxRows = opts.maxRows || 0;
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      result.bytes += n;
      lastByte = buf[n - 1];
      const text = carry + decoder.write(buf.subarray(0, n));
      const parts = text.split('\n');
      carry = parts.pop();
      for (const line of parts) {
        handleLine(line);
        if (maxRows && result.rows.length >= maxRows) return result;
      }
    }
    carry += decoder.end();
    if (carry) {
      handleLine(carry, true);
      result.tailPartial = true;
    }
  } finally {
    fs.closeSync(fd);
  }
  if (result.bytes > 0 && lastByte !== 0x0a && result.malformed.length === 0) result.tailPartial = true;
  if (opts.strict && result.malformed.length) {
    throw makeErr('malformed-record', `jsonl: ${result.malformed.length} malformed line(s) in ${path.basename(file)}`, {
      file,
      malformed: result.malformed
    });
  }
  return result;

  function handleLine(raw, isTail) {
    const line = raw.replace(/\r$/, '');
    if (!line) return;
    result.lines += 1;
    if (needles && !needles.some((n) => line.indexOf(n) >= 0)) return;
    let row;
    try {
      row = JSON.parse(line);
    } catch (e) {
      result.malformed.push({
        line: result.lines,
        reason: isTail ? 'tail-partial' : 'json-parse',
        preview: line.slice(0, 120)
      });
      return;
    }
    result.rows.push(row);
    if (opts.onRow && opts.onRow(row) === false) {
      // onRow 返回 false：停止读取（但仍保持已读统计）
      result.stopped = true;
    }
  }
}

/** 只解析包含 needle 的行（大文件按 repo 裁剪的快速通道） */
function scanJsonl(file, needle, onRow) {
  return readJsonl(file, { needle, onRow });
}

function writeJsonl(file, rows) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const body = rows.map((r) => JSON.stringify(r)).join('\n');
  fs.writeFileSync(file, rows.length ? `${body}\n` : '', 'utf8');
  return { written: rows.length, file };
}

/** 追加一行（append-only 账本） */
function appendJsonl(file, row) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify(row)}\n`, 'utf8');
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

module.exports = { readJsonl, scanJsonl, writeJsonl, appendJsonl, readJson, makeErr, CHUNK };
