'use strict';

/**
 * 把 live 模型判定与机械 witness 差分并排，生成 out/report/specdiff-live.md。
 * 只读两边的 results.jsonl，不调用模型。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const MECH = path.join(ROOT, 'out', 'specdiff', 'results.jsonl');
const LIVE = path.join(ROOT, 'out', 'specdiff', 'live', 'results.jsonl');
const OUT = path.join(ROOT, 'out', 'report', 'specdiff-live.md');

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
}

const mech = new Map(readJsonl(MECH).map((r) => [r.id, r]));
const live = readJsonl(LIVE);
const rows = live.map((l) => {
  const m = mech.get(l.id) || {};
  const expected = m.status === 'validated' ? { pre: true, post: true } : null;
  const got = l.parsed ? { pre: l.parsed.preViolates, post: l.parsed.postSatisfies } : null;
  const agree = expected && got ? expected.pre === got.pre && expected.post === got.post : null;
  let verdict;
  if (!l.ok) verdict = 'call-failed';
  else if (expected && agree) verdict = 'confirmed';
  else if (m.status === 'pre-already' && got && got.pre === false) verdict = 'seed-invalid';
  else verdict = 'review';
  return {
    id: l.id,
    family: l.family,
    mechanical: m.status || null,
    region: m.pre ? `${m.pre.kind}${m.pre.fallback ? '/fallback' : ''}` : null,
    modelKind: l.kind,
    ok: l.ok,
    pre: got ? got.pre : null,
    post: got ? got.post : null,
    agree,
    verdict,
    usage: l.usage,
    reason: l.parsed ? l.parsed.reason : null,
    error: l.kind === 'ok' ? l.parseError : `${l.kind}:${l.reason || ''}`
  };
});

const ok = rows.filter((r) => r.ok);
const agree = ok.filter((r) => r.agree === true);
const disagree = ok.filter((r) => r.agree === false);
const unknown = rows.filter((r) => !r.ok);
const confirmed = rows.filter((r) => r.verdict === 'confirmed');
const seedInvalid = rows.filter((r) => r.verdict === 'seed-invalid');
const review = rows.filter((r) => r.verdict === 'review');
const tokens = (a) => a.reduce((s, r) => s + ((r.usage && r.usage.promptTokens) || 0) + ((r.usage && r.usage.completionTokens) || 0), 0);

const lines = [];
lines.push('# Live 模型差分验证 vs 机械 witness 差分');
lines.push('');
lines.push(`生成时间：${new Date().toISOString()}`);
lines.push('');
lines.push(`输入：${live.length} 条有 prompt 的 patch；解析成功 ${ok.length} 条；机械 \`validated\` 且模型确认 ${confirmed.length} 条；机械 \`pre-already\` 且模型判 pre 不违反（seed 无效）${seedInvalid.length} 条；需复核 ${review.length} 条；失败 ${unknown.length} 条。`);
lines.push(`Token：输入 ${ok.reduce((s, r) => s + ((r.usage && r.usage.promptTokens) || 0), 0)} / 输出 ${ok.reduce((s, r) => s + ((r.usage && r.usage.completionTokens) || 0), 0)} / 合计 ${tokens(ok)}。`);
lines.push('');
lines.push('口径：机械 `validated` 的期望是模型判 `preViolates=true ∧ postSatisfies=true`。模型只看本实验给出的 pre/post 区域，不是完整函数语义证明。');
lines.push('');
lines.push('| id | family | 机械 | 区域 | 模型 | pre | post | 判定 |');
lines.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
for (const r of rows) {
  lines.push(`| ${r.id} | ${r.family} | ${r.mechanical} | ${r.region} | ${r.modelKind}${r.ok ? '' : ' (fail)'} | ${r.pre} | ${r.post} | ${r.verdict} |`);
}
lines.push('');
if (disagree.length) {
  lines.push('## 不一致 / 需要人看的条目');
  lines.push('');
  for (const r of disagree) {
    lines.push(`### ${r.id}（${r.family}）`);
    lines.push('');
    lines.push(`- 机械：${r.mechanical}（${r.region}）`);
    lines.push(`- 模型：preViolates=${r.pre}, postSatisfies=${r.post}`);
    lines.push(`- 理由：${r.reason || '(none)'}`);
    lines.push('');
  }
}
if (seedInvalid.length) {
  lines.push('## 被模型证伪的机械 seed');
  lines.push('');
  for (const r of seedInvalid) {
    lines.push(`- ${r.id}（${r.family}）：机械状态 \`pre-already\`，模型判 \`preViolates=${r.pre}\` / \`postSatisfies=${r.post}\`。`);
    lines.push(`  - 理由：${r.reason || '(none)'}`);
  }
  lines.push('');
}
if (unknown.length) {
  lines.push('## 调用失败');
  lines.push('');
  for (const r of unknown) lines.push(`- ${r.id}: ${r.error}`);
  lines.push('');
}
lines.push('## 解释');
lines.push('');
lines.push('- 一致 = 模型认可机械 witness 差分，不等于规范语义正确；不一致需要看 pre/post 区域是否截断、hunk 是否选错。');
lines.push('- 模型只被问两个布尔判定，没有给它完整调用链/数据流，因此不能把它当作漏洞裁决。');
lines.push('- token 数是 provider 返回的 usage；Command Code 的金额不在本地价目覆盖范围，不报 CNY。');
lines.push('');
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, lines.join('\n'), 'utf8');
console.log(`wrote ${OUT}: ${live.length} live, ${ok.length} ok, ${agree.length} agree, ${disagree.length} disagree`);
