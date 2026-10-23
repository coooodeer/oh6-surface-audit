'use strict';

/**
 * lib/l7/render.js —— 确定性 finding 卡/索引/executive 渲染。
 */

function esc(s) {
  return String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function code(s) {
  return `\`${String(s == null ? '' : s).replace(/`/g, '\\`')}\``;
}

function renderCard(card) {
  const lines = [];
  lines.push(`# ${card.findingId}: ${card.title}`);
  lines.push('');
  lines.push(`- 类别：${card.class} / ${card.tier}`);
  lines.push(`- 组件：${code(card.repo || '')}`);
  lines.push(`- 位置：${code(`${card.file || ''}:${card.line || ''}`)}`);
  lines.push(`- 函数：${code(card.function || 'n/a')}`);
  lines.push(`- 严重性：**${card.severity.level}** — ${card.severity.rationale}`);
  lines.push(`- 置信度：${card.confidence}`);
  lines.push(`- 状态：${card.status}`);
  lines.push('');
  lines.push('## 摘要');
  lines.push('');
  lines.push(card.weakness.rootCause || '');
  lines.push('');
  lines.push('## 入口');
  lines.push('');
  lines.push(`- kind: ${code(card.entry && card.entry.kind || 'n/a')}`);
  lines.push(`- id: ${code(card.entry && card.entry.id || 'n/a')}`);
  lines.push(`- attackerPositions: ${JSON.stringify(card.entry && card.entry.attackerPositions || [])}`);
  lines.push('');
  lines.push('## 证据');
  lines.push('');
  lines.push('| ref | file:line | source | text |');
  lines.push('| --- | --- | --- | --- |');
  for (const e of card.evidence) lines.push(`| ${esc(e.ref)} | ${esc(`${e.file}:${e.line}`)} | ${esc(e.source)} | ${esc(e.text)} |`);
  lines.push('');
  lines.push('## 义务');
  lines.push('');
  lines.push('| id | kind | status | reason |');
  lines.push('| --- | --- | --- | --- |');
  for (const o of card.obligations) lines.push(`| ${esc(o.id)} | ${esc(o.kind || '')} | ${esc(o.status || '')} | ${esc(o.reason || '')} |`);
  lines.push('');
  lines.push('## 攻击场景');
  lines.push('');
  lines.push(card.attackScenario);
  lines.push('');
  lines.push('## 影响');
  lines.push('');
  lines.push(card.impact);
  lines.push('');
  lines.push('## 前置条件');
  lines.push('');
  for (const p of card.prerequisites) lines.push(`- ${p}`);
  lines.push('');
  lines.push('## 复现');
  lines.push('');
  lines.push(`- kind: ${card.reproduction.kind}`);
  lines.push(`- runId: ${card.reproduction.runId || 'n/a'}`);
  lines.push(`- command: ${card.reproduction.command || 'n/a'}`);
  lines.push(`- inputHash: ${card.reproduction.inputHash || 'n/a'}`);
  lines.push('');
  lines.push('## 修复建议');
  lines.push('');
  lines.push(card.remediation);
  lines.push('');
  lines.push('## 引用');
  lines.push('');
  for (const r of card.references) lines.push(`- ${r}`);
  lines.push('');
  return lines.join('\n');
}

function renderIndex(cards, observations, summary) {
  const lines = [];
  lines.push('# L7 Findings');
  lines.push('');
  lines.push(`- reportable cards: ${cards.length}`);
  lines.push(`- observations (T3): ${observations.length}`);
  lines.push(`- generated: ${summary.generatedAt}`);
  lines.push('');
  lines.push('## 按严重性');
  lines.push('');
  lines.push('| severity | count |');
  lines.push('| --- | ---: |');
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    lines.push(`| ${sev} | ${cards.filter((c) => c.severity.level === sev).length} |`);
  }
  lines.push('');
  lines.push('## 卡片');
  lines.push('');
  lines.push('| finding | class | tier | severity | component | file:line |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const c of cards) {
    lines.push(`| [${c.findingId}](findings/${c.findingId}.md) | ${c.class} | ${c.tier} | ${c.severity.level} | ${esc(c.component || '')} | ${esc(`${c.file}:${c.line}`)} |`);
  }
  lines.push('');
  lines.push('## T3 Observations');
  lines.push('');
  lines.push('| observation | class | file:line | reason |');
  lines.push('| --- | --- | --- | --- |');
  for (const o of observations) lines.push(`| ${o.observationId} | ${o.class} | ${esc(`${o.file || ''}:${o.line || ''}`)} | ${esc(o.reason)} |`);
  lines.push('');
  return lines.join('\n');
}

function renderExecutive(summary, cards = summary.cards || []) {
  const lines = [];
  lines.push('# Executive Summary');
  lines.push('');
  lines.push(`- 生成时间：${summary.generatedAt}`);
  lines.push(`- 范围：${summary.scope}`);
  lines.push(`- T1 confirmed：${summary.counts.T1}`);
  lines.push(`- T2 weak candidate：${summary.counts.T2}`);
  lines.push(`- T3 instrumentation gap：${summary.counts.T3}`);
  lines.push(`- T4 negative：${summary.counts.T4}`);
  lines.push(`- reportable cards：${summary.cardCount}`);
  lines.push(`- unresolved refs：${summary.unresolved.length}`);
  lines.push('');
  if (summary.counts.T1 === 0) {
    lines.push('> 本批没有 target T1。所有 finding card 是 T2 静态弱候选，不是已确认可利用漏洞；没有用 L5 动态证据升级。');
    lines.push('');
  }
  lines.push('## 主要发现');
  lines.push('');
  for (const c of cards.slice(0, 20)) {
    lines.push(`- ${c.findingId} [${c.class}/${c.severity.level}] ${c.file}:${c.line} — ${c.title}`);
  }
  if (cards.length > 20) lines.push(`- … 其余 ${cards.length - 20} 张见 FINDINGS.md`);
  lines.push('');
  lines.push('## 方法与限制');
  lines.push('');
  lines.push('- finding card 由 claim/verdict 自动生成，不是手工撰写。');
  lines.push('- 证据 file:line 由 L1/L4a/live 数据回查；unresolved 会阻止卡进入 reportable。');
  lines.push('- T2 未经过 L5 动态确认，不能视为漏洞；T3 只作 observation；T4 只作附录。');
  lines.push('- delivery 包只生成本地文件，不联网、不创建 PR/advisory。');
  lines.push('');
  return lines.join('\n');
}

module.exports = { renderCard, renderIndex, renderExecutive, esc, code };
