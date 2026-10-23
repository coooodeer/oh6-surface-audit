'use strict';

/**
 * invariants.js —— P8 三种 invariant pattern 的权威声明。
 *
 * 前两条来自 oh6-vuln-agent/spec/invariants.yaml；第三条 INV-PAT-LIFECYCLE
 * 由本目标补齐，authority 指向本地历史族 lifetime-guard-added（42 条）与 P2 生命周期语义。
 * 这里只声明“命题与权威”，不做判定。
 */

const INVARIANTS = Object.freeze({
  'INV-PAT-STATE-GUARD': {
    id: 'INV-PAT-STATE-GUARD',
    text: '状态/状态码的写入必须满足状态机合法性（写入前有守卫或校验；先守卫后写入）',
    proposition: 'P-STATE-MACHINE-LEGAL',
    authority: 'oh6-vuln-agent/spec/invariants.yaml#patterns/INV-PAT-STATE-GUARD; propositionsByCode:reject:state-machine-legal; history-invariants state-guard-added (7)',
    source: 'spec'
  },
  'INV-PAT-RETURN-CONTRACT': {
    id: 'INV-PAT-RETURN-CONTRACT',
    text: '成功返回必须与内部状态一致（错误路径不得报成功；返回码必须来自真实检查结果）',
    proposition: 'P-STATE-MACHINE-LEGAL',
    authority: 'oh6-vuln-agent/spec/invariants.yaml#patterns/INV-PAT-RETURN-CONTRACT; propositionsByCode:reject:state-machine-legal; history return-path shapes',
    source: 'spec'
  },
  'INV-PAT-LIFECYCLE': {
    id: 'INV-PAT-LIFECYCLE',
    text: '对象的释放/重置必须满足生命周期与所有权约束（释放前有归属/引用计数/锁/空检查守卫）',
    proposition: 'P-LIFETIME-LEGAL',
    authority: 'oh6-vuln-agent/data/facts/history-invariants.jsonl#lifetime-guard-added (42); P2 O4/O5 lifecycle-anchor semantics; lib/p1p2p7p8/invariants.js',
    source: 'p1p2p7p8-extension'
  }
});

function invariantById(id) {
  return INVARIANTS[id] || null;
}

module.exports = { INVARIANTS, invariantById };
