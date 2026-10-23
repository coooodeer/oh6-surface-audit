'use strict';

/**
 * P8 fixtures（逻辑漏洞）。
 *
 * synthetic：3 种 invariant × 2 正 + 1 负 = 9；负例覆盖
 *   invariant-not-applicable / validation-dominates-write / exception-path-legal。
 * history-local：本地 state-guard-added 至少 4 条做 pre/post/mutant 守卫差分。
 */

const synthetic = [
  {
    id: 'P8-SYN-STATE-POS-01',
    class: 'P8',
    kind: 'synthetic-positive',
    invariant: 'INV-PAT-STATE-GUARD',
    label: '状态写入无状态机守卫',
    source: {
      original: [
        'void Service::OnStart()',
        '{',
        '    running_ = true;',
        '    StartWork();',
        '}'
      ].join('\n'),
      mutant: [
        'void Service::OnStart()',
        '{',
        '    if (running_) { return; }',
        '    running_ = true;',
        '    StartWork();',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-STATE-GUARD', writePattern: 'running_\\s*=', checkVars: ['running_'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'no-dominating-guard' }
  },
  {
    id: 'P8-SYN-STATE-POS-02',
    class: 'P8',
    kind: 'synthetic-positive',
    invariant: 'INV-PAT-STATE-GUARD',
    label: '任意 code 直接映射为状态',
    source: {
      original: [
        'void SetState(int code, SoftBusState *state)',
        '{',
        '    *state = (SoftBusState)code;',
        '}'
      ].join('\n'),
      mutant: [
        'void SetState(int code, SoftBusState *state)',
        '{',
        '    if (code < 0 || code > SOFTBUS_STATE_MAX) { return; }',
        '    *state = (SoftBusState)code;',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-STATE-GUARD', writePattern: '\\*state\\s*=', checkVars: ['state', 'code'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'no-dominating-guard' }
  },
  {
    id: 'P8-SYN-STATE-NEG-01',
    class: 'P8',
    kind: 'synthetic-negative',
    invariant: 'INV-PAT-STATE-GUARD',
    label: '先守卫后写入（validation dominates write）',
    source: {
      original: [
        'void Service::OnStart()',
        '{',
        '    if (state_ != ServiceState::STOPPED) { return; }',
        '    state_ = ServiceState::RUNNING;',
        '}'
      ].join('\n'),
      mutant: [
        'void Service::OnStart()',
        '{',
        '    state_ = ServiceState::RUNNING;',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-STATE-GUARD', writePattern: 'state_\\s*=', checkVars: ['state_'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'validation-dominates-write' }
  },
  {
    id: 'P8-SYN-RET-POS-01',
    class: 'P8',
    kind: 'synthetic-positive',
    invariant: 'INV-PAT-RETURN-CONTRACT',
    label: '错误路径返回 ERR_OK',
    source: {
      original: [
        'ErrCode DoWork(char *buf, int len)',
        '{',
        '    if (buf == nullptr || len <= 0) {',
        '        return ERR_OK;',
        '    }',
        '    return Run(buf, len);',
        '}'
      ].join('\n'),
      mutant: [
        'ErrCode DoWork(char *buf, int len)',
        '{',
        '    if (buf == nullptr || len <= 0) {',
        '        return ERR_INVALID_VALUE;',
        '    }',
        '    return Run(buf, len);',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-RETURN-CONTRACT', writePattern: 'return\\s+', anyGuardCovers: true },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'error-path-reports-success' }
  },
  {
    id: 'P8-SYN-RET-POS-02',
    class: 'P8',
    kind: 'synthetic-positive',
    invariant: 'INV-PAT-RETURN-CONTRACT',
    label: '无条件成功返回，无真实检查',
    source: {
      original: [
        'ErrCode Commit(Record *record)',
        '{',
        '    Save(record);',
        '    return ERR_OK;',
        '}'
      ].join('\n'),
      mutant: [
        'ErrCode Commit(Record *record)',
        '{',
        '    if (record == nullptr || !Save(record)) {',
        '        return ERR_INVALID_VALUE;',
        '    }',
        '    return ERR_OK;',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-RETURN-CONTRACT', writePattern: 'return\\s+ERR_OK', anyGuardCovers: true },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'unconditional-success-return' }
  },
  {
    id: 'P8-SYN-RET-NEG-01',
    class: 'P8',
    kind: 'synthetic-negative',
    invariant: 'INV-PAT-RETURN-CONTRACT',
    label: 'invariant 不适用：空桩 return ERR_OK',
    source: {
      original: [
        'ErrCode Callback::OnRequestRedirected(const Want &request)',
        '{',
        '    return ERR_OK;',
        '}'
      ].join('\n'),
      mutant: [
        'ErrCode Callback::OnRequestRedirected(const Want &request)',
        '{',
        '    if (request.GetStringParam("x").empty()) {',
        '        return ERR_INVALID_VALUE;',
        '    }',
        '    return ERR_OK;',
        '}'
      ].join('\n')
    },
    analysis: {
      mode: 'invariant', invariant: 'INV-PAT-RETURN-CONTRACT', writePattern: 'return\\s+ERR_OK',
      invariantApplicable: false
    },
    expected: { original: 'SATISFIED', mutant: 'SATISFIED', negativeCoverage: 'invariant-not-applicable' }
  },
  {
    id: 'P8-SYN-LIFE-POS-01',
    class: 'P8',
    kind: 'synthetic-positive',
    invariant: 'INV-PAT-LIFECYCLE',
    label: '释放对象前无空检查/所有权守卫',
    source: {
      original: [
        'void Release(Obj *obj)',
        '{',
        '    obj->Reset();',
        '    delete obj;',
        '}'
      ].join('\n'),
      mutant: [
        'void Release(Obj *obj)',
        '{',
        '    if (obj == nullptr) { return; }',
        '    obj->Reset();',
        '    delete obj;',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-LIFECYCLE', writePattern: 'delete\\s+obj', checkVars: ['obj'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'no-lifetime-guard' }
  },
  {
    id: 'P8-SYN-LIFE-POS-02',
    class: 'P8',
    kind: 'synthetic-positive',
    invariant: 'INV-PAT-LIFECYCLE',
    label: 'release 后继续使用（生命周期写点无守卫）',
    source: {
      original: [
        'void UseAfterRelease(Obj *obj)',
        '{',
        '    obj->Release();',
        '    obj->DoWork();',
        '}'
      ].join('\n'),
      mutant: [
        'void UseAfterRelease(Obj *obj)',
        '{',
        '    if (obj == nullptr || obj->IsReleased()) { return; }',
        '    obj->Release();',
        '    obj->DoWork();',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-LIFECYCLE', writePattern: 'obj->Release\\s*\\(', checkVars: ['obj'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'no-lifetime-guard' }
  },
  {
    id: 'P8-SYN-LIFE-NEG-01',
    class: 'P8',
    kind: 'synthetic-negative',
    invariant: 'INV-PAT-LIFECYCLE',
    label: '引用计数/锁守卫覆盖释放（exception path legal）',
    source: {
      original: [
        'void Release(std::shared_ptr<Obj> obj)',
        '{',
        '    std::lock_guard<std::mutex> lock(mutex_);',
        '    if (obj == nullptr) { return; }',
        '    obj->Reset();',
        '    obj.reset();',
        '}'
      ].join('\n'),
      mutant: [
        'void Release(Obj *obj)',
        '{',
        '    obj->Reset();',
        '    delete obj;',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'invariant', invariant: 'INV-PAT-LIFECYCLE', writePattern: '(?:delete\\s+obj|obj\\.reset)', checkVars: ['obj'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'exception-path-legal' }
  }
];

const historyLocal = [
  { id: 'P8-HIST-35f97eb9', historyId: 'INV-HIST-35f97eb9', label: 'event_hitrace_meter_adapter.h：IsTagEnabled 非空守卫' },
  { id: 'P8-HIST-99d126b9', historyId: 'INV-HIST-99d126b9', label: 'napi_os_account.cpp：状态/前置条件守卫' },
  { id: 'P8-HIST-cc89b164', historyId: 'INV-HIST-cc89b164', label: 'inner_os_account_manager.cpp：状态守卫' },
  { id: 'P8-HIST-f9df3318', historyId: 'INV-HIST-f9df3318', label: 'dbinder_service.cpp：状态守卫' }
].map((c) => ({
  ...c,
  class: 'P8',
  kind: 'history-local',
  family: 'state-guard-added',
  analysis: { mode: 'guard-differential', useWitnessAsGuard: true },
  expected: { pre: 'VIOLATION', post: 'SATISFIED', mutant: 'VIOLATION' }
}));

module.exports = { synthetic, historyLocal, all: [...synthetic, ...historyLocal] };
