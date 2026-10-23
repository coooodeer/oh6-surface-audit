'use strict';

/**
 * P1 fixtures（内存破坏）。
 *
 * 三类：
 *   - synthetic：5 正 + 5 负，正例 original=VIOLATION / mutant=SATISFIED，
 *     负例 original=SATISFIED / mutant=VIOLATION；
 *   - history-local：本地 history-invariants 的 bounds-check-added（pre/post/mutant）；
 *   - history-positive：本地历史正例 CWE-121/122（pre/post）。
 *
 * 全部只作 fixture/校准，不进入生产 D4 统计，不写 O10。
 */

const synthetic = [
  {
    id: 'P1-SYN-POS-01',
    class: 'P1',
    kind: 'synthetic-positive',
    label: 'parcel 读长度直接 malloc，无上界检查',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    char *buf = (char *)malloc(len);',
        '    if (buf == nullptr) { return; }',
        '    memcpy(buf, parcel.GetData(), len);',
        '    *out = buf;',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len <= 0 || len > MAX_ARRAY_LEN) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    if (buf == nullptr) { return; }',
        '    memcpy(buf, parcel.GetData(), len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'no-dominating-upper-bound-check' }
  },
  {
    id: 'P1-SYN-POS-02',
    class: 'P1',
    kind: 'synthetic-positive',
    label: 'check 在 sink 之后',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    char *buf = (char *)malloc(len);',
        '    if (len > MAX_ARRAY_LEN) {',
        '        free(buf);',
        '        return;',
        '    }',
        '    *out = buf;',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len > MAX_ARRAY_LEN) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'check-after-sink' }
  },
  {
    id: 'P1-SYN-POS-03',
    class: 'P1',
    kind: 'synthetic-positive',
    label: 'check 检查错变量',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    int32_t other = parcel.ReadInt32();',
        '    if (other > MAX_ARRAY_LEN) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    int32_t other = parcel.ReadInt32();',
        '    if (other > MAX_ARRAY_LEN || len > MAX_ARRAY_LEN) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'wrong-variable-check' }
  },
  {
    id: 'P1-SYN-POS-04',
    class: 'P1',
    kind: 'synthetic-positive',
    label: 'check 在死分支',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (false) {',
        '        if (len > MAX_ARRAY_LEN) { return; }',
        '    }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len > MAX_ARRAY_LEN) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'check-in-dead-branch' }
  },
  {
    id: 'P1-SYN-POS-05',
    class: 'P1',
    kind: 'synthetic-positive',
    label: '只有下界检查，仍可超大分配',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len <= 0) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len <= 0 || len > MAX_ARRAY_LEN) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'lower-bound-only' }
  },
  {
    id: 'P1-SYN-NEG-01',
    class: 'P1',
    kind: 'synthetic-negative',
    label: '早退守卫给出 literal 上界',
    source: {
      original: [
        'bool CopyString(Parcel &parcel, char *dst, size_t cap)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len < 0 || (size_t)len > cap) { return false; }',
        '    memcpy(dst, parcel.GetData(), (size_t)len);',
        '    return true;',
        '}'
      ].join('\n'),
      mutant: [
        'bool CopyString(Parcel &parcel, char *dst, size_t cap)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    memcpy(dst, parcel.GetData(), (size_t)len);',
        '    return true;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'memcpy\\s*\\(', checkVars: ['len', 'cap'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'check-before-sink' }
  },
  {
    id: 'P1-SYN-NEG-02',
    class: 'P1',
    kind: 'synthetic-negative',
    label: 'guarded-sink：只有 len 有界才 malloc',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len > 0 && len <= MAX_ARRAY_LEN) {',
        '        char *buf = (char *)malloc(len);',
        '        *out = buf;',
        '    }',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'guarded-sink' }
  },
  {
    id: 'P1-SYN-NEG-03',
    class: 'P1',
    kind: 'synthetic-negative',
    label: 'CheckReadLength 辅助函数覆盖 sink',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (CheckReadLength((size_t)len, BYTE_SIZE_32)) {',
        '        char *buf = (char *)malloc(len);',
        '        *out = buf;',
        '    }',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'bound-helper' }
  },
  {
    id: 'P1-SYN-NEG-04',
    class: 'P1',
    kind: 'synthetic-negative',
    label: '目标缓冲区容量上界',
    source: {
      original: [
        'bool CopyName(Parcel &parcel, char *dst, size_t dstSize)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len < 0 || len > (int32_t)dstSize) { return false; }',
        '    memcpy(dst, parcel.GetData(), (size_t)len);',
        '    return true;',
        '}'
      ].join('\n'),
      mutant: [
        'bool CopyName(Parcel &parcel, char *dst, size_t dstSize)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    memcpy(dst, parcel.GetData(), (size_t)len);',
        '    return true;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'memcpy\\s*\\(', checkVars: ['len', 'dstSize'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'capacity-bound' }
  },
  {
    id: 'P1-SYN-NEG-05',
    class: 'P1',
    kind: 'synthetic-negative',
    label: '固定上限常量 + 上界比较',
    source: {
      original: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len > 4096) { return; }',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n'),
      mutant: [
        'void ReadArray(Parcel &parcel, char **out)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    char *buf = (char *)malloc(len);',
        '    *out = buf;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', checkVars: ['len'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'literal-cap' }
  }
];

const historyLocal = [
  {
    id: 'P1-HIST-bb00b84c',
    class: 'P1',
    kind: 'history-local',
    historyId: 'INV-HIST-bb00b84c',
    family: 'bounds-check-added',
    label: 'domain_account_parcel.h：data/size 上界检查',
    analysisBySource: {
      pre: { sinkPattern: 'ParseFrom\\s*\\(', checkVars: ['data', 'size'] },
      post: { sinkPattern: 'WriteBuffer\\s*\\(', checkVars: ['data', 'size'], checkPattern: 'data\\s*!=\\s*0\\s*&&\\s*size\\s*>\\s*0' },
      mutant: { sinkPattern: 'WriteBuffer\\s*\\(', checkVars: ['data', 'size'] }
    },
    expected: { pre: 'VIOLATION', post: 'SATISFIED', mutant: 'VIOLATION', preAlready: false }
  },
  {
    id: 'P1-HIST-85cc873e',
    class: 'P1',
    kind: 'history-local',
    historyId: 'INV-HIST-85cc873e',
    family: 'bounds-check-added',
    label: 'ability_command.cpp：旧 MakeWantFromCmd 已有 optind 上界，witness 非新增',
    extract: { scopeFunction: 'MakeWantFromCmd' },
    mutantRemovePattern: 'optind\\s*<\\s*0',
    analysis: {
      sinkPattern: 'argv_\\[optind\\]',
      checkVars: ['optind'],
      checkPattern: 'optind\\s*<\\s*0\\s*\\|\\|\\s*optind\\s*>\\s*argc_'
    },
    expected: { pre: 'SATISFIED', post: 'SATISFIED', mutant: 'VIOLATION', preAlready: true }
  }
];

const historyPositive = [
  {
    id: 'P1-HPOS-CWE121',
    class: 'P1',
    kind: 'history-positive',
    cwe: 'CWE-121',
    positiveId: 'HIST-74ecd44d93bff47d',
    label: 'kernel liteos_a SysEpollWait/SysEpollPwait：maxevents 上界',
    analysisBySource: {
      pre: { sinkPattern: 'CPY_FROM_USER\\s*\\(', checkVars: ['maxevents'] },
      post: { sinkPattern: 'DUP_FROM_USER_NOCOPY\\s*\\(', checkVars: ['maxevents'], checkPattern: 'maxevents\\s*>\\s*EPOLL_DEFAULT_SIZE' }
    },
    expected: { pre: 'VIOLATION', post: 'SATISFIED' }
  },
  {
    id: 'P1-HPOS-CWE122',
    class: 'P1',
    kind: 'history-positive',
    cwe: 'CWE-122',
    positiveId: 'HIST-753a14eea838d61c',
    label: 'kernel liteos_a epoll_wait：循环上界从 nodeCount 改为 pollSize',
    analysisBySource: {
      pre: { sinkPattern: 'pFd\\[i\\]\\.fd\\s*=', checkVars: ['maxevents', 'pollSize'] },
      post: { sinkPattern: 'pFd\\[i\\]\\.fd\\s*=', checkVars: ['maxevents', 'pollSize'], loopBoundPattern: 'i\\s*<\\s*pollSize' }
    },
    expected: { pre: 'VIOLATION', post: 'SATISFIED' }
  }
];

module.exports = { synthetic, historyLocal, historyPositive, all: [...synthetic, ...historyLocal, ...historyPositive] };
