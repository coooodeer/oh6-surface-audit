'use strict';

/**
 * P7 fixtures（拒绝服务）。
 *
 * 四类 dosClass × 2 正 + 负例：正例无界/无限流，负例有 literal cap / limiter。
 * 另补 5 条 amplification fixture，用于把 D4 只有 1 条 amplification 候选的 claims 补到 6 条。
 * eval/external-cve/p7-cases.js 的 4 条只作义务/裁决校准，production:false。
 */

function loopCase(id, opts) {
  const head = opts.guarded
    ? ['while (pos < dumpInfo.length() && pos < MAX_DUMP_LEN) {']
    : ['while (pos < dumpInfo.length()) {'];
  return {
    id,
    class: 'P7',
    kind: opts.kind || 'synthetic-positive',
    dosClass: opts.dosClass,
    label: opts.label,
    source: {
      original: [
        'int ParseDump(const std::string &dumpInfo)',
        '{',
        '    size_t pos = 0;',
        ...head,
        '        Process(dumpInfo[pos]);',
        '        pos++;',
        '    }',
        '    return 0;',
        '}'
      ].join('\n'),
      mutant: [
        'int ParseDump(const std::string &dumpInfo)',
        '{',
        '    size_t pos = 0;',
        ...(opts.guarded ? ['while (pos < dumpInfo.length()) {'] : ['while (pos < dumpInfo.length() && pos < MAX_DUMP_LEN) {']),
        '        Process(dumpInfo[pos]);',
        '        pos++;',
        '    }',
        '    return 0;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'while\\s*\\(', capPattern: 'MAX_DUMP_LEN', criteria: ['cross-app-impact'] },
    expected: {
      original: opts.guarded ? 'SATISFIED' : 'VIOLATION',
      mutant: opts.guarded ? 'VIOLATION' : 'SATISFIED',
      originalReason: opts.guarded ? 'bounded-by-cap' : 'unbounded-loop'
    }
  };
}

const synthetic = [
  loopCase('P7-SYN-LOOP-POS-01', { dosClass: 'unbounded-loop', label: '输入长度驱动循环，无上限', kind: 'synthetic-positive' }),
  loopCase('P7-SYN-LOOP-NEG-01', { dosClass: 'unbounded-loop', label: 'literal 上限终止循环', kind: 'synthetic-negative', guarded: true }),
  {
    id: 'P7-SYN-ALLOC-POS-01',
    class: 'P7',
    kind: 'synthetic-positive',
    dosClass: 'unbounded-alloc',
    label: 'parcel 长度直接分配，无上限',
    source: {
      original: [
        'void *ReadBlob(Parcel &parcel)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    return malloc(len);',
        '}'
      ].join('\n'),
      mutant: [
        'void *ReadBlob(Parcel &parcel)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len > MAX_BLOB_SIZE) { return nullptr; }',
        '    return malloc(len);',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', capPattern: 'MAX_BLOB_SIZE', criteria: ['amplification'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'unbounded-alloc' }
  },
  {
    id: 'P7-SYN-ALLOC-NEG-01',
    class: 'P7',
    kind: 'synthetic-negative',
    dosClass: 'unbounded-alloc',
    label: '固定上限 + 提前返回',
    source: {
      original: [
        'void *ReadBlob(Parcel &parcel)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    if (len < 0 || len > MAX_BLOB_SIZE) { return nullptr; }',
        '    return malloc(len);',
        '}'
      ].join('\n'),
      mutant: [
        'void *ReadBlob(Parcel &parcel)',
        '{',
        '    int32_t len = parcel.ReadInt32();',
        '    return malloc(len);',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'malloc\\s*\\(', capPattern: 'MAX_BLOB_SIZE', criteria: ['amplification'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', originalReason: 'bounded-by-cap' }
  },
  {
    id: 'P7-SYN-HOLD-POS-01',
    class: 'P7',
    kind: 'synthetic-positive',
    dosClass: 'blocking-hold',
    label: '持锁执行攻击者可控重活，无超时',
    source: {
      original: [
        'int DoWork(std::mutex &m, const Request &req)',
        '{',
        '    std::lock_guard<std::mutex> lock(m);',
        '    return HeavyProcess(req.payload);',
        '}'
      ].join('\n'),
      mutant: [
        'int DoWork(std::mutex &m, const Request &req)',
        '{',
        '    std::lock_guard<std::mutex> lock(m);',
        '    if (req.payload.size() > MAX_PAYLOAD) { return -1; }',
        '    return HeavyProcess(req.payload);',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'HeavyProcess\\s*\\(', capPattern: 'MAX_PAYLOAD', criteria: ['persistence'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'blocking-hold' }
  },
  {
    id: 'P7-SYN-HOLD-NEG-01',
    class: 'P7',
    kind: 'synthetic-negative',
    dosClass: 'blocking-hold',
    label: '持锁前限制 payload 大小',
    source: {
      original: [
        'int DoWork(std::mutex &m, const Request &req)',
        '{',
        '    std::lock_guard<std::mutex> lock(m);',
        '    if (req.payload.size() > MAX_PAYLOAD) { return -1; }',
        '    return HeavyProcess(req.payload);',
        '}'
      ].join('\n'),
      mutant: [
        'int DoWork(std::mutex &m, const Request &req)',
        '{',
        '    std::lock_guard<std::mutex> lock(m);',
        '    return HeavyProcess(req.payload);',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'HeavyProcess\\s*\\(', capPattern: 'MAX_PAYLOAD', criteria: ['persistence'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', originalReason: 'bounded-by-cap' }
  },
  {
    id: 'P7-SYN-AMP-POS-01',
    class: 'P7',
    kind: 'synthetic-positive',
    dosClass: 'amplification',
    label: '一次输入触发 N×N 重复工作，无上限',
    source: {
      original: [
        'int Expand(const std::vector<Item> &items)',
        '{',
        '    int total = 0;',
        '    for (const auto &a : items) {',
        '        for (const auto &b : items) {',
        '            total += Merge(a, b);',
        '        }',
        '    }',
        '    return total;',
        '}'
      ].join('\n'),
      mutant: [
        'int Expand(const std::vector<Item> &items)',
        '{',
        '    if (items.size() > MAX_ITEMS) { return -1; }',
        '    int total = 0;',
        '    for (const auto &a : items) {',
        '        for (const auto &b : items) {',
        '            total += Merge(a, b);',
        '        }',
        '    }',
        '    return total;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'Merge\\s*\\(', capPattern: 'MAX_ITEMS', criteria: ['amplification'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'amplification-static-proxy' }
  },
  {
    id: 'P7-SYN-AMP-NEG-01',
    class: 'P7',
    kind: 'synthetic-negative',
    dosClass: 'amplification',
    label: '输入规模有上限的嵌套遍历',
    source: {
      original: [
        'int Expand(const std::vector<Item> &items)',
        '{',
        '    if (items.size() > MAX_ITEMS) { return -1; }',
        '    int total = 0;',
        '    for (const auto &a : items) {',
        '        for (const auto &b : items) {',
        '            total += Merge(a, b);',
        '        }',
        '    }',
        '    return total;',
        '}'
      ].join('\n'),
      mutant: [
        'int Expand(const std::vector<Item> &items)',
        '{',
        '    int total = 0;',
        '    for (const auto &a : items) {',
        '        for (const auto &b : items) {',
        '            total += Merge(a, b);',
        '        }',
        '    }',
        '    return total;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'Merge\\s*\\(', capPattern: 'MAX_ITEMS', criteria: ['amplification'] },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', originalReason: 'bounded-by-cap' }
  },
  {
    id: 'P7-SYN-AMP-FIX-01',
    class: 'P7',
    kind: 'fixture-claim',
    dosClass: 'amplification',
    label: 'amplification fixture 1：无界重复解析',
    source: {
      original: [
        'int ParseAll(const std::string &in)',
        '{',
        '    int n = 0;',
        '    for (size_t i = 0; i < in.size(); i++) {',
        '        for (size_t j = 0; j < in.size(); j++) {',
        '            n += Parse(in[j]);',
        '        }',
        '    }',
        '    return n;',
        '}'
      ].join('\n'),
      mutant: [
        'int ParseAll(const std::string &in)',
        '{',
        '    if (in.size() > MAX_PARSE_LEN) { return -1; }',
        '    int n = 0;',
        '    for (size_t i = 0; i < in.size(); i++) {',
        '        for (size_t j = 0; j < in.size(); j++) {',
        '            n += Parse(in[j]);',
        '        }',
        '    }',
        '    return n;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'Parse\\s*\\(', capPattern: 'MAX_PARSE_LEN', criteria: ['amplification'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', claims: true }
  },
  {
    id: 'P7-SYN-AMP-FIX-02',
    class: 'P7',
    kind: 'fixture-claim',
    dosClass: 'amplification',
    label: 'amplification fixture 2：一次请求放大 N 次回调',
    source: {
      original: [
        'void NotifyAll(const std::vector<Sub> &subs)',
        '{',
        '    for (const auto &s : subs) {',
        '        for (int i = 0; i < 8; i++) {',
        '            s->Notify(i);',
        '        }',
        '    }',
        '}'
      ].join('\n'),
      mutant: [
        'void NotifyAll(const std::vector<Sub> &subs)',
        '{',
        '    if (subs.size() > MAX_SUBS) { return; }',
        '    for (const auto &s : subs) {',
        '        for (int i = 0; i < 8; i++) {',
        '            s->Notify(i);',
        '        }',
        '    }',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'Notify\\s*\\(', capPattern: 'MAX_SUBS', criteria: ['amplification'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', claims: true }
  },
  {
    id: 'P7-SYN-AMP-FIX-03',
    class: 'P7',
    kind: 'fixture-claim',
    dosClass: 'amplification',
    label: 'amplification fixture 3：无界批量分配',
    source: {
      original: [
        'int Build(const std::vector<Item> &items)',
        '{',
        '    int total = 0;',
        '    for (const auto &it : items) {',
        '        total += Alloc(it.size);',
        '    }',
        '    return total;',
        '}'
      ].join('\n'),
      mutant: [
        'int Build(const std::vector<Item> &items)',
        '{',
        '    if (items.size() > MAX_BUILD_ITEMS) { return -1; }',
        '    int total = 0;',
        '    for (const auto &it : items) {',
        '        total += Alloc(it.size);',
        '    }',
        '    return total;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'Alloc\\s*\\(', capPattern: 'MAX_BUILD_ITEMS', criteria: ['amplification'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', claims: true }
  },
  {
    id: 'P7-SYN-AMP-FIX-04',
    class: 'P7',
    kind: 'fixture-claim',
    dosClass: 'amplification',
    label: 'amplification fixture 4：重复序列化放大',
    source: {
      original: [
        'std::string Dump(const Record &r)',
        '{',
        '    std::string out;',
        '    for (int i = 0; i < 64; i++) {',
        '        out += Serialize(r);',
        '    }',
        '    return out;',
        '}'
      ].join('\n'),
      mutant: [
        'std::string Dump(const Record &r)',
        '{',
        '    std::string out;',
        '    if (r.size > MAX_RECORD_SIZE) { return out; }',
        '    for (int i = 0; i < 64; i++) {',
        '        out += Serialize(r);',
        '    }',
        '    return out;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'Serialize\\s*\\(', capPattern: 'MAX_RECORD_SIZE', criteria: ['amplification'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', claims: true }
  },
  {
    id: 'P7-SYN-AMP-FIX-05',
    class: 'P7',
    kind: 'fixture-claim',
    dosClass: 'amplification',
    label: 'amplification fixture 5：全量扫描放大',
    source: {
      original: [
        'int Scan(const std::vector<Item> &items)',
        '{',
        '    int n = 0;',
        '    for (const auto &a : items) {',
        '        n += ScanOne(a);',
        '    }',
        '    return n;',
        '}'
      ].join('\n'),
      mutant: [
        'int Scan(const std::vector<Item> &items)',
        '{',
        '    if (items.size() > MAX_SCAN_ITEMS) { return -1; }',
        '    int n = 0;',
        '    for (const auto &a : items) {',
        '        n += ScanOne(a);',
        '    }',
        '    return n;',
        '}'
      ].join('\n')
    },
    analysis: { sinkPattern: 'ScanOne\\s*\\(', capPattern: 'MAX_SCAN_ITEMS', criteria: ['amplification'] },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', claims: true }
  }
];

/** external-cve 只作义务/裁决校准；analysisBySource 是 fixture 侧的匹配配置，不写进 case 本体。 */
const externalAnalysis = {
  'EXT-P7-001': {
    pre: { sinkPattern: 'buf2\\s*=\\s*smb_fdata', guardPattern: 'depth\\s*==\\s*10', criteria: ['amplification'] },
    post: { sinkPattern: 'buf2\\s*=\\s*smb_fdata', guardPattern: 'depth\\s*==\\s*10', criteria: ['amplification'] }
  },
  'EXT-P7-002': {
    pre: { sinkPattern: 'node_new_quantifier\\s*\\(', guardPattern: 'parse_depth\\s*>\\s*ParseDepthLimit', criteria: ['amplification'] },
    post: { sinkPattern: 'node_new_quantifier\\s*\\(', guardPattern: 'parse_depth\\s*>\\s*ParseDepthLimit', criteria: ['amplification'] }
  },
  'EXT-P7-003': {
    pre: { sinkPattern: 'cmap->data\\[i\\]', guardPattern: 'numcolors\\s*>\\s*RAS_CMAP_MAXSIZ', criteria: ['amplification'] },
    post: { sinkPattern: 'cmap->data\\[i\\]', guardPattern: 'numcolors\\s*>\\s*RAS_CMAP_MAXSIZ', criteria: ['amplification'] }
  },
  'EXT-P7-004': {
    pre: { sinkPattern: 'BUF_MEM_grow_clean\\s*\\(', guardPattern: 'l\\s*>\\s*SSL3_RT_MAX_PLAIN_LENGTH' },
    post: { sinkPattern: 'BUF_MEM_grow_clean\\s*\\(', guardPattern: 'l\\s*>\\s*SSL3_RT_MAX_PLAIN_LENGTH' }
  }
};

module.exports = { synthetic, externalAnalysis, all: synthetic };
