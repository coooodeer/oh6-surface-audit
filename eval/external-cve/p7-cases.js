'use strict';

/**
 * External CVE P7 calibration cases（与 OH6.0 无关，仅测试义务编排/裁决）。
 *
 * 纪律：
 *   - 不映射当前扫描范围；
 *   - 不产生 codeState / inTarget；
 *   - production=false，永不计入 D4/R1；
 *   - source 是修复前后函数片段（inline snippet），不是完整可编译文件；
 *   - 只用于测试 P7 的 O1–O6/O9 编排与 T2/T4 判定。
 */

const cases = [
  {
    id: 'EXT-P7-001',
    cveId: 'CVE-2018-16452',
    class: 'P7',
    cwe: ['674'],
    language: 'c',
    sourceKind: 'inline-snippet',
    completeFunction: false,
    fixCommit: '24182d959f661327525a20d9a94c98a8ec016778',
    references: [
      'https://github.com/the-tcpdump-group/tcpdump/commit/24182d959f661327525a20d9a94c98a8ec016778',
      'https://nvd.nist.gov/vuln/detail/CVE-2018-16452'
    ],
    source: {
      pre: [
        'static const u_char *',
        'smb_fdata(netdissect_options *ndo, const u_char *buf, const char *fmt,',
        '          const u_char *maxbuf, int unicodestr)',
        '{',
        '    while (buf < maxbuf) {',
        '        const u_char *buf2;',
        '        depth++;',
        '        buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);',
        '        depth--;',
        '        if (buf2 == NULL)',
        '            return (NULL);',
        '    }',
        '}'
      ].join('\n'),
      post: [
        'static const u_char *',
        'smb_fdata(netdissect_options *ndo, const u_char *buf, const char *fmt,',
        '          const u_char *maxbuf, int unicodestr)',
        '{',
        '    while (buf < maxbuf) {',
        '        const u_char *buf2;',
        '        depth++;',
        '        /* avoid stack exhaustion: at most 10 nested levels */',
        '        if (depth == 10)',
        '            ND_PRINT((ndo, "(too many nested levels, not recursing)"));',
        '        else',
        '            buf2 = smb_fdata(ndo, buf, fmt, maxbuf, unicodestr);',
        '        depth--;',
        '        if (buf2 == NULL)',
        '            return (NULL);',
        '    }',
        '}'
      ].join('\n')
    },
    affected: { component: 'tcpdump', file: 'smbutil.c', function: 'smb_fdata' },
    expected: {
      obligations: ['O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O9'],
      preVerdict: 'VIOLATION',
      postVerdict: 'SATISFIED',
      product: 'PROVEN-WEAKNESS'
    },
    usage: 'obligation-calibration',
    production: false,
    notes: 'CWE-674；修复为递归深度上限；pre 无上限，post depth==10 停止递归。'
  },
  {
    id: 'EXT-P7-002',
    cveId: 'CVE-2019-16163',
    class: 'P7',
    cwe: ['674'],
    language: 'c',
    sourceKind: 'inline-snippet',
    completeFunction: false,
    fixCommit: '4097828d7cc87589864fecf452f2cd46c5f37180',
    references: [
      'https://github.com/kkos/oniguruma/commit/4097828d7cc87589864fecf452f2cd46c5f37180',
      'https://nvd.nist.gov/vuln/detail/CVE-2019-16163'
    ],
    source: {
      pre: [
        'static int',
        'parse_exp(Node** np, PToken* tok, int term, UChar** src, UChar* end,',
        '          ScanEnv* env, int group_head)',
        '{',
        '    int r, len, group = 0;',
        '    Node* qn;',
        '    Node** tp;',
        '',
        '    *np = NULL;',
        '    if (tok->type == (enum TokenSyms)term)',
        '        goto end_of_token;',
        '',
        '    switch (tok->type) {',
        '    /* ... */',
        '    }',
        '    if (is_invalid_quantifier_target(*tp))',
        '        return ONIGERR_TARGET_OF_REPEAT_OPERATOR_INVALID;',
        '    qn = node_new_quantifier(tok->u.repeat.lower, tok->u.repeat.upper,',
        '                             r == TK_INTERVAL);',
        '    CHECK_NULL_RETURN_MEMERR(qn);',
        '}'
      ].join('\n'),
      post: [
        'static int',
        'parse_exp(Node** np, PToken* tok, int term, UChar** src, UChar* end,',
        '          ScanEnv* env, int group_head)',
        '{',
        '    int r, len, group;',
        '    Node* qn;',
        '    Node** tp;',
        '    unsigned int parse_depth;',
        '',
        '    group = 0;',
        '    *np = NULL;',
        '    if (tok->type == (enum TokenSyms)term)',
        '        goto end_of_token;',
        '',
        '    parse_depth = env->parse_depth;',
        '    switch (tok->type) {',
        '    /* ... */',
        '    }',
        '    if (is_invalid_quantifier_target(*tp))',
        '        return ONIGERR_TARGET_OF_REPEAT_OPERATOR_INVALID;',
        '    parse_depth++;',
        '    if (parse_depth > ParseDepthLimit)',
        '        return ONIGERR_PARSE_DEPTH_LIMIT_OVER;',
        '    qn = node_new_quantifier(tok->u.repeat.lower, tok->u.repeat.upper,',
        '                             r == TK_INTERVAL);',
        '    CHECK_NULL_RETURN_MEMERR(qn);',
        '}'
      ].join('\n')
    },
    affected: { component: 'oniguruma', file: 'src/regparse.c', function: 'parse_exp' },
    expected: {
      obligations: ['O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O9'],
      preVerdict: 'VIOLATION',
      postVerdict: 'SATISFIED',
      product: 'PROVEN-WEAKNESS'
    },
    usage: 'obligation-calibration',
    production: false,
    notes: 'CWE-674；修复为 ParseDepthLimit；pre 无深度上限，post 超限返回错误。'
  },
  {
    id: 'EXT-P7-003',
    cveId: 'CVE-2016-9388',
    class: 'P7',
    cwe: ['617'],
    language: 'c',
    sourceKind: 'inline-snippet',
    completeFunction: false,
    fixCommit: '411a4068f8c464e883358bf403a3e25158863823',
    references: [
      'https://github.com/jasper-software/jasper/commit/411a4068f8c464e883358bf403a3e25158863823',
      'https://nvd.nist.gov/vuln/detail/CVE-2016-9388'
    ],
    source: {
      pre: [
        'static int',
        'ras_getcmap(jas_stream_t *in, ras_hdr_t *hdr, ras_cmap_t *cmap)',
        '{',
        '    int i, j;',
        '    int numcolors;',
        '    int actualnumcolors;',
        '',
        '    switch (hdr->maptype) {',
        '    case RAS_MT_EQUALRGB:',
        '        /* ... */',
        '        break;',
        '    case RAS_MT_RAW:',
        '        numcolors = 1 << hdr->depth;',
        '        assert(numcolors <= RAS_CMAP_MAXSIZ);',
        '        actualnumcolors = hdr->maplength / 3;',
        '        for (i = 0; i < numcolors; i++) {',
        '            cmap->data[i] = 0;',
        '        }',
        '        break;',
        '    }',
        '}'
      ].join('\n'),
      post: [
        'static int',
        'ras_getcmap(jas_stream_t *in, ras_hdr_t *hdr, ras_cmap_t *cmap)',
        '{',
        '    int i, j;',
        '    int numcolors;',
        '    int actualnumcolors;',
        '',
        '    switch (hdr->maptype) {',
        '    case RAS_MT_EQUALRGB:',
        '        /* ... */',
        '        break;',
        '    case RAS_MT_RAW:',
        '        numcolors = 1 << hdr->depth;',
        '        if (numcolors > RAS_CMAP_MAXSIZ) {',
        '            return -1;',
        '        }',
        '        actualnumcolors = hdr->maplength / 3;',
        '        for (i = 0; i < numcolors; i++) {',
        '            cmap->data[i] = 0;',
        '        }',
        '        break;',
        '    }',
        '}'
      ].join('\n')
    },
    affected: { component: 'jasper', file: 'src/libjasper/ras/ras_dec.c', function: 'ras_getcmap' },
    expected: {
      obligations: ['O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O9'],
      preVerdict: 'VIOLATION',
      postVerdict: 'SATISFIED',
      product: 'PROVEN-WEAKNESS'
    },
    usage: 'obligation-calibration',
    production: false,
    notes: 'CWE-617；pre 用 assert 处理不可信 maplength/depth，post 返回 -1 优雅拒绝。'
  },
  {
    id: 'EXT-P7-004',
    cveId: 'CVE-2016-6307',
    class: 'P7',
    cwe: ['400'],
    language: 'c',
    sourceKind: 'inline-snippet',
    completeFunction: false,
    fixCommit: '4b390b6c3f8df925dc92a3dd6b022baa9a2f4650',
    references: [
      'https://github.com/openssl/openssl/commit/4b390b6c3f8df925dc92a3dd6b022baa9a2f4650',
      'https://nvd.nist.gov/vuln/detail/CVE-2016-6307'
    ],
    source: {
      pre: [
        'int tls_get_message_header(SSL *s, int *mt)',
        '{',
        '    long l;',
        '    /* ... read TLS message header ... */',
        '    l = RECORD_LAYER_get_rrec_length(&s->rlayer)',
        '        + SSL3_HM_HEADER_LENGTH;',
        '    if (l && !BUF_MEM_grow_clean(s->init_buf, (int)l)) {',
        '        SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, ERR_R_BUF_LIB);',
        '        goto err;',
        '    }',
        '    s->s3->tmp.message_size = l;',
        '    if (l > SSL3_RT_MAX_PLAIN_LENGTH + SSL3_HM_HEADER_LENGTH) {',
        '        SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, SSL_R_EXCESSIVE_MESSAGE_SIZE);',
        '        goto f_err;',
        '    }',
        '    /* ... */',
        '    return 1;',
        'f_err:',
        '    ssl3_send_alert(s, SSL3_AL_FATAL, al);',
        'err:',
        '    return 0;',
        '}'
      ].join('\n'),
      post: [
        'int tls_get_message_header(SSL *s, int *mt)',
        '{',
        '    long l;',
        '    /* ... read TLS message header ... */',
        '    l = RECORD_LAYER_get_rrec_length(&s->rlayer)',
        '        + SSL3_HM_HEADER_LENGTH;',
        '    s->s3->tmp.message_size = l;',
        '    if (l > SSL3_RT_MAX_PLAIN_LENGTH + SSL3_HM_HEADER_LENGTH) {',
        '        SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, SSL_R_EXCESSIVE_MESSAGE_SIZE);',
        '        goto f_err;',
        '    }',
        '    if (l && !BUF_MEM_grow_clean(s->init_buf, (int)l)) {',
        '        SSLerr(SSL_F_TLS_GET_MESSAGE_HEADER, ERR_R_BUF_LIB);',
        '        goto err;',
        '    }',
        '    /* ... */',
        '    return 1;',
        'f_err:',
        '    ssl3_send_alert(s, SSL3_AL_FATAL, al);',
        'err:',
        '    return 0;',
        '}'
      ].join('\n')
    },
    affected: { component: 'openssl', file: 'ssl/statem/statem_lib.c', function: 'tls_get_message_header' },
    expected: {
      obligations: ['O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O9'],
      preVerdict: 'VIOLATION',
      postVerdict: 'SATISFIED',
      product: 'PROVEN-WEAKNESS'
    },
    usage: 'obligation-calibration',
    production: false,
    notes: 'CWE-400；pre 先 grow 后检查 excessive length，post 先检查再 grow；用于测试“检查顺序/分配前置”义务。'
  }
];

const REQUIRED = ['id', 'cveId', 'class', 'cwe', 'language', 'sourceKind', 'completeFunction', 'fixCommit', 'references', 'source', 'affected', 'expected', 'usage', 'production'];
const ALLOWED_CWE = new Set(['400', '617', '674']);
const ALLOWED_USAGE = new Set(['obligation-calibration', 'verdict-calibration', 'negative-control']);

function validateCase(c) {
  const errors = [];
  for (const k of REQUIRED) if (!(k in c)) errors.push(`missing:${k}`);
  if (c.class !== 'P7') errors.push('class-must-be-P7');
  if (!Array.isArray(c.cwe) || !c.cwe.length || c.cwe.some((x) => !ALLOWED_CWE.has(String(x)))) errors.push('cwe-must-be-400/617/674');
  if (c.production !== false) errors.push('production-must-be-false');
  if ('inTarget' in c || 'codeState' in c) errors.push('external-must-not-have-inTarget-or-codeState');
  if (!c.source || typeof c.source.pre !== 'string' || typeof c.source.post !== 'string') errors.push('source-pre-post-required');
  if (c.source && c.source.pre === c.source.post) errors.push('pre-post-identical');
  if (!c.affected || !c.affected.component || !c.affected.file || !c.affected.function) errors.push('affected-fields-required');
  if (!c.expected || !Array.isArray(c.expected.obligations) || c.expected.obligations.length < 4) errors.push('expected-obligations-required');
  if (c.expected && c.expected.preVerdict !== 'VIOLATION') errors.push('preVerdict-must-be-VIOLATION');
  if (c.expected && c.expected.postVerdict !== 'SATISFIED') errors.push('postVerdict-must-be-SATISFIED');
  if (c.expected && c.expected.product !== 'PROVEN-WEAKNESS') errors.push('product-must-be-PROVEN-WEAKNESS');
  if (!ALLOWED_USAGE.has(c.usage)) errors.push('bad-usage');
  if (!c.fixCommit || !/^[0-9a-f]{40}$/.test(c.fixCommit)) errors.push('fixCommit-must-be-40hex');
  if (!Array.isArray(c.references) || !c.references.length) errors.push('references-required');
  return errors;
}

function validateAll() {
  const rows = cases.map((c) => ({ id: c.id, errors: validateCase(c) }));
  const bad = rows.filter((r) => r.errors.length);
  return { ok: bad.length === 0, bad, count: cases.length };
}

module.exports = { cases, validateCase, validateAll };
