'use strict';

/** OpenAI-compatible transport for the autonomous audit model gateway. */

const ENDPOINT_PATH = '/chat/completions';

/** 把密钥与鉴权头从任意字符串里抹掉（错误信息可能带 request dump） */
function redact(text, secret) {
  let s = String(text === undefined || text === null ? '' : text);
  if (secret && secret.length >= 8) {
    s = s.split(secret).join('[REDACTED-KEY]');
  }
  s = s.replace(/Bearer\s+[A-Za-z0-9._\-]{8,}/gi, 'Bearer [REDACTED]');
  s = s.replace(/("?(?:api[-_]?key|authorization)"?\s*[:=]\s*")[^"]{8,}(")/gi, '$1[REDACTED]$2');
  return s;
}

/** HTTP 状态码 → 具名 kind（未列出的按可重试的 transport-error 处理） */
function classifyStatus(status) {
  if (status === 401 || status === 403) return { kind: 'auth-failed', detail: `http-${status}` };
  if (status === 429) return { kind: 'rate-limited', detail: 'http-429' };
  if (status === 400 || status === 404 || status === 422) return { kind: 'param-rejected', detail: `http-${status}` };
  if (status >= 500 || status === 408) return { kind: 'transport-error', detail: `http-${status}` };
  return { kind: 'transport-error', detail: `http-${status}` };
}

/** usage 归一（保留命中/未命中两档） */
function parseUsage(u) {
  const x = u || {};
  const prompt = Number(x.prompt_tokens || 0);
  const completion = Number(x.completion_tokens || 0);
  const details = x.prompt_tokens_details || {};
  const hitRaw = x.prompt_cache_hit_tokens !== undefined ? x.prompt_cache_hit_tokens : details.cached_tokens;
  const missRaw = x.prompt_cache_miss_tokens;
  const hit = Number(hitRaw || 0);
  const miss = missRaw !== undefined ? Number(missRaw) : Math.max(0, prompt - hit);
  return { promptTokens: prompt, completionTokens: completion, cacheHitTokens: hit, cacheMissTokens: miss };
}

const RESPONSE_FORMAT = {
  type: 'json_schema',
  json_schema: { name: 'agent_output', schema: { type: 'object', additionalProperties: true } }
};

/** 请求体（**不含密钥**：密钥只在 HTTP 头里） */
function buildRequestBody({ model, messages, maxTokensPerRequest, requestExtra, stream, responseFormat = RESPONSE_FORMAT }) {
  const body = {
    model,
    messages,
    max_tokens: maxTokensPerRequest,
    stream: stream === true
  };
  if (responseFormat !== null) body.response_format = responseFormat;
  for (const [k, v] of Object.entries(requestExtra || {})) {
    if (v === undefined || v === null) continue;
    if (['model', 'messages', 'max_tokens', 'max_completion_tokens', 'stream', 'n'].includes(k)) throw new Error('requestExtra cannot override reserved request parameter: ' + k);
    body[k] = v;
  }
  return body;
}

/** Build a transport from the selected autonomy model profile. */
function makeHttpTransport(o = {}) {
  const apiKeyEnv = o.apiKeyEnv || 'OH6_LLM_API_KEY';
  const baseUrl = String(o.baseUrl || '').replace(/\/+$/, '');
  const endpoint = baseUrl + ENDPOINT_PATH;
  const timeoutMs = Number(o.timeoutMs || 120000);
  const maxTokensPerRequest = Number(o.maxTokensPerRequest || 8192);
  const requestExtra = o.requestExtra || {};
  const responseFormat = o.responseFormat === undefined ? RESPONSE_FORMAT : o.responseFormat;
  const userIdScope = o.userIdScope || null;
  const extraHeaders = o.extraHeaders || {};
  const fetchImpl = o.fetchImpl || (typeof fetch === 'function' ? fetch : null);
  const clock = o.clock || (() => Date.now());

  /** 构造**实际会发出**的请求体（不含密钥）；`send` 与缓存键共用同一条路径，保证键与请求一致 */
  function buildBody(messages, maxTokensOverride) {
    const maxTokensPerRequestEffective =
      maxTokensOverride === undefined || maxTokensOverride === null || !(Number(maxTokensOverride) > 0)
        ? maxTokensPerRequest
        : Math.floor(Number(maxTokensOverride));
    const body = buildRequestBody({ model: o.model, messages, maxTokensPerRequest: maxTokensPerRequestEffective, requestExtra, responseFormat });
    if (userIdScope) body.user_id = userIdScope;
    return body;
  }

  function keyPresent() {
    return !!process.env[apiKeyEnv];
  }

  return {
    id: 'http',
    simulated: false,
    implemented: true,
    requires: apiKeyEnv,
    endpoint,
    model: o.model || null,
    /** 请求级 token 上限（配置值）；预算预留的 `min()` 之一，故必须对外可见 */
    maxTokensPerRequest,
    keyPresent,
    redact: (s) => redact(s, process.env[apiKeyEnv]),
    /**
     * 请求描述：仅含**影响输出的请求参数**（model/max_tokens/response_format/附加参数/user_id）。
     * 缓存键必须覆盖它，否则"同一提示词、不同 max_tokens"会被当成同一次请求复用（实测踩到：
     * smoke 用 1024 上限产出的截断响应会被真实运行当命中）。
     */
    requestDescriptor({ messages, maxTokens }) {
      return buildBody(messages, maxTokens);
    },

    async send({ unitId, attempt, messages, maxTokens }) {
      const t0 = clock();
      if (!fetchImpl) return { kind: 'transport-unavailable', reason: 'no-fetch-impl', detail: '本 Node 无全局 fetch' };
      if (!baseUrl || !o.model) return { kind: 'transport-unavailable', reason: 'endpoint-not-configured', detail: 'autonomy model config missing baseUrl/model' };
      const key = process.env[apiKeyEnv];
      if (!key) return { kind: 'transport-unavailable', reason: 'api-key-missing', detail: apiKeyEnv };

      const body = buildBody(messages, maxTokens);
      const payload = JSON.stringify(body);

      let res;
      const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const abortTimer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
      try {
        // **硬超时（实测踩到）**：只靠 `AbortSignal.timeout` 不够——批次②有一次请求 42 分钟不返回、
        // 不抛错也不 abort，整批卡死（CPU 仅 19 s）。因此除了 abort，再用 Promise.race 保证**一定结算**。
        res = await Promise.race([
          fetchImpl(endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${key}`, ...extraHeaders },
            body: payload,
            signal: ctrl ? ctrl.signal : undefined
          }),
          new Promise((_, reject) => {
            const t = setTimeout(() => reject(Object.assign(new Error('hard-timeout'), { name: 'TimeoutError' })), timeoutMs + 500);
            if (t.unref) t.unref();
          })
        ]);
      } catch (e) {
        const wallMs = Math.max(0, clock() - t0);
        const aborted = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
        return {
          kind: 'transport-error',
          reason: aborted ? 'timeout' : 'network-error',
          detail: redact(`${(e && e.name) || 'Error'}: ${(e && e.message) || e}`, key),
          wallMs,
          unitId,
          attempt
        };
      } finally {
        if (abortTimer) clearTimeout(abortTimer);
      }

      if (!res.ok) {
        let text = '';
        try {
          text = await res.text();
        } catch (_) {
          text = '';
        }
        const wallMsErr = Math.max(0, clock() - t0);
        const cls = classifyStatus(res.status);
        return {
          kind: cls.kind,
          reason: cls.detail,
          detail: redact(String(text).slice(0, 500), key),
          status: res.status,
          wallMs: wallMsErr,
          unitId,
          attempt
        };
      }

      let json;
      try {
        json = await res.json();
      } catch (e) {
        // 解析失败同样在 body 读完（或尝试读完）之后 ⇒ 计时放在这里
        const wallMsBodyErr = Math.max(0, clock() - t0);
        return { kind: 'schema-invalid', reason: 'response-not-json', detail: redact(String((e && e.message) || e), key), wallMs: wallMsBodyErr, unitId, attempt };
      }
      const wallMs = Math.max(0, clock() - t0);
      const choice = (json.choices || [])[0] || {};
      const msg = choice.message || {};
      const content = msg.content === undefined || msg.content === null ? '' : String(msg.content);
      return {
        kind: 'ok',
        content,
        usage: parseUsage(json.usage),
        usageKnown: !!(json.usage && Number.isFinite(json.usage.prompt_tokens) && Number.isFinite(json.usage.completion_tokens)),
        finishReason: choice.finish_reason || null,
        model: json.model || o.model,
        reasoningChars: msg.reasoning_content ? String(msg.reasoning_content).length : 0,
        // 本次**实际发送**的请求级上限（预算预留会把它压低）：记账/复算需要它，否则
        // "为什么这次输出被截断"在产物里查不出来。
        maxTokensSent: body.max_tokens,
        wallMs,
        unitId,
        attempt
      };
    }
  };
}

module.exports = { makeHttpTransport, buildRequestBody, parseUsage, classifyStatus, redact, ENDPOINT_PATH };
