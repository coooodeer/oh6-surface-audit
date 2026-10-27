'use strict';

/**
 * lib/autonomy/state.js —— 记录构造 + Task/Question/Missing 状态机与归约。
 *
 * 纪律：
 *   - 记录封套（§5.1）只有这里构造，字段顺序固定；
 *   - 状态迁移**白名单**校验，非法迁移抛错（不静默改写）；
 *   - missing 的 category 与 reasonCode 走同一注册表，避免"具名原因"漂移成自由文本。
 */

const ids = require('./ids');

const SCHEMA_VERSION = '1';
const ARCHITECTURE_VERSION = '1.0.0-mvp';

const PRODUCERS = Object.freeze({
  discovery: { kind: 'analyzer', name: 'discovery', version: '1' },
  index: { kind: 'analyzer', name: 'index', version: '1' },
  tools: { kind: 'analyzer', name: 'tools', version: '1' },
  assessment: { kind: 'analyzer', name: 'assessment', version: '1' },
  report: { kind: 'analyzer', name: 'report', version: '1' },
  doctor: { kind: 'analyzer', name: 'doctor', version: '1' },
  store: { kind: 'analyzer', name: 'store', version: '1' },
  model: { kind: 'model', name: 'autonomy-model-gateway', version: '1' },
  host: { kind: 'host', name: 'verify-placeholder', version: '1' }
});

const TASK_STATES = Object.freeze(['queued', 'running', 'done', 'blocked', 'failed']);
const TASK_TRANSITIONS = Object.freeze({
  queued: ['running', 'blocked', 'failed'],
  running: ['done', 'blocked', 'failed'],
  done: [],
  blocked: [],
  failed: []
});

const QUESTION_KINDS = Object.freeze(['binding', 'check-presence', 'dominance', 'authorization-effect', 'permission-argument-match', 'input-boundary-local', 'operation-local']);
const QUESTION_STATUSES = Object.freeze(['unknown', 'supported', 'refuted', 'insufficient', 'conflict']);
const QUESTION_BASIS = Object.freeze(['observed', 'derived', 'llm', 'mixed']);
const QUESTION_ASSURANCE = Object.freeze(['observation', 'bounded-analysis', 'model-assessment']);

const MISSING_CATEGORIES = Object.freeze([
  'data', 'tool', 'precision', 'environment', 'conflict', 'model-capability', 'budget', 'authorization'
]);

/** reasonCode → category + 固定的 whyNeeded。新增原因必须在这里登记。 */
const MISSING_REASONS = Object.freeze({
  'binding-unbound': { category: 'data', why: '入口找不到实现体，无法判定函数体内是否有校验调用' },
  'binding-ambiguous': { category: 'precision', why: '入口绑定到多个实现候选，MVP 不做 owner/签名收敛' },
  'binding-metadata-only': { category: 'data', why: '该入口只有元数据（如 saId），没有可观察的方法体' },
  'no-check-call': { category: 'data', why: '函数体内未出现词表内的校验调用（宏/包装/上游可能已做，MVP 不验证）' },
  'check-call-weak-only': { category: 'precision', why: '函数体只有身份获取（weak）调用，没有可判定的授权校验调用' },
  'delegated-check-unproven': { category: 'precision', why: '精确一跳被调函数有校验调用，但主体、对象、顺序和失败路径未证明' },
  'delegation-incomplete': { category: 'precision', why: '一跳取证存在未解析、过期或截断的调用/源码' },
  'operation-unbound': { category: 'data', why: '入口尚未绑定具体受保护操作，无法判断该操作上的授权约束' },
  'norm-applicability-unapproved': { category: 'authorization', why: '规范尚未审核发布，异步入口适用性未获独立确认' },
  'norm-not-applicable': { category: 'authorization', why: '已发布规范集未覆盖此入口，不能据其他方法的契约裁决' },
  'guard-shape-unsupported': { category: 'precision', why: '局部检查条件不属于已支持的直线早退形式，不能将复杂条件误判为缺早退' },
  'prover-model-conflict': { category: 'conflict', why: '局部静态证明与经证据门接受的模型反证相左，不能直接排除' },
  'static-contract-suspect': { category: 'precision', why: '唯一操作已定位，但权限检查缺口或经证据门接受的模型反证尚未形成静态证明' },
  'operation-semantics-unproven': { category: 'precision', why: '操作目标源码已取回，但子视图不能继承父视图的授权结论' },
  'operation-target-unproven': { category: 'precision', why: '敏感操作调用点仅名称匹配，缺精确目标与完整路径' },
  'permission-argument-unresolved': { category: 'precision', why: '权限调用或常量声明不满足唯一、精确、已校验的局部比较条件' },
  'input-parser-unproven': { category: 'precision', why: '解析实现只按参数类型推测，调用目标和恶意输入下的边界行为未证实' },
  'dominance-unproven': { category: 'precision', why: 'MVP 不实现支配关系与对象一致性分析' },
  'tool-unsupported': { category: 'tool', why: '该工具在本轮明确不实现（注册为 unsupported）' },
  'verification-disabled': { category: 'environment', why: 'MVP 不做设备/host 验证' },
  'budget-exhausted': { category: 'budget', why: '预算用尽，状态已落 checkpoint' },
  'model-key-missing': { category: 'model-capability', why: '缺少 OH6_LLM_API_KEY，live 明确失败（不降级为 mock）' },
  'model-output-invalid': { category: 'model-capability', why: '模型输出未通过程序证据门（引用不可回查/枚举非法/自称已证漏洞）' },
  'replay-miss': { category: 'tool', why: 'mock 模式没有对应 fixture' },
  'stale-input': { category: 'data', why: '源文件哈希与 facts 记录不一致，禁止据旧快照出结论' },
  'index-truncated': { category: 'data', why: '索引达到上限被截断，枚举不完整' },
  'entry-index-out-of-sync': { category: 'conflict', why: '入口索引与 facts 记录不一致' },
  // §24.28 阶段 B：双命题裁决与实际门禁目录的具名缺口。
  'combined-gate-unsupported': { category: 'precision', why: '门禁条件是组合逻辑（或/与，含跨行），未支持其整体语义，不能据此判定主体可达性' },
  'gate-present-but-not-blocking': { category: 'precision', why: '识别出门禁相关形状，但不能证明其拒绝分支阻断该操作' },
  'permission-constant-unresolved': { category: 'precision', why: '权限门禁的常量实参无法唯一解析为权限字面量' },
  'native-token-helper-unresolved': { category: 'precision', why: 'native-token 匹配辅助函数无法唯一解析' },
  'native-token-helper-shape-unsupported': { category: 'precision', why: 'native-token 匹配辅助函数体不符合受支持的比较形状' },
  'native-token-helper-truncated': { category: 'data', why: 'native-token 匹配辅助函数源码截断或过期' },
  'native-token-subject-mismatch': { category: 'precision', why: 'native-token 门禁检查的不是调用方主体' },
  'subject-gate-satisfaction-unprovable': { category: 'precision', why: '命题依赖主体能否取得满足身份门的凭据，静态快照无法判定' },
  'policy-anchor-doc-only': { category: 'authorization', why: '预期策略锚点仅为文档或 Builder 自审假设，安全命题上限为 candidate' },
  'acl-enabled-obtainability-deployment-dependent': { category: 'authorization', why: '权限 ACL 使能，可获得性依赖部署签名配置，静态快照无法判定主体能否持有' },
  'unrecognized-caller-guard': { category: 'precision', why: '存在以调用方身份为条件的未识别门禁形状，不能由词表未命中证明无门禁' },
  'policy-anchor-unavailable': { category: 'authorization', why: '缺少可用的预期策略锚点材料' },
  'model-supported-suspect': { category: 'conflict', why: '经证据门接受的模型反例支持可疑路径，但静态证明未闭合' },
  'contract-comparison-unresolved': { category: 'precision', why: '契约比较（文档权限 vs 实现）未取得可判定结果' },
  'security-path-unproven': { category: 'precision', why: '安全命题的入口到操作路径证据未闭合' },
  'entry-or-builder-norm-unresolved': { category: 'authorization', why: '入口绑定或已发布 Builder 规范未满足双命题前置条件' },
  'norm-applicability-unknown': { category: 'authorization', why: '规范对该入口的适用性未确立' },
  'call-chain-or-operation-ambiguous': { category: 'precision', why: '调用链或操作目标存在歧义，不能构造限定路径命题' },
  'gate-evaluation-unknown': { category: 'precision', why: '门禁已识别但主体满足性未知' },
  'permission-check-ambiguous': { category: 'precision', why: '权限检查调用不满足唯一、精确、已校验的比较条件' },
  'permission-helper-unresolved': { category: 'precision', why: '本地权限 helper 无法按调用事实唯一解析到实现体' },
  'permission-helper-not-caller-scoped': { category: 'precision', why: '本地 helper 不是调用方权限校验（形参/比较对象不匹配），不能当作门禁' },
  'permission-helper-shape-unsupported': { category: 'precision', why: '本地权限 helper 的函数体不符合受支持的校验形状' },
  'permission-helper-truncated': { category: 'data', why: '本地权限 helper 源码截断或与快照哈希不一致' },
  'permission-obtainable-by-subject': { category: 'authorization', why: '预期权限按锚点元数据可由该主体持有，不能支撑“本应拒绝”的安全 finding' },
  'permission-not-anchored': { category: 'authorization', why: '预期权限没有登记在策略锚点中，无法判定主体可获得性' },
  // §1.0.41 1.0.23 Rust enum-code 有界裁决的具名缺口。
  'rust-code-binding-unresolved': { category: 'precision', why: 'Rust ipc-code 入口与 handler 绑定未闭合' },
  'rust-dependency-stale': { category: 'data', why: '固定哈希依赖与当前源码不一致，禁止据旧依赖出结论' },
  'rust-sa-profile-stale': { category: 'data', why: 'SA profile 与 metadata 记录哈希不一致' },
  'rust-sa-profile-invalid': { category: 'data', why: 'SA profile JSON 不可解析' },
  'rust-sa-profile-unresolved': { category: 'precision', why: 'SA profile 的 process/saId/libpath/分布式标记不符合声明变体' },
  'rust-probe-stale': { category: 'data', why: 'rust-ast-probe 二进制缺失或哈希漂移' },
  'rust-probe-failed': { category: 'data', why: 'rust-ast-probe 对固定源文件解析失败' },
  'rust-dispatch-binding-unresolved': { category: 'precision', why: 'Rust 派发函数（match 所属函数）未绑定' },
  'rust-dispatch-drift': { category: 'precision', why: 'enum 定义或派发边与固定样本不一致' },
  'rust-execute-edge-unresolved': { category: 'precision', why: 'execute! 操作边或操作函数不唯一' },
  'rust-macro-shape-unknown': { category: 'precision', why: 'execute! 宏定义形状未按有限语法子集闭合' },
  'rust-operation-chain-unknown': { category: 'precision', why: 'check_arguments→check_system_permission 链形状未闭合' },
  'rust-gate-shape-unknown': { category: 'precision', why: 'check_system_permission 门禁形状未识别' },
  'rust-stub-gate-or-object-unknown': { category: 'precision', why: 'stub 的 descriptor/try_from/Query 派发或对象构造形状未闭合' },
  'rust-object-link-unknown': { category: 'precision', why: '请求 Tag::UserId 覆盖目标用户的对象链未闭合' },
  'rust-subject-origin-unknown': { category: 'precision', why: '主体来源（IPC caller uid/FFI 进程信息）形状未闭合' },
  'rust-ffi-identity-unknown': { category: 'precision', why: 'C++ FFI 身份检查形状或 extern "C" 绑定未闭合' },
  'rust-sa-registration-unknown': { category: 'precision', why: 'SA 注册/publish/GN 变体形状未闭合' },
  'rust-caller-identity-unknown': { category: 'precision', why: 'C++ IPC caller token 机制的固定证据未闭合' }
});

function fail(code, message, extra) {
  const e = new Error(message);
  e.code = code;
  if (extra) Object.assign(e, extra);
  return e;
}

function nowIso() {
  return new Date().toISOString();
}

/** §5.1 封套。recordId 由调用方给（恒等于 payload 内同名前缀字段）。 */
function makeRecord({ recordId, recordType, manifestId, producer, dependencyRefs, payload, createdAt }) {
  if (!recordId) throw fail('record-id-missing', 'state: recordId required');
  if (!recordType) throw fail('record-type-missing', 'state: recordType required');
  if (!manifestId) throw fail('manifest-id-missing', 'state: manifestId required');
  const p = producer && producer.kind ? producer : null;
  if (!p) throw fail('producer-missing', 'state: producer required');
  return {
    recordId,
    recordType,
    schemaVersion: SCHEMA_VERSION,
    manifestId,
    createdAt: createdAt || nowIso(),
    producer: { kind: p.kind, name: p.name, version: String(p.version) },
    dependencyRefs: ids.uniqueSorted(dependencyRefs || []),
    payload
  };
}

function transitionTask(from, to) {
  const allowed = TASK_TRANSITIONS[from];
  if (!allowed) throw fail('task-state-unknown', `state: unknown task state ${from}`);
  if (!allowed.includes(to)) throw fail('task-transition-invalid', `state: illegal task transition ${from} -> ${to}`);
  return to;
}

function assertQuestionStatus(status) {
  if (!QUESTION_STATUSES.includes(status)) throw fail('question-status-invalid', `state: bad question status ${status}`);
  return status;
}

function buildMissing({ questionId, reasonCode, targetRefs, blocking, nextActions, terminalReason }) {
  const spec = MISSING_REASONS[reasonCode];
  if (!spec) throw fail('missing-reason-unknown', `state: unregistered reasonCode ${reasonCode}`);
  const payload = {
    missingId: null,
    questionId,
    category: spec.category,
    reasonCode,
    targetRefs: ids.uniqueSorted(targetRefs || []),
    whyNeeded: spec.why,
    blocking: blocking !== false,
    nextActions: ids.uniqueSorted(nextActions || []),
    terminalReason: terminalReason || null
  };
  payload.missingId = ids.missingId('missing', {
    questionId: payload.questionId,
    reasonCode: payload.reasonCode,
    targetRefs: payload.targetRefs,
    category: payload.category
  });
  return payload;
}

const TASK_QUESTION_TEXT = Object.freeze({
  binding: '入口能否绑定到唯一实现？',
  'check-presence': '入口实现体内是否存在权限/身份校验调用？',
  dominance: '校验是否支配敏感操作、且对象一致？',
  'authorization-effect': '异步入口的调用主体是否在具体策略修改前得到有效授权？',
  'permission-argument-match': '一跳被调实现中的唯一 CheckPermission 权限实参是否与来源文档的权限一致？',
  'static-contract': '此入口的敏感操作是否满足已发布的文档权限契约？',
  'static-permission-match': '0/1 跳实现中的唯一 CheckPermission 权限实参与文档是否一致？',
  'contract-deviation': '此入口的文档权限契约声明与实现是否一致（仅契约差异，非安全结论）？',
  'security-decision': '所构造的具体主体能否经实际门禁到达该入口的限定敏感操作？',
  'input-boundary-local': '策略数据解析是否在修改前拒绝越界或异常输入？',
  'operation-local': '目标操作的局部源码能否独立支持父任务所需的授权语义？'
});

/** 由事件流归约出每个任务的状态（check 与 report 都基于记录，不依赖内存） */
function reduceTaskStates(events) {
  const states = new Map();
  for (const ev of events) {
    if (!ev || !ev.taskId) continue;
    const prev = states.get(ev.taskId) || { state: null, revision: 0, lastSeq: 0 };
    if (ev.kind === 'task-admitted') {
      states.set(ev.taskId, { state: ev.to || 'queued', revision: prev.revision + 1, lastSeq: ev.seq });
      continue;
    }
    if (ev.kind === 'task-started' || ev.kind === 'task-finished' || ev.kind === 'budget-stop') {
      states.set(ev.taskId, { state: ev.to || prev.state, revision: prev.revision + 1, lastSeq: ev.seq });
    }
  }
  return states;
}

module.exports = {
  SCHEMA_VERSION,
  ARCHITECTURE_VERSION,
  PRODUCERS,
  TASK_STATES,
  TASK_TRANSITIONS,
  QUESTION_KINDS,
  QUESTION_STATUSES,
  QUESTION_BASIS,
  QUESTION_ASSURANCE,
  MISSING_CATEGORIES,
  MISSING_REASONS,
  TASK_QUESTION_TEXT,
  makeRecord,
  transitionTask,
  assertQuestionStatus,
  buildMissing,
  reduceTaskStates,
  nowIso,
  fail
};
