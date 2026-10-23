'use strict';

/**
 * P2 fixtures（释放后使用 / 生命周期）。
 *
 * synthetic：5 正 + 5 负；历史本地 lifetime-guard-added 做 pre/post/mutant 守卫差分；
 * 历史正例 CWE-416 做 pre/post 对照。全部只作 fixture/校准。
 */

const synthetic = [
  {
    id: 'P2-SYN-POS-01',
    class: 'P2',
    kind: 'synthetic-positive',
    label: '裸指针值捕获 + 外层 free，无 join/所有权',
    source: {
      original: [
        'void StartWork(Conn *conn)',
        '{',
        '    std::thread([conn]() {',
        '        conn->Run();',
        '    }).detach();',
        '    conn->Close();',
        '    free(conn);',
        '}'
      ].join('\n'),
      mutant: [
        'void StartWork(std::shared_ptr<Conn> conn)',
        '{',
        '    std::thread([conn]() {',
        '        conn->Run();',
        '    }).detach();',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread\\s*\\(', freePattern: 'free\\s*\\(conn\\)' },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'free-without-anchor' }
  },
  {
    id: 'P2-SYN-POS-02',
    class: 'P2',
    kind: 'synthetic-positive',
    label: 'this 捕获 + detached + delete this',
    source: {
      original: [
        'void Task::Post()',
        '{',
        '    std::thread([this]() {',
        '        this->Run();',
        '    }).detach();',
        '    this->Stop();',
        '    delete this;',
        '}'
      ].join('\n'),
      mutant: [
        'void Task::Post()',
        '{',
        '    auto self = shared_from_this();',
        '    std::thread([self]() {',
        '        self->Run();',
        '    }).detach();',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread\\s*\\(', freePattern: 'delete\\s+this' },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'free-without-anchor' }
  },
  {
    id: 'P2-SYN-POS-03',
    class: 'P2',
    kind: 'synthetic-positive',
    label: '栈引用捕获 + detached',
    source: {
      original: [
        'void PostCtx()',
        '{',
        '    Context ctx;',
        '    std::thread([&ctx]() {',
        '        ctx.Run();',
        '    }).detach();',
        '    ctx.Stop();',
        '}'
      ].join('\n'),
      mutant: [
        'void PostCtx()',
        '{',
        '    Context ctx;',
        '    std::thread([ctx]() mutable {',
        '        ctx.Run();',
        '    }).join();',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread\\s*\\(', captureKind: 'reference' },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'dangling-reference' }
  },
  {
    id: 'P2-SYN-POS-04',
    class: 'P2',
    kind: 'synthetic-positive',
    label: 'PostTask 捕获裸对象，随后 delete',
    source: {
      original: [
        'void Dispatch(Handler *handler)',
        '{',
        '    handler->PostTask([handler]() {',
        '        handler->OnEvent();',
        '    });',
        '    handler->Unregister();',
        '    delete handler;',
        '}'
      ].join('\n'),
      mutant: [
        'void Dispatch(Handler *handler)',
        '{',
        '    handler->PostTask([handler]() {',
        '        handler->OnEvent();',
        '    });',
        '    handler->Wait();',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'PostTask\\s*\\(', freePattern: 'delete\\s+handler' },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'free-without-anchor' }
  },
  {
    id: 'P2-SYN-POS-05',
    class: 'P2',
    kind: 'synthetic-positive',
    label: '回调引用捕获 + 帧退出',
    source: {
      original: [
        'void Register()',
        '{',
        '    Callback cb;',
        '    std::thread([&cb]() {',
        '        cb.Invoke();',
        '    }).detach();',
        '}'
      ].join('\n'),
      mutant: [
        'void Register()',
        '{',
        '    auto cb = std::make_shared<Callback>();',
        '    std::thread([cb]() {',
        '        cb->Invoke();',
        '    }).join();',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread\\s*\\(', captureKind: 'reference' },
    expected: { original: 'VIOLATION', mutant: 'SATISFIED', originalReason: 'dangling-reference' }
  },
  {
    id: 'P2-SYN-NEG-01',
    class: 'P2',
    kind: 'synthetic-negative',
    label: 'shared_ptr 值捕获（refcount 持有）',
    source: {
      original: [
        'void StartWork(std::shared_ptr<Conn> conn)',
        '{',
        '    std::thread([conn]() {',
        '        conn->Run();',
        '    }).detach();',
        '}'
      ].join('\n'),
      mutant: [
        'void StartWork(Conn *conn)',
        '{',
        '    std::thread([conn]() {',
        '        conn->Run();',
        '    }).detach();',
        '    free(conn);',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread\\s*\\(', freePattern: 'free\\s*\\(conn\\)' },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'refcount-hold' }
  },
  {
    id: 'P2-SYN-NEG-02',
    class: 'P2',
    kind: 'synthetic-negative',
    label: 'join 同步等待',
    source: {
      original: [
        'void StartWork(Conn *conn)',
        '{',
        '    std::thread t([conn]() {',
        '        conn->Run();',
        '    });',
        '    t.join();',
        '    free(conn);',
        '}'
      ].join('\n'),
      mutant: [
        'void StartWork(Conn *conn)',
        '{',
        '    std::thread([conn]() {',
        '        conn->Run();',
        '    }).detach();',
        '    free(conn);',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread', freePattern: 'free\\s*\\(conn\\)' },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'synchronized-wait' }
  },
  {
    id: 'P2-SYN-NEG-03',
    class: 'P2',
    kind: 'synthetic-negative',
    label: '纯值捕获（无生命周期面）',
    source: {
      original: [
        'void Notify(int userId)',
        '{',
        '    std::thread([userId]() {',
        '        Report(userId);',
        '    }).detach();',
        '}'
      ].join('\n'),
      mutant: [
        'void Notify(int *userId)',
        '{',
        '    std::thread([userId]() {',
        '        Report(*userId);',
        '    }).detach();',
        '    free(userId);',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread\\s*\\(', freePattern: 'free\\s*\\(userId\\)' },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'value-capture' }
  },
  {
    id: 'P2-SYN-NEG-04',
    class: 'P2',
    kind: 'synthetic-negative',
    label: 'unique_ptr move 捕获（所有权转移）',
    source: {
      original: [
        'void Start(std::unique_ptr<Conn> conn)',
        '{',
        '    auto raw = conn.get();',
        '    std::thread([owner = std::move(conn), raw]() {',
        '        raw->Run();',
        '    }).detach();',
        '}'
      ].join('\n'),
      mutant: [
        'void Start(Conn *conn)',
        '{',
        '    std::thread([conn]() {',
        '        conn->Run();',
        '    }).detach();',
        '    delete conn;',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread\\s*\\(', freePattern: 'delete\\s+conn' },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'ownership-transfer' }
  },
  {
    id: 'P2-SYN-NEG-05',
    class: 'P2',
    kind: 'synthetic-negative',
    label: '锁 + blocking wait 覆盖',
    source: {
      original: [
        'void Start(Conn *conn)',
        '{',
        '    std::lock_guard<std::mutex> lock(mutex_);',
        '    std::thread t([conn]() {',
        '        conn->Run();',
        '    });',
        '    t.join();',
        '    free(conn);',
        '}'
      ].join('\n'),
      mutant: [
        'void Start(Conn *conn)',
        '{',
        '    std::thread([conn]() {',
        '        conn->Run();',
        '    }).detach();',
        '    free(conn);',
        '}'
      ].join('\n')
    },
    analysis: { mode: 'async-lifetime', capturePattern: 'std::thread', freePattern: 'free\\s*\\(conn\\)' },
    expected: { original: 'SATISFIED', mutant: 'VIOLATION', negativeCoverage: 'lock-and-wait' }
  }
];

const historyLocal = [
  { id: 'P2-HIST-20541b41', historyId: 'INV-HIST-20541b41', label: 'event_queue.cpp：Remove 加锁' },
  { id: 'P2-HIST-298acf58', historyId: 'INV-HIST-298acf58', label: 'ipc_object_proxy.cpp：生命周期守卫' },
  { id: 'P2-HIST-2c307697', historyId: 'INV-HIST-2c307697', label: 'os_account_database_operator.cpp：init 加锁' },
  { id: 'P2-HIST-0585d9a3', historyId: 'INV-HIST-0585d9a3', label: 'sandbox_manager：rdb 加锁' },
  { id: 'P2-HIST-15afed5d', historyId: 'INV-HIST-15afed5d', label: 'eventhandler：生命周期守卫' },
  { id: 'P2-HIST-01d5caba', historyId: 'INV-HIST-01d5caba', label: 'samgr：RemoveDiedSystemAbility 加锁' },
  { id: 'P2-HIST-eec910d5', historyId: 'INV-HIST-eec910d5', label: 'safwk：生命周期守卫' },
  { id: 'P2-HIST-9a8cac28', historyId: 'INV-HIST-9a8cac28', label: 'common_event_service：生命周期守卫' }
].map((c) => ({
  ...c,
  class: 'P2',
  kind: 'history-local',
  family: 'lifetime-guard-added',
  analysis: { mode: 'guard-differential', useWitnessAsGuard: true },
  expected: { pre: 'VIOLATION', post: 'SATISFIED', mutant: 'VIOLATION' }
}));

const historyPositive = [
  {
    id: 'P2-HPOS-CWE416',
    class: 'P2',
    kind: 'history-positive',
    cwe: 'CWE-416',
    positiveId: 'HIST-a919237e8187f391',
    label: 'kernel liteos_a mqueue：OsMqGetAttr/OsMqSetAttr 生命周期',
    analysis: {
      mode: 'guard-differential',
      guardPattern: 'pthread_mutex_lock\\s*\\(\\s*&IPC_QUEUE_MUTEX',
      sinkPattern: 'MqGetPrivDataBuff\\s*\\('
    },
    expected: { pre: 'VIOLATION', post: 'SATISFIED' }
  }
];

module.exports = { synthetic, historyLocal, historyPositive, all: [...synthetic, ...historyLocal, ...historyPositive] };
