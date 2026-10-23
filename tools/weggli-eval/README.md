# Weggli 可行性验证（预研，非生产组件）

结论见 [../AG-EXECUTION/AG0-PREFLIGHT.md](../../AG-EXECUTION/AG0-PREFLIGHT.md) 的「Weggli 评估」一节。本目录只保留可复算的两个对比脚本，**不包含 weggli 源码与构建产物**。

## 重新构建（WSL，15 s 级）

```bash
# Windows 的 MSVC 工具链缺 cl.exe，无法直接 cargo build；WSL 里可以
wsl -d Ubuntu-22.04 -- bash -lc "cd /mnt/d/oh6.0/OpenHarmony-v6.0-Release/oh6-surface-audit/tools/weggli-eval \
  && git clone --depth 1 https://github.com/weggli-rs/weggli.git \
  && cd weggli && cargo build --release"
```

产物：`weggli/target/release/weggli`（v0.2.5，2023-11-23 最后提交；官方无预编译二进制）。

## 复算

```powershell
# 函数枚举召回：weggli `_ $fn(_) {_;}` vs tree-sitter function_definition
node tools\weggli-eval\compare-fn.js

# sink 查询召回：weggli `malloc(_)` vs tree-sitter call_expression
node tools\weggli-eval\compare-sinks.js
```

两个脚本都按“先构建、后对比”工作；脚本内部通过 `.sh` 文件调用 WSL（`wsl -- bash -c` 会吃掉 `$`）。

## 调用注意（实测踩坑）

- weggli 只接受**一个** `PATH`，多 root 必须循环调用。
- 位置参数必须放在 `-e/--extensions` 之前，否则 clap 2 会把 pattern/path 当成扩展名吃掉。
- C 与 C++ 是两种模式（默认 C，`-X` 开 C++），扩展名集合不同，需要跑两遍。
- 输出是给人看的源码片段（无 JSON），且会合并重叠匹配，**不能直接当事实流计数**。
- 文件解析失败时静默返回 0 个结果、退出码 0——没有 per-file 诊断。
