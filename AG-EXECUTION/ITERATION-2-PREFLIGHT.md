# 第二轮建议的前置核查（2026-10-22）

对象：REVIEW-ITERATION-2.md §7.0。本文只记录本轮实验决策，不覆盖 AGENT-ARCHITECTURE-GUIDE.md 的验收合同。所有动作保持 Windows 原生。

## 1. 范围

采纳“静态候选与 finding 分开”：当前试验不发布 finding，verify 保持 blocked、executedCommands=[]。拒绝删除正式 §23 的 finding/M6 条件：用户要求验证 M0-M6；把 M6 移出范围会改变目标，而不是证明它可行。没有获批隔离能力时，M6 继续记未通过。

## 2. 规范

采纳模型分离、来源锚定、运行时原文重检用于生成 proposed 规范。拒绝“AI 生成即可免独立审核而发布 accepted”：生成模型与运行模型不同并不能证明规范适用、例外完整或无自证环。现有 knowledge publish 必须由外部审核签名且仅支持 SetPolicy；第二条 UnSetPolicy 的文档原文存在与实现实参不一致，异步适用性未知。不能用该分歧反过来批准规范。AI 提案可另建开发样本，但不得进入正式知识版本。

## 3. 标签

采纳盲标、标签模型标识、生成参数和来源哈希作为**模型一致性诊断**；指标只能叫 agreementWithModelLabels，不叫准确率。拒绝把 10/10/5 模型标签冻结为 §21 的独立 20/20/10 holdout：目前两个纵向实质问题都恒为 insufficient；77 个去重问题中局部 check 仅 7 个 refuted，无法抽出独立的 10 反例，更不能靠重复 run 或同家族改写凑数。现有 labels.json 保持 pending；正式样本和规范仍需 Agent 外部审核。

## 4. 复算与出口消融

只读复算当前 out/autonomy 下 45 个 RUN：667 条 Assessment、77 个 questionId；末次裁决 37 supported、8 refuted、32 insufficient。它们不是 77 个独立漏洞案例。旧 authorization-v1 RUN:29898a9ac486f1f4 的 24 task 中，原报告 candidate=0。反事实仅用 entry-scan、binding supported、check-presence refuted 作出口得到 2 个候选；两者均为 SetPolicyAsync/UnSetPolicyAsync 已知委托包装，带 delegated-check-unproven、operation-unbound，且 operationRef 为空。加入真实 operationRef 条件后候选仍为 0。故“出口一改有候选”不证明瓶颈只在架构；放松出口会重引旧版已知不可行动候选。报告中应保留具体操作、委托反证和未知适用性，不用 candidate 数量当精度收益。

下一步采纳：按问题类型报告去重后的 decisive/insufficient 率，授权效果只测缺口质量；将非 stop 模型响应记不足并版本化；继续做有来源的操作绑定与独立评估。暂不采纳：降级正式规范与 holdout、删 M6、以直接调用词表否定生成正式候选、无测量收益前迁移框架或扩大同家族样本。
