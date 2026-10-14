# Delta for community-support

## ADDED Requirements

### Requirement: 社区支持力度评价模型

系统 SHALL 在活跃度指标之上，输出可解释的「社区支持力度」评价，用于评估组件可持续维护能力与引入后的自维护成本。

- 评价 MUST 输出 0-100 分、A/B/C/D 等级、等级说明与逐项扣分/加分依据。
- 等级划分 MUST 为：≥80 为 A（强）、≥60 为 B（较强）、≥40 为 C（一般）、其余为 D（弱）。
- 评价因子 MUST 至少覆盖：最近提交时间、近 12 个月发布次数、维护者数量（bus factor）、贡献者数量、issue 响应时长、PR 合并周期、安全响应策略、持续集成、基金会/厂商背书、下游依赖项目数、下载量与星标。
- 缺失信号 MUST 按「未知即风险」扣分，并列入 `missing` 清单。
- 项目已 archived 或标记 deprecated 时，分数 MUST 直接压至最低档。

#### Scenario: 健康项目评为 A 级

- GIVEN 组件近 12 个月多次发布、维护者充足、issue 响应快且有基金会背书
- WHEN 执行社区支持力度评价
- THEN 等级为 A
- AND 输出各项因子的得分依据

#### Scenario: 信号全部缺失时保守评价

- GIVEN 事实层无任何社区信号
- WHEN 执行评价
- THEN 每项缺失均计入扣分并列入 missing 清单
- AND 等级不高于 C

#### Scenario: 项目已归档

- GIVEN 组件仓库已 archived
- WHEN 执行评价
- THEN 分数被压至最低档且等级为 D
- AND 结论包含「社区支持基本中断」

### Requirement: 社区支持力度接入风险结论

社区支持力度评价 MUST 接入引入前评估与群组评估的结论输出，并支持按策略配置为硬阻断。

- 评价结果 MUST 出现在评分卡与 Markdown 报告中，MUST NOT 只给总分。
- 等级为 C 或 D 时 MUST 给出提示项与对应的治理建议。
- 策略中配置 `community_deny_grades` 后，命中该等级的组件 MUST 直接硬阻断。

#### Scenario: 社区支撑不足的组件

- GIVEN 组件社区支持力度为 D 级
- WHEN 执行引入前评估
- THEN 评分卡与报告中包含社区支持力度等级与依据
- AND 结论中包含提示项与治理建议

#### Scenario: 策略收紧

- GIVEN 策略配置 `community_deny_grades: ["D"]`
- WHEN 评估一个 D 级组件
- THEN 该组件直接判为 Deny
- AND 硬阻断项说明为「社区支持力度 D 级低于准入要求」
