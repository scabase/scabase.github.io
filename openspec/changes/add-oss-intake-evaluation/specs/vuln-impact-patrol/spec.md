# Delta for vuln-impact-patrol

## ADDED Requirements

### Requirement: 按应用聚合的漏洞影响巡检

系统 SHALL 以内网应用资产为维度，聚合开源组件的漏洞命中情况与安全基线待检项，输出分层巡检结论。

- 漏洞命中 MUST 精确到组件版本，MUST NOT 以「组件名相同」作为告警依据。
- 每个应用 MUST 输出：组件总数、受影响组件数、命中 KEV 数、应用风险分、结论分布、待巡检基线项清单。
- 每个受影响组件 MUST 输出 CVE 清单（含 CVSS、KEV、EPSS、修复版本、公开时间）、建议升级版本、风险评分与结论。
- 巡检结论 MUST 复用引入前评估的同一套风险模型与权重，保证两处口径一致。

#### Scenario: 支付核心被 log4j 影响

- GIVEN 应用「支付核心」引入 `log4j-core 2.14.1`，事实层记录 CVE-2021-44228 且命中 KEV
- WHEN 执行巡检
- THEN 该应用受影响组件数 ≥ 1、命中 KEV 数 ≥ 1
- AND 组件 finding 中列出 CVE-2021-44228、CVSS、修复版本 2.15.0
- AND 结论与引入前评估口径一致

#### Scenario: 未引入的组件不告警

- GIVEN 应用未引入某存在高危漏洞的组件
- WHEN 执行巡检
- THEN 该组件 MUST NOT 出现在该应用的巡检结果中

### Requirement: 巡检工单与整改期限

系统 SHALL 把巡检结论转为结构化工单，便于推送 SRE 运维平台 / 代码扫描中心跟踪闭环。

- 工单 MUST 包含：工单号、群组、应用、组件（GAV/PURL）、严重级别、结论、评分、命中 CVE、建议版本、关联基线编号、整改期限。
- 严重级别 MUST 由 KEV 命中与最高 CVSS 决定：命中 KEV 或 CVSS ≥ 9.0 为 `critical`，≥ 7.0 为 `high`，≥ 4.0 为 `medium`，其余为 `low`。
- 整改期限 MUST 按级别设定：critical 7 天、high 15 天、medium 30 天、low 90 天。
- 工单 MUST 按严重级别排序。

#### Scenario: 生成整改工单

- GIVEN 某应用组件命中 KEV 漏洞
- WHEN 生成工单
- THEN 工单严重级别为 critical
- AND 整改期限为生成日后第 7 天
- AND 工单按严重级别排在列表最前

### Requirement: 增量巡检对比

系统 SHALL 支持与上次巡检结果对比，输出新增风险、仍未修复与已修复闭环三类增量。

- 增量比对单位 MUST 为「应用 + 组件 + CVE」三元组。
- 无上次结果时 MUST 输出空增量而非报错。
- 巡检状态 MUST 可持久化并在下次巡检时加载。

#### Scenario: 二次巡检对比

- GIVEN 首次巡检已完成并保存状态，期间未修复任何漏洞
- WHEN 再次巡检并加载上次状态
- THEN 新增风险为 0，仍未修复数量大于 0
- AND 输出对比基准时间

#### Scenario: 升级后闭环

- GIVEN 组件已升级至修复版本
- WHEN 再次巡检
- THEN 该 CVE 出现在「已修复闭环」列表中

### Requirement: 跨应用共性风险识别

系统 SHALL 识别被多个应用共同引用的高风险组件，输出共性风险清单。

- 共性风险 MUST 满足「被 ≥ 2 个应用引用」且存在漏洞命中。
- 输出 MUST 包含影响应用清单、风险分、结论、命中 CVE 与建议版本。
- 共性风险 MUST 按影响应用数倒序、风险分倒序排列。

#### Scenario: 同一组件被两个应用引用

- GIVEN `fastjson 1.2.24` 同时被「支付核心」与「渠道前置」引入
- WHEN 执行巡检
- THEN 输出该组件的共性风险条目
- AND 影响应用数为 2 且列出两个应用名
