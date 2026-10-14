# Delta for intake-gate

## ADDED Requirements

### Requirement: 引入前评估流程

系统 SHALL 支持提交候选组件（GAV / PURL）与用途说明，自动完成事实层匹配、评分与策略比对，
并输出准入结论（Allow / Allow-with-condition / Review / Deny / Exception）。

- 评估结论 SHALL 包含：分项得分、命中规则、建议版本、复审到期日。
- 结论 SHALL 可导出为 JSON 与 Markdown，供审批系统归档。

#### Scenario: 提交候选组件并获结论

- GIVEN 申请人提交 `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`，用途为内部服务
- WHEN 执行引入前评估
- THEN 输出评分卡与结论 `Deny`
- AND 报告列出命中规则与建议版本 `2.17.1`

#### Scenario: 导出结论供归档

- GIVEN 一次评估已完成
- WHEN 请求导出
- THEN 产出 JSON 与 Markdown 两种格式的决议文件

### Requirement: CI 门禁集成

系统 SHALL 提供命令行门禁，读取构建产物 SBOM 并对其中每个组件执行评估，
按 `--fail-on` 阈值返回非零退出码以阻断流水线。

- 门禁 SHALL 在摘要中列出被阻断的组件及原因。
- 门禁 MUST NOT 因事实层缺失而静默通过。

#### Scenario: 高危组件阻断构建

- GIVEN 应用 SBOM 中存在结论为 `Deny` 的组件
- WHEN 在 CI 中执行门禁且 `--fail-on deny`
- THEN 进程退出码非 0
- AND 摘要列出该组件与阻断原因

#### Scenario: 事实层缺失时不静默通过

- GIVEN 待评估组件在事实层中不存在
- WHEN 执行门禁
- THEN 该组件标记为待人工复核
- AND 门禁按配置决定是否失败，MUST NOT 直接输出“无风险”

### Requirement: 例外与复审

例外结论 SHALL 必须记录补偿措施、责任人与复审到期日，并在到期后提醒复审。

#### Scenario: 例外到期自动回落

- GIVEN 某组件的例外结论复审到期日为 2026-12-31 且未复审
- WHEN 当前日期已超过该到期日
- THEN 该组件结论回落为 `Deny`
- AND 报告中标记“例外已过期，需重新评估”

### Requirement: 平台产物导出

门禁 SHALL 支持直接导出代码扫描中心、CICD 平台与 MR/PR 可消费的产物，实现与工具链流程联动。

- 门禁 MUST 支持导出 SARIF 2.1.0、JUnit XML 与 MR/PR 评论 Markdown。
- 门禁 MUST 支持读取 depinfo 台账（GAV/PURL 列表）作为评估对象。
- 门禁 MUST 支持将结论回传 depinfo（默认脱敏）。

#### Scenario: 在 CICD 中导出报告

- GIVEN 门禁评估了一份应用 SBOM
- WHEN 指定 `--sarif`、`--junit` 与 `--comment` 输出路径
- THEN 产出三种格式的产物
- AND SARIF 中 `Deny` 映射为 error、`Review` 映射为 warning

#### Scenario: 直接评估 depinfo 台账组件

- GIVEN 提供 depinfo 台账导出文件中的 GAV 列表
- WHEN 执行门禁
- THEN 每个 GAV 被归一为 PURL 后逐一评估
- AND 结论可回传 depinfo 且不含内网拓扑信息
