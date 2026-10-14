# Delta for toolchain-integration

## ADDED Requirements

### Requirement: DEPINFO 台账导入

系统 SHALL 支持导入 DEPINFO 导出的组件台账，自动转换为评估侧资产模型。

- 组件描述 MUST 支持三种形态：`purl`、`gav`（`groupId:artifactId:version`）、`eco` + `group` + `artifact` + `version`。
- 转换结果 MUST 生成 `群组 → 应用 → 组件 PURL/GAV 列表` 的资产模型，并保留应用重要性、网络暴露面与数据敏感度。
- 转换 MUST 幂等，重复导入同一台账 MUST 得到相同资产模型。

#### Scenario: 导入 DEPINFO 台账

- GIVEN DEPINFO 导出文件包含 2 个群组、3 个应用，组件以 GAV 与 PURL 混合描述
- WHEN 执行导入
- THEN 生成含 2 个群组的资产模型
- AND 应用下 `purls`/`gavs` 均完成归一
- AND 应用的重要性/暴露面/敏感度被保留

### Requirement: 评估结论回传 DEPINFO

系统 SHALL 支持把评估与巡检结论回传 DEPINFO，形成流程联动。

- 回传内容 MUST 包含组件 GAV、PURL、结论、评分、建议版本、复审到期日、命中 CVE 与硬阻断项。
- 回传 MUST 默认脱敏：只含组件维度结论，MUST NOT 包含应用名、群组名等内网拓扑信息；显式关闭脱敏时才保留应用维度。
- 回传 MUST 支持文件交换与 HTTP 推送两种方式；未配置 DEPINFO 端点时 MUST 跳过推送并明确提示，MUST NOT 报错中断。
- 回传 MUST 携带同步令牌，便于 DEPINFO 侧做幂等与追溯。

#### Scenario: 脱敏回传

- GIVEN 引入前评估产生 Deny 结论
- WHEN 生成回传文件且保持默认脱敏
- THEN 文件包含 GAV、结论、评分与建议版本
- AND MUST NOT 包含任何应用名或群组名
- AND 携带 `masked=true` 与同步令牌

#### Scenario: 未配置端点

- GIVEN 环境未配置 `SCABASE_DEPINFO_URL`
- WHEN 请求推送回传
- THEN 跳过推送并输出提示信息
- AND 回传文件仍正常落盘

### Requirement: CICD 流水线产物

系统 SHALL 把门禁结论转换为流水线可直接消费的产物与退出码语义。

- MUST 支持导出 SARIF 2.1.0，结论映射为 SARIF level：`Deny → error`、`Review → warning`、`Allow-with-condition → note`、`Allow → none`。
- MUST 支持导出 JUnit XML，命中门禁阈值的组件计为 failure。
- MUST 支持导出 MR/PR 评论 Markdown，包含结论分布、组件明细表与门禁未通过提示。
- 退出码语义 MUST 支持四档阈值：`never` / `deny` / `review` / `condition`。

#### Scenario: 门禁失败时阻断流水线

- GIVEN SBOM 中存在 Deny 组件且 `--fail-on deny`
- WHEN 在 CICD 中执行门禁
- THEN 导出 SARIF 与 JUnit 报告
- AND 退出码为 1，流水线中断

#### Scenario: 允许引入时不阻断

- GIVEN 全部组件结论为 Allow 且 `--fail-on deny`
- WHEN 执行门禁
- THEN 退出码为 0
- AND 评论 Markdown 中不出现「门禁未通过」
