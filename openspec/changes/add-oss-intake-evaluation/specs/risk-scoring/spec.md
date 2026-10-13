# Delta for risk-scoring

## ADDED Requirements

### Requirement: 四维加权评分

系统 SHALL 按以下四维加权计算 0–100 的风险分值（分值越高风险越大），权重可配置：

- **V 漏洞情报（35）**：CVSS 归一 ≤25、KEV 命中 +8、EPSS ≤5、无修复版本 +4、漏洞年龄 >180 天 +3
- **M 维护健康度（25）**：archived/deprecated 直接取满；否则按最近提交距今天数 ≤20、近 12 月发布数 ≤6、维护者集中度 ≤5、issue 响应时长 ≤4 累加
- **L 合规许可（20）**：unknown 12、strong-copyleft 20、weak-copyleft 10、business-source 14、permissive 0
- **B 业务影响（20）**：应用重要性 ≤8、网络暴露面 ≤6、数据敏感度 ≤6、影响半径 ≤5、直接依赖 3 / 传递依赖 1

每个维度 SHALL 封顶在其权重值内。

#### Scenario: 高危漏洞叠加无修复版本

- GIVEN 组件 CVSS 为 9.8，命中 KEV，且当前版本无修复版本
- WHEN 计算漏洞维度
- THEN 原始累加超过 35
- AND 最终按封顶取值 35

#### Scenario: 已归档组件

- GIVEN 组件仓库已 archived
- WHEN 计算维护健康度维度
- THEN 该维度取满 25

### Requirement: 硬阻断规则

命中以下任一条件时，系统 SHALL 直接判定为 `Deny`，不再依赖分值：

1. 命中 CISA KEV 且当前版本无修复版本
2. CVSS ≥ 9.0 且无修复版本
3. 许可证与用途策略冲突
4. 组件已 archived 或已 deprecated（除非走例外流程）
5. 支撑结论的数据集置信度不足且未完成人工复核

#### Scenario: KEV 无修复

- GIVEN 组件命中 KEV 且无可用修复版本
- WHEN 执行评估
- THEN 结论为 `Deny`
- AND 报告中列出该硬阻断项及依据

### Requirement: 决策矩阵

系统 SHALL 按以下规则给出结论：

| 条件 | 结论 |
| --- | --- |
| 命中硬阻断 | `Deny` |
| score ≥ 75 | `Deny` |
| 55 ≤ score < 75 | `Review` |
| 25 ≤ score < 55 或存在 warn 项 | `Allow-with-condition` |
| score < 25 且无阻断项 | `Allow` |

例外（Exception）SHALL 必须携带补偿措施、责任人与复审到期日；到期未复审 SHOULD 自动回落为 `Deny`。

#### Scenario: 低风险自动通过

- GIVEN 组件 score 为 12 且无任何阻断项
- WHEN 执行评估
- THEN 结论为 `Allow`

#### Scenario: 中等风险附带条件

- GIVEN 组件 score 为 38
- WHEN 执行评估
- THEN 结论为 `Allow-with-condition`
- AND 报告中给出限定版本与复审日期建议

### Requirement: 置信度降级与保守上调

当支撑某维度的数据集陈旧度超过 `freshness_sla`（默认 14 天，宽限 3 天）时，
系统 SHALL 按 `confidence = clamp(1 - max(0, age - grace) / (sla - grace), 0, 1)` 计算置信度，
并 SHALL 上调该维度分值、强制结论至少降级到 `needs-review`。

- 报告 SHALL 展示每个数据集的生成时间与陈旧天数。

#### Scenario: 数据陈旧触发降级

- GIVEN 漏洞数据集已 20 天未更新，sla 为 14 天、grace 为 3 天
- WHEN 执行评估
- THEN confidence 为 0
- AND 结论强制为 `needs-review`
- AND 报告顶部显示“漏洞情报已 20 天未更新”

### Requirement: 评分可解释性

评分结果 SHALL 输出每个维度的分项得分、命中规则与依据字段，
使得任一结论可被人工逐项复核，MUST NOT 只给总分。

#### Scenario: 输出可解释评分卡

- GIVEN 某组件评估完成，总分 62
- WHEN 生成评分卡
- THEN 展示 V / M / L / B 四个维度的分项得分
- AND 列出每条命中规则及其依据字段取值
