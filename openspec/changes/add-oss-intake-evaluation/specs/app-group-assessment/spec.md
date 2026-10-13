# Delta for app-group-assessment

## ADDED Requirements

### Requirement: 群组风险聚合

系统 SHALL 按 `应用群组 → 应用 → 组件` 层级聚合风险，并按以下公式计算群组分值：

```
group_score = 0.6 × max(component_score) + 0.4 × Σ(weight_app × avg_component_score_app) / Σweight_app
```

- 公式 MUST 同时体现“最差单点”与“整体水位”，禁止只用平均值掩盖单点高危。

#### Scenario: 单点高危拉高群组风险

- GIVEN 群组内有 20 个组件均为低分，但存在 1 个 95 分组件
- WHEN 计算群组分值
- THEN 群组分值显著高于各组件平均分
- AND 报告中突出该 95 分组件

### Requirement: 共性风险识别

当同一高危组件出现在同一群组的 ≥3 个应用中时，系统 SHALL 标记为横向共性风险并单独列出。

#### Scenario: 跨应用共用高危组件

- GIVEN 组件 X 出现在支付群组的 5 个应用中且评分 ≥ 55
- WHEN 生成群组评估报告
- THEN 组件 X 被标为共性风险
- AND 报告说明其横向影响面

### Requirement: 群组报告内容

群组评估 SHALL 输出：群组评分卡、Top N 风险组件、按四维分解的维度明细、共性风险列表、与上次评估的对比（新增 / 已修复 / 恶化）。

#### Scenario: 对比上次评估

- GIVEN 上次评估中存在组件 Y 评分 40，本次升级后评分 20
- WHEN 生成本次报告
- THEN 组件 Y 出现在“已改善”列表
- AND 展示两次评分与变化量
