# Delta for component-health

## ADDED Requirements

### Requirement: 活跃度指标采集

系统 SHALL 为每个组件采集并存储以下健康度指标：最近提交距今天数、近 12 个月发布次数、近 12 个月提交活跃度、
维护者数量（bus factor）、issue 中位响应时长、是否已 archived、是否已被 registry 标记 deprecated、仓库星标与下载量。

- 采集 SHALL 支持 deps.dev API、GitHub API 与各生态 registry 元数据三种来源，任一来源缺失时由其余来源补齐。
- 采集 SHALL 实现限流退避，MUST NOT 因触发 API 限流而中断整批任务。

#### Scenario: 仓库已归档

- GIVEN GitHub 仓库被标记为 archived
- WHEN 采集该组件健康度
- THEN `archived` 为 true
- AND 该组件在评分中直接进入维护健康度最高档

#### Scenario: 接口限流退避

- GIVEN GitHub API 返回 403 限流响应
- WHEN 采集任务继续
- THEN 按退避策略等待后重试
- AND 重试仍失败时该组件标记为 `health_unknown`，不中断整批

### Requirement: 健康度缺失处理

无法获取健康度指标的组件 SHALL 标记为 `health_unknown`，
评估时 MUST 按“未知即风险”处理并触发人工复核，MUST NOT 按健康组件放行。

#### Scenario: 无健康度数据

- GIVEN 某组件三个来源均无数据
- WHEN 执行引入前评估
- THEN 该组件维护健康度维度取保守值
- AND 结论至少为 `Allow-with-condition` 并附带人工复核要求

### Requirement: 采集频率与更新

健康度数据集 SHALL 按日增量更新、按周全量刷新，并在 `meta.json` 记录水位。

#### Scenario: 按周全量刷新

- GIVEN 距上次全量刷新已满 7 天
- WHEN 本轮采集触发
- THEN 对全部组件重新采集健康度指标
- AND 覆盖增量结果并更新水位
