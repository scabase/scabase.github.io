# Delta for sbom-fact-layer

## ADDED Requirements

### Requirement: PURL 主键与 GAV 投影

系统 SHALL 以 PURL（`pkg:<type>/<namespace>/<name>@<version>`）作为组件的唯一主键，
并 SHALL 为每个组件保留 `gav`（`groupId:artifactId:version`）作为 Maven 生态的可读投影字段。

- 支持的生态 MUST 至少包含 `maven`、`npm`、`pypi`、`go`、`cargo`、`gem`、`nuget`。
- 同一组件的不同坐标系表示 MUST 归一为同一个 PURL。

#### Scenario: Maven GAV 归一为 PURL

- GIVEN 输入 `com.alibaba:fastjson:1.2.24`
- WHEN 执行归一化
- THEN 产出 PURL `pkg:maven/com.alibaba/fastjson@1.2.24`
- AND `gav` 字段保留原值

#### Scenario: 多生态并存

- GIVEN 输入 `pkg:npm/lodash@4.17.20`
- WHEN 执行归一化
- THEN 生态识别为 `npm`，`gav` 字段为空

### Requirement: SBOM 摄入

系统 SHALL 解析 CycloneDX 1.5、SPDX 2.3、`mvn dependency:tree` 输出与常见 lock 文件，
并将其中每个组件归一为 PURL 后写入事实层。

- 解析 SHALL 保留依赖层级信息，用于区分**直接依赖**与**传递依赖**。
- 无法识别的条目 SHALL 记录为 `unresolved` 条目并在报告中列出，MUST NOT 静默丢弃。

#### Scenario: 解析 CycloneDX 并区分依赖层级

- GIVEN 一份 CycloneDX SBOM，其中组件 A 位于根 `dependencies`，组件 B 仅由 A 引用
- WHEN 摄入该 SBOM
- THEN 组件 A 标记为 direct
- AND 组件 B 标记为 transitive

#### Scenario: 无法识别的条目

- GIVEN SBOM 中存在缺少版本号的条目
- WHEN 摄入该 SBOM
- THEN 该条目进入 `unresolved` 列表
- AND 报告中显式列出该条目及原因

### Requirement: 事实层数据集分片

事实层 SHALL 按数据集分片存储（至少 `vulns`、`health`、`license`、`kev`、`inventory`），
并由 `meta.json` 记录每个数据集的版本、seq 与生成时间水位。

- 系统 MUST NOT 使用单一无界增长的文件承载全量事实。
- 外部情报数据集与内部资产数据集 SHALL 分开存放，内部资产数据集 MUST NOT 出现在外发数据包中。

#### Scenario: 内部资产不外发

- GIVEN 事实层中存在 `inventory` 数据集
- WHEN 构建外发数据包
- THEN 包内 MUST NOT 包含 `inventory` 的任何内容

### Requirement: 应用群组资产模型

系统 SHALL 维护 `应用群组（group）→ 应用（app）→ 组件（PURL）` 三层关联，
并为每个应用记录重要性（核心 / 重要 / 一般）、网络暴露面（对外 / 对内 / 离线）与数据敏感度（高 / 中 / 低）。

- 一个组件可被多个应用引用，系统 SHALL 记录其影响半径（引用该组件的应用数量）。

#### Scenario: 计算影响半径

- GIVEN 组件 X 被群组内 7 个应用引用
- WHEN 构建资产模型
- THEN 组件 X 的 `blast_radius` 为 7
- AND 评估报告可据此判定其影响面
