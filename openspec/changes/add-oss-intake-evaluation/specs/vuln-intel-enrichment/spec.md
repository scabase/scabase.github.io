# Delta for vuln-intel-enrichment

## ADDED Requirements

### Requirement: 多源漏洞情报富化

系统 SHALL 在 OSV + NVD 之外补充 CISA KEV（已在野利用）与 EPSS（利用概率），
并按 CVE 主键归并到同一条漏洞记录上。

- 每条 CVE 记录 SHALL 至少包含：CVE 编号、CVSS 分值、严重度、是否命中 KEV、EPSS 分值、修复版本列表、发布时间。
- 组件级 SHALL 聚合出 `max_cvss`、`kev_count`、`unfixed_count` 供评分直接使用。

#### Scenario: KEV 命中聚合

- GIVEN 组件存在三条 CVE，其中一条在 CISA KEV 目录中
- WHEN 完成富化
- THEN 该 CVE 的 `kev` 标记为 true
- AND 组件级 `kev_count` 为 1

#### Scenario: 无修复版本识别

- GIVEN 某 CVE 的影响范围包含当前版本且 `fixed` 字段为空
- WHEN 完成富化
- THEN 该 CVE 计入 `unfixed_count`

### Requirement: CVE 主键归一

系统 SHALL 从 OSV `id` 与 `aliases` 中提取全部 CVE 编号，并以 CVE 集合作为去重键合并指向同一漏洞的多条 advisory。

- GHSA 等非 CVE 标识 SHALL 保留为别名，MUST NOT 作为主键。

#### Scenario: 同源 advisory 合并

- GIVEN 两条 GHSA 记录指向相同的 CVE 集合
- WHEN 执行归一
- THEN 合并为一条以 CVE 为主键的记录
- AND 两条 GHSA 保留在别名列表中

### Requirement: 情报采集失败降级

任一情报源采集失败时，系统 SHALL 保留该源上一次成功的数据并标记水位停滞，MUST NOT 用空结果覆盖已有情报。

#### Scenario: KEV 源不可用

- GIVEN CISA KEV 接口返回异常
- WHEN 执行本轮富化
- THEN 沿用上一次成功的 KEV 数据
- AND `meta.json` 中该数据集的 `generated_at` 不更新且标记 `degraded`
