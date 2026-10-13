# Delta for vuln-data-collection

## MODIFIED Requirements

### Requirement: NVD 富化

系统 SHALL 对每条存在 CVE 编号的记录调用 NVD CVE 2.0 接口，补充标准 CVSS 与 CWE，
并在其之上补充 CISA KEV 与 EPSS 字段。

- 无 CVE 编号的 GHSA-only 记录 SHALL 跳过 NVD 查询。
- 未配置 `NVD_API_KEY` 时 SHALL 使用低速模式（默认 6.5s 间隔），配置密钥时使用 0.7s 间隔。
- 新增的 KEV / EPSS 源采集失败时 SHALL 沿用上一次成功数据并标记 `degraded`，MUST NOT 清空已有字段。

（Previously：仅调用 NVD 补充 CVSS 与 CWE，不涉及 KEV / EPSS。）

#### Scenario: 无 CVE 跳过富化

- GIVEN 某条 OSV 记录既无 CVE id 也无 CVE 别名
- WHEN 执行富化
- THEN 跳过 NVD 查询
- AND 该记录的 `nvd` 字段为 null

#### Scenario: EPSS 源不可用

- GIVEN EPSS 接口返回异常
- WHEN 执行本轮富化
- THEN 沿用上一次成功的 EPSS 分值
- AND 该数据集标记 `degraded`

## ADDED Requirements

### Requirement: 按数据集分片落盘

系统 SHALL 将采集结果按数据集（`vulns` / `health` / `license` / `kev`）分片写入事实层，并更新 `meta.json` 水位。

- 原有 `vulns.json` SHALL 转为 `facts/vulns` 数据集的兼容视图，保留两个发布周期。
- 单文件无界增长 MUST 被禁止。

#### Scenario: 分片写入

- GIVEN 本轮采集完成
- WHEN 落盘
- THEN 各数据集分别写入自身分片
- AND `meta.json` 中各数据集 seq 与 `generated_at` 更新
