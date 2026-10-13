# vuln-data-collection Specification

## Purpose

在互联网侧定时采集开源组件漏洞情报，富化后生成可供内网离线使用的事实层数据文件。

## Requirements

### Requirement: 清单驱动的 OSV 采集

系统 SHALL 读取 `ecosystem|package|version` 清单，逐个组件调用 OSV `/v1/query`，并将结果写入 `vulns.json`。

- 结果键 SHALL 为 `eco|pkg|ver`，其中 `eco` 保留清单中的原始小写生态名。
- 请求失败 SHALL 记录到 stderr 并降级为空结果，MUST NOT 中断整批采集。

#### Scenario: 采集失败降级

- GIVEN 某个组件调用 OSV 返回非 200
- WHEN 采集任务继续
- THEN 该组件写入空漏洞集合
- AND 其余组件继续采集直至完成

### Requirement: NVD 富化

系统 SHALL 对每条存在 CVE 编号的记录调用 NVD CVE 2.0 接口，补充标准 CVSS 与 CWE。

- 无 CVE 编号的 GHSA-only 记录 SHALL 跳过 NVD 查询。
- 未配置 `NVD_API_KEY` 时 SHALL 使用低速模式（默认 6.5s 间隔），配置密钥时使用 0.7s 间隔。

#### Scenario: 无 CVE 跳过富化

- GIVEN 某条 OSV 记录既无 CVE id 也无 CVE 别名
- WHEN 执行富化
- THEN 跳过 NVD 查询
- AND 该记录的 `nvd` 字段为 null

### Requirement: 每日定时更新

采集 SHALL 由 GitHub Actions 每日调度执行，并将更新后的数据文件提交回仓库。

- 增量更新 MUST 保留历史采集结果，避免已入库组件被单次失败清空。
