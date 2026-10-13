# vuln-lookup Specification

## Purpose

为用户提供开源组件已知漏洞的查询能力，输入组件清单或 CVE 编号，输出以 **CVE 编号为主键**聚合的漏洞结果，可在纯离线内网环境运行。

## Requirements

### Requirement: 组件清单解析

系统 SHALL 解析以下输入格式并按 `ecosystem|package|version` 归一化：
`pkg_list` 竖线格式、Maven GAV（`groupId:artifactId:version`）、`ecosystem:package@version` 简写、裸 CVE 编号。

- 生态名 SHALL 映射为 OSV 规范名（`maven`→`Maven`、`pypi`→`PyPI`、`go`→`Go` 等）。
- 以 `#` 开头的行 SHALL 视为注释，空行 SHALL 忽略。

#### Scenario: 解析 pkg_list 格式

- GIVEN 输入行 `maven|com.alibaba:fastjson|1.2.24`
- WHEN 提交查询
- THEN 解析为生态 `Maven`、包 `com.alibaba:fastjson`、版本 `1.2.24`

#### Scenario: 解析裸 CVE 编号

- GIVEN 输入行 `CVE-2021-44228`
- WHEN 提交查询
- THEN 从本地事实层反查受该 CVE 影响的全部组件
- AND 未命中时 MUST 停止（离线模式）或回退 OSV `/v1/vulns/{id}`（联网模式）

### Requirement: 以 CVE 为主键聚合

系统 SHALL 从 OSV `id` 与 `aliases` 中收集全部 CVE 编号，并按 CVE 集合合并指向同一漏洞组的多条 advisory。

- GHSA 等非 CVE 标识 SHALL 降级为次要别名标签。
- 合并后 SHALL 采用 NVD 富化对应的 CVE 作为主 CVE，避免标题与 CVSS 描述错位。

#### Scenario: 合并同源 advisory

- GIVEN 本地库中存在 5 条指向相同 CVE 集合的 GHSA 记录
- WHEN 渲染结果
- THEN 展示为合并后的 3 条记录
- AND 每条记录列出其关联的全部 CVE

### Requirement: 结果工具栏

系统 SHALL 提供 CVE/关键词过滤、严重度筛选、排序（严重度 / CVE / 发布时间 / 组件名）、「按组件 / 按 CVE」视图切换与「复制 CVE 清单」。

#### Scenario: 按 CVE 前缀过滤

- GIVEN 结果包含 `CVE-2021-44228` 与 `CVE-2022-22965`
- WHEN 过滤框输入 `CVE-2021`
- THEN 仅保留命中该前缀的 CVE，其余 CVE 从卡片中移除

### Requirement: 离线模式行为

当 `SCABASE_CONFIG.offline` 为 true 时，系统 MUST 隐藏「强制实时 OSV」选项并显示离线标记，且 MUST NOT 发起任何外部网络请求。

- 本地库未命中的组件 SHALL 返回显式的 `offlineMiss` 数据缺失卡片，而非“未发现已知漏洞”。

#### Scenario: 离线未知组件

- GIVEN 运行在离线模式
- WHEN 查询一个本地事实层中不存在的组件
- THEN 展示数据缺失提示卡片
- AND 外部请求次数为 0

### Requirement: 结果完整性

带 `note` 但无漏洞的条目 SHALL 保留卡片展示，且 MUST NOT 显示“未发现已知漏洞”这类误导性结论。
