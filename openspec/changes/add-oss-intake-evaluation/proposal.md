# Proposal: 开源引入评估体系

## Why

当前 ScaBase 只回答“某个组件有没有已知漏洞”，无法回答企业真正关心的三个问题：
**这个组件能不能引入**、**引入后哪个应用群组会受影响**、**这些组件还健不健康**。
同时互联网侧采集的数据无法进入无公网出口的内网，导致评估只能靠人肉查表、结论不可复现、无法审计。

本变更在现有漏洞查询能力之上，建立一套**以 SBOM 为骨架、多源情报为血肉、离线摆渡为通道**的开源引入评估体系，
把开源治理从“事后查漏洞”前移到“引入前决策 + 存量持续评估”。

## What Changes

- **新增事实层**：以 PURL 为主键，把漏洞情报、组件活跃度、许可证合规、内网应用 GAV 关联统一到一套可增量同步的数据集上。
- **新增数据源**：在互联网侧补充 CISA KEV（已可利用漏洞）、EPSS（利用概率）、组件活跃度（deps.dev / GitHub / 各 registry 元数据）、SPDX 许可证合规矩阵。
- **新增风险评分引擎**：四维加权（漏洞 / 维护健康度 / 合规许可 / 业务影响）+ 硬阻断规则 + 数据置信度降级。
- **新增引入前门禁**：提交候选组件即出评分与结论（Allow / Allow-with-condition / Deny / Exception），可作为 CI 门禁或人工评审输入。
- **新增应用群组评估**：按 应用群组 → 应用 → 组件 的层级聚合风险，输出群组风险总览、Top 风险组件与共性风险。
- **新增离线摆渡同步**：单向隔离场景下，通过带签名 manifest 与增量 seq 链的数据包完成“互联网采集 → 内网导入”，并产出可回传的接收回执。
- **新增构建交付链路**：互联网与内网两套 CI，分别产出数据包、镜像与离线 tar 包。

**BREAKING**：`vulns.json` 不再是唯一数据入口。新增事实层目录 `scabase-fetcher/data/facts/` 后，
前端与评估引擎统一从事实层读取；`vulns.json` 转为事实层 `vulns` 数据集的兼容视图，保留两个发布周期后移除。

## Capabilities

### New Capabilities

- `sbom-fact-layer`：SBOM/组件清单摄入、PURL 归一化、GAV 与应用关联，产出事实层数据集
- `vuln-intel-enrichment`：OSV / NVD / KEV / EPSS 多源漏洞情报富化与 CVE 主键归一
- `component-health`：开源组件活跃度与维护健康度采集与评分
- `license-compliance`：许可证识别、传染性判定与合规策略比对
- `risk-scoring`：四维加权风险评分、硬阻断规则与置信度降级
- `intake-gate`：开源引入前评估流程、决策结论与门禁集成
- `offline-ferry-sync`：离线数据包构建、签名、增量与内网导入校验
- `app-group-assessment`：按应用群组聚合的存量开源引入风险评估
- `build-delivery`：互联网/内网双环境构建、测试与交付流水线

### Modified Capabilities

- `vuln-data-collection`：采集目标由“仅 OSV+NVD 落单文件”改为“多源采集并按数据集分片写入事实层”
- `offline-delivery`：容器需承载事实层数据与新的评估页面，运行时配置需支持事实层根路径

## Impact

- **新增代码**：`scabase-fetcher/scripts/`（采集器）、`oss-intake/`（评分引擎与门禁 CLI）、`tests/`（单测与端到端冒烟）。
- **数据产物**：`scabase-fetcher/data/facts/`（事实层）、`scabase-fetcher/data/bundles/`（离线数据包）。
- **CI**：`.github/workflows/intake-sync.yml`（每日构建签名数据包）、`docker.yml` 扩展、内网侧 compose 编排。
- **前端**：新增 `intake.html`（内网评估台），沿用 ES5 IIFE 约定，不改动现有 `index.html` 的查询行为。
- **依赖**：Python 侧仅新增 `requests`（已有）；评分与导入路径 MUST 保持零第三方依赖以便内网运行。
