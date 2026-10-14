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
- `native-dependency-parsing`：多生态原生依赖文件解析（Maven/npm/PyPI/Go 等），引入阶段依赖关系自动化分析
- `community-support`：社区支持力度与可持续维护能力评价（A/B/C/D 等级 + 可解释依据）
- `security-baseline`：开源软件安全配置基线目录（声明式，覆盖独立部署型与依赖引入型组件）
- `ai-script-generation`：AI 智能体生成基线/漏洞检测脚本（SRE 运维平台 / 代码扫描中心 / 通用）与准确率回归门禁
- `vuln-impact-patrol`：漏洞影响范围与安全基线自动化巡检、工单与增量对比
- `toolchain-integration`：depinfo 台账导入与结论回传、CICD 产物（SARIF/JUnit/MR 评论）与退出码语义

### Modified Capabilities

- `vuln-data-collection`：采集目标由“仅 OSV+NVD 落单文件”改为“多源采集并按数据集分片写入事实层”
- `offline-delivery`：容器需承载事实层数据与新的评估页面，运行时配置需支持事实层根路径
- `component-health`：在活跃度指标基础上补充社区支持力度所需治理信号（安全响应策略 / CI / 背书组织 / 下游依赖数 / 下载量）
- `intake-gate`：门禁新增平台产物导出（SARIF / JUnit / MR 评论）与 depinfo 台账直接评估

## 落地背景（行业）

本方案面向行业开源软件治理的三个痛点：**引入阶段分析复杂度高**、**缺少安全配置基线能力**、
**漏洞影响资产检测能力不足**。对应增强如下：

1. **引入阶段依赖关系自动化分析**：直接解析外部社区 Maven / npm / PyPI 等原生依赖文件，
   自动归一为 PURL 并区分直接/传递依赖；同时给出供应链风险、安全风险、社区支持力度与活跃度评价，
   降低人工分析工作量。
2. **安全配置基线 + AI 脚本生成**：内置覆盖常见独立部署型与依赖引入型开源软件的基线目录；
   由 AI 智能体结合平台规范自动生成符合代码扫描中心、SRE 运维平台纳管规则的基线检查脚本与漏洞检测脚本，
   并以标注样本集回归校验把「扫描准确率达 90%」落成可度量的 CI 门禁。
3. **漏洞影响资产巡检**：按应用群组聚合受影响组件、命中 CVE 与基线待检项，输出工单与增量对比，
   替代人工摸排影响范围。
4. **工具链联动**：所有模块接入现有工具链——与 DEPINFO 系统双向互通（台账导入 + 结论回传，默认脱敏），
   与 CICD 平台联动（SARIF / JUnit / MR 评论 + 退出码阈值）。
5. **社区支持力度与活跃度采集**：每日由 CI 采集 GitHub / deps.dev / npm registry 三类信号，
   汇总为 0-100 分与 A/B/C/D 等级，写入事实层供内网评估使用。

## Impact

- **新增代码**：`scabase-fetcher/scripts/`（采集器）、`oss-intake/`（评分引擎与门禁 CLI）、`tests/`（单测与端到端冒烟）。
- **数据产物**：`scabase-fetcher/data/facts/`（事实层）、`scabase-fetcher/data/bundles/`（离线数据包）。
- **CI**：`.github/workflows/intake-sync.yml`（每日构建签名数据包）、`docker.yml` 扩展、内网侧 compose 编排。
- **前端**：新增 `intake.html`（内网评估台），沿用 ES5 IIFE 约定，不改动现有 `index.html` 的查询行为。
- **依赖**：Python 侧仅新增 `requests`（已有）；评分与导入路径 MUST 保持零第三方依赖以便内网运行。
