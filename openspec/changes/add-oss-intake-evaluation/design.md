# Design: 开源引入评估体系

## 1. 总体架构

采用**双区（Zone）单通道**架构：互联网侧只做“采集与富化”，内网侧只做“评估与管控”，中间由单向摆渡连接。

```
Zone A 互联网（允许出站）              Zone B 内网（禁止出站）
┌─────────────────────────────┐      ┌─────────────────────────────┐
│ Collectors                  │      │ Ingestors                   │
│  OSV / NVD / KEV / EPSS     │      │  SBOM 摄入（CI 上报）        │
│  deps.dev / GitHub / registry│     │  应用群组资产（CMDB/人工）   │
│  SPDX 许可证列表             │      │                             │
│             ↓               │      │             ↓               │
│ Normalizer（PURL 归一）      │      │ 本地事实层 facts/            │
│             ↓               │      │             ↓               │
│ 事实层 facts/（分片数据集）  │      │ 评估与门禁                   │
│             ↓               │      │  gate / assess / report      │
│ Bundle Builder + Signer ────┼─单─┼─▶ 验签 + 原子切换              │
│                             │  向  │             ↓               │
│                             │      │ 决策回执 outbox/ ──▶ 反向摆渡 │
└─────────────────────────────┘      └─────────────────────────────┘
```

**关键约束**：Zone B 到 Zone A 只允许回传**脱敏的统计回执**（导入水位、评估次数、通过/驳回计数），
禁止携带任何源代码、GAV 清单或内网拓扑信息。

## 2. 数据模型：以 PURL 为主键的事实层

事实层是 SBOM 模式的落地：每个组件由 PURL 唯一标识，各类情报以“数据集（dataset）”为单位挂载在 PURL 上。

```
facts/
├── meta.json               # 事实层版本、生成时间、各数据集 seq 与水位
├── vulns/                  # 漏洞情报（外部）
├── health/                 # 组件活跃度（外部）
├── license/                # 许可证合规（外部）
├── kev/                    # 已利用漏洞清单（外部）
└── inventory/              # 内网应用资产（内部生成，不出网）
```

组件记录形态：

```json
{
  "purl": "pkg:maven/com.alibaba/fastjson@1.2.24",
  "gav":  "com.alibaba:fastjson:1.2.24",
  "eco":  "maven",
  "vulns":  { "cves":[{"id":"CVE-2022-25845","cvss":9.8,"kev":true,"epss":0.94,"fixed":["1.2.83"]}],
              "max_cvss":9.8, "kev_count":1, "unfixed_count":0 },
  "health":  { "last_commit_days": 12, "releases_12m": 5, "maintainers": 3,
               "issue_response_hours": 48, "archived": false, "deprecated": false },
  "license": { "spdx":"Apache-2.0", "category":"permissive", "copyleft":"none" },
  "usage":   { "groups":["支付群组"], "apps":["pay-gateway"],
               "direct": true, "blast_radius": 7 }
}
```

**为什么用 PURL 而不是 GAV**：GAV 只覆盖 Maven，PURL 统一 `maven / npm / pypi / go / cargo / gem / nuget`，
与 SBOM 标准（SPDX、CycloneDX）原生兼容；GAV 作为 PURL 的一个投影字段保留，便于内网用户按熟悉的方式检索。

### 外部情报数据源

| 数据集 | 来源 | 采集频率 | 关键字段 |
| --- | --- | --- | --- |
| `vulns` | OSV + NVD CVE 2.0 | 6h | CVE、CVSS、CWE、修复版本、发布时间 |
| `kev` | CISA KEV 目录 | 日 | 是否在野利用、要求修复期限 |
| `epss` | FIRST EPSS | 日 | 30 天内被利用概率 |
| `health` | deps.dev API + GitHub API + registry 元数据 | 日/周 | 提交/发布节奏、维护者数、响应时长、archived |
| `license` | SPDX License List + registry 声明 | 周 | SPDX ID、传染性分类 |

### 内部数据源（Zone B 本地生成）

| 数据 | 来源 | 说明 |
| --- | --- | --- |
| SBOM | CycloneDX 1.5 / SPDX 2.3 / `mvn dependency:tree` / `package-lock.json` / `go.sum` | 由 CI 插件在构建时产出并上报 |
| 应用资产 | 应用群组定义 + 应用重要性/暴露面/数据敏感度标注 | 人工维护或 CMDB 导入 |

## 3. 离线摆渡同步协议

单向隔离场景下不使用任何双向通道，全部依靠**带签名的数据包 + 增量链**。

### 3.1 数据包结构

```
bundle-<dataset>-<seq>-<YYYYMMDD>.tar.gz
├── manifest.json
├── data/…
└── signature
```

`manifest.json`：

```json
{
  "schema": "scabase-bundle/v1",
  "dataset": "vulns",
  "seq": 1234,
  "mode": "delta|snapshot",
  "generated_at": "2026-10-14T02:00:00Z",
  "source_watermark": { "osv": "2026-10-14T01:30:00Z", "nvd": "2026-10-13T23:00:00Z" },
  "prev_digest": "sha256:9f2c…",
  "files": [ { "path": "data/maven/fastjson.json", "sha256": "…", "size": 1024, "op": "upsert|delete" } ],
  "signature": { "algo": "ed25519", "keyid": "scabase-sync-2026", "value": "MEUCI…" }
}
```

### 3.2 机制要点

| 机制 | 做法 | 目的 |
| --- | --- | --- |
| 增量 | 每个数据集独立单调递增 `seq`，客户端保存 `state.json`（seq + digest），仅请求/导入更新的分片 | 摆渡介质容量有限，避免每次全量 |
| 防篡改 | 逐文件 `sha256` + manifest 整体签名 | 介质经手多人，必须可验证 |
| 防回滚 | `prev_digest` 链式校验，导入时拒绝 `seq <= 当前 seq` | 防止旧包覆盖新数据 |
| 原子切换 | 写入 `.tmp` → 校验全部哈希 → `rename` 覆盖；失败保留上一版本 | 导入中断不留半套数据 |
| 全量校准 | 每季度或 seq 链断裂时导入 `mode=snapshot` 包 | 防止长期增量累积漂移 |
| 接收回执 | 导入成功后生成脱敏 `receipt-*.json`（导入 seq、数据集水位、评估计数） | 互联网侧度量水位差，可反向摆渡 |

### 3.3 数据陈旧度与置信度

每个数据集携带 `generated_at`，内网侧按 `freshness_sla`（默认 14 天）计算 `confidence`：

```
confidence = clamp(1 - max(0, age_days - grace) / (sla - grace), 0, 1)   # grace 默认 3 天
```

置信度不足时：评分**上调**（保守估计）、结论强制降级为 `needs-review`，
并在报告顶部显示数据水位与陈旧天数，杜绝“拿过期数据得出通过结论”。

## 4. 风险评分模型

总分 0–100，越高越危险，四维加权：

| 维度 | 权重 | 组成 |
| --- | --- | --- |
| **V** 漏洞情报 | 35 | CVSS 归一 25 + KEV 命中 8 + EPSS 概率 ≤5 + 无修复版本 4 + 漏洞年龄 >180d 3（封顶 35） |
| **M** 维护健康度 | 25 | archived/deprecated 直接 25；否则按 最近提交距今（≤20）、近 12 月发布数（≤6）、维护者集中度/bus factor（≤5）、issue 响应时长（≤4）累加（封顶 25） |
| **L** 合规许可 | 20 | 未声明/未知 12；强传染性 GPL/AGPL/SSPL 20；弱传染性 LGPL/MPL/EPL 10；BSL/商业源码 14；宽松许可 0；命中策略冲突直接 20 |
| **B** 业务影响 | 20 | 应用重要性（核心 8 / 重要 5 / 一般 2）、网络暴露面（对外 6 / 对内 3 / 离线 0）、数据敏感度（高 6 / 中 3 / 低 0）、影响半径（应用数 ≥10→5，≥5→3，≥2→2）、直接依赖 3 / 传递依赖 1（封顶 20） |

### 4.1 硬阻断（一票否决，直接 Deny）

- 命中 CISA KEV **且**当前版本无修复版本
- CVSS ≥ 9.0 **且**无修复版本
- 许可证与用途冲突（强传染性许可用于闭源分发）
- 仓库已 archived / 组件已 deprecated（除非走例外）
- 支撑结论的数据集置信度不足且未完成人工复核

### 4.2 决策矩阵

| 条件 | 结论 |
| --- | --- |
| 命中任一硬阻断 | `Deny`（可申请 `Exception`） |
| score ≥ 75 | `Deny` |
| 55 ≤ score < 75 | `Review`（安全组 + 架构组人工评审） |
| 25 ≤ score < 55 或 存在 warn 项 | `Allow-with-condition`（限定版本 / 隔离部署 / 复审日期） |
| score < 25 且无阻断项 | `Allow` |

`Exception` 必须携带：补偿措施、责任人、复审到期日；到期未复审则自动回落为 `Deny`。

## 5. 应用群组评估（Zone B 存量视角）

层级：**应用群组（Group）→ 应用（App）→ 组件（PURL）**

```
group_score = 0.6 × max(component_score) + 0.4 × Σ(weight_app × avg_component_score_app) / Σweight_app
```

- 取 `max` 防止“平均主义掩盖单点高危”，加权平均反映整体水位。
- **共性风险**：同一高危组件出现在 ≥3 个应用时，标记为横向风险（一处被攻破，全域受影响），单独列出。
- 输出：群组评分卡、Top N 风险组件、按维度的分解、与上次的对比（新增/已修复/恶化）。

## 6. 引入前评估流程（Gate）

```
申请人提交（候选 GAV/PURL + 用途 + 替代方案）
   → 自动预检（事实层匹配 → 评分 → 策略比对）
   → 决策（Allow / Allow-with-condition / Review / Deny）
   → 产出准入决议（含复审到期日）
   → 落地（写入 SBOM 台账 + CI 门禁规则）
```

同一套引擎有**两个调用面**：

- **交互式**：内网评估台页面填写候选组件，实时出评分卡。
- **CI 门禁**：`oss-intake gate --sbom app.cdx.json --fail-on deny`，构建期拦截，退出码非 0 即失败。

## 7. 构建与交付

| 环境 | 产物 | 流水线 |
| --- | --- | --- |
| Zone A | 事实层数据集、签名 Bundle、公网站点 | `intake-sync.yml`（每日）+ `pages.yml` |
| Zone A | 内网镜像 + 离线 tar 包 | `docker.yml` |
| Zone B | 导入后的本地事实层、评估报告 | 内网 compose 编排 + 定时导入任务 |

- 镜像沿用 `nginx:1.27-alpine` / 8080 / `/healthz` 约定，评估台为独立静态页，不改动现有查询页行为。
- 评分与导入路径保持**零第三方依赖**（仅 Python 标准库），保证内网可运行。

## 8. 测试策略

| 层级 | 覆盖 |
| --- | --- |
| 引擎单测 | 各维度评分边界值、封顶、硬阻断触发、决策阈值、置信度降级 |
| 同步单测 | 签名校验失败、seq 回滚拒绝、文件哈希不匹配、原子切换失败回滚、回执生成 |
| 采集单测 | 用固定 fixture 解析 CycloneDX / SPDX / mvn tree，断言 PURL 归一正确 |
| 端到端 | 本地构建 Bundle → 导入 → 评估 → 断言报告结论，全链路无网络 |
| 前端 | jsdom + 桩 `fetch`，断言评估台渲染与筛选 |

## 9. 关键决策与取舍

1. **单向摆渡 vs 内网代理**：用户环境为完全隔离，故不设计任何内网到公网的查询回源；未知组件在内网必须给出“数据缺失”而非实时补全。已保留 `SCABASE_OSV_API` 开关以兼容未来有条件代理的场景。
2. **PURL 作为主键**：牺牲 GAV 的直观性换取多生态与 SBOM 标准兼容，通过保留 `gav` 投影字段降低内网用户心智负担。
3. **评分取保守**：数据陈旧时上调分数 + 强制人工复核，宁可误报也不放过。
4. **引擎零依赖**：内网 Python 环境不可控，评分与导入只用标准库，避免安装失败导致门禁不可用。
5. **事实层分片而非单文件**：`vulns.json` 已 2.8MB 且只增不减，分片 + 增量是摆渡与扩容的前提。

## 10. 非目标（本次不做）

- 运行时依赖行为分析、二进制指纹比对。
- 源代码溯源与代码克隆检测。
- 自动修复/升级 PR（只给出建议版本，不自动改代码）。

## 11. 落地增强设计（行业场景）

### 11.1 原生依赖文件解析（引入阶段依赖关系自动化分析）

```
源码目录 ──discover()──▶ pom.xml / build.gradle / package.json / package-lock.json /
                          yarn.lock / pnpm-lock.yaml / requirements.txt /
                          Pipfile.lock / poetry.lock / pyproject.toml / go.mod / …
   │
   └── depfile.parse_file() ──▶ Component{purl, eco, name, version, gav,
                                         direct, scope, version_req, pinned}
                                  └── sbom.dedupe() ──▶ 统一组件清单
```

- 与 `sbom.py` 分工：`sbom.py` 消费**已生成**的物料清单，`depfile.py` 消费**开发态**依赖声明，
  因此无需先由外部工具产出 SBOM 即可完成引入前分析。
- `pinned` 标记版本可复现性：`requirements.txt` 写 `flask>=2.0.0` 时给出 `2.0.0` 并标记未锁定，
  风险模型可据此判断「依赖解析结果是否可复现」。
- 单文件解析失败进入「未解析清单」，不中断整目录扫描——CI 中一处坏文件不能让整条门禁失效。

### 11.2 社区支持力度评价（社区活跃度之上的可持续性维度）

```
health 数据集 + registry 元数据 ──▶ community.evaluate()
   ├─ 扣分：最近提交 / 发布节奏 / 维护者 bus factor / 贡献者 / issue 响应 / PR 周期 /
   │        无安全响应策略 / 无 CI / 无背书组织
   ├─ 加分：下游依赖项目数 / 月下载量 / Star
   └─ 缺失信号 → 「未知即风险」扣分 + missing 清单
        │
        └─ 0-100 分 + A/B/C/D 等级 + 逐项依据
              └─ 接入 gate 结论（C/D 给提示；策略配置 community_deny_grades 则硬阻断）
```

设计意图：**漏洞可以修，社区死了修不了**。活跃度（提交/发布）反映“现在是否活着”，
社区支持力度（bus factor、治理、背书、生态位）回答“三年后还活着吗、我能不能自己修”。

### 11.3 安全配置基线 + AI 智能体脚本生成

```
baseline.py（声明式目录）
   ├─ standalone：Redis / Nginx / Tomcat / Kafka / ZooKeeper / Elasticsearch /
   │              Nacos / MySQL / MongoDB / RabbitMQ / Docker / Jenkins
   └─ embedded ：fastjson / log4j / Shiro / Struts / Spring Boot Actuator / XStream / Jackson
        │
        ├── scriptgen 模板引擎（确定性，离线可用）
        │     ├─ sreops    → POSIX sh 巡检脚本（单行 JSON 结果，退出码恒 0）
        │     ├─ codescan  → YAML 规则 + Python 检测脚本（输出 SARIF 2.1.0）
        │     └─ python    → 通用巡检脚本（标准库，--json）
        │
        ├── scriptgen LLM 增强（SCABASE_LLM_ENDPOINT，失败回落模板）
        │     └─ 产物标记 generated_by=llm / review_required=true
        │
        └── lint 静态检查（shebang / STATUS / JSON 输出 / 无高危指令 / 语法可编译）
              └── verify 准确率回归（标注样本集，阈值 90%，UNKNOWN 计入漏检）
```

**为什么用声明式基线而不是直接生成脚本**：基线项是「合规状态」的唯一真相源，
脚本（sh / python / YAML 规则）只是它的三种投影。这样同一套判定语义既能被
`baseline.run_check` 在样本集上量化校验（得到准确率），也能被生成脚本在真实环境执行，
两者不会漂移。

**AI 智能体的定位**：只做「脚本工程化」（平台规范适配、输出格式、可读性），
不做判定决策；且必须经静态检查 + 回归校验 + 人工审核三重把关后才可上线。

### 11.4 漏洞影响范围巡检

```
facts(vulns/health/license) + inventory(应用资产) + baseline(基线目录)
        │
        └── patrol()
              ├─ 按应用聚合：受影响组件数 / KEV 数 / 风险分 / 基线待检项
              ├─ 组件级 finding：CVE 明细 + 建议版本 + 结论（复用评分模型）
              ├─ 工单：严重级别（KEV/CVSS）→ 整改期限（7/15/30/90 天）
              ├─ 增量对比：新增 / 未修复 / 已闭环（三元组：应用 + 组件 + CVE）
              └─ 共性风险：≥2 个应用共用的高危组件
```

与 `assess`（存量风险评估，面向治理视角）互补：`patrol` 是**日常巡检视角**，
回答“现在谁被打中了、要不要开工单、和上次比多了什么”。

### 11.5 工具链对接

| 对接面 | 方向 | 内容 | 约束 |
| --- | --- | --- | --- |
| DEPINFO | 入 | 组件台账导出文件 → 资产模型（支持 purl / gav / eco+group+artifact+version） | 幂等转换 |
| DEPINFO | 出 | 评估结论回传（GAV、结论、评分、建议版本、CVE、复审到期日） | **默认脱敏**：不含应用名/群组名 |
| CICD | 出 | SARIF 2.1.0 / JUnit XML / MR 评论 Markdown + 四档退出码 | Deny→error、Review→warning |
| 代码扫描中心 | 出 | 基线规则包（YAML + 检测脚本） | 规则 id 前缀 `scabase-` |
| SRE 运维平台 | 出 | 巡检脚本（单行 JSON）+ 巡检工单 | 退出码恒 0，结果以 JSON 判定 |

未配置端点时所有对接降级为**文件交换**，绝不因缺少网络而阻塞内网流程。

### 11.6 新增目录与模块

```
oss_intake/
├── depfile.py                 # 原生依赖文件解析
├── community.py               # 社区支持力度评价
├── baseline.py                # 安全配置基线目录 + 检查执行引擎
├── scriptgen.py               # 脚本生成（模板 + LLM 增强 + lint）
├── verify.py                  # 准确率回归校验
├── patrol.py                  # 漏洞影响巡检 / 工单 / 增量
└── integrations/
    ├── depinfo.py                # depinfo 台账导入与结论回传
    └── cicd.py                # SARIF / JUnit / MR 评论 / 退出码
examples/
├── deps/                      # 多生态依赖文件样本
├── baseline-catalog.json      # 基线扩展示例
├── accuracy-cases.json        # 准确率回归样本集（64 例）
└── depinfo-export.json           # depinfo 台账样本
```
