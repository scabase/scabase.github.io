# ScaBase · 开源软件成分治理平台

> **一句话定位**：把「开源组件查漏洞」升级为「开源引入全生命周期治理」——
> 互联网侧负责采集与富化，内网侧负责评估与管控，两侧用带签名的离线数据包单向摆渡。

- 在线站点：https://scabase.roweb.cn
- 源码仓库：https://github.com/scabase/scabase.github.io
- 许可证：MIT
- 建议宣讲时长：18–22 分钟（14 页正文 + 4 页备份）

---

## 讲者提纲（速览）

| # | 页面 | 核心主张 | 时长 |
|---|---|---|---|
| 01 | 封面 | 从「查得到」到「管得住」 | 0:30 |
| 02 | 痛点 | 开源治理的三个断层 | 1:30 |
| 03 | 全景 | 一张图看懂 Zone A / Zone B | 1:30 |
| 04 | 能力一 | 四生态 CVE 检索，CVE 为主键 | 1:30 |
| 05 | 能力二 | 数据资产公开，人与 LLM 都可取 | 1:30 |
| 06 | 能力三 | 社区支持力度 A/B/C/D | 2:00 |
| 07 | 能力四 | 引入前门禁：四维评分 + 硬阻断 | 2:30 |
| 08 | 能力五 | 不产 SBOM 也能扫：原生依赖解析 | 1:30 |
| 09 | 能力六 | 基线 + AI 脚本 + 90% 准确率门禁 | 2:00 |
| 10 | 能力七 | 巡检：从 CVE 到应用、到工单 | 1:30 |
| 11 | 能力八 | 离线摆渡与工具链联动 | 2:00 |
| 12 | 工程亮点 | 零依赖、极简依赖面、规范先行 | 1:30 |
| 13 | 数据看板 | 可核验的产出物 | 1:00 |
| 14 | 收尾 | 三步落地 + Roadmap | 1:00 |
| A1–A4 | 备份页 | CLI 速查 / 评分模型 / FAQ / 边界 | 备用 |

---

## 01 · 封面

**主标题**：ScaBase
**副标题**：开源软件成分治理平台 —— 从「查得到漏洞」到「管得住引入」

**页面要点**

- 覆盖 Maven / npm / PyPI / Go 四生态
- 数据源：OSV（主）+ NVD（富化 CVSS / CWE）
- 双区架构：互联网采集，内网评估，**中间只有带签名的数据包**

> **口播词**
> 各位评委好，我带来的项目叫 ScaBase。市面上的开源成分分析工具大多止步于「告诉你有漏洞」，
> 而 ScaBase 想解决的是后半程：**一个组件到底该不该引入、引入之后谁受影响、什么时候必须修完。**
> 它不是一个 SaaS，而是一套可以在完全隔离的内网里跑起来的治理体系。

---

## 02 · 为什么做：开源治理的三个断层

**页面要点**（三栏对照：现状 → 后果）

| 断层 | 现状 | 后果 |
|---|---|---|
| **查得到，管不住** | 扫描报告出了 CVE 清单，但没有准入决策 | 高危组件照样进生产，KB 与 PPT 里躺灰 |
| **看漏洞，不看活不活** | 只算 CVE 数量，不看维护活跃度 / bus factor | 引入两年后停维护的组件，出事无人修 |
| **外网有数据，内网不可用** | 情报工具依赖公网 API | 隔离网里只能手工搬运，数据不可信、不可验 |

**页面上可以强调的一句话**

> 漏洞只是风险的一个切面；**这个组件三年后还有人维护吗**，同样是安全问题。

> **口播词**
> 我们复盘了行业实践里的三个断层。第三个尤其关键：越是安全要求高的单位，网络隔离越严，
> 而几乎所有开源情报工具都假设「能连公网」。结果是内网要么没有数据，要么靠人工导 Excel，
> 数据的新鲜度和完整性都无法回答。这三个断层，正是 ScaBase 的产品边界。

---

## 03 · 全景架构：一张图

```
Zone A 互联网（允许出站）                    Zone B 内网（禁止出站）
─────────────────────────                  ─────────────────────────
采集 OSV / NVD / KEV / EPSS                摄入应用 SBOM（CI 上报）
采集活跃度 / 许可证                          维护应用群组资产
        ↓                                            ↓
归一化到 PURL 事实层                          事实层（本地 inventory）
        ↓
构建 + 签名 Bundle ────── 单向摆渡 ──────▶ 验签 + 原子导入
                                                     ↓
                                          引入前门禁 / 群组评估
                                                     ↓
                                          脱敏回执 ──▶ 反向摆渡
```

**关键设计**：事实层**以 PURL 为主键**，漏洞、活跃度、许可证、应用资产四类情报挂在同一主键上；
内网侧只做评估，**不发起任何公网请求**，未知组件给出显式的「数据缺失」结论而不是静默补全。

> **口播词**
> 这张图是整个项目的骨架。请注意两个词：**PURL** 和 **单向**。
> PURL 让 Maven 的 GAV、npm 的包名、PyPI、Go Module 归一到同一个主键上，情报才能对齐；
> 单向摆渡意味着内网永远不会主动往外连，数据包带着签名进来，验签失败直接拒绝导入。

---

## 04 · 能力一：四生态漏洞检索，以 CVE 为主键

**要点**

- 生态：Maven（groupId:artifactId）/ npm / PyPI / Go Module
- 双源：**OSV 主源**（含无 CVE 编号的 GHSA）+ **NVD 富化**（标准 CVSS 评分、CWE 分类）
- 结果以 **CVE 编号为主标识**聚合：支持按 CVE 过滤、按组件 / 按 CVE 双视图、一键复制清单
- 纯静态前端：GitHub Pages 公网 + Docker 离线内网，**同一套代码两种部署**

**部署形态**

| 形态 | 载体 | 特点 |
|---|---|---|
| 公网 | GitHub Pages | push 即发布，自定义域名绑定 |
| 内网 | Docker（nginx:1.27-alpine，8080） | `SCABASE_OFFLINE=true` 切离线，环境变量注入运行时配置 |
| 离线包 | Actions 产出的 image tar | 连不上镜像仓库时 `docker load` 导入 |

> **口播词**
> 检索层做了一件容易被忽略但很关键的事：**把结果的主键从「包」换成「CVE」**。
> 同一个 CVE 在不同语言里可能对应几十个包，按 CVE 聚合后，安全运营才拿得出一份能发通知的清单。

---

## 05 · 能力二：数据资产全公开，人和 LLM 都能取

**要点**

- 全部数据以 JSON / TXT 发布，**无 API Key、无跨域限制**，可直接 WebFetch
- `llms.txt`（llmstxt.org 规范）作为 LLM 取数入口，`index.json` 提供 URL / 字节数 / sha256 / 生成时间
- 常用依赖 Top 清单：**四生态各 1000 条**，站点可浏览、过滤、一键填入查询框

**可取数据集**

| 数据集 | 内容 | 体积量级 |
|---|---|---|
| `vulns.json` | 漏洞主库，key 为 `eco|pkg|ver` | MB 级，每日更新 |
| `popular-packages.json` | 四生态 Top 1000 及热度依据 | 约 0.7 MB |
| `community-support.json` | 社区支持力度 A/B/C/D | 约 0.3 MB |
| `pkg_list_popular.txt` | 四生态各前 100，共 400 行 | 约 13 KB |
| `repo-map.json` | purl → GitHub owner/repo 映射 | 约 1 KB |

> **口播词**
> 我们把数据当成一等公民交付。每条记录都带 sha256 与生成时间，任何结论都能回溯到某一版数据快照；
> 每条社区信号都带来源链接，评审可以点开核对，而不是相信我们的打分。这一点在后面还会反复出现。

---

## 06 · 能力三：社区支持力度 A/B/C/D

**要点**

- 在「活跃度」之上追加可持续性维度：bus factor、贡献者、issue 响应、PR 周期、安全响应策略、CI、基金会/厂商背书、下游依赖数、下载量、Star
- 输出 **0–100 分 + A/B/C/D 等级**，逐条扣分有依据
- 原则：**未知即风险** —— 信号缺失按扣分处理；`archived` 直接判 D
- 多源交叉采集，每个组件记录 `sources` 归因并在页面上以徽章展示、可点击查看出处

**数据源矩阵**

| 来源 | 提供的信号 |
|---|---|
| GitHub API | archived、最近提交、近 12 月发布、贡献者、PR 周期、SECURITY.md、CI、背书组织、Star |
| deps.dev | 下游依赖项目数；全版本 `publishedAt` → 近 12 月发布数、最近发布距今天数 |
| npm registry | 月下载量；`repository` 推断仓库；packument 的 maintainers 兜底 |
| PyPI JSON | 版本级接口推断仓库，补全未登记的 PyPI 组件 |
| repo-map | 显式 purl → owner/repo 映射 |

> **口播词**
> 这一页回答的是「这个组件三年后还有人维护吗」。我们没有用黑箱模型，
> 而是一套**白盒扣分制**：每一项为什么扣分、数据来自哪个站点，都能点开核对。
> 这里有个刻意的取舍——信号缺失我们不按「还好」处理，而按扣分处理。宁可错杀，不可漏判。

---

## 07 · 能力四：引入前门禁（核心）

**四维评分模型**

| 维度 | 权重 | 主要项 |
|---|---|---|
| **V** 漏洞情报 | 35 | CVSS 归一 ≤25、KEV +8、EPSS ≤5、无修复版本 +4、暴露 >180 天 +3 |
| **M** 维护健康度 | 25 | archived/deprecated 取满；最近提交 ≤20、发布数 ≤6、维护者 ≤5、响应 ≤4 |
| **L** 合规许可 | 20 | 强传染性 20 / 商业源码 14 / 未知 12 / 弱传染性 10 / 宽松 0 |
| **B** 业务影响 | 20 | 重要性 ≤8、暴露面 ≤6、数据敏感度 ≤6、影响半径 ≤5、直接依赖 3 |

**硬阻断（直接 Deny）**

- KEV 且无修复版本
- CVSS ≥ 9.0 且无修复版本
- 许可证与用途冲突
- 已 archived / deprecated

**诚实的不确定性**：数据陈旧时按 `confidence` 把分值向维度满分上调，并**强制降级为人工复核**
（`staleness_as_deny: true` 可直接判 Deny）。

**结论五档**：Allow / Allow-with-condition / Review / Deny / Exception，每档配复审到期日。

> **口播词（建议用真实样例演示）**
> 举个真实例子：`pkg:maven/com.alibaba/fastjson@1.2.24`。
> 漏洞维度 28 分——CVSS 10.0 打底，还有两条暴露超过 180 天的 CVE 再加 3 分。
> 请注意 health 那一栏：**事实层当时没有活跃度信号，系统没有假装它健康**，
> 而是按保守值计分、把置信度标成 0、并强制结论降级为「需人工复核」。
> 这就是我们对「数据不足」的处理态度——不确定必须被显式表达出来。

---

## 08 · 能力五：不产 SBOM 也能扫

**要点**

- `scan` 直接解析**原生依赖文件**，自动归一为 PURL，区分直接 / 传递依赖
- 支持：pom.xml（属性展开 / dependencyManagement / 多模块）、build.gradle(.kts)、gradle.lockfile、package.json、package-lock.json（v1/v2/v3）、yarn.lock、pnpm-lock.yaml、requirements.txt、Pipfile.lock、poetry.lock、pyproject.toml、go.mod、go.sum、Cargo、composer、Gemfile.lock
- 保留 `version_req` 与 `pinned`（是否锁版本），`--app` 可直接生成资产台账条目
- **解析不出任何组件时以退出码 2 失败**，绝不静默放行

> **口播词**
> SBOM 在实际推广里最大的障碍是「要求业务侧先产出 SBOM」。我们把这一步省掉了：
> 直接读项目里本来就有的 pom.xml、package-lock.json，对于那些写了 `^1.2.0` 没锁版本的，
> 也会单独标出来——**没锁版本本身就是一种风险信号。**

---

## 09 · 能力六：安全基线 + AI 脚本生成 + 准确率门禁

**要点**

- 内置 **32 条**安全基线：独立部署型（Redis / Nginx / Tomcat / Kafka / ZooKeeper / Elasticsearch / Nacos / MySQL / MongoDB / RabbitMQ / Docker / Jenkins）+ 依赖引入型（fastjson / log4j / Shiro / Struts / Spring Boot Actuator / XStream / Jackson）
- AI 智能体按目标平台规范生成脚本（sreops 巡检 / codescan 规则包 / 通用 Python），**未配置或校验不通过自动回落模板引擎**，全程不发起外部请求
- 生成产物写入 `manifest.json`（sha256、生成方式、`review_required`），**须经回归校验与人工审核**
- `verify` 用标注样本集做准确率回归，默认阈值 **90%**，不达标退出码非 0 —— 把「扫描准确率 90%」落成 CI 里可执行的门槛

> **口播词**
> 这一页有个设计细节值得说：AI 生成不是噱头，它有**兜底和验收**。
> LLM 不可用自动回落到确定性模板；生成的脚本要走静态 lint，
> 再用标注样本集回归，**准确率不过 90% 流水线直接红**。我们对 AI 的态度是：可以参与，但要能被验证。

---

## 10 · 能力七：漏洞影响面巡检

**要点**

- `patrol` 按**应用**聚合：受影响组件数、KEV 数、风险分、结论分布、基线待检项
- 漏洞命中**精确到版本**，不做粗粒度全包族告警
- 自动生成**工单**：按 KEV / CVSS 定级，整改期限 critical 7 天 / high 15 / medium 30 / low 90
- **增量对比**以「应用 + 组件 + CVE」三元组输出：新增 / 未修复 / 已闭环
- 跨 ≥2 个应用共用的高危组件自动列入**共性风险**
- 群组分值 = `0.6 × 最差组件 + 0.4 × 加权平均`，避免平均值掩盖单点高危

> **口播词**
> 漏洞情报到这儿才算闭环：从「有 CVE」走到「影响哪几个应用」「给谁开工单」「几天内必须修」，
> 还有下一次巡检时能不能证明**它在收敛**。最后这条 ID 增量三元组，是我们用来做月度复盘的口径。

---

## 11 · 能力八：离线摆渡与工具链联动

**同步协议保障**

- manifest 签名（优先 ed25519，回落 HMAC-SHA256）
- 逐文件 sha256、`prev_digest` 链、seq 单调校验 → **防篡改、防回滚**
- 临时目录 + rename **原子切换**；建议每季度导入一次 snapshot 全量校准
- 导入后生成**脱敏回执**（仅含 seq、水位、计数）用于反向摆渡

**工具链对接**

| 产物 / 能力 | 用途 |
|---|---|
| SARIF 2.1.0 | 代码扫描中心 / GitHub code scanning / GitLab SAST 纳管 |
| JUnit | 流水线测试报告展示 |
| MR 评论 | 结论分布 + 组件明细 + 门禁未通过提示 |
| 退出码 | `never` / `deny` / `review` / `condition` 四档阈值 |
| DEPINFO 台账 | 资产导入与结论回传（**默认脱敏**，不含应用名 / 群组名） |

**可选扩展**：漏洞告警推送钉钉 / 企业微信；SBOM → pkg_list 自动生成；R2 + NAS 备份流水线。

> **口播词**
> 隔离网场景里，「信任」是设计出来的而不是声明出来的。我们的做法是层层校验：
> 签名验不过不导、seq 回退不导、单文件哈希不对不导，最后还要落一个脱敏回执，
> 让互联网侧知道内网拿到了什么，同时**不带走任何内网应用信息**。

---

## 12 · 工程亮点

| 亮点 | 做法 |
|---|---|
| **内网零依赖可跑** | `oss_intake/` 评分 / 同步 / 脚本生成 / 巡检路径纯 Python 标准库 |
| **自身依赖面最小** | 采集器仅 `requests`（固定 2.32.4）；前端纯 ES5 IIFE，无构建步骤、无 npm 运行时依赖 |
| **规范先行** | 全部能力用 OpenSpec 管理：`openspec/specs` 基线 + `changes/` 提案，每个 Requirement 至少一个 Scenario |
| **自查不护短** | `self-scan.yml` 用本项目自己的门禁引擎扫 `requirements.txt`，命中 Deny 即阻断；事实层没覆盖的自身依赖以 warning 显式暴露工具盲区 |
| **教学样本不污染** | `examples/deps/*.sample` 里故意挑了 fastjson 1.2.24 等漏洞版本用于演示，带后缀避免被 Dependabot 当成真实清单（曾因此凭空多出 60 条告警） |
| **机器可读优先** | `llms.txt` + `index.json`，WebFetch 直接取数，无需 Key |

> **口播词**
> 最后说说工程自律。一个做开源治理的项目，自己必须是干净的。
> 我们用自己写的门禁引擎扫自己的依赖清单，而且故意保留了带漏洞版本的教学样本，
> 但通过 `.sample` 后缀隔开——因为曾经它们被依赖图误认成真实清单，凭空刷出 60 条告警。
> 事实层覆盖不到的自身依赖，我们会以 warning 显式承认「这里有工具盲区」。

---

## 13 · 数据看板（可核验）

> 取自仓库随附的最新一次采集产出物（`scabase-fetcher/data/`），均可点击核验。

| 指标 | 数值 |
|---|---|
| 常用依赖 Top 清单 | 四生态各 **1000** 条，合计 **4000** |
| 社区支持力度已覆盖组件 | **408** 个 |
| 等级分布 | A **174** / B **121** / C **29** / D **84** |
| 信号来源覆盖 | deps.dev 396 / GitHub 247 / PyPI 98 / npm registry 90 / repo-map 8 |
| 首批热门采集清单 | 400 行（`pkg_list_popular.txt`） |
| 内置安全基线 | 32 条 |
| 扫描准确率门禁阈值 | 90% |

**一句话总结这组数字**：不是「我们算出了什么」，而是**每个数字都能点回原始出处**。

---

## 14 · 收尾：三步落地与 Roadmap

**三步落地**

1. **先看得见**：GitHub Pages 或 `docker compose up -d`，把已有组件清单灌进去，先出一张 CVE 清单
2. **再管得住**：在 CI 里挂 `gate`，把 `--fail-on deny` 变成流水线上的一道闸
3. **持续收敛**：用 `patrol` 做周期性巡检，用工单增量证明风险在下降

**Roadmap**

- 🔔 漏洞告警：新增 CVE 推送钉钉 / 企业微信
- 📄 SBOM 双向：从 SBOM 自动生成清单，并回写评估结论
- 📊 漏洞报表导出与趋势视图
- ☁️ R2 + NAS 备份流水线标准化

**结束语**

> 开源治理的难点从来不是缺一个扫描器，而是**决策不可解释、数据不可核验、内网不可用**。
> ScaBase 把这三件事做成了默认能力。

---

# 附录

## A1 · CLI 速查

```bash
# 站点 / 数据
docker compose up -d                       # 内网一键起站（8080）

# Zone A：采集 → 事实层 → 签名数据包
python scabase-fetcher/scripts/fetch_oss_health.py --pkg-list data/pkg_list.txt --out data/health.json
python scabase-fetcher/scripts/build_facts.py --facts data/facts --vulns data/vulns.json --health data/health.json
python -m oss_intake.cli bundle --facts data/facts --dataset vulns --out bundles --mode snapshot

# Zone B：验签导入 → 门禁 → 群组评估
python -m oss_intake.cli import  --facts facts --bundle bundle-vulns-0001-*.tar.gz
python -m oss_intake.cli gate    --facts facts --purl pkg:maven/com.alibaba/fastjson@1.2.24 --tier core
python -m oss_intake.cli assess  --facts facts --assets examples/assets.json --base-dir .

# 落地增强
python -m oss_intake.cli scan      --path ./payment-core --app 支付核心 --tier core
python -m oss_intake.cli patrol    --facts facts --assets assets.json --state state.json --tickets tickets.json
python -m oss_intake.cli genscript --component redis --target sreops --out-dir scripts/sreops
python -m oss_intake.cli verify    --cases examples/accuracy-cases.json --threshold 0.9
python -m oss_intake.cli depinfo   --import depinfo-export.json --out assets.json

# 发布数据到 GitHub Packages
python -m oss_intake.cli release --out build/scabase-data
python -m oss_intake.cli verify-release --pkg build/scabase-data
```

## A2 · 三通道数据包

| 通道 | 坐标 |
|---|---|
| npm | `@scabase/data`（`https://npm.pkg.github.com`） |
| maven | `cn.scabase:scabase-data`（`https://maven.pkg.github.com/scabase/scabase.github.io`） |
| docker | `ghcr.io/scabase/scabase-data`（`docker run --rm <img> \| tar -x`） |

三通道共用同一份 staging 与同一个 CalVer 版本号，因此版本号与文件哈希必然一致；
`content_digest` 决定是否跳过发布。**外发红线**：只取 `vulns / health / license / kev`，
`inventory / outbox / state.json` 禁止出包。

## A3 · 术语表

| 术语 | 含义 |
|---|---|
| PURL | Package URL（`pkg:maven/g/a@v`），跨生态统一组件坐标，项目主事实键 |
| GAV | Maven 坐标 `groupId:artifactId:version` |
| 事实层 | 以 PURL 为主键、按数据源分片存储的规范化情报数据集 |
| Bundle | 一次离线摆渡的数据包，含 manifest、签名与增量链 |
| App Group | 内网应用群组，风险评估的汇报单元 |
| Intake Gate | 开源引入前评估门禁，输出 Allow / condition / Deny / Exception |

## A4 · 预判提问

**Q：为什么不直接接公网 API，而要做离线摆渡？**
因为目标场景是禁止出站的内网。摆渡不是妥协措施，而是把「信任」工程化：签名、seq 链、逐文件哈希、原子导入，每一步都可验证。

**Q：数据陈旧时会不会误判？**
会，所以我们不掩盖。置信度低于阈值时，分值向保守方向调整并把结论强制降级为人工复核；策略里也可以配 `staleness_as_deny: true` 直接判 Deny。

**Q：和商用 SCA 的差异？**
商用工具强在检出广度，ScaBase 强在**内网可用、决策可解释、治理可闭环**：从引入前门禁到巡检工单到增量收敛，全部在同一套 PURL 主键上完成，且纯 Python 标准库零依赖落地。

**Q：AI 生成脚本会不会不稳定？**
有三重约束：不对外部发起请求、LLM 失败自动回落确定性模板、输出必须 lint + 90% 准确率回归，通过后才允许上线。

---

*本讲稿对应产物：Markdown 讲稿 / HTML 演示文稿 / 画布 PPT 设计稿，三者同一叙事结构。*
