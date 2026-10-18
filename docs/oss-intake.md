# 开源引入评估 · 设计与操作手册

本手册对应 OpenSpec 变更 `add-oss-intake-evaluation`，规范文件位于 `openspec/`：

- 现状基线：`openspec/specs/`（`vuln-lookup`、`vuln-data-collection`、`offline-delivery`）
- 变更提案：`openspec/changes/add-oss-intake-evaluation/`（proposal / design / tasks / 各能力 delta）

## 1. 体系概览

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

核心设计：**事实层以 PURL 为主键**，漏洞、活跃度、许可证、应用资产四类情报挂载在同一主键上；
内网侧只做评估，不发起任何公网请求。

## 2. 目录结构

```
oss_intake/            评估引擎（零第三方依赖）
  purl.py              PURL 归一化与 GAV 投影
  sbom.py              CycloneDX / SPDX / mvn tree / lock 摄入
  depfile.py           原生依赖文件解析（pom/package.json/requirements/go.mod …）
  facts.py             事实层分片读写与置信度
  policy.py            权重、阈值、许可证合规矩阵、社区准入等级
  scoring.py           四维评分 + 硬阻断 + 决策
  community.py         社区支持力度评价（A/B/C/D）
  baseline.py          安全配置基线目录 + 检查执行引擎
  scriptgen.py         脚本生成（模板 / LLM 增强 / 静态检查）
  verify.py            生成脚本准确率回归校验
  patrol.py            漏洞影响巡检 / 工单 / 增量对比
  assets.py            应用群组资产与影响半径（支持 SBOM / GAV / PURL）
  assessment.py        群组风险聚合与共性风险
  sync.py              数据包构建 / 签名 / 导入 / 回执
  report.py            JSON / Markdown 报告
  cli.py               命令行入口
  integrations/        工具链对接
    depinfo.py            depinfo 台账导入与结论回传
    cicd.py            SARIF / JUnit / MR 评论 / 退出码
scabase-fetcher/scripts/
  build_facts.py       采集产物 → 事实层
  fetch_oss_health.py  社区支持力度与活跃度采集（deps.dev / GitHub / registry）
  fetch_kev_epss.py    KEV / EPSS 采集与富化
  community_report.py  社区支持力度汇总报告（0-100 分 + A/B/C/D）
  gen_popular_packages.py  常用依赖 Top 清单生成（四生态各 1000）
  gen_data_index.py    机器可读数据索引 index.json 生成（LLM WebFetch 入口）
  fetch_software.py    应用 / 基础设施软件漏洞与健康度采集（NVD CPE + GitHub）
.github/workflows/
  community-health.yml 每日采集社区支持力度与活跃度信号
  software-collect.yml 每日采集软件维度漏洞与健康度（nginx / 7-Zip / Kubernetes 等）
  self-scan.yml        仓库自身依赖面自查（用本项目门禁引擎扫 requirements.txt）
examples/
  deps/                原生依赖文件样本（*.sample 为教学样本，同名文件为零依赖空壳）
tests/                 单测与端到端冒烟
```

### 2.1 仓库自身的依赖面

本仓库刻意把依赖面压到最小：

| 范围 | 依赖 |
| --- | --- |
| `oss_intake/`（评分 / 同步 / 脚本生成 / 巡检） | **零第三方依赖**，纯 Python 标准库，保证无公网出口的内网可直接运行 |
| `scabase-fetcher/`（采集器） | 仅 `requests`（见 `scabase-fetcher/requirements.txt`，固定 `2.32.4`） |
| 前端 | 纯 ES5 IIFE，无构建步骤、无 npm 运行时依赖 |

因此 Dependabot 只需关注 `github-actions` 与 `pip` 两个生态（见 `.github/dependabot.yml`）。

`examples/deps/` 下的教学样本统一带 `.sample` 后缀（`pom.xml.sample`、`package.json.sample` …），
`depfile.classify()` 会先经 `canonical_name()` 剥掉后缀再识别。
**这样做是为了不让故意挑选的漏洞样本版本（fastjson 1.2.24、log4j 2.14.1、axios 0.21.1 …）
被 Dependabot / 依赖图当成真实清单**——本仓库曾因此凭空多出 60 条安全告警。
同名文件（`pom.xml` 等）是零依赖空壳，只为让仓库自身依赖面保持干净。

`.github/workflows/self-scan.yml` 会在 push / 每周执行一次**自查**：
用本项目自己的门禁引擎扫描 `scabase-fetcher/requirements.txt`，
命中 `Deny` 即阻断；事实层没覆盖到的自身依赖会以 `::warning::` 显式暴露（工具盲区）。

## 3. 互联网侧（Zone A）

```bash
# 1) 采集活跃度（可用 --no-network 跳过，或用 --fixtures 离线回放）
python scabase-fetcher/scripts/fetch_oss_health.py \
  --pkg-list scabase-fetcher/data/pkg_list.txt \
  --out scabase-fetcher/data/health.json

# 2) 采集 KEV / EPSS 并富化事实层（失败自动降级，保留上次数据）
python scabase-fetcher/scripts/fetch_kev_epss.py --facts scabase-fetcher/data/facts

# 3) 写入事实层
python scabase-fetcher/scripts/build_facts.py \
  --facts scabase-fetcher/data/facts \
  --vulns scabase-fetcher/data/vulns.json \
  --health scabase-fetcher/data/health.json \
  --license examples/license.json

# 4) 构建并签名数据包（密钥走环境变量 SCABASE_SYNC_KEY）
export SCABASE_SYNC_KEY='<从密钥管理获取>'
python -m oss_intake.cli bundle --facts scabase-fetcher/data/facts \
  --dataset vulns --out bundles --mode snapshot
```

数据包命名 `bundle-<dataset>-<seq>-<YYYYMMDD>.tar.gz`，内含 `manifest.json` 与 `data/`。
签名算法优先 ed25519（环境具备 `cryptography` 时自动启用），否则回落 HMAC-SHA256。

## 4. 摆渡与内网导入（Zone B）

```bash
# 把数据包放入摆渡目录后导入（验签 + 防回滚 + 逐文件哈希校验 + 原子切换）
python -m oss_intake.cli import --facts intranet-data/facts \
  --bundle intranet-data/ferry/bundle-vulns-0001-20261014.tar.gz

# 查看数据水位与置信度
python -m oss_intake.cli confidence --facts intranet-data/facts
```

导入成功后会在 `facts/outbox/` 生成**脱敏回执**（仅含 seq、水位、计数），可用于反向摆渡。

容器化场景直接用 compose 里的 `oss-intake` 服务，它会循环扫描摆渡目录并定期生成群组报告：

```bash
mkdir -p intranet-data/{facts,ferry,reports}
docker compose up -d
```

## 5. 引入前评估与 CI 门禁

```bash
# 单组件引入前评估（附业务上下文）
python -m oss_intake.cli gate \
  --facts intranet-data/facts \
  --purl pkg:maven/com.alibaba/fastjson@1.2.24 \
  --tier core --exposure internet --data-sensitivity high \
  --md reports/fastjson.md --fail-on deny

# 整份 SBOM 的 CI 门禁（存在 Deny 组件时退出码非 0）
python -m oss_intake.cli gate --facts intranet-data/facts \
  --sbom examples/sample-app.cdx.json --fail-on deny
```

`--fail-on` 取值：`never`（只看报告）/ `deny` / `review` / `condition`。

## 6. 应用群组评估

```bash
python -m oss_intake.cli inventory --facts intranet-data/facts \
  --assets examples/assets.json --base-dir .

python -m oss_intake.cli assess --facts intranet-data/facts \
  --assets examples/assets.json --base-dir . --group 支付群组 \
  --md reports/group.md
```

群组分值 `0.6 × 最差组件 + 0.4 × 加权平均`，避免平均值掩盖单点高危；
同一组件出现在 ≥3 个应用且评分 ≥55 时列入**共性风险**。

## 7. 评分模型

| 维度 | 权重 | 主要扣分/加分项 |
| --- | --- | --- |
| 漏洞情报 V | 35 | CVSS 归一 ≤25、KEV +8、EPSS ≤5、无修复版本 +4、暴露 >180 天 +3 |
| 维护健康度 M | 25 | archived/deprecated 取满；最近提交 ≤20、发布数 ≤6、维护者 ≤5、响应 ≤4 |
| 合规许可 L | 20 | 强传染性 20 / 商业源码 14 / 未知 12 / 弱传染性 10 / 宽松 0 |
| 业务影响 B | 20 | 重要性 ≤8、暴露面 ≤6、数据敏感度 ≤6、影响半径 ≤5、直接依赖 3 |

硬阻断：KEV 且无修复、CVSS ≥9.0 且无修复、许可证与用途冲突、已 archived/deprecated。
数据陈旧时按 `confidence` 把分值向维度满分上调，并强制降级为人工复核
（策略 `staleness_as_deny: true` 时直接判 Deny）。

策略文件示例见 `examples/policy.json`，未覆盖项回落到 `oss_intake/policy.py` 默认值。

## 8. 同步协议字段

```json
{
  "schema": "scabase-bundle/v1",
  "dataset": "vulns",
  "seq": 1234,
  "mode": "delta|snapshot",
  "generated_at": "2026-10-14T02:00:00Z",
  "source_watermark": { "dataset_seq": 12, "generated_at": "...", "degraded": false },
  "prev_digest": "sha256:...",
  "files": [ { "path": "data/maven.json", "sha256": "...", "size": 1024, "op": "upsert|delete" } ],
  "signature": { "algo": "ed25519|hmac-sha256", "keyid": "scabase-sync", "value": "..." }
}
```

保障机制：逐文件 sha256、manifest 签名、`prev_digest` 链、seq 单调校验、临时目录 + rename 原子切换。
建议每季度导入一次 `snapshot` 全量包做校准。

## 9. 测试

```bash
python -m unittest discover -s tests
```

覆盖范围：PURL 归一、SBOM 摄入、原生依赖文件解析（含 `.sample` 后缀识别与空壳清单断言）、
评分边界与硬阻断、置信度降级、社区支持力度、基线算子、脚本 lint、准确率回归、
签名/回滚/篡改/链断裂拒绝、原子导入、回执脱敏、群组聚合、巡检工单与增量、
DEPINFO / CICD 对接，以及一条端到端冒烟。

---

# 第二部分 · 落地增强（行业开源治理）

## 10. 引入阶段依赖关系自动化分析

无需先产出 SBOM，直接解析原生依赖文件：

```bash
# 扫描整个仓库的依赖文件（自动跳过 node_modules / target / build 等目录）
python -m oss_intake.cli scan --path ./payment-core --app 支付核心 \
  --group 支付群组 --tier core --exposure internet --data-sensitivity high \
  --json reports/scan.json --md reports/scan.md
```

支持格式：`pom.xml`（属性展开 / dependencyManagement 继承 / 多模块）、`build.gradle(.kts)`、
`gradle.lockfile`、`package.json`、`package-lock.json`（v1/v2/v3）、`yarn.lock`、
`pnpm-lock.yaml`、`requirements.txt`、`Pipfile.lock`、`poetry.lock`、`pyproject.toml`、
`go.mod`、`go.sum`、`Cargo.lock/toml`、`composer.json/lock`、`Gemfile.lock`。

输出区分直接/传递依赖，并保留 `version_req` 与 `pinned`（是否锁定具体版本）；
`--app` 可直接生成含 `purls` / `gavs` 的资产台账条目。

`gate --sbom` 同样接受原生依赖文件（优先走 `depfile`），因此可以直接对
`pom.xml` / `package.json` / `requirements.txt` 做门禁；解析不出任何组件时会以退出码 2 失败，
不会静默放行。教学样本带 `.sample` 后缀（见 2.1 节），`classify()` 会自动剥掉后缀识别。

## 11. 社区支持力度评价

在活跃度（提交/发布）之上追加可持续性维度：bus factor、贡献者、issue 响应、PR 周期、
安全响应策略、CI、基金会/厂商背书、下游依赖数、下载量、Star。
输出 0-100 分与 A/B/C/D 等级，每项扣分都有依据，缺失信号按「未知即风险」扣分。

采集侧（`scabase-fetcher/scripts/fetch_oss_health.py`）按生态组合多数据源，
每个组件在 `health.json` 中记录 `sources` 列表说明信号构成（前端卡片同步展示）：

| 来源 | 提供的信号 |
| --- | --- |
| GitHub API | archived、最近提交、近 12 月发布、贡献者、PR 合并周期、SECURITY.md、CI、背后组织、Star |
| deps.dev | 下游依赖项目数；全版本 `publishedAt` → **近 12 月发布数**、最近发布距今天数（覆盖无 GitHub 仓库的 Maven / PyPI / Go 组件） |
| npm registry | 月下载量；`repository` 字段推断 GitHub 仓库；packument 的 `maintainers` 与发布时间（**仅在无 GitHub 信号时兜底**，超 4MB 的大包放弃） |
| PyPI JSON | 版本级接口（约 10KB）的 `project_urls` / `home_page` 推断 GitHub 仓库，补全 repo-map 未登记的 PyPI 组件；整包接口的发布时间作为兜底 |
| repo-map | 显式 purl → owner/repo 映射（非 Go 生态的主要仓库来源） |

```bash
python -m oss_intake.cli gate --facts intranet-data/facts \
  --purl pkg:maven/com.alibaba/fastjson@1.2.24 --md reports/fastjson.md
```

报告中会包含「社区支持力度：D 级（5/100）— 社区支撑不足或已停止维护…」及逐项依据。
策略可在 `policy.json` 中配置硬阻断：

```json
{ "community_deny_grades": ["D"] }
```

## 12. 安全配置基线与 AI 脚本生成

```bash
# 查看基线目录（可按组件过滤）
python -m oss_intake.cli baseline --component redis --md reports/baseline.md

# 生成 SRE 运维平台巡检脚本 / 代码扫描中心规则包 / 通用 Python 巡检脚本
python -m oss_intake.cli genscript --component redis --target sreops --out-dir scripts/sreops
python -m oss_intake.cli genscript --rule redis-requirepass fastjson-autotype \
  --target codescan --out-dir scripts/codescan
python -m oss_intake.cli genscript --target python --out-dir scripts/python

# 准确率回归校验（默认阈值 90%，不达标退出码非 0）
python -m oss_intake.cli verify --cases examples/accuracy-cases.json --threshold 0.9 \
  --md reports/accuracy.md
```

- 基线目录内置 32 条，覆盖独立部署型（Redis、Nginx、Tomcat、Kafka、ZooKeeper、
  Elasticsearch、Nacos、MySQL、MongoDB、RabbitMQ、Docker、Jenkins）与依赖引入型
  （fastjson、log4j、Shiro、Struts、Spring Boot Actuator、XStream、Jackson）。
- 可维护自有目录：`examples/baseline-catalog.json` 为范式，按基线编号覆盖或追加。
- AI 智能体增强：配置 `SCABASE_LLM_ENDPOINT`（可选 `SCABASE_LLM_API_KEY`、`SCABASE_LLM_MODEL`）
  后由大模型按平台规范优化脚本；未配置或校验不通过时自动回落模板引擎，全程不发起外部请求。
- 生成产物一律写入 `manifest.json`，记录 sha256、生成方式（template/llm）与 `review_required`，
  须经回归校验与人工审核后方可上线。

## 13. 漏洞影响范围巡检

```bash
# 全量巡检：按应用聚合受影响组件、基线待检项，输出工单与增量对比
python -m oss_intake.cli patrol --facts intranet-data/facts --assets examples/assets.json \
  --baseline examples/baseline-catalog.json --state intranet-data/patrol-state.json \
  --json reports/patrol.json --md reports/patrol.md --tickets reports/tickets.json
```

- 漏洞命中精确到版本；每个应用输出受影响组件数、KEV 数、风险分、结论分布、基线待检项。
- 工单按严重级别（KEV/CVSS）排序，整改期限 critical 7 天 / high 15 / medium 30 / low 90。
- 增量对比以「应用 + 组件 + CVE」三元组为单位，输出新增 / 未修复 / 已闭环。
- 跨 ≥2 个应用共用的高危组件列入共性风险。

## 14. 工具链对接

```bash
# DEPINFO 台账导入 → 资产模型
python -m oss_intake.cli depinfo --import examples/depinfo-export.json --out reports/assets.json

# 评估结论回传（默认脱敏：不含应用名/群组名）
python -m oss_intake.cli depinfo --results reports/gate.json --out reports/depinfo-result.json
# 已配置 SCABASE_DEPINFO_URL / SCABASE_DEPINFO_TOKEN 时可加 --push 直接推送

# CICD 产物导出
python -m oss_intake.cli gate --facts intranet-data/facts --sbom app.cdx.json \
  --fail-on deny --sarif reports/gate.sarif --junit reports/gate.xml --comment reports/mr.md
```

| 产物 | 用途 |
| --- | --- |
| `--sarif` | 代码扫描中心 / GitHub code scanning / GitLab SAST 直接纳管（Deny→error、Review→warning） |
| `--junit` | 流水线测试报告展示，命中阈值的组件计为 failure |
| `--comment` | MR/PR 评论：结论分布 + 组件明细 + 门禁未通过提示 |
| 退出码 | `never` / `deny` / `review` / `condition` 四档阈值 |

## 15. 社区支持力度与活跃度采集（CI）

由 `.github/workflows/community-health.yml` 每日执行（也可手动触发），产出健康度数据集与汇总报告：

```bash
# 本地等价操作
export GITHUB_TOKEN='<可选，提高限流阈值>'
python scabase-fetcher/scripts/fetch_oss_health.py \
  --pkg-list scabase-fetcher/data/pkg_list.txt \
  --repo-map scabase-fetcher/data/repo-map.json \
  --out scabase-fetcher/data/health.json

# 汇总为社区支持力度报告（0-100 分 + A/B/C/D 等级）
# JSON 落在 data/ 下随站点发布（网页「开源软件支持力度和活跃度」tab 读取该文件），
# Markdown 仅用于归档 / Step Summary
python scabase-fetcher/scripts/community_report.py \
  --health scabase-fetcher/data/health.json \
  --md reports/community-support.md \
  --json scabase-fetcher/data/community-support.json

# 写入事实层 health 数据集，供摆渡到内网
python scabase-fetcher/scripts/build_facts.py \
  --facts scabase-fetcher/data/facts --health scabase-fetcher/data/health.json
```

采集的数据来源（每个组件的实际构成记录在 `health.json` 的 `sources` 字段）：

| 来源 | 信号 |
| --- | --- |
| GitHub API | 最近提交、近 12 月发布、贡献者数、PR 合并周期、`SECURITY.md`、`.github/workflows`（CI）、archived、星标、背后组织（基金会/厂商/组织/个人） |
| deps.dev | 下游依赖项目数、全版本发布时间（→ 近 12 月发布数、最近发布距今天数） |
| npm registry | 月下载量、`repository` 推断仓库、packument 的 maintainers 与发布时间（无 GitHub 信号时兜底） |
| PyPI JSON | `project_urls` 推断仓库、发布时间（兜底） |

- 组件清单格式 `ecosystem|package|version`，见 `scabase-fetcher/data/pkg_list.txt`；
  `community-health.yml` 还会额外采集 `pkg_list_popular.txt`（常用依赖四生态各 Top 100），
  两份结果合并写入 `health.json`。
- 仓库推断优先级：`repo-map.json` 显式映射 → go module 路径 → npm registry `repository`
  → **PyPI `project_urls`**；都失败时组件仍保留 deps.dev 与 registry 信号，
  按「未知即风险」对缺失的治理类信号扣分，不会被静默当作满分。
- 任一来源失败只降级，不中断整批；未配置 `GITHUB_TOKEN` 时仍可运行（限流更严格）。
- 产物（`health.json` + 社区支持力度报告）会上传为 workflow artifact，并写入 Step Summary；
  报告的「数据来源覆盖」章节统计每个来源实际覆盖的组件数。
- **人工核对**：`community_report.py` 为每个组件生成 `repo` / `deps_dev` / `registry`
  三个链接字段（GitHub 仓库、deps.dev 包页面、生态注册表页面）。前端健康度卡片的
  「数据来源」徽章据此渲染为可点击链接（无链接信息时降级为纯文本徽章），
  Markdown 报告的「数据来源」列同样带链接，点击即可跳转原始出处核对。
- **旧数据兜底**：报告数据尚未带上述字段时（如 CI 还用旧版脚本生成），前端会从
  组件 `purl` 直接推导 deps.dev / 注册表链接，并从 `repo-map.json` 补 GitHub 链接，
  保证来源徽章在任何数据版本下都可点击；`repo-map.json` 体积很小（KB 级），
  随健康报告同目录加载，失败时静默降级。

## 16. 常用依赖 Top 清单（站点示例）

`scabase-fetcher/scripts/gen_popular_packages.py` 维护 **Maven / npm / PyPI / Go 四个生态
各 Top 1000** 的高频依赖，版本号取刷新时刻的最新稳定发布版本，供站点「常用依赖 Top 清单」
面板浏览、快速填入示例与健康度采集复用。

各生态排序依据（`rank_basis` 字段会写入 JSON，前端「排序依据」可查）：

| 生态 | 数据源 | 排序信号 |
| --- | --- | --- |
| npm | npm registry 搜索接口（`/-/v1/search`，392 个关键词采样合并） | 近一周下载量 |
| PyPI | `top-pypi-packages`（hugovk.github.io，PyPI 官方下载量近 30 天榜） | 近 30 天下载量 |
| Maven | deps.dev `GetRequirements` 依赖图一层展开 + 人工高频构件种子 | 公开依赖项目数（Maven Central 不公开构件级下载量） |
| Go | GitHub 搜索 `language:go` 按 Star 排序 + deps.dev `GetProjectPackageVersions` 映射 | Star 数（辅以生态核心模块种子） |

```bash
# 联网刷新四个生态（默认每生态 1000 条）
python scabase-fetcher/scripts/gen_popular_packages.py --refresh

# 只补某一个生态（其余沿用已有 JSON，适合 npm 数据刷新失败后重试）
python scabase-fetcher/scripts/gen_popular_packages.py --refresh --only npm --top 1000

# 离线：直接用已有 JSON 重新生成 pkg_list（CI 内就用这个姿势）
python scabase-fetcher/scripts/gen_popular_packages.py \
  --json scabase-fetcher/data/popular-packages.json \
  --txt scabase-fetcher/data/pkg_list_popular.txt
```

| 产物 | 用途 |
| --- | --- |
| `data/popular-packages.json` | 前端「常用依赖 Top 清单」四个生态 tab 的数据源（每生态 1000 项，含版本/描述/热度元数据） |
| `data/pkg_list_popular.txt` | `pkg_list` 格式，每生态取前 `--txt-top`（默认 100）条共 400 行，供 `community-health.yml` 第二批健康度采集 |

- 版本比较自研 `version_key()` / `pick_latest_stable()`，覆盖 Maven（`7.1.0-M2`）、
  PyPI（`1.0.0.post1`）、Go（`v1.11.1`、`+incompatible`、伪版本）三种形态；
  无法解析的版本退化为字符串排序，预发布版不作为首选。
- `--txt-top` 是采集量与数据完整度的平衡：全量 4000 条会显著拖长
  `community-health.yml` 的 GitHub API 配额消耗，CI 只取每生态前 100。

前端消费方式：

- **漏洞查询**：清单支持按名称过滤、`Top N` 一键填入（10/50/100/1000），填入为追加语义；
- **支持力度与活跃度**：健康度是组件级评估，允许不带版本；未写版本时按同名组件匹配，
  并在卡片上标注报告实际采用的版本；未被 `pkg_list*.txt` 收录的组件单独列出，可一键复制回清单。

## 17. 机器可读数据（LLM / WebFetch 取数）

站点为纯静态架构，全部数据以文件形式公开，大模型或外部工具通过 WebFetch
即可直接获取，无需 API Key：

- **入口**：`https://scabase.roweb.cn/llms.txt`（llmstxt.org 规范）：站点说明、
  取数步骤、各数据集 schema 与示例；
- **数据索引**：`scabase-fetcher/data/index.json`：每个数据集的 URL、字节数、
  sha256、内嵌 `generated_at` 与 `llm_hint`，由 `gen_data_index.py` 重新生成
  （pages.yml 每次部署刷新；三个数据采集工作流 update-vuln / community-health /
  software-collect 提交数据时同步刷新仓库副本，数据无变化时撤销时间戳刷新，
  字节数与哈希始终与实际产物一致）；
- **漏洞主库**：`vulns.json` 以 `ecosystem|package|version` 为 key 精确查找；
  反查 CVE 需遍历 key 并匹配 `enriched[].osv.id` / `aliases`。

```bash
# 本地重新生成索引（CI 与镜像构建同款）
python scabase-fetcher/scripts/gen_data_index.py \
  --data scabase-fetcher/data --out scabase-fetcher/data/index.json
```

发布面（GitHub Pages 与 Docker 镜像保持一致）：

| 路径 | 内容 |
| --- | --- |
| `/llms.txt` | LLM 取数入口 |
| `/scabase-fetcher/data/index.json` | 机器可读数据索引 |
| `/scabase-fetcher/data/vulns.json` | 漏洞库（OSV + NVD） |
| `/scabase-fetcher/data/popular-packages.json` | 常用依赖 Top 清单（四生态各 1000） |
| `/scabase-fetcher/data/community-support.json` | 社区支持力度报告 |
| `/scabase-fetcher/data/pkg_list.txt` / `pkg_list_popular.txt` | 组件清单（`ecosystem\|package\|version`） |
| `/scabase-fetcher/data/repo-map.json` | purl → GitHub 仓库映射 |
| `/scabase-fetcher/data/software-vulns.json` | 软件漏洞库（nginx / 7-Zip / Kubernetes 等） |
| `/scabase-fetcher/data/software-support.json` | 软件健康度报告 |

## 18. 应用 / 基础设施软件维度（nginx / 7-Zip / Kubernetes 等）

与「库」维度（purl 生态）平行，站点新增按产品管理的服务器软件维度，由
`scabase-fetcher/scripts/fetch_software.py` 采集（工作流 `software-collect.yml`，
每日 03:43 UTC，与 community-health 错开）：

- **漏洞**：NVD CVE API 2.0 按 `keywordSearch` 拉取候选，本地用 CPE
  `vendor:product` 前缀精确过滤——注意 nginx 的 CPE vendor 已是 `f5`
  （F5 收购后迁移），MySQL 需同时收录 `oracle:mysql` 与 `mysql:mysql`；
  每个 CVE 提取 CVSS、影响版本区间（`versionStart/EndIncluding/Excluding`）、
  CWE 与参考链接。
- **健康度**：复用 GitHub 信号（Star、归档、发布节奏、背后组织），
  评分走 `oss_intake.community`；版本号取最新 GitHub release tag
  （兼容 `v1.24.0` / `release-1.24.0` / `openssl-4.0.3` / `curl-8_23_0` 等形态）。
- **统一查询清单**：`SOFTWARE` 清单（65 个，13 个分类）是两个页签共用的唯一
  查询清单。产物 `software-vulns.json` 的 `software` 数组**覆盖全清单**——
  未采集的软件以 `cve_count: 0` 占位（含 name / category / aliases / cpe / repo），
  前端据此把「查无此项」变成「未采集」卡（附 GitHub 仓库链接供人工核对），
  而不是消失在库维度里。离线重建（不带 `--refresh`）会自动补齐占位而不丢旧数据。
- **查询语法**：输入框直接写 `nginx 1.24.0` / `nginx@1.24.0` / `k8s` / `7zip`，
  别名表见 `SOFTWARE`（含 k8s、zk、7zip、httpd、pg 等常见缩写）；
  支持**多词名与别名最长匹配**（`Apache HTTP Server` / `docker engine` /
  `linux kernel` / `node.js 18`），`@` / `:` / 空格 / `-` 均可分隔版本；
  带版本时按 CPE 区间过滤受影响 CVE，不带版本展示全部。
  库坐标（`maven|g:a:v`、`g:a:v`）不会被误判成软件名。
- **前端**：软件结果渲染在独立区域（漏洞 `#softwareResults`、健康度
  `#softwareHealth`），CVE 编号链接 NVD 详情页，健康度卡片复用库维度渲染
  （含可点击的来源徽章）；与库维度输入可混合（同一行一个条目）。
  两个页签的「常用软件查询」chips 为同一份全量清单，按分类分组，
  暗色 chips 表示数据采集中。软件数据加载窗口中点查询会挂起，
  到位后自动补渲染（不会把 `nginx` 误报成无法识别）。
- **NVD 限流**：无 `NVD_API_KEY` 时 5 次/30 秒（脚本内置 6.5s 间隔，
  全量约 8 分钟）；配置仓库 Secret `NVD_API_KEY` 后自动提速。

```bash
# 全量采集
python scabase-fetcher/scripts/fetch_software.py --refresh

# 只刷新指定软件（未选中的软件沿用旧数据，不会从产物中丢失）
python scabase-fetcher/scripts/fetch_software.py --refresh --only nginx --only redis

# 离线重建：不联网，用旧数据 + 全清单占位重新生成产物（前端立即可查全清单）
python scabase-fetcher/scripts/fetch_software.py
```

产物：`software-vulns.json`（全清单 → CVE 列表，未采集为 0 占位）与
`software-support.json`（已采集软件的健康度评分卡，结构与 community-support.json
对齐，前端复用同一套渲染）。
