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
  fetch_oss_health.py  活跃度采集（deps.dev / GitHub / registry）
  fetch_kev_epss.py    KEV / EPSS 采集与富化
examples/              示例 SBOM、资产、策略、许可证、依赖文件、基线与样本集
tests/                 单测与端到端冒烟
```

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

覆盖范围：PURL 归一、SBOM 摄入、评分边界与硬阻断、置信度降级、
签名/回滚/篡改/链断裂拒绝、原子导入、回执脱敏、群组聚合，以及一条端到端冒烟。

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

## 11. 社区支持力度评价

在活跃度（提交/发布）之上追加可持续性维度：bus factor、贡献者、issue 响应、PR 周期、
安全响应策略、CI、基金会/厂商背书、下游依赖数、下载量、Star。
输出 0-100 分与 A/B/C/D 等级，每项扣分都有依据，缺失信号按「未知即风险」扣分。

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

# 生成 e运维巡检脚本 / 代码扫描中心规则包 / 通用 Python 巡检脚本
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
# depinfo 台账导入 → 资产模型
python -m oss_intake.cli depinfo --import examples/depinfo-export.json --out reports/assets.json

# 评估结论回传（默认脱敏：不含应用名/群组名）
python -m oss_intake.cli depinfo --results reports/gate.json --out reports/depinfo-result.json
# 已配置 SCABASE_depinfo_URL / SCABASE_depinfo_TOKEN 时可加 --push 直接推送

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
