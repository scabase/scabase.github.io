# ScaBase 项目长期记忆

## 项目定位
纯静态 SCA 漏洞查询站（GitHub Pages: scabase.roweb.cn / 内网 Docker 部署）。
数据源 OSV + NVD，漏洞库由 `scabase-fetcher` 的 GitHub Action 每日采集生成
`scabase-fetcher/data/vulns.json`（结构：`{"eco|pkg|ver": {osv_raw, enriched:[{osv,nvd}]}}`）。
前端结果**以 CVE 编号为主键**展示（见 2026-10-13 日志）。

## 部署约定
- GitHub Pages：`.github/workflows/pages.yml`（push main 时组装 `_site` 发布）；`CNAME` 为 scabase.roweb.cn。
- Docker 内网：`nginx:1.27-alpine`，**监听 8080**，`/healthz` 健康检查；
  运行时配置由 `docker/10-env-config.sh` 写 `assets/config.js`，
  关键环境变量 `SCABASE_OFFLINE`（离线内网设 true）、`SCABASE_OSV_API`（内网 OSV 代理）。
- 镜像 CI：`.github/workflows/docker.yml`，推阿里云 `roweb/scabase`，并产出离线 tar 产物。
- 本机 buildx 默认 builder 在沙箱下会失败，本地构建用 `DOCKER_BUILDKIT=0 docker build`。

## 开源引入评估（2026-10-14 新增）
- 规范用 OpenSpec 管理：`openspec/`（基线 specs + `changes/` 提案）。
  CLI 未全局安装，用 `/Users/block/.workbuddy/binaries/node/workspace/node_modules/.bin/openspec`。
  校验规则：每个 Requirement 至少一个 Scenario；MODIFIED 必须已存在于基线且需抄回原有 scenario。
- 引擎 `oss_intake/`（Python 标准库，零第三方依赖）：PURL 主键事实层
  `facts/<dataset>/<eco>.json`；评分四维 V35/M25/L20/B20；同步 bundle 带签名与 seq 链。
- CLI：`python -m oss_intake.cli {inventory|scan|gate|assess|patrol|baseline|genscript|verify|depinfo|bundle|import|confidence}`。
- 未实现：前端评估台页面（intake.html），在 openspec change 的 tasks Phase 5。

## 落地增强（2026-10-15 新增，行业场景）
- 命名约定：**DEPINFO**（依赖台账系统，原 SPMS）、**sreops**（SRE 运维平台，原 eops）。
  环境变量 `SCABASE_DEPINFO_URL` / `SCABASE_DEPINFO_TOKEN`。
- `depfile.py` 解析原生依赖文件（pom/gradle/npm×4/pypi×4/go/cargo/composer/gem），
  输出 PURL + `version_req` + `pinned`；npm scope 存为无 `@` 的 namespace（`pkg:npm/babel/core@x`）。
- `community.py`：社区支持力度 A/B/C/D，缺失信号按未知即风险扣分，archived → D。
- `baseline.py`：32 条声明式基线；配置项未声明时 set/eq/contains/regex 按空值判 FAIL，其余 UNKNOWN。
- `scriptgen.py`：三目标脚本（sreops sh / codescan yaml+py / 通用 py），模板 + 可选 LLM
  （`SCABASE_LLM_ENDPOINT`，失败回落模板）+ lint；FORBIDDEN 不能含 shutdown/reboot（会误伤描述文字）。
- `verify.py`：准确率回归默认阈值 0.9，UNKNOWN 计入漏检；样本集 `examples/accuracy-cases.json`。
- `patrol.py`：应用维度巡检 + 工单 + 增量（应用+PURL+CVE 三元组）+ 共性风险（≥2 应用）。
- `integrations/depinfo.py`：台账导入三形态（purl/gav/eco+group+artifact+version），回传默认脱敏；
  `integrations/cicd.py`：SARIF 2.1.0 / JUnit / MR 评论 / 四档退出码。
- 资产模型 app 支持 `gavs` / `purls`（DEPINFO 台账，无 SBOM 文件）。
- 社区采集 CI：`.github/workflows/community-health.yml`（每日 03:17 UTC）；
  依赖 `scabase-fetcher/data/repo-map.json` 做 purl→owner/repo 映射（非 go 生态必须登记）；
  `community_report.py` 产出汇总；`build_facts.py` 只为 count>0 的数据集刷新水位。
- 环境注意：某些会话没有 Bash 工具，无法执行测试；交付时要在 tasks.md 标注「待执行验证」。

## 包注册表发布（2026-10-15 新增）
- owner/org 是 **scabase**。漏洞与健康度结果每天 04:41 UTC 由
  `.github/workflows/publish-packages.yml` 发布到 GitHub Packages 三通道：
  `@scabase/data`（npm.pkg.github.com）、`cn.scabase:scabase-data`（maven.pkg.github.com/scabase/…）、
  `ghcr.io/scabase/scabase-data`（纯数据镜像，`docker run --rm <img> | tar -x` 取出）。
- 三通道共用同一份 staging（`oss_intake/release.py` 产出 `manifest.json` + `data/`）
  与同一个 CalVer 版本号 `YYYYMMDD.HHMM00.0`，因此版本号与文件哈希必然一致。
- `content_digest` 只由「路径 + sha256」算出，配合 Actions Cache 决定是否跳过发布。
- CLI：`python -m oss_intake.cli release`（构建）/`verify-release`（校验落地包）。
- 外发红线：事实层入包只取 `vulns/health/license/kev`，**inventory/outbox/state.json 禁止出包**。
- npm publish 必须指定目录：`npm publish packages/npm`（仓库根没有 package.json）。

## 常用依赖 Top 清单（2026-10-17 扩展为四生态 Top 1000）
- `scabase-fetcher/scripts/gen_popular_packages.py`（~2150 行）生成四生态各 1000 条：
  npm（registry 搜索 392 关键词采样，近一周下载量排序）、pypi（top-pypi-packages
  近 30 天下载榜）、maven（人工种子 + deps.dev 依赖图展开，按公开依赖项目数排序）、
  go（人工核心模块 + GitHub Star 仓库经 deps.dev GetProjectPackageVersions 映射）。
- 产物：`popular-packages.json`（前端 4 tab / 过滤 / 增量渲染 / Top N 一键填入）+
  `pkg_list_popular.txt`（每生态前 100 共 400 行，供 community-health 第二批采集）。
- CLI：`--refresh --top 1000 --txt-top 100 --workers 8 --only <eco>`（单生态增量刷新）；
  CI 只跑离线转换（`--json/--txt`），可字节级复现 txt。
- `version_key()` 自研版本比较覆盖 Maven/PyPI/Go 三种形态；限定词先去数字再判稳定词。
- 已弃用数据源：npmjs.com/browse、mvnrepository.com（Cloudflare 403）、Maven Central Solr
  （无流行度字段且约 50% 超时）、proxy.golang.org（沙箱阻断）。
- 细节与踩坑见 2026-10-17 日志。

## 机器可读数据 / LLM 取数（2026-10-17 新增）
- 根目录 `llms.txt`（llmstxt.org 规范）是 LLM WebFetch 入口；数据索引
  `scabase-fetcher/data/index.json` 由 `gen_data_index.py` 生成（URL/bytes/sha256/generated_at/llm_hint）。
- 发布面（Pages 与 Docker 一致）：llms.txt + index.json + vulns.json + popular-packages.json
  + community-support.json + pkg_list.txt + pkg_list_popular.txt + repo-map.json。
  pages.yml 构建时重新生成 index.json；Dockerfile 显式 COPY llms.txt。
- 前端布局约定（2026-10-17 用户最终确认）：**输入框置顶，选择项在下**。
  pane-vuln 顺序：查询框 → 查询/清空按钮 → 快速填入 chips → popularPanel（默认折叠，
  提示文案「填入上方查询框」）→ help；pane-health 顺序：查询框 → 按钮 → chips →
  标题/简介/KPI → help → 筛选控件。曾把 popularPanel 置顶+展开被用户明确否决
  （"输入框置顶，不是把选择项置顶"）。冒烟测试用 compareDocumentPosition 断言该顺序。

## 技术约定
- 前端为 ES5 风格 IIFE（var / function），无构建步骤，不要引入需要编译的语法。
- Python 侧：评估与同步路径保持零第三方依赖（内网可运行），仅采集器用 `requests`。
- 测试方式：Python `python -m unittest discover -s tests`（tests/fixtures.py 提供本地桩）；
  前端用 jsdom（装在 `/Users/block/.workbuddy/binaries/node/workspace`）+ 本地 vulns.json
  桩掉 fetch，在 node 里 eval `assets/app.js` 后操作 DOM 断言。
- 前端冒烟必须带 `NODE_PATH=/Users/block/.workbuddy/binaries/node/workspace/node_modules`
  跑 `node tests/.tmp-frontend-smoke.js`，否则 jsdom MODULE_NOT_FOUND。
- gate JSON 单组件时同时含 `result` 与 `results` 双键；depinfo `--results` 兼容三种形态
  （results 列表 / 单 result 对象 / items 列表）——2026-10-17 修过的 HEAD 既有 bug。
