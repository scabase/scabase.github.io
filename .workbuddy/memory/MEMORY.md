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
- 资产模型 app 支持 `gavs` / `purls`（depinfo 台账，无 SBOM 文件）。
- 环境注意：某些会话没有 Bash 工具，无法执行测试；交付时要在 tasks.md 标注「待执行验证」。

## 技术约定
- 前端为 ES5 风格 IIFE（var / function），无构建步骤，不要引入需要编译的语法。
- Python 侧：评估与同步路径保持零第三方依赖（内网可运行），仅采集器用 `requests`。
- 测试方式：Python `python -m unittest discover -s tests`（tests/fixtures.py 提供本地桩）；
  前端用 jsdom（装在 `/Users/block/.workbuddy/binaries/node/workspace`）+ 本地 vulns.json
  桩掉 fetch，在 node 里 eval `assets/app.js` 后操作 DOM 断言。
