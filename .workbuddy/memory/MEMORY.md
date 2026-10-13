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
- CLI：`python -m oss_intake.cli {inventory|gate|assess|bundle|import|confidence}`。
- 未实现：前端评估台页面（intake.html），在 openspec change 的 tasks Phase 5。

## 技术约定
- 前端为 ES5 风格 IIFE（var / function），无构建步骤，不要引入需要编译的语法。
- Python 侧：评估与同步路径保持零第三方依赖（内网可运行），仅采集器用 `requests`。
- 测试方式：Python `python -m unittest discover -s tests`（tests/fixtures.py 提供本地桩）；
  前端用 jsdom（装在 `/Users/block/.workbuddy/binaries/node/workspace`）+ 本地 vulns.json
  桩掉 fetch，在 node 里 eval `assets/app.js` 后操作 DOM 断言。
