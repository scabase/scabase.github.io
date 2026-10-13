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

## 技术约定
- 前端为 ES5 风格 IIFE（var / function），无构建步骤，不要引入需要编译的语法。
- 测试方式：jsdom（装在 `/Users/block/.workbuddy/binaries/node/workspace`）+ 本地 vulns.json
  桩掉 fetch，在 node 里 eval `assets/app.js` 后操作 DOM 断言。
