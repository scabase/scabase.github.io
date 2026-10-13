# offline-delivery Specification

## Purpose

将 ScaBase 及其数据交付到无公网出口的企业内网，并支持公网站点（GitHub Pages）与容器化内网部署两种形态。

## Requirements

### Requirement: 静态站点发布

系统 SHALL 在推送到 main 分支时组装 `_site` 产物并发布到 GitHub Pages，使用仓库中的 `CNAME` 绑定域名。

### Requirement: 容器化内网部署

系统 SHALL 提供基于 `nginx:1.27-alpine` 的镜像，监听 **8080** 端口，暴露 `/healthz` 健康检查端点。

- 镜像 SHALL 以非 root 用户运行。
- 数据目录 SHALL 支持通过挂载卷热更新，无需重建镜像。

#### Scenario: 挂载更新数据

- GIVEN 容器已运行
- WHEN 替换挂载目录中的 `vulns.json`
- THEN 站点无需重建镜像即可读到新数据

### Requirement: 运行时配置注入

系统 SHALL 在容器启动时由 `docker/10-env-config.sh` 按环境变量生成 `assets/config.js`。

- 支持的环境变量 SHALL 至少包含 `SCABASE_OFFLINE`、`SCABASE_OSV_API`、`SCABASE_NVD_PREFIX`。
- 前端 SHALL 通过 `window.SCABASE_CONFIG` 读取配置。

#### Scenario: 离线开关生效

- GIVEN 环境变量 `SCABASE_OFFLINE=true`
- WHEN 容器启动
- THEN 生成的 `assets/config.js` 中 offline 为 true
- AND 页面不出现任何依赖公网的交互入口

### Requirement: 离线镜像产物

镜像 CI SHALL 产出可用于纯内网的 OCI 镜像与 `docker` 格式的 tar 离线包，供 `docker load` 导入。

- 镜像 SHALL 使用 latest 与日期双标签。
- 离线包 SHALL 至少覆盖 amd64 与 arm64 架构。

### Requirement: 传输压缩

静态资源 SHALL 启用 gzip 压缩，使 `vulns.json` 由约 2.8MB 压缩至约 300KB 量级。
