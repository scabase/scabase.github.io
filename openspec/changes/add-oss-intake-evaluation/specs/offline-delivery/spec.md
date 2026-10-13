# Delta for offline-delivery

## MODIFIED Requirements

### Requirement: 容器化内网部署

系统 SHALL 提供基于 `nginx:1.27-alpine` 的镜像，监听 **8080** 端口，暴露 `/healthz` 健康检查端点，
并承载事实层数据集与开源引入评估台页面。

- 镜像 SHALL 以非 root 用户运行。
- 事实层与评估台数据目录 SHALL 支持通过挂载卷热更新，无需重建镜像。
- 评估台 SHALL 作为独立页面提供，MUST NOT 改变现有漏洞查询页的交互行为。

（Previously：镜像仅承载漏洞查询页面与 `vulns.json`。）

#### Scenario: 挂载更新数据

- GIVEN 容器已运行
- WHEN 替换挂载目录中的 `vulns.json`
- THEN 站点无需重建镜像即可读到新数据

#### Scenario: 挂载更新事实层

- GIVEN 容器已运行
- WHEN 替换挂载目录中的事实层数据集
- THEN 评估台与查询页无需重建镜像即可读到新数据

### Requirement: 运行时配置注入

系统 SHALL 在容器启动时由 `docker/10-env-config.sh` 按环境变量生成 `assets/config.js`。

- 支持的环境变量 SHALL 至少包含 `SCABASE_OFFLINE`、`SCABASE_OSV_API`、`SCABASE_NVD_PREFIX`、
  `SCABASE_FACTS_DIR`、`SCABASE_FRESHNESS_SLA_DAYS`、`SCABASE_GROUP_ASSETS`。
- 前端 SHALL 通过 `window.SCABASE_CONFIG` 读取配置。
- 离线开关为 true 时，评估台 MUST NOT 发起任何外部请求，未知组件 MUST 显示为数据缺失。

（Previously：仅支持离线开关、OSV 与 NVD 前缀三个变量。）

#### Scenario: 离线开关生效

- GIVEN 环境变量 `SCABASE_OFFLINE=true`
- WHEN 容器启动
- THEN 生成的 `assets/config.js` 中 offline 为 true
- AND 查询页与评估台均不出现任何依赖公网的交互入口

### Requirement: 传输压缩

静态资源 SHALL 启用 gzip 压缩，事实层数据集 SHALL 按分片压缩传输，
使单次摆渡的数据体积显著小于未压缩全量。

#### Scenario: 事实层分片压缩

- GIVEN 事实层某数据集未压缩体积为 2.8MB
- WHEN 构建离线数据包
- THEN 该分片以压缩形式入包
- AND 包体积显著小于未压缩体积
