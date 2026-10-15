# Delta for package-registry-publishing

## ADDED Requirements

### Requirement: 统一发布内容与清单

系统 SHALL 把漏洞结果、健康度结果与事实层快照构建为唯一的 staging 内容，
并由 `manifest.json` 描述每个文件的 sha256、体积与条目统计。

- staging MUST 采用目录结构：`<out>/manifest.json` + `<out>/data/**`。
- manifest MUST 至少包含 `schema`、`version`、`generated_at`、`content_digest`、
  `files[]`、`datasets{}` 字段。
- 任一数据文件缺失 MUST NOT 中断构建，该文件 SHALL 从 manifest 中缺席。
- 当漏洞、健康度、社区支持力度三类数据全部缺失时，系统 SHALL 判定为空包并失败。
- 配置了签名密钥（`SCABASE_SYNC_KEY` 或 `--key`）时，manifest SHALL 携带 `signature` 字段，
  签名算法复用 `oss_intake.sync.Signer`（ed25519 优先，回落 hmac-sha256）；
  未配置时 MUST NOT 写入 `signature` 字段。

#### Scenario: 构建发布包

- GIVEN 仓库中存在 `vulns.json`、`health.json` 与 `community-support.json`
- WHEN 执行 `python -m oss_intake.cli release --out <dir>`
- THEN `<dir>/data/` 下出现三个数据文件的副本
- AND `manifest.json` 中每个文件都有 sha256、size 与条目数统计
- AND `datasets.vulns` 记录 `entries` 与去重后的 `cve_count`

#### Scenario: 数据源缺失降级

- GIVEN `health.json` 不存在（当日健康度采集失败）
- WHEN 构建发布包
- THEN 构建仍然成功
- AND `datasets` 中不含 `health`
- AND manifest 的 `files[]` 里没有 health 相关条目

#### Scenario: 空包阻断

- GIVEN 三个数据文件都不存在
- WHEN 构建发布包
- THEN 命令以非零码退出并提示没有任何可用数据

### Requirement: 内容指纹与幂等发布

系统 SHALL 提供只反映数据内容、不含版本号与时间戳的 `content_digest`，
并据此跳过与上次内容一致的发布。

- `content_digest` SHALL 由「文件路径 + sha256」的有序集合计算得出。
- 修改版本号、生成时间或来源元信息 MUST NOT 改变 `content_digest`。
- 任一数据文件内容变化 SHALL 改变 `content_digest`。
- 流水线 SHALL 用 `content_digest` 作为 Actions Cache 的 key，
  命中时跳过全部三个发布 job。
- MAY 通过 `skip-unchanged=false` 强制重推。

#### Scenario: 内容未变化跳过发布

- GIVEN 上一轮已发布 `content_digest=D`
- WHEN 本轮构建出的 `content_digest` 仍为 `D`
- THEN prepare job 输出 `skipped=true`
- AND 三个发布 job 均不执行

#### Scenario: 内容变化后重新发布

- GIVEN 上一轮已发布 `content_digest=D1`
- WHEN 采集到新增 CVE 使本轮指纹变为 `D2`
- THEN 三个通道都以新版本号重新发布
- AND 新版本号严格大于上一轮版本号

### Requirement: 三通道同版本发布

系统 SHALL 把同一份 staging 内容发布到 npm、maven 与 docker 三类注册表，
并保证三处的版本号与文件哈希一致。

- npm 包名 SHALL 为 `@scabase/data`，发布到 `https://npm.pkg.github.com`。
- maven 坐标 SHALL 为 `cn.scabase:scabase-data`，发布到
  `https://maven.pkg.github.com/<owner>/<repo>`。
- docker 镜像 SHALL 为 `ghcr.io/<owner>/scabase-data`，同时打 `<version>` 与 `latest` 标签。
- 每个 job MUST 独立声明 `permissions: packages: write`，其余权限保持 `contents: read`。
- 三个通道 MUST NOT 使用除 `GITHUB_TOKEN` 以外的 Secret。
- 支持 `channels` 选择单通道发布，支持 `dry-run` 只构建不推送。

#### Scenario: 三通道版本一致

- GIVEN prepare job 产出 `version=20261015.231400.0`
- WHEN 三个发布 job 执行完毕
- THEN npm 包版本为 `20261015.231400.0`
- AND maven 包版本为 `20261015.231400.0`
- AND ghcr 镜像带 `20261015.231400.0` 标签

#### Scenario: 只发布单个通道

- GIVEN 手动触发并选择 `channels=maven`
- WHEN 工作流执行
- THEN 只有 maven job 运行
- AND npm 与 docker job 被跳过

#### Scenario: 预演不产生远端变更

- GIVEN 手动触发并勾选 `dry-run`
- WHEN 工作流执行到发布 job
- THEN npm 仅执行 `npm pack`
- AND maven 仅打包 jar 不 deploy
- AND docker 仅构建镜像不推送

### Requirement: 发布前完整性与外发合规校验

系统 SHALL 在发布前逐文件校验内容完整性，并保证企业内部资产数据不会进入公开包。

- 每个发布 job MUST 在推送前执行 `python -m oss_intake.cli verify-release`，
  发现文件缺失或 sha256 不一致即失败。
- 发布包 MAY 携带事实层快照，但 MUST NOT 包含 `inventory`、`outbox`、`state.json`
  等内部数据集。
- manifest 的 `source` 字段 SHALL 只包含仓库名、commit 与 run 链接，
  MUST NOT 包含应用维度信息。
- 单通道内容超过 500MB 时 SHALL 阻断发布并提示先拆分数据集。

#### Scenario: 传输损坏被拦截

- GIVEN staging 内容已经构建
- WHEN 发布前某个数据文件被意外改写
- THEN `verify-release` 报 `sha256-mismatch`
- AND 该通道的发布步骤失败

#### Scenario: 内部数据集不得入包

- GIVEN 事实层目录同时包含 `vulns` 与 `inventory` 数据集
- WHEN 构建发布包并传入 `--facts`
- THEN 包内 `data/facts/` 下只有 `vulns / health / license / kev` 四类子目录
- AND manifest 中不含任何 `inventory` 相关路径

### Requirement: 消费端可用性

系统 SHALL 为每个通道提供与其生态习惯一致的读取方式，并能就地校验数据完整性。

- npm 包 SHALL 导出 `manifest / version / contentDigest / datasetPath / read /
  vulns / health / community / findByCve / componentsByGrade / verify` 接口，
  并提供 `scabase-data` CLI。
- maven 包 SHALL 在 jar 的 `scabase-data/` 路径下提供全部数据，
  并附带 `cn.scabase.data.ScaBaseData` 读取入口。
- docker 镜像 SHALL 以 tar 流形式输出 `/manifest.json` 与 `/data`，
  并把版本号与 `content_digest` 写入 OCI label。
- 消费端 MUST 能在无公网的环境中完成校验（仅依赖本地 sha256 比对）。

#### Scenario: 按 CVE 反查组件

- GIVEN 已安装 `@scabase/data`
- WHEN 调用 `data.findByCve('CVE-2025-70974')`
- THEN 返回命中该 CVE 的组件列表
- AND 每条记录包含组件坐标、OSV 编号、等级别称与严重级别

#### Scenario: 容器取出数据并校验

- GIVEN 内网环境已拉取 `ghcr.io/scabase/scabase-data:latest`
- WHEN 执行 `docker run --rm <image> | tar -x -C ./scabase-data`
- THEN 目标目录出现 `manifest.json` 与 `data/`
- AND `python -m oss_intake.cli verify-release --pkg ./scabase-data` 输出 OK
