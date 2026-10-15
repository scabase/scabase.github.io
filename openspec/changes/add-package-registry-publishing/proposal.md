# Proposal: 漏洞与健康度结果发布到 GitHub Packages

## Why

现在漏洞结果（`vulns.json`）与健康度结果（`health.json` / `community-support.json`）只有两个出口：
**提交回仓库**（给静态站点用）和 **离线摆渡 Bundle**（给内网导入用）。第三方 CI、Java 平台、Node 脚本
想消费这些数据，只能自己 clone 仓库或手工搬运文件，既拿不到版本号，也无从校验数据是否被改动。

GitHub Packages 在同一处同时提供 **npm + maven + docker(ghcr.io)** 三种注册表，直接复用
Actions 内置的 `GITHUB_TOKEN` 就能发布（只需 `permissions: packages: write`），公开仓库下为免费公开包。
把「漏洞 + 健康度」结果作为依赖制品发布出去，可以让任何语言栈的进程用各自熟悉的包管理器
拿到的**带版本号、带哈希清单、可校验**的数据。

## What Changes

- **新增统一发布内容**：由 `oss_intake/release.py` 把漏洞、健康度与事实层快照打包成一份 staging
  （`manifest.json` + `data/`），npm / maven / docker 三通道共用同一份内容，保证版本号与文件哈希一致。
- **新增三通道发布**：`.github/workflows/publish-packages.yml` 发布 `@scabase/data`、
  `cn.scabase:scabase-data`、`ghcr.io/scabase/scabase-data`，支持 `channels` 选择与 `dry-run`。
- **新增发布幂等控制**：以 `content_digest`（剥离版本号与时间戳的内容指纹）配合 Actions Cache
  判断是否值得重推，内容没变就跳过发布。
- **新增发布前校验**：每个通道发布前逐文件核对 sha256，失败即阻断；事实层仅携带外部数据集，
  `inventory` 等内部数据集禁止进入发布包。
- **新增消费端访问层**：npm 包提供 `manifest/version/findByCve/verify` API 与 `scabase-data` CLI；
  maven 提供资源 jar 与 `cn.scabase.data.ScaBaseData` 读取入口；数据镜像默认以 tar 流吐出数据。

## Capabilities

### New Capabilities

- `package-registry-publishing`：漏洞与健康度结果向 npm / maven / docker 三类注册表的打包与发布，
  含内容清单、幂等判定、发布前校验与最小权限约束

### Modified Capabilities

- `build-delivery`：交付链路在 Pages 与镜像之外新增「包注册表」通道，并可被其他工作流 `workflow_call` 复用
- `component-health`：健康度结果（活跃度信号 + 社区支持力度汇总）成为可对外发布的一等公民产物

## Impact

- 新增文件：`oss_intake/release.py`、`packages/npm/**`、`packages/maven/**`、`docker/Dockerfile.data`、
  `.github/workflows/publish-packages.yml`、`docs/github-packages.md`、`tests/test_release.py`
- 修改文件：`oss_intake/cli.py`（新增 `release` / `verify-release` 子命令）、
  `readme.md`、`readme_zh_cn.md`、`.gitignore`
- 无 BREAKING：现有站点、镜像与离线摆渡链路行为完全不变；仅在数据流水线末端增加一条发布通道
- 成本：公开包免费；新增一轮每日 04:41 UTC 的定时任务
