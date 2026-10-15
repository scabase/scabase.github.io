# Tasks: 漏洞与健康度结果发布到 GitHub Packages

> 说明：本次交付在“无命令行执行环境”的会话中完成，标记为 ✅ 的任务已写完代码，
> 但**全部待本地/CI 执行验证**（`python -m unittest discover -s tests` 与一次 dry-run）。

## Phase 1 — 发布内容构建

- [x] 1.1 新增 `oss_intake/release.py`：staging 目录结构、manifest schema、逐文件 sha256
- [x] 1.2 实现 `content_digest`（只含路径 + 哈希，排除版本号与时间戳）
- [x] 1.3 实现数据集摘要统计（vulns 条目/CVE 数、health 可用条目、community 等级分布）
- [x] 1.4 实现事实层快照入包（仅 `vulns/health/license/kev`，排除 inventory 与 outbox）
- [x] 1.5 复用 `sync.Signer` 给 manifest 签名，无密钥时不写 `signature`
- [x] 1.6 实现 `verify()`：缺失 / sha256 不一致都会被列出
- [x] 1.7 源文件缺失降级为空 datasets 而非报错（全部缺失才失败）
- [ ] 1.8 待验证：`python -m unittest discover -s tests` 全绿

## Phase 2 — CLI 接入

- [x] 2.1 新增 `release` 子命令（`--out/--vulns/--health/--community/--facts/--version/--key/--json`）
- [x] 2.2 新增 `verify-release` 子命令（校验失败退出码 1）
- [x] 2.3 CalVer 版本号：`YYYYMMDD.HHMM00.0`，满足 semver 与 Maven 约束
- [ ] 2.4 待验证：`python -m oss_intake.cli release --out build/scabase-data` 产出 manifest

## Phase 3 — 三通道包形态

- [x] 3.1 `packages/npm`：package.json（`@scabase/data`，publishConfig 指向 npm.pkg.github.com）
- [x] 3.2 `packages/npm`：index.js（CommonJS API + findByCve + verify）与 index.d.ts
- [x] 3.3 `packages/npm`：cli.js（`scabase-data` 命令行）与 README
- [x] 3.4 `packages/maven`：pom.xml（generated/scabase-data → jar 内 scabase-data/ 资源）
- [x] 3.5 `packages/maven`：`cn.scabase.data.ScaBaseData` 读取入口与 README
- [x] 3.6 `docker/Dockerfile.data`：alpine 纯数据镜像，ENTRYPOINT 以 tar 流吐数据
- [ ] 3.7 待验证：`mvn -f packages/maven/pom.xml -B clean package` 能产出含数据资源的 jar
- [ ] 3.8 待验证：`node packages/npm/cli.js verify` 在真实安装包上运行通过

## Phase 4 — 发布流水线

- [x] 4.1 `.github/workflows/publish-packages.yml`：prepare 作业构建 staging 并上传 artifact
- [x] 4.2 健康度补采步骤（默认开启，`continue-on-error` 降级用已有数据）
- [x] 4.3 `content_digest` + Actions Cache 幂等跳过
- [x] 4.4 发布前 `verify-release` 门禁与 500MB 体积门禁
- [x] 4.5 npm job：`setup-node` 注入注册表与 token，版本写入后 publish，dry-run 走 `npm pack`
- [x] 4.6 maven job：`setup-java(server-id=github)` + `deploy:deploy-file` 推送 jar
- [x] 4.7 docker job：登录 ghcr.io 后 build-push 双平台，带 version 与 latest 标签
- [x] 4.8 支持 `workflow_dispatch` / `workflow_call` / `schedule`（每日 04:41 UTC）
- [ ] 4.9 待验证：手动 `dry-run` 跑一轮
- [ ] 4.10 待验证：正式发布一轮，确认三处版本号与 digest 一致

## Phase 5 — 文档与清理

- [x] 5.1 新增 `docs/github-packages.md`：三通道安装、取出、校验与排障
- [x] 5.2 更新 `readme.md` / `readme_zh_cn.md`：新增发布渠道说明与目录清单
- [x] 5.3 更新 `.gitignore`：排除 `build/`、`packages/maven/generated/`、`packages/npm/data/` 等中间产物
- [x] 5.4 新增 `tests/test_release.py`：manifest、指纹稳定性、缺失降级、签名、篡改检测
- [ ] 5.5 待办：确认 GitHub 侧包可见性（公开仓库默认可设为 Public）
