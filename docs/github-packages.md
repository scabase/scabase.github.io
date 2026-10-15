# GitHub Packages 发布（漏洞 + 健康度结果）

ScaBase 每天采集的**漏洞结果**（OSV + NVD 富化）与**健康度结果**（组件活跃度信号 +
社区支持力度 A/B/C/D 等级），除了提交回仓库供站点使用，还会打包发布到
**GitHub Packages**，让 CI / Java / Node 进程可以直接“装依赖”的方式拿到数据。

同一套数据产物同时发布到三个注册表，共用内置的 `GITHUB_TOKEN`
（只需 `permissions: packages: write`，无需额外 Secret）：

| 通道 | 坐标 | 注册表 |
| --- | --- | --- |
| npm | `@scabase/data` | `https://npm.pkg.github.com` |
| maven | `cn.scabase:scabase-data` | `https://maven.pkg.github.com/scabase/scabase.github.io` |
| docker | `ghcr.io/scabase/scabase-data` | `ghcr.io` |

> 公开仓库下发布的包可直接设为 Public，**完全免费**。

## 发布内容结构

三个通道共用同一份 staging 内容（`oss_intake/release.py` 产出），
因此版本号与每个文件的 sha256 在三处完全一致：

```
manifest.json
data/vulns.json                漏洞结果（按 eco|pkg|ver 聚合，含 CVE 编号统计）
data/health.json               组件活跃度原始信号
data/community-support.json    社区支持力度汇总（评分 + A/B/C/D 等级）
data/facts/<dataset>/<eco>.json  事实层分片快照（可选）
```

`manifest.json` 记录：`schema / version / content_digest / files[]（path、sha256、size）/
datasets[]（条目数、CVE 数、等级分布）/ source（仓库与 run 链接）/ signature（有密钥时）`。

## 触发方式

`.github/workflows/publish-packages.yml`：

- **定时**：每日 04:41 UTC（排在 `update-vuln` 02:00 与 `community-health` 03:17 之后）
- **手动**：Actions → publish-packages → Run workflow，可选 `channels`、
  `version`、`collect-health`、`skip-unchanged`、`dry-run`
- **被其他工作流调用**：已声明 `workflow_call`，可作为数据流水线末端的一步

作业结构：

```
prepare（采集健康度 → 构建 staging → 内容指纹比对 → 打包 artifact）
   ├── publish-npm     @scabase/data
   ├── publish-maven   cn.scabase:scabase-data
   └── publish-docker  ghcr.io/scabase/scabase-data
```

关键设计：

- **幂等发布**：`content_digest` 是剥离版本号与时间戳的内容指纹，
  通过 Actions Cache 记录上次发布的值，内容没变就跳过三个发布作业，避免每天重推同一份数据。
- **先校验再发布**：每个作业发布前跑 `python -m oss_intake.cli verify-release`
  逐文件核对 sha256，发现缺文件/哈希不一致直接失败。
- **体积门禁**：单通道内容超过 500MB 直接失败，提醒先拆分数据集。
- **dry-run**：勾上后只构建与打包（npm `npm pack`、maven 只打 jar、docker 只 build），不推送。

## 消费方式

### npm

```bash
# 项目根目录 .npmrc（令牌只需 read:packages）
@scabase:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}

npm install @scabase/data
```

```js
const data = require('@scabase/data');

data.version();                       // 版本号
data.findByCve('CVE-2025-70974');     // 反查受影响组件
data.componentsByGrade('D');          // 社区支持力度最差的组件
data.verify();                        // 逐文件 sha256 校验
```

随包提供 CLI：

```bash
npx scabase-data digest      # 内容指纹，判断是否值得重新拉取
npx scabase-data verify      # 校验完整性（失败退出码 1）
npx scabase-data cve CVE-2025-70974
```

### maven

```xml
<dependency>
  <groupId>cn.scabase</groupId>
  <artifactId>scabase-data</artifactId>
  <version>20261015.231400.0</version>
</dependency>
```

```java
import cn.scabase.data.ScaBaseData;

String manifest = ScaBaseData.manifest();   // scabase-data/manifest.json
String vulns = ScaBaseData.vulns();         // scabase-data/data/vulns.json
String community = ScaBaseData.community();
```

`settings.xml` 里给 `github` server 配上 `read:packages` 令牌即可解析依赖。

### docker

```bash
# 把数据以 tar 流取出
docker run --rm ghcr.io/scabase/scabase-data:latest | tar -x -C ./scabase-data

# 或直接浏览
docker run --rm --entrypoint ls ghcr.io/scabase/scabase-data:latest /data

# 校验取出的数据
python -m oss_intake.cli verify-release --pkg ./scabase-data
```

镜像是纯数据 OCI 制品（`alpine` 底 + `manifest.json` + `/data`），
版本号与 `content_digest` 都写进了 OCI label，适合离线环境先拉镜像再出库。

## 本地预演

```bash
# 只构建 staging 内容（不联网、不发布）
python -m oss_intake.cli release \
  --out build/scabase-data \
  --vulns scabase-fetcher/data/vulns.json \
  --health scabase-fetcher/data/health.json \
  --community scabase-fetcher/data/community-support.json \
  --facts scabase-fetcher/data/facts \
  --json reports/release.json

# 校验构建结果
python -m oss_intake.cli verify-release --pkg build/scabase-data

# 本地打 jar 看包内布局
mkdir -p packages/maven/generated/scabase-data
cp -r build/scabase-data/. packages/maven/generated/scabase-data/
mvn -f packages/maven/pom.xml -B clean package
unzip -l packages/maven/target/scabase-data.jar
```

## 版本与签名

- 版本号：`YYYYMMDD.HHMM00.0`（CalVer），同时满足 semver 与 Maven 约束，按时间单调递增。
- 相同内容重复发布会被跳过；需要强制重推时可取消勾选 `skip-unchanged` 或换版本号。
- 配置 Secret `SCABASE_SYNC_KEY` 后 manifest 带签名（`ed25519` 优先，回落 `hmac-sha256`）；
  未配置时 manifest 不出现 `signature` 字段，消费端按无签名处理。

## 故障排查

| 现象 | 原因 / 处理 |
| --- | --- |
| `403 Forbidden` 发布失败 | job 缺 `permissions: packages: write`，或令牌没有 `write:packages` |
| npm 报包名已存在 | `@scabase/data` 必须挂在本组织 scope 下，换 gap 前确认 owner 拼写 |
| maven `401` | `server-id` 必须与 `repositoryId=github` 一致，`GITHUB_TOKEN` 要传到 mvn 进程 |
| docker push `denied` | 先 `docker/login-action` 登录 `ghcr.io`，用户用 `github.actor`，口令用 `GITHUB_TOKEN` |
| 三个包版本号不一致 | 不可能：同一份 staging 共用同一个 `version`，不一致说明某通道复用了旧 artifact |
| 每天看到同一个 content_digest | 数据没变化已跳过发布；如需强推请取消 `skip-unchanged` |
