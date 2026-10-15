# @scabase/data

ScaBase 的**漏洞与健康度结果发布包**，通过 GitHub Packages 的 npm 注册表（`https://npm.pkg.github.com`）分发。

包内容每天随采集流水线刷新一次，`manifest.json` 记录版本号、`content_digest`、
每个文件的 sha256 / 体积 / 条目数，落地后可逐文件校验是否被篡改。

## 安装

在项目根目录建 `.npmrc`（令牌只需 `read:packages` 权限）：

```ini
@scabase:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
export GITHUB_TOKEN=<your token>
npm install @scabase/data
```

## 包内结构

```
manifest.json
data/vulns.json                漏洞结果（OSV + NVD 富化，按 eco|pkg|ver 聚合）
data/health.json               组件活跃度原始信号
data/community-support.json    社区支持力度汇总（0-100 分与 A/B/C/D 等级）
data/facts/<dataset>/<eco>.json  事实层分片快照（可选）
```

## 用法

```js
const data = require('@scabase/data');

console.log(data.version(), data.contentDigest());

const vulns = data.vulns();                       // { "pkg:maven/...|...": { osv_raw, enriched } }
console.log(data.findByCve('CVE-2025-70974'));    // 反查受影响组件
console.log(data.componentsByGrade('D'));         // 社区支持力度最差的组件

console.log(data.verify());                       // { ok, checked, failures }
```

命令行（随包提供 `scabase-data`）：

```bash
npx scabase-data version
npx scabase-data digest      # 内容指纹，CI 用它判断是否需要重新拉取
npx scabase-data verify      # 校验 sha256，失败退出码 1
npx scabase-data cve CVE-2025-70974
npx scabase-data dataset health
```

## 内联到内网流程

离线环境可把 `data/` 与 `manifest.json` 直接拷进内网制品库或对象存储，
再用 `python -m oss_intake.cli verify-release --pkg <dir>` 做落地校验；
校验通过的数据目录可直接作为 ScaBase 站点的事实层输入。

## 相关

- 同类 Maven 包：`cn.scabase:scabase-data`
- 同类容器镜像：`ghcr.io/scabase/scabase-data`
- 操作手册：[`docs/github-packages.md`](../../docs/github-packages.md)
