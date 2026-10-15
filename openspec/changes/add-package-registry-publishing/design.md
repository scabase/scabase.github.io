# Design: 漏洞与健康度结果发布到 GitHub Packages

## 背景

仓库每天产出两类可被外部复用的结果：

| 结果 | 文件 | 生成者 |
| --- | --- | --- |
| 漏洞结果 | `scabase-fetcher/data/vulns.json` | `update-vuln.yml`（OSV + NVD 富化） |
| 健康度结果 | `scabase-fetcher/data/health.json` + `community-support.json` | `community-health.yml`（GitHub / deps.dev / registry 三类信号） |

二者目前只服务静态站点与内网摆渡。本设计把它们变成**版本化的依赖制品**。

## 决策一：一份 staging，三个通道

不按通道各打一份包，而是先由 `oss_intake/release.py` 产出唯一的 staging：

```
<out>/manifest.json
<out>/data/vulns.json
<out>/data/health.json
<out>/data/community-support.json
<out>/data/facts/<dataset>/<eco>.json
```

npm 把整棵树放进 package 根目录；maven 把它注入 jar 的 `scabase-data/` 资源路径；
docker 把它复制为 `/manifest.json` + `/data`。好处：

- 版本号同一份，`manifest.content_digest` 跨通道可比；
- 新增第四种通道（如 PyPI / NuGet）只需加一个 job，不用改打包逻辑；
- CI 里只有一处算哈希，避免「三个包内容不一致」这种最难排查的问题。

**取舍**：npm 包体积会因为携带 `data/facts` 变大。因此事实层快照是**可选**项，
由 `--facts` 决定，流水线在确定为产品化形态后可关闭。

## 决策二：版本号与幂等

版本号取 CalVer `YYYYMMDD.HHMM00.0`（`20261015.231400.0`）：既满足 semver（npm），
又满足 Maven 版本约束，并天然按时间单调排序，不用维护 `CHANGELOG`。

数据每天都“变”（提交时间变了也算变），但我们不想每天把同一份内容重推一遍。
因此引入两级指纹：

1. `files[].sha256`：逐文件；
2. `content_digest`：把 `[{path, sha256}]` 规范化 JSON 后的 sha256，**只反映内容**。

CI 用 `actions/cache@v4` 以 `scabase-release-<content_digest>` 为 key 记录上次发布的值，
命中即跳过三个发布作业。这一招不需要查询远程仓库状态，也不需要额外 Secret。

## 决策三：最小权限与令牌

`workflow_call` / `workflow_dispatch` / `schedule` 三种触发都只用内置环境：

| 通道 | 认证 |
| --- | --- |
| npm | `actions/setup-node`（registry-url + scope）+ `NODE_AUTH_TOKEN` |
| maven | `actions/setup-java`（server-id `github`）+ `GITHUB_TOKEN` |
| docker | `docker/login-action`（ghcr.io，`github.actor` + `GITHUB_TOKEN`） |

三个 job 统一声明 `permissions: { contents: read, packages: write }`，顶层 workflow 只给
`contents: read`。没凑 `$GITHUB_TOKEN` 之外的 Secret，也不需要往 `mvn` 里塞明文口令
（`setup-java` 会把 `${env.GITHUB_TOKEN}` 写进 `settings.xml`，运行期由环境变量求值）。

## 决策四：外发合规

离线摆渡链路已经用 `EXTERNAL_DATASETS` 把 `inventory`（内网资产台账）挡在外面，
发布链路必须继承这条红线：

- staging 只接受 `vulns / health / license / kev` 四个事实层数据集；
- `--facts` 传根目录时，`release.py` 只会遍历白名单内的子目录，
  `inventory/`、`outbox/`、`state.json` 不会进包；
- manifest 的 `source` 只含仓库名、commit 与 run 链接，不含任何应用资产信息。

这与既有 MCP 输出脱敏策略保持一致：**对外只有组件维度的情报，没有企业维度的资产。**

## 决策五：消费端形态

不同语言栈的习惯差别很大，因此每个通道都提供「刚好够用」的一层：

- **npm**：CommonJS API（`vulns() / community() / findByCve() / verify()`）+ `scabase-data` CLI
  （`digest / verify / cve / dataset`），让 CI 脚本一行拿到 CVE 命中面或判断是否需要重新拉取。
- **maven**：资源 jar + `cn.scabase.data.ScaBaseData`（`manifest()/vulns()/health()/community()`），
  零第三方依赖，Java 侧接入只要一个 `<dependency>`。
- **docker**：纯数据 OCI 制品，默认 `ENTRYPOINT ["/bin/tar", ...]` 以 tar 流吐出数据，
  离线环境可以先拉取镜像再出库；版本号与 `content_digest` 写进 OCI label 便于追溯。

## 决策六：失败处理

| 环节 | 处理 |
| --- | --- |
| 健康度采集失败 | `continue-on-error`，用仓库里已有的 `community-support.json` 继续发布 |
| 事实层写入失败 | 同上，发布包退化为「漏洞 + 社区支持力度」，缺失文件不进 manifest |
| 无一可用数据 | `ReleaseError` 直接失败，不发布空包 |
| 发布前校验失败 | 该 job 失败，其余通道不受影响（`fail-fast` 未启用） |
| 某通道发布失败 | 其余通道照常结束；重跑同一 workflow 即可补齐 |
| 内容超过 500MB | 体积门禁失败，提示先拆分数据集（注册表对单包体积有上限） |

## 备选方案

- **GH Pages 直链下载**：零发布成本，但没有版本号与校验清单，需要消费者自己管增量——弃用。
- **只发 docker**：对 Java / Node 栈不友好，且 ghcr 拉取需要 docker 运行时——弃用。
- **GitHub Release 附件 + `gh release download`**：可行但生态不通用，无法 `npm install`——暂缓，
  可作为未来的第四通道（Release 附件 tar.gz）。
