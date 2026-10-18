# ScaBase
> ScaBase：开源软件成分分析（SCA）平台
[![Image](tos-cn-i-a9rns2rl98/rc/online_import/14995fa34eb54d648791a1fde2819cf4)](https://github.com/scabase/scabase-fetcher/actions)
[![Image](tos-cn-i-a9rns2rl98/rc/online_import/af660d2beb7f49208b60626afc810c7d)](https://osv.dev/)
[![Image](tos-cn-i-a9rns2rl98/rc/online_import/a0b48a21b4df4b99b6e8c7892fb705cc)](LICENSE)

在线站点：https://scabase.roweb.cn

> [English Document](./README.md)

## 项目简介
ScaBase 是面向 DevSecOps、应用安全团队的开源SCA（软件成分分析）漏洞查询平台。
支持 **Maven / NPM / PyPI / Go** 多语言开源组件漏洞检索，基于 OSV + NVD 双漏洞数据库驱动。

- ✅ 多生态支持：Maven GAV、NPM、Python PyPI、Go Module
- ✅ 软件维度支持：nginx / 7-Zip / ZooKeeper / Kubernetes / Redis / MySQL 等 65 个常用
  应用与基础设施软件的漏洞（NVD CPE 精确匹配）与社区健康度查询；两个页签共用同一份
  软件查询清单（名称 / 别名 / 多词名 / 分类），未采集软件显示「未采集」卡并附仓库链接
- ✅ 数据源：OSV作为主数据源，NVD补充标准CVSS、CWE信息
- ✅ 自动更新：GitHub Actions 定时任务自动拉取最新漏洞
- ✅ 纯静态前端：无需后端服务，可部署于 GitHub Pages / Cloudflare Pages
- ✅ 以 CVE 编号呈现：结果以 CVE 为主标识，支持按 CVE 聚合、过滤、排序与一键复制清单
- ✅ 可选备份：通过 Cloudflare R2 将漏洞JSON同步备份至个人NAS

> SCA（Software Composition Analysis，软件成分分析）：识别项目引入的第三方开源依赖组件，查询CVE风险信息，用于软件供应链安全检测。

## 仓库组织
该GitHub组织包含多个代码仓库：
- `scabase-fetcher`：漏洞采集脚本 + GitHub Actions工作流，自动生成`data/vulns.json`漏洞库
- `scabase-web`：静态查询网站前端代码
- `scabase-docs`：项目文档与用户手册

### 目录结构（scabase-fetcher）
scabase-fetcher/
├── .github/workflows/update-vuln.yml   # GitHub Action 定时任务
├── scripts/fetch_osv\[_nvd.py](_nvd.py)            # OSV + NVD 漏洞采集脚本
└── data/
├── pkg_list.txt                    # 待监控组件清单
└── vulns.json                      # 自动生成漏洞数据库

### 目录结构（站点根目录）
```
.
├── index.html                      # 查询页面
├── assets/                         # app.js / style.css / config.js（运行时配置）
├── scabase-fetcher/data/           # vulns.json + pkg_list.txt
├── Dockerfile                      # nginx:alpine 镜像
├── docker/nginx-default.conf       # nginx 站点配置（监听 8080）
├── docker/10-env-config.sh         # 容器启动时生成 assets/config.js
├── docker-compose.yml              # 内网一键部署
├── .github/workflows/
│   ├── pages.yml                   # GitHub Pages 发布
│   ├── docker.yml                  # 镜像构建与推送（含离线 tar 产物）
│   ├── update-vuln.yml             # 漏洞库定时采集
│   ├── community-health.yml        # 组件健康度与社区支持力度采集
│   ├── software-collect.yml        # 软件维度（nginx/k8s 等）漏洞与健康度采集
│   └── publish-packages.yml        # 发布到 GitHub Packages（npm / maven / docker）
```
## 组件清单格式 `data/pkg_list.txt`
格式：`ecosystem|package|version`
```txt
# ecosystem: maven / npm / pypi / go
# Maven包填写 groupId:artifactId
maven|org.springframework.boot:spring-boot-starter-web|2.7.0
maven|com.alibaba:fastjson|1.2.24
npm|lodash|4.17.20
pypi|requests|2.20.0
go|github.com/gin-gonic/gin|1.6.0
工作原理
1. GitHub Actions 在 UTC 每日凌晨 2 点自动执行，同时支持手动触发。
2. 读取pkg_list.txt组件清单，调用 OSV API 查询每个包的漏洞。
3. 对带有 CVE 编号的漏洞，调用 NVD API 补充 CVSS 评分、CWE 分类信息。
4. 合并所有漏洞数据输出data/vulns.json，自动提交回代码仓库。
5. 静态网页前端加载vulns.json，在浏览器提供漏洞检索；结果以 CVE 编号为主标识展示，可切换「按组件 / 按 CVE」视图。
6. 可选：上传vulns.json至 Cloudflare R2，NAS 定时拉取实现本地备份。
部署指南
1. 仓库基础配置
1. Clone 或者 Fork 本仓库
2. 进入仓库 设置(Settings) → Actions → 通用(General) → Workflow permissions
开启 Read and write permissions，允许机器人提交代码。
3. 【可选】申请 NVD API 密钥：https://nvd.nist.gov/developers/request-an-api-key
在仓库 Secret 中添加变量 NVD_API_KEY，提升 NVD 接口访问速率。
2. 运行采集工作流
- 自动执行：UTC 每日 02:00 自动运行
- 手动触发：Actions → Update SCA Vulnerability Data → Run workflow
工作流执行完毕后，data/vulns.json 文件会自动更新。
3. 部署前端网站
本站是纯静态站点，提供两种部署方式：**GitHub Pages（公网）** 与 **Docker（内网离线）**。

#### 方式一：GitHub Pages（公网）
1. 仓库 Settings → Pages → Build and deployment → Source 选择 **GitHub Actions**。
2. 推送到 `main` 分支后，`.github/workflows/pages.yml` 自动执行：
   组装 `_site`（index.html + assets + scabase-fetcher/data + CNAME）并发布。
3. 绑定自定义域名：修改仓库根目录 `CNAME` 文件（当前为 `scabase.roweb.cn`），
   并在 DNS 处添加 CNAME 记录指向 `<组织>.github.io`。
4. 也可在 Actions → Deploy GitHub Pages → Run workflow 手动触发。

> 注意：`.nojekyll` 已内置，避免 Jekyll 忽略下划线目录。

#### 方式二：Docker（内网 / 离线）
镜像基于 `nginx:1.27-alpine`，构建脚本见 `Dockerfile`，GitHub Actions 工作流见
`.github/workflows/docker.yml`（默认构建 `linux/amd64,linux/arm64`，推送到阿里云镜像仓库，
并额外产出可离线导入的 image tar）。

```bash
# 1）本地构建并启动（内网一键部署）
docker compose up -d          # 或 docker build -t scabase:latest .
# 访问 http://<内网IP>:8080

# 2）用 Actions 构建的成品镜像
docker pull registry.cn-hangzhou.aliyuncs.com/roweb/scabase:latest
docker run -d --name scabase -p 8080:8080 \
  -e SCABASE_OFFLINE=true \
  registry.cn-hangzhou.aliyuncs.com/roweb/scabase:latest

# 3）纯内网（连不上镜像仓库）：下载 Actions 产物中的 image tar 后导入
docker load -i scabase-linux-amd64.tar     # arm64 用 scabase-linux-arm64.tar
docker run -d --name scabase -p 8080:8080 -e SCABASE_OFFLINE=true scabase:latest
```

容器环境变量（在启动时写入 `assets/config.js`，无需重新构建镜像）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SCABASE_OFFLINE` | `false` | `true` 时禁用实时 OSV 请求，仅查本地漏洞库，页面显示「离线模式」标记 |
| `SCABASE_OSV_API` | `https://api.osv.dev/v1/query` | 内网自建 OSV 代理时填写（需先关闭离线模式） |
| `SCABASE_OSV_VULN_API` | `https://api.osv.dev/v1/vulns/` | OSV 单漏洞查询地址 |
| `SCABASE_OSV_WEB` | `https://osv.dev/vulnerability/` | OSV 详情页前缀 |
| `SCABASE_NVD_WEB` | `https://nvd.nist.gov/vuln/detail/` | NVD 详情页前缀 |

更新漏洞库而不重建镜像（把宿主机目录挂进容器即可）：

```bash
docker run -d --name scabase -p 8080:8080 -e SCABASE_OFFLINE=true \
  -v /opt/scabase/data:/usr/share/nginx/html/scabase-fetcher/data:ro \
  scabase:latest
```

> 容器监听 **8080**（非特权端口，nginx 以非 root 用户运行）；
> `/healthz` 提供健康检查，镜像与 compose 均已内置 HEALTHCHECK。
扩展能力
- 🔔 漏洞告警：检测到新增 CVE 时推送钉钉 / 企业微信通知
- 📄 SBOM 解析：从 pom.xml/package.json/go.mod 自动生成 pkg_list 清单
- ☁️ Cloudflare R2 + NAS 备份流水线
- 📊 漏洞报表导出
数据源对比
数据源
用途
特点
OSV
主漏洞数据源
原生支持 Maven/NPM/PyPI/Go，无需 API 密钥，包含无 CVE 编号的 GHSA 漏洞
NVD
信息补充增强
NIST 官方 CVE 库，提供标准 CVSS 评分、CWE 分类，建议配置 API 密钥
## 开源引入评估（SBOM 模式 · 离线摆渡）

在漏洞查询之上，ScaBase 另提供一套**开源引入评估体系**：以 SBOM / PURL 为骨架，
把互联网侧漏洞情报、组件活跃度、许可证合规与内网应用 GAV 资产关联整合到同一事实层，
支持**引入前评估门禁**与**按应用群组的存量风险评估**。互联网与内网完全隔离时，
通过带签名与增量链的数据包单向摆渡同步。

```bash
# 互联网侧：采集 → 事实层 → 构建签名数据包
python -m oss_intake.cli bundle --facts scabase-fetcher/data/facts \
  --dataset vulns --out bundles --mode snapshot

# 内网侧：验签导入 → 引入前评估 / 群组评估
python -m oss_intake.cli import --facts intranet-data/facts --bundle bundles/bundle-vulns-0001-*.tar.gz
python -m oss_intake.cli gate --facts intranet-data/facts --purl pkg:maven/com.alibaba/fastjson@1.2.24 --tier core
python -m oss_intake.cli assess --facts intranet-data/facts --assets examples/assets.json --base-dir .
```

### 落地增强（行业开源治理）

- **引入阶段依赖关系自动化分析**：`scan` 直接解析 Maven `pom.xml`、npm
  `package.json`/`package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`、PyPI
  `requirements.txt`/`Pipfile.lock`/`poetry.lock`/`pyproject.toml`、`go.mod` 等原生依赖文件，
  自动归一为 PURL 并区分直接/传递依赖，无需先产出 SBOM。
- **社区支持力度评价**：在活跃度之上输出 0-100 分与 A/B/C/D 等级，
  覆盖 bus factor、治理、背书与生态位，支撑“三年后还维护吗”的判断。
- **安全配置基线 + AI 脚本生成**：内置 32 条覆盖独立部署型与依赖引入型组件的基线目录；
  由 AI 智能体按代码扫描中心、SRE 运维平台规范自动生成基线检查与漏洞检测脚本，
  并以标注样本集回归校验把「扫描准确率达 90%」落成 CI 门禁。
- **漏洞影响范围巡检**：`patrol` 按应用聚合受影响组件、命中 CVE 与基线待检项，
  输出工单（按 KEV/CVSS 定级与整改期限）与新增/未修复/已闭环增量。
- **工具链联动**：DEPINFO 台账导入与结论回传（默认脱敏）、CICD 产物
  （SARIF / JUnit / MR 评论）与四档退出码阈值。

```bash
python -m oss_intake.cli scan   --path ./payment-core --app 支付核心 --tier core
python -m oss_intake.cli patrol --facts intranet-data/facts --assets examples/assets.json \
  --state intranet-data/patrol-state.json --tickets reports/tickets.json
python -m oss_intake.cli genscript --component redis --target sreops --out-dir scripts/sreops
python -m oss_intake.cli verify --cases examples/accuracy-cases.json --threshold 0.9
```

### 以包的形式分发数据（GitHub Packages）

漏洞与健康度结果每天还会打包发布到 **GitHub Packages**，CI / Java / Node 进程可直接当依赖拉取，
三通道复用同一个 `GITHUB_TOKEN`（只需 `packages: write`），公开仓库下免费：

| 通道 | 坐标 |
| --- | --- |
| npm | `@scabase/data`（`https://npm.pkg.github.com`） |
| maven | `cn.scabase:scabase-data`（`https://maven.pkg.github.com/scabase/scabase.github.io`） |
| docker | `ghcr.io/scabase/scabase-data`（纯数据镜像，`docker run --rm <img> | tar -x`） |

```bash
python -m oss_intake.cli release --out build/scabase-data \  # 本地构建 staging
  --vulns scabase-fetcher/data/vulns.json \
  --health scabase-fetcher/data/health.json \
  --community scabase-fetcher/data/community-support.json
python -m oss_intake.cli verify-release --pkg build/scabase-data
```

同一版本号与文件指纹在三处完全一致，内容未变化时自动跳过发布；
详细说明见 [`docs/github-packages.md`](docs/github-packages.md)。

- 规范与提案：`openspec/`（基线 `specs/`，变更 `changes/add-oss-intake-evaluation/`）
- 设计与操作手册：[`docs/oss-intake.md`](docs/oss-intake.md)
- 测试：`python -m unittest discover -s tests`

### 仓库自身的依赖面

本仓库把依赖面压到最小：`oss_intake/` 评分、同步、脚本生成与巡检路径**纯 Python 标准库**
（内网零依赖可直接运行），采集器只用 `requests`（`scabase-fetcher/requirements.txt`，固定 2.32.4），
前端为无构建步骤的 ES5 IIFE。Dependabot 因此只需关注 `github-actions` 与 `pip` 两个生态。

`examples/deps/` 下的教学样本统一带 `.sample` 后缀——样本里的 fastjson 1.2.24、log4j 2.14.1、
axios 0.21.1 等版本是**故意挑选的漏洞版本**，用于演示 `scan` 与评估能力；
加后缀是为了避免被 Dependabot / 依赖图当成真实清单而刷出假告警（曾因此出现 60 条）。
`depfile.classify()` 会自动剥掉后缀识别。新增教学样本时请沿用这一约定。

`.github/workflows/self-scan.yml` 会用本项目自己的门禁引擎扫描 `scabase-fetcher/requirements.txt`，
命中 `Deny` 即阻断；事实层没覆盖到的自身依赖会以 warning 形式暴露工具盲区。

注意事项
1. OSV API 存在请求频率限制，大批量包扫描时建议在循环中增加休眠延时。
2. NVD API 为可选配置；未配置密钥时仍会查询 NVD，但速率较低（建议配置 NVD_API_KEY 提升速率）。
3. 本项目仅用于漏洞信息查询，不执行漏洞利用、主动漏洞扫描动作。
4. 漏洞信息仅作为安全参考，不可直接作为合规审计的唯一依据。
许可证
MIT