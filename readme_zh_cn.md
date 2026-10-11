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
- ✅ 数据源：OSV作为主数据源，NVD补充标准CVSS、CWE信息
- ✅ 自动更新：GitHub Actions 定时任务自动拉取最新漏洞
- ✅ 纯静态前端：无需后端服务，可部署于 GitHub Pages / Cloudflare Pages
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
5. 静态网页前端加载vulns.json，在浏览器提供漏洞检索。
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
scabase-web 仓库中的静态前端可部署在：
- GitHub Pages
- Cloudflare Pages（推荐，自带全球 CDN 加速）
网站地址：https://scabase.roweb.cn
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
NIST 官方 CVE 库，提供标准 CVSS 评分、CWE 分类，需要 API 密钥
注意事项
1. OSV API 存在请求频率限制，大批量包扫描时建议在循环中增加休眠延时。
2. NVD API 为可选配置，无密钥时仅使用 OSV 数据，项目依旧可以正常运行。
3. 本项目仅用于漏洞信息查询，不执行漏洞利用、主动漏洞扫描动作。
4. 漏洞信息仅作为安全参考，不可直接作为合规审计的唯一依据。
许可证
MIT