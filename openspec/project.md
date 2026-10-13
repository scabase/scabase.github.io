# Project Context

## Purpose

ScaBase 是一套面向企业内网的开源软件成分（SCA）治理平台，覆盖两条主线：

1. **已知风险查询**：以 CVE 编号为主键查询开源组件的已知漏洞（OSV + NVD 富化）。
2. **开源引入评估**：在组件进入企业资产之前完成风险评分与准入决策，并按应用群组持续评估存量开源引入风险。

互联网侧负责采集与富化，内网侧负责评估与管控；两侧通过**单向离线数据摆渡**连接。

## Domain glossary

| 术语 | 含义 |
| --- | --- |
| **GAV** | Maven 坐标 `groupId:artifactId:version`，内网应用资产的主要表达形式 |
| **PURL** | Package URL（`pkg:maven/g/a@v`），跨生态统一组件坐标，本项目的主事实键 |
| **SBOM** | Software Bill of Materials，支持 SPDX 2.3 / CycloneDX 1.5 / Maven dependency:tree |
| **事实层（Fact Layer）** | 以 PURL 为主键、按数据源分片存储的规范化情报数据集 |
| **Bundle** | 一次离线摆渡的数据包，含 manifest、签名与增量链 |
| **App Group** | 内网应用群组（如支付群组、风控群组），风险评估的汇报单元 |
| **Intake Gate** | 开源引入前评估门禁，输出 Allow / Allow-with-condition / Deny / Exception |

## Conventions

- **前端**：ES5 风格 IIFE（`var` / `function`），无构建步骤，禁止引入需要编译的语法。
- **脚本**：Python 3，除 `requests` 外不引入第三方依赖；评分与同步必须可离线运行。
- **数据**：JSON；大文件 gzip；事实层按数据集分片，禁止全量单文件增长。
- **部署**：GitHub Pages（公网站点）+ Docker 内网镜像（`nginx:1.27-alpine`，监听 8080）。
- **测试**：Python `unittest`（引擎与管线）；前端用 jsdom + 桩 `fetch` 做 DOM 断言。

## Environment split

| 区域 | 能力 | 出站网络 |
| --- | --- | --- |
| Zone A（互联网） | 采集 OSV / NVD / KEV / 活跃度 / 许可证，富化，构建并签名 Bundle | 允许 |
| Zone B（内网） | 导入 Bundle，群组评估，引入前门禁，报告与回执 | 禁止 |

内网**不允许**任何直连公网的数据调用；未知组件在离线模式下必须给出显式“数据缺失”结论而非实时补全。
