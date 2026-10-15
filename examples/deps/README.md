# examples/deps — 原生依赖文件样本

这里放**两套**文件，用途完全不同，不要混用：

| 文件 | 用途 |
| --- | --- |
| `pom.xml` / `package.json` / `requirements.txt` / `go.mod` / `yarn.lock` | **零依赖空壳**，只为让仓库自身的依赖面保持干净。本仓库没有 Maven / npm / Go 运行时依赖，这些清单不声明任何依赖。 |
| `*.sample`（`pom.xml.sample` 等） | **教学样本**，包含故意挑选的漏洞版本（fastjson 1.2.24、log4j 2.14.1、axios 0.21.1、lodash 4.17.20、requests 2.31.0、gin 1.7.7 …），用于演示 `oss_intake.cli scan` 的解析与评估能力。 |

## 为什么样本要带 `.sample` 后缀

GitHub 的 Dependabot 与依赖图会解析仓库里所有符合命名规范的清单文件。把漏洞版本样本直接命名成
`pom.xml` / `package.json`，会让仓库凭空多出几十条安全告警（本仓库曾因此出现 60 条：
4 critical / 23 high / 30 moderate / 3 low），而这些版本**本来就是故意选的**。

`oss_intake/depfile.py` 的 `classify()` 会先经 `canonical_name()` 剥掉
`.sample` / `.example` / `.tmpl` / `.fixture` / `.tpl` 后缀再匹配，
所以带后缀的样本依然能被 `scan` 正常解析，只是不会被外部依赖图识别。

## 用法

```bash
# 扫描教学样本（单个文件或整个目录均可）
python -m oss_intake.cli scan --path examples/deps/pom.xml.sample
python -m oss_intake.cli scan --path examples/deps --md reports/scan.md

# 仓库自身的真实依赖面只有这一处：
#   scabase-fetcher/requirements.txt  → requests（唯一第三方运行时依赖）
```
