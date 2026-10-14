# Delta for native-dependency-parsing

## ADDED Requirements

### Requirement: 多生态原生依赖文件解析

系统 SHALL 直接解析开发态依赖声明文件，无需先由外部工具产出 SBOM，至少覆盖：

- Maven：`pom.xml`（含 `${property}` 占位符展开、`dependencyManagement` 版本继承、`<modules>` 多模块识别）、`build.gradle(.kts)`、`gradle.lockfile`；
- npm：`package.json`、`package-lock.json`（v1/v2/v3）、`npm-shrinkwrap.json`、`yarn.lock`、`pnpm-lock.yaml`；
- PyPI：`requirements.txt`（含 `==`/`>=`/`~=` 等约束）、`Pipfile.lock`、`poetry.lock`、`pyproject.toml`（PEP 621 与 `[tool.poetry.dependencies]`）；
- Go：`go.mod`（含 `// indirect` 标记）、`go.sum`；
- 其他：`Cargo.lock`/`Cargo.toml`、`composer.json`/`composer.lock`、`Gemfile.lock`。

- 每条依赖 MUST 归一为 PURL，作为事实层与评分引擎的唯一主键。
- 解析结果 MUST 区分直接依赖与传递依赖，并保留原始版本约束与是否已锁定具体版本。
- 单个文件解析失败 MUST NOT 中断整目录扫描，失败项须进入「未解析清单」并给出原因。

#### Scenario: Maven 属性占位符与依赖管理

- GIVEN `pom.xml` 中 `<version>${fastjson.version}</version>`，且 `<properties>` 与 `dependencyManagement` 均提供版本
- WHEN 解析该 pom
- THEN 产出 `pkg:maven/com.alibaba/fastjson@1.2.24` 形式的 PURL
- AND 未声明 version 的依赖从 `dependencyManagement` 继承版本
- AND `<modules>` 中的子模块被单独列出

#### Scenario: npm 锁定文件区分直接与传递依赖

- GIVEN 存在 `package-lock.json`（v3，`packages` 中根条目声明依赖）
- WHEN 解析该文件
- THEN 根依赖与一级 `node_modules/` 条目标记为直接依赖
- AND 嵌套 `node_modules/` 下的条目标记为传递依赖
- AND dev 依赖被标记 dev 作用域

#### Scenario: PyPI 范围约束与未锁定条目

- GIVEN `requirements.txt` 同时包含 `requests==2.31.0`、`flask>=2.0.0` 与 `attrs`
- WHEN 解析该文件
- THEN 前两条产出 PURL 且 `flask` 的「已锁定」标记为否
- AND `attrs` 进入未解析清单，原因为版本约束无法锁定

#### Scenario: 损坏文件不中断扫描

- GIVEN 目录中某 `pom.xml` 为非法 XML
- WHEN 执行目录扫描
- THEN 该文件进入未解析清单且原因包含「解析失败」
- AND 其余依赖文件的解析结果完整返回

### Requirement: 源码目录扫描与资产台账生成

系统 SHALL 支持递归扫描源码目录，聚合所有依赖文件为一份去重后的组件清单，并可一键转为资产台账条目。

- 扫描 SHALL 跳过 `.git`、`node_modules`、`target`、`build`、`dist`、`vendor` 等构建与依赖目录。
- 扫描深度 SHALL 可配置，默认 6 层。
- 扫描结果 MUST 按 PURL 去重，直接依赖优先保留。
- 转换出的资产台账条目 MUST 可直接用于 `inventory` 摄入与 depinfo 回传格式。

#### Scenario: 扫描多语言仓库

- GIVEN 仓库同时包含 `pom.xml`、`package.json`、`requirements.txt`、`go.mod`
- WHEN 执行目录扫描
- THEN 报告识别到 4 类格式与各自组件数
- AND 输出按 PURL 去重的统一组件清单
- AND 可生成含 `purls` 与 `gavs` 的应用台账条目
