# Delta for security-baseline

## ADDED Requirements

### Requirement: 声明式基线目录

系统 SHALL 内置一套覆盖常见开源软件的安全配置基线目录，同时支持维护的外部目录覆盖与追加。

- 每条基线项 MUST 包含：基线编号、适用组件、部署形态（`standalone` 独立运行 / `embedded` 依赖引入 / `any`）、类别、标题、严重级别、检查定义、修复建议、参考标准与 CWE。
- 覆盖范围 MUST 同时包含独立部署类（Redis、Nginx、Tomcat、Kafka、ZooKeeper、Elasticsearch、Nacos、MySQL、MongoDB、RabbitMQ、Docker、Jenkins 等）与依赖引入类（fastjson、log4j、Shiro、Struts、Spring Boot Actuator、XStream、Jackson 等）。
- 外部目录 MUST 按基线编号与内置条目合并（同 id 覆盖、新 id 追加）。
- 每条基线项 MUST 声明「合规状态」，即检查通过代表配置合规。

#### Scenario: 按组件匹配基线项

- GIVEN 事实层中存在 `log4j-core 2.14.1`
- WHEN 执行漏洞影响巡检
- THEN 匹配到「log4j-core 版本低于 2.17.1」基线项
- AND 输出其严重级别、修复建议与关联 CVE

#### Scenario: 追加自有基线

- GIVEN 外部目录中包含 `minio-root-credential` 条目
- WHEN 加载基线目录
- THEN 内置条目保持不变
- AND 外部条目按编号追加生效

### Requirement: 检查语义与判定算子

系统 SHALL 提供统一的检查执行引擎，支持对「环境快照」执行单条或批量检查，输出 PASS / FAIL / UNKNOWN 与判定依据。

- 检查类型 MUST 覆盖：配置文件键值（`config`）、命令行输出（`cli`）、HTTP 响应状态（`http`）、组件版本比较（`version`）、文件属性（`file`）。
- 判定算子 MUST 覆盖：`set`、`eq`、`ne`、`in`、`not_in`、`contains`、`not_contains`、`regex`、`not_regex`、`gte`、`gt`、`lte`、`lt`、`status`、`mode_not`、`absent`、`present`。
- 配置文件未声明某项时：对「必须有值 / 必须等于 / 必须包含 / 必须匹配」类断言 MUST 按空值判失败；其余算子 MUST 判 UNKNOWN 并提示人工确认默认值。
- 快照缺少对应数据时 MUST 返回 UNKNOWN，MUST NOT 默认判 PASS。

#### Scenario: 配置项未声明

- GIVEN `elasticsearch.yml` 中未声明 `xpack.security.enabled`
- WHEN 执行「必须为 true」的基线检查
- THEN 判定为 FAIL
- AND 依据说明为「未显式配置，按空值判定」

#### Scenario: 快照数据缺失

- GIVEN 快照中完全没有该配置文件
- WHEN 执行基线检查
- THEN 判定为 UNKNOWN 且依据说明缺失原因
- AND 准确率统计中 UNKNOWN 计入未检出
