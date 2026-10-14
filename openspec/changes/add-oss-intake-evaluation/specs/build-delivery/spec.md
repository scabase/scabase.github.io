# Delta for build-delivery

## ADDED Requirements

### Requirement: 互联网侧流水线

系统 SHALL 提供每日执行的互联网流水线，完成：多源采集 → 事实层写入 → 构建增量 Bundle → 签名 → 发布产物。

- 流水线 SHALL 在采集源全部失败时保留上一轮产物并标记失败，MUST NOT 发布空数据包。
- 签名密钥 SHALL 由流水线密钥管理，MUST NOT 出现在仓库明文文件中。

#### Scenario: 采集全失败不发空包

- GIVEN 本轮所有外部情报源均不可用
- WHEN 流水线执行到发布阶段
- THEN 不产出新数据包
- AND 流水线标记为失败并告警

### Requirement: 内网侧交付

内网镜像 SHALL 同时承载事实层数据与评估台页面，并在容器启动时按环境变量生成运行时配置。

- 运行时配置 SHALL 至少支持：离线开关、事实层根路径、群组资产路径、数据陈旧度阈值。
- 内网流水线 SHALL 产出镜像与可 `docker load` 的 tar 离线包。

#### Scenario: 配置事实层路径

- GIVEN 环境变量 `SCABASE_FACTS_DIR=/data/facts`
- WHEN 容器启动
- THEN 生成的运行时配置中事实层根路径为该值
- AND 评估台从该路径加载数据

### Requirement: 定时导入任务

内网部署 SHALL 提供定时导入任务，扫描指定目录中的数据包并按 seq 顺序导入，导入结果写入回执目录。

#### Scenario: 批量导入

- GIVEN 摆渡目录中存在三个数据集的多个数据包
- WHEN 定时导入任务执行
- THEN 按各数据集 seq 升序导入
- AND 为每个成功导入的包生成回执

### Requirement: 测试门禁

构建 SHALL 在发布前执行引擎单测、同步单测与端到端冒烟，任一失败 MUST 阻断发布。

#### Scenario: 单测失败阻断发布

- GIVEN 评分引擎某个单测失败
- WHEN 流水线执行到发布阶段
- THEN 发布被阻断
- AND 流水线输出失败的用例名称

### Requirement: 脚本准确率门禁与产物归档

互联网侧构建 SHALL 在发布前执行基线/漏洞检测脚本的准确率回归，并将生成的脚本与回归报告作为产物归档。

- 准确率回归 MUST 使用标注样本集，默认阈值 90%，未达标 MUST 阻断发布。
- 生成脚本 MUST 全部通过静态检查后才允许归档。
- 产物 MUST 包含各目标的 `manifest.json`、脚本正文与准确率报告。

#### Scenario: 准确率未达标

- GIVEN 样本集回归准确率为 87%
- WHEN 流水线执行到准确率门禁
- THEN 流水线失败并输出准确率与阈值
- AND 不产出脚本归档产物

#### Scenario: 脚本静态检查失败

- GIVEN 某条生成脚本缺少 shebang 或包含高危指令
- WHEN 执行脚本生成与静态检查
- THEN 该规则标记 `lint_ok=false` 并记录问题
- AND 命令以非零退出码结束，阻断归档
