# Delta for ai-script-generation

## ADDED Requirements

### Requirement: 面向平台的脚本生成

系统 SHALL 把基线项与漏洞描述自动转换为符合安全扫描平台规则的检查脚本，至少支持三类产出目标：

- `sreops`：SRE 运维平台巡检脚本（POSIX sh），末尾以单行 JSON 输出 `rule_id`/`status`/`severity`/`evidence`/`ts`，无论 PASS/FAIL 退出码均为 0；
- `codescan`：代码扫描中心规则包（YAML 规则 + 同名 Python 检测脚本，输出 SARIF 2.1.0 片段）；
- `python`：通用 Python 巡检脚本（仅标准库，支持 `--json`，只读检查）。

- 生成产物 MUST 保留基线编号与严重级别，判定语义 MUST 与基线目录一致。
- 生成产物 MUST 通过静态检查（shebang、STATUS 判定、JSON 输出、无破坏性指令、Python 语法可编译）方可落盘。
- 生成产物 MUST 输出 `manifest.json`，记录每条规则的产出文件、sha256、生成方式（模板 / 大模型）与审核状态。

#### Scenario: 生成 SRE 运维平台巡检脚本

- GIVEN 基线项 `redis-requirepass`（检查 redis.conf 中 requirepass 必须有值）
- WHEN 以 `sreops` 为目标生成脚本
- THEN 脚本为 POSIX sh 且包含 shebang、规则编号与修复建议注释
- AND 脚本读取配置文件、判定 PASS/FAIL 并输出单行 JSON
- AND 退出码恒为 0

#### Scenario: 生成代码扫描中心规则包

- GIVEN 基线项 `redis-requirepass`
- WHEN 以 `codescan` 为目标生成
- THEN 产出 YAML 规则（id 形如 `scabase-redis-requirepass`）与 Python 检测脚本
- AND Python 脚本可独立运行并输出 SARIF 2.1.0 片段

### Requirement: AI 智能体增强与安全回落

系统 SHALL 支持在配置大模型端点后由智能体对模板脚本做优化，未配置或调用失败时 MUST 回落到模板结果。

- 大模型调用 MUST 仅通过显式配置的端点发起，MUST NOT 在未配置时发起任何外部请求。
- 调用失败、超时或返回内容静态检查不通过时，系统 MUST 回落到模板引擎结果。
- 凡由大模型生成的产物 MUST 标记 `generated_by=llm` 与 `review_required=true`，MUST NOT 直接投入生产。
- 提示词 MUST 附带目标平台规范、基线项全文与模板基线脚本，并要求保持判定语义不变。

#### Scenario: 未配置大模型

- GIVEN 环境未配置 `SCABASE_LLM_ENDPOINT`
- WHEN 执行脚本生成
- THEN 不发起任何网络请求
- AND 全部产物标记为模板生成且通过静态检查

#### Scenario: 大模型返回不合规内容

- GIVEN 大模型返回的脚本缺少规则编号或包含高危指令
- WHEN 执行静态检查
- THEN 判定不通过并回落到模板产物
- AND manifest 中记录回落原因

### Requirement: 脚本准确率回归门禁

系统 SHALL 提供标注样本集回归校验，把「漏洞及基线扫描准确率达 90%」落成可度量的门禁指标。

- 样本集 MUST 包含规则编号、环境快照与人工标注的期望结论（PASS / FAIL）。
- 统计 MUST 输出总体准确率、逐规则准确率、漏报、误报与无法判定数量。
- UNKNOWN MUST 计入未检出（等价于漏检）。
- 准确率低于阈值（默认 90%）时，命令 MUST 以非零退出码失败，供 CI 阻断。

#### Scenario: 准确率达标

- GIVEN 样本集覆盖全部基线项且各含正反两例
- WHEN 执行回归校验
- THEN 输出总体准确率与逐规则明细
- AND 准确率 ≥ 90% 时退出码为 0

#### Scenario: 存在漏报

- GIVEN 某规则在「配置违规」样本上被误判为 PASS
- WHEN 执行回归校验
- THEN 该样本计入漏报
- AND 准确率随之下降，低于阈值时命令失败
