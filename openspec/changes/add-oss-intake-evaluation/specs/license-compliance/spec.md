# Delta for license-compliance

## ADDED Requirements

### Requirement: 许可证识别与分类

系统 SHALL 识别组件声明的 SPDX 许可证，并归入以下类别之一：
`permissive`（MIT/BSD/Apache 等）、`weak-copyleft`（LGPL/MPL/EPL 等）、
`strong-copyleft`（GPL/AGPL/SSPL 等）、`business-source`（BSL 等）、`unknown`/`undeclared`。

- 声明为多许可证时 SHALL 取**限制最强**的一项作为判定依据。
- 无法识别或缺失声明 SHALL 归入 `unknown` 并触发人工复核。

#### Scenario: 多许可证取最严

- GIVEN 组件声明 `MIT OR GPL-3.0`
- WHEN 判定许可证类别
- THEN 归类为 `strong-copyleft`

#### Scenario: 缺失许可证声明

- GIVEN 组件无任何许可证声明
- WHEN 判定许可证类别
- THEN 归类为 `unknown`
- AND 报告中给出人工复核要求

### Requirement: 合规策略比对

系统 SHALL 支持按用途配置许可证策略（如闭源分发、内部服务、SaaS），
当组件许可证与用途策略冲突时 SHALL 判定为硬阻断项。

- 策略 SHALL 可通过配置文件扩展，MUST NOT 硬编码在评分代码中。

#### Scenario: 强传染性许可用于闭源分发

- GIVEN 用途为闭源分发，策略禁止 `strong-copyleft`
- WHEN 评估一个 GPL-3.0 组件
- THEN 命中许可证硬阻断
- AND 结论为 `Deny`

#### Scenario: 同一组件用于内部服务

- GIVEN 用途为内部服务，策略允许 `strong-copyleft`
- WHEN 评估同一个 GPL-3.0 组件
- THEN 不命中许可证硬阻断
- AND 评分中保留许可证维度的提示性分值
