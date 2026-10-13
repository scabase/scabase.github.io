# Delta for offline-ferry-sync

## ADDED Requirements

### Requirement: 数据包结构

系统 SHALL 产出带 `manifest.json` 的数据包，manifest 至少包含：
`schema`、`dataset`、`seq`、`mode`（`delta` / `snapshot`）、`generated_at`、
`source_watermark`、`prev_digest`、`files[]`（path / sha256 / size / op）与 `signature`。

- 每个数据集 SHALL 使用独立、单调递增的 `seq`。
- 数据包 SHALL 不包含任何内网资产数据。

#### Scenario: 构建漏洞数据集增量包

- GIVEN 事实层中 vulns 数据集当前 seq 为 1233
- WHEN 本轮采集产生变更
- THEN 产出 seq 为 1234、mode 为 delta 的数据包
- AND manifest 中 `prev_digest` 指向 1233 包的摘要

### Requirement: 签名与验签

系统 SHALL 对 manifest 进行 ed25519 签名，并 SHALL 在内网导入前完成验签。

- 验签失败 SHALL 拒绝导入，且 MUST NOT 修改任何已导入数据。
- 签名 SHALL 携带 `keyid` 以支持密钥轮换。

#### Scenario: 验签失败拒绝导入

- GIVEN 一个签名被篡改的数据包
- WHEN 内网执行导入
- THEN 导入中止并返回错误
- AND 已导入的数据保持原状

### Requirement: 防回滚

系统 SHALL 校验 `prev_digest` 链，并 SHALL 拒绝导入 `seq` 小于或等于当前已导入 seq 的数据包。

#### Scenario: 导入过期数据包

- GIVEN 内网已导入 seq 为 1234 的数据包
- WHEN 导入 seq 为 1200 的数据包
- THEN 导入被拒绝
- AND 返回 seq 回退错误

### Requirement: 原子导入

系统 SHALL 采用“写入临时目录 → 校验全部文件 sha256 → 原子切换”的方式导入，
任一校验失败 SHALL 保留上一版本数据。

#### Scenario: 导入中断

- GIVEN 数据包中某个文件哈希不匹配
- WHEN 执行导入
- THEN 切换未发生
- AND 上一版本数据保持可用

### Requirement: 状态与回执

系统 SHALL 在内网维护 `state.json` 记录每个数据集的 seq 与摘要，
并 SHALL 在导入成功后生成**脱敏**接收回执（导入 seq、数据集水位、评估执行次数、结论计数）。

- 回执 MUST NOT 包含 GAV 清单、源代码、内网拓扑或应用名称。

#### Scenario: 生成回执

- GIVEN 一次导入成功完成
- WHEN 生成回执
- THEN 回执仅包含数据集 seq、水位与聚合计数
- AND 回执可被反向摆渡回互联网侧用于水位对齐

### Requirement: 全量校准

系统 SHALL 支持 `mode=snapshot` 全量包，用于首次部署、季度校准与 seq 链断裂后的恢复。

#### Scenario: seq 链断裂后恢复

- GIVEN 内网 state 中记录 `prev_digest` 与待导入包不一致
- WHEN 导入一个 `mode=snapshot` 的全量包
- THEN 忽略链校验完成导入
- AND state 重置为该 snapshot 的 seq 与摘要
