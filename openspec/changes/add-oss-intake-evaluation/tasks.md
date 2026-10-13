# Tasks: 开源引入评估体系

## Phase 1 — 事实层与归一化

- [ ] 1.1 定义 `facts/` 目录结构、`meta.json` schema 与组件记录 schema
- [ ] 1.2 实现 PURL 构造与解析（maven/npm/pypi/go/cargo/gem/nuget）及 GAV 投影
- [ ] 1.3 实现 SBOM 摄入器：CycloneDX 1.5、SPDX 2.3、`mvn dependency:tree`、lock 文件
- [ ] 1.4 实现应用群组资产模型（group → app → component，含重要性/暴露面/敏感度）
- [ ] 1.5 将现有 `vulns.json` 迁移为 `facts/vulns` 数据集，保留兼容视图

## Phase 2 — 互联网采集

- [ ] 2.1 扩展采集器：KEV 与 EPSS 拉取并入事实层
- [ ] 2.2 实现组件活跃度采集（deps.dev + GitHub API + registry 元数据，含限流退避）
- [ ] 2.3 实现许可证采集与 SPDX 传染性分类
- [ ] 2.4 采集结果按数据集分片落盘并更新 `meta.json` 水位
- [ ] 2.5 采集失败降级：单源失败不得清空已有数据

## Phase 3 — 评分引擎与门禁

- [ ] 3.1 实现四维评分（V 漏洞 / M 健康度 / L 许可 / B 业务影响）与权重配置
- [ ] 3.2 实现硬阻断规则与决策矩阵（Allow / Allow-with-condition / Review / Deny / Exception）
- [ ] 3.3 实现数据陈旧度 → 置信度 → 评分上调与结论降级
- [ ] 3.4 实现应用群组聚合评分与共性风险识别
- [ ] 3.5 实现 `gate` 门禁 CLI（读 SBOM，输出 JSON/Markdown 报告，退出码语义）
- [ ] 3.6 实现 `assess` 群组评估 CLI 与报告

## Phase 4 — 离线摆渡同步

- [ ] 4.1 实现 Bundle 构建：manifest、逐文件 sha256、seq 链、`prev_digest`
- [ ] 4.2 实现 ed25519 签名与验签（密钥轮换与 keyid）
- [ ] 4.3 实现内网导入：验签、防回滚、逐文件校验、原子切换、`state.json`
- [ ] 4.4 实现 snapshot 全量校准与 seq 链断裂恢复
- [ ] 4.5 实现脱敏接收回执生成

## Phase 5 — 前端评估台

- [ ] 5.1 新增 `intake.html`：候选组件输入与评分卡展示（ES5 IIFE）
- [ ] 5.2 新增应用群组总览视图（评分卡、Top 风险组件、共性风险）
- [ ] 5.3 展示数据水位与陈旧度提示
- [ ] 5.4 离线模式下禁止任何外部请求

## Phase 6 — 构建交付

- [ ] 6.1 新增 `.github/workflows/intake-sync.yml`：每日采集 → 构建签名 Bundle → 发布产物
- [ ] 6.2 扩展 `docker.yml` 打包事实层与评估台
- [ ] 6.3 内网 compose 编排：定时导入 + 评估任务 + 报告卷
- [ ] 6.4 更新 `readme.md` / `readme_zh_cn.md` 与内网部署文档

## Phase 7 — 测试

- [ ] 7.1 引擎单测：维度边界、封顶、硬阻断、决策阈值、置信度降级
- [ ] 7.2 同步单测：验签失败、seq 回滚拒绝、哈希不匹配、原子切换回滚
- [ ] 7.3 采集单测：三种 SBOM fixture → PURL 归一断言
- [ ] 7.4 端到端冒烟：构建 Bundle → 导入 → 评估，全流程无网络
- [ ] 7.5 前端 jsdom 测试：评估台渲染

## Phase 8 — 归档

- [ ] 8.1 更新基线 specs，执行 `openspec archive` 合并 delta
