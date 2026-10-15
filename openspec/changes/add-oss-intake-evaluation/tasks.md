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

## Phase 9 — 引入阶段依赖关系自动化分析（落地）

- [x] 9.1 实现多生态原生依赖文件解析：`pom.xml`/gradle、npm 系（package.json/lock/yarn/pnpm）、PyPI 系（requirements/Pipfile/poetry/pyproject）、go.mod/go.sum、Cargo、Composer、Gemfile
- [x] 9.2 实现目录扫描与 PURL 去重聚合，跳过构建与依赖目录，单文件解析失败不中断扫描
- [x] 9.3 实现 `scan` CLI：输出 JSON/Markdown，并可一键生成资产台账条目（purls/gavs）
- [x] 9.4 单测：覆盖属性展开、依赖管理继承、锁定/未锁定、间接依赖、损坏文件容错

## Phase 10 — 社区支持力度评价

- [x] 10.1 实现 `community.py`：0-100 分 + A/B/C/D 等级 + 逐项扣分依据 + missing 清单
- [x] 10.2 接入评分引擎：评分卡与 Markdown 报告输出等级与治理建议
- [x] 10.3 策略支持 `community_deny_grades` 配置为硬阻断
- [x] 10.4 健康度采集补充治理信号（安全响应策略 / CI / 背书组织 / 下游依赖数 / 下载量）

## Phase 11 — 安全配置基线与 AI 脚本生成

- [x] 11.1 实现 `baseline.py`：声明式基线目录（32 条内置）+ 外部目录合并 + 检查执行引擎（PASS/FAIL/UNKNOWN）
- [x] 11.2 实现 `scriptgen.py`：SRE 运维平台 sh 巡检脚本、代码扫描中心 YAML 规则 + Python 检测脚本、通用 Python 巡检脚本
- [x] 11.3 实现 LLM 增强与安全回落（`SCABASE_LLM_ENDPOINT`），产物标记 `generated_by` 与 `review_required`
- [x] 11.4 实现 `verify.py`：标注样本集回归校验，准确率门禁默认 90%，UNKNOWN 计入漏检
- [x] 11.5 实现 `genscript` / `verify` / `baseline` CLI 与 `manifest.json` 产物
- [x] 11.6 单测：算子判定、快照缺失、脚本 lint、准确率达标与漏报识别

## Phase 12 — 漏洞影响范围自动化巡检

- [x] 12.1 实现 `patrol.py`：按应用聚合受影响组件、CVE、基线待检项与风险分
- [x] 12.2 实现结构化工单输出（严重级别、整改期限、建议版本、关联基线编号）
- [x] 12.3 实现增量巡检对比（新增 / 未修复 / 已闭环）与状态持久化
- [x] 12.4 实现跨应用共性风险识别（≥2 个应用共用）
- [x] 12.5 实现 `patrol` CLI：JSON / Markdown / 工单文件 / 状态文件
- [x] 12.6 单测：应用聚合、工单优先级、增量对比、共性风险

## Phase 13 — 工具链对接

- [x] 13.1 实现 `integrations/depinfo.py`：台账导入（purl/gav/eco 三形态）→ 资产模型；结论回传（默认脱敏）+ HTTP 推送
- [x] 13.2 资产模型扩展：应用支持 `gavs` / `purls`，无需 SBOM 文件即可建 inventory
- [x] 13.3 实现 `integrations/cicd.py`：SARIF 2.1.0、JUnit XML、MR/PR 评论 Markdown、四档退出码
- [x] 13.4 实现 `depinfo` CLI 与 gate 的 `--sarif` / `--junit` / `--comment` 选项
- [x] 13.5 单测：台账转换、脱敏回传、SARIF 结构、JUnit 失败计数、退出码语义

## Phase 14 — 待执行（需在具备命令行的环境完成）

- [ ] 14.1 运行全量单测：`python -m unittest discover -s tests`，确认新增用例与原有 51 条用例全绿
- [ ] 14.2 用真实 `vulns.json` 跑通 `scan → inventory → patrol → genscript → verify` 全链路演示并归档报告
- [ ] 14.3 在 CI 中接入 `verify` 准确率门禁（阈值 0.9）与 `genscript` manifest 校验
- [ ] 14.4 按 `examples/baseline-catalog.json` 范式补充自有组件基线（MinIO、Consul、K8s、Harbor 等）

## Phase 15 — 命名统一与社区采集 CI（2026-10-15）

- [x] 15.1 SPMS 更名为 DEPINFO：模块 `integrations/depinfo.py`、CLI 子命令 `depinfo`、环境变量 `SCABASE_DEPINFO_URL` / `SCABASE_DEPINFO_TOKEN`、回传 schema `depinfo-result/v1`
- [x] 15.2 eops 更名为 sreops：`scriptgen.TARGETS`、平台规范文案、目录注释与全部文档
- [x] 15.3 新增 `.github/workflows/community-health.yml`：每日采集社区支持力度与活跃度信号（GitHub / deps.dev / npm registry），写入事实层并产出汇总报告
- [x] 15.4 新增 `scabase-fetcher/scripts/community_report.py`：社区支持力度汇总（0-100 分 + A/B/C/D 等级分布 + 缺失信号统计）
- [x] 15.5 新增 `scabase-fetcher/data/repo-map.json`：purl → owner/repo 显式映射（非 go 生态必须登记才能拿到 GitHub 治理信号）
- [x] 15.6 修正 `build_facts.py`：只为本轮真正写入的数据集刷新水位，避免把未采集的数据集标记为新鲜
- [x] 15.7 新增 `tests/test_community_collection.py`：覆盖组织背书分类、仓库推断、汇总渲染与缺失信号统计
- [ ] 15.8 待执行验证：`python -m unittest discover -s tests`（本次会话无命令行工具，未实际运行）

## Phase 16 — 仓库自身依赖面治理（2026-10-15）

- [x] 16.1 定位 60 条 Dependabot 告警来源：全部来自 `examples/deps/` 教学样本（故意选的漏洞版本），仓库真实第三方依赖只有 `requests`
- [x] 16.2 `depfile` 支持 `.sample` / `.example` / `.tmpl` / `.fixture` / `.tpl` 后缀（`canonical_name()` 剥离后识别），样本不再被 Dependabot / 依赖图解析
- [x] 16.3 样本内容迁至 `examples/deps/*.sample`，同名清单替换为零依赖空壳，并补 `examples/deps/README.md` 说明两套文件的用途
- [x] 16.4 新增 `scabase-fetcher/requirements.txt`（`requests==2.32.4`，CVE-2024-47081 修复版）并把 `pypi|requests|2.32.4` 加入 `pkg_list.txt`
- [x] 16.5 新增 `.github/dependabot.yml`：仅管理 `github-actions` 与 `pip`（scabase-fetcher）两个生态
- [x] 16.6 新增 `.github/workflows/self-scan.yml`：用本项目门禁引擎自查自身依赖，命中 Deny 阻断；事实层未覆盖的自身依赖以 `::warning::` 暴露盲区
- [x] 16.7 修复 `gate --sbom` 对 `pom.xml` 等 XML 清单静默解析出 0 个组件而放行的问题：优先走 `depfile`，零组件时返回退出码 2
- [x] 16.8 测试：`.sample` 后缀识别、空壳清单零依赖断言、目录跳过 node_modules/target、gate 原生文件与零组件拒绝、自身 requirements 门禁
- [ ] 16.9 待执行验证：`python -m unittest discover -s tests`（本次会话无命令行工具，未实际运行）
