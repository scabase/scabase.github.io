"""ScaBase 开源引入评估引擎。

模块划分：
  purl         PURL 归一化（跨生态统一主键）
  sbom         SBOM / 依赖清单摄入
  depfile      原生依赖文件解析（pom / package.json / requirements / go.mod …）
  facts        事实层读写（按数据集分片）
  policy       评估策略与许可证合规矩阵
  scoring      四维风险评分引擎
  community    社区支持力度评价
  baseline     安全配置基线目录与检查执行
  scriptgen    检查脚本生成（模板 / LLM 增强 / 静态检查）
  verify       生成脚本准确率回归校验
  patrol       漏洞影响范围巡检与工单
  assets       内网应用群组资产与影响半径
  assessment   应用群组风险聚合
  sync         离线摆渡同步（构建 / 签名 / 导入 / 回执）
  report       JSON / Markdown 报告
  cli          命令行入口
  integrations 工具链对接（depinfo / CICD）

评分、同步、脚本生成与巡检路径仅依赖 Python 标准库，可在无公网出口的内网运行。
"""

__version__ = "0.2.0"
