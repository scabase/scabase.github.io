"""ScaBase 开源引入评估引擎。

模块划分：
  purl        PURL 归一化（跨生态统一主键）
  sbom        SBOM / 依赖清单摄入
  facts       事实层读写（按数据集分片）
  policy      评估策略与许可证合规矩阵
  scoring     四维风险评分引擎
  assets      内网应用群组资产与影响半径
  assessment  应用群组风险聚合
  sync        离线摆渡同步（构建 / 签名 / 导入 / 回执）
  report      JSON / Markdown 报告
  cli         命令行入口

评分与同步路径仅依赖 Python 标准库，可在无公网出口的内网运行。
"""

__version__ = "0.1.0"
