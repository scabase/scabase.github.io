"""工具链对接：depinfo 与 CICD。

- `depinfo`：把 depinfo 组件台账（应用 ↔ GAV/PURL）转成评估侧资产模型，
  并把评估结论回传给 depinfo（支持脱敏，禁止外泄应用名与内网拓扑）。
- `cicd`：把门禁结论转成流水线可直接消费的产物（SARIF 2.1.0、JUnit XML、
  MR/PR 评论 Markdown）与退出码语义。

零第三方依赖（HTTP 走 urllib）。
"""
