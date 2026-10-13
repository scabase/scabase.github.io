"""报告渲染：JSON 与 Markdown 两种形态，供审批归档与 CI 摘要使用。

零第三方依赖。
"""
import json
import os
import time

CONCLUSION_ORDER = {"Deny": 0, "Review": 1, "Allow-with-condition": 2, "Allow": 3}


def _stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def to_json(payload, path=None):
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False)
    if path:
        _ensure_parent(path)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    return text


def _table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def render_gate_markdown(result, confidence_report=None, source=None):
    lines = ["# 开源引入评估 · 门禁报告", ""]
    lines.append("- 生成时间：%s" % _stamp())
    if source:
        lines.append("- 评估对象：%s" % source)
    lines.append("- 用途策略：%s" % result.get("profile"))
    lines.append("")

    if confidence_report:
        lines.append("## 数据水位")
        lines.append("")
        rows = []
        for name, info in sorted(confidence_report.items()):
            age = info.get("age_days")
            rows.append([
                name,
                "—" if age is None else "%.1f 天" % age,
                "%.2f" % info.get("confidence", 0),
                info.get("generated_at") or "—",
            ])
        lines.append(_table(["数据集", "陈旧度", "置信度", "生成时间"], rows))
        lines.append("")

    lines.append("## 结论")
    lines.append("")
    lines.append("- **%s**（评分 %.2f）" % (result.get("conclusion"), result.get("score", 0)))
    if result.get("hard_blocks"):
        lines.append("- 硬阻断项：")
        for item in result["hard_blocks"]:
            lines.append("  - %s" % item)
    if result.get("warnings"):
        lines.append("- 提示项：")
        for item in result["warnings"]:
            lines.append("  - %s" % item)
    if result.get("suggested_version"):
        lines.append("- 建议版本：**%s**" % result["suggested_version"])
    if result.get("review_due"):
        lines.append("- 复审到期日：%s" % result["review_due"])
    lines.append("")

    lines.append("## 分项评分")
    lines.append("")
    rows = []
    for name, dim in (result.get("dimensions") or {}).items():
        rows.append([
            name,
            dim.get("score"),
            dim.get("raw"),
            dim.get("weight"),
            "%.2f" % dim.get("confidence", 0),
        ])
    lines.append(_table(["维度", "调整后", "原始", "满分", "置信度"], rows))
    lines.append("")
    for name, dim in (result.get("dimensions") or {}).items():
        lines.append("**%s**" % name)
        for note in dim.get("notes") or []:
            lines.append("- %s" % note)
        lines.append("")
    return "\n".join(lines)


def render_multi_markdown(results, confidence_report=None, source=None):
    lines = ["# 开源引入评估 · 批量门禁报告", ""]
    lines.append("- 生成时间：%s" % _stamp())
    if source:
        lines.append("- 评估对象：%s" % source)
    lines.append("")

    counts = {}
    for result in results:
        counts[result["conclusion"]] = counts.get(result["conclusion"], 0) + 1
    lines.append("## 概要")
    lines.append("")
    for name in sorted(counts, key=lambda k: CONCLUSION_ORDER.get(k, 9)):
        lines.append("- %s：%d" % (name, counts[name]))
    lines.append("")

    if confidence_report:
        lines.append("## 数据水位")
        lines.append("")
        rows = [[name,
                 "—" if info.get("age_days") is None else "%.1f 天" % info["age_days"],
                 "%.2f" % info.get("confidence", 0)]
                for name, info in sorted(confidence_report.items())]
        lines.append(_table(["数据集", "陈旧度", "置信度"], rows))
        lines.append("")

    ordered = sorted(results, key=lambda r: (CONCLUSION_ORDER.get(r["conclusion"], 9),
                                             -r.get("score", 0)))
    lines.append("## 组件明细")
    lines.append("")
    rows = []
    for result in ordered:
        rows.append([
            result.get("display") or result.get("purl"),
            result.get("score"),
            result.get("conclusion"),
            "；".join(result.get("hard_blocks") or []) or "—",
            result.get("suggested_version") or "—",
        ])
    lines.append(_table(["组件", "评分", "结论", "硬阻断项", "建议版本"], rows))
    lines.append("")
    return "\n".join(lines)


def render_group_markdown(assessment, confidence_report=None):
    lines = ["# 应用群组开源引入风险评估：%s" % assessment.get("group"), ""]
    lines.append("- 生成时间：%s" % _stamp())
    lines.append("- **群组分值：%.2f**" % assessment.get("group_score", 0))
    lines.append("- 组件总数：%d" % assessment.get("component_count", 0))
    lines.append("- 最差单点：%.2f / 加权平均：%.2f" % (
        assessment.get("worst_component_score", 0), assessment.get("weighted_average", 0)))
    lines.append("")

    counts = assessment.get("conclusion_counts") or {}
    if counts:
        lines.append("## 结论分布")
        lines.append("")
        for name in sorted(counts, key=lambda k: CONCLUSION_ORDER.get(k, 9)):
            lines.append("- %s：%d" % (name, counts[name]))
        lines.append("")

    lines.append("## 维度分解")
    lines.append("")
    rows = [[name, value] for name, value in (assessment.get("dimension_breakdown") or {}).items()]
    lines.append(_table(["维度", "平均分"], rows))
    lines.append("")

    lines.append("## Top 风险组件")
    lines.append("")
    rows = [[item["display"], item["score"], item["conclusion"]]
            for item in assessment.get("top_risks") or []]
    lines.append(_table(["组件", "评分", "结论"], rows) if rows else "_无_")
    lines.append("")

    lines.append("## 共性风险（≥3 个应用共用且评分 ≥55）")
    lines.append("")
    common = assessment.get("common_risks") or []
    if common:
        rows = [[item["display"], item["score"], item["apps"], item["conclusion"]]
                for item in common]
        lines.append(_table(["组件", "评分", "影响应用数", "结论"], rows))
    else:
        lines.append("_无_")
    lines.append("")
    return "\n".join(lines)
