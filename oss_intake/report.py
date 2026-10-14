"""报告渲染：JSON 与 Markdown 两种形态，供审批归档与 CI 摘要使用。

零第三方依赖。
"""
import json
import os
import time

from . import purl

CONCLUSION_ORDER = {"Deny": 0, "Review": 1, "Allow-with-condition": 2, "Allow": 3}


def _display(purl_value):
    return purl.display_of(purl_value) if purl_value else "—"


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
    community = result.get("community")
    if community:
        lines.append("- 社区支持力度：**%s 级（%.0f/100）** — %s" % (
            community.get("grade"), community.get("score", 0), community.get("advice")))
        for factor in (community.get("factors") or [])[:5]:
            lines.append("  - %s（%+.0f）" % (factor.get("factor"), factor.get("impact", 0)))
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


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def render_scan_markdown(scan):
    lines = ["# 原生依赖文件扫描结果", ""]
    lines.append("- 生成时间：%s" % _stamp())
    lines.append("- 扫描根路径：%s" % scan.get("root"))
    lines.append("- 组件总数：%d" % len(scan.get("components") or []))
    lines.append("- 未解析条目：%d" % len(scan.get("unresolved") or []))
    lines.append("")

    lines.append("## 识别到的依赖文件")
    lines.append("")
    rows = [[item.get("path"), item.get("eco"), item.get("format"),
             item.get("components"), item.get("unresolved")]
            for item in scan.get("files") or []]
    lines.append(_table(["文件", "生态", "格式", "组件数", "未解析"], rows) if rows else "_无_")
    lines.append("")

    lines.append("## 直接依赖明细")
    lines.append("")
    rows = []
    for comp in scan.get("components") or []:
        if not comp.get("direct"):
            continue
        rows.append([_display(comp.get("purl")), comp.get("version_req") or "—",
                     "是" if comp.get("pinned") else "否", comp.get("scope") or "—"])
    lines.append(_table(["组件", "版本约束", "已锁定", "作用域"], rows) if rows else "_无_")
    lines.append("")

    unresolved = scan.get("unresolved") or []
    if unresolved:
        lines.append("## 未解析条目（需人工确认）")
        lines.append("")
        rows = [[item.get("file") or "—", item.get("name"), item.get("reason")]
                for item in unresolved[:30]]
        lines.append(_table(["文件", "条目", "原因"], rows))
        lines.append("")
    return "\n".join(lines)


def render_baseline_markdown(payload):
    lines = ["# 开源软件安全配置基线", ""]
    lines.append("- 生成时间：%s" % _stamp())
    if "results" in payload:
        results = payload["results"]
        lines.append("- 执行条目：%d" % len(results))
        lines.append("")
        counts = {}
        for item in results:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        for status in ("FAIL", "PASS", "UNKNOWN"):
            if counts.get(status):
                lines.append("- %s：%d" % (status, counts[status]))
        lines.append("")
        rows = []
        for item in sorted(results, key=lambda i: (_SEVERITY_ORDER.get(i.get("severity"), 9),
                                                   i.get("id") or "")):
            rows.append([item.get("id"), item.get("severity"), item.get("status"),
                         item.get("evidence") or "—", item.get("remediation") or "—"])
        lines.append(_table(["基线项", "级别", "状态", "依据", "修复建议"], rows))
    else:
        items = payload.get("items") or []
        lines.append("- 基线条目：%d" % len(items))
        lines.append("")
        rows = [[item.get("id"), item.get("component"), item.get("deploy"),
                 item.get("category"), item.get("severity"), item.get("title")]
                for item in sorted(items, key=lambda i: (_SEVERITY_ORDER.get(
                    i.get("severity"), 9), i.get("id") or ""))]
        lines.append(_table(["基线项", "组件", "部署形态", "类别", "级别", "说明"], rows))
    lines.append("")
    return "\n".join(lines)


def render_patrol_markdown(payload):
    lines = ["# 开源软件漏洞影响与基线巡检报告", ""]
    lines.append("- 生成时间：%s" % payload.get("generated_at") or _stamp())
    lines.append("- 应用数：%d" % len(payload.get("apps") or []))
    tickets = payload.get("tickets") or []
    critical = len([t for t in tickets if t.get("severity") == "critical"])
    high = len([t for t in tickets if t.get("severity") == "high"])
    lines.append("- 待处理工单：%d（紧急 %d / 高危 %d）" % (len(tickets), critical, high))
    lines.append("")

    delta = payload.get("delta") or {}
    if delta.get("previous_at"):
        lines.append("## 增量对比（对比基准 %s）" % delta["previous_at"])
        lines.append("")
        lines.append("- 新增风险项：%d" % len(delta.get("new") or []))
        lines.append("- 已修复闭环：%d" % len(delta.get("fixed") or []))
        lines.append("- 仍未修复：%d" % len(delta.get("open") or []))
        lines.append("")

    lines.append("## 应用概览")
    lines.append("")
    rows = []
    for app in sorted(payload.get("apps") or [],
                      key=lambda a: -(a.get("risk_score") or 0)):
        rows.append([app.get("group"), app.get("app"), app.get("tier"),
                     app.get("component_count"), app.get("affected_count"),
                     app.get("kev_count"), app.get("risk_score"),
                     app.get("baseline_item_count")])
    lines.append(_table(["群组", "应用", "重要性", "组件数", "受影响", "KEV", "风险分", "基线项"], rows)
                 if rows else "_无_")
    lines.append("")

    common = payload.get("common_risks") or []
    lines.append("## 跨应用共性风险")
    lines.append("")
    if common:
        rows = [[item.get("display"), len(item.get("apps") or []), item.get("score"),
                 item.get("conclusion"), ",".join((item.get("cves") or [])[:3]) or "—",
                 item.get("suggested_version") or "—"] for item in common[:15]]
        lines.append(_table(["组件", "影响应用数", "风险分", "结论", "CVE（前 3）", "建议版本"], rows))
    else:
        lines.append("_无_")
    lines.append("")

    lines.append("## 待处理工单（Top 20）")
    lines.append("")
    if tickets:
        rows = [[t.get("ticket_id"), t.get("app"), t.get("gav") or t.get("purl"),
                 t.get("severity"), ",".join((t.get("cves") or [])[:3]) or "—",
                 t.get("suggested_version") or "—", t.get("due")]
                for t in tickets[:20]]
        lines.append(_table(["工单号", "应用", "组件", "级别", "CVE（前 3）", "建议版本", "整改期限"], rows))
    else:
        lines.append("_无_")
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
