"""生成脚本/规则的准确率回归校验。

目标：把「漏洞及基线扫描准确率达 90%」落成可度量的门禁指标。
校验在**声明式检查层**进行——生成的 shell / Python 脚本与 `baseline.run_check`
共用同一套判定语义，因此在标注样本集上测得的准确率即为脚本上线后的预期准确率。

样本集格式（examples/accuracy-cases.json）：
    {"cases": [
       {"case_id": "redis-ok-01", "rule_id": "redis-requirepass",
        "snapshot": {"configs": {"/etc/redis/redis.conf": {"requirepass": "Str0ng!"}}},
        "expected": "PASS"}, ...
    ]}

UNKNOWN 视为未检出（不正确），因为巡检脚本无法给出结论等价于漏检。
零第三方依赖。
"""
import json
import os

from . import baseline as baseline_mod

DEFAULT_THRESHOLD = 0.9


class AccuracyError(Exception):
    """准确率未达阈值。"""


def load_cases(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    cases = data.get("cases") if isinstance(data, dict) else data
    return [c for c in cases or [] if isinstance(c, dict)]


def predict(catalog, case):
    """在样本上执行基线检查，返回 (status, evidence)。"""
    item = baseline_mod.by_id(catalog, case.get("rule_id"))
    if not item:
        return "UNKNOWN", "基线目录中不存在规则 %s" % case.get("rule_id")
    return baseline_mod.run_check(item.get("check"), case.get("snapshot") or {})


def evaluate(catalog, cases, threshold=DEFAULT_THRESHOLD):
    """计算准确率、漏报、误报与逐规则明细。"""
    per_rule = {}
    false_negative = []
    false_positive = []
    unknown = []
    total = 0
    correct = 0

    for case in cases:
        rule_id = case.get("rule_id")
        expected = (case.get("expected") or "").upper()
        status, evidence = predict(catalog, case)
        total += 1
        ok = status == expected
        if ok:
            correct += 1
        bucket = per_rule.setdefault(rule_id, {"total": 0, "correct": 0,
                                               "false_negative": 0, "false_positive": 0,
                                               "unknown": 0})
        bucket["total"] += 1
        if ok:
            bucket["correct"] += 1
        record = {"case_id": case.get("case_id"), "rule_id": rule_id,
                  "expected": expected, "predicted": status, "evidence": evidence}
        if status == "UNKNOWN":
            unknown.append(record)
            bucket["unknown"] += 1
        elif expected == "FAIL" and status == "PASS":
            false_negative.append(record)
            bucket["false_negative"] += 1
        elif expected == "PASS" and status == "FAIL":
            false_positive.append(record)
            bucket["false_positive"] += 1

    for bucket in per_rule.values():
        bucket["accuracy"] = round(
            bucket["correct"] / bucket["total"], 4) if bucket["total"] else 0.0

    accuracy = round(correct / total, 4) if total else 0.0
    covered = set(per_rule.keys())
    uncovered = sorted({item.get("id") for item in catalog} - covered)
    return {
        "threshold": threshold,
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "passed": accuracy >= threshold,
        "unknown_count": len(unknown),
        "false_negative_count": len(false_negative),
        "false_positive_count": len(false_positive),
        "false_negative": false_negative,
        "false_positive": false_positive,
        "unknown": unknown,
        "per_rule": per_rule,
        "uncovered_rules": uncovered,
    }


def assert_accuracy(metrics, threshold=None):
    """未达阈值时抛错，供 CI 门禁使用。"""
    limit = threshold if threshold is not None else metrics.get("threshold", DEFAULT_THRESHOLD)
    if metrics.get("accuracy", 0) < limit:
        raise AccuracyError(
            "准确率 %.2f%% 低于阈值 %.2f%%（样本 %d，漏报 %d，误报 %d，无法判定 %d）" % (
                metrics.get("accuracy", 0) * 100, limit * 100,
                metrics.get("total", 0), metrics.get("false_negative_count", 0),
                metrics.get("false_positive_count", 0), metrics.get("unknown_count", 0)))
    return metrics


def render_markdown(metrics):
    lines = ["# 基线/漏洞检测脚本准确率回归", ""]
    lines.append("- 样本数：%d，正确：%d" % (metrics.get("total", 0), metrics.get("correct", 0)))
    lines.append("- **准确率：%.2f%%**（阈值 %.2f%%）→ %s" % (
        metrics.get("accuracy", 0) * 100, metrics.get("threshold", DEFAULT_THRESHOLD) * 100,
        "通过" if metrics.get("passed") else "未通过"))
    lines.append("- 漏报 %d / 误报 %d / 无法判定 %d" % (
        metrics.get("false_negative_count", 0), metrics.get("false_positive_count", 0),
        metrics.get("unknown_count", 0)))
    lines.append("")

    lines.append("## 逐规则准确率")
    lines.append("")
    lines.append("| 规则 | 样本 | 正确 | 准确率 | 漏报 | 误报 |")
    lines.append("|---|---|---|---|---|---|")
    for rule_id, bucket in sorted((metrics.get("per_rule") or {}).items()):
        lines.append("| %s | %d | %d | %.2f%% | %d | %d |" % (
            rule_id, bucket["total"], bucket["correct"], bucket["accuracy"] * 100,
            bucket["false_negative"], bucket["false_positive"]))
    lines.append("")

    if metrics.get("uncovered_rules"):
        lines.append("## 缺少样本的规则")
        lines.append("")
        for rule_id in metrics["uncovered_rules"]:
            lines.append("- %s" % rule_id)
        lines.append("")
    return "\n".join(lines)
