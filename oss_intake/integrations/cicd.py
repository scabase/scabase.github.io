"""CICD 平台对接：把门禁结论转成流水线可消费的产物。

- SARIF 2.1.0：可被代码扫描中心 / GitLab SAST / GitHub code scanning 直接纳管；
- JUnit XML：通用流水线测试报告展示；
- MR/PR 评论 Markdown：在合并请求中给出可读结论；
- 退出码语义：never / deny / review / condition 四档阈值。

零第三方依赖。
"""
import json
import time
from xml.sax.saxutils import escape

FAIL_LEVELS = {
    "never": [],
    "deny": ["Deny"],
    "review": ["Deny", "Review"],
    "condition": ["Deny", "Review", "Allow-with-condition"],
}

LEVEL_OF = {
    "Deny": "error",
    "Review": "warning",
    "Allow-with-condition": "note",
    "Allow": "none",
    "Exception": "note",
}

RULE_TEXT = {
    "Deny": "开源组件引入被拒绝：命中硬阻断规则或风险总分超过 Deny 阈值",
    "Review": "开源组件引入需安全评审：风险总分达到 Review 区间",
    "Allow-with-condition": "开源组件可附条件引入：需落实补偿措施并在到期前复审",
    "Allow": "开源组件风险可控，允许引入",
    "Exception": "已登记例外，按例外条件使用",
}


def rule_id_of(conclusion):
    return "SCABASE-%s" % str(conclusion).upper().replace("-", "_").replace(" ", "_")


def to_sarif(results, tool_name="scabase-oss-intake", tool_version="1.0.0",
             fail_on="deny"):
    """生成 SARIF 2.1.0 报告。"""
    rules = {}
    sarif_results = []
    blocking = FAIL_LEVELS.get(fail_on, FAIL_LEVELS["deny"])
    for result in results or []:
        conclusion = result.get("conclusion") or "Unknown"
        rule_id = rule_id_of(conclusion)
        level = LEVEL_OF.get(conclusion, "warning")
        rules[rule_id] = {
            "id": rule_id,
            "name": conclusion,
            "shortDescription": {"text": RULE_TEXT.get(conclusion, conclusion)},
            "defaultConfiguration": {"level": level},
            "help": {"text": "；".join(result.get("hard_blocks") or [])
                     or RULE_TEXT.get(conclusion, conclusion)},
        }
        message = "评分 %.2f" % (result.get("score") or 0)
        if result.get("suggested_version"):
            message += "，建议版本 %s" % result["suggested_version"]
        if result.get("hard_blocks"):
            message += "，硬阻断：%s" % "；".join(result["hard_blocks"])
        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": result.get("purl") or "unknown"},
                }
            }],
            "properties": {
                "score": result.get("score"),
                "conclusion": conclusion,
                "suggestedVersion": result.get("suggested_version"),
                "reviewDue": result.get("review_due"),
                "blocking": conclusion in blocking,
            },
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://scabase.roweb.cn",
                    "rules": [rules[key] for key in sorted(rules)],
                }
            },
            "results": sarif_results,
        }],
    }


def to_junit(results, suite="scabase-oss-intake", fail_on="deny"):
    """生成 JUnit XML 文本。"""
    blocking = FAIL_LEVELS.get(fail_on, FAIL_LEVELS["deny"])
    cases = []
    failures = 0
    for result in results or []:
        name = escape(result.get("display") or result.get("purl") or "unknown")
        classname = escape(result.get("purl") or "unknown")
        conclusion = result.get("conclusion") or "Unknown"
        if conclusion in blocking:
            failures += 1
            text = escape("评分 %.2f；%s" % (
                result.get("score") or 0,
                "；".join(result.get("hard_blocks") or []) or conclusion))
            cases.append(
                '    <testcase classname="%s" name="%s">'
                '<failure message="%s" type="OssIntakeGate">%s</failure></testcase>'
                % (classname, name, escape(conclusion), text))
        else:
            cases.append('    <testcase classname="%s" name="%s" />' % (classname, name))
    return "\n".join([
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<testsuites>',
        '  <testsuite name="%s" tests="%d" failures="%d" time="0" timestamp="%s">'
        % (suite, len(results or []), failures,
           time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())),
    ] + cases + [
        '  </testsuite>',
        '</testsuites>',
    ])


def to_comment(results, fail_on="deny", limit=20, title="开源引入评估结果"):
    """生成 MR/PR 评论 Markdown。"""
    blocking = FAIL_LEVELS.get(fail_on, FAIL_LEVELS["deny"])
    counts = {}
    for result in results or []:
        counts[result.get("conclusion")] = counts.get(result.get("conclusion"), 0) + 1
    lines = ["### %s" % title, ""]
    for conclusion in sorted(counts, key=lambda k: -list(LEVEL_OF).index(k)
                             if k in LEVEL_OF else 9):
        lines.append("- %s：%d" % (conclusion, counts[conclusion]))
    ordered = sorted(results or [], key=lambda r: -(r.get("score") or 0))[:limit]
    if ordered:
        lines.append("")
        lines.append("| 组件 | 评分 | 结论 | 建议版本 |")
        lines.append("|---|---|---|---|")
        for result in ordered:
            lines.append("| %s | %.2f | %s | %s |" % (
                result.get("display") or result.get("purl"),
                result.get("score") or 0,
                result.get("conclusion"),
                result.get("suggested_version") or "—"))
    blocked = [r for r in (results or []) if r.get("conclusion") in blocking]
    if blocked:
        lines.append("")
        lines.append("> 门禁未通过：%d 个组件命中 `%s` 阈值，请整改后重新触发流水线。"
                     % (len(blocked), fail_on))
    return "\n".join(lines)


def exit_code(results, fail_on="deny"):
    """流水线退出码：0 通过 / 1 门禁失败。"""
    blocking = FAIL_LEVELS.get(fail_on, FAIL_LEVELS["deny"])
    return 1 if any((r.get("conclusion") in blocking) for r in results or []) else 0


def write_sarif(results, path, **kwargs):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_sarif(results, **kwargs), handle, ensure_ascii=False, indent=2)
    return path
