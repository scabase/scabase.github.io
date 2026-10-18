"""社区支持力度与活跃度汇总报告。

读取 `fetch_oss_health.py` 产出的 health.json，调用 `oss_intake.community`
为每个组件计算社区支持力度评分与 A/B/C/D 等级，输出 Markdown 与 JSON 两种形态，
供互联网侧 CI 归档与内网侧人工复核使用。

用法：
    python scabase-fetcher/scripts/community_report.py \
        --health scabase-fetcher/data/health.json \
        --md reports/community.md \
        --json reports/community.json
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from oss_intake import community as community_mod  # noqa: E402
from oss_intake import purl as purl_mod  # noqa: E402

GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3}

# 数据来源展示名（与前端 app.js 的 SOURCE_LABELS 保持一致）
SOURCE_LABELS = {
    "github": "GitHub API",
    "deps.dev": "deps.dev",
    "npm-registry": "npm registry",
    "pypi": "PyPI JSON",
    "repo-map": "repo-map 显式映射",
}

# deps.dev 包页面（package 级）与各生态注册表页面，供人工点击核对数据来源
DEPS_DEV_SYSTEM = {"maven": "maven", "npm": "npm", "pypi": "pypi", "go": "go"}
REGISTRY_LABELS = {"npm": "npmjs.com", "pypi": "PyPI",
                   "maven": "Maven Central", "go": "pkg.go.dev"}


def deps_dev_url(info):
    """deps.dev 包页面 URL（package 级，不带版本）。"""
    eco = info.get("eco")
    name = info.get("name")
    if eco not in DEPS_DEV_SYSTEM or not name:
        return None
    # 兼容两种 purl 形态：scope 带 @（pkg:npm/@babel/core）与不带 @（pkg:npm/babel/core）
    namespace = (info.get("namespace") or "").lstrip("@")
    if eco == "maven":
        package = "%s:%s" % (namespace, name) if namespace else name
    elif eco == "npm" and namespace:
        # purl 约定把 npm scope 存为无 @ 的 namespace，deps.dev 需要补回 @
        package = "@%s/%s" % (namespace, name)
    elif namespace:
        package = "%s/%s" % (namespace, name)
    else:
        package = name
    return "https://deps.dev/%s/%s" % (DEPS_DEV_SYSTEM[eco], package)


def registry_url(info):
    """各生态注册表 / 文档站页面 URL，便于人工核对该组件的发布与下载数据。"""
    eco = info.get("eco")
    name = info.get("name")
    if not name:
        return None
    namespace = (info.get("namespace") or "").lstrip("@")
    if eco == "npm":
        package = "@%s/%s" % (namespace, name) if namespace else name
        return "https://www.npmjs.com/package/%s" % package
    if eco == "pypi":
        return "https://pypi.org/project/%s/" % name
    if eco == "maven" and namespace:
        return "https://central.sonatype.com/artifact/%s/%s" % (namespace, name)
    if eco == "go":
        package = "%s/%s" % (namespace, name) if namespace else name
        return "https://pkg.go.dev/%s" % package
    return None


def source_links_cell(row):
    """Markdown 表格里的「数据来源」单元格：可点击跳转原始出处。"""
    parts = []
    if row.get("repo"):
        parts.append("[GitHub](https://github.com/%s)" % row["repo"])
    if row.get("deps_dev"):
        parts.append("[deps.dev](%s)" % row["deps_dev"])
    if row.get("registry"):
        parts.append("[%s](%s)" % (REGISTRY_LABELS.get(row["eco"], "注册表"),
                                   row["registry"]))
    return "<br>".join(parts) if parts else "—"


def build_report(health):
    rows = []
    counts = {}
    missing_total = {}
    source_total = {}
    for purl_value, payload in sorted(health.items()):
        if not isinstance(payload, dict):
            continue
        result = community_mod.evaluate(payload)
        counts[result["grade"]] = counts.get(result["grade"], 0) + 1
        for key in result.get("missing") or []:
            missing_total[key] = missing_total.get(key, 0) + 1
        sources = payload.get("sources") or []
        for source in sources:
            source_total[source] = source_total.get(source, 0) + 1
        info = purl_mod.parse(purl_value) or {}
        rows.append({
            "purl": purl_value,
            "display": purl_mod.display_of(purl_value),
            "eco": info.get("eco"),
            "score": result["score"],
            "grade": result["grade"],
            "level": result["level"],
            "archived": bool(payload.get("archived") or payload.get("deprecated")),
            "last_commit_days": (result.get("signals") or {}).get("last_commit_days"),
            "releases_12m": (result.get("signals") or {}).get("releases_12m"),
            "maintainers": (result.get("signals") or {}).get("maintainers"),
            "org_backing": (result.get("signals") or {}).get("org_backing"),
            "monthly_downloads": (result.get("signals") or {}).get("monthly_downloads"),
            # GitHub 活跃度原始计数（供卡片展示与人工核对，不参与评分）
            "stars": payload.get("stars"),
            "forks": payload.get("forks"),
            "watchers": payload.get("watchers"),
            "sources": sources,
            "repo": payload.get("repo"),
            "deps_dev": deps_dev_url(info),
            "registry": registry_url(info),
            "missing": result.get("missing") or [],
            "advice": result.get("advice"),
        })
    rows.sort(key=lambda item: (GRADE_ORDER.get(item["grade"], 9), -item["score"]))
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "component_count": len(rows),
        "grade_counts": counts,
        "missing_signal_counts": missing_total,
        "source_counts": source_total,
        "components": rows,
    }


def render_markdown(report):
    lines = ["# 社区支持力度与活跃度汇总", ""]
    lines.append("- 生成时间：%s" % report["generated_at"])
    lines.append("- 组件数：%d" % report["component_count"])
    if report["grade_counts"]:
        distribution = "、".join(
            "%s 级 %d" % (grade, report["grade_counts"][grade])
            for grade in sorted(report["grade_counts"], key=lambda g: GRADE_ORDER.get(g, 9)))
        lines.append("- 等级分布：%s" % distribution)
    lines.append("")

    lines.append("| 组件 | 生态 | 评分 | 等级 | 最近提交(天) | 近12月发布 | 维护者 | 背后组织 | 月下载量 | 数据来源（可点击核对） |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for row in report["components"]:
        lines.append("| %s | %s | %.1f | %s | %s | %s | %s | %s | %s | %s |" % (
            row["display"], row["eco"], row["score"], row["grade"],
            row["last_commit_days"] if row["last_commit_days"] is not None else "—",
            row["releases_12m"] if row["releases_12m"] is not None else "—",
            row["maintainers"] if row["maintainers"] is not None else "—",
            row["org_backing"] or "—",
            row["monthly_downloads"] if row["monthly_downloads"] is not None else "—",
            source_links_cell(row)))
    lines.append("")

    if report["missing_signal_counts"]:
        lines.append("## 缺失信号统计（按「未知即风险」扣分）")
        lines.append("")
        for key, count in sorted(report["missing_signal_counts"].items(),
                                 key=lambda item: -item[1]):
            lines.append("- `%s`：%d 个组件缺失" % (key, count))
        lines.append("")

    if report.get("source_counts"):
        lines.append("## 数据来源覆盖")
        lines.append("")
        lines.append("| 来源 | 覆盖组件数 |")
        lines.append("| --- | --- |")
        for source, count in sorted(report["source_counts"].items(),
                                    key=lambda item: -item[1]):
            lines.append("| %s | %d |" % (SOURCE_LABELS.get(source, source), count))
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="社区支持力度与活跃度汇总")
    parser.add_argument("--health", default="scabase-fetcher/data/health.json")
    parser.add_argument("--md")
    parser.add_argument("--json")
    args = parser.parse_args()

    if not os.path.exists(args.health):
        print("缺少 %s，请先执行 fetch_oss_health.py" % args.health, file=sys.stderr)
        return 2
    with open(args.health, "r", encoding="utf-8") as handle:
        health = json.load(handle)

    report = build_report(health)
    if args.json:
        parent = os.path.dirname(args.json)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
    if args.md:
        parent = os.path.dirname(args.md)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.md, "w", encoding="utf-8") as handle:
            handle.write(render_markdown(report))
    print(render_markdown(report))
    print("组件 %d，等级分布 %s" % (report["component_count"], report["grade_counts"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
