"""应用群组风险评估：层级聚合、共性风险识别与报告数据准备。

零第三方依赖。
"""
from . import purl
from . import scoring

COMMON_RISK_MIN_APPS = 3
COMMON_RISK_MIN_SCORE = 55


def _app_weight(app_tier_scores, tier):
    return 1.0 + float(app_tier_scores.get(tier, 2)) / 8.0


def assess_group(store, group, policy, confidences, base_dir="."):
    """评估一个应用群组，返回评分卡与共性风险。"""
    results = []
    seen = set()
    for app in group.get("apps") or []:
        sbom_path = app.get("sbom")
        if not sbom_path:
            continue
        # 由 build_inventory 写入的应用级上下文
        context = {
            "tier": app.get("tier", "normal"),
            "exposure": app.get("exposure", "internal"),
            "data_sensitivity": app.get("data_sensitivity", "low"),
        }
        for record in _iter_app_components(store, app.get("name")):
            key = purl.key_of(record["purl"]) or record["purl"]
            if key in seen:
                continue
            seen.add(key)
            usage = dict(record)
            usage.update({k: v for k, v in context.items() if k not in usage})
            component = store.component(record["purl"])
            component["usage"] = usage
            result = scoring.evaluate(component, policy=policy,
                                      confidences=confidences,
                                      profile=group.get("profile"))
            result["apps"] = usage.get("apps") or []
            results.append(result)

    results.sort(key=lambda item: item["score"], reverse=True)

    app_tier_scores = policy.get("app_tier_scores") or {}
    per_app = {}
    for result in results:
        for app_name in result.get("apps") or []:
            per_app.setdefault(app_name, []).append(result["score"])

    weighted_sum = 0.0
    weight_total = 0.0
    for app in group.get("apps") or []:
        scores = per_app.get(app.get("name")) or []
        if not scores:
            continue
        weight = _app_weight(app_tier_scores, app.get("tier", "normal"))
        weighted_sum += weight * (sum(scores) / len(scores))
        weight_total += weight
    average = (weighted_sum / weight_total) if weight_total else 0.0
    worst = max([result["score"] for result in results], default=0.0)
    group_score = round(0.6 * worst + 0.4 * average, 2)

    common_risks = [
        {
            "purl": result["purl"],
            "display": result["display"],
            "score": result["score"],
            "conclusion": result["conclusion"],
            "apps": len(result.get("apps") or []),
        }
        for result in results
        if result["score"] >= COMMON_RISK_MIN_SCORE
        and len(result.get("apps") or []) >= COMMON_RISK_MIN_APPS
    ]

    breakdown = {}
    for name in scoring.DIMENSIONS:
        values = [
            r["dimensions"].get(name, {}).get("score", 0) for r in results
            if isinstance(r["dimensions"].get(name), dict)
        ]
        breakdown[name] = round(sum(values) / len(values), 2) if values else 0.0

    return {
        "group": group.get("name"),
        "group_score": group_score,
        "worst_component_score": worst,
        "weighted_average": round(average, 2),
        "component_count": len(results),
        "conclusion_counts": _count_conclusions(results),
        "dimension_breakdown": breakdown,
        "top_risks": [
            {"display": r["display"], "score": r["score"], "conclusion": r["conclusion"]}
            for r in results[:10]
        ],
        "common_risks": common_risks,
        "components": results,
    }


def _iter_app_components(store, app_name):
    for _key, record in store.iter_dataset("inventory"):
        if app_name in (record.get("apps") or []):
            yield record


def _count_conclusions(results):
    counts = {}
    for result in results:
        key = result["conclusion"]
        counts[key] = counts.get(key, 0) + 1
    return counts


def assess_all(store, assets, policy, confidences):
    return [assess_group(store, group, policy, confidences)
            for group in assets.get("groups") or []]
