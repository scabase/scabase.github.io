"""风险评分引擎：四维加权 + 硬阻断 + 置信度降级。

零第三方依赖，可在纯内网运行。每个结论都输出可解释的分项明细。
"""
import time

from . import community as community_mod
from . import policy as policy_mod
from . import purl

DIMENSIONS = ("vulnerability", "health", "license", "business")


def _cap(value, weight):
    return max(0.0, min(float(weight), float(value)))


def _version_tuple(version):
    parts = []
    for chunk in str(version or "").split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def _age_days(stamp, now):
    if not stamp:
        return None
    try:
        parsed = time.mktime(time.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        try:
            parsed = time.mktime(time.strptime(stamp[:10], "%Y-%m-%d"))
        except (ValueError, OverflowError):
            return None
    return max(0.0, (now - parsed) / 86400.0)


# --------------------------------------------------------------- 维度：漏洞

def score_vulnerability(vulns, weight):
    """返回 (raw, notes, missing)。"""
    if not vulns:
        return None, ["事实层无漏洞情报"], True
    notes = []
    cves = vulns.get("cves") or []
    max_cvss = float(vulns.get("max_cvss") or 0)
    value = max_cvss / 10.0 * 25.0
    notes.append("CVSS %.1f → 基础分 %.1f" % (max_cvss, value))

    kev_count = int(vulns.get("kev_count") or 0)
    if kev_count:
        value += 8
        notes.append("命中 CISA KEV（%d 条）→ +8" % kev_count)

    epss = 0.0
    for cve in cves:
        try:
            epss = max(epss, float(cve.get("epss") or 0))
        except (TypeError, ValueError):
            continue
    if epss:
        add = min(5.0, epss * 5.0)
        value += add
        notes.append("EPSS %.2f → +%.1f" % (epss, add))

    unfixed = int(vulns.get("unfixed_count") or 0)
    if unfixed:
        value += 4
        notes.append("存在无修复版本的 CVE（%d 条）→ +4" % unfixed)

    now = time.time()
    aged = 0
    for cve in cves:
        age = _age_days(cve.get("published"), now)
        if age is not None and age > 180:
            aged += 1
    if aged:
        value += 3
        notes.append("存在暴露超过 180 天的 CVE（%d 条）→ +3" % aged)

    return _cap(value, weight), notes, False


# --------------------------------------------------------- 维度：维护健康度

def score_health(health, weight):
    if not health:
        return None, ["事实层无活跃度指标"], True
    notes = []
    if health.get("archived") or health.get("deprecated"):
        notes.append("仓库已 archived/deprecated → 取满档")
        return float(weight), notes, False

    value = 0.0
    last_commit = health.get("last_commit_days")
    if last_commit is not None:
        days = float(last_commit)
        if days > 730:
            step = 20
        elif days > 365:
            step = 15
        elif days > 180:
            step = 10
        elif days > 90:
            step = 6
        else:
            step = 0
        if step:
            notes.append("最近提交距今 %.0f 天 → +%d" % (days, step))
        value += step

    releases = health.get("releases_12m")
    if releases is not None:
        if int(releases) == 0:
            step = 6
        elif int(releases) == 1:
            step = 3
        elif int(releases) <= 3:
            step = 1
        else:
            step = 0
        if step:
            notes.append("近 12 个月发布 %s 次 → +%d" % (releases, step))
        value += step

    maintainers = health.get("maintainers")
    if maintainers is not None:
        if int(maintainers) <= 1:
            step = 5
        elif int(maintainers) == 2:
            step = 2
        else:
            step = 0
        if step:
            notes.append("维护者 %s 人（bus factor 偏低）→ +%d" % (maintainers, step))
        value += step

    response = health.get("issue_response_hours")
    if response is not None:
        hours = float(response)
        if hours > 720:
            step = 4
        elif hours > 168:
            step = 2
        else:
            step = 0
        if step:
            notes.append("issue 中位响应 %.0f 小时 → +%d" % (hours, step))
        value += step

    if not notes:
        notes.append("各项活跃度指标正常（提交/发布/维护者/响应均达标）")
    return _cap(value, weight), notes, False


# ----------------------------------------------------------- 维度：合规许可

def score_license(license_info, profile_name, weight, policy):
    category, is_deny, is_warn = policy_mod.license_verdict(
        license_info, profile_name, policy
    )
    base = {
        "permissive": 0,
        "weak-copyleft": 10,
        "business-source": 14,
        "unknown": 12,
        "strong-copyleft": 20,
    }.get(category, 12)
    notes = []
    if not license_info:
        notes.append("事实层无许可证信息，按 unknown 处理")
    else:
        notes.append("许可证类别 %s → %d" % (category, base))
    if is_deny:
        notes.append("与用途策略 %s 冲突，判定为硬阻断" % profile_name)
    elif is_warn:
        notes.append("与用途策略 %s 存在合规提示" % profile_name)
    return _cap(base, weight), notes, category, is_deny, is_warn


# ----------------------------------------------------------- 维度：业务影响

def score_business(usage, weight, policy):
    if not usage:
        return None, ["事实层无应用资产关联"], True
    notes = []
    value = 0.0

    tier = usage.get("tier")
    step = (policy.get("app_tier_scores") or {}).get(tier, 0)
    if step:
        notes.append("应用重要性 %s → +%d" % (tier, step))
    value += step

    exposure = usage.get("exposure")
    step = (policy.get("exposure_scores") or {}).get(exposure, 0)
    if step:
        notes.append("网络暴露面 %s → +%d" % (exposure, step))
    value += step

    sensitivity = usage.get("data_sensitivity")
    step = (policy.get("data_sensitivity_scores") or {}).get(sensitivity, 0)
    if step:
        notes.append("数据敏感度 %s → +%d" % (sensitivity, step))
    value += step

    blast = int(usage.get("blast_radius") or 0)
    if blast >= 10:
        step = 5
    elif blast >= 5:
        step = 3
    elif blast >= 2:
        step = 2
    else:
        step = 0
    if step:
        notes.append("影响半径 %d 个应用 → +%d" % (blast, step))
    value += step

    if usage.get("direct"):
        notes.append("直接依赖 → +3")
        value += 3
    elif "direct" in usage:
        notes.append("传递依赖 → +1")
        value += 1

    if not notes:
        notes.append("未命中业务影响加分项（重要性/暴露面/敏感度/影响半径均为最低档）")
    return _cap(value, weight), notes, False


def _suggested_version(vulns):
    candidates = []
    for cve in (vulns or {}).get("cves") or []:
        for fixed in cve.get("fixed") or []:
            candidates.append(fixed)
    if not candidates:
        return None
    candidates.sort(key=_version_tuple)
    return candidates[-1]


def _apply_confidence(raw, weight, confidence):
    """置信度越低，分值越向该维度满分靠拢（保守估计）。"""
    if raw is None:
        return None
    if confidence >= 1.0:
        return raw
    return raw + (weight - raw) * (1.0 - confidence)


def evaluate(component, policy=None, confidences=None, profile=None,
             human_reviewed=False):
    """对单个组件执行完整评估，返回可解释的评分卡。"""
    policy = policy or policy_mod.load_policy()
    profile = profile or policy.get("default_profile")
    confidences = confidences or {}
    weights = policy.get("weights") or {}
    unknown = policy.get("unknown_scores") or {}
    thresholds = policy.get("thresholds") or {}

    vulns = component.get("vulns")
    health = component.get("health")
    license_info = component.get("license")
    usage = component.get("usage")

    dimensions = {}
    hard_blocks = []
    warnings = []
    missing_data = False

    # --- 漏洞
    weight = weights.get("vulnerability", 35)
    raw, notes, missing = score_vulnerability(vulns, weight)
    if missing:
        raw = unknown.get("vulnerability", 24)
        missing_data = True
        notes.append("按未知取保守值 %.1f" % raw)
    conf = confidences.get("vulns", 1.0)
    dimensions["vulnerability"] = {
        "weight": weight,
        "raw": round(raw, 2),
        "score": round(_apply_confidence(raw, weight, conf), 2),
        "confidence": round(conf, 3),
        "notes": notes,
    }

    # --- 健康度
    weight = weights.get("health", 25)
    raw, notes, missing = score_health(health, weight)
    if missing:
        raw = unknown.get("health", 18)
        missing_data = True
        notes.append("按未知取保守值 %.1f" % raw)
    conf = confidences.get("health", 1.0)
    dimensions["health"] = {
        "weight": weight,
        "raw": round(raw, 2),
        "score": round(_apply_confidence(raw, weight, conf), 2),
        "confidence": round(conf, 3),
        "notes": notes,
    }

    # --- 许可
    weight = weights.get("license", 20)
    raw, notes, category, is_deny, is_warn = score_license(
        license_info, profile, weight, policy
    )
    if not license_info:
        missing_data = True
    conf = confidences.get("license", 1.0)
    dimensions["license"] = {
        "weight": weight,
        "raw": round(raw, 2),
        "score": round(_apply_confidence(raw, weight, conf), 2),
        "confidence": round(conf, 3),
        "category": category,
        "notes": notes,
    }
    if is_deny:
        hard_blocks.append("许可证类别 %s 与用途策略 %s 冲突" % (category, profile))
    elif is_warn:
        warnings.append("许可证类别 %s 需合规确认" % category)

    # --- 社区支持力度（活跃度之上的可持续性评价，可解释但不单独占权重）
    support = community_mod.evaluate(health, policy=policy)

    # --- 业务影响
    weight = weights.get("business", 20)
    raw, notes, missing = score_business(usage, weight, policy)
    if missing:
        raw = unknown.get("business", 6)
        notes.append("按未知取保守值 %.1f" % raw)
    conf = confidences.get("inventory", 1.0)
    dimensions["business"] = {
        "weight": weight,
        "raw": round(raw, 2),
        "score": round(_apply_confidence(raw, weight, conf), 2),
        "confidence": round(conf, 3),
        "notes": notes,
    }

    # --- 硬阻断（非陈旧度类）
    if vulns:
        kev = int(vulns.get("kev_count") or 0)
        unfixed = int(vulns.get("unfixed_count") or 0)
        max_cvss = float(vulns.get("max_cvss") or 0)
        if kev and unfixed:
            hard_blocks.append("命中 CISA KEV 且当前版本无修复版本")
        if max_cvss >= 9.0 and unfixed:
            hard_blocks.append("CVSS %.1f ≥ 9.0 且无修复版本" % max_cvss)
    if health and (health.get("archived") or health.get("deprecated")):
        hard_blocks.append("组件已 archived/deprecated")
    if support["grade"] in ("C", "D"):
        warnings.append("社区支持力度 %s 级（%.0f/100）：%s" % (
            support["grade"], support["score"], support["advice"]))
    deny_grades = policy.get("community_deny_grades") or []
    if support["grade"] in deny_grades:
        hard_blocks.append("社区支持力度 %s 级低于准入要求 %s" % (
            support["grade"], "/".join(deny_grades)))

    # --- 置信度降级
    stale = [name for name, value in confidences.items() if value < 0.5]
    if stale:
        warnings.append("数据集 %s 数据不足（陈旧或缺失），结论需人工复核" % "、".join(sorted(stale)))
        if policy.get("staleness_as_deny") and not human_reviewed:
            hard_blocks.append("支撑数据陈旧且未完成人工复核")

    score = round(sum(dimensions[name]["score"] for name in DIMENSIONS), 2)

    if hard_blocks:
        conclusion = "Deny"
    elif score >= thresholds.get("deny", 75):
        conclusion = "Deny"
        warnings.append("总分 %.2f 达到 Deny 阈值" % score)
    elif score >= thresholds.get("condition", 55):
        conclusion = "Review"
    elif score >= thresholds.get("allow", 25) or warnings:
        conclusion = "Allow-with-condition"
    else:
        conclusion = "Allow"

    needs_review = conclusion in ("Review", "Deny") or bool(
        stale) or missing_data or bool(warnings)

    review_days = 180 if conclusion == "Deny" else 90
    review_due = time.strftime(
        "%Y-%m-%d", time.localtime(time.time() + review_days * 86400)
    )

    purl_value = component.get("purl")
    return {
        "purl": purl_value,
        "gav": component.get("gav") or (purl.parse(purl_value) or {}).get("gav"),
        "display": purl.display_of(purl_value) if purl_value else None,
        "profile": profile,
        "score": score,
        "conclusion": conclusion,
        "hard_blocks": hard_blocks,
        "warnings": warnings,
        "dimensions": dimensions,
        "community": support,
        "needs_review": needs_review,
        "missing_data": missing_data,
        "suggested_version": _suggested_version(vulns),
        "review_due": review_due if conclusion != "Allow" else None,
    }
