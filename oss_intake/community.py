"""社区支持力度与活跃度评价。

面向「社区活跃度 / 支持力度」这一类供应链可持续性风险：
把事实层 `health` 数据集与 registry 元数据折算为 0-100 分与 A/B/C/D 等级，
输出每一项的扣分依据，保证结论可人工复核（未知即风险，缺失项按保守扣分）。

零第三方依赖。
"""
GRADE_BANDS = ((80, "A", "强"), (60, "B", "较强"), (40, "C", "一般"), (0, "D", "弱"))

SUPPORT_ADVICE = {
    "A": "社区活跃、维护者充足，可正常引入并纳入常规版本跟踪。",
    "B": "社区状况良好，建议锁定版本并关注季度发布节奏。",
    "C": "社区支撑偏弱，引入前需评估自维护能力，建议建立内部镜像与应急补丁预案。",
    "D": "社区支撑不足或已停止维护，原则上不得引入；存量须制定替换或自维护方案。",
}


def _first(health, registry, key):
    if isinstance(health, dict) and health.get(key) is not None:
        return health.get(key)
    if isinstance(registry, dict) and registry.get(key) is not None:
        return registry.get(key)
    return None


def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def evaluate(health=None, registry=None, policy=None):
    """计算社区支持力度评分卡。

    返回 {score, grade, level, factors, signals, missing, advice}。
    """
    health = health or {}
    registry = registry or {}
    policy = policy or {}

    score = 100.0
    factors = []
    missing = []
    signals = {}

    def penalty(condition, points, note):
        nonlocal score
        if condition:
            score -= points
            factors.append({"factor": note, "impact": -float(points)})
            return True
        return False

    def bonus(condition, points, note):
        nonlocal score
        if condition:
            score += points
            factors.append({"factor": note, "impact": float(points)})
            return True
        return False

    # --- 停止维护是一票扣满项
    if health.get("archived") or health.get("deprecated"):
        factors.append({"factor": "项目已归档/标记废弃，社区支持基本中断", "impact": -95.0})
        score = min(score, 5.0)

    last_commit = _as_float(_first(health, registry, "last_commit_days"))
    signals["last_commit_days"] = last_commit
    if last_commit is None:
        missing.append("last_commit_days")
        penalty(True, 10, "最近提交时间未知（未知即风险）")
    else:
        penalty(last_commit > 730, 30, "最近提交距今 %.0f 天（>2 年）" % last_commit)
        penalty(365 < last_commit <= 730, 20, "最近提交距今 %.0f 天（>1 年）" % last_commit)
        penalty(180 < last_commit <= 365, 10, "最近提交距今 %.0f 天（>180 天）" % last_commit)
        penalty(90 < last_commit <= 180, 4, "最近提交距今 %.0f 天（>90 天）" % last_commit)

    releases = _as_float(_first(health, registry, "releases_12m"))
    signals["releases_12m"] = releases
    if releases is None:
        missing.append("releases_12m")
        penalty(True, 8, "近 12 个月发布次数未知")
    else:
        penalty(releases == 0, 15, "近 12 个月无正式发布")
        penalty(releases == 1, 6, "近 12 个月仅发布 1 次")
        penalty(1 < releases <= 3, 2, "近 12 个月发布 %.0f 次（偏少）" % releases)

    maintainers = _as_float(_first(health, registry, "maintainers"))
    signals["maintainers"] = maintainers
    if maintainers is None:
        missing.append("maintainers")
        penalty(True, 8, "维护者数量未知")
    else:
        penalty(maintainers <= 1, 15, "仅 %.0f 名维护者（bus factor = 1）" % maintainers)
        penalty(maintainers == 2, 6, "维护者 %.0f 人（bus factor 偏低）" % maintainers)
        penalty(maintainers == 3, 2, "维护者 %.0f 人" % maintainers)

    contributors = _as_float(_first(health, registry, "contributors"))
    signals["contributors"] = contributors
    if contributors is None:
        missing.append("contributors")
        penalty(True, 3, "贡献者数量未知")
    else:
        penalty(contributors <= 2, 8, "贡献者仅 %.0f 人，社区参与度不足" % contributors)

    response = _as_float(_first(health, registry, "issue_response_hours"))
    signals["issue_response_hours"] = response
    if response is None:
        missing.append("issue_response_hours")
        penalty(True, 6, "issue 响应时长未知")
    else:
        penalty(response > 720, 12, "issue 中位响应 %.0f 小时（>30 天）" % response)
        penalty(168 < response <= 720, 5, "issue 中位响应 %.0f 小时（>7 天）" % response)

    pr_days = _as_float(_first(health, registry, "pr_merge_days"))
    signals["pr_merge_days"] = pr_days
    if pr_days is None:
        missing.append("pr_merge_days")
        penalty(True, 3, "PR 合并周期未知")
    else:
        penalty(pr_days > 90, 8, "PR 平均 %.0f 天才合并" % pr_days)
        penalty(30 < pr_days <= 90, 3, "PR 平均 %.0f 天合并" % pr_days)

    # --- 治理与工程化能力
    security_policy = _first(health, registry, "has_security_policy")
    signals["has_security_policy"] = security_policy
    if security_policy is None:
        missing.append("has_security_policy")
        penalty(True, 3, "是否有安全响应策略未知")
    else:
        penalty(security_policy is False, 5, "未提供安全漏洞上报策略（SECURITY.md）")

    ci = _first(health, registry, "has_ci")
    signals["has_ci"] = ci
    if ci is None:
        missing.append("has_ci")
        penalty(True, 2, "是否具备 CI 未知")
    else:
        penalty(ci is False, 4, "未配置持续集成，补丁验证能力存疑")

    backing = _first(health, registry, "org_backing")
    signals["org_backing"] = backing
    if not backing:
        missing.append("org_backing")
        penalty(True, 2, "背后组织未知")
    else:
        text = str(backing).lower()
        if text in ("foundation", "apache", "cncf", "linux", "eclipse"):
            bonus(True, 5, "由基金会背书（%s）" % backing)
        elif text in ("vendor", "organization", "company"):
            bonus(True, 2, "由组织/厂商维护（%s）" % backing)
        else:
            penalty(True, 2, "个人维护，无组织背书（%s）" % backing)

    # --- 生态位与采用度（加分项）
    dependents = _as_float(_first(health, registry, "dependent_projects"))
    signals["dependent_projects"] = dependents
    if dependents is None:
        missing.append("dependent_projects")
    else:
        bonus(dependents >= 1000, 3, "下游依赖项目 %.0f 个，生态位关键" % dependents)
        bonus(100 <= dependents < 1000, 1, "下游依赖项目 %.0f 个" % dependents)

    downloads = _as_float(_first(health, registry, "monthly_downloads"))
    signals["monthly_downloads"] = downloads
    if downloads is None:
        missing.append("monthly_downloads")
    else:
        bonus(downloads >= 1000000, 3, "月下载量 %.0f，采用度极高" % downloads)
        bonus(100000 <= downloads < 1000000, 1, "月下载量 %.0f" % downloads)

    stars = _as_float(_first(health, registry, "stars"))
    signals["stars"] = stars
    if stars is not None:
        bonus(stars >= 10000, 2, "Star %.0f，社区关注度突出" % stars)
        bonus(1000 <= stars < 10000, 1, "Star %.0f" % stars)

    score = max(0.0, min(100.0, round(score, 1)))
    grade, level = "D", "弱"
    for band, name, text in GRADE_BANDS:
        if score >= band:
            grade, level = name, text
            break

    return {
        "score": score,
        "grade": grade,
        "level": level,
        "advice": SUPPORT_ADVICE.get(grade),
        "factors": factors,
        "signals": signals,
        "missing": missing,
    }
