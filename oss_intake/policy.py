"""评估策略：权重、阈值、许可证合规矩阵。

策略以 JSON 文件提供，未配置项回落到默认值，便于内网按群组定制。
零第三方依赖。
"""
import json
import os

LICENSE_CATEGORIES = {
    # 宽松许可
    "MIT": "permissive",
    "MIT-0": "permissive",
    "Apache-2.0": "permissive",
    "Apache-1.1": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "0BSD": "permissive",
    "ISC": "permissive",
    "Unlicense": "permissive",
    "Python-2.0": "permissive",
    "PSF-2.0": "permissive",
    "Zlib": "permissive",
    "CC0-1.0": "permissive",
    "BlueOak-1.0.0": "permissive",
    # 弱传染性
    "LGPL-2.0": "weak-copyleft",
    "LGPL-2.1": "weak-copyleft",
    "LGPL-3.0": "weak-copyleft",
    "MPL-1.1": "weak-copyleft",
    "MPL-2.0": "weak-copyleft",
    "EPL-1.0": "weak-copyleft",
    "EPL-2.0": "weak-copyleft",
    "CDDL-1.0": "weak-copyleft",
    "CDDL-1.1": "weak-copyleft",
    "MS-RL": "weak-copyleft",
    # 强传染性
    "GPL-1.0": "strong-copyleft",
    "GPL-2.0": "strong-copyleft",
    "GPL-3.0": "strong-copyleft",
    "AGPL-1.0": "strong-copyleft",
    "AGPL-3.0": "strong-copyleft",
    "SSPL-1.0": "strong-copyleft",
    "EUPL-1.1": "strong-copyleft",
    "EUPL-1.2": "strong-copyleft",
    "CC-BY-SA-4.0": "strong-copyleft",
    "OSL-3.0": "strong-copyleft",
    "CPL-1.0": "strong-copyleft",
    # 商业源码
    "BSL-1.0": "business-source",
    "BUSL-1.1": "business-source",
    "Elastic-2.0": "business-source",
    "SSPL-1.0-or-later": "strong-copyleft",
}

# 限制强度递增；用于多许可证时取最严格的一项
CATEGORY_RANK = {
    "permissive": 0,
    "weak-copyleft": 1,
    "business-source": 2,
    "strong-copyleft": 3,
}

DEFAULT_POLICY = {
    "weights": {
        "vulnerability": 35,
        "health": 25,
        "license": 20,
        "business": 20,
    },
    "thresholds": {
        "allow": 25,
        "condition": 55,
        "deny": 75,
    },
    "freshness_sla_days": 14,
    "freshness_grace_days": 3,
    # 数据陈旧默认只降级为人工复核；置 true 时按硬阻断处理
    "staleness_as_deny": False,
    # 事实层缺失时的保守取值（未知即风险）
    "unknown_scores": {
        "vulnerability": 24,
        "health": 18,
        "license": 12,
        "business": 6,
    },
    "license_profiles": {
        "closed_source": {
            "deny": ["strong-copyleft"],
            "warn": ["weak-copyleft", "business-source", "unknown"],
        },
        "saas": {
            "deny": ["strong-copyleft"],
            "warn": ["business-source", "unknown"],
        },
        "internal_service": {
            "deny": [],
            "warn": ["strong-copyleft", "unknown"],
        },
    },
    "default_profile": "internal_service",
    "app_tier_scores": {"core": 8, "important": 5, "normal": 2},
    "exposure_scores": {"internet": 6, "internal": 3, "offline": 0},
    "data_sensitivity_scores": {"high": 6, "mid": 3, "low": 0},
    # 社区支持力度低于该等级直接硬阻断（默认关闭，由策略开启）
    "community_deny_grades": [],
}

CONCLUSIONS = ("Allow", "Allow-with-condition", "Review", "Deny", "Exception")


def _deep_merge(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_policy(path=None):
    """加载策略文件并与默认策略合并。"""
    if not path:
        return json.loads(json.dumps(DEFAULT_POLICY))
    with open(path, "r", encoding="utf-8") as handle:
        override = json.load(handle)
    return _deep_merge(DEFAULT_POLICY, override)


def _normalize_spdx(token):
    return token.strip().replace("+", "").replace("-or-later", "").replace("-only", "")


def category_of(spdx):
    """把 SPDX 表达式归类；多取值时取限制最强的一项。"""
    if not spdx:
        return "unknown"
    tokens = []
    for part in str(spdx).replace(" OR ", "|").replace(" AND ", "|").split("|"):
        token = part.strip()
        if not token or token in ("(", ")"):
            continue
        tokens.append(token)
    best = None
    for token in tokens:
        category = LICENSE_CATEGORIES.get(_normalize_spdx(token))
        if category is None:
            continue
        if best is None or CATEGORY_RANK[category] > CATEGORY_RANK[best]:
            best = category
    return best or "unknown"


def license_verdict(license_info, profile_name, policy):
    """返回 (category, is_hardblock, is_warn)。"""
    profile = (policy.get("license_profiles") or {}).get(
        profile_name, (policy.get("license_profiles") or {}).get(policy.get("default_profile"))
    ) or {"deny": [], "warn": []}
    category = (license_info or {}).get("category")
    if not category:
        category = category_of((license_info or {}).get("spdx"))
    is_deny = category in (profile.get("deny") or [])
    is_warn = category in (profile.get("warn") or [])
    return category, is_deny, is_warn
