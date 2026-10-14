"""漏洞影响范围与安全基线自动化巡检。

输入：事实层（漏洞情报 / 活跃度 / 许可）+ 内网应用资产（inventory）+ 基线目录。
输出：按应用群组分层的巡检结论、待巡检基线项、工单清单，以及与上次巡检的增量对比。

设计要点：
- 组件以 PURL 为主键，漏洞命中精确到版本，避免「组件名相同即告警」的误报；
- 结论复用 `scoring` 风险模型，保证巡检口径与引入前评估一致；
- 增量对比以 (应用, 组件, CVE) 三元组为单位，支撑「新增 / 未修复 / 已修复」跟踪；
- 工单结构化输出，可直接推送 SRE 运维平台 / 代码扫描中心。

零第三方依赖。
"""
import json
import os
import time

from . import baseline as baseline_mod
from . import policy as policy_mod
from . import purl
from . import scoring

SEVERITY_DUE_DAYS = {"critical": 7, "high": 15, "medium": 30, "low": 90}


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _due_date(severity):
    days = SEVERITY_DUE_DAYS.get(severity, 30)
    return time.strftime("%Y-%m-%d", time.localtime(time.time() + days * 86400))


def _severity_of(finding):
    if finding.get("kev_count"):
        return "critical"
    cvss = float(finding.get("max_cvss") or 0)
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _cves_of(vulns):
    return list((vulns or {}).get("cves") or [])


def _iter_app_components(store, app_name):
    for _key, record in store.iter_dataset("inventory"):
        if app_name in (record.get("apps") or []):
            yield record


def evaluate_component(store, record, context, policy, confidences, catalog, profile=None):
    """对单个组件求值，产出巡检 finding。"""
    purl_value = record.get("purl")
    component = store.component(purl_value)
    usage = dict(record)
    for key, value in (context or {}).items():
        if value:
            usage[key] = value
    component["usage"] = usage
    result = scoring.evaluate(component, policy=policy, confidences=confidences,
                              profile=profile)
    info = purl.parse(purl_value) or {}
    name = info.get("name") or ""
    baseline_items = [
        {"id": item.get("id"), "title": item.get("title"),
         "severity": item.get("severity"), "category": item.get("category")}
        for item in baseline_mod.match(catalog, name)
    ]
    cves = _cves_of(component.get("vulns"))
    finding = {
        "purl": purl_value,
        "display": result.get("display") or purl_value,
        "gav": info.get("gav"),
        "direct": bool(record.get("direct")),
        "cve_count": len(cves),
        "cves": [{"id": c.get("id"), "cvss": c.get("cvss"), "kev": c.get("kev"),
                  "epss": c.get("epss"), "fixed": c.get("fixed"),
                  "published": c.get("published")} for c in cves],
        "max_cvss": (component.get("vulns") or {}).get("max_cvss", 0),
        "kev_count": int((component.get("vulns") or {}).get("kev_count") or 0),
        "unfixed_count": int((component.get("vulns") or {}).get("unfixed_count") or 0),
        "suggested_version": result.get("suggested_version"),
        "score": result.get("score"),
        "conclusion": result.get("conclusion"),
        "community": result.get("community"),
        "baseline": baseline_items,
        "apps": record.get("apps") or [],
    }
    finding["severity"] = _severity_of(finding)
    return finding


def patrol_app(store, app, group, policy, confidences, catalog):
    findings = []
    context = {
        "tier": app.get("tier", "normal"),
        "exposure": app.get("exposure", "internal"),
        "data_sensitivity": app.get("data_sensitivity", "low"),
    }
    for record in _iter_app_components(store, app.get("name")):
        findings.append(evaluate_component(
            store, record, context, policy, confidences, catalog,
            profile=group.get("profile")))
    findings.sort(key=lambda item: (-(item.get("score") or 0), item.get("display") or ""))

    counts = {}
    for finding in findings:
        counts[finding["conclusion"]] = counts.get(finding["conclusion"], 0) + 1
    affected = [f for f in findings if f["cve_count"]]
    baseline_ids = sorted({item["id"] for f in findings for item in f["baseline"]})
    risk = round(max([f["score"] for f in findings], default=0.0), 2)
    return {
        "app": app.get("name"),
        "group": group.get("name"),
        "tier": app.get("tier", "normal"),
        "exposure": app.get("exposure", "internal"),
        "data_sensitivity": app.get("data_sensitivity", "low"),
        "component_count": len(findings),
        "affected_count": len(affected),
        "kev_count": sum(f["kev_count"] for f in findings),
        "risk_score": risk,
        "conclusion_counts": counts,
        "baseline_item_count": len(baseline_ids),
        "baseline_items": baseline_ids,
        "findings": findings,
    }


def build_tickets(reports, limit=None):
    """把巡检结论转成结构化工单。"""
    tickets = []
    for app_report in reports:
        for finding in app_report.get("findings") or []:
            if not finding["cve_count"] and finding["conclusion"] in ("Allow", "Allow-with-condition"):
                continue
            if not finding["baseline"] and not finding["cve_count"]:
                continue
            severity = finding["severity"] if finding["cve_count"] else "low"
            tickets.append({
                "ticket_id": "PATROL-%s-%s" % (
                    app_report["app"], abs(hash(finding["purl"])) % 100000),
                "group": app_report["group"],
                "app": app_report["app"],
                "purl": finding["purl"],
                "gav": finding["gav"],
                "severity": severity,
                "conclusion": finding["conclusion"],
                "score": finding["score"],
                "cves": [c["id"] for c in finding["cves"]],
                "suggested_version": finding["suggested_version"],
                "baseline_ids": [item["id"] for item in finding["baseline"]],
                "due": _due_date(severity),
            })
    tickets.sort(key=lambda t: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        t["severity"], 4), t["app"]))
    if limit:
        tickets = tickets[:limit]
    return tickets


def _triples(payload):
    triples = {}
    for app_report in payload.get("apps") or []:
        for finding in app_report.get("findings") or []:
            cves = [c["id"] for c in finding["cves"]] or [""]
            for cve_id in cves:
                triples[(app_report["app"], finding["purl"], cve_id)] = finding["severity"]
    return triples


def diff(current, previous):
    """与上次巡检对比，产出新增 / 未修复 / 已修复。"""
    if not previous:
        return {"new": [], "open": [], "fixed": [], "previous_at": None}
    now = _triples(current)
    before = _triples(previous)
    added = sorted(set(now) - set(before))
    fixed = sorted(set(before) - set(now))
    still = sorted(set(now) & set(before))
    def _fmt(items):
        return [{"app": a, "purl": p, "cve": c} for a, p, c in items]
    return {
        "previous_at": previous.get("generated_at"),
        "new": _fmt(added),
        "fixed": _fmt(fixed),
        "open": _fmt(still),
    }


def patrol(store, assets, policy=None, catalog=None, previous=None, base_dir=".",
           rebuild_inventory=False):
    """执行全量巡检。"""
    policy = policy or policy_mod.load_policy()
    catalog = catalog if catalog is not None else baseline_mod.load_catalog()
    if rebuild_inventory:
        from . import assets as assets_mod
        assets_mod.build_inventory(store, assets, base_dir=base_dir)
    confidences = {
        name: store.confidence(name,
                               policy.get("freshness_sla_days", 14),
                               policy.get("freshness_grace_days", 3))
        for name in ("vulns", "health", "license", "inventory")
    }

    groups = []
    app_reports = []
    for group in assets.get("groups") or []:
        reports = [patrol_app(store, app, group, policy, confidences, catalog)
                   for app in group.get("apps") or []]
        app_reports.extend(reports)
        affected = sum(r["affected_count"] for r in reports)
        groups.append({
            "group": group.get("name"),
            "app_count": len(reports),
            "component_count": sum(r["component_count"] for r in reports),
            "affected_count": affected,
            "kev_count": sum(r["kev_count"] for r in reports),
            "risk_score": round(max([r["risk_score"] for r in reports], default=0.0), 2),
            "baseline_item_count": sum(r["baseline_item_count"] for r in reports),
            "apps": reports,
        })

    # 共性风险：跨多个应用被同一组件影响
    by_purl = {}
    for report in app_reports:
        for finding in report.get("findings") or []:
            if not finding["cve_count"]:
                continue
            entry = by_purl.setdefault(finding["purl"], {
                "purl": finding["purl"], "display": finding["display"],
                "score": finding["score"], "conclusion": finding["conclusion"],
                "cves": [c["id"] for c in finding["cves"]],
                "suggested_version": finding["suggested_version"],
                "apps": set(),
            })
            entry["apps"].add(report["app"])
    common_risks = sorted(
        [{"purl": e["purl"], "display": e["display"], "score": e["score"],
          "conclusion": e["conclusion"], "cves": e["cves"],
          "suggested_version": e["suggested_version"],
          "apps": sorted(e["apps"])} for e in by_purl.values() if len(e["apps"]) >= 2],
        key=lambda item: (-len(item["apps"]), -(item["score"] or 0)))

    payload = {
        "generated_at": _now_iso(),
        "confidence": store.confidence_report(policy.get("freshness_sla_days", 14),
                                              policy.get("freshness_grace_days", 3)),
        "groups": groups,
        "apps": app_reports,
        "common_risks": common_risks,
        "baseline_catalog_size": len(catalog),
    }
    payload["tickets"] = build_tickets(app_reports)
    payload["delta"] = diff(payload, previous)
    return payload


def load_state(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_state(path, payload):
    if not path:
        return None
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    return path
