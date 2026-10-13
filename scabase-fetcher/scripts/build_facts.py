"""把采集产物（vulns.json / health.json / license.json）写入事实层。

这是互联网侧的落盘环节，产出可直接打包摆渡的分片数据集。
用法：
    python scabase-fetcher/scripts/build_facts.py \
        --facts scabase-fetcher/data/facts \
        --vulns scabase-fetcher/data/vulns.json \
        --health scabase-fetcher/data/health.json
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))

from oss_intake import facts as facts_mod  # noqa: E402
from oss_intake import policy as policy_mod  # noqa: E402
from oss_intake import purl as purl_mod  # noqa: E402


def parse_key(key):
    """解析 `eco|pkg|ver` 为 (eco, namespace, name, version)。"""
    parts = key.split("|")
    if len(parts) < 3:
        return None
    eco = purl_mod.normalize_eco(parts[0])
    name = parts[1].strip()
    version = parts[2].strip()
    namespace = None
    if eco == "maven" and ":" in name:
        namespace, name = name.split(":", 1)
    elif eco == "npm" and name.startswith("@") and "/" in name:
        namespace, name = name[1:].split("/", 1)
    return eco, namespace, name, version


def _cvss_of(nvd):
    if not nvd:
        return None
    metrics = nvd.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            data = items[0].get("cvssData") or {}
            score = data.get("baseScore")
            if score is not None:
                return float(score)
    return None


def _cve_ids(osv_record):
    ids = []
    vid = osv_record.get("id") or ""
    if vid.startswith("CVE-"):
        ids.append(vid)
    for alias in osv_record.get("aliases") or []:
        if alias.startswith("CVE-") and alias not in ids:
            ids.append(alias)
    return ids


def _fixed_versions(osv_record):
    fixed = []
    for affected in osv_record.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    return fixed


def _severity_of(osv_record, nvd):
    for item in osv_record.get("severity") or []:
        if item.get("score"):
            return item.get("score")
    return None


def build_vulns(store, vulns_path):
    with open(vulns_path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    count = 0
    for key, record in raw.items():
        parsed = parse_key(key)
        if not parsed:
            continue
        eco, namespace, name, version = parsed
        purl_value = purl_mod.build(eco, name, version, namespace)
        if not purl_value:
            continue
        cves = []
        for item in record.get("enriched") or []:
            osv_record = item.get("osv") or {}
            nvd = item.get("nvd") or {}
            cve_ids = _cve_ids(osv_record) or [osv_record.get("id")]
            fixed = _fixed_versions(osv_record)
            cvss = _cvss_of(nvd)
            published = (nvd or {}).get("published") or osv_record.get("published")
            for cve_id in cve_ids:
                if not cve_id:
                    continue
                cves.append({
                    "id": cve_id,
                    "cvss": cvss,
                    "severity": _severity_of(osv_record, nvd),
                    "kev": False,
                    "epss": None,
                    "fixed": fixed,
                    "published": published,
                    "summary": (osv_record.get("summary") or "")[:200],
                })
        max_cvss = max([c["cvss"] for c in cves if c["cvss"]], default=0.0)
        unfixed = len([c for c in cves if not c["fixed"]])
        payload = {
            "purl": purl_value,
            "cves": cves,
            "max_cvss": max_cvss,
            "kev_count": 0,
            "unfixed_count": unfixed,
        }
        store.upsert("vulns", purl_value, payload)
        count += 1
    store.bump("vulns")
    return count


def build_health(store, health_path):
    if not health_path or not os.path.exists(health_path):
        return 0
    with open(health_path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    count = 0
    for purl_value, payload in raw.items():
        if not isinstance(payload, dict):
            continue
        record = dict(payload)
        record["purl"] = purl_value
        store.upsert("health", purl_value, record)
        count += 1
    store.bump("health")
    return count


def build_license(store, license_path):
    if not license_path or not os.path.exists(license_path):
        return 0
    with open(license_path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    count = 0
    for purl_value, payload in raw.items():
        if not isinstance(payload, dict):
            continue
        spdx = payload.get("spdx")
        category = payload.get("category") or policy_mod.category_of(spdx)
        store.upsert("license", purl_value, {"spdx": spdx, "category": category,
                                             "source": payload.get("source")})
        count += 1
    store.bump("license")
    return count


def main():
    parser = argparse.ArgumentParser(description="把采集产物写入事实层")
    parser.add_argument("--facts", default="scabase-fetcher/data/facts")
    parser.add_argument("--vulns", default="scabase-fetcher/data/vulns.json")
    parser.add_argument("--health", default="scabase-fetcher/data/health.json")
    parser.add_argument("--license", default="scabase-fetcher/data/license.json")
    parser.add_argument("--generated-at", help="覆盖水位时间戳（测试用）")
    args = parser.parse_args()

    store = facts_mod.FactsStore(args.facts).ensure()
    stamp = args.generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    stats = {}
    if args.vulns and os.path.exists(args.vulns):
        stats["vulns"] = build_vulns(store, args.vulns)
    stats["health"] = build_health(store, args.health)
    stats["license"] = build_license(store, args.license)
    for name in stats:
        store.dataset_meta(name)["generated_at"] = stamp
    store.save_meta()
    print(json.dumps({"facts": args.facts, "counts": stats, "generated_at": stamp},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
