"""采集 CISA KEV（已在野利用）与 FIRST EPSS（利用概率）。

两者都是纯情报补充，采集失败只降级，不影响已有漏洞数据。
"""
import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_kev(timeout=60):
    resp = requests.get(KEV_URL, timeout=timeout)
    resp.raise_for_status()
    payload = resp.json()
    items = {}
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cveID")
        if not cve:
            continue
        items[cve] = {
            "kev": True,
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
        }
    return items


def fetch_epss(cve_ids, timeout=60, batch=50):
    scores = {}
    for start in range(0, len(cve_ids), batch):
        chunk = cve_ids[start:start + batch]
        url = "%s?cve=%s" % (EPSS_URL, ",".join(chunk))
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            print("  EPSS HTTP %s，跳过该批次" % resp.status_code, file=sys.stderr)
            continue
        for item in (resp.json() or {}).get("data") or []:
            try:
                scores[item["cve"]] = float(item.get("epss"))
            except (KeyError, TypeError, ValueError):
                continue
        time.sleep(0.5)
    return scores


def main():
    parser = argparse.ArgumentParser(description="采集 KEV 与 EPSS 情报")
    parser.add_argument("--facts", help="事实层目录，指定后直接富化 vulns 数据集")
    parser.add_argument("--out-dir", default="data", help="未指定 --facts 时的缓存输出目录")
    parser.add_argument("--no-network", action="store_true")
    args = parser.parse_args()

    if requests is None and not args.no_network:
        print("缺少 requests，无法联网；可加 --no-network 跳过", file=sys.stderr)
        return 2

    kev = {}
    epss = {}
    if not args.no_network:
        try:
            kev = fetch_kev()
            print("KEV: %d 条" % len(kev))
        except Exception as exc:
            print("KEV 采集失败（降级保留上次数据）：%s" % exc, file=sys.stderr)
            kev = None
    else:
        kev = None

    if args.facts:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
        from oss_intake import facts as facts_mod
        store = facts_mod.FactsStore(args.facts).ensure()
        cve_ids = []
        for _key, payload in store.iter_dataset("vulns"):
            for cve in payload.get("cves") or []:
                if cve.get("id"):
                    cve_ids.append(cve["id"])
        cve_ids = sorted(set(cve_ids))
        if cve_ids and not args.no_network:
            try:
                epss = fetch_epss(cve_ids)
                print("EPSS: %d 条" % len(epss))
            except Exception as exc:
                print("EPSS 采集失败（降级保留上次数据）：%s" % exc, file=sys.stderr)
                epss = {}

        touched = 0
        for key, payload in list(store.iter_dataset("vulns")):
            changed = False
            kev_count = 0
            for cve in payload.get("cves") or []:
                cve_id = cve.get("id")
                if kev and cve_id in kev and not cve.get("kev"):
                    cve["kev"] = True
                    cve["kev_meta"] = kev[cve_id]
                    changed = True
                if cve.get("kev"):
                    kev_count += 1
                if cve_id in epss:
                    cve["epss"] = epss[cve_id]
                    changed = True
            if changed or kev is None:
                payload["kev_count"] = kev_count
                store.upsert("vulns", payload.get("purl") or key, payload)
                touched += 1
        if kev is not None:
            store.upsert("kev", "pkg:kev/cisa/catalog@current",
                         {"count": len(kev), "updated_at": time.strftime(
                             "%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
            store.bump("kev")
        store.bump("vulns", degraded=(kev is None))
        store.save_meta()
        print("已富化 %d 个组件" % touched)
        return 0

    os.makedirs(args.out_dir, exist_ok=True)
    if kev is not None:
        with open(os.path.join(args.out_dir, "kev.json"), "w", encoding="utf-8") as handle:
            json.dump(kev, handle, ensure_ascii=False, indent=2)
    print("完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
