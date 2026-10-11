import requests
import json
import os

PKG_LIST_PATH = "data/pkg_list.txt"
OUTPUT_PATH = "data/vulns.json"
OSV_API = "https://api.osv.dev/v1/query"
NVD_API = "https://api.nvd.nist.gov/v2/cves/"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

def load_pkg_list():
    pkgs = []
    if not os.path.exists(PKG_LIST_PATH):
        return pkgs
    with open(PKG_LIST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            eco, pkg, ver = line.split("|")
            pkgs.append({"ecosystem": eco, "package": pkg, "version": ver})
    return pkgs

def query_osv(eco, pkg, ver):
    payload = {
        "package": {
            "name": pkg,
            "ecosystem": eco
        },
        "version": ver
    }
    resp = requests.post(OSV_API, json=payload, timeout=30)
    if resp.status_code == 200:
        return resp.json()
    return {"vulns": []}

def query_nvd(cve_id):
    """通过CVE编号，从NVD拉取标准CVSS、CWE"""
    if not NVD_API_KEY:
        return None
    headers = {"apiKey": NVD_API_KEY}
    try:
        r = requests.get(f"{NVD_API}{cve_id}", headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            items = data.get("vulnerabilities", [])
            if items:
                return items[0]["cve"]
    except Exception:
        pass
    return None

def main():
    result = {}
    pkg_list = load_pkg_list()
    print(f"Total packages to scan: {len(pkg_list)}")
    for item in pkg_list:
        eco = item["ecosystem"]
        pkg = item["package"]
        ver = item["version"]
        key = f"{eco}|{pkg}|{ver}"
        print(f"Query: {key}")
        osv_data = query_osv(eco, pkg, ver)
        enriched_vulns = []
        for vul in osv_data.get("vulns", []):
            cve_id = vul.get("id")
            nvd_data = None
            # 只有以CVE开头的编号才去NVD查询，GHSA这类漏洞跳过NVD
            if cve_id.startswith("CVE-"):
                nvd_data = query_nvd(cve_id)
            merged = {
                "osv": vul,
                "nvd": nvd_data
            }
            enriched_vulns.append(merged)
        result[key] = {
            "osv_raw": osv_data,
            "enriched": enriched_vulns
        }

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
