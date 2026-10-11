import argparse
import json
import os
import sys
import time
import urllib.parse

import requests

OSV_API = "https://api.osv.dev/v1/query"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

# pkg_list 中生态名小写，需映射为 OSV 要求的规范名（大小写敏感）
ECO_MAP = {
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "pip": "PyPI",
    "go": "Go",
    "golang": "Go",
    "cargo": "crates.io",
    "crates.io": "crates.io",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "packagist": "Packagist",
    "nuget": "NuGet",
}


def to_osv_eco(eco):
    """将 pkg_list 中的生态名映射为 OSV 规范名。"""
    return ECO_MAP.get(eco.strip().lower(), eco.strip())


def load_pkg_list(path):
    """读取 `ecosystem|package|version` 格式清单。"""
    pkgs = []
    if not os.path.exists(path):
        print(f"pkg_list not found: {path}", file=sys.stderr)
        return pkgs
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 3:
                print(f"skip malformed line: {line}", file=sys.stderr)
                continue
            eco, pkg, ver = parts[0], parts[1], parts[2]
            pkgs.append({
                "ecosystem": to_osv_eco(eco),      # OSV 规范名，用于查询
                "eco_key": eco.strip().lower(),    # 原始清单名，用于结果键
                "package": pkg.strip(),
                "version": ver.strip(),
            })
    return pkgs


def query_osv(eco, pkg, ver):
    payload = {"package": {"name": pkg, "ecosystem": eco}}
    if ver:
        payload["version"] = ver
    try:
        resp = requests.post(OSV_API, json=payload, timeout=30)
    except Exception as e:
        print(f"  OSV error {eco}|{pkg}: {e}", file=sys.stderr)
        return {"vulns": []}
    if resp.status_code == 200:
        return resp.json()
    print(f"  OSV HTTP {resp.status_code} for {eco}|{pkg}", file=sys.stderr)
    return {"vulns": []}


def extract_cve(vul):
    """从 OSV 记录中提取 CVE 编号：优先 id，其次 aliases。"""
    vid = vul.get("id", "")
    if vid.startswith("CVE-"):
        return vid
    for alias in vul.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    return None


def query_nvd(cve_id):
    """通过 CVE 编号从 NVD 拉取标准 CVSS、CWE 信息。"""
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    url = f"{NVD_API}?{urllib.parse.urlencode({'cveId': cve_id})}"
    for attempt in range(2):
        try:
            r = requests.get(url, headers=headers, timeout=45)
            if r.status_code == 200:
                items = r.json().get("vulnerabilities", [])
                if items:
                    return items[0]["cve"]
                return None
            print(f"  NVD {cve_id} -> HTTP {r.status_code}", file=sys.stderr)
            return None
        except Exception as e:
            if attempt == 0:
                time.sleep(3)
                continue
            print(f"  NVD {cve_id} error: {e}", file=sys.stderr)
    return None


def main():
    parser = argparse.ArgumentParser(description="抓取多生态组件的 OSV / NVD 漏洞数据")
    parser.add_argument("--pkg-list", default="data/pkg_list.txt", help="组件清单路径")
    parser.add_argument("--out", default="data/vulns.json", help="输出 JSON 路径")
    parser.add_argument("--no-nvd", action="store_true", help="仅使用 OSV，跳过 NVD 补充")
    parser.add_argument(
        "--nvd-delay",
        type=float,
        default=None,
        help="NVD 每次请求间隔秒数（无密钥默认 6.5s，有密钥默认 0.7s）",
    )
    args = parser.parse_args()

    nvd_delay = args.nvd_delay if args.nvd_delay is not None else (0.7 if NVD_API_KEY else 6.5)

    if not args.no_nvd and not NVD_API_KEY:
        print("提示: 未配置 NVD_API_KEY，将以低速模式查询 NVD（建议配置密钥提升速率）")

    result = {}
    pkg_list = load_pkg_list(args.pkg_list)
    print(f"Total packages to scan: {len(pkg_list)}")
    for item in pkg_list:
        eco = item["ecosystem"]
        pkg = item["package"]
        ver = item["version"]
        key = f"{item['eco_key']}|{pkg}|{ver}"
        print(f"Query: {key}")
        osv_data = query_osv(eco, pkg, ver)
        enriched_vulns = []
        for vul in osv_data.get("vulns", []):
            nvd_data = None
            cve_id = extract_cve(vul)
            # 只有存在 CVE 编号（id 或 aliases）时才去 NVD 查询，GHSA-only 漏洞跳过
            if cve_id and not args.no_nvd:
                nvd_data = query_nvd(cve_id)
                time.sleep(nvd_delay)
            enriched_vulns.append({"osv": vul, "nvd": nvd_data})
        result[key] = {
            "osv_raw": osv_data,
            "enriched": enriched_vulns,
        }

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"Wrote {args.out} ({len(result)} packages)")


if __name__ == "__main__":
    main()
