#!/usr/bin/env python3
"""抓取多生态包的漏洞信息并合并 OSV / NVD 结果。

用法::

    python scripts/fetch_osv_nvd.py \
        --pkg-list data/pkg_list.txt \
        --out data/vulns.json

数据来源:
    * OSV  : https://api.osv.dev/v1/query      （无需 API Key）
    * NVD  : https://services.nvd.nist.gov/rest/json/cves/2.0
             可选设置环境变量 NVD_API_KEY 以提高速率限制。

依赖: 仅使用标准库（Python 3.9+）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OSV_API = "https://api.osv.dev/v1/query"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "scabase-fetcher/1.0 (+https://github.com/scabase/scabase.github.io)"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def http_post_json(url: str, payload: dict, retries: int = 3) -> dict:
    """向 url 发送 JSON POST 请求并返回解析后的 JSON。"""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    return _request_json(req, retries)


def http_get_json(url: str, retries: int = 3) -> dict:
    """向 url 发送 GET 请求并返回解析后的 JSON。"""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    req = urllib.request.Request(url, headers=headers, method="GET")
    return _request_json(req, retries)


def _request_json(req: urllib.request.Request, retries: int) -> dict:
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:  # 4xx/5xx
            last_err = err
            if err.code in (403, 429):  # 速率限制，退避后重试
                time.sleep(5 * attempt)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            last_err = err
            time.sleep(2 * attempt)
    raise RuntimeError(f"请求失败（已重试 {retries} 次）: {req.full_url}: {last_err}")


def parse_entries(path: Path) -> list[str]:
    """读取包清单，忽略空行与以 ``#`` 开头的注释行。"""
    entries: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def split_entry(entry: str) -> tuple[str, str, str | None]:
    """将 ``ecosystem:package[@version]`` 拆分为 (ecosystem, package, version)。"""
    if ":" not in entry:
        raise ValueError(f"非法条目，缺少生态前缀: {entry!r}")
    ecosystem, rest = entry.split(":", 1)
    name, _, version = rest.partition("@")
    return ecosystem.strip(), name.strip(), (version.strip() or None)


# --------------------------------------------------------------------------- #
# 数据源
# --------------------------------------------------------------------------- #
def query_osv(ecosystem: str, name: str, version: str | None) -> list[dict]:
    """查询单个包的 OSV 漏洞，返回精简后的记录列表。"""
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    try:
        result = http_post_json(OSV_API, payload)
    except Exception as err:  # noqa: BLE001 - 单包失败不影响整体
        print(f"  [warn] OSV 查询失败 {ecosystem}:{name}: {err}", file=sys.stderr)
        return []

    records = []
    for vuln in result.get("vulns", []):
        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        records.append(
            {
                "source": "OSV",
                "id": vuln.get("id"),
                "cve": cve_id,
                "aliases": aliases,
                "summary": vuln.get("summary", ""),
                "details": (vuln.get("details") or "").strip(),
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
                "severity": _osv_severity(vuln),
                "references": [r.get("url") for r in vuln.get("references", []) if r.get("url")],
            }
        )
    return records


def _osv_severity(vuln: dict) -> str | None:
    """从 OSV 记录中尽力提取严重级别（CVSS 向量或标签）。"""
    for sev in vuln.get("severity", []):
        if sev.get("score"):
            return sev["score"]
    for aff in vuln.get("affected", []):
        for sev in aff.get("severity", []):
            if sev.get("score"):
                return sev["score"]
    db = vuln.get("database_specific", {})
    if isinstance(db, dict) and db.get("severity"):
        return db["severity"]
    return None


def query_nvd(cve_id: str) -> dict | None:
    """按 CVE 编号查询 NVD，返回精简记录（失败时返回 None）。"""
    url = NVD_API + "?" + urllib.parse.urlencode({"cveId": cve_id})
    try:
        result = http_get_json(url)
    except Exception as err:  # noqa: BLE001
        print(f"  [warn] NVD 查询失败 {cve_id}: {err}", file=sys.stderr)
        return None

    items = result.get("vulnerabilities", [])
    if not items:
        return None
    cve = items[0].get("cve", {})
    metrics = cve.get("metrics", {})
    return {
        "source": "NVD",
        "id": cve.get("id", cve_id),
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "description": _nvd_description(cve),
        "cvss": _nvd_cvss(metrics),
        "references": [r.get("url") for r in cve.get("references", []) if r.get("url")],
    }


def _nvd_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _nvd_cvss(metrics: dict) -> dict | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "version": data.get("version"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or entries[0].get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
    return None


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def fetch(pkg_list: Path, out: Path, with_nvd: bool, nvd_delay: float) -> dict:
    entries = parse_entries(pkg_list)
    print(f"共 {len(entries)} 个待查询条目")

    packages: list[dict] = []
    for entry in entries:
        try:
            ecosystem, name, version = split_entry(entry)
        except ValueError as err:
            print(f"[warn] 跳过条目: {err}", file=sys.stderr)
            continue

        target = f"{ecosystem}:{name}" + (f"@{version}" if version else "")
        print(f"-> 查询 {target}")
        osv = query_osv(ecosystem, name, version)

        cve_ids = sorted({r["cve"] for r in osv if r.get("cve")})
        nvd: list[dict] = []
        if with_nvd:
            for cve_id in cve_ids:
                record = query_nvd(cve_id)
                if record:
                    nvd.append(record)
                time.sleep(nvd_delay)  # 遵守 NVD 速率限制

        packages.append(
            {
                "ecosystem": ecosystem,
                "package": name,
                "version": version,
                "query": target,
                "osv": osv,
                "nvd": nvd,
            }
        )

    result = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": ["OSV", "NVD"] if with_nvd else ["OSV"],
        "package_count": len(packages),
        "vuln_count": sum(len(p["osv"]) for p in packages),
        "packages": packages,
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"已写入 {out}（{result['package_count']} 个包，{result['vuln_count']} 条 OSV 记录）")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="抓取多生态包的 OSV / NVD 漏洞数据")
    parser.add_argument("--pkg-list", type=Path, default=Path("data/pkg_list.txt"), help="包清单路径")
    parser.add_argument("--out", type=Path, default=Path("data/vulns.json"), help="输出 JSON 路径")
    parser.add_argument("--no-nvd", action="store_true", help="仅使用 OSV，不查询 NVD")
    parser.add_argument(
        "--nvd-delay",
        type=float,
        default=6.5 if not NVD_API_KEY else 0.7,
        help="NVD 每次请求间隔秒数（无 API Key 时默认 6.5s）",
    )
    args = parser.parse_args(argv)

    if not args.pkg_list.exists():
        print(f"包清单不存在: {args.pkg_list}", file=sys.stderr)
        return 2

    fetch(args.pkg_list, args.out, with_nvd=not args.no_nvd, nvd_delay=args.nvd_delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
