"""采集开源组件活跃度 / 维护健康度指标。

数据源优先级：
  1. deps.dev（跨生态元数据：发布时间、许可证、关联漏洞）
  2. GitHub API（archived、push 时间、发布数、贡献者数、星标）
  3. 各生态 registry 元数据（下载量、deprecated 标记）

任一源失败只降级，不中断整批任务。支持 --fixtures 用本地 JSON 离线回放，便于测试。
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

GITHUB_API = "https://api.github.com/repos"
DEPS_DEV = "https://api.deps.dev/v3alpha/systems"

ECO_TO_DEPS_SYSTEM = {
    "maven": "MAVEN",
    "npm": "NPM",
    "pypi": "PYPI",
    "go": "GO",
    "cargo": "CARGO",
    "gem": "RUBYGEMS",
    "nuget": "NUGET",
}


def _get(url, token=None, timeout=30, retries=3):
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
        except Exception as exc:
            if attempt + 1 == retries:
                print("  请求失败 %s: %s" % (url, exc), file=sys.stderr)
                return None
            time.sleep(2 ** attempt)
            continue
        if resp.status_code == 403 or resp.status_code == 429:
            # 触发限流，退避后重试
            time.sleep(min(60, 5 * (attempt + 1)))
            continue
        if resp.status_code >= 400:
            return None
        try:
            return resp.json()
        except ValueError:
            return None
    return None


def days_since(iso_stamp):
    if not iso_stamp:
        return None
    try:
        parsed = time.mktime(time.strptime(iso_stamp[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        try:
            parsed = time.mktime(time.strptime(iso_stamp[:10], "%Y-%m-%d"))
        except (ValueError, OverflowError):
            return None
    return max(0, int((time.time() - parsed) / 86400))


def github_slug(purl, eco):
    """尽力推断 GitHub 仓库（Maven 用 GAV 的 groupId 作为 owner 的近似不可靠，故需显式映射）。"""
    name = purl.get("name") or ""
    namespace = purl.get("namespace") or ""
    if eco == "go":
        module = "%s/%s" % (namespace, name) if namespace else name
        if module.startswith("github.com/"):
            parts = module.split("/")
            if len(parts) >= 3:
                return "%s/%s" % (parts[1], parts[2])
    if eco == "npm" and namespace:
        return None
    return None


def collect_from_github(slug, token, releases_limit=100):
    repo = _get("%s/%s" % (GITHUB_API, slug), token=token)
    if not repo:
        return None
    health = {
        "archived": bool(repo.get("archived")),
        "deprecated": bool(repo.get("disabled")),
        "stars": repo.get("stargazers_count"),
        "open_issues": repo.get("open_issues_count"),
        "last_commit_days": days_since(repo.get("pushed_at")),
        "repo": slug,
    }
    releases = _get("%s/%s/releases?per_page=%d" % (GITHUB_API, slug, releases_limit), token=token)
    if isinstance(releases, list):
        recent = 0
        for item in releases:
            published = item.get("published_at") or item.get("created_at")
            age = days_since(published)
            if age is not None and age <= 365:
                recent += 1
        health["releases_12m"] = recent
    contributors = _get("%s/%s/contributors?per_page=100&anon=false" % (GITHUB_API, slug), token=token)
    if isinstance(contributors, list):
        health["maintainers"] = min(len(contributors), 100)
    return health


def collect_from_deps_dev(eco, purl):
    system = ECO_TO_DEPS_SYSTEM.get(eco)
    if not system:
        return None
    name = purl.get("name")
    if not name:
        return None
    path = "%s/%s" % (purl.get("namespace"), name) if purl.get("namespace") else name
    url = "%s/%s/packages/%s" % (DEPS_DEV, system, path.replace("/", "%2F"))
    payload = _get(url)
    if not payload:
        return None
    versions = payload.get("versions") or []
    info = {
        "versions_count": len(versions),
        "latest_version": (versions[-1] or {}).get("versionKey", {}).get("version") if versions else None,
    }
    published = [v.get("publishedAt") for v in versions if v.get("publishedAt")]
    if published:
        info["latest_release_days"] = days_since(max(published))
    return info


def merge_health(base, extra):
    if not extra:
        return base
    for key, value in extra.items():
        if value is not None:
            base[key] = value
    return base


def main():
    parser = argparse.ArgumentParser(description="采集组件活跃度 / 健康度指标")
    parser.add_argument("--pkg-list", default="data/pkg_list.txt")
    parser.add_argument("--out", default="data/health.json")
    parser.add_argument("--repo-map", help="JSON：{\"purl\":\"owner/repo\"} 显式仓库映射")
    parser.add_argument("--fixtures", help="本地 JSON 目录，离线回放用（跳过网络）")
    parser.add_argument("--no-network", action="store_true", help="不发起任何网络请求")
    args = parser.parse_args()

    if (args.no_network or args.fixtures) and requests is None:
        pass
    elif requests is None:
        print("缺少 requests，无法联网采集；请使用 --fixtures", file=sys.stderr)
        return 2

    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    from oss_intake import purl as purl_mod

    repo_map = {}
    if args.repo_map and os.path.exists(args.repo_map):
        with open(args.repo_map, "r", encoding="utf-8") as handle:
            repo_map = json.load(handle)

    entries = []
    with open(args.pkg_list, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 3:
                continue
            eco = purl_mod.normalize_eco(parts[0].strip())
            name = parts[1].strip()
            version = parts[2].strip()
            namespace = None
            if eco == "maven" and ":" in name:
                namespace, name = name.split(":", 1)
            purl_value = purl_mod.build(eco, name, version, namespace)
            if purl_value:
                entries.append({"eco": eco, "purl": purl_value,
                                "info": purl_mod.parse(purl_value)})

    result = {}
    for entry in entries:
        purl_value = entry["purl"]
        health = {"purl": purl_value, "collected_at": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        if args.fixtures:
            fixture = os.path.join(args.fixtures, "health_%s.json" % abs(hash(purl_value)))
            if os.path.exists(fixture):
                with open(fixture, "r", encoding="utf-8") as handle:
                    health.update(json.load(handle))
        elif not args.no_network:
            slug = repo_map.get(purl_value) or github_slug(entry["info"], entry["eco"])
            if slug:
                merge_health(health, collect_from_github(slug, os.getenv("GITHUB_TOKEN")))
            merge_health(health, collect_from_deps_dev(entry["eco"], entry["info"]) or {})
        if "last_commit_days" not in health and "latest_release_days" in health:
            health["last_commit_days"] = health["latest_release_days"]
        if not any(k in health for k in ("archived", "releases_12m", "maintainers", "last_commit_days")):
            health["health_unknown"] = True
        result[purl_value] = health
        print("health: %s" % purl_value)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print("Wrote %s (%d components)" % (args.out, len(result)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
