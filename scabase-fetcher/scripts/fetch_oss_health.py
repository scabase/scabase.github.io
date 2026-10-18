"""采集开源组件活跃度 / 维护健康度指标。

数据源（按对评分信号的贡献）：
  1. deps.dev（跨生态元数据：下游依赖项目数、全部版本发布时间
     → 近 12 月发布数 / 最近发布距今天数；MAVEN/NPM/PYPI/GO/CARGO/RUBYGEMS/NUGET）
  2. GitHub API（archived、push 时间、发布数、贡献者数、星标、背后组织、
     SECURITY.md / CI、PR 合并周期）
  3. npm registry（月下载量；packument 的 maintainers 与发布时间，无 GitHub 信号时兜底；
     repository 字段推断 GitHub 仓库）
  4. PyPI JSON（project_urls / home_page 推断 GitHub 仓库，补全 PyPI 组件的 GitHub 信号）

任一源失败只降级，不中断整批任务。每个组件记录 `sources` 列表说明信号来源，
便于人工复核「未知即风险」扣分的构成。支持 --fixtures 用本地 JSON 离线回放，便于测试。
"""
import argparse
import calendar
import json
import os
import sys
import time
from urllib.parse import quote

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

GITHUB_API = "https://api.github.com/repos"
DEPS_DEV = "https://api.deps.dev/v3alpha/systems"
NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-month/"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_JSON = "https://pypi.org/pypi"

# npm packument 整包体积上限（@types/node 等超大类可达 10MB+，超出则放弃兜底）
NPM_PACKUMENT_MAX_BYTES = 4 * 1024 * 1024

# PyPI project_urls 标签优先级：越靠前越可能是源码仓库
PYPI_URL_LABEL_PRIORITY = ("source", "source code", "repository", "repo", "github",
                           "homepage", "home page", "home")

# 背后组织识别：基金会 / 厂商 / 一般组织 / 个人
KNOWN_FOUNDATION_ORGS = {"apache", "cncf", "linuxfoundation", "eclipse", "mozilla",
                         "python", "nodejs", "rust-lang", "openjsf"}
KNOWN_VENDOR_ORGS = {"google", "alibaba", "tencent", "spring-projects", "elastic",
                     "redhat", "microsoft", "amazon", "facebook", "meta", "vmware",
                     "oracle", "ibm", "netflix", "apple"}

ECO_TO_DEPS_SYSTEM = {
    "maven": "MAVEN",
    "npm": "NPM",
    "pypi": "PYPI",
    "go": "GO",
    "cargo": "CARGO",
    "gem": "RUBYGEMS",
    "nuget": "NUGET",
}


def _wait_env(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


# GitHub 配额等待预算（秒）：用法见 _rate_limit_sleep
WAIT_BUDGET = _wait_env("SCABASE_GH_WAIT_BUDGET", 1800)
_wait_left = [WAIT_BUDGET]


def reset_wait_budget(seconds=None):
    """重置等待预算（便于测试与分段使用）。"""
    _wait_left[0] = WAIT_BUDGET if seconds is None else seconds


def _rate_limit_sleep(resp, budget):
    """限流时睡到 X-RateLimit-Reset，预算内自动续跑。

    GitHub 配额按小时窗口计：CI 上 community-health（03:17，400+ 组件）与
    software-collect 相隔不到一小时，后者开跑时配额已被前者打满。旧实现只退避
    几秒就「降级」，于是相当一部分组件连仓库信息都没采到（65 个软件里只有 23 个
    有 stars、0 个 forks/watchers）。这里改为按服务端给出的 reset 时间等待，
    超出 WAIT_BUDGET 才降级。

    返回等待秒数；无需等待或预算不足时返回 None。
    """
    try:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset = int(resp.headers.get("X-RateLimit-Reset", "0") or 0)
    except (AttributeError, ValueError):
        return None
    if remaining != "0" or not reset:
        return None
    wait = reset - int(time.time()) + 2
    if wait <= 0 or wait > budget[0]:
        return None
    budget[0] -= wait
    print("  GitHub 配额已用尽，等待 %d 秒至配额重置（剩余预算 %d 秒）…"
          % (wait, budget[0]), file=sys.stderr)
    time.sleep(wait)
    return wait


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
            # 触发限流：优先睡到配额重置（不消耗重试次数），否则短退避重试
            if _rate_limit_sleep(resp, _wait_left) is None:
                time.sleep(min(60, 5 * (attempt + 1)))
            continue
        if resp.status_code >= 400:
            return None
        try:
            return resp.json()
        except ValueError:
            return None
    return None


def _parse_utc(iso_stamp):
    """把 UTC ISO 时间戳解析为 epoch 秒（timegm，不受本机时区影响）。"""
    try:
        return calendar.timegm(time.strptime(iso_stamp[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        try:
            return calendar.timegm(time.strptime(iso_stamp[:10], "%Y-%m-%d"))
        except (ValueError, OverflowError):
            return None


def days_since(iso_stamp):
    if not iso_stamp:
        return None
    parsed = _parse_utc(iso_stamp)
    if parsed is None:
        return None
    return max(0, int((time.time() - parsed) / 86400))


def count_within(stamps, days=365, now=None):
    """统计 ISO 时间戳中距今不超过 days 的数量（近 12 月发布数等）。"""
    horizon = (now if now is not None else time.time()) - days * 86400
    count = 0
    for stamp in stamps:
        if not stamp:
            continue
        parsed = _parse_utc(stamp)
        if parsed is not None and parsed >= horizon:
            count += 1
    return count


def github_slug_from_url(url):
    """从任意 URL 中提取 GitHub owner/repo（无则返回 None）。

    兼容 ``https://github.com/o/r``、``git+https://…/o/r.git`` 与
    ``git@github.com:o/r``（SCP 风格）三种写法。
    """
    if not url:
        return None
    text = str(url)
    if "github.com/" in text:
        tail = text.split("github.com/", 1)[1]
    elif "github.com:" in text:
        tail = text.split("github.com:", 1)[1]
    else:
        return None
    tail = tail.strip("/")
    if tail.endswith(".git"):
        tail = tail[:-4]
    parts = [part for part in tail.split("/") if part]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    return "%s/%s" % (parts[0], parts[1])


def slug_from_pypi_info(info):
    """从 PyPI JSON 的 info 块推断 GitHub 仓库（project_urls 优先 Source/Repository）。"""
    if not isinstance(info, dict):
        return None
    candidates = []
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for label, url in project_urls.items():
            if isinstance(url, str):
                candidates.append((str(label or "").strip().lower(), url))
    for key in ("home_page", "project_url"):
        value = info.get(key)
        if isinstance(value, str):
            candidates.append(("", value))

    def rank(item):
        label = item[0]
        return (PYPI_URL_LABEL_PRIORITY.index(label)
                if label in PYPI_URL_LABEL_PRIORITY else len(PYPI_URL_LABEL_PRIORITY))

    candidates.sort(key=rank)  # 稳定排序：同优先级保持原始顺序
    for _, url in candidates:
        slug = github_slug_from_url(url)
        if slug:
            return slug
    return None


def npm_packument_signals(payload):
    """npm packument → {maintainers, releases_12m}（供无 GitHub 信号时兜底）。"""
    out = {}
    maintainers = payload.get("maintainers") if isinstance(payload, dict) else None
    if isinstance(maintainers, list) and maintainers:
        out["maintainers"] = len(maintainers)
    time_map = payload.get("time") if isinstance(payload, dict) else None
    if isinstance(time_map, dict):
        stamps = [value for key, value in time_map.items()
                  if key not in ("created", "modified") and isinstance(value, str)]
        if stamps:
            out["releases_12m"] = count_within(stamps, 365)
    return out


def pypi_release_signals(payload):
    """PyPI 整包 JSON 的 releases → {releases_12m, latest_release_days}。"""
    releases = payload.get("releases") if isinstance(payload, dict) else None
    if not isinstance(releases, dict):
        return {}
    stamps = []
    for files in releases.values():
        if not isinstance(files, list):
            continue
        for item in files:
            stamp = item.get("upload_time") if isinstance(item, dict) else None
            if stamp:
                stamps.append(stamp)
    if not stamps:
        return {}
    return {"releases_12m": count_within(stamps, 365),
            "latest_release_days": days_since(max(stamps))}


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


def _head_status(url, token=None, timeout=20):
    """只取 HTTP 状态码，用于判断文件/目录是否存在。"""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except Exception:
        return None
    if resp.status_code in (403, 429) and _rate_limit_sleep(resp, _wait_left):
        try:
            return requests.get(url, headers=headers, timeout=timeout).status_code
        except Exception:
            return None
    return resp.status_code


def _org_backing(repo):
    """识别背后组织：foundation / vendor / organization / personal。"""
    owner = repo.get("owner") or {}
    login = (owner.get("login") or "").lower()
    if (owner.get("type") or "").lower() != "organization":
        return "personal" if login else None
    if login in KNOWN_FOUNDATION_ORGS:
        return "foundation"
    if login in KNOWN_VENDOR_ORGS:
        return "vendor"
    return "organization"


def collect_pr_merge_days(slug, token, limit=30):
    """近 limit 个已合并 PR 的平均合并周期（天）。"""
    pulls = _get("%s/%s/pulls?state=closed&sort=updated&direction=desc&per_page=%d"
                 % (GITHUB_API, slug, limit), token=token)
    if not isinstance(pulls, list):
        return None
    gaps = []
    for item in pulls:
        created = item.get("created_at")
        merged = item.get("merged_at") or item.get("closed_at")
        if not created or not merged:
            continue
        gap = days_since(created) - days_since(merged)
        if gap is not None and gap >= 0:
            gaps.append(gap)
    if not gaps:
        return None
    gaps.sort()
    middle = len(gaps) // 2
    if len(gaps) % 2:
        return float(gaps[middle])
    return round((gaps[middle - 1] + gaps[middle]) / 2.0, 1)


def collect_from_github(slug, token, releases_limit=100):
    repo = _get("%s/%s" % (GITHUB_API, slug), token=token)
    if not repo:
        return None
    health = {
        "archived": bool(repo.get("archived")),
        "deprecated": bool(repo.get("disabled")),
        "stars": repo.get("stargazers_count"),
        # forks_count 为仓库派生（fork）数；subscribers_count 即 watch 数
        # （GitHub 的 watchers 字段历史遗留等于 star 数，不能用作 watch）
        "forks": repo.get("forks_count"),
        "watchers": repo.get("subscribers_count"),
        "open_issues": repo.get("open_issues_count"),
        "last_commit_days": days_since(repo.get("pushed_at")),
        "repo": slug,
        "org_backing": _org_backing(repo),
    }
    security = _head_status("%s/%s/contents/SECURITY.md" % (GITHUB_API, slug), token)
    if security is not None:
        health["has_security_policy"] = security == 200
    workflows = _head_status("%s/%s/contents/.github/workflows" % (GITHUB_API, slug), token)
    if workflows is not None:
        health["has_ci"] = workflows == 200
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
        health["contributors"] = min(len(contributors), 100)
    merged_days = collect_pr_merge_days(slug, token)
    if merged_days is not None:
        health["pr_merge_days"] = merged_days
    return health


def deps_dev_package_path(eco, purl):
    """按生态拼 deps.dev 包名（与各 ecosystem 的官方命名一致）。

    MAVEN 为 ``groupId:artifactId``；NPM 的 scope 包保留 ``@`` 前缀
    （项目内 purl 约定把 scope 存为无 @ 的 namespace，这里要补回来）；
    Go 等其余生态为 ``namespace/name``。
    """
    name = purl.get("name")
    if not name:
        return None
    namespace = purl.get("namespace")
    system = ECO_TO_DEPS_SYSTEM.get(eco)
    if namespace and system == "MAVEN":
        return "%s:%s" % (namespace, name)
    if namespace and system == "NPM":
        return "@%s/%s" % (namespace, name)
    if namespace:
        return "%s/%s" % (namespace, name)
    return name


def collect_from_deps_dev(eco, purl):
    system = ECO_TO_DEPS_SYSTEM.get(eco)
    if not system:
        return None
    path = deps_dev_package_path(eco, purl)
    if not path:
        return None
    url = "%s/%s/packages/%s" % (DEPS_DEV, system, quote(path, safe=""))
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
        # 全版本发布时间 → 近 12 月发布数（无 GitHub 仓库的组件的主要节奏信号）
        info["releases_12m"] = count_within(published, 365)
    dependents = payload.get("dependentsCount")
    if dependents is None:
        dependents = payload.get("dependents_count")
    if dependents is not None:
        info["dependent_projects"] = dependents
    return info


def collect_from_npm(full_name):
    """npm 月下载量（采用度信号）。"""
    if requests is None or not full_name:
        return None
    try:
        resp = requests.get(NPM_DOWNLOADS + full_name.replace("/", "%2F"), timeout=15)
        if resp.status_code != 200:
            return None
        downloads = (resp.json() or {}).get("downloads")
        return {"monthly_downloads": downloads} if downloads is not None else None
    except Exception:
        return None


def npm_repo_slug(full_name):
    """从 npm registry 元数据推断 GitHub 仓库（owner/repo）。

    很多热门 npm 包没有登记在 repo-map 里，但其 registry 元数据自带仓库地址，
    据此补齐 GitHub 信号，避免「无仓库信息」被整套判成未知。
    """
    if requests is None or not full_name:
        return None
    try:
        resp = requests.get("%s/%s/latest" % (NPM_REGISTRY, full_name.replace("/", "%2F")),
                            timeout=20)
        if resp.status_code != 200:
            return None
        repo = (resp.json() or {}).get("repository")
    except Exception:
        return None
    url = ""
    if isinstance(repo, dict):
        url = repo.get("url") or ""
    elif isinstance(repo, str):
        url = repo
    return github_slug_from_url(url)


def collect_from_pypi(name, version):
    """PyPI JSON 采集：推断 GitHub 仓库 + （整包接口才有）发布时间信号。

    优先请求版本级接口（``/pypi/<name>/<version>/json``，约 10KB，含 project_urls），
    404（版本已删除 / 清单过期）时回退整包接口（大包可达数 MB）。
    返回 {"repo_hint": slug, "releases_12m": n, "latest_release_days": d} 或 None。
    """
    if requests is None or not name:
        return None
    encoded = quote(name, safe="")
    urls = []
    if version:
        urls.append("%s/%s/%s/json" % (PYPI_JSON, encoded, quote(version, safe="")))
    urls.append("%s/%s/json" % (PYPI_JSON, encoded))
    for url in urls:
        try:
            resp = requests.get(url, timeout=20, headers={"Accept": "application/json"})
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            payload = resp.json()
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        out = {"repo_hint": slug_from_pypi_info(payload.get("info"))}
        out.update(pypi_release_signals(payload))
        return out
    return None


def collect_from_npm_meta(full_name):
    """npm packument 兜底：maintainers 数 + 近 12 月发布数。

    仅在拿不到 GitHub 信号时调用（无仓库或 GitHub 采集失败）。
    整包 packument 对大包可达 10MB+，超限直接放弃（stream 预检 Content-Length）。
    """
    if requests is None or not full_name:
        return None
    url = "%s/%s" % (NPM_REGISTRY, full_name.replace("/", "%2F"))
    try:
        resp = requests.get(url, stream=True, timeout=20)
    except Exception:
        return None
    try:
        length = resp.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > NPM_PACKUMENT_MAX_BYTES:
            return None
        if resp.status_code != 200:
            return None
        payload = resp.json()
    except Exception:
        return None
    finally:
        resp.close()
    if not isinstance(payload, dict):
        return None
    return npm_packument_signals(payload)


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
            full_name = None
            if entry["eco"] == "npm":
                info = entry["info"] or {}
                full_name = ("@%s/%s" % (info.get("namespace"), info.get("name"))
                             if info.get("namespace") else info.get("name"))
            sources = []
            slug = repo_map.get(purl_value)
            if slug:
                sources.append("repo-map")
            if not slug:
                slug = github_slug(entry["info"], entry["eco"])
            if not slug and full_name:
                slug = npm_repo_slug(full_name)
                if slug:
                    sources.append("npm-registry")
            # PyPI：版本级 JSON 推断仓库（补全 repo-map 未登记的 PyPI 组件）
            pypi_meta = None
            if entry["eco"] == "pypi":
                pypi_meta = collect_from_pypi((entry["info"] or {}).get("name"),
                                              (entry["info"] or {}).get("version"))
                if pypi_meta:
                    repo_hint = pypi_meta.pop("repo_hint", None)
                    if not slug and repo_hint:
                        slug = repo_hint
                        sources.append("pypi")
            github_health = collect_from_github(slug, os.getenv("GITHUB_TOKEN")) if slug else None
            if github_health:
                merge_health(health, github_health)
                sources.append("github")
            deps_info = collect_from_deps_dev(entry["eco"], entry["info"])
            if deps_info:
                merge_health(health, deps_info)
                sources.append("deps.dev")
            if full_name:
                npm_info = collect_from_npm(full_name)
                if npm_info:
                    merge_health(health, npm_info)
                    if "npm-registry" not in sources:
                        sources.append("npm-registry")
            # 兜底一：PyPI 发布时间（deps.dev 缺失时）
            if pypi_meta:
                for key, value in pypi_meta.items():
                    if value is not None and key not in health:
                        health[key] = value
                if "pypi" not in sources:
                    sources.append("pypi")
            # 兜底二：npm packument 的 maintainers / 发布时间（无 GitHub 信号时）
            if full_name and not github_health:
                meta = collect_from_npm_meta(full_name)
                if meta:
                    for key, value in meta.items():
                        if value is not None and key not in health:
                            health[key] = value
                    if "npm-registry" not in sources:
                        sources.append("npm-registry")
            if sources:
                health["sources"] = sources
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
