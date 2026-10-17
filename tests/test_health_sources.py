"""健康度采集数据源补充的离线测试。

覆盖 fetch_oss_health 的新增能力（全部离线，用 FakeRequests 桩掉网络）：
  - count_within：近 12 月发布数统计（边界 / 脏数据 / now 注入）
  - github_slug_from_url：任意 URL → owner/repo
  - slug_from_pypi_info：PyPI project_urls 优先级推断仓库
  - npm_packument_signals：maintainers 与 time → releases_12m
  - pypi_release_signals：releases upload_time → 发布时间信号
  - collect_from_deps_dev：从 versions[].publishedAt 推导 releases_12m
  - collect_from_pypi：版本级接口优先、404 回退整包
  - collect_from_npm_meta：Content-Length 超限放弃
  - community_report：sources 透传与 source_counts 汇总
  - community_report：来源链接构造（deps_dev_url / registry_url）与报告行字段
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, cleanup  # noqa: E402

FETCHER = os.path.join(ROOT, "scabase-fetcher", "scripts")
sys.path.insert(0, FETCHER)

import community_report  # noqa: E402
import fetch_oss_health as foh  # noqa: E402


class FakeResp(object):
    def __init__(self, payload=None, status=200, headers=None):
        self._payload = payload
        self.status_code = status
        self.headers = headers or {}
        self.closed = False

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def close(self):
        self.closed = True


class FakeRequests(object):
    """按 URL 关键字返回预置响应，并记录请求过的 URL。"""

    def __init__(self, routes, default_status=404):
        self.routes = routes  # [(url 关键字, FakeResp)]
        self.default_status = default_status
        self.requested = []

    def get(self, url, timeout=0, stream=False, headers=None, **kwargs):
        self.requested.append(url)
        for needle, resp in self.routes:
            if needle in url:
                return resp
        return FakeResp(None, status=self.default_status)


def _iso(days_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days_ago * 86400))


class CountWithinTest(unittest.TestCase):
    def test_counts_only_recent_stamps(self):
        now = time.time()
        stamps = [_iso(10), _iso(200), _iso(400), _iso(800), "", None, "not-a-date"]
        self.assertEqual(foh.count_within(stamps, 365, now=now), 2)

    def test_boundary_is_inclusive(self):
        now = time.time()
        # 恰好 365 天（减 60s 缓冲避免秒级误差）
        self.assertEqual(foh.count_within([_iso(365 - 0.001)], 365, now=now), 1)

    def test_default_window_matches_parameter(self):
        now = time.time()
        self.assertEqual(foh.count_within([_iso(30), _iso(370)], now=now),
                         foh.count_within([_iso(30), _iso(370)], 365, now=now))


class GithubSlugFromUrlTest(unittest.TestCase):
    def test_common_forms(self):
        self.assertEqual(foh.github_slug_from_url("git+https://github.com/axios/axios.git"),
                         "axios/axios")
        self.assertEqual(foh.github_slug_from_url("https://github.com/lodash/lodash"),
                         "lodash/lodash")
        self.assertEqual(foh.github_slug_from_url("https://github.com/spring-projects/spring-boot/tree/main"),
                         "spring-projects/spring-boot")
        self.assertEqual(foh.github_slug_from_url("git@github.com:foo/bar.git"), "foo/bar")

    def test_rejects_non_github_and_incomplete(self):
        self.assertIsNone(foh.github_slug_from_url("https://gitlab.com/a/b.git"))
        self.assertIsNone(foh.github_slug_from_url("https://github.com/onlyowner"))
        self.assertIsNone(foh.github_slug_from_url(""))
        self.assertIsNone(foh.github_slug_from_url(None))


class SlugFromPypiInfoTest(unittest.TestCase):
    def test_source_label_beats_homepage(self):
        info = {"project_urls": {"Homepage": "https://requests.readthedocs.io",
                                 "Source": "https://github.com/psf/requests"}}
        self.assertEqual(foh.slug_from_pypi_info(info), "psf/requests")

    def test_gitlab_source_falls_through_to_github(self):
        info = {"project_urls": {"Source": "https://gitlab.com/a/b",
                                 "Repository": "https://github.com/c/d"}}
        self.assertEqual(foh.slug_from_pypi_info(info), "c/d")

    def test_home_page_fallback(self):
        self.assertEqual(foh.slug_from_pypi_info({"home_page": "https://github.com/pallets/flask"}),
                         "pallets/flask")

    def test_none_when_no_github(self):
        self.assertIsNone(foh.slug_from_pypi_info({"project_urls": {"Docs": "https://x.y"}}))
        self.assertIsNone(foh.slug_from_pypi_info(None))
        self.assertIsNone(foh.slug_from_pypi_info({}))


class NpmPackumentSignalsTest(unittest.TestCase):
    def test_maintainers_and_releases(self):
        now = time.time()
        payload = {
            "maintainers": [{"name": "a"}, {"name": "b"}],
            "time": {"created": _iso(3000), "modified": _iso(1),
                     "1.0.0": _iso(400), "1.1.0": _iso(100), "1.2.0": _iso(5)},
        }
        out = foh.npm_packument_signals(payload)
        self.assertEqual(out["maintainers"], 2)
        self.assertEqual(out["releases_12m"], 2)  # created/modified 不计入

    def test_empty_payload(self):
        self.assertEqual(foh.npm_packument_signals({}), {})
        self.assertEqual(foh.npm_packument_signals(None), {})


class PypiReleaseSignalsTest(unittest.TestCase):
    def test_skips_empty_file_lists(self):
        payload = {"releases": {
            "1.0.0": [{"upload_time": _iso(500)}],
            "2.0.0": [],                       # 空文件列表不得越界
            "3.0.0": [{"upload_time": _iso(3)}],
        }}
        out = foh.pypi_release_signals(payload)
        self.assertEqual(out["releases_12m"], 1)
        self.assertEqual(out["latest_release_days"], 3)

    def test_no_releases(self):
        self.assertEqual(foh.pypi_release_signals({}), {})
        self.assertEqual(foh.pypi_release_signals({"releases": {}}), {})


class DepsDevPathTest(unittest.TestCase):
    """deps.dev 包名按生态拼装（回归：Maven 冒号 / npm scope 带 @ 曾静默 404）。"""

    def test_ecosystem_specific_names(self):
        self.assertEqual(
            foh.deps_dev_package_path("maven", {"namespace": "com.alibaba", "name": "fastjson"}),
            "com.alibaba:fastjson")
        self.assertEqual(
            foh.deps_dev_package_path("npm", {"namespace": "babel", "name": "core"}),
            "@babel/core")
        self.assertEqual(foh.deps_dev_package_path("npm", {"name": "lodash"}), "lodash")
        self.assertEqual(
            foh.deps_dev_package_path("go", {"namespace": "github.com/gin-gonic", "name": "gin"}),
            "github.com/gin-gonic/gin")
        self.assertEqual(foh.deps_dev_package_path("pypi", {"name": "requests"}), "requests")
        self.assertIsNone(foh.deps_dev_package_path("maven", {"namespace": "com.alibaba"}))
        # 未知生态不拼特殊形态（由调用方按 ECO_TO_DEPS_SYSTEM 拦截）
        self.assertEqual(foh.deps_dev_package_path("unknown-eco", {"name": "x"}), "x")


class DepsDevReleasesTest(unittest.TestCase):
    """deps.dev 版本发布时间 → releases_12m / latest_release_days。"""

    class _Deps(FakeRequests):
        def __init__(self, payload):
            FakeRequests.__init__(self, [("api.deps.dev", FakeResp(payload))])

    def _collect(self, versions):
        payload = {"packageKey": "MAVEN/com.alibaba:fastjson",
                   "versions": versions,
                   "dependentsCount": 42}
        original = foh.requests
        try:
            foh.requests = self._Deps(payload)
            return foh.collect_from_deps_dev("maven", {"name": "fastjson",
                                                       "namespace": "com.alibaba"})
        finally:
            foh.requests = original

    def test_derives_releases_12m(self):
        versions = [{"versionKey": {"version": "1.2.0"}, "publishedAt": _iso(300)},
                    {"versionKey": {"version": "1.2.24"}, "publishedAt": _iso(30)},
                    {"versionKey": {"version": "0.9.0"}, "publishedAt": None}]
        info = self._collect(versions)
        self.assertEqual(info["releases_12m"], 2)  # 300 天与 30 天均在近 12 月内
        self.assertEqual(info["latest_release_days"], 30)
        self.assertEqual(info["dependent_projects"], 42)
        self.assertEqual(info["versions_count"], 3)

    def test_without_published_at(self):
        info = self._collect([{"versionKey": {"version": "1.0.0"}}])
        self.assertNotIn("releases_12m", info)
        self.assertNotIn("latest_release_days", info)


class CollectFromPypiTest(unittest.TestCase):
    def test_version_level_first_then_full_fallback(self):
        version_resp = FakeResp({"info": {"project_urls": {
            "Source": "https://github.com/psf/requests"}}})
        full_resp = FakeResp({"info": {"home_page": "https://github.com/boto/boto3"},
                              "releases": {"1.0.0": [{"upload_time": _iso(2)}]}})
        original = foh.requests
        try:
            # 版本级命中
            foh.requests = FakeRequests([("pypi.org/pypi/requests/2.31.0/json", version_resp)])
            out = foh.collect_from_pypi("requests", "2.31.0")
            self.assertEqual(out["repo_hint"], "psf/requests")
            self.assertNotIn("releases_12m", out)  # 版本级无发布历史
            # 版本级 404 → 回退整包
            foh.requests = FakeRequests([("pypi.org/pypi/boto3/json", full_resp)])
            out = foh.collect_from_pypi("boto3", "9.9.9")
            self.assertEqual(out["repo_hint"], "boto/boto3")
            self.assertEqual(out["releases_12m"], 1)
        finally:
            foh.requests = original

    def test_all_miss_returns_none(self):
        original = foh.requests
        try:
            foh.requests = FakeRequests([], default_status=404)
            self.assertIsNone(foh.collect_from_pypi("nope", "1.0.0"))
        finally:
            foh.requests = original


class CollectFromNpmMetaTest(unittest.TestCase):
    def test_signals_and_size_guard(self):
        payload = {"maintainers": [{"name": "a"}],
                   "time": {"1.0.0": _iso(10), "1.1.0": _iso(600)}}
        original = foh.requests
        try:
            ok = FakeRequests([("registry.npmjs.org/lodash",
                                FakeResp(payload, headers={"Content-Length": "1024"}))])
            foh.requests = ok
            self.assertEqual(foh.collect_from_npm_meta("lodash"),
                             {"maintainers": 1, "releases_12m": 1})
            # 超限直接放弃
            big = FakeRequests([("registry.npmjs.org/@types/node",
                                 FakeResp(payload, headers={"Content-Length": "99999999"}))])
            foh.requests = big
            self.assertIsNone(foh.collect_from_npm_meta("@types/node"))
            # 404 放弃
            foh.requests = FakeRequests([], default_status=404)
            self.assertIsNone(foh.collect_from_npm_meta("nope"))
        finally:
            foh.requests = original


class ReportSourcesTest(unittest.TestCase):
    def test_sources_passthrough_and_counts(self):
        health = {
            "pkg:pypi/requests@2.31.0": {"releases_12m": 4, "last_commit_days": 3,
                                         "sources": ["pypi", "github", "deps.dev"]},
            "pkg:maven/com.alibaba/fastjson@1.2.24": {"archived": True,
                                                      "last_commit_days": 900,
                                                      "sources": ["deps.dev"]},
            "pkg:npm/lodash@4.17.20": {"releases_12m": 2},  # 无 sources（旧数据兼容）
        }
        report = community_report.build_report(health)
        by_purl = {row["purl"]: row for row in report["components"]}
        self.assertEqual(by_purl["pkg:pypi/requests@2.31.0"]["sources"],
                         ["pypi", "github", "deps.dev"])
        self.assertEqual(by_purl["pkg:npm/lodash@4.17.20"]["sources"], [])
        self.assertEqual(report["source_counts"], {"pypi": 1, "github": 1, "deps.dev": 2})
        md = community_report.render_markdown(report)
        self.assertIn("数据来源覆盖", md)
        self.assertIn("deps.dev", md)


class SourceLinksTest(unittest.TestCase):
    """来源徽章 / 报告行的可点击链接（供人工核对）。"""

    def test_deps_dev_url_per_ecosystem(self):
        self.assertEqual(
            community_report.deps_dev_url(
                {"eco": "maven", "namespace": "com.alibaba", "name": "fastjson"}),
            "https://deps.dev/maven/com.alibaba:fastjson")
        # npm scope：purl 命名空间无 @，deps.dev 需要补回
        self.assertEqual(
            community_report.deps_dev_url({"eco": "npm", "namespace": "babel", "name": "core"}),
            "https://deps.dev/npm/@babel/core")
        self.assertEqual(
            community_report.deps_dev_url({"eco": "npm", "namespace": None, "name": "lodash"}),
            "https://deps.dev/npm/lodash")
        self.assertEqual(
            community_report.deps_dev_url({"eco": "pypi", "namespace": None, "name": "requests"}),
            "https://deps.dev/pypi/requests")
        self.assertEqual(
            community_report.deps_dev_url(
                {"eco": "go", "namespace": "github.com/gin-gonic", "name": "gin"}),
            "https://deps.dev/go/github.com/gin-gonic/gin")
        self.assertIsNone(community_report.deps_dev_url({"eco": "cargo", "name": "serde"}))
        self.assertIsNone(community_report.deps_dev_url({"eco": "maven", "name": None}))

    def test_registry_url_per_ecosystem(self):
        self.assertEqual(
            community_report.registry_url({"eco": "npm", "namespace": "babel", "name": "core"}),
            "https://www.npmjs.com/package/@babel/core")
        self.assertEqual(
            community_report.registry_url({"eco": "npm", "namespace": None, "name": "lodash"}),
            "https://www.npmjs.com/package/lodash")
        self.assertEqual(
            community_report.registry_url({"eco": "pypi", "namespace": None, "name": "requests"}),
            "https://pypi.org/project/requests/")
        self.assertEqual(
            community_report.registry_url(
                {"eco": "maven", "namespace": "com.alibaba", "name": "fastjson"}),
            "https://central.sonatype.com/artifact/com.alibaba/fastjson")
        self.assertEqual(
            community_report.registry_url(
                {"eco": "go", "namespace": "golang.org/x", "name": "net"}),
            "https://pkg.go.dev/golang.org/x/net")
        self.assertIsNone(community_report.registry_url({"eco": "maven", "namespace": None,
                                                         "name": "x"}))
        self.assertIsNone(community_report.registry_url({"eco": "pypi", "name": None}))

    def test_report_rows_carry_links(self):
        health = {
            "pkg:pypi/requests@2.31.0": {"repo": "psf/requests",
                                         "sources": ["pypi", "github", "deps.dev"]},
            "pkg:maven/com.alibaba/fastjson@1.2.24": {"sources": ["deps.dev"]},
            "pkg:go/github.com/gin-gonic/gin@1.6.0": {"sources": ["github", "repo-map"]},
            "pkg:npm/babel/core@7.0.0": {"sources": ["npm-registry"]},
        }
        report = community_report.build_report(health)
        by_purl = {row["purl"]: row for row in report["components"]}
        py = by_purl["pkg:pypi/requests@2.31.0"]
        self.assertEqual(py["repo"], "psf/requests")
        self.assertEqual(py["deps_dev"], "https://deps.dev/pypi/requests")
        self.assertEqual(py["registry"], "https://pypi.org/project/requests/")
        mvn = by_purl["pkg:maven/com.alibaba/fastjson@1.2.24"]
        self.assertEqual(mvn["deps_dev"], "https://deps.dev/maven/com.alibaba:fastjson")
        self.assertEqual(mvn["registry"],
                         "https://central.sonatype.com/artifact/com.alibaba/fastjson")
        self.assertIsNone(mvn["repo"])
        go = by_purl["pkg:go/github.com/gin-gonic/gin@1.6.0"]
        self.assertEqual(go["deps_dev"], "https://deps.dev/go/github.com/gin-gonic/gin")
        self.assertEqual(go["registry"], "https://pkg.go.dev/github.com/gin-gonic/gin")
        # 项目内 purl 约定：npm scope 存为无 @ 的 namespace
        npm_row = by_purl["pkg:npm/babel/core@7.0.0"]
        self.assertEqual(npm_row["deps_dev"], "https://deps.dev/npm/@babel/core")
        self.assertEqual(npm_row["registry"], "https://www.npmjs.com/package/@babel/core")
        # 容错：purl 里 scope 带 @ 时也不应拼出 @@
        at_form = community_report.deps_dev_url({"eco": "npm", "namespace": "@babel",
                                                 "name": "core"})
        self.assertEqual(at_form, "https://deps.dev/npm/@babel/core")

    def test_markdown_contains_clickable_source_links(self):
        health = {
            "pkg:pypi/requests@2.31.0": {"repo": "psf/requests",
                                         "sources": ["pypi", "github"]},
        }
        report = community_report.build_report(health)
        md = community_report.render_markdown(report)
        self.assertIn("数据来源（可点击核对）", md)
        self.assertIn("[GitHub](https://github.com/psf/requests)", md)
        self.assertIn("[deps.dev](https://deps.dev/pypi/requests)", md)
        self.assertIn("[PyPI](https://pypi.org/project/requests/)", md)


if __name__ == "__main__":
    unittest.main()
