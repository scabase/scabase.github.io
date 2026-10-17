"""常用依赖 Top 清单的生成 / 消费链路测试（全部离线，不发起网络请求）。

覆盖：
  - gen_popular_packages 的产物结构（四生态 Top N、pkg_list 行、缺版本条目跳过）
  - 种子清单自身去重与规模
  - 版本比较（Maven / PyPI / Go 常见版本形态）
  - fetch_oss_health 从 npm registry 元数据推断 GitHub 仓库
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, cleanup  # noqa: E402

FETCHER = os.path.join(ROOT, "scabase-fetcher", "scripts")
sys.path.insert(0, FETCHER)

import fetch_oss_health  # noqa: E402
import gen_popular_packages as gen  # noqa: E402


class SeedTest(unittest.TestCase):
    def test_seed_lists_have_enough_unique_entries(self):
        for name in ("MAVEN_SEEDS", "NPM_SEEDS", "PYPI_SEEDS", "GO_SEEDS"):
            seeds = getattr(gen, name)
            self.assertGreaterEqual(len(seeds), 100, name)
            self.assertEqual(len(seeds), len({seed[0] for seed in seeds}), name)

    def test_maven_seed_names_are_gav(self):
        for gav, _desc in gen.MAVEN_SEEDS:
            self.assertEqual(gav.count(":"), 1, gav)

    def test_npm_keywords_are_long_enough(self):
        # registry 搜索接口要求 text 长度 2~64
        for keyword in gen.NPM_KEYWORDS:
            self.assertTrue(2 <= len(keyword) <= 64, keyword)


class VersionCompareTest(unittest.TestCase):
    def test_maven_style_versions(self):
        cases = [
            ("2.7.0", "2.7.18", "2.7.18"),
            ("1.2.24", "1.2.80", "1.2.80"),
            ("1.2", "1.2.0", "1.2.0"),
            ("7.0.9", "7.1.0-M2", "7.1.0-M2"),
            ("1.0.0", "1.0.0.Final", "1.0.0.Final"),
            ("6.0.0", "6.0.0-bridge.1", "6.0.0"),
        ]
        for older, newer, want in cases:
            self.assertEqual(max([older, newer], key=gen.version_key), want,
                             "%s vs %s" % (older, newer))

    def test_pypi_style_versions(self):
        cases = [
            ("2.32.4", "2.32.5", "2.32.5"),
            ("1.0.0", "1.0.0.post1", "1.0.0.post1"),
            ("1.0.0", "1.0.0rc1", "1.0.0"),
            ("4.16.0", "4.9.0", "4.16.0"),
        ]
        for older, newer, want in cases:
            self.assertEqual(max([older, newer], key=gen.version_key), want,
                             "%s vs %s" % (older, newer))

    def test_go_style_versions(self):
        cases = [
            ("v1.9.0", "v1.11.1", "v1.11.1"),
            ("v2.0.0+incompatible", "v2.0.1", "v2.0.1"),
            ("v1.0.0", "v1.0.0-rc.1", "v1.0.0"),
        ]
        for older, newer, want in cases:
            self.assertEqual(max([older, newer], key=gen.version_key), want,
                             "%s vs %s" % (older, newer))

    def test_pick_latest_stable_prefers_release(self):
        self.assertEqual(
            gen.pick_latest_stable(["7.0.9", "7.1.0-M2", "7.0.10"]), "7.0.10")
        self.assertEqual(
            gen.pick_latest_stable(["v0.0.0-20230101000000-abcdef", "v1.2.3"]),
            "v1.2.3")
        # 只有预发布/伪版本时退回最新
        self.assertEqual(
            gen.pick_latest_stable(["v0.0.0-20230101000000-abcdef",
                                    "v0.0.0-20240101000000-abcdef"]),
            "v0.0.0-20240101000000-abcdef")

    def test_empty_versions(self):
        self.assertIsNone(gen.pick_latest_stable([]))
        self.assertEqual(gen.sort_versions([]), [])


class GenPopularPackagesTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="popular-")
        self.json_path = os.path.join(self.work, "popular-packages.json")
        self.txt_path = os.path.join(self.work, "pkg_list_popular.txt")

    def tearDown(self):
        cleanup(self.work)

    def test_document_has_four_top_lists(self):
        document = gen.build_document(refresh=False, top=100)
        self.assertEqual([group["key"] for group in document["lists"]],
                         ["maven", "npm", "pypi", "go"])
        for group in document["lists"]:
            self.assertEqual(group["count"], 100, group["key"])
            self.assertEqual([item["rank"] for item in group["items"]],
                             list(range(1, 101)), group["key"])
            self.assertTrue(group["rank_basis"], group["key"])
            self.assertTrue(group["items"][0]["line"].startswith(group["ecosystem"] + "|"))

    def test_line_format_is_pkg_list(self):
        document = gen.build_document(refresh=False, top=3)
        for group in document["lists"]:
            for item in group["items"]:
                # 离线模式无版本，行仍保持三段式结构
                self.assertEqual(item["line"], "%s|%s|" % (group["ecosystem"], item["name"]))

    def test_write_txt_skips_versionless_items(self):
        document = gen.build_document(refresh=False, top=5)
        for group in document["lists"]:
            group["items"][0]["version"] = "1.2.3"
            group["items"][0]["line"] = "%s|%s|1.2.3" % (group["ecosystem"],
                                                         group["items"][0]["name"])
        original_json, original_txt = gen.JSON_OUT, gen.TXT_OUT
        try:
            gen.JSON_OUT, gen.TXT_OUT = self.json_path, self.txt_path
            gen.write_txt(document)
            with open(self.txt_path, "r", encoding="utf-8") as handle:
                lines = [line for line in handle.read().splitlines()
                         if line and not line.startswith("#")]
            self.assertEqual(len(lines), 4)  # 四份清单各仅第一项有版本
            for line in lines:
                self.assertEqual(len(line.split("|")), 3)
                self.assertTrue(line.split("|")[2], line)
        finally:
            gen.JSON_OUT, gen.TXT_OUT = original_json, original_txt

    def test_top_argument_truncates(self):
        document = gen.build_document(refresh=False, top=7)
        for group in document["lists"]:
            self.assertEqual(len(group["items"]), 7)

    def test_offline_document_roundtrip(self):
        document = gen.build_document(refresh=False, top=12)
        original_json = gen.JSON_OUT
        try:
            gen.JSON_OUT = self.json_path
            gen.write_json(document)
            reloaded = gen.load_existing(self.json_path)
            self.assertEqual([g["key"] for g in reloaded["lists"]],
                             ["maven", "npm", "pypi", "go"])
            self.assertEqual(reloaded["lists"][0]["count"], 12)
        finally:
            gen.JSON_OUT = original_json


class NpmRepoSlugTest(unittest.TestCase):
    class FakeResp:
        def __init__(self, payload, status=200):
            self._payload = payload
            self.status_code = status

        def json(self):
            return self._payload

    class FakeRequests:
        def __init__(self, payload):
            self.payload = payload

        def get(self, url, timeout=0):
            return NpmRepoSlugTest.FakeResp(self.payload)

    def _call(self, payload):
        original = fetch_oss_health.requests
        try:
            fetch_oss_health.requests = self.FakeRequests(payload)
            return fetch_oss_health.npm_repo_slug("axios")
        finally:
            fetch_oss_health.requests = original

    def test_slug_from_dict_repository(self):
        self.assertEqual(
            self._call({"repository": {"url": "git+https://github.com/axios/axios.git"}}),
            "axios/axios")

    def test_slug_from_string_repository(self):
        self.assertEqual(
            self._call({"repository": "https://github.com/lodash/lodash.git"}),
            "lodash/lodash")

    def test_non_github_returns_none(self):
        self.assertIsNone(self._call({"repository": {"url": "https://gitlab.com/a/b.git"}}))
        self.assertIsNone(self._call({}))


if __name__ == "__main__":
    unittest.main()
