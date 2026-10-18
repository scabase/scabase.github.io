"""fetch_software.py（应用/基础设施软件维度）的离线测试。

覆盖（全部离线，不打网络）：
  - version_affected：NVD CPE 版本区间判断（含 / 不含、开闭区间、脏值）
  - cpe_vendor_product / cve_touches_software：CPE 前缀过滤与多前缀并集
  - best_cvss / cve_record：CVSS 优先级、描述截断、参考限量、CWE 提取
  - parse_release_version：release-1.24.0 / v1.24.0 → 1.24.0
  - build_document：fixtures 离线回放，产物结构对齐 community-support.json
  - build_document：离线重建沿用旧数据，全清单占位（未采集软件也可查询）
  - 数据文件：software-vulns.json 覆盖全清单且带分类
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT  # noqa: E402

FETCHER = os.path.join(ROOT, "scabase-fetcher", "scripts")
sys.path.insert(0, FETCHER)

import fetch_software as fs  # noqa: E402


def _cve(cve_id, cpe, published="2024-01-15T00:00:00.000", desc="desc"):
    return {
        "id": cve_id,
        "published": published,
        "descriptions": [{"lang": "en", "value": desc}],
        "configurations": [{
            "nodes": [{"cpeMatch": [
                {"criteria": cpe, "vulnerable": True,
                 "versionEndExcluding": "1.20.1"}
            ]}]
        }],
        "metrics": {"cvssMetricV31": [{
            "cvssData": {"baseScore": 7.7, "baseSeverity": "HIGH"},
            "baseSeverity": "HIGH"}]},
        "weaknesses": [{"description": [{"value": "CWE-787"}]}],
        "references": [{"url": "https://example.com/a"},
                       {"url": "https://example.com/b"}],
    }


class VersionAffectedTest(unittest.TestCase):
    def test_end_excluding_boundaries(self):
        match = {"versionEndExcluding": "1.20.1"}
        self.assertTrue(fs.version_affected(match, "1.20.0"))
        self.assertTrue(fs.version_affected(match, "1.9.0"))
        self.assertFalse(fs.version_affected(match, "1.20.1"))
        self.assertFalse(fs.version_affected(match, "1.21.0"))

    def test_range_inclusive_exclusive(self):
        match = {"versionStartIncluding": "1.2.0",
                 "versionEndIncluding": "1.4.9"}
        self.assertTrue(fs.version_affected(match, "1.2.0"))
        self.assertTrue(fs.version_affected(match, "1.4.9"))
        self.assertFalse(fs.version_affected(match, "1.1.9"))
        self.assertFalse(fs.version_affected(match, "1.5.0"))

    def test_dash_placeholder_is_ignored(self):
        match = {"versionStartIncluding": "-", "versionEndExcluding": "-"}
        self.assertTrue(fs.version_affected(match, "9.9.9"))

    def test_no_version_means_all(self):
        self.assertTrue(fs.version_affected({"versionEndExcluding": "1.0"}, ""))
        self.assertTrue(fs.version_affected({}, None))

    def test_v_prefix_normalized(self):
        match = {"versionEndExcluding": "1.20.1"}
        self.assertTrue(fs.version_affected(match, "v1.19.0"))


class CpeFilterTest(unittest.TestCase):
    def test_vendor_product_extraction(self):
        self.assertEqual(
            fs.cpe_vendor_product("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"),
            "f5:nginx")
        self.assertIsNone(fs.cpe_vendor_product("cpe:2.3:o:linux:linux_kernel:*"))
        self.assertIsNone(fs.cpe_vendor_product("garbage"))

    def test_touches_software_multi_prefix(self):
        cve = _cve("CVE-2024-0001", "cpe:2.3:a:oracle:mysql:8.0.0:*:*:*:*:*:*:*")
        # MySQL 同时收录 oracle:mysql 与 mysql:mysql 两个前缀
        self.assertTrue(fs.cve_touches_software(
            cve, ["oracle:mysql", "mysql:mysql"]))
        self.assertFalse(fs.cve_touches_software(cve, ["mariadb:mariadb"]))
        self.assertFalse(fs.cve_touches_software(cve, []))

    def test_touches_software_collects_all_matches(self):
        cve = _cve("CVE-2024-0002", "cpe:2.3:a:redis:redis:7.0.0:*:*:*:*:*:*:*")
        hits = fs.cve_touches_software(cve, ["redis:redis", "redislabs:redis"])
        self.assertEqual(len(hits), 1)


class CveRecordTest(unittest.TestCase):
    def test_record_structure_and_limits(self):
        long_desc = "x" * 500
        cve = _cve("CVE-2024-0003", "cpe:2.3:a:nginx:nginx:1.0.0:*:*:*:*:*:*:*",
                   desc=long_desc)
        cve["references"] = [{"url": "https://example.com/%d" % i}
                             for i in range(10)]
        record = fs.cve_record(
            cve, fs.cve_touches_software(cve, ["f5:nginx", "nginx:nginx"]))
        self.assertEqual(record["id"], "CVE-2024-0003")
        self.assertEqual(record["cvss"], 7.7)
        self.assertEqual(record["severity"], "HIGH")
        self.assertEqual(record["weaknesses"], ["CWE-787"])
        self.assertEqual(record["published"], "2024-01-15")
        self.assertLessEqual(len(record["description"]), 301)
        self.assertTrue(record["description"].endswith("…"))
        self.assertLessEqual(len(record["references"]), 5)
        self.assertEqual(record["affected"],
                         [{"start_including": None, "start_excluding": None,
                           "end_including": None, "end_excluding": "1.20.1"}])

    def test_record_dedupes_identical_ranges(self):
        cve = _cve("CVE-2024-0004", "cpe:2.3:a:f5:nginx:1.0.0:*:*:*:*:*:*:*")
        hits = [{"criteria": "a", "versionEndExcluding": "1.20.1"},
                {"criteria": "b", "versionEndExcluding": "1.20.1"}]
        record = fs.cve_record(cve, hits)
        self.assertEqual(len(record["affected"]), 1)


class ReleaseVersionTest(unittest.TestCase):
    def test_parse_release_version(self):
        self.assertEqual(fs.parse_release_version("v1.24.0"), "1.24.0")
        self.assertEqual(fs.parse_release_version("release-1.24.0"), "1.24.0")
        self.assertEqual(fs.parse_release_version("1.24.0"), "1.24.0")
        self.assertEqual(fs.parse_release_version("openssl-4.0.3"), "4.0.3")
        self.assertEqual(fs.parse_release_version("docker-v29.9.1"), "29.9.1")
        self.assertEqual(fs.parse_release_version("curl-8_23_0"), "8.23.0")
        self.assertEqual(fs.parse_release_version(""), "")

    def test_version_tuple(self):
        self.assertEqual(fs.version_tuple("1.24.0"), (1, 24, 0))
        self.assertEqual(fs.version_tuple("23.01"), (23, 1))
        self.assertEqual(fs.version_tuple("v2.14.1-rc1"), (2, 14, 1))
        self.assertEqual(fs.version_tuple(""), ())


class SoftwareCatalogTest(unittest.TestCase):
    def test_user_examples_present(self):
        names = {e["name"].lower() for e in fs.SOFTWARE}
        aliases = {a for e in fs.SOFTWARE for a in e.get("aliases") or []}
        self.assertIn("nginx", names)
        self.assertIn("7-zip", names)
        self.assertIn("zookeeper", names)
        self.assertIn("kubernetes", names)
        for alias in ("7zip", "zk", "k8s", "httpd", "postgres"):
            self.assertIn(alias, aliases)

    def test_entries_well_formed(self):
        for entry in fs.SOFTWARE:
            self.assertTrue(entry.get("name"), entry)
            self.assertTrue(entry.get("cpe"), entry["name"])
            self.assertTrue(entry.get("keywords"), entry["name"])
            # 分类供前端 chips 分组与清单浏览，每个软件都必须有
            self.assertTrue(entry.get("category"), entry["name"])
            for cpe in entry["cpe"]:
                vendor, _, product = cpe.partition(":")
                self.assertTrue(vendor and product, (entry["name"], cpe))

    def test_aliases_are_lowercase(self):
        # 前端别名索引统一小写匹配，清单里的别名必须全小写
        for entry in fs.SOFTWARE:
            for alias in entry.get("aliases") or []:
                self.assertEqual(alias, alias.lower(), (entry["name"], alias))

    def test_select_entries_by_alias(self):
        picked = fs._select_entries(["k8s", "7zip"])
        self.assertEqual({e["name"] for e in picked},
                         {"Kubernetes", "7-Zip"})
        self.assertEqual(len(fs._select_entries([])), len(fs.SOFTWARE))


class GithubTokenTest(unittest.TestCase):
    """GITHUB_TOKEN 必须独立于 NVD_API_KEY 读取。

    历史事故：脚本只读 NVD_API_KEY，CI 注入的 GITHUB_TOKEN 从未被使用，
    GitHub 调用全匿名（60 次/时），限流后 42/65 软件连仓库信息都没采到。
    """

    def test_reads_github_token_from_env(self):
        self.assertEqual(fs._github_token({"GITHUB_TOKEN": "ghs_x"}), "ghs_x")
        self.assertIsNone(fs._github_token({}))
        self.assertIsNone(fs._github_token({"GITHUB_TOKEN": ""}))
        self.assertIsNone(fs._github_token({"NVD_API_KEY": "nvd-only"}))

    def test_real_env_token_is_none_or_nonempty(self):
        # 本地/CI 沙箱通常无 token：函数应安静返回 None 或非空串，不抛错
        value = fs._github_token()
        self.assertTrue(value is None or (isinstance(value, str) and value), value)


class LatestReleaseVersionTest(unittest.TestCase):
    """版本提取：Releases 优先，无 Release 回退 tags 并按版本取最大。"""

    def test_looks_like_version(self):
        for good in ("18.1", "23.01", "1.24.0", "8"):
            self.assertTrue(fs._looks_like_version(good), good)
        for bad in ("master", "18.STABLE", "", "1.2.3-rc1", "v1.2.3"):
            self.assertFalse(fs._looks_like_version(bad), bad)

    def test_releases_preferred(self):
        def fake_get(url, **kwargs):
            if "releases?per_page" in url:
                return [{"tag_name": "v2.0.0-beta", "prerelease": True},
                        {"tag_name": "v1.31.7"}]
            if "releases/latest" in url:
                return {"tag_name": "v1.31.7"}
            raise AssertionError("有 Release 时不应回退 tags：%s" % url)

        original = fs._get_json
        fs._get_json = fake_get
        try:
            self.assertEqual(fs._latest_release_version("nginx/nginx"), "1.31.7")
        finally:
            fs._get_json = original

    @staticmethod
    def _install_fake(tags, dates):
        """tags 名称 → 提交日期 的假 API（日期可为 None 表示请求失败）。"""
        stamp = {"n": 0}

        def fake_get(url, **kwargs):
            if "releases?per_page" in url:
                return []
            if "releases/latest" in url:
                return {}
            if "/tags" in url:
                return [{"name": name} for name in tags]
            if "commits?sha=" in url:
                name = url.split("sha=", 1)[1].split("&", 1)[0]
                date = dates.get(name)
                if date is None:
                    return []
                return [{"commit": {"committer": {"date": date}}}]
            raise AssertionError(url)

        original = fs._get_json
        fs._get_json = fake_get
        return original

    def test_tags_fallback_for_release_less_repos(self):
        """PostgreSQL 只打 tag（REL_18_1）不建 GitHub Release。

        tags 接口实测按名称 ASCII 降序返回（古代 tag 反而在前），
        因此必须按版本号取最大，而不是取第一条。
        """
        tags = ["release-6-3", "Release_2_0_0", "master", "REL_18_STABLE",
                "REL_17_6", "REL_18_1", "REL_19_RC1"]
        dates = {name: "2025-11-10T21:52:06Z" for name in tags}
        original = self._install_fake(tags, dates)
        try:
            self.assertEqual(fs._latest_release_version("postgres/postgres"), "18.1")
        finally:
            fs._get_json = original

    def test_tag_cadence_counts_only_recent(self):
        """发布节奏只数近 12 个月的版本 tag；分支/RC tag 不计数。"""
        tags = ["master", "REL_18_STABLE", "REL_18_2", "REL_18_1",
                "REL_17_9", "REL_17_8", "REL_19_RC1"]
        import time
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        old = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(time.time() - 400 * 86400))
        dates = {"REL_18_2": now, "REL_18_1": old, "REL_17_9": old,
                 "REL_17_8": old}
        original = self._install_fake(tags, dates)
        try:
            signals = fs._tag_release_signals("postgres/postgres")
        finally:
            fs._get_json = original
        self.assertEqual(signals["version"], "18.2")
        self.assertEqual(signals["releases_12m"], 1)

    def test_no_version_anywhere(self):
        def fake_get(url, **kwargs):
            return [] if "releases?per_page" in url or "/tags" in url else {}

        original = fs._get_json
        fs._get_json = fake_get
        try:
            self.assertIsNone(fs._latest_release_version("redis/redis"))
            self.assertEqual(fs._tag_release_signals("redis/redis"), {})
        finally:
            fs._get_json = original


class ScoringKeyContractTest(unittest.TestCase):
    """信号键名契约：pushed_days 不是评分键（事故回归）。"""

    def test_pushed_days_is_not_a_scoring_key(self):
        import oss_intake.community as community
        result = community.evaluate({"pushed_days": 1})
        self.assertIn("last_commit_days", result["missing"])
        self.assertIsNone(result["signals"]["last_commit_days"])

    def test_last_commit_days_is_scored(self):
        import oss_intake.community as community
        result = community.evaluate({"last_commit_days": 1})
        self.assertNotIn("last_commit_days", result["missing"])
        self.assertEqual(result["signals"]["last_commit_days"], 1.0)


class BuildDocumentFixtureTest(unittest.TestCase):
    """用 fixtures 目录离线回放，验证产物结构与字段透传。"""

    FIXTURES = os.path.join(ROOT, "tests", "fixtures", "software")

    def test_fixture_roundtrip(self):
        if not os.path.isdir(self.FIXTURES):
            self.skipTest("fixtures 目录不存在")
        vulns_doc, support_doc = fs.build_document(
            False, None, fixtures=self.FIXTURES, health=True)
        # fixtures 模式遍历全清单，只有 nginx 有回放文件
        self.assertEqual(vulns_doc["software_count"], len(fs.SOFTWARE))
        self.assertEqual(vulns_doc["source"].startswith("NVD"), True)
        by_name = {s["name"]: s for s in vulns_doc["software"]}
        self.assertEqual(by_name["nginx"]["cve_count"], 2)
        self.assertEqual(by_name["nginx"]["repo"], "nginx/nginx")
        self.assertEqual(by_name["nginx"]["cve_count"],
                         len(by_name["nginx"]["cves"]))
        self.assertEqual(by_name["Redis"]["cve_count"], 0)  # 无 fixture → 空占位
        rows = {r["software"]: r for r in support_doc["components"]}
        self.assertEqual(len(rows), len(fs.SOFTWARE))
        row = rows["nginx"]
        for key in ("purl", "display", "software", "eco", "score", "grade",
                    "sources", "repo", "missing", "advice"):
            self.assertIn(key, row)
        self.assertEqual(row["eco"], "software")
        self.assertEqual(row["version"], "1.31.7")
        self.assertTrue(row["purl"].startswith("pkg:generic/"))
        self.assertEqual(sum(support_doc["grade_counts"].values()), len(rows))

    def test_fixture_signals_reach_the_card(self):
        """fixture 里的 GitHub 信号必须流入评分卡（键名契约的端到端守卫）。

        fixture 即 collect_from_github 的输出形态；若采集端改写键名
        （如历史事故里的 pushed_days），这里的断言会先失败。
        """
        if not os.path.isdir(self.FIXTURES):
            self.skipTest("fixtures 目录不存在")
        _, support_doc = fs.build_document(
            False, None, fixtures=self.FIXTURES, health=True)
        row = {r["software"]: r for r in support_doc["components"]}["nginx"]
        self.assertEqual(row["last_commit_days"], 1)
        self.assertEqual(row["releases_12m"], 24)
        self.assertEqual(row["maintainers"], 100)
        self.assertEqual(row["org_backing"], "organization")
        self.assertEqual(row["stars"], 31908)
        # 信号齐全：只剩无数据源的依赖数/下载量与 issue 响应时长
        self.assertNotIn("last_commit_days", row["missing"])
        self.assertNotIn("releases_12m", row["missing"])
        self.assertNotIn("maintainers", row["missing"])
        self.assertEqual(row["grade"], "A")


class OfflineRebuildTest(unittest.TestCase):
    """离线重建（不联网、不传 fixtures）：未选中的软件沿用旧数据。

    这是「统一查询清单」的数据基础：即使某软件还没采集到 CVE / 健康度，
    也会以空占位进入产物，前端据此渲染「未采集」卡而不是查无此项。
    """

    def test_offline_rebuild_emits_full_manifest(self):
        prior_vulns = {"software": [{
            "name": "nginx", "aliases": ["nginx"], "cpe": ["f5:nginx"],
            "repo": "nginx/nginx", "cve_count": 2,
            "cves": [{"id": "CVE-1"}, {"id": "CVE-2"}]
        }]}
        prior_support = {"components": [
            {"software": "nginx", "purl": "pkg:generic/nginx@1.0", "grade": "B"}
        ]}
        vulns_doc, support_doc = fs.build_document(
            False, None, existing_vulns=prior_vulns, existing_support=prior_support)
        self.assertEqual(vulns_doc["software_count"], len(fs.SOFTWARE))
        by_name = {s["name"]: s for s in vulns_doc["software"]}
        # 旧数据完整保留
        self.assertEqual(by_name["nginx"]["cve_count"], 2)
        self.assertEqual(len(by_name["nginx"]["cves"]), 2)
        # 未采集软件：空占位但别名 / CPE / 分类齐全，可被前端索引
        self.assertEqual(by_name["Redis"]["cve_count"], 0)
        self.assertEqual(by_name["Redis"]["cves"], [])
        self.assertTrue(by_name["Redis"]["aliases"])
        self.assertTrue(by_name["Redis"]["cpe"])
        for entry in vulns_doc["software"]:
            self.assertTrue(entry.get("category"), entry["name"])
        # 健康度只保留已采集的行
        self.assertEqual(len(support_doc["components"]), 1)
        self.assertEqual(support_doc["grade_counts"], {"B": 1})


class SoftwareDataFileTest(unittest.TestCase):
    """已发布的数据文件必须是全清单（否则前端只能查到已采集的子集）。"""

    PATH = os.path.join(ROOT, "scabase-fetcher", "data", "software-vulns.json")

    def test_data_covers_full_manifest_with_categories(self):
        if not os.path.exists(self.PATH):
            self.skipTest("software-vulns.json 尚未生成")
        with open(self.PATH, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        names = {s["name"] for s in doc["software"]}
        self.assertEqual(names, {e["name"] for e in fs.SOFTWARE})
        collected = [s for s in doc["software"] if s["cve_count"] > 0]
        self.assertGreater(len(collected), 0)  # 至少有已采集样本
        for entry in doc["software"]:
            self.assertTrue(entry.get("category"), entry["name"])
            self.assertEqual(entry["cve_count"], len(entry["cves"]))


if __name__ == "__main__":
    unittest.main()
