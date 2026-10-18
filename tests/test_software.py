"""fetch_software.py（应用/基础设施软件维度）的离线测试。

覆盖（全部离线，不打网络）：
  - version_affected：NVD CPE 版本区间判断（含 / 不含、开闭区间、脏值）
  - cpe_vendor_product / cve_touches_software：CPE 前缀过滤与多前缀并集
  - best_cvss / cve_record：CVSS 优先级、描述截断、参考限量、CWE 提取
  - parse_release_version：release-1.24.0 / v1.24.0 → 1.24.0
  - build_document：fixtures 离线回放，产物结构对齐 community-support.json
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
            for cpe in entry["cpe"]:
                vendor, _, product = cpe.partition(":")
                self.assertTrue(vendor and product, (entry["name"], cpe))

    def test_select_entries_by_alias(self):
        picked = fs._select_entries(["k8s", "7zip"])
        self.assertEqual({e["name"] for e in picked},
                         {"Kubernetes", "7-Zip"})
        self.assertEqual(len(fs._select_entries([])), len(fs.SOFTWARE))


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
        self.assertEqual(row["version"], "1.27.3")
        self.assertTrue(row["purl"].startswith("pkg:generic/"))
        self.assertEqual(sum(support_doc["grade_counts"].values()), len(rows))


if __name__ == "__main__":
    unittest.main()
