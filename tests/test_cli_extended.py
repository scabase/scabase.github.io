"""CLI 新增子命令的冒烟测试：scan / baseline / genscript / verify / patrol / depinfo / gate 产物导出。

全部走内存与临时文件，不发起任何网络请求。
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, build_store, cleanup  # noqa: E402
from oss_intake import cli  # noqa: E402

DEPS = os.path.join(ROOT, "examples", "deps")
CASES = os.path.join(ROOT, "examples", "accuracy-cases.json")
DEPINFO = os.path.join(ROOT, "examples", "depinfo-export.json")

ASSETS = {
    "groups": [{
        "name": "支付群组",
        "apps": [{
            "name": "支付核心", "tier": "core", "exposure": "internet",
            "data_sensitivity": "high",
            "gavs": ["com.alibaba:fastjson:1.2.24",
                     "org.apache.logging.log4j:log4j-core:2.14.1"],
        }],
    }]
}


class CliExtendedTest(unittest.TestCase):
    def setUp(self):
        self.facts = build_store()
        self.work = tempfile.mkdtemp(prefix="oss-intake-cli-")

    def tearDown(self):
        cleanup(self.facts)
        cleanup(self.work)

    def _path(self, name):
        return os.path.join(self.work, name)

    def _write_assets(self):
        path = self._path("assets.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(ASSETS, handle, ensure_ascii=False)
        return path

    def test_scan_writes_json_and_markdown(self):
        json_path = self._path("scan.json")
        md_path = self._path("scan.md")
        self.assertEqual(cli.main(["scan", "--path", DEPS, "--app", "支付核心",
                                   "--json", json_path, "--md", md_path]), 0)
        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertIn("pkg:maven/com.alibaba/fastjson@1.2.24", payload["assets_entry"]["purls"])
        with open(md_path, "r", encoding="utf-8") as handle:
            self.assertIn("原生依赖文件扫描结果", handle.read())

    def test_baseline_lists_catalog(self):
        json_path = self._path("baseline.json")
        self.assertEqual(cli.main(["baseline", "--json", json_path]), 0)
        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertGreaterEqual(payload["count"], 30)

    def test_genscript_and_manifest(self):
        out_dir = self._path("scripts")
        self.assertEqual(cli.main(["genscript", "--rule", "redis-requirepass",
                                   "--target", "sreops", "--out-dir", out_dir]), 0)
        manifest_path = os.path.join(out_dir, "manifest.json")
        self.assertTrue(os.path.exists(manifest_path))
        script_path = os.path.join(out_dir, "redis-requirepass", "redis-requirepass.sh")
        self.assertTrue(os.path.exists(script_path))
        with open(script_path, "r", encoding="utf-8") as handle:
            self.assertIn("#!/bin/sh", handle.read())

    def test_verify_accuracy_gate(self):
        json_path = self._path("accuracy.json")
        self.assertEqual(cli.main(["verify", "--cases", CASES,
                                   "--threshold", "0.9", "--json", json_path]), 0)
        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertGreaterEqual(payload["accuracy"], 0.9)

    def test_patrol_and_tickets(self):
        assets = self._write_assets()
        self.assertEqual(cli.main(["inventory", "--facts", self.facts,
                                   "--assets", assets]), 0)
        json_path = self._path("patrol.json")
        tickets_path = self._path("tickets.json")
        state_path = self._path("state.json")
        self.assertEqual(cli.main(["patrol", "--facts", self.facts, "--assets", assets,
                                   "--json", json_path, "--tickets", tickets_path,
                                   "--state", state_path]), 0)
        with open(tickets_path, "r", encoding="utf-8") as handle:
            tickets = json.load(handle)["tickets"]
        self.assertTrue(tickets)
        self.assertTrue(os.path.exists(state_path))

    def test_depinfo_import_and_export(self):
        assets_path = self._path("depinfo-assets.json")
        self.assertEqual(cli.main(["depinfo", "--import", DEPINFO, "--out", assets_path]), 0)
        with open(assets_path, "r", encoding="utf-8") as handle:
            assets = json.load(handle)
        self.assertEqual(len(assets["groups"]), 2)

        gate_json = self._path("gate.json")
        self.assertEqual(cli.main(["gate", "--facts", self.facts, "--purl",
                                   "pkg:maven/com.alibaba/fastjson@1.2.24",
                                   "--json", gate_json, "--fail-on", "never"]), 0)
        result_path = self._path("depinfo-result.json")
        self.assertEqual(cli.main(["depinfo", "--results", gate_json,
                                   "--out", result_path]), 0)
        with open(result_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertTrue(payload["masked"])
        self.assertNotIn("apps", payload["items"][0])

    def test_gate_exports_cicd_artifacts(self):
        sarif = self._path("gate.sarif")
        junit = self._path("gate.xml")
        comment = self._path("mr.md")
        self.assertEqual(cli.main(["gate", "--facts", self.facts,
                                   "--purl", "pkg:maven/com.alibaba/fastjson@1.2.24",
                                   "--sarif", sarif, "--junit", junit,
                                   "--comment", comment, "--fail-on", "deny"]), 1)
        with open(sarif, "r", encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["version"], "2.1.0")
        with open(junit, "r", encoding="utf-8") as handle:
            self.assertIn("<failure", handle.read())
        with open(comment, "r", encoding="utf-8") as handle:
            self.assertIn("门禁未通过", handle.read())


    def test_gate_accepts_native_dependency_file(self):
        # 原生依赖文件（.sample 后缀）应走 depfile 解析，而非 sbom.ingest
        json_path = self._path("gate-native.json")
        self.assertEqual(cli.main([
            "gate", "--facts", self.facts,
            "--sbom", os.path.join(DEPS, "pom.xml.sample"),
            "--json", json_path, "--fail-on", "never"]), 0)
        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        purls = [item["purl"] for item in payload["results"]]
        self.assertGreaterEqual(len(purls), 4)
        self.assertIn("pkg:maven/com.alibaba/fastjson@1.2.24", purls)

    def test_gate_refuses_unparseable_sbom(self):
        # 解析不出任何组件时必须失败，MUST NOT 静默放行
        path = self._path("empty.cdx.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"bomFormat": "CycloneDX", "components": []}')
        self.assertEqual(cli.main(["gate", "--facts", self.facts, "--sbom", path,
                                   "--fail-on", "never"]), 2)

    def test_gate_scans_own_requirements(self):
        # 仓库自身的依赖面：scabase-fetcher/requirements.txt 里的 requests
        json_path = self._path("gate-self.json")
        self.assertEqual(cli.main([
            "gate", "--facts", self.facts,
            "--sbom", os.path.join(ROOT, "scabase-fetcher", "requirements.txt"),
            "--json", json_path, "--fail-on", "never"]), 0)
        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual([item["purl"] for item in payload["results"]],
                         ["pkg:pypi/requests@2.32.4"])


if __name__ == "__main__":
    unittest.main()
