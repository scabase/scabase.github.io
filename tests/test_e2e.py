"""端到端冒烟：互联网侧构建 → 摆渡 → 内网导入 → 引入前门禁 → 群组评估。

全程不发起任何网络请求。
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from fixtures import ROOT as ROOT_PATH, build_store, cleanup, tmp_facts  # noqa: E402
from oss_intake import cli  # noqa: E402
from oss_intake import facts as facts_mod  # noqa: E402

KEY = "e2e-key"
ASSETS = os.path.join(ROOT, "examples", "assets.json")
SBOM = os.path.join(ROOT, "examples", "sample-app.cdx.json")


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.src = build_store()
        self.dst = tmp_facts()
        self.ferry = tempfile.mkdtemp(prefix="oss-intake-ferry-")
        self.work = tempfile.mkdtemp(prefix="oss-intake-work-")

    def tearDown(self):
        for path in (self.src, self.dst, self.ferry, self.work):
            cleanup(path)

    def _bundle_all(self):
        paths = []
        for dataset in ("vulns", "health", "license"):
            code = cli.main(["bundle", "--facts", self.src, "--dataset", dataset,
                             "--out", self.ferry, "--mode", "snapshot", "--key", KEY])
            self.assertEqual(code, 0)
            paths.extend([os.path.join(self.ferry, name)
                          for name in sorted(os.listdir(self.ferry))
                          if name.startswith("bundle-%s" % dataset)])
        return paths

    def test_full_flow(self):
        bundles = self._bundle_all()
        self.assertEqual(len(bundles), 3)

        for path in bundles:
            self.assertEqual(
                cli.main(["import", "--facts", self.dst, "--bundle", path, "--key", KEY]), 0)

        store = facts_mod.FactsStore(self.dst)
        self.assertEqual(store.get("vulns",
                                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
                         ["max_cvss"], 10.0)

        # 内网资产摄入
        self.assertEqual(
            cli.main(["inventory", "--facts", self.dst, "--assets", ASSETS,
                      "--base-dir", ROOT]), 0)
        self.assertEqual(store.get("inventory",
                                   "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
                         ["blast_radius"], 4)

        # 引入前评估（单组件）
        md_path = os.path.join(self.work, "gate.md")
        code = cli.main(["gate", "--facts", self.dst,
                         "--purl", "pkg:maven/com.alibaba/fastjson@1.2.24",
                         "--tier", "core", "--exposure", "internet",
                         "--data-sensitivity", "high",
                         "--md", md_path, "--fail-on", "never"])
        self.assertEqual(code, 0)
        with open(md_path, "r", encoding="utf-8") as handle:
            markdown = handle.read()
        self.assertIn("开源引入评估", markdown)
        self.assertIn("分项评分", markdown)

        # CI 门禁：存在 Deny 组件时应失败
        json_path = os.path.join(self.work, "gate.json")
        self.assertEqual(
            cli.main(["gate", "--facts", self.dst, "--sbom", SBOM,
                      "--json", json_path, "--fail-on", "never"]), 0)
        with open(json_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        conclusions = [item["conclusion"] for item in payload["results"]]
        self.assertIn("Deny", conclusions)
        self.assertEqual(
            cli.main(["gate", "--facts", self.dst, "--sbom", SBOM, "--fail-on", "deny"]), 1)

        # 群组评估
        group_md = os.path.join(self.work, "group.md")
        self.assertEqual(
            cli.main(["assess", "--facts", self.dst, "--assets", ASSETS,
                      "--base-dir", ROOT, "--group", "支付群组",
                      "--md", group_md]), 0)
        with open(group_md, "r", encoding="utf-8") as handle:
            group_text = handle.read()
        self.assertIn("支付群组", group_text)
        self.assertIn("共性风险", group_text)

        # 回执已生成
        self.assertTrue(os.listdir(os.path.join(self.dst, "outbox")))


class MigrationTest(unittest.TestCase):
    """验证现有 vulns.json 可以迁移进事实层。"""

    def test_build_facts_from_vulns_json(self):
        script = os.path.join(ROOT, "scabase-fetcher", "scripts", "build_facts.py")
        vulns = os.path.join(ROOT, "scabase-fetcher", "data", "vulns.json")
        if not os.path.exists(vulns):
            self.skipTest("缺少 vulns.json")
        facts_dir = tmp_facts()
        try:
            proc = subprocess.run(
                [sys.executable, script, "--facts", facts_dir, "--vulns", vulns],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            store = facts_mod.FactsStore(facts_dir)
            total = sum(1 for _ in store.iter_dataset("vulns"))
            self.assertGreater(total, 0)
            for _key, payload in store.iter_dataset("vulns"):
                self.assertIn("cves", payload)
                self.assertIn("max_cvss", payload)
                break
        finally:
            cleanup(facts_dir)


if __name__ == "__main__":
    unittest.main()
