import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT  # noqa: E402
from oss_intake.integrations import cicd as cicd_mod  # noqa: E402
from oss_intake.integrations import depinfo as depinfo_mod  # noqa: E402

DEPINFO_EXPORT = os.path.join(ROOT, "examples", "depinfo-export.json")

RESULTS = [
    {"purl": "pkg:maven/com.alibaba/fastjson@1.2.24", "conclusion": "Deny", "score": 82.5,
     "suggested_version": "1.2.83", "review_due": "2027-01-01",
     "cves": [{"id": "CVE-2022-25845"}], "hard_blocks": ["CVSS 9.8 且无修复版本"],
     "apps": ["支付核心"]},
    {"purl": "pkg:npm/axios@0.21.1", "conclusion": "Allow", "score": 12.0,
     "cves": [], "hard_blocks": [], "apps": ["渠道前置"]},
]


class DepinfoTest(unittest.TestCase):
    def test_export_converted_to_assets(self):
        assets = depinfo_mod.sync_from_export(DEPINFO_EXPORT)
        groups = assets["groups"]
        self.assertEqual(len(groups), 2)
        names = [g["name"] for g in groups]
        self.assertIn("支付群组", names)
        self.assertIn("数据群组", names)
        pay = [g for g in groups if g["name"] == "支付群组"][0]
        self.assertEqual(len(pay["apps"]), 2)
        pay_core = pay["apps"][0]
        self.assertIn("pkg:maven/com.alibaba/fastjson@1.2.24", pay_core["purls"])
        self.assertIn("pkg:npm/axios@0.21.1", pay_core["purls"])
        self.assertIn("com.alibaba:fastjson:1.2.24", pay_core["gavs"])
        self.assertEqual(pay_core["tier"], "core")

    def test_normalize_component_variants(self):
        self.assertEqual(depinfo_mod.normalize_component({"gav": "a:b:1.0"}),
                         "pkg:maven/a/b@1.0")
        self.assertEqual(depinfo_mod.normalize_component(
            {"eco": "maven", "group": "a", "artifact": "b", "version": "1.0"}),
            "pkg:maven/a/b@1.0")
        self.assertEqual(depinfo_mod.normalize_component({"purl": "pkg:pypi/x@1"}),
                         "pkg:pypi/x@1")
        self.assertIsNone(depinfo_mod.normalize_component({"name": "x"}))

    def test_result_payload_masked_by_default(self):
        payload = depinfo_mod.result_payload(RESULTS)
        self.assertTrue(payload["masked"])
        self.assertEqual(payload["schema"], "depinfo-result/v1")
        item = payload["items"][0]
        self.assertEqual(item["gav"], "com.alibaba:fastjson:1.2.24")
        self.assertNotIn("apps", item)
        self.assertEqual(item["cves"], ["CVE-2022-25845"])

    def test_result_payload_keeps_app_when_unmasked(self):
        payload = depinfo_mod.result_payload(RESULTS, mask=False)
        self.assertFalse(payload["masked"])
        self.assertEqual(payload["items"][0]["apps"], ["支付核心"])

    def test_client_disabled_without_endpoint(self):
        client = depinfo_mod.DepinfoClient(base_url="")
        self.assertFalse(client.enabled())
        with self.assertRaises(RuntimeError):
            client.push({})


class CicdTest(unittest.TestCase):
    def test_sarif_structure(self):
        sarif = cicd_mod.to_sarif(RESULTS)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["ruleId"], "SCABASE-DENY")
        self.assertEqual(run["results"][1]["level"], "none")
        self.assertTrue(run["tool"]["driver"]["rules"])

    def test_junit_reports_failures(self):
        text = cicd_mod.to_junit(RESULTS)
        self.assertIn('failures="1"', text)
        self.assertIn("<failure", text)
        self.assertIn("fastjson", text)

    def test_exit_code_semantics(self):
        self.assertEqual(cicd_mod.exit_code(RESULTS, "deny"), 1)
        self.assertEqual(cicd_mod.exit_code(RESULTS, "review"), 1)
        self.assertEqual(cicd_mod.exit_code(RESULTS, "never"), 0)
        self.assertEqual(cicd_mod.exit_code([RESULTS[1]], "deny"), 0)

    def test_comment_mentions_blocking(self):
        comment = cicd_mod.to_comment(RESULTS, fail_on="deny")
        self.assertIn("门禁未通过", comment)
        self.assertIn("| 组件 |", comment)

    def test_comment_silent_with_never(self):
        comment = cicd_mod.to_comment(RESULTS, fail_on="never")
        self.assertNotIn("门禁未通过", comment)


if __name__ == "__main__":
    unittest.main()
