import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, build_store, cleanup, load_example  # noqa: E402
from oss_intake import assessment  # noqa: E402
from oss_intake import assets as assets_mod  # noqa: E402
from oss_intake import facts as facts_mod  # noqa: E402
from oss_intake import policy as policy_mod  # noqa: E402


class AssessmentTest(unittest.TestCase):
    def setUp(self):
        self.root = build_store()
        self.store = facts_mod.FactsStore(self.root)
        self.policy = policy_mod.load_policy()
        self.assets = load_example("assets.json")
        self.confidences = {name: 1.0 for name in
                            ("vulns", "health", "license", "inventory")}
        assets_mod.build_inventory(self.store, self.assets, base_dir=ROOT)

    def tearDown(self):
        cleanup(self.root)

    def test_inventory_records_blast_radius(self):
        usage = assets_mod.usage_of(
            self.store, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        self.assertEqual(usage["blast_radius"], 4)
        self.assertEqual(usage["tier"], "core")
        self.assertEqual(usage["exposure"], "internet")
        self.assertEqual(usage["data_sensitivity"], "high")
        self.assertIn("支付群组", usage["groups"])

    def test_group_score_reflects_worst_component(self):
        group = self.assets["groups"][0]
        report = assessment.assess_group(self.store, group, self.policy, self.confidences)
        self.assertGreater(report["group_score"], 0)
        self.assertGreaterEqual(report["group_score"], report["weighted_average"])
        self.assertEqual(report["worst_component_score"],
                         max(c["score"] for c in report["components"]))

    def test_group_score_is_not_masked_by_average(self):
        group = self.assets["groups"][0]
        report = assessment.assess_group(self.store, group, self.policy, self.confidences)
        average = sum(c["score"] for c in report["components"]) / len(report["components"])
        self.assertGreater(report["group_score"], average)

    def test_common_risk_detection(self):
        group = self.assets["groups"][0]
        report = assessment.assess_group(self.store, group, self.policy, self.confidences)
        self.assertTrue(report["common_risks"])
        for item in report["common_risks"]:
            self.assertGreaterEqual(item["apps"], 3)
            self.assertGreaterEqual(item["score"], 55)

    def test_different_profiles_change_license_outcome(self):
        from oss_intake import scoring
        store = self.store
        store.upsert("license", "pkg:maven/gpl/lib@1",
                     {"spdx": "GPL-3.0", "category": "strong-copyleft"})
        closed = scoring.evaluate(store.component("pkg:maven/gpl/lib@1"),
                                  policy=self.policy, confidences=self.confidences,
                                  profile="closed_source")
        internal = scoring.evaluate(store.component("pkg:maven/gpl/lib@1"),
                                    policy=self.policy, confidences=self.confidences,
                                    profile="internal_service")
        self.assertEqual(closed["conclusion"], "Deny")
        self.assertNotEqual(internal["conclusion"], "Deny")

    def test_assess_all_groups(self):
        reports = assessment.assess_all(self.store, self.assets, self.policy,
                                        self.confidences)
        self.assertEqual(len(reports), 2)
        self.assertEqual([r["group"] for r in reports], ["支付群组", "风控群组"])


if __name__ == "__main__":
    unittest.main()
