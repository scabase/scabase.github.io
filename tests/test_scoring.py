import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, build_store, cleanup, sample_vulns  # noqa: E402
from oss_intake import policy as policy_mod  # noqa: E402
from oss_intake import scoring  # noqa: E402

LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
FASTJSON = "pkg:maven/com.alibaba/fastjson@1.2.24"
SPRING = "pkg:maven/org.springframework/spring-core@5.3.20"


class ScoringTest(unittest.TestCase):
    def setUp(self):
        self.root = build_store()
        self.policy = policy_mod.load_policy()
        self.confidences = {"vulns": 1.0, "health": 1.0, "license": 1.0, "inventory": 1.0}

    def tearDown(self):
        cleanup(self.root)

    def _evaluate(self, purl_value, **kwargs):
        from oss_intake import facts as facts_mod
        store = facts_mod.FactsStore(self.root)
        return scoring.evaluate(store.component(purl_value), policy=self.policy,
                                confidences=self.confidences, **kwargs)

    def test_log4shell_is_conditional_with_suggested_version(self):
        result = self._evaluate(LOG4J)
        self.assertEqual(result["dimensions"]["vulnerability"]["score"], 35)
        self.assertIn(result["conclusion"], ("Allow-with-condition", "Review", "Deny"))
        self.assertEqual(result["suggested_version"], "2.15.0")

    def test_archived_component_takes_full_health_score(self):
        result = self._evaluate(FASTJSON)
        self.assertEqual(result["dimensions"]["health"]["score"], 25)
        self.assertGreaterEqual(result["score"], 55)
        self.assertIn(result["conclusion"], ("Review", "Deny"))

    def test_clean_component_is_low_risk(self):
        result = self._evaluate(SPRING)
        self.assertLess(result["score"], 25)
        self.assertEqual(result["conclusion"], "Allow")

    def test_kev_without_fix_is_hard_blocked(self):
        from oss_intake import facts as facts_mod
        store = facts_mod.FactsStore(self.root)
        store.upsert("vulns", "pkg:maven/x/y@1", {
            "cves": [{"id": "CVE-2099-0001", "cvss": 7.5, "kev": True,
                      "epss": 0.9, "fixed": [], "published": None}],
            "max_cvss": 7.5, "kev_count": 1, "unfixed_count": 1,
        })
        result = scoring.evaluate(store.component("pkg:maven/x/y@1"),
                                  policy=self.policy, confidences=self.confidences)
        self.assertEqual(result["conclusion"], "Deny")
        self.assertTrue(any("KEV" in item for item in result["hard_blocks"]))

    def test_license_conflict_is_hard_blocked(self):
        from oss_intake import facts as facts_mod
        store = facts_mod.FactsStore(self.root)
        store.upsert("license", "pkg:maven/gpl/lib@1", {"spdx": "GPL-3.0",
                                                        "category": "strong-copyleft"})
        result = scoring.evaluate(store.component("pkg:maven/gpl/lib@1"),
                                  policy=self.policy, confidences=self.confidences,
                                  profile="closed_source")
        self.assertEqual(result["conclusion"], "Deny")
        self.assertTrue(any("许可证" in item for item in result["hard_blocks"]))

    def test_unknown_data_is_conservative(self):
        result = self._evaluate("pkg:maven/unknown/pkg@9.9.9")
        self.assertTrue(result["missing_data"])
        self.assertTrue(result["needs_review"])
        self.assertEqual(result["dimensions"]["vulnerability"]["score"], 24)
        self.assertEqual(result["dimensions"]["health"]["score"], 18)
        self.assertEqual(result["dimensions"]["license"]["score"], 12)
        self.assertGreaterEqual(result["score"], 55)

    def test_stale_data_pushes_score_to_max_and_forces_review(self):
        stale_root = build_store(
            generated_at=time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 40 * 86400)))
        try:
            from oss_intake import facts as facts_mod
            store = facts_mod.FactsStore(stale_root)
            confidences = {name: store.confidence(name, 14, 3)
                           for name in ("vulns", "health", "license", "inventory")}
            self.assertEqual(confidences["vulns"], 0.0)
            result = scoring.evaluate(store.component(SPRING), policy=self.policy,
                                      confidences=confidences)
            self.assertEqual(result["score"], 100)
            self.assertEqual(result["conclusion"], "Deny")
            self.assertTrue(result["needs_review"])
        finally:
            cleanup(stale_root)

    def test_staleness_as_deny_adds_hard_block(self):
        policy = policy_mod.load_policy()
        policy["staleness_as_deny"] = True
        stale = {"vulns": 0.0, "health": 0.0, "license": 0.0, "inventory": 0.0}
        result = scoring.evaluate({"purl": "pkg:maven/a/b@1"}, policy=policy,
                                  confidences=stale)
        self.assertTrue(any("陈旧" in item for item in result["hard_blocks"]))

    def test_dimension_cap(self):
        raw, _notes, _missing = scoring.score_vulnerability(
            {"cves": [{"id": "CVE-1", "cvss": 10, "kev": True, "epss": 1.0,
                       "fixed": [], "published": "2019-01-01T00:00:00"}],
             "max_cvss": 10, "kev_count": 1, "unfixed_count": 1}, 35)
        self.assertLessEqual(raw, 35)

    def test_explanation_is_complete(self):
        result = self._evaluate(LOG4J)
        for name in scoring.DIMENSIONS:
            self.assertIn(name, result["dimensions"])
            self.assertTrue(result["dimensions"][name]["notes"])


if __name__ == "__main__":
    unittest.main()
