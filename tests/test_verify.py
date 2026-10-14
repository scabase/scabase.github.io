import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT  # noqa: E402
from oss_intake import baseline as baseline_mod  # noqa: E402
from oss_intake import verify as verify_mod  # noqa: E402

CASES = os.path.join(ROOT, "examples", "accuracy-cases.json")


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.catalog = baseline_mod.load_catalog()
        self.cases = verify_mod.load_cases(CASES)

    def test_sample_set_loads(self):
        self.assertGreaterEqual(len(self.cases), 40)
        for case in self.cases:
            self.assertIn(case["expected"], ("PASS", "FAIL"))
            self.assertTrue(baseline_mod.by_id(self.catalog, case["rule_id"]))

    def test_accuracy_meets_threshold(self):
        metrics = verify_mod.evaluate(self.catalog, self.cases, threshold=0.9)
        self.assertEqual(metrics["unknown_count"], 0)
        self.assertGreaterEqual(metrics["accuracy"], 0.9)
        self.assertTrue(metrics["passed"])
        verify_mod.assert_accuracy(metrics, 0.9)

    def test_every_rule_has_samples(self):
        metrics = verify_mod.evaluate(self.catalog, self.cases)
        self.assertEqual(metrics["uncovered_rules"], [])

    def test_false_negative_is_recorded(self):
        tampered = [dict(case) for case in self.cases]
        tampered[0]["expected"] = "FAIL" if tampered[0]["expected"] == "PASS" else "PASS"
        metrics = verify_mod.evaluate(self.catalog, tampered)
        self.assertGreaterEqual(metrics["false_negative_count"] + metrics["false_positive_count"], 1)
        self.assertLess(metrics["accuracy"], 1.0)

    def test_unknown_counts_as_miss(self):
        cases = [{"case_id": "no-snapshot", "rule_id": "redis-requirepass",
                  "expected": "FAIL", "snapshot": {}}]
        metrics = verify_mod.evaluate(self.catalog, cases)
        self.assertEqual(metrics["accuracy"], 0.0)
        self.assertEqual(metrics["unknown_count"], 1)

    def test_assert_accuracy_raises_below_threshold(self):
        metrics = verify_mod.evaluate(self.catalog, self.cases, threshold=0.99)
        metrics["accuracy"] = 0.5
        with self.assertRaises(verify_mod.AccuracyError):
            verify_mod.assert_accuracy(metrics, 0.9)

    def test_markdown_report_renders(self):
        metrics = verify_mod.evaluate(self.catalog, self.cases)
        text = verify_mod.render_markdown(metrics)
        self.assertIn("准确率", text)
        self.assertIn("| 规则 |", text)


if __name__ == "__main__":
    unittest.main()
