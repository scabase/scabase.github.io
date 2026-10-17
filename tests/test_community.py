import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oss_intake import community  # noqa: E402

HEALTHY = {
    "last_commit_days": 5, "releases_12m": 12, "maintainers": 20,
    "contributors": 80, "issue_response_hours": 24, "pr_merge_days": 5,
    "has_security_policy": True, "has_ci": True, "org_backing": "foundation",
}
REGISTRY = {"dependent_projects": 20000, "monthly_downloads": 50000000, "stars": 30000}


class CommunityTest(unittest.TestCase):
    def test_healthy_project_scores_a(self):
        result = community.evaluate(HEALTHY, REGISTRY)
        self.assertEqual(result["grade"], "A")
        self.assertGreaterEqual(result["score"], 90)
        self.assertEqual(result["missing"], [])

    def test_archived_project_is_d(self):
        result = community.evaluate({"archived": True, "last_commit_days": 5})
        self.assertEqual(result["grade"], "D")
        self.assertLessEqual(result["score"], 10)
        self.assertIn("归档", result["factors"][0]["factor"])

    def test_unknown_signals_are_conservative(self):
        result = community.evaluate({}, {})
        self.assertIn(result["grade"], ("C", "D"))
        self.assertGreater(len(result["missing"]), 5)
        self.assertTrue(any("未知" in f["factor"] for f in result["factors"]))

    def test_single_maintainer_penalised(self):
        base = dict(HEALTHY)
        base.update({"maintainers": 1, "contributors": 1})
        low = community.evaluate(base, {})
        self.assertLess(low["score"], community.evaluate(HEALTHY, {})["score"])
        self.assertTrue(any("bus factor" in f["factor"] for f in low["factors"]))

    def test_stale_project_ranked_lower(self):
        stale = dict(HEALTHY)
        stale.update({"last_commit_days": 800, "releases_12m": 0})
        self.assertLess(community.evaluate(stale, {})["score"],
                        community.evaluate(HEALTHY, {})["score"])

    def test_advice_present_for_every_grade(self):
        for grade in ("A", "B", "C", "D"):
            self.assertTrue(community.SUPPORT_ADVICE.get(grade))


if __name__ == "__main__":
    unittest.main()
