"""社区支持力度与活跃度采集 / 汇总的测试。

覆盖 fetch_oss_health 的治理信号解析与 community_report 的汇总渲染。
全部离线，不发起任何网络请求。
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

from oss_intake import community as community_mod  # noqa: E402

import community_report  # noqa: E402
import fetch_oss_health  # noqa: E402


class GithubSignalTest(unittest.TestCase):
    """fetch_oss_health 的信号派生逻辑（不打网络，直接调用纯函数）。"""

    def test_org_backing_classification(self):
        cases = [
            ({"owner": {"login": "apache", "type": "Organization"}}, "foundation"),
            ({"owner": {"login": "spring-projects", "type": "Organization"}}, "vendor"),
            ({"owner": {"login": "some-random-org", "type": "Organization"}}, "organization"),
            ({"owner": {"login": "individual-dev", "type": "User"}}, "personal"),
            ({}, None),
        ]
        for repo, expected in cases:
            self.assertEqual(fetch_oss_health._org_backing(repo), expected, repo)

    def test_days_since_handles_bad_input(self):
        self.assertIsNone(fetch_oss_health.days_since(None))
        self.assertIsNone(fetch_oss_health.days_since("not-a-date"))
        self.assertIsInstance(fetch_oss_health.days_since("2020-01-01T00:00:00"), int)

    def test_github_slug_only_for_go_modules(self):
        info = {"namespace": "github.com/gin-gonic", "name": "gin"}
        self.assertEqual(fetch_oss_health.github_slug(info, "go"), "gin-gonic/gin")
        self.assertIsNone(fetch_oss_health.github_slug(
            {"namespace": "babel", "name": "core"}, "npm"))

    def test_npm_collector_disabled_without_requests(self):
        original = fetch_oss_health.requests
        try:
            fetch_oss_health.requests = None
            self.assertIsNone(fetch_oss_health.collect_from_npm("axios"))
        finally:
            fetch_oss_health.requests = original


class CommunityReportTest(unittest.TestCase):
    HEALTH = {
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {
            "archived": False, "last_commit_days": 20, "releases_12m": 6,
            "maintainers": 8, "contributors": 40, "issue_response_hours": 72,
            "pr_merge_days": 5, "has_security_policy": True, "has_ci": True,
            "org_backing": "foundation", "dependent_projects": 5000,
            "monthly_downloads": 2000000, "stars": 15000,
        },
        "pkg:maven/com.alibaba/fastjson@1.2.24": {
            "archived": True, "last_commit_days": 900, "releases_12m": 0,
            "maintainers": 1, "issue_response_hours": 1200,
        },
        "pkg:npm/axios@0.21.1": {},
    }

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="community-report-")
        self.health_path = os.path.join(self.work, "health.json")
        with open(self.health_path, "w", encoding="utf-8") as handle:
            json.dump(self.HEALTH, handle, ensure_ascii=False)

    def tearDown(self):
        cleanup(self.work)

    def test_report_counts_grades(self):
        report = community_report.build_report(self.HEALTH)
        self.assertEqual(report["component_count"], 3)
        grades = {row["purl"]: row["grade"] for row in report["components"]}
        self.assertEqual(grades["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"], "A")
        self.assertEqual(grades["pkg:maven/com.alibaba/fastjson@1.2.24"], "D")
        self.assertIn(report["grade_counts"].get("D"), (1, 2))

    def test_missing_signals_counted(self):
        report = community_report.build_report(self.HEALTH)
        # 空 payload 的组件会贡献大量缺失信号
        self.assertIn("last_commit_days", report["missing_signal_counts"])

    def test_rows_sorted_by_grade_then_score(self):
        report = community_report.build_report(self.HEALTH)
        order = [row["grade"] for row in report["components"]]
        self.assertEqual(order, sorted(order, key=lambda g: {"A": 0, "B": 1, "C": 2, "D": 3}[g]))

    def test_markdown_renders(self):
        text = community_report.render_markdown(
            community_report.build_report(self.HEALTH))
        self.assertIn("# 社区支持力度与活跃度汇总", text)
        self.assertIn("| 组件 | 生态 | 评分 | 等级 |", text)
        self.assertIn("缺失信号统计", text)

    def test_unknown_payload_is_conservative(self):
        result = community_mod.evaluate({}, {})
        self.assertIn(result["grade"], ("C", "D"))
        self.assertGreater(len(result["missing"]), 5)


if __name__ == "__main__":
    unittest.main()
