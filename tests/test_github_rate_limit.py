"""GitHub 配额等待与「跳过 NVD」补采的行为回归。

背景：健康度信号缺失（65 个软件只有 23 个有 stars、0 个 forks/watchers）
的根因之一是 GitHub 配额按小时窗口计——旧逻辑退避几秒就降级，把 403
当成「该源不可用」。这里固化两个修复：

  1) fetch_oss_health._rate_limit_sleep 按 X-RateLimit-Reset 等待（预算内）
  2) fetch_software 支持 --no-vulns，只补 GitHub 信号且不动漏洞产物
"""
import os
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
SCRIPTS = os.path.join(ROOT, "scabase-fetcher", "scripts")
for path in (ROOT, SCRIPTS):
    if path not in sys.path:
        sys.path.insert(0, path)

import fetch_oss_health as foh  # noqa: E402


class FakeResponse(object):
    def __init__(self, headers, status=403):
        self.headers = headers
        self.status_code = status


def _budget(seconds=1000):
    return [seconds]


class RateLimitWaitTest(unittest.TestCase):
    def setUp(self):
        foh.reset_wait_budget(10 ** 6)  # 测试期间不触发预算限制

    def test_waits_until_reset_when_exhausted(self):
        reset = int(time.time()) + 42
        resp = FakeResponse({"X-RateLimit-Remaining": "0",
                             "X-RateLimit-Reset": str(reset)})
        budget = _budget()
        with mock.patch.object(foh.time, "sleep") as slept:
            got = foh._rate_limit_sleep(resp, budget)
        self.assertIsNotNone(got)
        self.assertGreater(got, 40)          # 含 2 秒余量
        slept.assert_called_once_with(got)
        self.assertLess(budget[0], 10 ** 6)  # 预算被扣减

    def test_no_wait_when_quota_remaining(self):
        resp = FakeResponse({"X-RateLimit-Remaining": "37",
                             "X-RateLimit-Reset": str(int(time.time()) + 100)})
        with mock.patch.object(foh.time, "sleep") as slept:
            self.assertIsNone(foh._rate_limit_sleep(resp, _budget()))
        slept.assert_not_called()

    def test_no_wait_when_budget_insufficient(self):
        reset = int(time.time()) + 900
        resp = FakeResponse({"X-RateLimit-Remaining": "0",
                             "X-RateLimit-Reset": str(reset)})
        with mock.patch.object(foh.time, "sleep") as slept:
            self.assertIsNone(foh._rate_limit_sleep(resp, [60]))
        slept.assert_not_called()

    def test_budget_env_switch(self):
        # 预算可关闭（0）：CI 之外想快速失败时用 SCABASE_GH_WAIT_BUDGET=0
        self.assertTrue(hasattr(foh, "WAIT_BUDGET"))

    def test_get_retries_after_quota_reset(self):
        """_get 在限流时应先睡到配额重置，而不是直接返回 None（降级）。"""
        reset = int(time.time()) + 30
        limited = FakeResponse({"X-RateLimit-Remaining": "0",
                                "X-RateLimit-Reset": str(reset)}, status=403)

        class _Ok(object):
            status_code = 200
            headers = {"X-RateLimit-Remaining": "56"}

            def json(self):
                return {"ok": True}

        responses = [limited, _Ok()]
        with mock.patch.object(foh, "requests") as req, \
                mock.patch.object(foh.time, "sleep"):
            req.get.side_effect = lambda *a, **kw: responses.pop(0)
            got = foh._get("https://api.github.com/repos/x/y", None)
        self.assertEqual(got, {"ok": True})
        self.assertEqual(req.get.call_count, 2)


class RepoStatusTest(unittest.TestCase):
    """登记的仓库失效时必须能和低质量采集区分开（GitLab 迁出 GitHub 的场景）。"""

    def _call(self, resp_or_exc):
        with mock.patch.object(foh, "requests") as req:
            if isinstance(resp_or_exc, Exception):
                req.get.side_effect = resp_or_exc
            else:
                req.get.return_value = resp_or_exc
            return foh.repo_status("gitlab-org/gitlab", None)

    def test_ok(self):
        self.assertEqual(self._call(FakeResponse({}, 200)), "ok")

    def test_not_found(self):
        self.assertEqual(self._call(FakeResponse({}, 404)), "not_found")

    def test_network_error_is_unknown(self):
        self.assertEqual(self._call(Exception("timeout")), "unknown")

    def test_no_slug(self):
        self.assertEqual(foh.repo_status(None, None), "unknown")

    def test_row_carries_repo_status(self):
        import fetch_software as fs

        row = fs.build_support_row(
            "GitLab", {"name": "GitLab", "repo": "gitlab-org/gitlab"},
            {}, None, repo_status="not_found")
        self.assertEqual(row["repo_status"], "not_found")
        self.assertIsNone(row["stars"])
        self.assertIsNone(row["forks"])


class NoVulnsRefreshTest(unittest.TestCase):
    def test_skip_vulns_keeps_existing_cves(self):
        """--no-vulns 只刷 GitHub 信号：不调 NVD，漏洞条目原样保留。"""
        import fetch_software as fs

        prior_vulns = {"software": [{
            "name": "nginx", "category": "Web 服务器与代理",
            "aliases": ["nginx"], "cpe": ["f5:nginx"],
            "repo": "nginx/nginx", "cve_count": 1,
            "cves": [{"id": "CVE-2022-41741"}]
        }]}

        def boom(*args, **kwargs):  # 若被调用即证明没跳过 NVD
            raise AssertionError("不应调用 NVD")

        with mock.patch.object(fs, "fetch_nvd_cves", boom), \
                mock.patch.object(fs, "SOFTWARE", [
                    {"name": "nginx", "repo": "nginx/nginx",
                     "category": "Web 服务器与代理", "cpe": ["f5:nginx"]}]), \
                mock.patch.object(fs, "fetch_software_health",
                                  lambda repo, token: ({"stars": 1, "forks": 2,
                                                        "watchers": 3}, "1.0.0")):
            vulns, support = fs.build_document(
                True, None, only=["nginx"], fixtures=None, health=True,
                existing_vulns=prior_vulns, existing_support={},
                include_vulns=False)

        self.assertEqual(vulns["software"][0]["cve_count"], 1)
        self.assertEqual(vulns["software"][0]["cves"][0]["id"], "CVE-2022-41741")
        row = support["components"][0]
        self.assertEqual((row["stars"], row["forks"], row["watchers"]), (1, 2, 3))


if __name__ == "__main__":
    unittest.main()
