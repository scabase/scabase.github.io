import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import build_store, cleanup  # noqa: E402
from oss_intake import baseline as baseline_mod  # noqa: E402
from oss_intake import facts as facts_mod  # noqa: E402
from oss_intake import patrol as patrol_mod  # noqa: E402
from oss_intake import policy as policy_mod  # noqa: E402

ASSETS = {
    "groups": [{
        "name": "支付群组",
        "apps": [
            {"name": "支付核心", "tier": "core", "exposure": "internet",
             "data_sensitivity": "high",
             "gavs": ["com.alibaba:fastjson:1.2.24",
                      "org.apache.logging.log4j:log4j-core:2.14.1"]},
            {"name": "渠道前置", "tier": "important", "exposure": "internal",
             "data_sensitivity": "mid",
             "gavs": ["com.alibaba:fastjson:1.2.24"]},
        ],
    }]
}


class PatrolTest(unittest.TestCase):
    def setUp(self):
        self.root = build_store()
        self.store = facts_mod.FactsStore(self.root)
        self.policy = policy_mod.load_policy()
        self.catalog = baseline_mod.load_catalog()

    def tearDown(self):
        cleanup(self.root)

    def _run(self, previous=None):
        return patrol_mod.patrol(self.store, ASSETS, policy=self.policy,
                                 catalog=self.catalog, previous=previous,
                                 rebuild_inventory=True)

    def test_patrol_aggregates_by_app(self):
        payload = self._run()
        self.assertEqual(len(payload["apps"]), 2)
        core = [a for a in payload["apps"] if a["app"] == "支付核心"][0]
        self.assertEqual(core["component_count"], 2)
        self.assertGreaterEqual(core["affected_count"], 2)
        self.assertGreaterEqual(core["kev_count"], 1)
        self.assertGreater(core["risk_score"], 0)

    def test_baseline_items_attached_to_findings(self):
        payload = self._run()
        core = [a for a in payload["apps"] if a["app"] == "支付核心"][0]
        ids = set(core["baseline_items"])
        self.assertIn("log4j-jndilookup", ids)
        self.assertIn("fastjson-autotype", ids)

    def test_tickets_prioritised_by_severity(self):
        payload = self._run()
        tickets = payload["tickets"]
        self.assertTrue(tickets)
        self.assertEqual(tickets[0]["severity"], "critical")
        for ticket in tickets:
            self.assertTrue(ticket["ticket_id"].startswith("PATROL-"))
            self.assertRegex(ticket["due"], r"^\d{4}-\d{2}-\d{2}$")
        log4j = [t for t in tickets if "log4j" in (t["gav"] or "")][0]
        self.assertIn("CVE-2021-44228", log4j["cves"])
        self.assertEqual(log4j["suggested_version"], "2.15.0")

    def test_common_risk_identified(self):
        payload = self._run()
        fastjson = [r for r in payload["common_risks"] if "fastjson" in r["purl"]]
        self.assertEqual(len(fastjson), 1)
        self.assertEqual(fastjson[0]["apps"], ["支付核心", "渠道前置"])

    def test_delta_against_previous_run(self):
        first = self._run()
        second = self._run(previous=first)
        self.assertEqual(second["delta"]["new"], [])
        self.assertGreater(len(second["delta"]["open"]), 0)
        self.assertEqual(second["delta"]["previous_at"], first["generated_at"])

    def test_state_roundtrip(self):
        first = self._run()
        path = os.path.join(tempfile.mkdtemp(prefix="patrol-"), "state.json")
        patrol_mod.save_state(path, first)
        loaded = patrol_mod.load_state(path)
        self.assertEqual(loaded["generated_at"], first["generated_at"])
        cleanup(os.path.dirname(path))

    def test_group_summary(self):
        payload = self._run()
        group = payload["groups"][0]
        self.assertEqual(group["app_count"], 2)
        self.assertGreaterEqual(group["kev_count"], 1)
        self.assertGreater(group["baseline_item_count"], 0)


if __name__ == "__main__":
    unittest.main()
