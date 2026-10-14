import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT  # noqa: E402
from oss_intake import baseline as baseline_mod  # noqa: E402

CATALOG_PATH = os.path.join(ROOT, "examples", "baseline-catalog.json")


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.catalog = baseline_mod.load_catalog()

    def _item(self, rule_id):
        item = baseline_mod.by_id(self.catalog, rule_id)
        self.assertIsNotNone(item, "基线项缺失：%s" % rule_id)
        return item

    def test_catalog_is_non_trivial(self):
        self.assertGreaterEqual(len(self.catalog), 30)
        for item in self.catalog:
            self.assertTrue(item.get("id"))
            self.assertIn(item.get("severity"), baseline_mod.SEVERITIES)
            self.assertIn(item.get("deploy"), baseline_mod.DEPLOY_MODES)

    def test_config_set_operator(self):
        item = self._item("redis-requirepass")
        ok, evidence = baseline_mod.run_check(
            item["check"], {"configs": {"/etc/redis/redis.conf": {"requirepass": "Str0ng!"}}})
        self.assertEqual(ok, "PASS")
        self.assertIn("requirepass", evidence)
        bad, _ = baseline_mod.run_check(
            item["check"], {"configs": {"/etc/redis/redis.conf": {"requirepass": ""}}})
        self.assertEqual(bad, "FAIL")

    def test_missing_key_uses_empty_value_for_positive_assertions(self):
        item = self._item("es-security")
        status, _ = baseline_mod.run_check(
            item["check"], {"configs": {"/etc/elasticsearch/elasticsearch.yml": {}}})
        self.assertEqual(status, "FAIL")

    def test_not_contains_operator(self):
        item = self._item("redis-bind")
        self.assertEqual(baseline_mod.run_check(
            item["check"],
            {"configs": {"/etc/redis/redis.conf": {"bind": "10.0.0.1"}}})[0], "PASS")
        self.assertEqual(baseline_mod.run_check(
            item["check"],
            {"configs": {"/etc/redis/redis.conf": {"bind": "0.0.0.0"}}})[0], "FAIL")

    def test_version_operator(self):
        item = self._item("fastjson-autotype")
        self.assertEqual(baseline_mod.run_check(item["check"], {"version": "1.2.83"})[0], "PASS")
        self.assertEqual(baseline_mod.run_check(item["check"], {"version": "1.2.24"})[0], "FAIL")
        self.assertEqual(baseline_mod.run_check(item["check"], {"version": "1.2.83.1"})[0], "PASS")

    def test_http_operator(self):
        item = self._item("tomcat-manager-auth")
        self.assertEqual(baseline_mod.run_check(
            item["check"],
            {"http": {"http://127.0.0.1:8080/manager/html": {"status": 401}}})[0], "PASS")
        self.assertEqual(baseline_mod.run_check(
            item["check"],
            {"http": {"http://127.0.0.1:8080/manager/html": {"status": 200}}})[0], "FAIL")

    def test_unknown_when_snapshot_incomplete(self):
        item = self._item("redis-requirepass")
        status, evidence = baseline_mod.run_check(item["check"], {})
        self.assertEqual(status, "UNKNOWN")
        self.assertIn("缺少", evidence)

    def test_match_by_component_name(self):
        hits = baseline_mod.match(self.catalog, "redis")
        self.assertTrue(hits)
        self.assertTrue(all("redis" in item["component"] for item in hits))
        self.assertEqual(baseline_mod.match(self.catalog, "kubernetes"), [])

    def test_external_catalog_extends_builtin(self):
        extended = baseline_mod.load_catalog(CATALOG_PATH)
        self.assertEqual(len(extended), len(self.catalog) + 2)
        self.assertIsNotNone(baseline_mod.by_id(extended, "consul-acl"))

    def test_run_all_returns_structured_results(self):
        snapshot = {"configs": {"/etc/redis/redis.conf": {"requirepass": "x", "bind": "0.0.0.0"}}}
        results = baseline_mod.run_all(self.catalog, snapshot, name="redis")
        statuses = {item["id"]: item["status"] for item in results}
        self.assertEqual(statuses["redis-requirepass"], "PASS")
        self.assertEqual(statuses["redis-bind"], "FAIL")
        self.assertTrue(all("severity" in item for item in results))


if __name__ == "__main__":
    unittest.main()
