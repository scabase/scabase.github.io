import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oss_intake import policy as policy_mod  # noqa: E402


class LicenseCategoryTest(unittest.TestCase):
    def test_permissive(self):
        self.assertEqual(policy_mod.category_of("MIT"), "permissive")
        self.assertEqual(policy_mod.category_of("Apache-2.0"), "permissive")

    def test_strong_copyleft(self):
        self.assertEqual(policy_mod.category_of("GPL-3.0"), "strong-copyleft")
        self.assertEqual(policy_mod.category_of("AGPL-3.0"), "strong-copyleft")

    def test_multi_license_takes_strongest(self):
        self.assertEqual(policy_mod.category_of("MIT OR GPL-3.0"), "strong-copyleft")
        self.assertEqual(policy_mod.category_of("LGPL-2.1 AND MPL-2.0"), "weak-copyleft")

    def test_plus_suffix(self):
        self.assertEqual(policy_mod.category_of("GPL-2.0+"), "strong-copyleft")

    def test_unknown(self):
        self.assertEqual(policy_mod.category_of(None), "unknown")
        self.assertEqual(policy_mod.category_of("Some-Custom-License"), "unknown")


class LicenseVerdictTest(unittest.TestCase):
    def setUp(self):
        self.policy = policy_mod.load_policy()

    def test_closed_source_blocks_strong_copyleft(self):
        category, deny, warn = policy_mod.license_verdict(
            {"spdx": "GPL-3.0"}, "closed_source", self.policy)
        self.assertEqual(category, "strong-copyleft")
        self.assertTrue(deny)

    def test_internal_service_warns_only(self):
        category, deny, warn = policy_mod.license_verdict(
            {"spdx": "GPL-3.0"}, "internal_service", self.policy)
        self.assertFalse(deny)
        self.assertTrue(warn)

    def test_permissive_clean(self):
        category, deny, warn = policy_mod.license_verdict(
            {"spdx": "MIT"}, "closed_source", self.policy)
        self.assertFalse(deny)
        self.assertFalse(warn)


class PolicyMergeTest(unittest.TestCase):
    def test_override_merges_with_defaults(self):
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "examples", "policy.json")
        merged = policy_mod.load_policy(path)
        self.assertEqual(merged["freshness_sla_days"], 14)
        self.assertIn("business-source",
                      merged["license_profiles"]["closed_source"]["deny"])
        # 未覆盖项保留默认值
        self.assertEqual(merged["weights"]["vulnerability"], 35)


if __name__ == "__main__":
    unittest.main()
