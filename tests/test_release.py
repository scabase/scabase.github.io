import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from oss_intake import release as release_mod  # noqa: E402

VULNS = {
    "maven|com.alibaba:fastjson|1.2.24": {
        "osv_raw": {
            "vulns": [{
                "id": "GHSA-jm7w-5684-pvh8",
                "aliases": ["CVE-2025-70974"],
                "modified": "2026-10-05T18:45:05Z",
            }],
        },
        "enriched": [{"osv": {"vulns": [{"id": "CVE-2025-70974"}]}, "nvd": {"cvss": 9.8}}],
    },
    "npm|lodash|4.17.20": {"osv_raw": {}, "enriched": []},
}

HEALTH = {
    "pkg:npm/lodash@4.17.20": {"last_commit_days": 3, "releases_12m": 4},
    "pkg:pypi/requests@2.20.0": {"health_unknown": True},
}

COMMUNITY = {
    "generated_at": "2026-10-15T03:20:00Z",
    "component_count": 1,
    "grade_counts": {"A": 1, "D": 1},
    "components": [
        {"purl": "pkg:npm/lodash@4.17.20", "grade": "A"},
        {"purl": "pkg:pypi/requests@2.20.0", "grade": "D"},
    ],
}

KEY = "test-release-key"


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oss-intake-release-")
        self.src = os.path.join(self.tmp, "src")
        self.out = os.path.join(self.tmp, "staging")
        os.makedirs(os.path.join(self.src, "facts", "vulns"))
        os.makedirs(os.path.join(self.src, "facts", "license"))
        self._write(os.path.join(self.src, "vulns.json"), VULNS)
        self._write(os.path.join(self.src, "health.json"), HEALTH)
        self._write(os.path.join(self.src, "community-support.json"), COMMUNITY)
        self._write(os.path.join(self.src, "facts", "vulns", "maven.json"), {"pkg:maven/a/b@1": {}})
        self._write(os.path.join(self.src, "facts", "meta.json"), {"version": 1, "datasets": {}})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _write(path, payload):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        return path

    def _build(self, **kwargs):
        options = {
            "vulns": os.path.join(self.src, "vulns.json"),
            "health": os.path.join(self.src, "health.json"),
            "community": os.path.join(self.src, "community-support.json"),
            "facts": os.path.join(self.src, "facts"),
            "version": "20261015.231400.0",
            "now": 1761000000,
            "source": {"repo": "scabase/scabase.github.io"},
        }
        options.update(kwargs)
        return release_mod.build_release(self.out, **options)

    def test_build_manifest_and_files(self):
        built = self._build()
        manifest = built["manifest"]
        self.assertEqual(manifest["schema"], release_mod.RELEASE_SCHEMA)
        self.assertEqual(manifest["version"], "20261015.231400.0")
        self.assertEqual(sorted(manifest["datasets"]), ["community", "health", "vulns"])
        self.assertEqual(manifest["datasets"]["vulns"]["entries"], 2)
        self.assertEqual(manifest["datasets"]["vulns"]["cve_count"], 1)
        self.assertEqual(manifest["datasets"]["health"]["usable_entries"], 1)
        self.assertEqual(manifest["datasets"]["community"]["entries"], 2)
        self.assertIn("shards", manifest["facts"].get("vulns") or {})
        self.assertEqual(manifest["file_count"], len(manifest["files"]))
        self.assertEqual(manifest["total_size"],
                         sum(item["size"] for item in manifest["files"]))
        self.assertIn("_meta", manifest["facts"])
        for name in ("vulns.json", "health.json", "community-support.json"):
            self.assertTrue(os.path.exists(os.path.join(self.out, "data", name)))
        self.assertTrue(os.path.exists(os.path.join(self.out, "data", "facts", "meta.json")))

    def test_staging_layout_matches_manifest(self):
        self._build()
        result = release_mod.verify(self.out)
        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["checked"], 5)

    def test_content_digest_stable_and_sensitive(self):
        first = self._build()["content_digest"]
        second = self._build(version="20261231.000000.0")["content_digest"]
        self.assertEqual(first, second)
        # 指纹只看内容：版本号、时间戳与来源元信息都不参与
        self.assertEqual(first, self._build(
            now=1769999999, source={"repo": "other/repo"})["content_digest"])
        patched = json.loads(json.dumps(VULNS))
        patched["npm|lodash|4.17.20"] = {"osv_raw": {"vulns": [{"id": "CVE-2026-0001"}]}}
        self._write(os.path.join(self.src, "vulns.json"), patched)
        self.assertNotEqual(first, self._build()["content_digest"])

    def test_missing_sources_degrade_and_empty_fail(self):
        built = release_mod.build_release(
            self.out,
            vulns=os.path.join(self.src, "vulns.json"),
            health=os.path.join(self.src, "missing-health.json"),
            community=None,
            version="20261015.231400.0",
        )
        self.assertEqual(list(built["manifest"]["datasets"]), ["vulns"])
        with self.assertRaises(release_mod.ReleaseError):
            release_mod.build_release(self.out, vulns=None, health=None, community=None)

    def test_signature(self):
        unsigned = self._build()
        self.assertNotIn("signature", unsigned["manifest"])
        signed = self._build(key=KEY)
        self.assertEqual(signed["manifest"]["signature"]["algo"], "hmac-sha256")
        self.assertTrue(signed["manifest"]["signature"]["value"])
        self.assertEqual(signed["content_digest"], unsigned["content_digest"])
        self.assertTrue(release_mod.verify(self.out)["ok"])

    def test_verify_detects_tamper(self):
        self._build()
        target = os.path.join(self.out, "data", "vulns.json")
        with open(target, "w", encoding="utf-8") as handle:
            json.dump({}, handle)
        result = release_mod.verify(self.out)
        self.assertFalse(result["ok"])
        self.assertEqual(result["failures"][0]["reason"], "sha256-mismatch")
        os.remove(target)
        result = release_mod.verify(self.out)
        self.assertFalse(result["ok"])
        self.assertEqual(result["failures"][0]["reason"], "missing")

    def test_version_stamp_format(self):
        self.assertRegex(release_mod.version_stamp(1761000000), r"^\d{8}\.\d{6}\.0$")
        self.assertNotEqual(release_mod.version_stamp(1761000000),
                            release_mod.version_stamp(1761003600))

    def test_source_from_env(self):
        source = release_mod.source_from_env({
            "GITHUB_REPOSITORY": "scabase/scabase.github.io",
            "GITHUB_SHA": "abc123",
            "GITHUB_RUN_ID": "42",
        })
        self.assertEqual(source["repo"], "scabase/scabase.github.io")
        self.assertEqual(source["commit"], "abc123")
        self.assertTrue(source["run_url"].endswith("/actions/runs/42"))


if __name__ == "__main__":
    unittest.main()
