import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oss_intake import baseline as baseline_mod  # noqa: E402
from oss_intake import scriptgen  # noqa: E402


class ScriptgenTest(unittest.TestCase):
    def setUp(self):
        self.catalog = baseline_mod.load_catalog()
        self.redis = baseline_mod.by_id(self.catalog, "redis-requirepass")
        self.fastjson = baseline_mod.by_id(self.catalog, "fastjson-autotype")
        self.out = tempfile.mkdtemp(prefix="scriptgen-")

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def test_sreops_script_passes_lint(self):
        content = scriptgen.render(self.redis, "sreops")[0]["content"]
        ok, problems = scriptgen.lint(content, "sreops", "redis-requirepass")
        self.assertTrue(ok, problems)
        self.assertIn("#!/bin/sh", content)
        self.assertIn("STATUS=", content)
        self.assertIn("requirepass", content)

    def test_version_check_script_has_comparison(self):
        content = scriptgen.render(self.fastjson, "sreops")[0]["content"]
        ok, problems = scriptgen.lint(content, "sreops", "fastjson-autotype")
        self.assertTrue(ok, problems)
        self.assertIn("sort -V", content)

    def test_codescan_yaml_and_script(self):
        files = scriptgen.render(self.redis, "codescan")
        self.assertEqual(len(files), 2)
        yaml_text = files[0]["content"]
        self.assertIn("scabase-redis-requirepass", yaml_text)
        ok, problems = scriptgen.lint(yaml_text, "codescan", "redis-requirepass")
        self.assertTrue(ok, problems)
        compile(files[1]["content"], "<generated>", "exec")

    def test_python_script_compiles_and_lints(self):
        content = scriptgen.render(self.redis, "python")[0]["content"]
        compile(content, "<generated>", "exec")
        ok, problems = scriptgen.lint(content, "python", "redis-requirepass")
        self.assertTrue(ok, problems)
        self.assertIn("def main", content)

    def test_generate_writes_manifest_and_files(self):
        manifest = scriptgen.generate([self.redis, self.fastjson], target="sreops",
                                      out_dir=self.out)
        self.assertEqual(len(manifest["rules"]), 2)
        for rule in manifest["rules"]:
            self.assertTrue(rule["lint_ok"], rule["problems"])
            self.assertEqual(rule["generated_by"], "template")
            self.assertTrue(rule["review_required"])
            for entry in rule["files"]:
                path = os.path.join(self.out, rule["id"], entry["filename"])
                self.assertTrue(os.path.exists(path))
        self.assertTrue(os.path.exists(os.path.join(self.out, "manifest.json")))

    def test_llm_disabled_falls_back_to_template(self):
        client = scriptgen.LLMClient(endpoint="")
        self.assertFalse(client.enabled())
        self.assertIsNone(client.complete("hello"))
        manifest = scriptgen.generate([self.redis], target="sreops", out_dir=self.out,
                                      llm=client, use_llm=True)
        self.assertEqual(manifest["rules"][0]["generated_by"], "template")

    def test_lint_rejects_dangerous_content(self):
        ok, problems = scriptgen.lint("#!/bin/sh\nrm -rf /data\n", "sreops", "x")
        self.assertFalse(ok)
        self.assertTrue(any("高危指令" in p for p in problems))

    def test_prompt_contains_platform_rules(self):
        prompt = scriptgen.build_prompt(self.redis, "sreops",
                                        scriptgen.render(self.redis, "sreops")[0]["content"])
        self.assertIn("e运维巡检脚本规范", prompt)
        self.assertIn("redis-requirepass", prompt)

    def test_unsupported_target_raises(self):
        with self.assertRaises(ValueError):
            scriptgen.render(self.redis, "unknown-target")


if __name__ == "__main__":
    unittest.main()
