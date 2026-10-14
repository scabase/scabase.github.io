import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, cleanup  # noqa: E402
from oss_intake import depfile  # noqa: E402

DEPS = os.path.join(ROOT, "examples", "deps")


def _write(name, text):
    path = os.path.join(tempfile.mkdtemp(prefix="depfile-"), name)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


class DepfileTest(unittest.TestCase):
    def _purls(self, result):
        return [component["purl"] for component in result["components"]]

    def test_pom_resolves_properties_and_managed_version(self):
        result = depfile.parse_file(os.path.join(DEPS, "pom.xml"))
        self.assertEqual(result["format"], "pom")
        purls = self._purls(result)
        self.assertIn("pkg:maven/com.alibaba/fastjson@1.2.24", purls)
        self.assertIn("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", purls)
        # 版本来自 dependencyManagement
        self.assertIn("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0", purls)
        junit = [c for c in result["components"] if c["name"] == "junit"][0]
        self.assertEqual(junit["scope"], "test")
        self.assertTrue(all(component["direct"] for component in result["components"]))

    def test_pom_reports_modules(self):
        text = """<project><modules><module>svc-a</module><module>svc-b</module></modules>
        <dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>
        <version>1.0</version></dependency></dependencies></project>"""
        result = depfile.parse_file(_write("pom.xml", text))
        self.assertEqual(result["modules"], ["svc-a", "svc-b"])

    def test_requirements_handles_ranges_and_unpinned(self):
        result = depfile.parse_file(os.path.join(DEPS, "requirements.txt"))
        purls = self._purls(result)
        self.assertIn("pkg:pypi/requests@2.31.0", purls)
        self.assertIn("pkg:pypi/flask@2.0.0", purls)
        self.assertIn("pkg:pypi/numpy@1.21.0", purls)
        pinned = {c["name"]: c["pinned"] for c in result["components"]}
        self.assertTrue(pinned["requests"])
        self.assertFalse(pinned["flask"])
        self.assertFalse(pinned["numpy"])
        # 未锁定版本的条目进入 unresolved
        self.assertTrue(any(u["name"] == "attrs" for u in result["unresolved"]))

    def test_package_json_marks_dev_and_scoped(self):
        result = depfile.parse_file(os.path.join(DEPS, "package.json"))
        by_name = {c["name"]: c for c in result["components"]}
        self.assertEqual(by_name["axios"]["purl"], "pkg:npm/axios@0.21.1")
        self.assertEqual(by_name["eslint"]["scope"], "dev")
        self.assertFalse(by_name["eslint"]["direct"])
        self.assertEqual(by_name["core"]["purl"], "pkg:npm/babel/core@7.12.3")
        self.assertFalse(by_name["core"]["pinned"])

    def test_yarn_lock_versions(self):
        result = depfile.parse_file(os.path.join(DEPS, "yarn.lock"))
        purls = self._purls(result)
        self.assertIn("pkg:npm/axios@0.21.1", purls)
        self.assertIn("pkg:npm/lodash@4.17.20", purls)
        self.assertIn("pkg:npm/babel/core@7.23.6", purls)

    def test_go_mod_direct_and_indirect(self):
        result = depfile.parse_file(os.path.join(DEPS, "go.mod"))
        by_purl = {c["purl"]: c for c in result["components"]}
        self.assertTrue(by_purl["pkg:golang/github.com/gin-gonic/gin@v1.7.7"]["direct"])
        # // indirect 标记的依赖不应计入直接依赖
        self.assertFalse(by_purl["pkg:golang/github.com/golang/jwt/v4@v4.5.0"]["direct"])
        self.assertTrue(by_purl["pkg:golang/github.com/go-redis/redis/v8@v8.11.5"]["direct"])

    def test_npm_lock_v3(self):
        text = """{"lockfileVersion": 3, "packages": {
          "": {"dependencies": {"axios": "^0.21.1"}},
          "node_modules/axios": {"version": "0.21.1"},
          "node_modules/axios/node_modules/debug": {"version": "4.3.4"}
        }}"""
        result = depfile.parse_file(_write("package-lock.json", text))
        by_name = {c["name"]: c for c in result["components"]}
        self.assertTrue(by_name["axios"]["direct"])
        self.assertFalse(by_name["debug"]["direct"])

    def test_pnpm_lock(self):
        text = """lockfileVersion: 5.4
packages:
  /axios/0.21.1:
    resolution: {integrity: sha512-x}
  /@babel/core/7.23.6:
    resolution: {integrity: sha512-y}
"""
        result = depfile.parse_file(_write("pnpm-lock.yaml", text))
        purls = self._purls(result)
        self.assertIn("pkg:npm/axios@0.21.1", purls)
        self.assertIn("pkg:npm/babel/core@7.23.6", purls)

    def test_poetry_and_pipfile_lock(self):
        poetry = """[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "flask"
version = "2.0.0"
"""
        result = depfile.parse_file(_write("poetry.lock", poetry))
        self.assertIn("pkg:pypi/requests@2.31.0", self._purls(result))

        pipfile = '{"default": {"requests": {"version": "==2.31.0"}}, "develop": {"pytest": {"version": "==7.4.0"}}}'
        result = depfile.parse_file(_write("Pipfile.lock", pipfile))
        by_name = {c["name"]: c for c in result["components"]}
        self.assertTrue(by_name["requests"]["direct"])
        self.assertEqual(by_name["pytest"]["scope"], "dev")

    def test_pyproject_pep621(self):
        text = """[project]
name = "demo"
dependencies = [
  "requests>=2.31.0",
  "flask==2.0.0"
]
"""
        result = depfile.parse_file(_write("pyproject.toml", text))
        purls = self._purls(result)
        self.assertIn("pkg:pypi/requests@2.31.0", purls)
        self.assertIn("pkg:pypi/flask@2.0.0", purls)

    def test_gradle_composer_cargo_gem(self):
        gradle = "dependencies {\n    implementation 'com.alibaba:fastjson:1.2.24'\n    testImplementation 'junit:junit:4.13.2'\n}"
        result = depfile.parse_file(_write("build.gradle", gradle))
        by_name = {c["name"]: c for c in result["components"]}
        self.assertEqual(by_name["fastjson"]["version"], "1.2.24")
        self.assertEqual(by_name["junit"]["scope"], "test")

        composer = '{"require": {"monolog/monolog": "2.9.1"}, "require-dev": {"phpunit/phpunit": "9.6.0"}}'
        result = depfile.parse_file(_write("composer.json", composer))
        self.assertIn("pkg:composer/monolog/monolog@2.9.1", self._purls(result))

        cargo = """[[package]]
name = "serde"
version = "1.0.188"
"""
        result = depfile.parse_file(_write("Cargo.lock", cargo))
        self.assertIn("pkg:cargo/serde@1.0.188", self._purls(result))

        gem = "GEM\n  specs:\n    rails (7.0.8)\n"
        result = depfile.parse_file(_write("Gemfile.lock", gem))
        self.assertIn("pkg:gem/rails@7.0.8", self._purls(result))

    def test_scan_dir_aggregates_all_formats(self):
        scan = depfile.scan_dir(DEPS)
        formats = sorted({item["format"] for item in scan["files"]})
        self.assertEqual(formats, ["go-mod", "package-json", "pom", "requirements", "yarn-lock"])
        self.assertGreater(scan["component_count"], 10)
        # 去重后每个 PURL 只出现一次
        purls = [c["purl"] for c in scan["components"]]
        self.assertEqual(len(purls), len(set(purls)))

    def test_assets_entry_from_scan(self):
        scan = depfile.scan_dir(DEPS)
        entry = depfile.assets_entry("支付群组", "支付核心", scan, tier="core")
        self.assertEqual(entry["group"], "支付群组")
        self.assertIn("pkg:maven/com.alibaba/fastjson@1.2.24", entry["purls"])
        self.assertIn("com.alibaba:fastjson:1.2.24", entry["gavs"])

    def test_broken_file_does_not_break_scan(self):
        path = _write("pom.xml", "<project><dependencies>")
        directory = os.path.dirname(path)
        try:
            scan = depfile.scan_dir(directory)
        finally:
            cleanup(directory)
        self.assertTrue(any("解析失败" in (u.get("reason") or "") for u in scan["unresolved"]))


if __name__ == "__main__":
    unittest.main()
