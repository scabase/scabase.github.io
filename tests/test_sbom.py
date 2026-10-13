import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, load_example  # noqa: E402
from oss_intake import sbom  # noqa: E402


class SbomTest(unittest.TestCase):
    def test_cyclonedx_ingest(self):
        path = os.path.join(ROOT, "examples", "sample-app.cdx.json")
        result = sbom.ingest(path)
        self.assertEqual(result["format"], "cyclonedx")
        self.assertEqual(len(result["components"]), 4)
        self.assertEqual(len(result["unresolved"]), 1)
        self.assertEqual(result["unresolved"][0]["name"], "mystery-lib")

    def test_direct_and_transitive(self):
        path = os.path.join(ROOT, "examples", "sample-app.cdx.json")
        result = sbom.ingest(path)
        by_purl = {item["purl"]: item for item in result["components"]}
        self.assertTrue(by_purl["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]["direct"])
        self.assertFalse(by_purl["pkg:maven/junit/junit@4.13.2"]["direct"])

    def test_gav_projection_present(self):
        path = os.path.join(ROOT, "examples", "sample-app.cdx.json")
        result = sbom.ingest(path)
        gavs = [item["gav"] for item in result["components"] if item["gav"]]
        self.assertIn("org.apache.logging.log4j:log4j-core:2.14.1", gavs)

    def test_maven_tree_ingest(self):
        import tempfile
        tree = "\n".join([
            "[INFO] --- maven-dependency-plugin:3.1.1:tree ---",
            "[INFO] com.example:demo:jar:1.0.0",
            "[INFO] +- com.alibaba:fastjson:jar:1.2.24:compile",
            "[INFO] |  \\- org.ow2.asm:asm:jar:9.2:compile",
            "[INFO] \\- junit:junit:jar:4.13.2:test",
        ])
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write(tree)
            path = handle.name
        try:
            result = sbom.ingest(path)
        finally:
            os.remove(path)
        by_gav = {item["gav"]: item for item in result["components"]}
        self.assertIn("com.alibaba:fastjson:1.2.24", by_gav)
        self.assertTrue(by_gav["com.alibaba:fastjson:1.2.24"]["direct"])
        self.assertFalse(by_gav["org.ow2.asm:asm:9.2"]["direct"])

    def test_requirements_ingest(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("requests==2.20.0\n# comment\nflask==2.0.1\n")
            path = handle.name
        try:
            result = sbom.ingest(path)
        finally:
            os.remove(path)
        names = sorted(item["name"] for item in result["components"])
        self.assertEqual(names, ["flask", "requests"])

    def test_dedupe_prefers_direct(self):
        components = [
            {"purl": "pkg:maven/a/b@1", "direct": False},
            {"purl": "pkg:maven/a/b@1", "direct": True},
        ]
        merged = sbom.dedupe(components)
        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0]["direct"])


if __name__ == "__main__":
    unittest.main()
