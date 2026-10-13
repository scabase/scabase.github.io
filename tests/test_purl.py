import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oss_intake import purl  # noqa: E402


class PurlTest(unittest.TestCase):
    def test_gav_to_purl(self):
        self.assertEqual(
            purl.from_gav("com.alibaba:fastjson:1.2.24"),
            "pkg:maven/com.alibaba/fastjson@1.2.24",
        )

    def test_gav_without_version(self):
        self.assertEqual(
            purl.from_gav("com.alibaba:fastjson"),
            "pkg:maven/com.alibaba/fastjson",
        )

    def test_parse_roundtrip_with_gav_projection(self):
        info = purl.parse("pkg:maven/com.alibaba/fastjson@1.2.24")
        self.assertEqual(info["eco"], "maven")
        self.assertEqual(info["namespace"], "com.alibaba")
        self.assertEqual(info["name"], "fastjson")
        self.assertEqual(info["version"], "1.2.24")
        self.assertEqual(info["gav"], "com.alibaba:fastjson:1.2.24")

    def test_eco_alias(self):
        self.assertEqual(purl.normalize_eco("PyPI"), "pypi")
        self.assertEqual(purl.normalize_eco("golang"), "go")
        self.assertEqual(purl.normalize_eco("crates.io"), "cargo")

    def test_npm_scoped(self):
        built = purl.build("npm", "lodash", "4.17.20", "babel")
        self.assertEqual(built, "pkg:npm/babel/lodash@4.17.20")
        info = purl.parse(built)
        self.assertEqual(info["eco"], "npm")
        self.assertIsNone(info["gav"])

    def test_go_module(self):
        built = purl.build("go", "gin", "1.6.0", "github.com/gin-gonic")
        self.assertTrue(built.startswith("pkg:golang/github.com/gin-gonic/gin"))
        info = purl.parse(built)
        self.assertEqual(info["eco"], "go")

    def test_key_is_stable_and_lowercase(self):
        first = purl.key_of("pkg:maven/Com.Alibaba/Fastjson@1.2.24")
        second = purl.key_of("pkg:maven/com.alibaba/fastjson@1.2.24")
        self.assertEqual(first, second)

    def test_display_prefers_gav(self):
        self.assertEqual(
            purl.display_of("pkg:maven/com.alibaba/fastjson@1.2.24"),
            "com.alibaba:fastjson:1.2.24",
        )

    def test_invalid_input(self):
        self.assertIsNone(purl.parse("not-a-purl"))
        self.assertIsNone(purl.from_gav("fastjson"))


if __name__ == "__main__":
    unittest.main()
