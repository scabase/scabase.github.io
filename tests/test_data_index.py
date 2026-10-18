"""机器可读数据索引（gen_data_index）测试（全部离线）。

覆盖：
  - index.json 条目结构（URL / bytes / sha256 / 内嵌 generated_at）
  - sha256 与字节数与实际文件一致
  - 缺失文件被跳过而不报错
  - CLI main() 落盘
  - DATASETS 清单自身约束（id / 文件名唯一、字段齐全）
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import ROOT, cleanup  # noqa: E402

FETCHER = os.path.join(ROOT, "scabase-fetcher", "scripts")
sys.path.insert(0, FETCHER)

import gen_data_index as idx  # noqa: E402


class DatasetTableTest(unittest.TestCase):
    def test_dataset_ids_and_files_unique(self):
        ids = [d["id"] for d in idx.DATASETS]
        files = [d["file"] for d in idx.DATASETS]
        self.assertEqual(len(ids), len(set(ids)), "数据集 id 重复")
        self.assertEqual(len(files), len(set(files)), "数据集文件名重复")

    def test_dataset_entries_have_required_fields(self):
        for entry in idx.DATASETS:
            for field in ("id", "file", "title", "format", "schema", "llm_hint"):
                self.assertIn(field, entry, "%s 缺少 %s" % (entry.get("id"), field))

    def test_real_data_dir_has_all_datasets(self):
        # 仓库内的数据目录应覆盖索引清单中的每个文件（pages.yml 同步发布，
        # 数据采集工作流提交数据时同步刷新索引）
        data_dir = os.path.join(ROOT, "scabase-fetcher", "data")
        for entry in idx.DATASETS:
            self.assertTrue(os.path.exists(os.path.join(data_dir, entry["file"])),
                            "缺少数据文件 %s" % entry["file"])


class BuildIndexTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scabase-index-")
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(self.data)
        # 只放两个文件，其余走「缺失跳过」分支
        self.vulns = {"maven|com.alibaba:fastjson|1.2.24": {"osv_raw": {"vulns": []},
                                                            "enriched": []}}
        with open(os.path.join(self.data, "vulns.json"), "w", encoding="utf-8") as fh:
            json.dump(self.vulns, fh)
        with open(os.path.join(self.data, "pkg_list.txt"), "w", encoding="utf-8") as fh:
            fh.write("# 注释\nmaven|com.alibaba:fastjson|1.2.24\n")

    def tearDown(self):
        cleanup(self.tmp)

    def test_entry_shape(self):
        index = idx.build_index(self.data, "https://example.com/")
        self.assertEqual(index["base_url"], "https://example.com")
        self.assertEqual(index["llms_txt"], "https://example.com/llms.txt")
        by_id = {d["id"]: d for d in index["datasets"]}
        self.assertEqual(set(by_id), {"vulns", "pkg-list"})

        vulns = by_id["vulns"]
        self.assertEqual(vulns["url"], "https://example.com/scabase-fetcher/data/vulns.json")
        self.assertEqual(vulns["path"], "/scabase-fetcher/data/vulns.json")
        with open(os.path.join(self.data, "vulns.json"), "rb") as fh:
            raw = fh.read()
        self.assertEqual(vulns["bytes"], len(raw))
        self.assertEqual(vulns["sha256"], hashlib.sha256(raw).hexdigest())

        pkg = by_id["pkg-list"]
        self.assertEqual(pkg["format"], "text")
        self.assertNotIn("generated_at", pkg)

    def test_embedded_generated_at_extracted(self):
        path = os.path.join(self.data, "community-support.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"generated_at": "2026-10-17T00:00:00Z", "components": []}, fh)
        index = idx.build_index(self.data, "https://example.com")
        by_id = {d["id"]: d for d in index["datasets"]}
        self.assertEqual(by_id["community-support"]["generated_at"], "2026-10-17T00:00:00Z")

    def test_cli_writes_file(self):
        out = os.path.join(self.tmp, "index.json")
        # 直接走 main（argparse 从 sys.argv 读取）
        argv = sys.argv
        sys.argv = ["gen_data_index.py", "--data", self.data,
                    "--out", out, "--base-url", "https://example.com"]
        try:
            self.assertEqual(idx.main(), 0)
        finally:
            sys.argv = argv
        with open(out, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertEqual(payload["base_url"], "https://example.com")
        self.assertTrue(payload["datasets"])
        self.assertIn("generated_at", payload)


if __name__ == "__main__":
    unittest.main()
