import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixtures import build_store, cleanup, tmp_facts  # noqa: E402
from oss_intake import facts as facts_mod  # noqa: E402
from oss_intake import sync as sync_mod  # noqa: E402

KEY = "test-sync-key"


class SyncTest(unittest.TestCase):
    def setUp(self):
        self.src = build_store()
        self.dst = tmp_facts()
        self.out = tempfile.mkdtemp(prefix="oss-intake-bundles-")
        self.signer = sync_mod.Signer(KEY)
        self.producer = sync_mod.Bundle(facts_mod.FactsStore(self.src), self.signer)
        self.consumer = sync_mod.Bundle(facts_mod.FactsStore(self.dst).ensure(), self.signer)

    def tearDown(self):
        cleanup(self.src)
        cleanup(self.dst)
        cleanup(self.out)

    def _build(self, dataset="vulns", mode="delta"):
        return self.producer.build(dataset, self.out, mode=mode)

    def test_snapshot_build_and_import(self):
        built = self._build(mode="snapshot")
        self.assertIsNotNone(built)
        self.assertEqual(built["manifest"]["seq"], 1)
        imported = self.consumer.import_bundle(built["path"])
        self.assertEqual(imported["seq"], 1)
        self.assertGreater(imported["files"], 0)
        self.assertEqual(
            facts_mod.FactsStore(self.dst).read_shard("vulns", "maven"),
            facts_mod.FactsStore(self.src).read_shard("vulns", "maven"),
        )

    def test_no_change_produces_nothing(self):
        self._build(mode="snapshot")
        self.assertIsNone(self._build(mode="delta"))

    def test_delta_only_carries_changes(self):
        self._build(mode="snapshot")
        previous = self.producer._load_last("vulns")["digest"]
        store = facts_mod.FactsStore(self.src)
        store.upsert("vulns", "pkg:maven/new/pkg@1", {"cves": [], "max_cvss": 0,
                                                      "kev_count": 0, "unfixed_count": 0})
        built = self._build()
        self.assertEqual(built["manifest"]["seq"], 2)
        self.assertEqual(built["manifest"]["mode"], "delta")
        self.assertEqual(built["manifest"]["prev_digest"], previous)

    def test_signature_mismatch_rejected(self):
        built = self._build(mode="snapshot")
        other = sync_mod.Bundle(facts_mod.FactsStore(self.dst).ensure(),
                                sync_mod.Signer("wrong-key"))
        with self.assertRaises(sync_mod.SyncError) as ctx:
            other.import_bundle(built["path"])
        self.assertIn("签名校验失败", str(ctx.exception))

    def test_seq_rollback_rejected(self):
        first = self._build(mode="snapshot")
        store = facts_mod.FactsStore(self.src)
        store.upsert("vulns", "pkg:maven/new/pkg@1", {"cves": [], "max_cvss": 0,
                                                      "kev_count": 0, "unfixed_count": 0})
        second = self._build()
        self.consumer.import_bundle(first["path"])
        self.consumer.import_bundle(second["path"])
        with self.assertRaises(sync_mod.SyncError) as ctx:
            self.consumer.import_bundle(first["path"])
        self.assertIn("seq 回退", str(ctx.exception))

    def test_broken_chain_rejected(self):
        first = self._build(mode="snapshot")
        self.consumer.import_bundle(first["path"])
        # 伪造上游状态，使下一个 delta 包的 prev_digest 与内网记录不一致
        self.producer._save_last("vulns", {"seq": 1, "digest": "sha256:bogus",
                                           "shards": {}})
        store = facts_mod.FactsStore(self.src)
        store.upsert("vulns", "pkg:maven/new/pkg@1", {"cves": [], "max_cvss": 0,
                                                      "kev_count": 0, "unfixed_count": 0})
        built = self._build()
        with self.assertRaises(sync_mod.SyncError) as ctx:
            self.consumer.import_bundle(built["path"])
        self.assertIn("prev_digest", str(ctx.exception))

    def test_tampered_file_rejected(self):
        built = self._build(mode="snapshot")
        tampered = os.path.join(self.out, "tampered.tar.gz")
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(built["path"], "r:gz") as tar:
                tar.extractall(tmp)
            shard = os.path.join(tmp, "data", "maven.json")
            with open(shard, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            payload["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"] = {
                "cves": [], "max_cvss": 0, "kev_count": 0, "unfixed_count": 0}
            with open(shard, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            with tarfile.open(tampered, "w:gz") as tar:
                tar.add(os.path.join(tmp, "manifest.json"), arcname="manifest.json")
                tar.add(os.path.join(tmp, "data"), arcname="data")
        with self.assertRaises(sync_mod.SyncError) as ctx:
            self.consumer.import_bundle(tampered)
        self.assertIn("哈希不匹配", str(ctx.exception))
        self.assertEqual(facts_mod.FactsStore(self.dst).read_shard("vulns", "maven"), {})

    def test_receipt_is_generated_and_desensitized(self):
        built = self._build(mode="snapshot")
        imported = self.consumer.import_bundle(built["path"])
        path = self.consumer.write_receipt(imported)
        self.assertTrue(os.path.exists(path))
        with open(path, "r", encoding="utf-8") as handle:
            receipt = json.load(handle)
        self.assertEqual(receipt["dataset"], "vulns")
        self.assertEqual(receipt["seq"], 1)
        blob = json.dumps(receipt, ensure_ascii=False)
        self.assertNotIn("com.alibaba", blob)
        self.assertNotIn("log4j", blob)

    def test_internal_dataset_cannot_be_bundled(self):
        with self.assertRaises(sync_mod.SyncError) as ctx:
            self._build(dataset="inventory")
        self.assertIn("禁止外发", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
