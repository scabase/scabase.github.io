"""离线摆渡同步：数据包构建、签名、内网导入与回执。

关键机制：
  * 每个数据集独立单调递增 seq
  * manifest 逐文件 sha256 + 整体签名（防篡改）
  * prev_digest 链 + seq 单调校验（防回滚）
  * 临时目录 → 全量校验 → 原子 rename（导入中断不留半套数据）
  * 脱敏回执（不含 GAV 清单 / 源代码 / 拓扑）

零第三方依赖；ed25519 在具备 cryptography 时自动启用，否则回落 HMAC-SHA256。
"""
import hashlib
import hmac
import json
import os
import shutil
import tarfile
import tempfile
import time

from .facts import EXTERNAL_DATASETS

BUNDLE_SCHEMA = "scabase-bundle/v1"


def _canonical(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


class Signer(object):
    """签名器：优先 ed25519，回落 HMAC-SHA256。"""

    def __init__(self, key, algo=None, keyid="scabase-sync"):
        self.key = key
        self.keyid = keyid
        self.algo = algo or self._pick_algo()

    @staticmethod
    def _pick_algo():
        try:  # pragma: no cover - 取决于运行环境
            import cryptography  # noqa: F401
            return "ed25519"
        except Exception:
            return "hmac-sha256"

    def sign(self, payload):
        if self.algo == "ed25519":  # pragma: no cover - 需 cryptography
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private = serialization.load_pem_private_key(
                self.key.encode("utf-8") if isinstance(self.key, str) else self.key,
                password=None,
            )
            if not isinstance(private, Ed25519PrivateKey):
                raise ValueError("ed25519 需要 Ed25519 私钥 PEM")
            return private.sign(payload).hex()
        return hmac.new(self._key_bytes(), payload, hashlib.sha256).hexdigest()

    def verify(self, payload, signature):
        try:
            if self.algo == "ed25519":  # pragma: no cover - 需 cryptography
                from cryptography.hazmat.primitives import serialization
                public = serialization.load_pem_public_key(
                    self.key.encode("utf-8") if isinstance(self.key, str) else self.key)
                public.verify(bytes.fromhex(signature), payload)
                return True
            expected = self.sign(payload)
            return hmac.compare_digest(expected, signature or "")
        except Exception:
            return False

    def _key_bytes(self):
        return self.key.encode("utf-8") if isinstance(self.key, str) else self.key


class SyncError(Exception):
    pass


class Bundle(object):
    """数据包构建与导入。"""

    def __init__(self, store, signer):
        self.store = store
        self.signer = signer
        self.bundle_dir = os.path.join(store.root, "bundles")
        os.makedirs(self.bundle_dir, exist_ok=True)

    # ------------------------------------------------------------ 状态

    def _last_path(self, dataset):
        return os.path.join(self.bundle_dir, "%s.last.json" % dataset)

    def _load_last(self, dataset):
        path = self._last_path(dataset)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return {"seq": 0, "digest": None, "shards": {}}

    def _save_last(self, dataset, state):
        with open(self._last_path(dataset), "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)

    # ------------------------------------------------------------ 构建

    def build(self, dataset, out_dir, mode="delta", now=None):
        if dataset not in EXTERNAL_DATASETS:
            raise SyncError("内部数据集 %s 禁止外发" % dataset)

        os.makedirs(out_dir, exist_ok=True)
        last = self._load_last(dataset)
        current = {}
        directory = os.path.join(self.store.root, dataset)
        for name in self.store.shards(dataset):
            current[name] = sha256_file(os.path.join(directory, name))

        changes = []
        if mode == "snapshot":
            for name in sorted(current):
                changes.append({"path": "data/%s" % name, "sha256": current[name],
                                "size": os.path.getsize(os.path.join(directory, name)),
                                "op": "upsert"})
        else:
            previous = last.get("shards") or {}
            for name in sorted(current):
                if previous.get(name) != current[name]:
                    changes.append({"path": "data/%s" % name, "sha256": current[name],
                                    "size": os.path.getsize(os.path.join(directory, name)),
                                    "op": "upsert"})
            for name in sorted(set(previous) - set(current)):
                changes.append({"path": "data/%s" % name, "sha256": "", "size": 0,
                                "op": "delete"})
        if not changes and mode == "delta":
            return None

        meta = self.store.dataset_meta(dataset)
        manifest = {
            "schema": BUNDLE_SCHEMA,
            "dataset": dataset,
            "seq": int(last.get("seq", 0)) + 1,
            "mode": mode,
            "generated_at": meta.get("generated_at") or time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now if now else time.time())),
            "source_watermark": {
                "dataset_seq": meta.get("seq"),
                "generated_at": meta.get("generated_at"),
                "degraded": bool(meta.get("degraded")),
            },
            "prev_digest": last.get("digest"),
            "files": changes,
        }
        signature = self.signer.sign(_canonical(manifest))
        signed = dict(manifest)
        signed["signature"] = {
            "algo": self.signer.algo,
            "keyid": self.signer.keyid,
            "value": signature,
        }
        digest = sha256_bytes(_canonical(manifest))

        stamp = time.strftime("%Y%m%d", time.gmtime(now if now else time.time()))
        name = "bundle-%s-%04d-%s.tar.gz" % (dataset, manifest["seq"], stamp)
        out_path = os.path.join(out_dir, name)
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = os.path.join(tmp, "data")
            os.makedirs(data_dir, exist_ok=True)
            with open(os.path.join(tmp, "manifest.json"), "w", encoding="utf-8") as handle:
                json.dump(signed, handle, ensure_ascii=False, indent=2, sort_keys=True)
            for change in changes:
                if change["op"] == "delete":
                    continue
                source = os.path.join(directory, os.path.basename(change["path"]))
                shutil.copyfile(source, os.path.join(data_dir, os.path.basename(change["path"])))
            with tarfile.open(out_path, "w:gz") as tar:
                tar.add(os.path.join(tmp, "manifest.json"), arcname="manifest.json")
                tar.add(data_dir, arcname="data")

        last.update({"seq": manifest["seq"], "digest": digest, "shards": current})
        self._save_last(dataset, last)
        return {"path": out_path, "manifest": signed, "digest": digest}

    # ------------------------------------------------------------ 导入

    def _load_state(self):
        if os.path.exists(self.store.state_path):
            with open(self.store.state_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return {}

    def _save_state(self, state):
        with open(self.store.state_path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)

    def import_bundle(self, bundle_path, force=False):
        with tempfile.TemporaryDirectory() as tmp:
            with tarfile.open(bundle_path, "r:gz") as tar:
                try:
                    tar.extractall(tmp, filter="data")
                except TypeError:  # pragma: no cover - Python < 3.12
                    tar.extractall(tmp)

            manifest_path = os.path.join(tmp, "manifest.json")
            if not os.path.exists(manifest_path):
                raise SyncError("数据包缺少 manifest.json")
            with open(manifest_path, "r", encoding="utf-8") as handle:
                signed = json.load(handle)
            if signed.get("schema") != BUNDLE_SCHEMA:
                raise SyncError("manifest schema 不匹配：%s" % signed.get("schema"))

            signature = signed.get("signature") or {}
            manifest = {k: v for k, v in signed.items() if k != "signature"}
            if not self.signer.verify(_canonical(manifest), signature.get("value")):
                raise SyncError("签名校验失败（algo=%s keyid=%s）" % (
                    signature.get("algo"), signature.get("keyid")))

            dataset = manifest.get("dataset")
            seq = int(manifest.get("seq") or 0)
            state = self._load_state()
            current = state.get(dataset) or {}
            # 防回滚：任何模式都拒绝 seq 小于等于已导入值
            if not force and seq <= int(current.get("seq") or 0):
                raise SyncError("seq 回退：已导入 %s，待导入 %s" % (
                    current.get("seq"), seq))
            # 增量链校验：snapshot 用于全量校准，允许不携带 prev_digest
            if manifest.get("mode") != "snapshot" and not force:
                if current.get("digest") and manifest.get("prev_digest") != current.get("digest"):
                    raise SyncError("prev_digest 链校验失败，需导入 snapshot 全量包")

            staged = os.path.join(tmp, "data")
            prepared = []
            for entry in manifest.get("files") or []:
                rel = os.path.basename(entry.get("path") or "")
                target = os.path.join(self.store.root, dataset, rel)
                if entry.get("op") == "delete":
                    prepared.append(("delete", target, None))
                    continue
                source = os.path.join(staged, rel)
                if not os.path.exists(source):
                    raise SyncError("数据包缺少文件：%s" % rel)
                if sha256_file(source) != entry.get("sha256"):
                    raise SyncError("文件哈希不匹配：%s" % rel)
                prepared.append(("upsert", target, source))

            # 原子切换：先落 .tmp，再整体 rename
            pending = []
            for op, target, source in prepared:
                tmp_target = target + ".tmp-import"
                os.makedirs(os.path.dirname(target), exist_ok=True)
                if op == "delete":
                    pending.append((op, target, tmp_target, None))
                else:
                    shutil.copyfile(source, tmp_target)
                    pending.append((op, target, tmp_target, source))

            for op, target, tmp_target, source in pending:
                if op == "delete":
                    if os.path.exists(target):
                        os.remove(target)
                else:
                    os.replace(tmp_target, target)

            digest = sha256_bytes(_canonical(manifest))
            state[dataset] = {"seq": seq, "digest": digest,
                              "imported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            self._save_state(state)

            meta = self.store.dataset_meta(dataset)
            meta["seq"] = seq
            meta["generated_at"] = manifest.get("generated_at")
            meta["degraded"] = bool((manifest.get("source_watermark") or {}).get("degraded"))
            self.store.save_meta()

            return {
                "dataset": dataset,
                "seq": seq,
                "mode": manifest.get("mode"),
                "digest": digest,
                "files": len(prepared),
                "generated_at": manifest.get("generated_at"),
            }

    # ------------------------------------------------------------ 回执

    def write_receipt(self, imported, extra=None):
        os.makedirs(self.store.outbox_dir, exist_ok=True)
        receipt = {
            "schema": "scabase-receipt/v1",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "dataset": imported.get("dataset"),
            "seq": imported.get("seq"),
            "digest": imported.get("digest"),
            "imported_at": imported.get("imported_at"),
            "data_generated_at": imported.get("generated_at"),
            "files": imported.get("files"),
        }
        if extra:
            receipt["aggregate"] = extra
        name = "receipt-%s-%04d.json" % (imported.get("dataset"), imported.get("seq"))
        path = os.path.join(self.store.outbox_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, ensure_ascii=False, indent=2, sort_keys=True)
        return path
