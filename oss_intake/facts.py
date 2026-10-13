"""事实层读写：按数据集分片存储，以 PURL 为主键。

目录结构：
    facts/
      meta.json            各数据集的 seq / 水位 / 摘要
      state.json           内网已导入的 seq 与摘要（防回滚用）
      <dataset>/<eco>.json 分片，内容为 {purl_key: payload}
      inventory/           内网资产（本地生成，禁止外发）
      outbox/              脱敏回执

零第三方依赖。
"""
import json
import os
import time

from . import purl

EXTERNAL_DATASETS = ("vulns", "health", "license", "kev")
INTERNAL_DATASETS = ("inventory",)
ALL_DATASETS = EXTERNAL_DATASETS + INTERNAL_DATASETS

META_VERSION = 1


def _now_iso(ts=None):
    ts = ts if ts is not None else time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _parse_iso(value):
    if not value:
        return None
    try:
        return time.mktime(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, OverflowError):
        return None


class FactsStore(object):
    def __init__(self, root):
        self.root = root
        self.meta_path = os.path.join(root, "meta.json")
        self.state_path = os.path.join(root, "state.json")
        self.outbox_dir = os.path.join(root, "outbox")
        self._meta = None

    # ------------------------------------------------------------ 基础设施

    def ensure(self):
        os.makedirs(self.root, exist_ok=True)
        os.makedirs(self.outbox_dir, exist_ok=True)
        for name in ALL_DATASETS:
            os.makedirs(os.path.join(self.root, name), exist_ok=True)
        if not os.path.exists(self.meta_path):
            self._meta = {"version": META_VERSION, "datasets": {}}
            self.save_meta()
        return self

    @property
    def meta(self):
        if self._meta is None:
            if os.path.exists(self.meta_path):
                with open(self.meta_path, "r", encoding="utf-8") as handle:
                    self._meta = json.load(handle)
            else:
                self._meta = {"version": META_VERSION, "datasets": {}}
        return self._meta

    def save_meta(self):
        os.makedirs(self.root, exist_ok=True)
        with open(self.meta_path, "w", encoding="utf-8") as handle:
            json.dump(self.meta, handle, ensure_ascii=False, indent=2, sort_keys=True)

    def dataset_meta(self, name):
        return self.meta.setdefault("datasets", {}).setdefault(
            name, {"seq": 0, "generated_at": None, "degraded": False, "shards": []}
        )

    # ------------------------------------------------------------ 分片读写

    def shard_path(self, dataset, eco):
        safe = "".join(ch for ch in (eco or "unknown").lower() if ch.isalnum() or ch in "-_")
        return os.path.join(self.root, dataset, "%s.json" % (safe or "unknown"))

    def read_shard(self, dataset, eco):
        path = self.shard_path(dataset, eco)
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def write_shard(self, dataset, eco, mapping):
        os.makedirs(os.path.join(self.root, dataset), exist_ok=True)
        path = self.shard_path(dataset, eco)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(mapping, handle, ensure_ascii=False, indent=2, sort_keys=True)
        return path

    def shards(self, dataset):
        directory = os.path.join(self.root, dataset)
        if not os.path.isdir(directory):
            return []
        return sorted(name for name in os.listdir(directory) if name.endswith(".json"))

    # ------------------------------------------------------------ 组件读写

    def get(self, dataset, purl_value):
        info = purl.parse(purl_value) or {}
        shard = self.read_shard(dataset, info.get("eco") or "unknown")
        return shard.get(purl.key_of(purl_value) or purl_value)

    def upsert(self, dataset, purl_value, payload):
        info = purl.parse(purl_value) or {}
        eco = info.get("eco") or "unknown"
        shard = self.read_shard(dataset, eco)
        shard[purl.key_of(purl_value) or purl_value] = payload
        self.write_shard(dataset, eco, shard)
        meta = self.dataset_meta(dataset)
        name = os.path.basename(self.shard_path(dataset, eco))
        if name not in meta["shards"]:
            meta["shards"].append(name)

    def bump(self, dataset, generated_at=None, degraded=False):
        """更新数据集水位并推进 seq。"""
        meta = self.dataset_meta(dataset)
        meta["seq"] = int(meta.get("seq", 0)) + 1
        meta["generated_at"] = generated_at or _now_iso()
        meta["degraded"] = bool(degraded)
        return meta

    # ------------------------------------------------------------ 置信度

    def freshness(self, dataset, now=None):
        """返回 (age_days, generated_at)。无水位时返回 (None, None)。"""
        meta = self.dataset_meta(dataset)
        stamp = meta.get("generated_at")
        parsed = _parse_iso(stamp)
        if parsed is None:
            return None, stamp
        now = now if now is not None else time.time()
        return max(0.0, (now - parsed) / 86400.0), stamp

    def confidence(self, dataset, sla_days=14, grace_days=3, now=None):
        age, _ = self.freshness(dataset, now=now)
        if age is None:
            return 0.0
        if age <= grace_days:
            return 1.0
        span = max(1.0, float(sla_days) - float(grace_days))
        value = 1.0 - (age - grace_days) / span
        return max(0.0, min(1.0, value))

    def confidence_report(self, sla_days=14, grace_days=3, now=None):
        result = {}
        for name in self.meta.get("datasets", {}):
            age, stamp = self.freshness(name, now=now)
            result[name] = {
                "age_days": None if age is None else round(age, 2),
                "generated_at": stamp,
                "confidence": self.confidence(name, sla_days, grace_days, now=now),
            }
        return result

    # ------------------------------------------------------------ 组件视图

    def iter_dataset(self, dataset):
        """遍历数据集全部分片，产出 (key, payload)。"""
        directory = os.path.join(self.root, dataset)
        for name in self.shards(dataset):
            with open(os.path.join(directory, name), "r", encoding="utf-8") as handle:
                shard = json.load(handle)
            for key, payload in shard.items():
                yield key, payload

    def component(self, purl_value):
        """合并各数据集，返回组件完整画像。"""
        return {
            "purl": purl_value,
            "gav": (purl.parse(purl_value) or {}).get("gav"),
            "vulns": self.get("vulns", purl_value),
            "health": self.get("health", purl_value),
            "license": self.get("license", purl_value),
            "usage": self.get("inventory", purl_value),
        }
