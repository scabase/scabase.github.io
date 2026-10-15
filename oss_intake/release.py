"""GitHub Packages 发布包构建：把漏洞与健康度结果打包成可发布的产物。

统一的 staging 目录结构（npm / maven / docker 三通道共用同一份内容）：

    <out>/
      manifest.json
      data/
        vulns.json                  漏洞结果（OSV + NVD 富化，CVE 聚合）
        health.json                 组件活跃度原始信号
        community-support.json      社区支持力度汇总（A/B/C/D 等级）
        facts/meta.json             事实层水位（可选）
        facts/<dataset>/<eco>.json  事实层分片快照（可选）

清单要点：

* 每个文件记录 sha256 / size / 条目数，消费端落地后可逐文件校验；
* ``content_digest`` 是剥离版本号与时间戳后的内容指纹，CI 用它判断
  「本轮内容是否与上次发布一致」，避免每天把同一份数据重推一遍；
* 签名复用 ``oss_intake.sync.Signer``（ed25519 优先，回落 HMAC-SHA256），
  未配置密钥时 manifest 不出现 ``signature`` 字段，消费端按无签名处理。

零第三方依赖，内网也可直接构造。
"""
import hashlib
import json
import os
import shutil
import time

from . import sync

RELEASE_SCHEMA = "scabase-release/v1"

# 逻辑数据集 →（包内文件名，统计方式）
DATA_KINDS = {
    "vulns": ("vulns.json", "vulns"),
    "health": ("health.json", "health"),
    "community": ("community-support.json", "community"),
}

FACTS_DATASETS = ("vulns", "health", "license", "kev")


class ReleaseError(Exception):
    pass


def _now_iso(now=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(now if now is not None else time.time()))


def version_stamp(now=None):
    """CalVer 版本号：`YYYYMMDD.HHMM00.0`。

    同时满足 semver（npm）与 Maven 版本约束，按发布时间单调递增。
    """
    return time.strftime("%Y%m%d.%H%M00.0",
                         time.gmtime(now if now is not None else time.time()))


def sha256_bytes(data):
    digest = hashlib.sha256()
    digest.update(data if isinstance(data, bytes) else data.encode("utf-8"))
    return digest.hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _cve_ids(records):
    found = set()
    for record in records or []:
        if not isinstance(record, dict):
            continue
        candidates = [record.get("id")] + list(record.get("aliases") or [])
        for value in candidates:
            if isinstance(value, str) and value.upper().startswith("CVE-"):
                found.add(value)
    return found


def _canonical(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _summarize(kind, payload):
    """按文件类型统计写入清单的摘要元数据（条目数、CVE 数、等级分布等）。"""
    if kind == "vulns":
        vuln_count = 0
        cves = set()
        for record in payload.values():
            raw = (record or {}).get("osv_raw") or {}
            batch = raw.get("vulns") or []
            vuln_count += len(batch)
            cves |= _cve_ids(batch)
            for item in (record or {}).get("enriched") or []:
                osv = (item or {}).get("osv") or {}
                cves |= _cve_ids(osv.get("vulns") or [])
        return {"entries": len(payload), "vuln_count": vuln_count,
                "cve_count": len(cves)}
    if kind == "health":
        usable = sum(1 for item in (payload or {}).values()
                     if isinstance(item, dict) and not item.get("health_unknown"))
        return {"entries": len(payload), "usable_entries": usable}
    if kind == "community":
        summary = {
            "entries": len(payload.get("components") or []),
            "generated_at": payload.get("generated_at"),
            "component_count": payload.get("component_count"),
        }
        if payload.get("grade_counts"):
            summary["grade_counts"] = payload["grade_counts"]
        return summary
    return {"entries": None}


def source_from_env(environ=None):
    """从 GitHub Actions（或本机 git 无关）环境变量提取发布来源信息。"""
    env = environ if environ is not None else os.environ
    source = {}
    repo = env.get("SCABASE_SOURCE_REPO") or env.get("GITHUB_REPOSITORY")
    commit = env.get("SCABASE_SOURCE_COMMIT") or env.get("GITHUB_SHA")
    server = env.get("GITHUB_SERVER_URL") or "https://github.com"
    run_id = env.get("GITHUB_RUN_ID")
    if repo:
        source["repo"] = repo
    if commit:
        source["commit"] = commit
    if repo and run_id:
        source["run_url"] = "%s/%s/actions/runs/%s" % (server, repo, run_id)
    source["builder"] = env.get("SCABASE_BUILDER", "oss-intake/release")
    return source


def _copy(src, rel, root, entries):
    target = os.path.join(root, rel)
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    shutil.copyfile(src, target)
    entry = {
        "path": "data/%s" % rel,
        "sha256": _sha256_file(target),
        "size": os.path.getsize(target),
    }
    entries.append(entry)
    return entry


def build_release(out, vulns=None, health=None, community=None, facts=None,
                  datasets=None, version=None, key=None, now=None, source=None):
    """构建 staging 目录并返回 manifest。

    sources 里任何一个文件缺失都只降级（不进入 packages），
    只有当 vulns 与 community 都不存在时才视为空包报错。
    """
    out = os.path.abspath(out)
    if os.path.exists(out):
        shutil.rmtree(out)
    data_root = os.path.join(out, "data")
    os.makedirs(data_root)

    entries = []
    datasets_meta = {}
    sources = (("vulns", vulns), ("health", health), ("community", community))
    for name, path in sources:
        if not path or not os.path.exists(path):
            continue
        rel, kind = DATA_KINDS[name]
        payload = _read_json(path)
        entry = _copy(path, rel, data_root, entries)
        meta = _summarize(kind, payload)
        meta.update(entry)
        datasets_meta[name] = meta

    if not datasets_meta:
        raise ReleaseError("没有任何可用数据：请至少提供 vulns.json 或 community-support.json")

    facts_meta = {}
    if facts and os.path.isdir(facts):
        wanted = tuple(datasets or FACTS_DATASETS)
        for name in wanted:
            directory = os.path.join(facts, name)
            if not os.path.isdir(directory):
                continue
            copied = 0
            for shard in sorted(os.listdir(directory)):
                src = os.path.join(directory, shard)
                if not os.path.isfile(src):
                    continue
                _copy(src, "facts/%s/%s" % (name, shard), data_root, entries)
                copied += 1
            if copied:
                facts_meta[name] = {"shards": copied}
        meta_path = os.path.join(facts, "meta.json")
        if os.path.exists(meta_path):
            entry = _copy(meta_path, "facts/meta.json", data_root, entries)
            facts_meta["_meta"] = entry

    entries.sort(key=lambda item: item["path"])
    content_digest = sha256_bytes(json.dumps(
        [{"path": item["path"], "sha256": item["sha256"]} for item in entries],
        ensure_ascii=False, sort_keys=True, separators=(",", ":")))

    manifest = {
        "schema": RELEASE_SCHEMA,
        "version": version or version_stamp(now),
        "generated_at": _now_iso(now),
        "source": source if source is not None else source_from_env(),
        "content_digest": content_digest,
        "file_count": len(entries),
        "total_size": sum(item["size"] for item in entries),
        "files": entries,
        "datasets": datasets_meta,
        "facts": facts_meta,
    }

    if key:
        signer = sync.Signer(key)
        signed = dict(manifest)
        signed["signature"] = {
            "algo": signer.algo,
            "keyid": signer.keyid,
            "value": signer.sign(_canonical(manifest)),
        }
    else:
        signed = manifest

    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(signed, handle, ensure_ascii=False, indent=2, sort_keys=True)

    return {
        "out": out,
        "manifest": signed,
        "version": manifest["version"],
        "content_digest": content_digest,
        "files": entries,
        "total_size": manifest["total_size"],
    }


def load_manifest(root):
    path = os.path.join(root, "manifest.json")
    if not os.path.exists(path):
        raise ReleaseError("发布包缺少 manifest.json：%s" % root)
    return _read_json(path)


def verify(root):
    """逐文件校验发布包完整性：缺失 / 哈希不一致都会被列出。"""
    manifest = load_manifest(root)
    failures = []
    files = manifest.get("files") or []
    for entry in files:
        target = os.path.join(root, entry.get("path") or "")
        if not os.path.exists(target):
            failures.append({"path": entry.get("path"), "reason": "missing"})
            continue
        if entry.get("sha256") and _sha256_file(target) != entry["sha256"]:
            failures.append({"path": entry.get("path"), "reason": "sha256-mismatch"})
    return {
        "ok": not failures,
        "checked": len(files),
        "failures": failures,
        "version": manifest.get("version"),
        "content_digest": manifest.get("content_digest"),
        "datasets": sorted(manifest.get("datasets") or {}),
        "root": root,
    }
