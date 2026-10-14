"""内网应用群组资产：group → app → component 的关联与影响半径计算。

资产数据在内网本地生成，禁止出现在外发数据包中。
零第三方依赖。
"""
import json
import os

from . import purl
from . import sbom

TIER_RANK = {"normal": 0, "important": 1, "core": 2}
EXPOSURE_RANK = {"offline": 0, "internal": 1, "internet": 2}
SENSITIVITY_RANK = {"low": 0, "mid": 1, "high": 2}


def load_assets(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _max_by(existing, candidate, ranks):
    if not candidate:
        return existing
    if not existing:
        return candidate
    return candidate if ranks.get(candidate, -1) > ranks.get(existing, -1) else existing


def build_inventory(store, assets, base_dir="."):
    """把资产清单中的 SBOM 摄入结果写入事实层 inventory 数据集。

    返回应用级摘要，便于报告展示。
    """
    summary = []
    collected = {}

    for group in assets.get("groups") or []:
        group_name = group.get("name")
        for app in group.get("apps") or []:
            app_name = app.get("name")
            sbom_path = app.get("sbom")
            entry = {
                "group": group_name,
                "app": app_name,
                "tier": app.get("tier", "normal"),
                "exposure": app.get("exposure", "internal"),
                "data_sensitivity": app.get("data_sensitivity", "low"),
                "components": 0,
                "unresolved": [],
            }
            items = []
            if sbom_path:
                full = sbom_path if os.path.isabs(sbom_path) else os.path.join(base_dir, sbom_path)
                if os.path.exists(full):
                    result = sbom.ingest(full)
                    components = sbom.dedupe(result["components"])
                    entry["components"] = len(components)
                    entry["unresolved"] = result["unresolved"]
                    for comp in components:
                        items.append((comp["purl"], comp.get("gav"), bool(comp["direct"])))

            # depinfo 台账形态：直接给出 GAV / PURL 列表，无 SBOM 文件
            for raw in app.get("gavs") or []:
                purl_value = purl.from_gav(raw)
                if purl_value:
                    items.append((purl_value, raw, True))
            for raw in app.get("purls") or []:
                items.append((raw, (purl.parse(raw) or {}).get("gav"), True))

            entry["components"] = len(items)
            for purl_value, gav, direct in items:
                key = purl.key_of(purl_value) or purl_value
                record = collected.setdefault(key, {
                    "purl": purl_value,
                    "gav": gav,
                    "groups": [],
                    "apps": [],
                    "tier": app.get("tier", "normal"),
                    "exposure": app.get("exposure", "internal"),
                    "data_sensitivity": app.get("data_sensitivity", "low"),
                    "direct": bool(direct),
                })
                if group_name and group_name not in record["groups"]:
                    record["groups"].append(group_name)
                if app_name and app_name not in record["apps"]:
                    record["apps"].append(app_name)
                record["tier"] = _max_by(record["tier"], app.get("tier"), TIER_RANK)
                record["exposure"] = _max_by(
                    record["exposure"], app.get("exposure"), EXPOSURE_RANK)
                record["data_sensitivity"] = _max_by(
                    record["data_sensitivity"], app.get("data_sensitivity"), SENSITIVITY_RANK)
                if direct:
                    record["direct"] = True
            summary.append(entry)

    for record in collected.values():
        record["blast_radius"] = len(record["apps"])
        store.upsert("inventory", record["purl"], record)
    store.bump("inventory")
    store.save_meta()
    return summary


def usage_of(store, purl_value):
    """读取组件的应用资产关联。"""
    return store.get("inventory", purl_value)
