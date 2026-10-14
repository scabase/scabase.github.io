"""DEPINFO 系统对接：依赖台账导入与评估结论回传。

DEPINFO 是行内开源组件依赖台账系统。本模块负责两侧互通：

- **导入侧**：读取 DEPINFO 导出的组件台账，自动转换为评估侧资产模型。
  组件描述支持三种形态（任一即可）：
      {"purl": "pkg:maven/com.alibaba/fastjson@1.2.24"}
      {"gav":  "com.alibaba:fastjson:1.2.24"}
      {"eco": "maven", "group": "com.alibaba", "artifact": "fastjson", "version": "1.2.24"}
- **回传侧**：把评估与巡检结论回传 DEPINFO，形成流程联动。
  回传默认脱敏：只含组件维度结论，不含应用名、群组名等内网拓扑信息。

零第三方依赖（HTTP 走 urllib；未配置端点时自动降级为文件交换）。
"""
import json
import os
import time
import urllib.request

from .. import purl as purl_mod

SCHEMA = "depinfo-result/v1"
DEFAULTS = {"tier": "normal", "exposure": "internal", "data_sensitivity": "low"}


def load_export(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_component(entry):
    """把台账中的一条组件记录转成 PURL。"""
    if not isinstance(entry, dict):
        return None
    if entry.get("purl"):
        return entry["purl"]
    if entry.get("gav"):
        return purl_mod.from_gav(entry["gav"])
    name = entry.get("artifact") or entry.get("name")
    version = entry.get("version")
    if not name or not version:
        return None
    eco = entry.get("eco") or "maven"
    namespace = entry.get("group") or entry.get("namespace")
    if eco == "maven" and name.startswith("pkg:"):
        return name
    return purl_mod.build(eco, name, version, namespace)


def assets_from_depinfo(export, defaults=None):
    """把 DEPINFO 台账转成评估侧资产模型（群组 → 应用 → 组件 PURL/GAV 列表）。"""
    defaults = dict(DEFAULTS, **(defaults or {}))
    groups = {}
    for app in export.get("apps") or []:
        app_name = app.get("app_name") or app.get("name") or app.get("app_id")
        group_name = app.get("group") or app.get("group_name") or "默认群组"
        purls = []
        gavs = []
        for entry in app.get("components") or []:
            purl_value = normalize_component(entry)
            if not purl_value:
                continue
            purls.append(purl_value)
            info = purl_mod.parse(purl_value) or {}
            if info.get("gav"):
                gavs.append(info["gav"])
        for raw in app.get("gavs") or []:
            purl_value = purl_mod.from_gav(raw)
            if purl_value and purl_value not in purls:
                purls.append(purl_value)
                gavs.append(raw)
        for raw in app.get("purls") or []:
            if raw not in purls:
                purls.append(raw)
        entry = {
            "name": app_name,
            "tier": app.get("tier") or defaults["tier"],
            "exposure": app.get("exposure") or defaults["exposure"],
            "data_sensitivity": app.get("data_sensitivity") or defaults["data_sensitivity"],
            "purls": purls,
            "gavs": gavs,
            "app_id": app.get("app_id"),
            "owner": app.get("owner"),
        }
        groups.setdefault(group_name, {"name": group_name, "apps": []})["apps"].append(entry)
    return {"groups": [groups[name] for name in sorted(groups)]}


def result_payload(results, mask=True, sync_token=None, source="scabase-oss-intake"):
    """把评估/巡检结论转成 DEPINFO 回传结构。"""
    items = []
    for result in results or []:
        purl_value = result.get("purl")
        info = purl_mod.parse(purl_value) or {}
        item = {
            "gav": info.get("gav"),
            "purl": purl_value,
            "conclusion": result.get("conclusion"),
            "score": result.get("score"),
            "suggested_version": result.get("suggested_version"),
            "review_due": result.get("review_due"),
            "cves": [c.get("id") if isinstance(c, dict) else c
                     for c in (result.get("cves") or [])],
            "hard_blocks": result.get("hard_blocks") or [],
        }
        if not mask:
            item["apps"] = result.get("apps") or []
            item["groups"] = result.get("groups") or []
        items.append(item)
    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": source,
        "sync_token": sync_token or _token(),
        "masked": bool(mask),
        "items": items,
    }


def _token():
    return "depinfo-%d" % int(time.time())


def write_payload(payload, path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    return path


class DepinfoClient(object):
    """DEPINFO HTTP 客户端；未配置 base_url 时整体禁用（离线内网场景）。"""

    def __init__(self, base_url=None, token=None, timeout=15):
        self.base_url = (base_url or os.getenv("SCABASE_DEPINFO_URL") or "").rstrip("/")
        self.token = token or os.getenv("SCABASE_DEPINFO_TOKEN") or ""
        self.timeout = timeout

    def enabled(self):
        return bool(self.base_url)

    def _request(self, path, payload=None, method="POST"):
        if not self.enabled():
            raise RuntimeError("DEPINFO 未配置，请在离线模式下使用文件交换")
        data = json.dumps(payload or {}).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer %s" % self.token
        request = urllib.request.Request(self.base_url + path, data=data,
                                         headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def pull(self):
        """拉取 DEPINFO 组件台账。"""
        return self._request("/api/v1/components", method="GET")

    def push(self, payload):
        """回传评估结论。"""
        return self._request("/api/v1/oss-assessments", payload)


def sync_from_export(path, defaults=None):
    """便捷入口：读取 DEPINFO 导出文件 → 资产模型。"""
    return assets_from_depinfo(load_export(path), defaults=defaults)
