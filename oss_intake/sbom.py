"""SBOM / 依赖清单摄入：CycloneDX、SPDX、Maven dependency:tree、lock 文件。

产出统一的组件引用列表（以 PURL 为主键），并区分直接依赖与传递依赖。
零第三方依赖。
"""
import json
import os
import re

from . import purl

_MVN_TREE_RE = re.compile(
    r"^(?:[+\\|`\-/\s]*)(?P<coord>[^\s]+:[^\s]+:[^\s]+:[^\s]+(?::[^\s]+)?)$"
)
_REQ_RE = re.compile(r"^(?P<name>[A-Za-z0-9._\-]+)\s*==\s*(?P<ver>[A-Za-z0-9._\-+!]+)")
_GOSUM_RE = re.compile(r"^(?P<mod>[^\s]+)\s+(?P<ver>[^\s]+?)(?:/go\.mod)?\s")


class Component(object):
    """摄入后的组件引用。"""

    def __init__(self, purl_value, eco=None, name=None, version=None,
                 gav=None, direct=True, scope=None):
        self.purl = purl_value
        self.eco = eco
        self.name = name
        self.version = version
        self.gav = gav
        self.direct = direct
        self.scope = scope

    def to_dict(self):
        return {
            "purl": self.purl,
            "eco": self.eco,
            "name": self.name,
            "version": self.version,
            "gav": self.gav,
            "direct": self.direct,
            "scope": self.scope,
        }


def _finish(purl_value, direct=True, scope=None):
    """由 PURL 补全派生字段。"""
    info = purl.parse(purl_value) if purl_value else None
    if not info:
        return None
    return Component(
        purl_value,
        eco=info["eco"],
        name=info["name"],
        version=info["version"],
        gav=info["gav"],
        direct=direct,
        scope=scope,
    )


def _from_parts(eco, name, version, namespace=None, direct=True, scope=None):
    purl_value = purl.build(eco, name, version, namespace)
    if not purl_value:
        return None
    return _finish(purl_value, direct=direct, scope=scope)


# ---------------------------------------------------------------- CycloneDX

def _ingest_cyclonedx(doc):
    components = []
    unresolved = []
    raw = doc.get("components") or []
    meta = doc.get("metadata") or {}
    root_ref = None
    meta_comp = meta.get("component")
    if isinstance(meta_comp, dict):
        root_ref = meta_comp.get("bom-ref") or meta_comp.get("bomRef")

    direct_refs = set()
    deps = doc.get("dependencies") or []
    if deps:
        if root_ref:
            for entry in deps:
                if entry.get("ref") == root_ref:
                    direct_refs = set(entry.get("dependsOn") or [])
        else:
            # 无根引用时，取第一条依赖条目的 dependsOn 作为直接依赖
            direct_refs = set((deps[0] or {}).get("dependsOn") or [])
        referenced = set()
        for entry in deps:
            if root_ref and entry.get("ref") == root_ref:
                continue
            referenced.update(entry.get("dependsOn") or [])
        # 被其他组件引用的条目视为传递依赖
        for entry in deps:
            if entry.get("ref") in referenced:
                direct_refs.discard(entry.get("ref"))

    for item in raw:
        if not isinstance(item, dict):
            continue
        ref = item.get("bom-ref") or item.get("bomRef")
        purl_value = item.get("purl")
        scope = item.get("scope")
        direct = (ref in direct_refs) if direct_refs else True
        comp = None
        if purl_value:
            comp = _finish(purl_value, direct=direct, scope=scope)
        else:
            etype = (item.get("type") or "").lower()
            name = item.get("name")
            version = item.get("version")
            group = item.get("group")
            if name and version:
                comp = _from_parts(purl.normalize_eco(etype) or "maven", name,
                                   version, group, direct=direct, scope=scope)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": item.get("name") or ref,
                               "reason": "缺少 purl 或 name/version"})
    return components, unresolved


# -------------------------------------------------------------------- SPDX

def _ingest_spdx(doc):
    components = []
    unresolved = []
    packages = doc.get("packages") or []
    relationships = doc.get("relationships") or []

    purl_by_id = {}
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        spdx_id = pkg.get("SPDXID")
        found = None
        for ref in pkg.get("externalRefs") or []:
            if (ref.get("referenceType") or "").lower() == "purl":
                found = ref.get("referenceLocator")
        if found:
            purl_by_id[spdx_id] = found

    direct_ids = set()
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        rtype = (rel.get("relationshipType") or "").upper()
        if rtype in ("DESCRIBES", "DESCRIBED_BY"):
            for side in ("relatedSpdxElement", "spdxElementId"):
                value = rel.get(side)
                if value and value != "SPDXRef-DOCUMENT":
                    direct_ids.add(value)
    dependent_ids = set()
    for rel in relationships:
        if (rel.get("relationshipType") or "").upper() == "DEPENDS_ON":
            dependent_ids.add(rel.get("relatedSpdxElement"))

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        spdx_id = pkg.get("SPDXID")
        purl_value = purl_by_id.get(spdx_id)
        direct = spdx_id in direct_ids or spdx_id not in dependent_ids
        comp = None
        if purl_value:
            comp = _finish(purl_value, direct=direct)
        else:
            name = pkg.get("name")
            version = pkg.get("versionInfo")
            if name and version:
                comp = _from_parts("maven", name, version, direct=direct)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": pkg.get("name") or spdx_id,
                               "reason": "缺少 purl 外部引用或 name/versionInfo"})
    return components, unresolved


# --------------------------------------------------------------- 文本清单

def _ingest_maven_tree(text):
    components = []
    unresolved = []
    parsed = []
    for line in text.splitlines():
        # 去掉 Maven 输出的 [INFO] 等前缀
        cleaned = line.strip()
        while cleaned.startswith("[") and "]" in cleaned:
            cleaned = cleaned[cleaned.index("]") + 1:].strip()
        if not cleaned:
            continue
        match = _MVN_TREE_RE.match(cleaned)
        if not match:
            continue
        coord = match.group("coord")
        parts = coord.split(":")
        if len(parts) < 4:
            unresolved.append({"name": coord, "reason": "坐标字段不足 4 段"})
            continue
        group, artifact, _, version = parts[0], parts[1], parts[2], parts[3]
        scope = parts[4] if len(parts) > 4 else None
        parsed.append({"indent": match.start("coord"), "group": group, "artifact": artifact,
                       "version": version, "scope": scope, "coord": coord})

    levels = sorted({item["indent"] for item in parsed})
    if len(levels) <= 1:
        root_indent, direct_indent = None, levels[0] if levels else 0
    else:
        root_indent, direct_indent = levels[0], levels[1]

    for item in parsed:
        if root_indent is not None and item["indent"] == root_indent:
            continue  # 根模块自身，不作为依赖
        comp = _from_parts("maven", item["artifact"], item["version"], item["group"],
                           direct=(item["indent"] == direct_indent), scope=item["scope"])
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": item["coord"], "reason": "无法构造 PURL"})
    return components, unresolved


def _ingest_npm_lock(doc):
    components = []
    unresolved = []
    packages = doc.get("packages") or {}
    deps = doc.get("dependencies") or {}
    root_deps = set(((doc.get("packages") or {}).get("") or {}).get("dependencies", {}).keys())
    for path, meta in packages.items():
        if not path:
            continue
        if not isinstance(meta, dict):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        version = meta.get("version")
        if not version and name in deps:
            version = deps[name].get("version")
        if not name or not version:
            unresolved.append({"name": path, "reason": "缺少 name 或 version"})
            continue
        direct = (name in root_deps) or path.count("node_modules/") == 1
        namespace = None
        if name.startswith("@") and "/" in name:
            namespace, name_body = name[1:].split("/", 1)
            name = name_body
        comp = _from_parts("npm", name, version, namespace, direct=direct)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": path, "reason": "无法构造 PURL"})
    return components, unresolved


def _ingest_requirements(text):
    components = []
    unresolved = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _REQ_RE.match(line)
        if not match:
            unresolved.append({"name": line, "reason": "非 name==version 形式"})
            continue
        comp = _from_parts("pypi", match.group("name"), match.group("ver"))
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": line, "reason": "无法构造 PURL"})
    return components, unresolved


def _ingest_gosum(text):
    components = []
    unresolved = []
    seen = set()
    for line in text.splitlines():
        match = _GOSUM_RE.match(line.strip())
        if not match:
            continue
        module = match.group("mod")
        version = match.group("ver")
        if module in seen:
            continue
        seen.add(module)
        namespace = module.rsplit("/", 1)[0] if "/" in module else None
        name = module.rsplit("/", 1)[1] if "/" in module else module
        comp = _from_parts("go", name, version, namespace)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": module, "reason": "无法构造 PURL"})
    return components, unresolved


def _detect_format(text, path):
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX":
            return "cyclonedx", doc
        if doc.get("spdxVersion"):
            return "spdx", doc
        if "packages" in doc and "lockfileVersion" in doc:
            return "npm-lock", doc
        if "packages" in doc and doc.get("SPDXID") is None and "dependencies" in doc:
            return "npm-lock", doc
    ext = os.path.splitext(path)[1].lower()
    if ext == ".txt" or "maven-dependency-plugin" in text or "+- " in text or "\\- " in text:
        if ":" in text and text.count(":") >= 3:
            return "maven-tree", text
    if ext in (".txt", ".pip", ".req") or "==" in text:
        return "requirements", text
    if ext == ".sum" or ext == ".mod":
        return "gosum", text
    return "maven-tree", text


def ingest(path):
    """摄入一个 SBOM / 依赖清单文件。"""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    fmt, payload = _detect_format(text, path)
    if fmt == "cyclonedx":
        components, unresolved = _ingest_cyclonedx(payload)
    elif fmt == "spdx":
        components, unresolved = _ingest_spdx(payload)
    elif fmt == "npm-lock":
        components, unresolved = _ingest_npm_lock(payload)
    elif fmt == "requirements":
        components, unresolved = _ingest_requirements(payload)
    elif fmt == "gosum":
        components, unresolved = _ingest_gosum(payload)
    else:
        components, unresolved = _ingest_maven_tree(payload)
    return {
        "source": os.path.basename(path),
        "format": fmt,
        "components": [c.to_dict() for c in components],
        "unresolved": unresolved,
    }


def dedupe(components):
    """按 PURL 去重，直接依赖优先保留。"""
    merged = {}
    for comp in components:
        key = purl.key_of(comp["purl"]) or comp["purl"]
        existing = merged.get(key)
        if not existing or (comp["direct"] and not existing["direct"]):
            merged[key] = comp
    return list(merged.values())
