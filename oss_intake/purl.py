"""PURL 归一化：把各生态坐标（GAV / npm / go module 等）统一为 pkg: 形式。

零第三方依赖，可在纯内网环境运行。
"""
import urllib.parse

ECO_TO_TYPE = {
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "pip": "pypi",
    "go": "golang",
    "golang": "golang",
    "cargo": "cargo",
    "crates.io": "cargo",
    "gem": "gem",
    "rubygems": "gem",
    "composer": "composer",
    "packagist": "composer",
    "nuget": "nuget",
}

# 生态别名 → 规范生态名（业务侧统一用 go / pypi / cargo 等")
ECO_CANONICAL = {
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "pip": "pypi",
    "go": "go",
    "golang": "go",
    "cargo": "cargo",
    "crates.io": "cargo",
    "gem": "gem",
    "rubygems": "gem",
    "composer": "composer",
    "packagist": "composer",
    "nuget": "nuget",
}

TYPE_TO_ECO = {
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "golang": "go",
    "cargo": "cargo",
    "gem": "gem",
    "composer": "composer",
    "nuget": "nuget",
}

# PURL 分段中允许保留的字符；斜杠保留以支持 go module 路径与 maven groupId。
_SAFE = ".-_~:/@!$&'()*+,;="


def _quote(value):
    return urllib.parse.quote(value or "", safe=_SAFE)


def _unquote(value):
    return urllib.parse.unquote(value or "")


def normalize_eco(eco):
    """把生态别名映射为规范生态名（go / pypi / cargo …）。

    PURL 分段类型（golang / crates.io 等）由 ECO_TO_TYPE 另行处理。
    """
    key = (eco or "").strip().lower()
    return ECO_CANONICAL.get(key, key)


def build(eco, name, version=None, namespace=None):
    """构造 PURL。namespace 为空时省略该段。"""
    ptype = ECO_TO_TYPE.get(normalize_eco(eco), normalize_eco(eco))
    if not name:
        return None
    if namespace:
        path = "%s/%s" % (_quote(namespace), _quote(name))
    else:
        path = _quote(name)
    purl = "pkg:%s/%s" % (ptype, path)
    if version:
        purl += "@%s" % _quote(version)
    return purl


def from_gav(gav):
    """Maven 坐标 groupId:artifactId[:version] → PURL。"""
    if not gav or gav.count(":") < 1:
        return None
    parts = gav.split(":")
    group = parts[0]
    artifact = parts[1]
    version = parts[2] if len(parts) > 2 and parts[2] else None
    return build("maven", artifact, version, group)


def parse(purl):
    """解析 PURL，返回含 eco / gav 投影的字典；无法解析返回 None。"""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    if "@" in body:
        path, _, version = body.partition("@")
        version = _unquote(version)
    else:
        path, version = body, None
    segments = [s for s in path.split("/") if s != ""]
    if not segments:
        return None
    ptype = _unquote(segments[0])
    rest = [_unquote(s) for s in segments[1:]]
    if len(rest) >= 2:
        namespace = "/".join(rest[:-1])
        name = rest[-1]
    elif len(rest) == 1:
        namespace, name = None, rest[0]
    else:
        namespace, name = None, None
    eco = TYPE_TO_ECO.get(ptype, ptype)
    gav = None
    if eco == "maven" and namespace:
        gav = "%s:%s%s" % (namespace, name, (":" + version) if version else "")
    return {
        "purl": purl,
        "type": ptype,
        "eco": eco,
        "namespace": namespace,
        "name": name,
        "version": version,
        "gav": gav,
    }


def key_of(purl):
    """用于事实层存储的稳定键。"""
    info = parse(purl)
    if not info:
        return None
    ns = (info["namespace"] or "").lower()
    return "%s/%s/%s@%s" % (info["type"], ns, (info["name"] or "").lower(), info["version"] or "")


def display_of(purl):
    """人类可读展示名，Maven 优先展示 GAV。"""
    info = parse(purl)
    if not info:
        return purl
    if info["gav"]:
        return info["gav"]
    name = info["name"] or ""
    if info["namespace"]:
        name = "%s/%s" % (info["namespace"], name)
    if info["version"]:
        name = "%s@%s" % (name, info["version"])
    return name
