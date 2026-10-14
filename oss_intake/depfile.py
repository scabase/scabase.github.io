"""原生依赖文件解析：Maven / Gradle / npm / Yarn / pnpm / PyPI / Go / Cargo / Composer / RubyGems。

与 `sbom.py` 的分工：
- `sbom.py` 面向**已生成的物料清单**（CycloneDX / SPDX / lock 产物）；
- `depfile.py` 面向**开发态依赖声明文件**（pom.xml、package.json、requirements.txt …），
  直接支撑「引入阶段依赖关系自动化分析」，无需先产出 SBOM。

统一输出以 PURL 为主键的组件引用，并保留 `version_req`（原始版本约束）
与 `pinned`（是否已锁定具体版本）两个字段，供风险模型判定版本可复现性。

零第三方依赖，可在纯内网运行。
"""
import json
import os
import re
import xml.etree.ElementTree as ET

from . import purl
from . import sbom

# ------------------------------------------------------------------ 文件识别

NAME_MAP = {
    "pom.xml": ("maven", "pom"),
    "build.gradle": ("maven", "gradle"),
    "build.gradle.kts": ("maven", "gradle"),
    "gradle.lockfile": ("maven", "gradle-lock"),
    "package.json": ("npm", "package-json"),
    "package-lock.json": ("npm", "npm-lock"),
    "npm-shrinkwrap.json": ("npm", "npm-lock"),
    "yarn.lock": ("npm", "yarn-lock"),
    "pnpm-lock.yaml": ("npm", "pnpm-lock"),
    "requirements.txt": ("pypi", "requirements"),
    "pipfile.lock": ("pypi", "pipfile-lock"),
    "poetry.lock": ("pypi", "poetry-lock"),
    "pyproject.toml": ("pypi", "pyproject"),
    "go.mod": ("go", "go-mod"),
    "go.sum": ("go", "go-sum"),
    "cargo.lock": ("cargo", "cargo-lock"),
    "cargo.toml": ("cargo", "cargo-toml"),
    "composer.json": ("composer", "composer-json"),
    "composer.lock": ("composer", "composer-lock"),
    "gemfile.lock": ("gem", "gemfile-lock"),
}

SKIP_DIRS = {
    ".git", "node_modules", "target", "build", "dist", "vendor", ".venv", "venv",
    "__pycache__", ".gradle", ".idea", ".vscode", "out", "bin", ".next", "coverage",
}

ECO_BY_FORMAT = {
    "pom": "maven", "gradle": "maven", "gradle-lock": "maven",
    "package-json": "npm", "npm-lock": "npm", "yarn-lock": "npm", "pnpm-lock": "npm",
    "requirements": "pypi", "pipfile-lock": "pypi", "poetry-lock": "pypi",
    "pyproject": "pypi",
    "go-mod": "go", "go-sum": "go",
    "cargo-lock": "cargo", "cargo-toml": "cargo",
    "composer-json": "composer", "composer-lock": "composer",
    "gemfile-lock": "gem",
}


def classify(filename):
    """按文件名判定 (eco, format)；无法识别返回 None。"""
    name = os.path.basename(filename).lower()
    if name in NAME_MAP:
        return NAME_MAP[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return ("pypi", "requirements")
    if name.endswith(".gradle") or name.endswith(".gradle.kts"):
        return ("maven", "gradle")
    return None


def discover(root, max_depth=6):
    """递归发现目录中的依赖声明文件。"""
    found = []
    root = os.path.abspath(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        if dirpath.count(os.sep) - base_depth > max_depth:
            dirnames[:] = []
            continue
        for name in filenames:
            if classify(name):
                found.append(os.path.join(dirpath, name))
    return sorted(found)


# ------------------------------------------------------------------ 版本约束

def _version_from_req(req):
    """把版本约束拆成 (具体版本, 是否已锁定)。无法推出具体版本时返回 (None, pinned)。"""
    req = (req or "").strip().strip("\"'").strip()
    if not req:
        return None, False
    pinned = bool(re.match(r"^(==|v)?\d[\w.\-+]*$", req))
    token = req.split(",")[0].strip()
    token = re.sub(r"^[\^~=><!v\s]*", "", token).strip()
    token = token.split()[0] if token.split() else ""
    token = token.rstrip(".*")
    if not token or not re.match(r"^\d", token):
        return None, pinned
    return token, pinned


def _is_range(version):
    if not version:
        return False
    return any(ch in version for ch in "()[],") or version.endswith("+")


def _split_pypi(line):
    """解析一行 PEP 508 依赖声明，返回 (name, req, version, pinned) 或 None。"""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    line = line.split(" #")[0].split(" ;")[0].split(";")[0].strip().strip(",")
    if not line:
        return None
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", line)
    if not match:
        return None
    name, req = match.group(1), (match.group(2) or "").strip()
    version, pinned = _version_from_req(req)
    return name, req, version, pinned


def _npm_parts(name):
    """npm 包名拆成 (namespace, name)。"""
    if name.startswith("@") and "/" in name:
        namespace, body = name[1:].split("/", 1)
        return namespace, body
    return None, name


def _ns_parts(eco, name):
    """通用 vendor/name 拆分（composer、go module 等）。"""
    if "/" in name:
        namespace, body = name.rsplit("/", 1)
        return namespace, body
    return None, name


def _make(eco, name, version, direct=True, scope=None, version_req=None, pinned=True):
    """按生态构造组件引用，自动处理命名空间。"""
    namespace = None
    if eco in ("npm",):
        namespace, name = _npm_parts(name)
    elif eco in ("maven",):
        namespace = None
        if ":" in name:
            namespace, name = name.split(":", 1)
    elif eco in ("composer", "go", "cargo"):
        namespace, name = _ns_parts(eco, name)
    comp = sbom.build_component(eco, name, version, namespace, direct=direct,
                                scope=scope, version_req=version_req, pinned=pinned)
    return comp


# ------------------------------------------------------------------ Maven

def _local(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _text(element):
    return (element.text or "").strip()


def _resolve(value, props):
    """展开 ${property} 占位符。"""
    if not value or "${" not in value:
        return value

    def repl(match):
        key = match.group(1)
        for candidate in (key, "project." + key, "pom." + key, "parent." + key):
            if props.get(candidate):
                return props[candidate]
        return match.group(0)

    out = value
    for _ in range(4):
        nxt = re.sub(r"\$\{([^}]+)\}", repl, out)
        if nxt == out:
            break
        out = nxt
    return out


def _pom_props(root):
    props = {}
    for element in root.iter():
        if _local(element.tag) == "properties":
            for child in element:
                if _text(child):
                    props[_local(child.tag)] = _text(child)
    for child in root:
        tag = _local(child.tag)
        if tag in ("groupId", "artifactId", "version") and _text(child):
            props.setdefault("project." + tag, _text(child))
            props.setdefault("pom." + tag, _text(child))
        if tag == "parent":
            for item in child:
                props.setdefault("parent." + _local(item.tag), _text(item))
    return props


def _parents(root):
    mapping = {}
    for parent in root.iter():
        for child in parent:
            mapping[child] = parent
    return mapping


def _is_managed(element, parents):
    node = parents.get(element)
    while node is not None:
        if _local(node.tag) == "dependencyManagement":
            return True
        node = parents.get(node)
    return False


def _dep_fields(element, props):
    group = artifact = version = scope = None
    optional = False
    for child in element:
        tag = _local(child.tag)
        value = _text(child)
        if tag == "groupId":
            group = value
        elif tag == "artifactId":
            artifact = value
        elif tag == "version":
            version = value
        elif tag == "scope":
            scope = value
        elif tag == "optional":
            optional = value.lower() == "true"
    return (_resolve(group, props), artifact, _resolve(version, props), scope, optional)


def _parse_pom(text):
    root = ET.fromstring(text)
    props = _pom_props(root)
    parents = _parents(root)

    managed = {}
    for element in root.iter():
        if _local(element.tag) != "dependency" or not _is_managed(element, parents):
            continue
        group, artifact, version, _scope, _opt = _dep_fields(element, props)
        if group and artifact and version:
            managed["%s:%s" % (group, artifact)] = version

    components = []
    unresolved = []
    for element in root.iter():
        if _local(element.tag) != "dependency" or _is_managed(element, parents):
            continue
        group, artifact, version, scope, optional = _dep_fields(element, props)
        if not artifact:
            unresolved.append({"name": "unknown", "reason": "dependency 缺少 artifactId"})
            continue
        if not version:
            version = managed.get("%s:%s" % (group, artifact))
        if not version:
            unresolved.append({"name": "%s:%s" % (group, artifact),
                               "reason": "版本未声明且 dependencyManagement 未提供"})
            continue
        comp = _make("maven", "%s:%s" % (group or "", artifact), version,
                     direct=True, scope=scope or "compile",
                     version_req=version, pinned=not _is_range(version))
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": "%s:%s:%s" % (group, artifact, version),
                               "reason": "无法构造 PURL"})

    modules = [_text(element) for element in root.iter() if _local(element.tag) == "module"]
    return components, unresolved, {"modules": [m for m in modules if m]}


_GRADLE_RE = re.compile(
    r"^\s*(?P<cfg>implementation|api|compile|runtime|runtimeOnly|compileOnly|"
    r"testImplementation|testCompile|testRuntimeOnly|annotationProcessor)\s*"
    r"[\( ]?\s*['\"](?P<coord>[^'\"]+)['\"]")
_GRADLE_LOCK_RE = re.compile(r"^(?P<g>[\w.\-]+):(?P<a>[\w.\-]+):(?P<v>[^=]+)=(?P<cfg>.*)$")


def _parse_gradle(text):
    components = []
    unresolved = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        match = _GRADLE_RE.match(line)
        if not match:
            continue
        parts = match.group("coord").split(":")
        if len(parts) < 3:
            unresolved.append({"name": match.group("coord"), "reason": "坐标不足 3 段"})
            continue
        config = match.group("cfg")
        scope = "test" if config.lower().startswith("test") else "compile"
        comp = _make("maven", "%s:%s" % (parts[0], parts[1]), parts[2],
                     direct=True, scope=scope, version_req=parts[2],
                     pinned=not _is_range(parts[2]))
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": match.group("coord"), "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_gradle_lock(text):
    components = []
    unresolved = []
    for line in text.splitlines():
        match = _GRADLE_LOCK_RE.match(line.strip())
        if not match:
            continue
        version = match.group("v").strip()
        configs = match.group("cfg") or ""
        scope = "test" if "test" in configs else "compile"
        comp = _make("maven", "%s:%s" % (match.group("g"), match.group("a")), version,
                     direct=True, scope=scope, version_req=version,
                     pinned=not _is_range(version))
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": line.strip(), "reason": "无法构造 PURL"})
    return components, unresolved


# -------------------------------------------------------------------- npm

def _parse_package_json(text):
    doc = json.loads(text)
    components = []
    unresolved = []
    fields = (("dependencies", "prod", True),
              ("optionalDependencies", "prod", True),
              ("peerDependencies", "peer", True),
              ("devDependencies", "dev", False))
    for field, scope, direct in fields:
        for name, req in (doc.get(field) or {}).items():
            version, pinned = _version_from_req(req)
            if not version:
                unresolved.append({"name": name, "reason": "版本约束 %s 无法锁定" % req})
                continue
            comp = _make("npm", name, version, direct=direct, scope=scope,
                         version_req=req, pinned=pinned)
            if comp:
                components.append(comp)
            else:
                unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_npm_lock(text):
    doc = json.loads(text)
    components = []
    unresolved = []
    packages = doc.get("packages") or {}
    if packages:
        root = packages.get("") or {}
        root_names = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            root_names.update((root.get(field) or {}).keys())
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or path.split("node_modules/")[-1]
            version = meta.get("version")
            if not version:
                unresolved.append({"name": path, "reason": "缺少 version"})
                continue
            direct = (name in root_names) or path.count("node_modules/") == 1
            scope = "dev" if meta.get("dev") else ("peer" if meta.get("peer") else "prod")
            comp = _make("npm", name, version, direct=direct, scope=scope,
                         version_req=version, pinned=True)
            if comp:
                components.append(comp)
            else:
                unresolved.append({"name": name, "reason": "无法构造 PURL"})
        return components, unresolved

    def walk(deps, depth):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                unresolved.append({"name": name, "reason": "缺少 version"})
                continue
            scope = "dev" if meta.get("dev") else "prod"
            comp = _make("npm", name, version, direct=(depth == 0), scope=scope,
                         version_req=version, pinned=True)
            if comp:
                components.append(comp)
            else:
                unresolved.append({"name": name, "reason": "无法构造 PURL"})
            if meta.get("dependencies"):
                walk(meta["dependencies"], depth + 1)

    walk(doc.get("dependencies") or {}, 0)
    return components, unresolved


def _parse_yarn_lock(text):
    components = []
    unresolved = []
    pending = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[:1].isspace() and line.rstrip().endswith(":"):
            keys = [k.strip().strip("\"'") for k in line.rstrip()[:-1].split(",")]
            key = keys[0] if keys else ""
            idx = key.rfind("@")
            pending = key[:idx] if idx > 0 else (key or None)
            continue
        match = re.match(r'^\s+version\s+"?([^"\s]+)"?', line)
        if match and pending:
            name, version = pending, match.group(1)
            pending = None
            comp = _make("npm", name, version, direct=False, scope="prod",
                         version_req=version, pinned=True)
            if comp:
                components.append(comp)
            else:
                unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


_PNPM_VER_RE = re.compile(r"^[@A-Za-z0-9._\-/]+@\d")


def _parse_pnpm_lock(text):
    components = []
    unresolved = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or not raw.endswith(":"):
            continue
        token = raw[:-1].strip().strip("\"'")
        if not token:
            continue
        name = version = None
        if token.startswith("/"):
            parts = token[1:].split("/")
            if len(parts) < 2:
                continue
            version = parts[-1].split("_")[0]
            name = "/".join(parts[:-1])
        elif _PNPM_VER_RE.match(token):
            idx = token.rfind("@")
            if idx <= 0:
                continue
            name, version = token[:idx], token[idx + 1:].split("_")[0]
        if not name or not version:
            continue
        comp = _make("npm", name, version, direct=False, scope="prod",
                     version_req=version, pinned=True)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


# ------------------------------------------------------------------- PyPI

def _parse_requirements(text):
    components = []
    unresolved = []
    for line in text.splitlines():
        parsed = _split_pypi(line)
        if not parsed:
            continue
        name, req, version, pinned = parsed
        if not version:
            unresolved.append({"name": name, "reason": "版本约束 %s 无法锁定" % (req or "空")})
            continue
        comp = _make("pypi", name, version, direct=True, scope="prod",
                     version_req=req, pinned=pinned)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_pipfile_lock(text):
    doc = json.loads(text)
    components = []
    unresolved = []
    for section, scope in (("default", "prod"), ("develop", "dev")):
        for name, meta in (doc.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            req = meta.get("version") or ""
            version, pinned = _version_from_req(req)
            if not version:
                unresolved.append({"name": name, "reason": "版本约束 %s 无法锁定" % req})
                continue
            comp = _make("pypi", name, version, direct=(scope == "prod"), scope=scope,
                         version_req=req, pinned=pinned)
            if comp:
                components.append(comp)
            else:
                unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_toml_blocks(text):
    """解析 [[package]] name/version 形式的锁文件（poetry.lock / Cargo.lock）。"""
    blocks = []
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[["):
            if current and current.get("name") and current.get("version"):
                blocks.append(current)
            current = {}
            continue
        if current is None:
            continue
        match = re.match(r'^(name|version)\s*=\s*"([^"]+)"', stripped)
        if match:
            current[match.group(1)] = match.group(2)
    if current and current.get("name") and current.get("version"):
        blocks.append(current)
    return blocks


def _parse_poetry_lock(text):
    components = []
    unresolved = []
    for block in _parse_toml_blocks(text):
        comp = _make("pypi", block["name"], block["version"], direct=False, scope="prod",
                     version_req=block["version"], pinned=True)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": block["name"], "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_pyproject(text):
    components = []
    unresolved = []
    mode = None
    in_array = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]").strip()
            in_array = False
            mode = None
            if section.startswith("tool.poetry") and section.endswith("dependencies"):
                mode = "poetry"
            elif section == "project" or section.startswith("project."):
                mode = "pep621"
            continue
        if mode == "poetry":
            match = re.match(r"^([A-Za-z0-9._\-]+)\s*=\s*(.+)$", stripped)
            if not match or match.group(1) == "python":
                continue
            value = match.group(2)
            found = re.search(r'version\s*=\s*"([^"]+)"', value)
            req = found.group(1) if found else value.strip().strip(",").strip("\"'")
            version, pinned = _version_from_req(req)
            if not version:
                unresolved.append({"name": match.group(1),
                                   "reason": "版本约束 %s 无法锁定" % req})
                continue
            comp = _make("pypi", match.group(1), version, direct=True, scope="prod",
                         version_req=req, pinned=pinned)
            if comp:
                components.append(comp)
        elif mode == "pep621":
            if "dependencies" in stripped:
                in_array = True
            if not in_array:
                continue
            for item in re.findall(r'"([^"]+)"', stripped):
                parsed = _split_pypi(item)
                if not parsed:
                    continue
                name, req, version, pinned = parsed
                if not version:
                    unresolved.append({"name": name,
                                       "reason": "版本约束 %s 无法锁定" % (req or "空")})
                    continue
                comp = _make("pypi", name, version, direct=True, scope="prod",
                             version_req=req, pinned=pinned)
                if comp:
                    components.append(comp)
            if "]" in stripped:
                in_array = False
    return components, unresolved


# ------------------------------------------------------------ Go / 其他生态

def _parse_go_mod(text):
    components = []
    unresolved = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require "):
            body = stripped[len("require "):].strip()
        elif in_block:
            body = stripped
        else:
            continue
        indirect = "// indirect" in line
        body = body.split("//")[0].strip()
        parts = body.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        comp = _make("go", module, version, direct=not indirect, scope="prod",
                     version_req=version, pinned=True)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": module, "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_go_sum(text):
    components = []
    unresolved = []
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if module in seen:
            continue
        seen.add(module)
        comp = _make("go", module, version, direct=False, scope="prod",
                     version_req=version, pinned=True)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": module, "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_cargo_lock(text):
    components = []
    unresolved = []
    for block in _parse_toml_blocks(text):
        comp = _make("cargo", block["name"], block["version"], direct=False, scope="prod",
                     version_req=block["version"], pinned=True)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": block["name"], "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_cargo_toml(text):
    components = []
    unresolved = []
    mode = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            mode = stripped.strip("[]").strip().endswith("dependencies")
            continue
        if not mode:
            continue
        match = re.match(r"^([A-Za-z0-9._\-]+)\s*=\s*(.+)$", stripped)
        if not match:
            continue
        value = match.group(2)
        found = re.search(r'version\s*=\s*"([^"]+)"', value)
        req = found.group(1) if found else value.strip().strip(",").strip("\"'")
        version, pinned = _version_from_req(req)
        if not version:
            unresolved.append({"name": match.group(1), "reason": "版本约束 %s 无法锁定" % req})
            continue
        comp = _make("cargo", match.group(1), version, direct=True, scope="prod",
                     version_req=req, pinned=pinned)
        if comp:
            components.append(comp)
    return components, unresolved


def _parse_composer_json(text):
    doc = json.loads(text)
    components = []
    unresolved = []
    for field, scope in (("require", "prod"), ("require-dev", "dev")):
        for name, req in (doc.get(field) or {}).items():
            if name == "php":
                continue
            version, pinned = _version_from_req(req)
            if not version:
                unresolved.append({"name": name, "reason": "版本约束 %s 无法锁定" % req})
                continue
            comp = _make("composer", name, version, direct=True, scope=scope,
                         version_req=req, pinned=pinned)
            if comp:
                components.append(comp)
            else:
                unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


def _parse_composer_lock(text):
    doc = json.loads(text)
    components = []
    unresolved = []
    for field, scope in (("packages", "prod"), ("packages-dev", "dev")):
        for item in doc.get(field) or []:
            name = item.get("name")
            version = (item.get("version") or "").lstrip("v")
            if not name or not version:
                unresolved.append({"name": name or "unknown", "reason": "缺少 name/version"})
                continue
            comp = _make("composer", name, version, direct=(scope == "prod"), scope=scope,
                         version_req=version, pinned=True)
            if comp:
                components.append(comp)
            else:
                unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


_GEM_RE = re.compile(r"^([A-Za-z0-9._\-]+)\s*\(([^)]+)\)$")


def _parse_gemfile_lock(text):
    components = []
    unresolved = []
    for line in text.splitlines():
        match = _GEM_RE.match(line.strip())
        if not match:
            continue
        name = match.group(1)
        version = match.group(2).split(",")[0].strip()
        version, pinned = _version_from_req(version or "")
        if not version:
            unresolved.append({"name": name, "reason": "版本无法解析"})
            continue
        comp = _make("gem", name, version, direct=False, scope="prod",
                     version_req=version, pinned=pinned)
        if comp:
            components.append(comp)
        else:
            unresolved.append({"name": name, "reason": "无法构造 PURL"})
    return components, unresolved


# ------------------------------------------------------------------ 调度入口

_PARSERS = {
    "pom": _parse_pom,
    "gradle": _parse_gradle,
    "gradle-lock": _parse_gradle_lock,
    "package-json": _parse_package_json,
    "npm-lock": _parse_npm_lock,
    "yarn-lock": _parse_yarn_lock,
    "pnpm-lock": _parse_pnpm_lock,
    "requirements": _parse_requirements,
    "pipfile-lock": _parse_pipfile_lock,
    "poetry-lock": _parse_poetry_lock,
    "pyproject": _parse_pyproject,
    "go-mod": _parse_go_mod,
    "go-sum": _parse_go_sum,
    "cargo-lock": _parse_cargo_lock,
    "cargo-toml": _parse_cargo_toml,
    "composer-json": _parse_composer_json,
    "composer-lock": _parse_composer_lock,
    "gemfile-lock": _parse_gemfile_lock,
}


def parse_file(path):
    """解析单个依赖声明文件，返回统一的摄入结果。"""
    kind = classify(path)
    if not kind:
        return None
    eco, fmt = kind
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    result = {"path": path, "source": os.path.basename(path), "eco": eco,
              "format": fmt, "components": [], "unresolved": [], "modules": []}
    parser = _PARSERS.get(fmt)
    if not parser:
        result["unresolved"].append({"name": path, "reason": "暂不支持的格式 %s" % fmt})
        return result
    try:
        parsed = parser(text)
    except Exception as exc:  # 解析失败不得中断整体扫描
        result["unresolved"].append({"name": os.path.basename(path),
                                     "reason": "解析失败：%s" % exc})
        return result
    components, unresolved = parsed[0], parsed[1]
    extra = parsed[2] if len(parsed) > 2 else {}
    result["components"] = [c.to_dict() for c in components]
    result["unresolved"] = unresolved
    result["modules"] = (extra or {}).get("modules") or []
    return result


def scan_dir(root, max_depth=6):
    """扫描目录树，聚合所有依赖声明文件的解析结果。"""
    root = os.path.abspath(root)
    files = []
    collected = []
    unresolved = []
    for path in discover(root, max_depth=max_depth):
        result = parse_file(path)
        if not result:
            continue
        files.append({
            "path": os.path.relpath(path, root),
            "eco": result["eco"],
            "format": result["format"],
            "components": len(result["components"]),
            "unresolved": len(result["unresolved"]),
        })
        collected.extend(result["components"])
        for item in result["unresolved"]:
            item = dict(item)
            item["file"] = os.path.relpath(path, root)
            unresolved.append(item)
    return {
        "root": root,
        "files": files,
        "component_count": len(collected),
        "components": sbom.dedupe(collected),
        "unresolved": unresolved,
    }


def assets_entry(group, app, scan_result, tier="normal", exposure="internal",
                 data_sensitivity="low"):
    """把扫描结果转成资产台账条目（应用 → 组件 PURL 列表），供 depinfo / 评估台使用。"""
    purls = []
    gavs = []
    for comp in scan_result.get("components") or []:
        purls.append(comp["purl"])
        if comp.get("gav"):
            gavs.append(comp["gav"])
    return {
        "name": app,
        "group": group,
        "tier": tier,
        "exposure": exposure,
        "data_sensitivity": data_sensitivity,
        "purls": purls,
        "gavs": gavs,
    }


def purls_of(scan_result):
    return [comp["purl"] for comp in scan_result.get("components") or []]
