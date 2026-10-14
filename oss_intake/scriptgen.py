"""AI 智能体脚本生成：把基线项 / 漏洞描述转成平台可直接纳管的检查脚本。

三类产出目标：
- `sreops`   SRE 运维平台巡检脚本（POSIX sh，单行 JSON 结果，无第三方依赖）
- `codescan` 代码扫描中心规则包（YAML 规则 + Python 检测脚本）
- `python`   通用 Python 巡检脚本（标准库实现，支持 --json）

生成链路：`模板引擎`（确定性、可离线）→ 可选 `LLM 增强`（配置 SCABASE_LLM_ENDPOINT 时）
→ `静态检查 lint` → 不通过则回落到模板结果 → 落盘并生成 manifest。
凡由 LLM 生成的产物一律标记 `generated_by=llm`、`review_required=true`，
须经 `verify` 回归校验与人工审核后方可上线。

零第三方依赖（HTTP 调用走 urllib，仅 LLM 增强路径使用）。
"""
import hashlib
import json
import os
import time

TARGETS = ("sreops", "codescan", "python")

PLATFORM_RULES = {
    "sreops": (
        "SRE 运维平台巡检脚本规范：POSIX sh（#!/bin/sh）；脚本末尾以单行 JSON 输出巡检结果，"
        "字段固定为 rule_id / status / severity / evidence / ts，status 取值 PASS|FAIL|UNKNOWN；"
        "无论 PASS 还是 FAIL，脚本退出码均为 0，仅执行失败时退出码非 0；"
        "禁止破坏性操作（rm -rf、kill、覆写配置文件）与管道执行远程脚本；"
        "外部命令须带超时（--max-time / timeout），单脚本执行不超过 30 秒。"
    ),
    "codescan": (
        "代码扫描中心规则包规范：YAML；单条规则字段为 id / name / severity / languages / "
        "patterns / message / remediation / references / metadata；pattern 使用正则；"
        "同时提供同名 Python 检测脚本，读取 --path 扫描目标目录，输出 SARIF 片段。"
    ),
    "python": (
        "通用 Python 巡检脚本规范：仅使用标准库；支持 --json 输出；"
        "输出字段 rule_id / status / severity / evidence；"
        "读取配置文件时使用只读方式，禁止修改目标环境；执行失败输出 UNKNOWN。"
    ),
}

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sh_quote(text):
    return str(text).replace("\\", "\\\\").replace("\"", "\\\"")


# ---------------------------------------------------------- SRE 运维平台脚本

def _sh_header(item):
    lines = [
        "#!/bin/sh",
        "# 自动生成：scabase 开源软件安全配置基线巡检脚本（模板引擎）",
        "# rule_id : %s" % item.get("id"),
        "# 标题    : %s" % item.get("title"),
        "# 组件    : %s（%s）" % (item.get("component"), item.get("deploy")),
        "# 级别    : %s" % item.get("severity"),
        "# 修复建议: %s" % item.get("remediation"),
        "# 参考    : %s" % ", ".join(item.get("references") or []),
        "# 说明    : 上线前须通过 verify 回归校验（目标准确率 >= 90%）并完成人工审核",
        "set -u",
        'RULE_ID="%s"' % item.get("id"),
        'SEVERITY="%s"' % item.get("severity"),
        'TS=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")',
        "",
    ]
    return "\n".join(lines)


def _sh_tail():
    return "\n".join([
        "",
        'case "$STATUS" in',
        "  PASS) ;;",
        "  FAIL) ;;",
        "  *) STATUS=UNKNOWN ;;",
        "esac",
        'EVIDENCE=$(printf %s "$EVIDENCE" | tr -d \'"\' | tr "\\n" " ")',
        'printf \'{"rule_id":"%s","status":"%s","severity":"%s","evidence":"%s","ts":"%s"}\\n\' \\',
        '  "$RULE_ID" "$STATUS" "$SEVERITY" "$EVIDENCE" "$TS"',
        "exit 0",
    ])


def _sh_body(check):
    kind = check.get("kind")
    expect = check.get("expect") or {}
    op = expect.get("op")
    value = expect.get("value")
    if kind == "config":
        path = check.get("path")
        key = check.get("key")
        body = [
            'CONF="%s"' % path,
            'KEY="%s"' % key,
            'if [ ! -r "$CONF" ]; then',
            '  STATUS=UNKNOWN; EVIDENCE="配置文件不存在或无权限: $CONF"',
            "else",
            '  VALUE=$(grep -E "^[[:space:]]*${KEY}[[:space:]]" "$CONF" 2>/dev/null | tail -n1 \\',
            '         | sed -E "s/^[[:space:]]*${KEY}[[:space:]]*//" | tr -d "\\r")',
            '  EVIDENCE="$CONF:$KEY = $VALUE"',
        ]
        if op == "set":
            body.append('  if [ -n "$VALUE" ]; then STATUS=PASS; else STATUS=FAIL; fi')
        elif op == "eq":
            body.append('  if [ "$VALUE" = "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        elif op == "ne":
            body.append('  if [ "$VALUE" != "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        elif op == "contains":
            body.append('  if printf %%s "$VALUE" | grep -q "%s"; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        elif op == "not_contains":
            body.append('  if printf %%s "$VALUE" | grep -q "%s"; then STATUS=FAIL; else STATUS=PASS; fi'
                        % _sh_quote(value))
        elif op == "regex":
            body.append('  if printf %%s "$VALUE" | grep -Eq "%s"; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        elif op == "not_regex":
            body.append('  if printf %%s "$VALUE" | grep -Eq "%s"; then STATUS=FAIL; else STATUS=PASS; fi'
                        % _sh_quote(value))
        else:
            body.append("  STATUS=UNKNOWN")
        body.append("fi")
        return "\n".join(body)
    if kind == "cli":
        command = check.get("command")
        body = [
            'OUTPUT=$(timeout 20 sh -c \'%s\' 2>/dev/null | tr -d "\\r")' % _sh_quote(command),
            'EVIDENCE="$ %s -> $OUTPUT"' % _sh_quote(command),
        ]
        if op == "eq":
            body.append('if [ "$OUTPUT" = "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        elif op == "ne":
            body.append('if [ "$OUTPUT" != "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        elif op == "regex":
            body.append('if printf %%s "$OUTPUT" | grep -Eq "%s"; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        elif op == "not_regex":
            body.append('if printf %%s "$OUTPUT" | grep -Eq "%s"; then STATUS=FAIL; else STATUS=PASS; fi'
                        % _sh_quote(value))
        else:
            body.append("STATUS=UNKNOWN")
        return "\n".join(body)
    if kind == "http":
        url = check.get("url")
        body = [
            'CODE=$(curl -s -o /dev/null -w "%%{http_code}" --max-time 8 "%s" 2>/dev/null)' % url,
            'EVIDENCE="GET %s -> $CODE"' % url,
        ]
        if op == "status":
            body.append('if [ "$CODE" = "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        else:
            body.append("STATUS=UNKNOWN")
        return "\n".join(body)
    if kind == "version":
        body = [
            'VERSION="${1:-}"',
            'if [ -z "$VERSION" ]; then STATUS=UNKNOWN; EVIDENCE="未提供组件版本（参数 1）"; else',
            '  EVIDENCE="version = $VERSION"',
        ]
        if op in ("gte", "gt", "lte", "lt"):
            body.append(
                '  MIN=$(printf "%%s\\n%%s\\n" "%s" "$VERSION" | sort -V | head -n1)'
                % _sh_quote(value))
            if op == "gte":
                body.append('  if [ "$MIN" = "%s" ] || [ "$VERSION" = "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                            % (_sh_quote(value), _sh_quote(value)))
            elif op == "gt":
                body.append('  if [ "$MIN" = "%s" ] && [ "$VERSION" != "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                            % (_sh_quote(value), _sh_quote(value)))
            elif op == "lte":
                body.append('  if [ "$MIN" = "$VERSION" ] || [ "$VERSION" = "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                            % _sh_quote(value))
            else:
                body.append('  if [ "$MIN" = "$VERSION" ] && [ "$VERSION" != "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                            % _sh_quote(value))
        else:
            body.append("  STATUS=UNKNOWN")
        body.append("fi")
        return "\n".join(body)
    if kind == "file":
        path = check.get("path")
        body = [
            'TARGET="%s"' % path,
            'if [ ! -e "$TARGET" ]; then STATUS=UNKNOWN; EVIDENCE="文件不存在: $TARGET"; else',
            '  MODE=$(stat -c %a "$TARGET" 2>/dev/null)',
            '  EVIDENCE="$TARGET mode = $MODE"',
        ]
        if op == "mode_not":
            body.append('  if [ "$MODE" = "%s" ]; then STATUS=FAIL; else STATUS=PASS; fi'
                        % _sh_quote(value))
        elif op == "eq":
            body.append('  if [ "$MODE" = "%s" ]; then STATUS=PASS; else STATUS=FAIL; fi'
                        % _sh_quote(value))
        else:
            body.append("  STATUS=UNKNOWN")
        body.append("fi")
        return "\n".join(body)
    return 'STATUS=UNKNOWN\nEVIDENCE="暂不支持的检查类型 %s"' % (kind or "unknown")


def render_sreops(item):
    check = item.get("check") or {}
    return _sh_header(item) + _sh_body(check) + _sh_tail() + "\n"


# --------------------------------------------------------- 代码扫描中心规则包

def render_codescan_yaml(item):
    check = item.get("check") or {}
    patterns = []
    if check.get("kind") == "config":
        patterns.append(r"^\s*%s\s*" % (check.get("key") or ""))
    elif check.get("kind") == "version":
        patterns.append(r"version\s*[:=]\s*[\"']?%s" % (item.get("component") or ""))
    else:
        patterns.append(r"%s" % (item.get("component") or ""))
    if (check.get("expect") or {}).get("value"):
        patterns.append(r"%s" % str(check["expect"]["value"]))
    lines = [
        "- id: scabase-%s" % item.get("id"),
        "  name: %s" % item.get("title"),
        "  severity: %s" % SEVERITY_MAP.get(item.get("severity"), "medium"),
        "  languages: [yaml, properties, conf, ini, xml]",
        "  patterns:",
    ]
    for pattern in patterns:
        lines.append("    - '%s'" % str(pattern).replace("'", "''"))
    lines += [
        "  message: %s" % item.get("title"),
        "  remediation: %s" % item.get("remediation"),
        "  references: [%s]" % ", ".join('"%s"' % r for r in (item.get("references") or [])),
        "  metadata:",
        "    cwe: %s" % (item.get("cwe") or ""),
        "    component: %s" % (item.get("component") or ""),
        "    scabase_rule_id: %s" % item.get("id"),
        "    source: scabase-baseline",
    ]
    return "\n".join(lines) + "\n"


_PY_DETECTOR = '''#!/usr/bin/env python3
"""代码扫描中心检测脚本 · 自动生成（模板引擎）

规则 %(rule_id)s：%(title)s
用法：python %(filename)s --path <扫描目录> [--sarif 输出路径]
仅使用标准库，输出 SARIF 2.1.0 片段。
"""
import argparse
import json
import os
import re
import sys

RULE_ID = "%(rule_id)s"
SEVERITY = "%(severity)s"
TITLE = "%(title)s"
PATTERNS = %(patterns)s
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(
    SEVERITY, "warning")


def scan(root):
    findings = []
    compiled = [re.compile(p) for p in PATTERNS]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "node_modules", "target", "build")]
        for name in filenames:
            if not name.endswith((".yml", ".yaml", ".properties", ".conf", ".ini", ".xml")):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.read().splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                for pattern in compiled:
                    if pattern.search(line):
                        findings.append({
                            "ruleId": RULE_ID,
                            "level": LEVEL,
                            "message": {"text": TITLE},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": os.path.relpath(path, root)},
                                    "region": {"startLine": number},
                                }
                            }],
                        })
                        break
    return findings


def to_sarif(findings):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "scabase-baseline",
                "rules": [{"id": RULE_ID, "name": TITLE,
                           "defaultConfiguration": {"level": LEVEL}}],
            }},
            "results": findings,
        }],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=RULE_ID)
    parser.add_argument("--path", default=".")
    parser.add_argument("--sarif")
    args = parser.parse_args(argv)
    findings = scan(args.path)
    payload = to_sarif(findings)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        print(text)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
'''


def render_codescan_script(item, filename):
    check = item.get("check") or {}
    patterns = []
    if check.get("kind") == "config":
        patterns.append(r"^\s*%s\s*" % (check.get("key") or ""))
    if (check.get("expect") or {}).get("value"):
        patterns.append(re.escape(str(check["expect"]["value"])))
    if not patterns:
        patterns.append(re.escape(str(item.get("component") or "")))
    return _PY_DETECTOR % {
        "rule_id": item.get("id"),
        "title": item.get("title"),
        "severity": item.get("severity"),
        "patterns": json.dumps(patterns, ensure_ascii=False),
        "filename": filename,
    }


# --------------------------------------------------------------- 通用 Python

_PY_CHECK = '''#!/usr/bin/env python3
"""开源软件安全基线巡检脚本 · 自动生成（模板引擎）

规则 %(rule_id)s：%(title)s
用法：python %(filename)s [--version <组件版本>] [--json]
输出：{"rule_id", "status", "severity", "evidence"}，status ∈ PASS/FAIL/UNKNOWN
仅使用标准库，只读检查，不修改目标环境。
"""
import argparse
import json
import os
import re
import sys

RULE_ID = "%(rule_id)s"
SEVERITY = "%(severity)s"
CHECK = %(check)s


def _vt(version):
    parts = []
    for chunk in str(version or "").split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def _vcmp(left, right):
    a, b = _vt(left), _vt(right)
    size = max(len(a), len(b))
    a += (0,) * (size - len(a))
    b += (0,) * (size - len(b))
    return (a > b) - (a < b)


def read_config(path, key):
    """只读解析 key value 形式配置；返回 (found, value)。"""
    if not os.path.isfile(path):
        return False, None
    pattern = re.compile(r"^\\s*" + re.escape(key) + r"\\s*(.*)$")
    value = None
    found = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = pattern.match(line.rstrip("\\n"))
                if match:
                    found = True
                    value = match.group(1).strip()
    except OSError:
        return False, None
    return found, value


def collect(check, version=None):
    kind = check.get("kind")
    if kind == "config":
        return read_config(check.get("path"), check.get("key"))
    if kind == "version":
        return (version is not None), version
    if kind == "cli":
        import subprocess
        try:
            out = subprocess.run(check.get("command"), shell=True, timeout=20,
                                 capture_output=True, text=True)
            return True, (out.stdout or "").strip()
        except Exception:
            return False, None
    if kind == "http":
        import urllib.request
        try:
            with urllib.request.urlopen(check.get("url"), timeout=8) as resp:
                return True, str(resp.status)
        except Exception as exc:
            if hasattr(exc, "code"):
                return True, str(exc.code)
            return False, None
    if kind == "file":
        path = check.get("path")
        if not os.path.exists(path):
            return False, None
        return True, oct(os.stat(path).st_mode & 0o777)
    return False, None


def judge(check, found, actual):
    expect = check.get("expect") or {}
    op = expect.get("op")
    value = expect.get("value")
    if not found:
        if op in ("set", "eq", "contains", "regex"):
            actual = ""
        else:
            return "UNKNOWN"
    if actual is None:
        actual = ""
    text = str(actual)
    if op == "set":
        return "PASS" if text.strip() not in ("", "no", "false", "0", "off") else "FAIL"
    if op == "eq":
        return "PASS" if text == str(value) else "FAIL"
    if op == "ne":
        return "PASS" if text != str(value) else "FAIL"
    if op == "contains":
        return "PASS" if str(value) in text else "FAIL"
    if op == "not_contains":
        return "PASS" if str(value) not in text else "FAIL"
    if op == "regex":
        return "PASS" if re.search(str(value), text) else "FAIL"
    if op == "not_regex":
        return "PASS" if re.search(str(value), text) is None else "FAIL"
    if op in ("gte", "gt", "lte", "lt"):
        cmp = _vcmp(text.strip(), str(value))
        ok = {"gte": cmp >= 0, "gt": cmp > 0, "lte": cmp <= 0, "lt": cmp < 0}[op]
        return "PASS" if ok else "FAIL"
    if op == "status":
        return "PASS" if text == str(value) else "FAIL"
    if op == "mode_not":
        return "PASS" if text != str(value) else "FAIL"
    return "UNKNOWN"


def main(argv=None):
    parser = argparse.ArgumentParser(description=RULE_ID)
    parser.add_argument("--version", help="组件实际版本（version 类检查必填）")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    found, actual = collect(CHECK, args.version)
    status = judge(CHECK, found, actual)
    payload = {
        "rule_id": RULE_ID,
        "status": status,
        "severity": SEVERITY,
        "evidence": str(actual) if actual is not None else "",
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print("%%s %%s %%s" %% (payload["rule_id"], payload["status"], payload["evidence"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def render_python(item, filename):
    return _PY_CHECK % {
        "rule_id": item.get("id"),
        "title": item.get("title"),
        "severity": item.get("severity"),
        "check": json.dumps(item.get("check") or {}, ensure_ascii=False, indent=4),
        "filename": filename,
    }


# ------------------------------------------------------------------ 渲染调度

def render(item, target="sreops"):
    """渲染单条基线项，返回 [{filename, content}]。"""
    rule_id = item.get("id")
    if target == "sreops":
        return [{"filename": "%s.sh" % rule_id, "content": render_sreops(item)}]
    if target == "codescan":
        script_name = "%s.py" % rule_id
        return [
            {"filename": "%s.yml" % rule_id, "content": render_codescan_yaml(item)},
            {"filename": script_name, "content": render_codescan_script(item, script_name)},
        ]
    if target == "python":
        script_name = "%s.py" % rule_id
        return [{"filename": script_name, "content": render_python(item, script_name)}]
    raise ValueError("不支持的产出目标 %s" % target)


# ------------------------------------------------------------------ 静态检查

# 只保留无歧义的破坏性指令片段；描述性文字（如「关闭 SHUTDOWN 端口」）不得命中
FORBIDDEN = ("rm -rf", "| sh", "|sh", ":(){", "mkfs", "kill -9", "dd if=", "> /dev/sd")


def lint(content, target, rule_id):
    """静态检查生成产物，返回 (ok, [问题])。"""
    problems = []
    if not content or not content.strip():
        return False, ["内容为空"]
    if rule_id not in content:
        problems.append("产物中缺少 rule_id 标识")
    for token in FORBIDDEN:
        if token in content:
            problems.append("包含高危指令片段：%s" % token)
    if target == "sreops":
        if not content.startswith("#!"):
            problems.append("缺少 shebang")
        if "STATUS=" not in content:
            problems.append("缺少 STATUS 判定")
        if "printf" not in content:
            problems.append("缺少 JSON 结果输出")
    elif target == "codescan":
        if "id:" not in content:
            problems.append("缺少规则 id 字段")
    elif target == "python":
        try:
            compile(content, "<generated>", "exec")
        except SyntaxError as exc:
            problems.append("Python 语法错误：%s" % exc)
        if "def main" not in content:
            problems.append("缺少 main 入口")
    return (not problems), problems


# ------------------------------------------------------------------ LLM 增强

SYSTEM_PROMPT = (
    "你是一名行业安全运维工程师，负责把开源软件安全配置基线转换为"
    "可在安全扫描平台纳管的检查脚本。只输出脚本代码，不要输出解释文字。"
)


class LLMClient(object):
    """可选的大模型客户端；未配置端点时整体禁用，保证内网离线可用。"""

    def __init__(self, endpoint=None, api_key=None, model=None, timeout=30):
        self.endpoint = endpoint or os.getenv("SCABASE_LLM_ENDPOINT") or ""
        self.api_key = api_key or os.getenv("SCABASE_LLM_API_KEY") or ""
        self.model = model or os.getenv("SCABASE_LLM_MODEL") or "gpt-4o-mini"
        self.timeout = timeout

    def enabled(self):
        return bool(self.endpoint)

    def complete(self, prompt):
        if not self.enabled():
            return None
        import urllib.request
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer %s" % self.api_key
        payload = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        try:
            request = urllib.request.Request(
                self.endpoint, data=json.dumps(payload).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except Exception:
            return None
        choices = data.get("choices") or []
        if choices:
            message = choices[0].get("message") or {}
            return message.get("content") or choices[0].get("text")
        for key in ("content", "result", "output", "data"):
            if isinstance(data.get(key), str):
                return data.get(key)
        return None


def build_prompt(item, target, template):
    return "\n".join([
        "请把下列开源软件安全基线项转换为符合目标平台规范的检查脚本。",
        "",
        "【目标平台】%s" % target,
        "【平台规则】%s" % PLATFORM_RULES.get(target, ""),
        "",
        "【基线项】",
        json.dumps(item, ensure_ascii=False, indent=2),
        "",
        "【模板基线脚本（可作参考，允许改进但不得改变判定语义）】",
        "```",
        template,
        "```",
        "",
        "要求：",
        "1. 只输出一个代码块内的脚本正文；",
        "2. 必须保留 rule_id=%s 与 severity=%s；" % (item.get("id"), item.get("severity")),
        "3. 判定结果 status 取值只能是 PASS / FAIL / UNKNOWN；",
        "4. 不得包含任何破坏性操作。",
    ])


def _strip_fence(text):
    if not text:
        return ""
    match = None
    lines = text.splitlines()
    start = end = None
    for index, line in enumerate(lines):
        if line.strip().startswith("```"):
            if start is None:
                start = index
            else:
                end = index
                break
    if start is not None and end is not None:
        match = "\n".join(lines[start + 1:end])
    return match or text.strip()


# ------------------------------------------------------------------ 生成入口

def generate(items, target="sreops", out_dir=None, llm=None, use_llm=True):
    """批量生成脚本并落盘，返回 manifest。"""
    if target not in TARGETS:
        raise ValueError("不支持的产出目标 %s" % target)
    llm = llm if llm is not None else LLMClient()
    manifest = {
        "schema": "scabase-scriptgen/v1",
        "generated_at": _stamp(),
        "target": target,
        "platform_rules": PLATFORM_RULES.get(target),
        "rules": [],
    }
    for item in items:
        rule_id = item.get("id")
        files = render(item, target)
        generated_by = "template"
        ok, problems = True, []
        for entry in files:
            ok_entry, problems_entry = lint(entry["content"], target, rule_id)
            ok = ok and ok_entry
            problems.extend(problems_entry)

        if use_llm and llm.enabled() and target != "codescan":
            try:
                prompt = build_prompt(item, target, files[0]["content"])
                refined = _strip_fence(llm.complete(prompt))
                if refined:
                    ok_llm, problems_llm = lint(refined, target, rule_id)
                    if ok_llm:
                        files = [{"filename": files[0]["filename"], "content": refined}]
                        generated_by = "llm"
                        ok, problems = ok_llm, problems_llm
            except Exception as exc:
                problems.append("LLM 增强失败，已回落模板：%s" % exc)

        entry_files = []
        for entry in files:
            entry_files.append({
                "filename": entry["filename"],
                "sha256": _sha(entry["content"]),
                "bytes": len(entry["content"].encode("utf-8")),
            })
            if out_dir:
                path = os.path.join(out_dir, rule_id, entry["filename"])
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(entry["content"])
        manifest["rules"].append({
            "id": rule_id,
            "title": item.get("title"),
            "component": item.get("component"),
            "severity": item.get("severity"),
            "generated_by": generated_by,
            "lint_ok": ok,
            "problems": problems,
            "review_required": True,
            "verified": False,
            "files": entry_files,
        })

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
    return manifest
