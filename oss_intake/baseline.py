"""开源软件安全配置基线目录（声明式）。

每条基线项描述「合规状态是什么」，由 `run_check` 依据环境快照判定
PASS / FAIL / UNKNOWN。同一份声明同时驱动：
- `scriptgen.py`：生成 e运维巡检脚本、代码扫描中心规则包与通用检测脚本；
- `verify.py`：在标注样本集上回归校验准确率（目标 ≥90%）；
- `patrol.py`：按组件匹配出应用待巡检项。

基线项可整体由维护：`load_catalog(path)` 会按 id 覆盖内置条目。
零第三方依赖。
"""
import copy
import json
import os
import re

SEVERITIES = ("critical", "high", "medium", "low")
DEPLOY_MODES = ("standalone", "embedded", "any")


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
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    return (a > b) - (a < b)


# ------------------------------------------------------------------ 内置目录

CATALOG = [
    # ---------------------------------------------------------------- Redis
    {
        "id": "redis-requirepass",
        "component": "redis",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Redis 未启用口令认证",
        "severity": "high",
        "check": {"kind": "config", "path": "/etc/redis/redis.conf",
                  "key": "requirepass", "expect": {"op": "set"}},
        "remediation": "在 redis.conf 中设置 requirepass <强口令> 并重启实例",
        "references": ["CWE-306", "CIS Redis 5.1"],
        "cwe": "CWE-306",
    },
    {
        "id": "redis-protected-mode",
        "component": "redis",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Redis protected-mode 未开启",
        "severity": "high",
        "check": {"kind": "config", "path": "/etc/redis/redis.conf",
                  "key": "protected-mode", "expect": {"op": "eq", "value": "yes"}},
        "remediation": "设置 protected-mode yes，禁止无保护暴露在公网",
        "references": ["CWE-668", "CIS Redis 5.2"],
        "cwe": "CWE-668",
    },
    {
        "id": "redis-bind",
        "component": "redis",
        "deploy": "standalone",
        "category": "网络暴露",
        "title": "Redis 监听 0.0.0.0",
        "severity": "critical",
        "check": {"kind": "config", "path": "/etc/redis/redis.conf",
                  "key": "bind", "expect": {"op": "not_contains", "value": "0.0.0.0"}},
        "remediation": "bind 仅保留内网地址，并在主机防火墙限制 6379 端口来源",
        "references": ["CWE-668", "CIS Redis 5.3"],
        "cwe": "CWE-668",
    },
    {
        "id": "redis-rename-command",
        "component": "redis",
        "deploy": "standalone",
        "category": "权限最小化",
        "title": "Redis 高危命令未重命名/禁用（FLUSHALL/CONFIG/EVAL）",
        "severity": "medium",
        "check": {"kind": "config", "path": "/etc/redis/redis.conf",
                  "key": "rename-command", "expect": {"op": "set"}},
        "remediation": "使用 rename-command 重命名或置空高危命令",
        "references": ["CWE-269"],
        "cwe": "CWE-269",
    },
    # ---------------------------------------------------------------- Nginx
    {
        "id": "nginx-server-tokens",
        "component": "nginx",
        "deploy": "standalone",
        "category": "信息泄露",
        "title": "Nginx 未关闭版本号回显",
        "severity": "low",
        "check": {"kind": "config", "path": "/etc/nginx/nginx.conf",
                  "key": "server_tokens", "expect": {"op": "eq", "value": "off"}},
        "remediation": "在 http 段设置 server_tokens off;",
        "references": ["CWE-200", "CIS Nginx 2.5.2"],
        "cwe": "CWE-200",
    },
    {
        "id": "nginx-tls-protocol",
        "component": "nginx",
        "deploy": "standalone",
        "category": "传输安全",
        "title": "Nginx TLS 启用不安全协议（SSLv3/TLSv1/TLSv1.1）",
        "severity": "high",
        "check": {"kind": "config", "path": "/etc/nginx/nginx.conf",
                  "key": "ssl_protocols",
                  "expect": {"op": "not_contains", "value": "TLSv1 "}},
        "remediation": "ssl_protocols 仅保留 TLSv1.2 TLSv1.3",
        "references": ["CWE-326", "CIS Nginx 4.1.4"],
        "cwe": "CWE-326",
    },
    {
        "id": "nginx-autoindex",
        "component": "nginx",
        "deploy": "standalone",
        "category": "信息泄露",
        "title": "Nginx 开启目录列举",
        "severity": "medium",
        "check": {"kind": "config", "path": "/etc/nginx/nginx.conf",
                  "key": "autoindex", "expect": {"op": "eq", "value": "off"}},
        "remediation": "关闭 autoindex，避免目录结构泄露",
        "references": ["CWE-548"],
        "cwe": "CWE-548",
    },
    # --------------------------------------------------------------- Tomcat
    {
        "id": "tomcat-manager-auth",
        "component": "tomcat",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Tomcat 管理后台弱口令/默认口令",
        "severity": "critical",
        "check": {"kind": "http", "url": "http://127.0.0.1:8080/manager/html",
                  "expect": {"op": "status", "value": 401}},
        "remediation": "删除默认账号、启用强口令并限制管理端访问来源 IP",
        "references": ["CWE-521", "CIS Tomcat 4.1"],
        "cwe": "CWE-521",
    },
    {
        "id": "tomcat-shutdown-port",
        "component": "tomcat",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Tomcat SHUTDOWN 端口使用默认指令与端口",
        "severity": "high",
        "check": {"kind": "config", "path": "/usr/local/tomcat/conf/server.xml",
                  "key": "Server.port", "expect": {"op": "eq", "value": "-1"}},
        "remediation": "将 Server port 置为 -1 关闭 SHUTDOWN 端口，或改为非默认强指令",
        "references": ["CWE-306", "CIS Tomcat 4.2"],
        "cwe": "CWE-306",
    },
    {
        "id": "tomcat-directory-listing",
        "component": "tomcat",
        "deploy": "standalone",
        "category": "信息泄露",
        "title": "Tomcat 开启目录列举（listings）",
        "severity": "medium",
        "check": {"kind": "config", "path": "/usr/local/tomcat/conf/web.xml",
                  "key": "listings", "expect": {"op": "eq", "value": "false"}},
        "remediation": "DefaultServlet 的 listings 参数置为 false",
        "references": ["CWE-548", "CIS Tomcat 2.2"],
        "cwe": "CWE-548",
    },
    # ---------------------------------------------------------------- Kafka
    {
        "id": "kafka-sasl",
        "component": "kafka",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Kafka 未启用 SASL 认证",
        "severity": "high",
        "check": {"kind": "config", "path": "/opt/kafka/config/server.properties",
                  "key": "sasl.enabled.mechanisms", "expect": {"op": "set"}},
        "remediation": "启用 SASL/SCRAM 认证并同步客户端配置",
        "references": ["CWE-306"],
        "cwe": "CWE-306",
    },
    {
        "id": "kafka-authorizer",
        "component": "kafka",
        "deploy": "standalone",
        "category": "权限最小化",
        "title": "Kafka 未配置授权器（ACL）",
        "severity": "medium",
        "check": {"kind": "config", "path": "/opt/kafka/config/server.properties",
                  "key": "authorizer.class.name", "expect": {"op": "set"}},
        "remediation": "配置 AclAuthorizer 并按最小权限授予 topic 访问",
        "references": ["CWE-732"],
        "cwe": "CWE-732",
    },
    # ------------------------------------------------------------ Zookeeper
    {
        "id": "zookeeper-auth",
        "component": "zookeeper",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "ZooKeeper 未启用认证，存在未授权访问",
        "severity": "critical",
        "check": {"kind": "cli", "command": "echo srvr | nc 127.0.0.1 2181",
                  "expect": {"op": "not_regex", "value": "not in whitelist|Authentication is not valid"}},
        "remediation": "启用 SASL/Kerberos 或 digest 认证，并配置四字命令白名单",
        "references": ["CWE-306"],
        "cwe": "CWE-306",
    },
    {
        "id": "zookeeper-4lw",
        "component": "zookeeper",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "ZooKeeper 四字命令未做白名单限制",
        "severity": "medium",
        "check": {"kind": "config", "path": "/opt/zookeeper/conf/zoo.cfg",
                  "key": "4lw.commands.whitelist", "expect": {"op": "set"}},
        "remediation": "设置 4lw.commands.whitelist=srvr 等最小集合",
        "references": ["CWE-16"],
        "cwe": "CWE-16",
    },
    # -------------------------------------------------------- Elasticsearch
    {
        "id": "es-security",
        "component": "elasticsearch",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Elasticsearch 未启用安全认证（xpack.security）",
        "severity": "critical",
        "check": {"kind": "config", "path": "/etc/elasticsearch/elasticsearch.yml",
                  "key": "xpack.security.enabled", "expect": {"op": "eq", "value": "true"}},
        "remediation": "启用 xpack.security 并配置内置账号强口令/TLS",
        "references": ["CWE-306"],
        "cwe": "CWE-306",
    },
    {
        "id": "es-network-host",
        "component": "elasticsearch",
        "deploy": "standalone",
        "category": "网络暴露",
        "title": "Elasticsearch 绑定 0.0.0.0",
        "severity": "high",
        "check": {"kind": "config", "path": "/etc/elasticsearch/elasticsearch.yml",
                  "key": "network.host", "expect": {"op": "not_contains", "value": "0.0.0.0"}},
        "remediation": "network.host 绑定内网地址并限制 9200/9300 端口来源",
        "references": ["CWE-668"],
        "cwe": "CWE-668",
    },
    # ---------------------------------------------------------------- Nacos
    {
        "id": "nacos-auth",
        "component": "nacos",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Nacos 未开启鉴权（nacos.core.auth.enabled）",
        "severity": "critical",
        "check": {"kind": "config", "path": "/opt/nacos/conf/application.properties",
                  "key": "nacos.core.auth.enabled", "expect": {"op": "eq", "value": "true"}},
        "remediation": "开启鉴权并修改默认密钥与默认账号口令",
        "references": ["CWE-306"],
        "cwe": "CWE-306",
    },
    # ---------------------------------------------------------------- MySQL
    {
        "id": "mysql-bind-address",
        "component": "mysql",
        "deploy": "standalone",
        "category": "网络暴露",
        "title": "MySQL 监听 0.0.0.0",
        "severity": "high",
        "check": {"kind": "config", "path": "/etc/my.cnf",
                  "key": "bind-address", "expect": {"op": "not_contains", "value": "0.0.0.0"}},
        "remediation": "bind-address 指定内网地址，数据库不得直接对公网开放",
        "references": ["CWE-668", "CIS MySQL 3.1"],
        "cwe": "CWE-668",
    },
    {
        "id": "mysql-empty-password",
        "component": "mysql",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "MySQL 存在空口令账号",
        "severity": "critical",
        "check": {"kind": "cli",
                  "command": "mysql -N -e \"select count(*) from mysql.user where authentication_string=''\"",
                  "expect": {"op": "eq", "value": "0"}},
        "remediation": "清理空口令与匿名账号，统一口令强度策略",
        "references": ["CWE-521", "CIS MySQL 2.1"],
        "cwe": "CWE-521",
    },
    # ------------------------------------------------------------- RabbitMQ
    {
        "id": "rabbitmq-default-user",
        "component": "rabbitmq",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "RabbitMQ 保留默认 guest/guest 账号",
        "severity": "high",
        "check": {"kind": "cli", "command": "rabbitmqctl list_users",
                  "expect": {"op": "not_regex", "value": "^guest\\s"}},
        "remediation": "删除或禁用默认 guest 账号，创建最小权限业务账号",
        "references": ["CWE-521"],
        "cwe": "CWE-521",
    },
    # ------------------------------------------------------------- MongoDB
    {
        "id": "mongodb-auth",
        "component": "mongodb",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "MongoDB 未启用认证（authorization）",
        "severity": "critical",
        "check": {"kind": "config", "path": "/etc/mongod.conf",
                  "key": "security.authorization", "expect": {"op": "eq", "value": "enabled"}},
        "remediation": "开启 authorization 并创建带角色的业务账号",
        "references": ["CWE-306"],
        "cwe": "CWE-306",
    },
    {
        "id": "mongodb-bindip",
        "component": "mongodb",
        "deploy": "standalone",
        "category": "网络暴露",
        "title": "MongoDB bindIp 配置为 0.0.0.0",
        "severity": "high",
        "check": {"kind": "config", "path": "/etc/mongod.conf",
                  "key": "net.bindIp", "expect": {"op": "not_contains", "value": "0.0.0.0"}},
        "remediation": "bindIp 限制为内网地址",
        "references": ["CWE-668"],
        "cwe": "CWE-668",
    },
    # ------------------------------------------------------- Docker / Jenkins
    {
        "id": "docker-daemon-socket",
        "component": "docker",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Docker daemon 对外暴露 2375 未加密端口",
        "severity": "critical",
        "check": {"kind": "cli", "command": "ss -lntp | grep ':2375'",
                  "expect": {"op": "eq", "value": ""}},
        "remediation": "关闭 2375 端口，改用 TLS 保护的 2376 或本地 unix socket",
        "references": ["CWE-306", "CIS Docker 2.1"],
        "cwe": "CWE-306",
    },
    {
        "id": "jenkins-anonymous",
        "component": "jenkins",
        "deploy": "standalone",
        "category": "访问控制",
        "title": "Jenkins 允许匿名读取",
        "severity": "high",
        "check": {"kind": "config", "path": "/var/lib/jenkins/config.xml",
                  "key": "useSecurity", "expect": {"op": "eq", "value": "true"}},
        "remediation": "启用安全域与矩阵授权，取消匿名可读权限",
        "references": ["CWE-306"],
        "cwe": "CWE-306",
    },
    # ------------------------------------------------- 依赖型组件（库/框架）
    {
        "id": "fastjson-autotype",
        "component": "fastjson",
        "deploy": "embedded",
        "category": "反序列化",
        "title": "fastjson 未关闭 autoType 且版本低于 1.2.83",
        "severity": "critical",
        "check": {"kind": "version", "expect": {"op": "gte", "value": "1.2.83"}},
        "remediation": "升级至 1.2.83+ 并显式关闭 autoType（safeMode）",
        "references": ["CVE-2022-25845", "CWE-502"],
        "cwe": "CWE-502",
        "cve_hint": ["CVE-2022-25845"],
    },
    {
        "id": "log4j-jndilookup",
        "component": "log4j",
        "deploy": "embedded",
        "category": "反序列化",
        "title": "log4j-core 版本低于 2.17.1（JNDI Lookup 风险）",
        "severity": "critical",
        "check": {"kind": "version", "expect": {"op": "gte", "value": "2.17.1"}},
        "remediation": "升级 log4j-core 至 2.17.1 及以上",
        "references": ["CVE-2021-44228", "CVE-2021-45046", "CWE-20"],
        "cwe": "CWE-20",
        "cve_hint": ["CVE-2021-44228", "CVE-2021-45046"],
    },
    {
        "id": "shiro-rememberme-key",
        "component": "shiro",
        "deploy": "embedded",
        "category": "访问控制",
        "title": "Shiro 使用默认 rememberMe 加密密钥",
        "severity": "critical",
        "check": {"kind": "config", "path": "application.yml",
                  "key": "shiro.cipher-key",
                  "expect": {"op": "not_contains", "value": "kPH+bIxk5D2deZiIxcaaaA=="}},
        "remediation": "更换默认 cipherKey，升级至 1.13.0+/2.0+",
        "references": ["CVE-2016-4437", "CWE-798"],
        "cwe": "CWE-798",
        "cve_hint": ["CVE-2016-4437"],
    },
    {
        "id": "struts-ognl",
        "component": "struts",
        "deploy": "embedded",
        "category": "远程代码执行",
        "title": "Struts2 版本低于 6.4.0（OGNL 注入风险）",
        "severity": "critical",
        "check": {"kind": "version", "expect": {"op": "gte", "value": "6.4.0"}},
        "remediation": "升级 Struts2 至 6.4.0 及以上并关闭动态方法调用",
        "references": ["CVE-2023-50164", "CWE-94"],
        "cwe": "CWE-94",
        "cve_hint": ["CVE-2023-50164"],
    },
    {
        "id": "springboot-actuator",
        "component": "spring-boot",
        "deploy": "embedded",
        "category": "信息泄露",
        "title": "Spring Boot Actuator 暴露 env/heapdump 端点",
        "severity": "high",
        "check": {"kind": "config", "path": "application.yml",
                  "key": "management.endpoints.web.exposure.include",
                  "expect": {"op": "not_contains", "value": "heapdump"}},
        "remediation": "仅暴露 health/info，并对 actuator 路径做访问控制",
        "references": ["CWE-200"],
        "cwe": "CWE-200",
    },
    {
        "id": "springboot-actuator-auth",
        "component": "spring-boot",
        "deploy": "embedded",
        "category": "访问控制",
        "title": "Spring Boot Actuator 未接入鉴权",
        "severity": "medium",
        "check": {"kind": "http", "url": "http://127.0.0.1:8080/actuator/env",
                  "expect": {"op": "status", "value": 401}},
        "remediation": "为 /actuator/** 配置鉴权或改为内网管理端口",
        "references": ["CWE-306"],
        "cwe": "CWE-306",
    },
    {
        "id": "xstream-deserialize",
        "component": "xstream",
        "deploy": "embedded",
        "category": "反序列化",
        "title": "XStream 版本低于 1.4.20 且未配置安全白名单",
        "severity": "high",
        "check": {"kind": "version", "expect": {"op": "gte", "value": "1.4.20"}},
        "remediation": "升级至 1.4.20+ 并使用 allowTypesByWildcard 白名单",
        "references": ["CVE-2021-21351", "CWE-502"],
        "cwe": "CWE-502",
        "cve_hint": ["CVE-2021-21351"],
    },
    {
        "id": "jackson-polymorphic",
        "component": "jackson-databind",
        "deploy": "embedded",
        "category": "反序列化",
        "title": "jackson-databind 启用 defaultTyping 且版本低于 2.15.0",
        "severity": "medium",
        "check": {"kind": "version", "expect": {"op": "gte", "value": "2.15.0"}},
        "remediation": "升级至 2.15.0+，禁用 enableDefaultTyping",
        "references": ["CWE-502"],
        "cwe": "CWE-502",
    },
]


# ------------------------------------------------------------------ 目录加载

def load_catalog(path=None):
    """加载基线目录：内置条目 + 外部覆盖（按 id 合并）。"""
    catalog = copy.deepcopy(CATALOG)
    if not path:
        return catalog
    with open(path, "r", encoding="utf-8") as handle:
        external = json.load(handle)
    items = external.get("items") if isinstance(external, dict) else external
    for item in items or []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        index = next((i for i, existing in enumerate(catalog)
                      if existing["id"] == item["id"]), None)
        if index is None:
            catalog.append(item)
        else:
            catalog[index] = item
    return catalog


def by_id(catalog, rule_id):
    for item in catalog:
        if item.get("id") == rule_id:
            return item
    return None


def match(catalog, name, deploy=None):
    """按组件名匹配基线项（不区分大小写的子串匹配）。"""
    text = (name or "").lower()
    if not text:
        return []
    hits = []
    for item in catalog:
        key = (item.get("component") or "").lower()
        if not key or key not in text:
            continue
        if deploy and item.get("deploy") not in ("any", deploy):
            continue
        hits.append(item)
    return hits


# ------------------------------------------------------------------ 检查执行

_FALSY = ("", "no", "false", "0", "off", "none", "#")


def _compare(actual, expect):
    """把实际值按期望算子比对，返回 True/False/None（None 表示无法判定）。"""
    op = (expect or {}).get("op")
    value = (expect or {}).get("value")
    if op == "set":
        if actual is None:
            return False
        return str(actual).strip().lower() not in _FALSY
    if op == "absent":
        return actual is None
    if op == "present":
        return actual is not None
    if actual is None:
        return None
    text = str(actual)
    if op == "eq":
        return text.strip() == str(value).strip()
    if op == "ne":
        return text.strip() != str(value).strip()
    if op == "in":
        return text in (value or [])
    if op == "not_in":
        return text not in (value or [])
    if op == "contains":
        return str(value) in text
    if op == "not_contains":
        return str(value) not in text
    if op == "regex":
        return re.search(str(value), text) is not None
    if op == "not_regex":
        return re.search(str(value), text) is None
    if op in ("gte", "gt", "lte", "lt"):
        cmp = _vcmp(text.strip(), str(value))
        return {"gte": cmp >= 0, "gt": cmp > 0, "lte": cmp <= 0, "lt": cmp < 0}[op]
    if op == "status":
        try:
            return int(text) == int(value)
        except (TypeError, ValueError):
            return None
    if op == "mode_not":
        return text.strip() != str(value).strip()
    return None


def run_check(check, snapshot):
    """在环境快照上执行一条基线检查，返回 (status, evidence)。

    status ∈ PASS / FAIL / UNKNOWN；UNKNOWN 表示快照缺少该项数据。
    """
    snapshot = snapshot or {}
    kind = (check or {}).get("kind")
    expect = (check or {}).get("expect") or {}
    actual = None
    evidence = ""
    if kind == "config":
        path = (check or {}).get("path")
        key = (check or {}).get("key")
        configs = snapshot.get("configs") or {}
        if path not in configs:
            return "UNKNOWN", "快照缺少配置文件 %s" % path
        table = configs.get(path) or {}
        if key not in table:
            # 未显式声明：对「必须有值 / 必须等于 / 必须包含」类断言按空值判失败；
            # 其余算子（not_contains 等）无法区分默认值，交由人工确认。
            if expect.get("op") in ("set", "eq", "contains", "regex"):
                actual = ""
                evidence = "%s 中未声明 %s，按空值判定" % (path, key)
            else:
                return "UNKNOWN", "%s 中未声明 %s，需人工确认默认值" % (path, key)
        else:
            actual = table.get(key)
            evidence = "%s:%s = %s" % (path, key, "（空）" if actual is None else actual)
    elif kind == "cli":
        command = (check or {}).get("command")
        outputs = snapshot.get("cli") or {}
        if command not in outputs:
            return "UNKNOWN", "快照缺少命令输出 %s" % command
        actual = outputs.get(command)
        evidence = "$ %s → %s" % (command, actual)
    elif kind == "http":
        url = (check or {}).get("url")
        responses = snapshot.get("http") or {}
        if url not in responses:
            return "UNKNOWN", "快照缺少探测结果 %s" % url
        response = responses.get(url) or {}
        actual = response.get("status")
        evidence = "GET %s → %s" % (url, actual)
    elif kind == "version":
        actual = snapshot.get("version")
        if actual is None:
            return "UNKNOWN", "快照缺少组件版本"
        evidence = "version = %s" % actual
    elif kind == "file":
        path = (check or {}).get("path")
        files = snapshot.get("files") or {}
        if path not in files:
            return "UNKNOWN", "快照缺少文件属性 %s" % path
        meta = files.get(path) or {}
        actual = meta.get("mode")
        evidence = "%s mode = %s" % (path, actual)
    else:
        return "UNKNOWN", "不支持的检查类型 %s" % kind

    verdict = _compare(actual, expect)
    if verdict is None:
        return "UNKNOWN", evidence
    return ("PASS" if verdict else "FAIL"), evidence


def run_item(item, snapshot):
    """执行单条基线项，返回结构化结果。"""
    status, evidence = run_check(item.get("check"), snapshot)
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "component": item.get("component"),
        "category": item.get("category"),
        "severity": item.get("severity"),
        "status": status,
        "evidence": evidence,
        "remediation": item.get("remediation"),
        "references": item.get("references") or [],
    }


def run_all(catalog, snapshot, name=None, deploy=None):
    """批量执行基线检查。"""
    if name:
        items = match(catalog, name, deploy=deploy)
    else:
        items = catalog
    return [run_item(item, snapshot) for item in items]


def write_catalog(catalog, path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"items": catalog}, handle, ensure_ascii=False, indent=2)
    return path
