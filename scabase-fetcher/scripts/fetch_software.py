"""常用应用 / 基础设施软件漏洞与健康度采集。

与「库」维度（purl 生态：maven / npm / pypi / go）平行，本脚本覆盖按产品管理的
服务器软件（nginx / 7-Zip / ZooKeeper / Kubernetes 等）：

  1. 漏洞：NVD CVE API 2.0 按 keywordSearch 拉取候选，本地用 CPE
     ``vendor:product`` 前缀精确过滤（一个软件可带多个前缀，如 MySQL 同时收录
     ``oracle:mysql`` 与 ``mysql:mysql``），提取 CVSS、影响版本区间、CWE 与参考链接；
  2. 健康度：复用 fetch_oss_health.collect_from_github 的全量 GitHub 信号
     （Star、最近提交、近 12 月发布、维护者/贡献者、PR 合并周期、安全策略、
     CI、背后组织；键名与 oss_intake.community 评分模块对齐），
     版本号取最新 GitHub Release，无 Release 的项目回退 tags；
     评分走 oss_intake.community。GitHub 调用使用 GITHUB_TOKEN
     （CI 默认注入；匿名限额 60 次/时，全量刷新必限流）。

任一来源失败只降级，不中断整批。产物：
  - scabase-fetcher/data/software-vulns.json   软件 → CVE 列表
  - scabase-fetcher/data/software-support.json 软件健康度评分卡

用法：
    python scabase-fetcher/scripts/fetch_software.py --refresh          # 全量联网采集
    python scabase-fetcher/scripts/fetch_software.py --refresh --only nginx --only redis
    python scabase-fetcher/scripts/fetch_software.py --fixtures tests/fixtures/software  # 离线回放
    python scabase-fetcher/scripts/fetch_software.py                    # 不带 --refresh 时保留已有产物
"""
import argparse
import json
import os
import re
import sys
import time
from urllib.parse import quote

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import fetch_oss_health as foh  # noqa: E402
from oss_intake import community as community_mod  # noqa: E402

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = 2000
# 无 API key 时限流 5 次 / 30 秒；配置 NVD_API_KEY 后放宽到 50 次 / 30 秒
NVD_INTERVAL = 6.5
NVD_INTERVAL_KEYED = 0.8
GITHUB_RELEASES = "https://api.github.com/repos/%s/releases?per_page=100"
GITHUB_LATEST_RELEASE = "https://api.github.com/repos/%s/releases/latest"
GITHUB_TAGS = "https://api.github.com/repos/%s/tags?per_page=100"
GITHUB_COMMITS_BY_REF = "https://api.github.com/repos/%s/commits?sha=%s&per_page=1"
# 无 GitHub Releases 时探测提交时间的 tag 数上限（按版本号取最新的若干个）。
# tags 接口不保证顺序（实测按 tag 名 ASCII 降序，古代 tag 反而在前），
# 因此先按版本号排序再探测，且只统计形态为纯版本的 tag。
TAG_PROBE_LIMIT = 12

# 常用软件清单。字段：
#   name     展示名 / 查询主键
#   category 分类（前端 chips 分组与清单浏览用）
#   aliases  输入别名（小写，含中文语境常见缩写；支持多词，如 "apache http server"）
#   keywords NVD keywordSearch 关键词（一般等于产品名）
#   cpe      CPE vendor:product 前缀列表（本地精确过滤；多前缀取并集）
#   repo     GitHub owner/repo（健康度信号来源，无则留空）
SOFTWARE = [
    {"name": "nginx", "category": "Web 服务器与代理", "aliases": ["nginx", "engine x", "enginex"],
     "keywords": ["nginx"], "cpe": ["f5:nginx", "nginx:nginx"],
     "repo": "nginx/nginx"},
    {"name": "7-Zip", "category": "压缩工具", "aliases": ["7zip", "7-zip", "7z", "p7zip"],
     "keywords": ["7-Zip"], "cpe": ["7-zip:7-zip", "igor_pavlov:7-zip"],
     "repo": "ip7z/7zip"},
    {"name": "ZooKeeper", "category": "协调与服务发现", "aliases": ["zookeeper", "zk", "zoo keeper"],
     "keywords": ["ZooKeeper"], "cpe": ["apache:zookeeper"],
     "repo": "apache/zookeeper"},
    {"name": "Kubernetes", "category": "容器与编排", "aliases": ["kubernetes", "k8s", "kube"],
     "keywords": ["Kubernetes"], "cpe": ["kubernetes:kubernetes"],
     "repo": "kubernetes/kubernetes"},
    {"name": "Redis", "category": "数据库与缓存", "aliases": ["redis"],
     "keywords": ["Redis"], "cpe": ["redis:redis", "redislabs:redis"],
     "repo": "redis/redis"},
    {"name": "MySQL", "category": "数据库与缓存", "aliases": ["mysql"],
     "keywords": ["MySQL"], "cpe": ["oracle:mysql", "mysql:mysql"],
     "repo": "mysql/mysql-server"},
    {"name": "PostgreSQL", "category": "数据库与缓存", "aliases": ["postgresql", "postgres", "pg"],
     "keywords": ["PostgreSQL"], "cpe": ["postgresql:postgresql"],
     "repo": "postgres/postgres"},
    {"name": "MariaDB", "category": "数据库与缓存", "aliases": ["mariadb"],
     "keywords": ["MariaDB"], "cpe": ["mariadb:mariadb"],
     "repo": "MariaDB/server"},
    {"name": "MongoDB", "category": "数据库与缓存", "aliases": ["mongodb", "mongo"],
     "keywords": ["MongoDB"], "cpe": ["mongodb:mongodb"],
     "repo": "mongodb/mongo"},
    {"name": "Apache HTTP Server", "category": "Web 服务器与代理", "aliases": ["httpd", "apache http server",
                                               "apache httpd", "apache2"],
     "keywords": ["httpd"], "cpe": ["apache:http_server"],
     "repo": "apache/httpd"},
    {"name": "OpenSSL", "category": "网络与安全基础", "aliases": ["openssl"],
     "keywords": ["OpenSSL"], "cpe": ["openssl:openssl"],
     "repo": "openssl/openssl"},
    {"name": "Docker Engine", "category": "容器与编排", "aliases": ["docker", "docker engine", "moby"],
     "keywords": ["Docker"], "cpe": ["docker:docker", "moby:moby"],
     "repo": "moby/moby"},
    {"name": "containerd", "category": "容器与编排", "aliases": ["containerd"],
     "keywords": ["containerd"], "cpe": ["containerd:containerd"],
     "repo": "containerd/containerd"},
    {"name": "runc", "category": "容器与编排", "aliases": ["runc"],
     "keywords": ["runc"], "cpe": ["opencontainers:runc", "linuxfoundation:runc"],
     "repo": "opencontainers/runc"},
    {"name": "etcd", "category": "协调与服务发现", "aliases": ["etcd"],
     "keywords": ["etcd"], "cpe": ["etcd-io:etcd", "redhat:etcd"],
     "repo": "etcd-io/etcd"},
    {"name": "CoreDNS", "category": "协调与服务发现", "aliases": ["coredns"],
     "keywords": ["CoreDNS"], "cpe": ["coredns:coredns"],
     "repo": "coredns/coredns"},
    {"name": "Helm", "category": "容器与编排", "aliases": ["helm"],
     "keywords": ["Helm"], "cpe": ["helm:helm"],
     "repo": "helm/helm"},
    {"name": "Istio", "category": "容器与编排", "aliases": ["istio"],
     "keywords": ["Istio"], "cpe": ["istio:istio"],
     "repo": "istio/istio"},
    {"name": "Cilium", "category": "容器与编排", "aliases": ["cilium"],
     "keywords": ["Cilium"], "cpe": ["cilium:cilium"],
     "repo": "cilium/cilium"},
    {"name": "Envoy", "category": "Web 服务器与代理", "aliases": ["envoy"],
     "keywords": ["Envoy"], "cpe": ["envoyproxy:envoy"],
     "repo": "envoyproxy/envoy"},
    {"name": "Traefik", "category": "Web 服务器与代理", "aliases": ["traefik"],
     "keywords": ["Traefik"], "cpe": ["traefik:traefik"],
     "repo": "traefik/traefik"},
    {"name": "HAProxy", "category": "Web 服务器与代理", "aliases": ["haproxy"],
     "keywords": ["HAProxy"], "cpe": ["haproxy:haproxy"],
     "repo": "haproxy/haproxy"},
    {"name": "Apache Kafka", "category": "消息与日志", "aliases": ["kafka"],
     "keywords": ["Kafka"], "cpe": ["apache:kafka"],
     "repo": "apache/kafka"},
    {"name": "Apache Tomcat", "category": "内容管理与应用", "aliases": ["tomcat"],
     "keywords": ["Tomcat"], "cpe": ["apache:tomcat"],
     "repo": "apache/tomcat"},
    {"name": "Elasticsearch", "category": "消息与日志", "aliases": ["elasticsearch", "es"],
     "keywords": ["Elasticsearch"], "cpe": ["elastic:elasticsearch"],
     "repo": "elastic/elasticsearch"},
    {"name": "Kibana", "category": "消息与日志", "aliases": ["kibana"],
     "keywords": ["Kibana"], "cpe": ["elastic:kibana"],
     "repo": "elastic/kibana"},
    {"name": "Logstash", "category": "消息与日志", "aliases": ["logstash"],
     "keywords": ["Logstash"], "cpe": ["elastic:logstash"],
     "repo": "elastic/logstash"},
    {"name": "Grafana", "category": "运维与可观测", "aliases": ["grafana"],
     "keywords": ["Grafana"], "cpe": ["grafana:grafana"],
     "repo": "grafana/grafana"},
    {"name": "Prometheus", "category": "运维与可观测", "aliases": ["prometheus"],
     "keywords": ["Prometheus"], "cpe": ["prometheus:prometheus"],
     "repo": "prometheus/prometheus"},
    {"name": "Jenkins", "category": "开发与构建", "aliases": ["jenkins"],
     "keywords": ["Jenkins"], "cpe": ["jenkins:jenkins"],
     "repo": "jenkinsci/jenkins"},
    {"name": "GitLab", "category": "开发与构建", "aliases": ["gitlab"],
     "keywords": ["GitLab"], "cpe": ["gitlab:gitlab"],
     "repo": "gitlab-org/gitlab"},
    {"name": "SonarQube", "category": "开发与构建", "aliases": ["sonarqube"],
     "keywords": ["SonarQube"], "cpe": ["sonarsource:sonarqube"],
     "repo": "SonarSource/sonarqube"},
    {"name": "Harbor", "category": "容器与编排", "aliases": ["harbor"],
     "keywords": ["Harbor"], "cpe": ["goharbor:harbor"],
     "repo": "goharbor/harbor"},
    {"name": "WordPress", "category": "内容管理与应用", "aliases": ["wordpress", "wp"],
     "keywords": ["WordPress"], "cpe": ["wordpress:wordpress"],
     "repo": "WordPress/WordPress"},
    {"name": "Drupal", "category": "内容管理与应用", "aliases": ["drupal"],
     "keywords": ["Drupal"], "cpe": ["drupal:drupal"],
     "repo": "drupal/drupal"},
    {"name": "Apache Struts", "category": "内容管理与应用", "aliases": ["struts"],
     "keywords": ["Struts"], "cpe": ["apache:struts"],
     "repo": "apache/struts"},
    {"name": "Apache Shiro", "category": "内容管理与应用", "aliases": ["shiro"],
     "keywords": ["Shiro"], "cpe": ["apache:shiro"],
     "repo": "apache/shiro"},
    {"name": "Apache Solr", "category": "内容管理与应用", "aliases": ["solr"],
     "keywords": ["Solr"], "cpe": ["apache:solr"],
     "repo": "apache/solr"},
    {"name": "Apache Spark", "category": "大数据处理", "aliases": ["spark"],
     "keywords": ["Spark"], "cpe": ["apache:spark"],
     "repo": "apache/spark"},
    {"name": "Apache Hadoop", "category": "大数据处理", "aliases": ["hadoop"],
     "keywords": ["Hadoop"], "cpe": ["apache:hadoop"],
     "repo": "apache/hadoop"},
    {"name": "Apache Flink", "category": "大数据处理", "aliases": ["flink"],
     "keywords": ["Flink"], "cpe": ["apache:flink"],
     "repo": "apache/flink"},
    {"name": "Apache Airflow", "category": "大数据处理", "aliases": ["airflow"],
     "keywords": ["Airflow"], "cpe": ["apache:airflow"],
     "repo": "apache/airflow"},
    {"name": "Apache ActiveMQ", "category": "消息与日志", "aliases": ["activemq"],
     "keywords": ["ActiveMQ"], "cpe": ["apache:activemq"],
     "repo": "apache/activemq"},
    {"name": "RabbitMQ", "category": "消息与日志", "aliases": ["rabbitmq"],
     "keywords": ["RabbitMQ"], "cpe": ["vmware:rabbitmq",
                                       "pivotal_software:rabbitmq"],
     "repo": "rabbitmq/rabbitmq-server"},
    {"name": "Memcached", "category": "数据库与缓存", "aliases": ["memcached"],
     "keywords": ["Memcached"], "cpe": ["memcached:memcached"],
     "repo": "memcached/memcached"},
    {"name": "curl", "category": "网络与安全基础", "aliases": ["curl"],
     "keywords": ["curl"], "cpe": ["haxx:curl", "haxx:libcurl"],
     "repo": "curl/curl"},
    {"name": "OpenSSH", "category": "网络与安全基础", "aliases": ["openssh"],
     "keywords": ["OpenSSH"], "cpe": ["openbsd:openssh"],
     "repo": "openssh/openssh-portable"},
    {"name": "ISC BIND", "category": "网络与安全基础", "aliases": ["bind", "bind9"],
     "keywords": ["BIND"], "cpe": ["isc:bind"],
     "repo": "isc-projects/bind9"},
    {"name": "Node.js", "category": "运行时与语言", "aliases": ["node.js", "nodejs", "node"],
     "keywords": ["Node.js"], "cpe": ["nodejs:node.js"],
     "repo": "nodejs/node"},
    {"name": "PHP", "category": "运行时与语言", "aliases": ["php"],
     "keywords": ["PHP"], "cpe": ["php:php"],
     "repo": "php/php-src"},
    {"name": "Python", "category": "运行时与语言", "aliases": ["python", "cpython"],
     "keywords": ["CPython"], "cpe": ["python:python"],
     "repo": "python/cpython"},
    {"name": "OpenJDK", "category": "运行时与语言", "aliases": ["openjdk", "jdk", "java"],
     "keywords": ["OpenJDK"], "cpe": ["oracle:openjdk"],
     "repo": "openjdk/jdk"},
    {"name": "Apache Maven", "category": "开发与构建", "aliases": ["maven"],
     "keywords": ["Maven"], "cpe": ["apache:maven"],
     "repo": "apache/maven"},
    {"name": "Gradle", "category": "开发与构建", "aliases": ["gradle"],
     "keywords": ["Gradle"], "cpe": ["gradle:gradle"],
     "repo": "gradle/gradle"},
    {"name": "Ansible", "category": "运维与可观测", "aliases": ["ansible"],
     "keywords": ["Ansible"], "cpe": ["redhat:ansible", "ansible:ansible"],
     "repo": "ansible/ansible"},
    {"name": "Terraform", "category": "运维与可观测", "aliases": ["terraform"],
     "keywords": ["Terraform"], "cpe": ["hashicorp:terraform"],
     "repo": "hashicorp/terraform"},
    {"name": "Vault", "category": "运维与可观测", "aliases": ["vault"],
     "keywords": ["Vault"], "cpe": ["hashicorp:vault"],
     "repo": "hashicorp/vault"},
    {"name": "Consul", "category": "协调与服务发现", "aliases": ["consul"],
     "keywords": ["Consul"], "cpe": ["hashicorp:consul"],
     "repo": "hashicorp/consul"},
    {"name": "systemd", "category": "运维与可观测", "aliases": ["systemd"],
     "keywords": ["systemd"], "cpe": ["systemd_project:systemd"],
     "repo": "systemd/systemd"},
    {"name": "Vim", "category": "系统与工具", "aliases": ["vim"],
     "keywords": ["Vim"], "cpe": ["vim:vim"],
     "repo": "vim/vim"},
    {"name": "Linux Kernel", "category": "系统与工具", "aliases": ["linux kernel", "linux", "kernel"],
     "keywords": ["Linux Kernel"], "cpe": ["linux:linux_kernel"],
     "repo": "torvalds/linux"},
    {"name": "Nacos", "category": "协调与服务发现", "aliases": ["nacos"],
     "keywords": ["Nacos"], "cpe": ["alibaba:nacos"],
     "repo": "alibaba/nacos"},
    {"name": "Seata", "category": "协调与服务发现", "aliases": ["seata"],
     "keywords": ["Seata"], "cpe": ["apache:seata", "seata:seata"],
     "repo": "apache/incubator-seata"},
    {"name": "Squid", "category": "Web 服务器与代理", "aliases": ["squid"],
     "keywords": ["Squid"], "cpe": ["squid-cache:squid"],
     "repo": "squid-cache/squid"},
    {"name": "vsftpd", "category": "Web 服务器与代理", "aliases": ["vsftpd"],
     "keywords": ["vsftpd"], "cpe": ["vsftpd_project:vsftpd",
                                     "beastie:vsftpd"],
     "repo": ""},
]

DESC_LIMIT = 300
REF_LIMIT = 5


# ---------------------------------------------------------------- 纯函数（可离线测试）

def normalize_version(value):
    """统一版本形态：去 v 前缀、去首尾空白。"""
    text = str(value or "").strip()
    if text[:1] in ("v", "V") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    return text


def parse_release_version(tag):
    """从 GitHub release tag 提取版本号。

    覆盖常见 tag 形态：``v1.24.0`` / ``release-1.24.0`` / ``openssl-4.0.3`` /
    ``docker-v29.9.1`` / ``curl-8_23_0`` → 纯版本号。
    """
    text = str(tag or "").strip()
    # 去掉项目名前缀（release- / openssl- / docker-v 等），保留 v 前缀版本号
    text = re.sub(r"^[A-Za-z][\w.]*?[-_]v?", "", text, count=1)
    text = text.replace("_", ".")
    return normalize_version(text)


def version_tuple(value):
    """把版本拆为可比较的数字元组（1.24.0 / 23.01 / 2.14.1-rc1 → (1,24,0)）。"""
    text = normalize_version(value)
    if not text:
        return ()
    core = re.split(r"[-+]", text, 1)[0]
    parts = []
    for seg in core.split("."):
        digits = re.match(r"\d+", seg)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def _clean_bound(value):
    text = str(value or "").strip()
    return None if text in ("", "-", "*") else text


def version_affected(match, version):
    """判断 NVD CPE match 的版本区间是否命中给定版本。

    match 为 cpeMatch 字典（versionStartIncluding 等字段，NVD 用 "-" 表示未设置）。
    未提供版本时返回 True（查询侧决定是否展示全部）。
    """
    given = normalize_version(version)
    if not given:
        return True
    start_in = _clean_bound(match.get("versionStartIncluding"))
    start_ex = _clean_bound(match.get("versionStartExcluding"))
    end_in = _clean_bound(match.get("versionEndIncluding"))
    end_ex = _clean_bound(match.get("versionEndExcluding"))
    given_key = version_tuple(given)
    if start_in and given_key < version_tuple(start_in):
        return False
    if start_ex and given_key <= version_tuple(start_ex):
        return False
    if end_in and given_key > version_tuple(end_in):
        return False
    if end_ex and given_key >= version_tuple(end_ex):
        return False
    return True


def cpe_vendor_product(criteria):
    """从 CPE criteria 提取 vendor:product（非 application 类型返回 None）。"""
    parts = str(criteria or "").split(":")
    if len(parts) < 5 or parts[2] != "a":
        return None
    vendor, product = parts[3], parts[4]
    if not vendor or not product:
        return None
    return "%s:%s" % (vendor, product)


def cve_touches_software(cve, prefixes):
    """该 CVE 的 CPE match 是否命中软件前缀列表；返回命中的 match 列表。"""
    wanted = set(prefixes or [])
    if not wanted:
        return []
    hits = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                vp = cpe_vendor_product(match.get("criteria"))
                if vp and vp in wanted:
                    hits.append(match)
    return hits


def best_cvss(cve):
    """取最高优先级 CVSS（3.1 > 3.0 > 2.0），返回 (score, severity)。"""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key) or []
        if items:
            data = items[0].get("cvssData") or {}
            score = data.get("baseScore")
            severity = items[0].get("baseSeverity") or data.get("baseSeverity")
            if score is not None:
                return score, severity or ""
    items = metrics.get("cvssMetricV2") or []
    if items:
        data = items[0].get("cvssData") or {}
        score = data.get("baseScore")
        if score is not None:
            return score, items[0].get("baseSeverity") or ""
    return None, ""


def _english_description(cve):
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return item.get("value") or ""
    values = [item.get("value") for item in cve.get("descriptions") or []]
    return values[0] if values else ""


def cve_record(cve, hits):
    """NVD CVE → 站点展示用结构（描述截断、参考限量、版本区间去重）。"""
    score, severity = best_cvss(cve)
    weaknesses = []
    for item in cve.get("weaknesses") or []:
        for desc in item.get("description") or []:
            value = desc.get("value")
            if value and value.startswith("CWE-") and value not in weaknesses:
                weaknesses.append(value)
    ranges = []
    seen = set()
    for match in hits:
        key = (
            _clean_bound(match.get("versionStartIncluding")),
            _clean_bound(match.get("versionStartExcluding")),
            _clean_bound(match.get("versionEndIncluding")),
            _clean_bound(match.get("versionEndExcluding")),
        )
        if key in seen:
            continue
        seen.add(key)
        ranges.append({
            "start_including": key[0],
            "start_excluding": key[1],
            "end_including": key[2],
            "end_excluding": key[3],
        })
    references = []
    for ref in cve.get("references") or []:
        url = ref.get("url")
        if url and url not in references:
            references.append(url)
        if len(references) >= REF_LIMIT:
            break
    description = _english_description(cve)
    if len(description) > DESC_LIMIT:
        description = description[:DESC_LIMIT].rstrip() + "…"
    return {
        "id": cve.get("id"),
        "description": description,
        "cvss": score,
        "severity": severity,
        "published": (cve.get("published") or "")[:10],
        "weaknesses": weaknesses,
        "affected": ranges,
        "references": references,
    }


# ---------------------------------------------------------------- 采集

def _get_json(url, token=None, timeout=40, attempts=3, auth_style="apiKey"):
    """GET JSON。NVD 用 apiKey 头，GitHub 用 Authorization 头。"""
    headers = {"Accept": "application/json"}
    if token:
        if auth_style == "apiKey":
            headers["apiKey"] = token
        else:
            headers["Authorization"] = "token %s" % token
    last_error = None
    for attempt in range(attempts):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            last_error = "HTTP %s" % resp.status_code
            if resp.status_code in (403, 429):  # 限流：退避后重试
                time.sleep(min(30, 10 * (attempt + 1)))
                continue
            if resp.status_code == 404:
                return None
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(2 * (attempt + 1))
    print("  请求失败 %s：%s" % (url[:90], last_error), file=sys.stderr)
    return None


def fetch_nvd_cves(entry, token=None):
    """keywordSearch 拉全 + CPE 前缀过滤，返回结构化 CVE 列表（按发布时间倒序）。"""
    records = []
    seen = set()
    for keyword in entry.get("keywords") or []:
        start = 0
        while True:
            url = ("%s?keywordSearch=%s&resultsPerPage=%d&startIndex=%d"
                   % (NVD_API, quote(keyword), NVD_PAGE, start))
            payload = _get_json(url, token=token)
            if not payload:
                break
            vulns = payload.get("vulnerabilities") or []
            for item in vulns:
                cve = item.get("cve") or {}
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen:
                    continue
                hits = cve_touches_software(cve, entry.get("cpe"))
                if not hits:
                    continue
                seen.add(cve_id)
                records.append(cve_record(cve, hits))
            total = payload.get("totalResults") or 0
            start += NVD_PAGE
            if start >= total or not vulns:
                break
    records.sort(key=lambda r: r.get("published") or "", reverse=True)
    return records


def _looks_like_version(text):
    """严格版本形态：纯数字加点（18.1 / 23.01 / 1.24.0）。

    tag 回退用它过滤 ``master`` / ``REL_18_STABLE`` 之类的分支与里程碑 tag，
    避免把非版本串当成版本写进卡片。
    """
    return bool(re.match(r"^\d+(\.\d+)*$", str(text or "")))


def _tag_release_signals(repo, token=None, probe_limit=TAG_PROBE_LIMIT):
    """tag 回退信号：``{"version": ..., "releases_12m": ...}`` 或 ``{}``。

    未建 GitHub Release 的项目（PostgreSQL 只打 tag、MySQL 部分产品线不走
    Release）用 tag 当发布记录：

    - 只收形态为纯版本的 tag（``REL_18_1`` → 18.1），过滤 ``master`` /
      ``REL_18_STABLE`` 之类的分支 tag——它们指向分支顶端，会把发布节奏算虚高；
    - 版本号按 ``version_tuple`` 取最大（tags 接口不保证顺序，不能取第一条）；
    - 发布节奏：对版本最高的前 ``probe_limit`` 个 tag 用
      ``commits?sha=<tag>`` 取被打标签的提交时间（兼容轻量 tag），
      统计近 12 个月的数量。``commits?sha`` 返回的是该 ref 的祖先，
      首条即被打标签的提交本身。
    """
    tags = _get_json(GITHUB_TAGS % repo, token=token, auth_style="bearer") or []
    if not isinstance(tags, list):
        return {}
    versioned = []
    for tag in tags:
        parsed = parse_release_version(tag.get("name"))
        if parsed and _looks_like_version(parsed):
            key = version_tuple(parsed)
            if key:
                versioned.append((tag.get("name"), parsed, key))
    if not versioned:
        return {}
    versioned.sort(key=lambda item: item[2], reverse=True)
    signals = {"version": versioned[0][1]}
    stamps = []
    for name, _parsed, _key in versioned[:probe_limit]:
        payload = _get_json(GITHUB_COMMITS_BY_REF % (repo, quote(str(name), safe="")),
                            token=token, auth_style="bearer") or []
        if not isinstance(payload, list) or not payload:
            continue
        commit = (payload[0].get("commit") or {})
        stamps.append((commit.get("committer") or {}).get("date")
                      or (commit.get("author") or {}).get("date"))
    if stamps:
        signals["releases_12m"] = foh.count_within(stamps)
    return signals


def _release_version(repo, token=None):
    """从 GitHub Releases 取最新稳定版本（不含 tags 回退）。"""
    releases = _get_json(GITHUB_RELEASES % repo, token=token,
                         auth_style="bearer") or []
    if isinstance(releases, list):
        for release in releases:
            if release.get("draft") or release.get("prerelease"):
                continue
            parsed = parse_release_version(release.get("tag_name"))
            if parsed:
                return parsed
    latest = _get_json(GITHUB_LATEST_RELEASE % repo, token=token,
                       auth_style="bearer") or {}
    if isinstance(latest, dict):
        parsed = parse_release_version(latest.get("tag_name"))
        if parsed:
            return parsed
    return None


def _latest_release_version(repo, token=None):
    """最新发布版本：GitHub Releases → /releases/latest → tags 回退。"""
    version = _release_version(repo, token)
    if version:
        return version
    return (_tag_release_signals(repo, token) or {}).get("version")


def _github_token(env=None):
    """GitHub API token。

    CI 由 software-collect.yml 注入 ``GITHUB_TOKEN``（1000 次/时）；
    本地未配置时退化为匿名（60 次/时，仅够少量 ``--only`` 刷新）。
    曾因只读 ``NVD_API_KEY`` 而使 GitHub 调用全匿名：限流后 65 个软件里
    42 个连仓库信息都没采到（stars / org_backing 全空）。
    """
    env = os.environ if env is None else env
    return env.get("GITHUB_TOKEN") or None


def fetch_software_health(repo, token=None):
    """GitHub 全量信号（复用库维度采集器）+ 最新发布版本。

    信号键名与 ``oss_intake.community`` 评分模块严格对齐：
    ``last_commit_days`` / ``releases_12m`` / ``maintainers`` /
    ``contributors`` / ``pr_merge_days`` / ``has_security_policy`` /
    ``has_ci`` / ``org_backing`` / ``stars`` / ``archived``。
    历史教训：本函数曾自建信号集并写入 ``pushed_days``（评分模块只认
    ``last_commit_days``），导致全部软件的「最近提交」被静默丢弃，
    社区活跃度评分系统性偏低。

    无（近 12 月）GitHub Release 的项目（PostgreSQL 等）用 tag 补发布
    节奏与版本，避免「卡片显示 18.6 却说 12 个月无发布」的自相矛盾；
    tags 全流程只探测一次（版本与节奏共用），控制匿名限额下的请求数。
    """
    if not repo:
        return {}, None
    health = foh.collect_from_github(repo, token)
    if not health:
        return {}, None
    health = dict(health)
    version = _release_version(repo, token)
    if not version or not health.get("releases_12m"):
        tag_signals = _tag_release_signals(repo, token)
        if not health.get("releases_12m") and tag_signals.get("releases_12m") is not None:
            health["releases_12m"] = tag_signals["releases_12m"]
        if not version:
            version = tag_signals.get("version")
    return health, version


def build_support_row(name, entry, health, version):
    """评分卡（结构与 community-support.json 对齐，前端可直接复用渲染）。"""
    result = community_mod.evaluate(health)
    return {
        "purl": "pkg:generic/%s@%s" % (name.lower().replace(" ", "-"),
                                       version or ""),
        "display": "%s%s" % (name, (" " + version) if version else ""),
        "software": name,
        "eco": "software",
        "version": version,
        "score": result["score"],
        "grade": result["grade"],
        "level": result["level"],
        "archived": bool(health.get("archived")),
        "last_commit_days": (result.get("signals") or {}).get("last_commit_days"),
        "releases_12m": (result.get("signals") or {}).get("releases_12m"),
        "maintainers": (result.get("signals") or {}).get("maintainers"),
        "org_backing": (result.get("signals") or {}).get("org_backing"),
        "monthly_downloads": None,
        "stars": health.get("stars"),
        "forks": health.get("forks"),
        "watchers": health.get("watchers"),
        "repo": entry.get("repo") or None,
        "sources": ["github"] if entry.get("repo") else [],
        "missing": result.get("missing") or [],
        "advice": result.get("advice"),
    }


def _select_entries(only):
    if not only:
        return SOFTWARE
    wanted = {name.lower() for name in only}
    return [e for e in SOFTWARE
            if e["name"].lower() in wanted
            or any(a in wanted for a in e.get("aliases") or [])]


def _load_json(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _fixture_payload(base, name, kind):
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    path = os.path.join(base, "%s-%s.json" % (slug, kind))
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_document(refresh, token, only=None, fixtures=None, health=True,
                   existing_vulns=None, existing_support=None, gh_token=None,
                   include_vulns=True):
    """组装两份产物数据。

    refresh   ：联网采集；否则沿用 existing_* 里的旧数据（离线转换场景）
    fixtures  ：本地回放目录，文件名为 <slug>-cves.json / <slug>-health.json
    gh_token  ：GitHub API token（GITHUB_TOKEN）；缺省时匿名调用、限流严格
    include_vulns：False 时跳过 NVD，只刷健康度（--no-vulns），用于配额紧张时
                   单独补 GitHub 信号；未选中的软件仍沿用旧漏洞数据
    """
    existing_vulns = existing_vulns or {}
    existing_support = existing_support or {}
    prior_cves = {s["name"]: s for s in existing_vulns.get("software") or []}
    prior_rows = {r.get("software"): r for r in existing_support.get("components") or []}
    selected = None
    if only:
        selected = {e["name"] for e in _select_entries(only)}

    software = []
    support_rows = []
    interval = NVD_INTERVAL_KEYED if token else NVD_INTERVAL
    for entry in SOFTWARE:
        name = entry["name"]
        if selected is not None and name not in selected:
            # --only 刷新时，未选中的软件沿用旧数据，避免产物丢掉其余条目
            prior = prior_cves.get(name) or {}
            cves = prior.get("cves") or []
            software.append({
                "name": name,
                "category": entry.get("category") or "",
                "aliases": entry.get("aliases") or [],
                "cpe": entry.get("cpe") or [],
                "repo": entry.get("repo") or None,
                "cve_count": len(cves),
                "cves": cves,
            })
            row = prior_rows.get(name)
            if health and row:
                support_rows.append(row)
            continue
        print("采集 %s …" % name, file=sys.stderr)
        if fixtures:
            cves = _fixture_payload(fixtures, name, "cves") or []
            fixture_health = _fixture_payload(fixtures, name, "health") or {}
            gh_health = fixture_health.get("health") or {}
            version = fixture_health.get("version")
            support_row = fixture_health.get("row")
            if support_row is None:
                support_row = build_support_row(name, entry, gh_health, version)
        elif refresh:
            cves = fetch_nvd_cves(entry, token=token) if include_vulns \
                else (prior_cves.get(name) or {}).get("cves") or []
            gh_health, version = ({}, None)
            if health:
                gh_health, version = fetch_software_health(
                    entry.get("repo"), token=gh_token)
            support_row = build_support_row(name, entry, gh_health, version) \
                if health else None
        else:
            cves = (prior_cves.get(name) or {}).get("cves") or []
            support_row = prior_rows.get(name)
        software.append({
            "name": name,
            "category": entry.get("category") or "",
            "aliases": entry.get("aliases") or [],
            "cpe": entry.get("cpe") or [],
            "repo": entry.get("repo") or None,
            "cve_count": len(cves),
            "cves": cves,
        })
        if health and support_row:
            support_rows.append(support_row)
        # 跳过 NVD 时无需遵守 NVD 的请求间隔（6.5s/条），避免无谓等待
        if refresh and not fixtures and include_vulns:
            time.sleep(interval)
    vulns_doc = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "NVD CVE API 2.0（keywordSearch + CPE vendor:product 过滤）",
        "software_count": len(software),
        "software": software,
    }
    grades = {}
    for row in support_rows:
        grades[row["grade"]] = grades.get(row["grade"], 0) + 1
    support_doc = {
        "generated_at": vulns_doc["generated_at"],
        "component_count": len(support_rows),
        "grade_counts": grades,
        "components": support_rows,
    }
    return vulns_doc, support_doc


def write_json(path, payload):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))


def main():
    parser = argparse.ArgumentParser(description="常用软件漏洞与健康度采集")
    parser.add_argument("--refresh", action="store_true", help="联网采集")
    parser.add_argument("--no-health", action="store_true", help="跳过健康度采集")
    parser.add_argument("--no-vulns", action="store_true",
                        help="跳过 NVD，只刷 GitHub 健康度信号（未选中条目沿用旧漏洞数据）")
    parser.add_argument("--only", action="append", default=[],
                        help="只采集指定软件（可多次，按名称或别名）")
    parser.add_argument("--fixtures", help="离线回放目录（测试用）")
    parser.add_argument("--out-vulns", default="scabase-fetcher/data/software-vulns.json")
    parser.add_argument("--out-support", default="scabase-fetcher/data/software-support.json")
    args = parser.parse_args()

    if args.refresh and requests is None:
        print("缺少 requests，无法联网采集", file=sys.stderr)
        return 2
    token = os.getenv("NVD_API_KEY")
    gh_token = _github_token()
    if args.refresh and not gh_token:
        print("未配置 GITHUB_TOKEN：GitHub 匿名限额 60 次/时，"
              "全量刷新会大面积限流失败（建议本地 --only 单软件验证）",
              file=sys.stderr)
    vulns_doc, support_doc = build_document(
        args.refresh, token, only=args.only, fixtures=args.fixtures,
        health=not args.no_health,
        existing_vulns=_load_json(args.out_vulns),
        existing_support=_load_json(args.out_support),
        gh_token=gh_token, include_vulns=not args.no_vulns)
    # --no-vulns 时漏洞数据完全沿用旧文件：不重写 generated_at，
    # 避免 7MB 的 software-vulns.json 每轮都产生巨大 diff
    if not args.no_vulns:
        write_json(args.out_vulns, vulns_doc)
    if not args.no_health:
        write_json(args.out_support, support_doc)
    total_cves = sum(s["cve_count"] for s in vulns_doc["software"])
    print("软件 %d 个，CVE %d 条 → %s" % (
        vulns_doc["software_count"], total_cves, args.out_vulns))
    return 0


if __name__ == "__main__":
    sys.exit(main())
