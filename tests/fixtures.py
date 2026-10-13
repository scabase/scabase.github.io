"""测试辅助：构建临时事实层与示例数据。

不依赖网络，全部使用本地 fixture。
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from oss_intake import facts as facts_mod  # noqa: E402

EXAMPLES = os.path.join(ROOT, "examples")


def sample_vulns():
    """三条组件的漏洞情报，覆盖 KEV / 无修复 / 干净 三种情形。"""
    return {
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "cves": [{
                "id": "CVE-2021-44228",
                "cvss": 10.0,
                "kev": True,
                "epss": 0.97,
                "fixed": ["2.15.0"],
                "published": "2021-12-10T10:15:00",
            }],
            "max_cvss": 10.0,
            "kev_count": 1,
            "unfixed_count": 0,
        },
        "pkg:maven/com.alibaba/fastjson@1.2.24": {
            "purl": "pkg:maven/com.alibaba/fastjson@1.2.24",
            "cves": [{
                "id": "CVE-2022-25845",
                "cvss": 9.8,
                "kev": False,
                "epss": 0.12,
                "fixed": [],
                "published": "2022-06-20T00:00:00",
            }],
            "max_cvss": 9.8,
            "kev_count": 0,
            "unfixed_count": 1,
        },
        "pkg:maven/org.springframework/spring-core@5.3.20": {
            "purl": "pkg:maven/org.springframework/spring-core@5.3.20",
            "cves": [],
            "max_cvss": 0.0,
            "kev_count": 0,
            "unfixed_count": 0,
        },
    }


def sample_health():
    return {
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {
            "archived": False,
            "deprecated": False,
            "last_commit_days": 20,
            "releases_12m": 6,
            "maintainers": 8,
            "issue_response_hours": 72,
        },
        "pkg:maven/com.alibaba/fastjson@1.2.24": {
            "archived": True,
            "deprecated": False,
            "last_commit_days": 900,
            "releases_12m": 0,
            "maintainers": 1,
            "issue_response_hours": 1200,
        },
        "pkg:maven/org.springframework/spring-core@5.3.20": {
            "archived": False,
            "deprecated": False,
            "last_commit_days": 5,
            "releases_12m": 12,
            "maintainers": 20,
            "issue_response_hours": 24,
        },
    }


def sample_license():
    return {
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {
            "spdx": "Apache-2.0", "category": "permissive"},
        "pkg:maven/com.alibaba/fastjson@1.2.24": {
            "spdx": "Apache-2.0", "category": "permissive"},
        "pkg:maven/org.springframework/spring-core@5.3.20": {
            "spdx": "Apache-2.0", "category": "permissive"},
    }


def build_store(root=None, generated_at=None):
    """建一个填满示例数据的事实层。"""
    root = root or tempfile.mkdtemp(prefix="oss-intake-facts-")
    store = facts_mod.FactsStore(root).ensure()
    for purl_value, payload in sample_vulns().items():
        store.upsert("vulns", purl_value, payload)
    for purl_value, payload in sample_health().items():
        store.upsert("health", purl_value, payload)
    for purl_value, payload in sample_license().items():
        store.upsert("license", purl_value, payload)
    for dataset in ("vulns", "health", "license"):
        store.bump(dataset, generated_at=generated_at)
    store.save_meta()
    return root


def tmp_facts():
    return tempfile.mkdtemp(prefix="oss-intake-facts-")


def cleanup(path):
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    elif os.path.exists(path):
        os.remove(path)


def load_example(name):
    with open(os.path.join(EXAMPLES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)
