#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成机器可读数据索引 ``scabase-fetcher/data/index.json``。

LLM / 外部工具通过 WebFetch 取数时，先读 index.json 即可获知每个已发布数据集的
URL、字节数、sha256、schema 与内嵌 ``generated_at``，无需猜测路径或反复试探。
本文件由构建流程（pages.yml / 镜像构建）重新生成，字节数与哈希始终与实际产物一致。

用法::

    python gen_data_index.py                  # 默认数据目录 + https://scabase.roweb.cn
    python gen_data_index.py --data <dir> --out <file> --base-url https://example.com
"""
import argparse
import hashlib
import json
import os
import sys
import time

BASE_URL_DEFAULT = "https://scabase.roweb.cn"
OUT_DEFAULT = os.path.join("scabase-fetcher", "data", "index.json")

# 站点实际发布的数据集（与 pages.yml / Dockerfile 拷贝清单保持一致）。
# schema 为摘要描述；字段名以各数据集真实内容为准。
DATASETS = [
    {
        "id": "vulns",
        "file": "vulns.json",
        "title": "漏洞库（OSV + NVD）",
        "format": "json",
        "update": "每日（GitHub Action 采集）",
        "schema": {
            "type": "object",
            "key": "ecosystem|package|version（ecosystem ∈ maven/npm/pypi/go；Maven 的 package 为 groupId:artifactId）",
            "value": {
                "osv_raw": {"vulns": "OSV 原始记录列表"},
                "enriched": [{"osv": "OSV 记录", "nvd": "NVD CVE 记录"}],
            },
        },
        "llm_hint": "组件→漏洞主查找表，key 精确匹配，例：npm|lodash|4.17.20；"
                    "反查 CVE 时遍历 key 并匹配 enriched[].osv.id / aliases",
    },
    {
        "id": "popular-packages",
        "file": "popular-packages.json",
        "title": "常用依赖 Top 清单（四生态各 1000）",
        "format": "json",
        "update": "手动 / 按需刷新",
        "schema": {
            "type": "object",
            "fields": {
                "generated_at": "生成时间（UTC）",
                "source": "数据源说明",
                "notes": "备注",
                "lists": "按生态分组，见下",
            },
            "list": {
                "key": "生态标识（maven/npm/pypi/go）",
                "label": "展示名",
                "ecosystem": "同 key",
                "count": "条目数",
                "rank_basis": "排序依据",
                "items": [{"rank": "排名", "name": "包名", "version": "版本",
                           "desc": "说明", "line": "ecosystem|package|version 查询行",
                           "meta": "热度元数据（按生态：weekly_downloads / monthly_downloads / dependents / stars）"}],
            },
        },
        "llm_hint": "热门组件清单；item.line 可直接作为 vulns.json 的 key 前缀参考",
    },
    {
        "id": "community-support",
        "file": "community-support.json",
        "title": "社区支持力度与活跃度报告",
        "format": "json",
        "update": "每日（GitHub Action 采集）",
        "schema": {
            "type": "object",
            "fields": {
                "generated_at": "生成时间（UTC）",
                "component_count": "组件数",
                "grade_counts": "各等级组件数",
                "missing_signal_counts": "缺失信号统计",
                "source_counts": "各数据来源覆盖的组件数",
                "components": "组件评分卡列表，见下",
            },
            "component": {
                "purl": "Package URL",
                "display": "展示名",
                "eco": "生态",
                "score": "评分",
                "grade": "A/B/C/D",
                "level": "等级中文名",
                "archived": "是否已归档",
                "sources": "信号来源列表（github / deps.dev / npm-registry / pypi / repo-map）",
                "repo": "GitHub owner/repo（有则可点击核对仓库）",
                "deps_dev": "deps.dev 包页面 URL（可点击核对发布与依赖数据）",
                "registry": "生态注册表页面 URL（npmjs.com / PyPI / Maven Central / pkg.go.dev）",
                "missing": "缺失信号列表",
                "advice": "建议",
            },
        },
        "llm_hint": "组件级健康度；评分遵循「未知即风险」，archived 直接判 D",
    },
    {
        "id": "pkg-list",
        "file": "pkg_list.txt",
        "title": "基础组件清单",
        "format": "text",
        "update": "随仓库维护",
        "schema": {"type": "text", "line": "ecosystem|package|version，# 开头为注释"},
        "llm_hint": "站点默认展示的组件清单",
    },
    {
        "id": "pkg-list-popular",
        "file": "pkg_list_popular.txt",
        "title": "常用依赖采集清单（四生态各前 100）",
        "format": "text",
        "update": "随 popular-packages.json 生成",
        "schema": {"type": "text", "line": "ecosystem|package|version，# 开头为注释"},
        "llm_hint": "约 400 行的小体积热门组件清单，适合作为首批拉取",
    },
    {
        "id": "repo-map",
        "file": "repo-map.json",
        "title": "purl → GitHub 仓库映射",
        "format": "json",
        "update": "随仓库维护",
        "schema": {"type": "object", "key": "purl", "value": "owner/repo"},
        "llm_hint": "把组件关联到源码仓库，例：pkg:npm/lodash@4.17.20 → lodash/lodash",
    },
]

DATA_PREFIX = "/scabase-fetcher/data/"


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def embedded_generated_at(path):
    """读取 JSON 数据集内嵌的 generated_at（若有）。"""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return None
    if isinstance(payload, dict):
        stamp = payload.get("generated_at")
        if isinstance(stamp, str) and stamp:
            return stamp
    return None


def build_index(data_dir, base_url):
    base_url = (base_url or BASE_URL_DEFAULT).rstrip("/")
    datasets = []
    for meta in DATASETS:
        path = os.path.join(data_dir, meta["file"])
        if not os.path.exists(path):
            print("跳过不存在的数据集：%s" % path, file=sys.stderr)
            continue
        entry = dict(meta)
        entry["path"] = DATA_PREFIX + meta["file"]
        entry["url"] = base_url + DATA_PREFIX + meta["file"]
        entry["bytes"] = os.path.getsize(path)
        entry["sha256"] = sha256_of(path)
        stamp = embedded_generated_at(path)
        if stamp:
            entry["generated_at"] = stamp
        datasets.append(entry)
    return {
        "site": "ScaBase",
        "description": "开源组件漏洞与社区支持查询站的机器可读数据索引；"
                       "字段 llm_hint 面向通过 WebFetch 取数的智能体",
        "base_url": base_url,
        "llms_txt": base_url + "/llms.txt",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "datasets": datasets,
    }


def main():
    parser = argparse.ArgumentParser(description="生成机器可读数据索引 index.json")
    parser.add_argument("--data", default=os.path.join("scabase-fetcher", "data"),
                        help="数据目录（默认 scabase-fetcher/data）")
    parser.add_argument("--out", default=OUT_DEFAULT, help="输出路径")
    parser.add_argument("--base-url", default=BASE_URL_DEFAULT,
                        help="站点对外地址（默认 https://scabase.roweb.cn）")
    args = parser.parse_args()

    index = build_index(args.data, args.base_url)
    if not index["datasets"]:
        print("数据目录 %s 下没有已发布的数据集" % args.data, file=sys.stderr)
        return 1
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(index, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print("已写入 %s（%d 个数据集）" % (args.out, len(index["datasets"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
