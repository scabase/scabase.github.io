"""命令行入口。

  inventory   摄入应用资产 SBOM / GAV 台账，写入事实层 inventory 数据集
  scan        扫描源码目录中的原生依赖文件（pom.xml / package.json / requirements.txt …）
  gate        引入前评估 / CI 门禁（单组件或整份 SBOM），可导出 SARIF / JUnit / MR 评论
  assess      应用群组存量风险评估
  patrol      漏洞影响范围与安全基线自动化巡检，输出工单与增量对比
  baseline    安全配置基线目录查询与现场执行
  genscript   AI 智能体生成基线/漏洞检测脚本（SRE 运维平台 / 代码扫描中心 / 通用）
  verify      生成脚本的准确率回归校验（目标准确率 ≥90%）
  depinfo        depinfo 台账导入与结论回传
  bundle      构建离线摆渡数据包（互联网侧）
  import      导入数据包（内网侧）
  confidence  查看事实层数据水位与置信度
"""
import argparse
import json
import os
import sys

from . import assessment
from . import assets as assets_mod
from . import baseline as baseline_mod
from . import depfile
from . import facts as facts_mod
from . import patrol as patrol_mod
from . import policy as policy_mod
from . import purl
from . import report as report_mod
from . import sbom as sbom_mod
from . import scoring
from . import scriptgen
from . import sync as sync_mod
from . import verify as verify_mod
from .integrations import cicd as cicd_mod
from .integrations import depinfo as depinfo_mod

FAIL_LEVELS = {
    "never": [],
    "deny": ["Deny"],
    "review": ["Deny", "Review"],
    "condition": ["Deny", "Review", "Allow-with-condition"],
}


def _ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _store(root):
    return facts_mod.FactsStore(root).ensure()


def _confidences(store, policy):
    return {
        name: store.confidence(
            name,
            policy.get("freshness_sla_days", 14),
            policy.get("freshness_grace_days", 3),
        )
        for name in ("vulns", "health", "license", "inventory")
    }


def cmd_inventory(args):
    store = _store(args.facts)
    data = assets_mod.load_assets(args.assets)
    summary = assets_mod.build_inventory(store, data, base_dir=args.base_dir)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_gate(args):
    store = _store(args.facts)
    policy = policy_mod.load_policy(args.policy)
    confidences = _confidences(store, policy)
    profile = args.profile or policy.get("default_profile")

    results = []
    if args.purl:
        component = store.component(args.purl)
        usage = component.get("usage") or {}
        if args.tier:
            usage["tier"] = args.tier
        if args.exposure:
            usage["exposure"] = args.exposure
        if args.data_sensitivity:
            usage["data_sensitivity"] = args.data_sensitivity
        if usage:
            component["usage"] = usage
        results.append(scoring.evaluate(component, policy=policy,
                                        confidences=confidences,
                                        profile=profile,
                                        human_reviewed=args.human_reviewed))
        source = args.purl
    else:
        # 原生依赖文件（pom.xml / package.json / requirements.txt / go.mod …）优先走 depfile，
        # 它比 sbom.ingest 覆盖更全；SBOM（CycloneDX / SPDX / lock 产物）走 sbom。
        native = depfile.parse_file(args.sbom)
        if native is not None:
            components = sbom_mod.dedupe(native["components"])
            unresolved = native["unresolved"]
        else:
            ingested = sbom_mod.ingest(args.sbom)
            components = sbom_mod.dedupe(ingested["components"])
            unresolved = ingested["unresolved"]
        if not components:
            # 解析不出任何组件时必须显式失败，MUST NOT 静默放行
            print("未能从 %s 解析出任何组件（未解析条目 %d 个），门禁中止" % (
                args.sbom, len(unresolved)), file=sys.stderr)
            return 2
        source = args.sbom
        for comp in components:
            component = store.component(comp["purl"])
            usage = component.get("usage") or {}
            usage["direct"] = comp.get("direct", usage.get("direct"))
            component["usage"] = usage or None
            result = scoring.evaluate(component, policy=policy,
                                      confidences=confidences, profile=profile)
            result["direct"] = comp.get("direct")
            results.append(result)
        if unresolved:
            print("警告：%d 个条目无法解析为 PURL，需人工确认" % len(unresolved),
                  file=sys.stderr)

    conf_report = store.confidence_report(
        policy.get("freshness_sla_days", 14), policy.get("freshness_grace_days", 3))

    if len(results) == 1:
        markdown = report_mod.render_gate_markdown(results[0], conf_report, source)
        payload = {"source": source, "confidence": conf_report, "result": results[0]}
    else:
        markdown = report_mod.render_multi_markdown(results, conf_report, source)
        payload = {"source": source, "confidence": conf_report, "results": results}

    if args.json:
        report_mod.to_json(payload, args.json)
    if args.md:
        _ensure_parent(args.md)
        with open(args.md, "w", encoding="utf-8") as handle:
            handle.write(markdown)
    if args.sarif:
        cicd_mod.write_sarif(results, args.sarif, fail_on=args.fail_on)
    if args.junit:
        _write(args.junit, cicd_mod.to_junit(results, fail_on=args.fail_on))
    if args.comment:
        _write(args.comment, cicd_mod.to_comment(results, fail_on=args.fail_on))
    if not args.json and not args.md and not args.sarif and not args.junit and not args.comment:
        print(markdown)

    blocking = FAIL_LEVELS.get(args.fail_on, [])
    failed = [r for r in results if r["conclusion"] in blocking]
    if failed:
        print("门禁失败：%d 个组件命中 %s 阈值" % (len(failed), args.fail_on), file=sys.stderr)
        return 1
    return 0


def cmd_assess(args):
    store = _store(args.facts)
    policy = policy_mod.load_policy(args.policy)
    data = assets_mod.load_assets(args.assets)
    if args.rebuild_inventory:
        assets_mod.build_inventory(store, data, base_dir=args.base_dir)
    confidences = _confidences(store, policy)

    groups = [g for g in (data.get("groups") or [])
              if not args.group or g.get("name") == args.group]
    reports = [assessment.assess_group(store, g, policy, confidences) for g in groups]

    conf_report = store.confidence_report(
        policy.get("freshness_sla_days", 14), policy.get("freshness_grace_days", 3))
    payload = {"confidence": conf_report, "groups": reports}

    if args.json:
        report_mod.to_json(payload, args.json)
    if args.md:
        _ensure_parent(args.md)
        chunks = [report_mod.render_group_markdown(r, conf_report) for r in reports]
        with open(args.md, "w", encoding="utf-8") as handle:
            handle.write("\n\n---\n\n".join(chunks))
    if not args.json and not args.md:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _write(path, text):
    _ensure_parent(path)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def cmd_scan(args):
    if os.path.isfile(args.path):
        single = depfile.parse_file(args.path)
        if not single:
            print("无法识别的依赖文件：%s" % args.path, file=sys.stderr)
            return 1
        payload = {
            "root": args.path,
            "files": [{"path": os.path.basename(args.path), "eco": single["eco"],
                       "format": single["format"],
                       "components": len(single["components"]),
                       "unresolved": len(single["unresolved"])}],
            "components": sbom_mod.dedupe(single["components"]),
            "unresolved": single["unresolved"],
        }
    else:
        payload = depfile.scan_dir(args.path, max_depth=args.max_depth)
    if args.app:
        payload["assets_entry"] = depfile.assets_entry(
            args.group or "默认群组", args.app, payload,
            tier=args.tier, exposure=args.exposure, data_sensitivity=args.data_sensitivity)
    if args.json:
        report_mod.to_json(payload, args.json)
    if args.md:
        _write(args.md, report_mod.render_scan_markdown(payload))
    if not args.json and not args.md:
        print(json.dumps({
            "root": payload["root"],
            "files": payload["files"],
            "component_count": len(payload["components"]),
            "unresolved_count": len(payload["unresolved"]),
        }, ensure_ascii=False, indent=2))
    return 0


def cmd_patrol(args):
    store = _store(args.facts)
    policy = policy_mod.load_policy(args.policy)
    data = assets_mod.load_assets(args.assets)
    catalog = baseline_mod.load_catalog(args.baseline)
    previous = patrol_mod.load_state(args.state) if args.state else None
    payload = patrol_mod.patrol(store, data, policy=policy, catalog=catalog,
                                previous=previous, base_dir=args.base_dir,
                                rebuild_inventory=args.rebuild_inventory)
    if args.state:
        patrol_mod.save_state(args.state, payload)
    if args.json:
        report_mod.to_json(payload, args.json)
    if args.tickets:
        report_mod.to_json({"generated_at": payload["generated_at"],
                            "tickets": payload["tickets"]}, args.tickets)
    if args.md:
        _write(args.md, report_mod.render_patrol_markdown(payload))
    if not args.json and not args.md:
        print(json.dumps({
            "generated_at": payload["generated_at"],
            "groups": [{k: v for k, v in group.items() if k != "apps"}
                       for group in payload["groups"]],
            "common_risks": payload["common_risks"],
            "ticket_count": len(payload["tickets"]),
            "delta": {k: len(v) if isinstance(v, list) else v
                      for k, v in payload["delta"].items()},
        }, ensure_ascii=False, indent=2))
    return 0


def cmd_baseline(args):
    catalog = baseline_mod.load_catalog(args.catalog)
    items = baseline_mod.match(catalog, args.component) if args.component else catalog
    if args.snapshot:
        with open(args.snapshot, "r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
        payload = {"results": baseline_mod.run_all(catalog, snapshot, name=args.component)}
    else:
        payload = {"count": len(items), "items": items}
    if args.json:
        report_mod.to_json(payload, args.json)
    if args.md:
        _write(args.md, report_mod.render_baseline_markdown(payload))
    if not args.json and not args.md:
        if args.snapshot:
            for result in payload["results"]:
                print("%-28s %-8s %s" % (result["id"], result["status"], result["evidence"]))
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_genscript(args):
    catalog = baseline_mod.load_catalog(args.catalog)
    if args.rule:
        items = [baseline_mod.by_id(catalog, rule) for rule in args.rule]
        items = [item for item in items if item]
    elif args.component:
        items = baseline_mod.match(catalog, args.component)
    else:
        items = catalog
    if not items:
        print("无匹配的基线项", file=sys.stderr)
        return 1
    manifest = scriptgen.generate(items, target=args.target, out_dir=args.out_dir,
                                  llm=scriptgen.LLMClient(),
                                  use_llm=not args.no_llm)
    llm_count = len([r for r in manifest["rules"] if r["generated_by"] == "llm"])
    bad = [r for r in manifest["rules"] if not r["lint_ok"]]
    print("已生成 %d 条规则（目标 %s），LLM 增强 %d 条，静态检查失败 %d 条" % (
        len(manifest["rules"]), args.target, llm_count, len(bad)))
    if args.out_dir:
        print("输出目录：%s" % args.out_dir)
    return 1 if bad else 0


def cmd_verify(args):
    catalog = baseline_mod.load_catalog(args.catalog)
    cases = verify_mod.load_cases(args.cases)
    metrics = verify_mod.evaluate(catalog, cases, threshold=args.threshold)
    if args.json:
        report_mod.to_json(metrics, args.json)
    if args.md:
        _write(args.md, verify_mod.render_markdown(metrics))
    if not args.json and not args.md:
        print(verify_mod.render_markdown(metrics))
    try:
        verify_mod.assert_accuracy(metrics, args.threshold)
    except verify_mod.AccuracyError as exc:
        print("准确率门禁失败：%s" % exc, file=sys.stderr)
        return 1
    return 0


def cmd_depinfo(args):
    if args.import_file:
        assets = depinfo_mod.sync_from_export(args.import_file)
        payload = assets
    elif args.results:
        with open(args.results, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        items = raw.get("results") or raw.get("components") or raw.get("items") or []
        payload = depinfo_mod.result_payload(items, mask=not args.no_mask,
                                          sync_token=args.sync_token)
        if args.push:
            client = depinfo_mod.DepinfoClient()
            if not client.enabled():
                print("DEPINFO 未配置（SCABASE_DEPINFO_URL 为空），已跳过推送", file=sys.stderr)
            else:
                client.push(payload)
                payload["pushed"] = True
    else:
        print("depinfo 需要 --import 或 --results", file=sys.stderr)
        return 2
    if args.out:
        report_mod.to_json(payload, args.out)
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _signer(key):
    return sync_mod.Signer(key or os.getenv("SCABASE_SYNC_KEY", "dev-key"))


def cmd_bundle(args):
    store = _store(args.facts)
    bundle = sync_mod.Bundle(store, _signer(args.key))
    result = bundle.build(args.dataset, args.out, mode=args.mode)
    if not result:
        print("无变更，未产出数据包")
        return 0
    print("已生成数据包：%s（seq=%d, files=%d）" % (
        result["path"], result["manifest"]["seq"], len(result["manifest"]["files"])))
    return 0


def cmd_import(args):
    store = _store(args.facts)
    bundle = sync_mod.Bundle(store, _signer(args.key))
    try:
        imported = bundle.import_bundle(args.bundle, force=args.force)
    except sync_mod.SyncError as exc:
        print("导入失败：%s" % exc, file=sys.stderr)
        return 2
    path = bundle.write_receipt(imported)
    print("导入成功：dataset=%s seq=%d files=%d" % (
        imported["dataset"], imported["seq"], imported["files"]))
    print("回执：%s" % path)
    return 0


def cmd_confidence(args):
    store = _store(args.facts)
    policy = policy_mod.load_policy(args.policy)
    print(json.dumps(store.confidence_report(
        policy.get("freshness_sla_days", 14), policy.get("freshness_grace_days", 3)),
        ensure_ascii=False, indent=2))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="oss-intake", description="开源引入评估工具")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("inventory", help="摄入应用资产 SBOM")
    p.add_argument("--facts", required=True)
    p.add_argument("--assets", required=True)
    p.add_argument("--base-dir", default=".")
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("gate", help="引入前评估 / CI 门禁")
    p.add_argument("--facts", required=True)
    p.add_argument("--sbom", help="应用 SBOM 路径")
    p.add_argument("--purl", help="候选组件 PURL（引入前评估）")
    p.add_argument("--policy")
    p.add_argument("--profile")
    p.add_argument("--tier", choices=["core", "important", "normal"])
    p.add_argument("--exposure", choices=["internet", "internal", "offline"])
    p.add_argument("--data-sensitivity", choices=["high", "mid", "low"])
    p.add_argument("--human-reviewed", action="store_true")
    p.add_argument("--fail-on", default="deny", choices=list(FAIL_LEVELS.keys()))
    p.add_argument("--json")
    p.add_argument("--md")
    p.add_argument("--sarif", help="导出 SARIF 2.1.0（供代码扫描中心 / CI 纳管）")
    p.add_argument("--junit", help="导出 JUnit XML（供流水线测试报告展示）")
    p.add_argument("--comment", help="导出 MR/PR 评论 Markdown")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("scan", help="扫描原生依赖文件")
    p.add_argument("--path", required=True, help="源码目录或单个依赖文件")
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--app", help="生成资产台账条目时使用的应用名")
    p.add_argument("--group", default="默认群组")
    p.add_argument("--tier", default="normal", choices=["core", "important", "normal"])
    p.add_argument("--exposure", default="internal", choices=["internet", "internal", "offline"])
    p.add_argument("--data-sensitivity", default="low", choices=["high", "mid", "low"])
    p.add_argument("--json")
    p.add_argument("--md")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("patrol", help="漏洞影响范围与基线巡检")
    p.add_argument("--facts", required=True)
    p.add_argument("--assets", required=True)
    p.add_argument("--base-dir", default=".")
    p.add_argument("--policy")
    p.add_argument("--baseline", help="外部基线目录 JSON")
    p.add_argument("--state", help="上次巡检结果路径，用于增量对比")
    p.add_argument("--rebuild-inventory", action="store_true")
    p.add_argument("--json")
    p.add_argument("--md")
    p.add_argument("--tickets", help="工单输出路径")
    p.set_defaults(func=cmd_patrol)

    p = sub.add_parser("baseline", help="安全配置基线目录")
    p.add_argument("--catalog", help="外部基线目录 JSON")
    p.add_argument("--component", help="按组件名过滤")
    p.add_argument("--snapshot", help="环境快照 JSON，用于现场执行基线检查")
    p.add_argument("--json")
    p.add_argument("--md")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("genscript", help="AI 智能体生成检查脚本")
    p.add_argument("--catalog", help="外部基线目录 JSON")
    p.add_argument("--rule", action="append", help="基线项 id，可重复")
    p.add_argument("--component", help="按组件名批量生成")
    p.add_argument("--target", default="sreops", choices=list(scriptgen.TARGETS))
    p.add_argument("--out-dir", required=True)
    p.add_argument("--no-llm", action="store_true", help="禁用大模型增强，仅用模板引擎")
    p.set_defaults(func=cmd_genscript)

    p = sub.add_parser("verify", help="生成脚本准确率回归校验")
    p.add_argument("--catalog", help="外部基线目录 JSON")
    p.add_argument("--cases", required=True, help="标注样本集 JSON")
    p.add_argument("--threshold", type=float, default=verify_mod.DEFAULT_THRESHOLD)
    p.add_argument("--json")
    p.add_argument("--md")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("depinfo", help="DEPINFO 台账导入与结论回传")
    p.add_argument("--import", dest="import_file", help="DEPINFO 组件台账导出文件")
    p.add_argument("--results", help="评估/巡检结果 JSON，用于回传")
    p.add_argument("--out", help="输出路径")
    p.add_argument("--sync-token")
    p.add_argument("--no-mask", action="store_true", help="回传时保留应用维度信息")
    p.add_argument("--push", action="store_true", help="推送至 DEPINFO（需配置 SCABASE_DEPINFO_URL）")
    p.set_defaults(func=cmd_depinfo)

    p = sub.add_parser("assess", help="应用群组评估")
    p.add_argument("--facts", required=True)
    p.add_argument("--assets", required=True)
    p.add_argument("--base-dir", default=".")
    p.add_argument("--policy")
    p.add_argument("--group")
    p.add_argument("--rebuild-inventory", action="store_true")
    p.add_argument("--json")
    p.add_argument("--md")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("bundle", help="构建离线数据包")
    p.add_argument("--facts", required=True)
    p.add_argument("--dataset", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--mode", default="delta", choices=["delta", "snapshot"])
    p.add_argument("--key")
    p.set_defaults(func=cmd_bundle)

    p = sub.add_parser("import", help="导入离线数据包")
    p.add_argument("--facts", required=True)
    p.add_argument("--bundle", required=True)
    p.add_argument("--key")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("confidence", help="数据水位与置信度")
    p.add_argument("--facts", required=True)
    p.add_argument("--policy")
    p.set_defaults(func=cmd_confidence)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    if args.command == "gate" and not args.sbom and not args.purl:
        parser.error("gate 需要 --sbom 或 --purl")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
