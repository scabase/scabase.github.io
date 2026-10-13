"""命令行入口。

  inventory   摄入应用资产 SBOM，写入事实层 inventory 数据集
  gate        引入前评估 / CI 门禁（单组件或整份 SBOM）
  assess      应用群组存量风险评估
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
from . import facts as facts_mod
from . import policy as policy_mod
from . import purl
from . import report as report_mod
from . import sbom as sbom_mod
from . import scoring
from . import sync as sync_mod

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
        ingested = sbom_mod.ingest(args.sbom)
        components = sbom_mod.dedupe(ingested["components"])
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
        if ingested["unresolved"]:
            print("警告：%d 个条目无法解析为 PURL，需人工确认" % len(ingested["unresolved"]),
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
    if not args.json and not args.md:
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
    p.set_defaults(func=cmd_gate)

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
