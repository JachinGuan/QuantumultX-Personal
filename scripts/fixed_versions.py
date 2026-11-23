"""Render a read-only QX fixed-version checklist using saved Issue #1 evidence."""

import argparse
import json
from pathlib import Path
import re

if __package__:
    from . import check_upstream as monitor, upstream_alerts as alerts, upstream_graph as graph
    from .module_registry import ROOT, load_modules, select_sources
    from .upstream_transport import DownloadError, endpoint
else:
    import check_upstream as monitor
    import upstream_alerts as alerts
    import upstream_graph as graph
    from module_registry import ROOT, load_modules, select_sources
    from upstream_transport import DownloadError, endpoint


def coordinates(url):
    """Identify the publisher and path; URL syntax alone cannot prove a Git commit."""
    try:
        parts = endpoint(url)
    except DownloadError:
        return None, None
    path = parts.path.strip("/").split("/")
    if parts.hostname == "raw.githubusercontent.com" and len(path) >= 4:
        owner, repo, ref, *file = path
        if ref == "refs" and len(file) >= 3 and file[0] == "heads":
            _, ref, *file = file
        return ("github", owner, repo, *file), ref
    if parts.hostname in ("gist.github.com", "gist.githubusercontent.com") and len(path) in (4, 5) and path[2] == "raw":
        owner, gist, _, *tail = path
        return ("gist", owner, gist, tail[-1]), tail[0] if len(tail) == 2 else None
    return None, None


def fixed(url):
    identity, ref = coordinates(url)
    return identity is not None and ref is not None and re.fullmatch(r"[a-f0-9]{40}", ref) is not None


def assess(source, baseline, graph_record, alerts_record, references, verify=None, *, frozen=False):
    if not source:
        return "无上游监控入口", "不适用", None
    if not baseline or baseline["url"] != source["url"]:
        return "缺少与当前来源匹配的基线", "未知", None
    signals = set(alerts_record.get("signals", ()))
    if signals & alerts.AVAILABILITY or (source.get("investigation") and "profile" not in baseline):
        return "上游不可用或跳转首页，保留原地址", "未知", None
    observed = graph_record.get("last_observed") or {}
    complete = graph_record.get("last_complete") or {}
    if not observed.get("graph_complete") or complete.get("root") != source["url"]:
        return "未完整冻结：静态依赖闭包不完整或未知", "不完整或未知", None
    files = complete["files"]
    root = files.get(source["url"], {})
    deps = {url: node["sha256"] for url, node in files.items() if url != source["url"]}
    if any(not fixed(url) for url in deps) or any(
        target not in files for _, target, _, _ in complete["dependencies"]
    ):
        return "未完整冻结：仍引用浮动或未知依赖", f"完整静态图，{len(deps)} 个依赖", None
    if root.get("sha256") != baseline["sha256"]:
        return "基线与静态图的入口哈希不一致", "待核对", None
    for record in references:
        pin = record["entry"]
        if (record["source"] != source["url"] or not fixed(pin)
                or coordinates(pin)[0] != coordinates(source["url"])[0]
                or record["sha256"] != baseline["sha256"] or record["dependencies"] != deps):
            continue
        if record["license_confirmed"] is not True or not record.get("license_evidence"):
            return "研究样本：固定版本和可解析引用均有证据，许可待核对", f"完整静态图，{len(deps)} 个依赖", None
        if frozen:
            return "模块已冻结或停用，保留原地址", f"完整静态图，{len(deps)} 个依赖", None
        if verify is None or not verify(source, record):
            return "未完成本轮在线校验，保留原地址", f"完整静态图，{len(deps)} 个依赖", None
        return "固定版本候选，待用户与 QX 人工验证", f"完整静态图，{len(deps)} 个依赖", pin
    return "无与当前基线匹配的已验证固定版本", f"完整静态图，{len(deps)} 个依赖", None


def verify_reference(source, record):
    pinned = {**source, "url": record["entry"]}
    runner = graph.GraphMonitor(monitor.validate, monitor.profile, monitor.InvalidContent)
    root = runner.load(pinned["url"], pinned["kind"], pinned)
    if isinstance(root, str) or root.final != pinned["url"] or root.sha256 != record["sha256"]:
        return False
    snapshot = runner.walk("Candidate", pinned, root)
    deps = {url: node["sha256"] for url, node in snapshot["files"].items() if url != pinned["url"]}
    return snapshot["graph_complete"] and deps == record["dependencies"] and all(
        fixed(url) and fixed(snapshot["files"][url]["final_url"])
        and coordinates(url) == coordinates(snapshot["files"][url]["final_url"]) for url in deps
    )


def render(sources, modules, previous, before, state, reviewed, verify=None):
    lines = [
        "# QX 固定版本候选清单", "",
        "客户端开关只反映用户报告。静态闭包完整不等于安全或客户端兼容。", "",
        "| 模块 | 上游 / 历史 SHA-256 | 上次入口观测 | 静态闭包 | 许可 | 固定状态 | 客户端 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    candidates = []
    for name, module in modules.items():
        source = sources.get(name)
        current = previous.get(name, {})
        status, closure, candidate = assess(
            source, current, before.get(name, {}), state.get(name, {}),
            reviewed["references"].get(name, []), verify,
            frozen=(not module["monitor_enabled"] or module["client_enabled"] is False
                    or module["update_policy"] == "frozen"),
        )
        client = {True: "启用（用户报告）", False: "停用（用户报告）", None: "未知"}[module["client_enabled"]]
        upstream = f"[原地址]({source['url']})" if source else "无"
        if source and current.get("sha256"):
            upstream += f" / `{current['sha256']}`"
        if not source or not module["monitor_enabled"]:
            availability = "未监控"
        elif status.startswith("上游不可用"):
            availability = "失败"
        elif current.get("url") == source["url"] and "profile" in current:
            availability = "有有效历史入口"
        else:
            availability = "未知"
        license_note = reviewed["license"].get(name, "未确认再分发许可") if source else "见仓库现有批准流程"
        lines.append(f"| {name} | {upstream} | {availability} | {closure} | {license_note} | {status} | {client} |")
        if candidate:
            candidates.append(f"- **{name}** · `{candidate}`")
    return "\n".join([*lines, "", "## 可手动复制的候选", "", *(candidates or ["当前无符合条件的候选。"]), ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path, help="Saved Issue #1 body; only read locally")
    parser.add_argument("--verify", action="store_true", help="Recheck licensed reviewed pins over HTTPS")
    args = parser.parse_args()
    body = args.baseline.read_text(encoding="utf-8")
    sources = json.loads((ROOT / "upstream/sources.json").read_text())
    modules = load_modules(ROOT / "upstream/modules.json")
    select_sources(sources, modules)
    previous, before = monitor.read_state(body), graph.read_graph(body)
    reviewed = json.loads((ROOT / "upstream/fixed-versions.json").read_text())
    print(render(sources, modules, previous, before, alerts.migrate(body, previous, before), reviewed,
                 verify_reference if args.verify else None), end="")


if __name__ == "__main__":
    main()
