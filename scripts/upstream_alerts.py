"""Build durable, low-noise monitoring alerts from static observations."""

import json
import re

if __package__:
    from . import upstream_graph as graph
else:
    import upstream_graph as graph

BEGIN = "<!-- QX_ALERTS_BEGIN -->"
END = "<!-- QX_ALERTS_END -->"
SIGNALS = {
    "offline": ("入口不可用", 1),
    "html": ("HTML、挑战页或首页跳转", 1),
    "closure": ("依赖闭包不完整", 1),
    "mitm": ("MITM 范围可能扩大", 2),
    "sensitive": ("敏感信息访问线索", 2),
    "execution": ("动态执行或混淆线索", 2),
}
AVAILABILITY = {"offline", "html"}
TRACKED = {"mitm", "sensitive", "execution"}
FINGERPRINT_LIMIT = 16
FINGERPRINT = re.compile(r"[0-9a-f]{24}")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+00:00")
PATTERN = re.compile(r"[-a-zA-Z0-9.*?]{1,86}")


def read_state(body):
    if BEGIN not in body and END not in body:
        return {}
    if body.count(BEGIN) != 1 or body.count(END) != 1:
        raise ValueError("提醒状态标记损坏")
    _, _, tail = body.partition(BEGIN)
    raw, _, _ = tail.partition(END)
    if len(raw) > 64000:
        raise ValueError("提醒状态超出限制")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("提醒状态无效")
    for name, item in value.items():
        if (not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or not isinstance(item, dict)
                or set(item) - {"signals", "last_success", "mitm_base", "fingerprints"}
                or not {"signals", "last_success", "mitm_base"} <= item.keys()):
            raise ValueError("提醒状态无效")
        signals, timestamp, anchor = item["signals"], item["last_success"], item["mitm_base"]
        if (not isinstance(signals, list) or any(not isinstance(key, str) or key not in SIGNALS for key in signals)
                or timestamp is not None and (not isinstance(timestamp, str) or not STAMP.fullmatch(timestamp))
                or anchor is not None and (not isinstance(anchor, list) or len(anchor) > 60
                                            or any(not isinstance(host, str) or not PATTERN.fullmatch(host) for host in anchor))):
            raise ValueError("提醒状态无效")
        fingerprints = item.get("fingerprints", {})
        if not isinstance(fingerprints, dict) or any(
            key not in TRACKED or key not in signals or not isinstance(ids, list)
            or len(ids) > FINGERPRINT_LIMIT
            or any(not isinstance(value, str) or not FINGERPRINT.fullmatch(value) for value in ids)
            for key, ids in fingerprints.items()
        ):
            raise ValueError("提醒证据指纹无效")
    return value


def serialize(state):
    return f"{BEGIN}\n{graph.packed(state).decode()}\n{END}"


def static_findings(snapshot):
    evidence = {}
    fingerprints = {}
    for url, node in snapshot.get("files", {}).items():
        for kind, line, label in node.get("findings", ()):
            if kind in ("execution", "sensitive"):
                identity = fingerprint(kind, url, label)
                finding = f"`{graph.file_label(url)}` 第 {graph.safe(line, 8)} 行，{graph.safe(label)}"
                fingerprints.setdefault(kind, {})[identity] = finding
                evidence.setdefault(kind, finding)
    return evidence, fingerprints


def fingerprint(*parts):
    # The Issue stores identifiers only. Line numbers are display metadata.
    return graph.sha(graph.packed(parts))[:24]


def bounded(ids):
    return sorted(ids)[:FINGERPRINT_LIMIT]


def hosts(snapshot):
    entries = set(snapshot.get("mitm", ()))
    root = snapshot.get("files", {}).get(snapshot.get("root"), {})
    entries.update(label for kind, _, label in root.get("findings", ()) if kind == "mitm")
    return {entry for entry in entries if PATTERN.fullmatch(entry)}


def expansion(before, after):
    return sorted(
        [value for value in after - before if not value.startswith("-")]
        + [f"移除排除项 {value}" for value in before - after if value.startswith("-")]
    )


def seed(prior):
    previous_observation = prior.get("last_observed", {})
    complete = prior.get("last_complete") or {}
    known, fingerprints = static_findings(complete)
    signals = set(known)
    if previous_observation and not previous_observation.get("graph_complete"):
        signals.add("closure")
    checked = complete.get("checked_at")
    return {"signals": sorted(signals), "last_success": checked if checked and STAMP.fullmatch(checked) else None,
            "mitm_base": None, "fingerprints": {key: bounded(ids) for key, ids in fingerprints.items()}}


def migrate(body, previous, previous_graph):
    """Carry only already-reported conditions into the first low-noise run."""
    if BEGIN in body or END in body:
        return read_state(body)
    visible = body.split("<!-- QX_STATE_BEGIN -->", 1)[0]
    result = {name: seed(previous_graph.get(name, {})) for name in previous}
    sections = re.split(r"(?m)^#### ([A-Za-z0-9_-]{1,64})\s*$", visible)
    for name, section in zip(sections[1::2], sections[2::2]):
        if name not in result:
            continue
        active = set(result[name]["signals"])
        if re.search(r"(?m)^  - 观察到 动态执行或混淆线索", section):
            active.add("execution")
        if re.search(r"(?m)^  - 观察到 敏感信息线索", section):
            active.add("sensitive")
        result[name]["signals"] = sorted(active)
    for name, item in result.items():
        escaped = re.escape(name)
        for match in re.finditer(rf"(?m)^- \*\*{escaped}\*\* · ([^\n]+)", visible):
            reason = match[1]
            if "保留基线" in reason:
                signal = "html" if html_failure(reason) else "offline"
                item["signals"] = sorted(set(item["signals"]) | {signal})
                break
    return result


def html_failure(error):
    return re.search(r"HTML|challenge|站点首页|验证码", error, re.I) is not None


def observation_signals(old, observation, snapshot, prior, previous):
    active = set(old["signals"])
    last_success = old["last_success"]
    anchor = old["mitm_base"]
    evidence = {}
    previous_ids = old.get("fingerprints", {})
    if observation.error:
        signal = "html" if html_failure(observation.error) else "offline"
        evidence[signal] = graph.safe(observation.error, 150)
        return (active - AVAILABILITY) | {signal}, evidence, anchor, last_success, previous_ids, {}

    evidence, observed_ids = static_findings(snapshot)
    if snapshot["graph_complete"]:
        last_success = snapshot["checked_at"]
        active.clear()
    else:
        active -= AVAILABILITY
        evidence["closure"] = "；".join(
            f"`{graph.file_label(url)}` {graph.safe(issue, 90)}"
            for url, _, issue in snapshot["issues"][:2]
        )
    complete = prior.get("last_complete") or {}
    if complete.get("root") == snapshot["root"]:
        previous_hosts = hosts(complete)
    elif previous.get("url") == snapshot["root"] and "profile" in previous:
        previous_hosts = set(previous["profile"]["mitm"])
    else:
        previous_hosts = None
    current_hosts = hosts(snapshot)
    reference = set(anchor) if anchor is not None else previous_hosts
    if reference is not None and (delta := expansion(reference, current_hosts)):
        anchor = sorted(reference)
        evidence["mitm"] = "、".join(graph.safe(value) for value in delta[:4])
        observed_ids["mitm"] = {fingerprint("mitm", host): graph.safe(host) for host in delta}
    elif snapshot["graph_complete"]:
        anchor = None
    active |= evidence.keys()
    fingerprints, new_evidence = {}, {}
    for key in active & TRACKED:
        observed = observed_ids.get(key, {})
        known = set(previous_ids.get(key, ()))
        stable = bounded(set(observed) | (known if not snapshot["graph_complete"] else set()))
        if observed or key in previous_ids:
            fingerprints[key] = stable
        if key in old["signals"] and key in previous_ids:
            added = (set(stable) & observed.keys()) - known
            if added:
                new_evidence[key] = "；".join(observed[value] for value in sorted(added)[:3])
    return active, evidence, anchor, last_success, fingerprints, new_evidence


def recommendation(item, active, monitored):
    if item.get("client_enabled") is False:
        return "观察，保持当前停用。"
    if item.get("risk_status") == "compatibility_concern" or any(SIGNALS[key][1] >= 2 for key in active):
        prefix = "若目前已启用，" if item.get("client_enabled") is None else ""
        return prefix + "建议在 QX 手动停用并排查。静态线索尚未验证运行行为。"
    if active or not monitored or item.get("risk_status") == "watch":
        return "观察，先核对响应或依赖。"
    return "若已启用且体验正常，可继续使用。"


def render(modules, observed, snapshots, previous, previous_graph, prior_alerts, details):
    rows, notices = [], []
    state = prior_alerts.copy()
    for name, item in modules.items():
        prior = previous_graph.get(name, {})
        old = prior_alerts.get(name) or seed(prior)
        monitored = name in observed
        active, evidence, anchor, last_success = set(old["signals"]), {}, old["mitm_base"], old["last_success"]
        if monitored:
            active, evidence, anchor, last_success, fingerprints, new_evidence = observation_signals(
                old, observed[name], snapshots.get(name), prior, previous.get(name, {})
            )
            state[name] = {"signals": sorted(active), "last_success": last_success, "mitm_base": anchor,
                           "fingerprints": fingerprints}
            before = set(old["signals"])
            added, cleared = active - before, before - active
            if added or cleared or new_evidence:
                severity = max((SIGNALS[key][1] for key in active), default=0)
                old_severity = max((SIGNALS[key][1] for key in before), default=0)
                labels = []
                if added:
                    label = "严重程度升级" if before and severity > old_severity else "新异常"
                    labels.append(label + " · " + "、".join(SIGNALS[key][0] for key in sorted(added)))
                recovered = cleared - AVAILABILITY if active & AVAILABILITY else cleared
                if new_evidence:
                    labels.append("同类新证据 · " + "、".join(SIGNALS[key][0] for key in sorted(new_evidence)))
                if recovered:
                    labels.append("恢复 · " + "、".join(SIGNALS[key][0] for key in sorted(recovered)))
                notices.extend([f"#### {name} · {'；'.join(labels)}", recommendation(item, active, monitored)])
                notices.extend(f"- {SIGNALS[key][0]} · {evidence[key]}" for key in sorted(added) if key in evidence)
                notices.extend(f"- {SIGNALS[key][0]} · {new_evidence[key]}" for key in sorted(new_evidence))
        client = {True: "启用（用户报告）", False: "停用（用户报告）", None: "未知"}
        names = "、".join(SIGNALS[key][0] for key in sorted(active))
        status = names or "未发现本轮异常"
        if not monitored:
            status = "上游监控已暂停" + (f"；上次记录：{names}" if names else "")
        level = "较高" if any(SIGNALS[key][1] >= 2 for key in active) else "关注" if active else "正常" if monitored else "未检查"
        change = "上游未检查" if not monitored else "入口未验证，保留基线" if name not in snapshots else (
            "依赖闭包待核实，保留完整基线" if not snapshots[name]["graph_complete"] else
            ("已更新，仍有异常" if active else "正常内容更新或首次建立基线") if name in details else "无变化"
        )
        rows.extend([
            f"#### {name}",
            f"- 监控：{'开' if item['monitor_enabled'] else '关'} · 客户端：{client[item.get('client_enabled')]} · "
            f"发布接管：{'是' if item.get('managed') else '否'} · 更新：{'冻结' if item.get('update_policy') == 'frozen' else '人工审核'}"
            f" · 登记风险：{graph.safe(item.get('risk_status', '未知'))}",
            f"- 上次完整检查：{last_success or '未知'} · {level} · {status}",
            f"- 变化：{change}。{recommendation(item, active, monitored)}",
        ])
        rows.extend(f"  - {SIGNALS[key][0]} · {evidence[key]}" for key in sorted(evidence))
        if item.get("client_report"):
            rows.append("- 客户端事件（用户报告）： " + graph.safe(item["client_report"].get("summary", ""), 220))
    return rows, notices, state
