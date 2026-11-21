"""Bounded dependency traversal, immutable candidate export and Issue reporting."""

import base64
from dataclasses import astuple, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from time import monotonic
from urllib.parse import urljoin, urlsplit
import zlib

if __package__:
    from .upstream_scan import javascript_scan, rewrite_scan
    from .upstream_transport import MAX_BYTES, DownloadError, download, endpoint
else:
    from upstream_scan import javascript_scan, rewrite_scan
    from upstream_transport import MAX_BYTES, DownloadError, download, endpoint

MAX_FILES = 48
MAX_DEPTH = 3
MAX_TOTAL_BYTES = 24 * 1024 * 1024
MAX_SECONDS = 150
MAX_EDGES = 160
MAX_ENTRY_FILES = 18
STATE_LIMIT = 512 * 1024
STATE_BEGIN = "<!-- QX_GRAPH_BEGIN -->"
STATE_END = "<!-- QX_GRAPH_END -->"
SHA = re.compile(r"[a-f0-9]{64}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def packed(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Resource:
    data: bytes
    final: str
    media: str
    redirects: tuple
    sha256: str
    scan: object
    profile: dict


def reference_url(reference, base, kind):
    value = reference.target
    if not value:
        return None
    if kind == "javascript" and value.startswith(("./", "../", "/")) and not value.startswith("//"):
        value = urljoin(base, value)
    try:
        endpoint(value)
    except DownloadError:
        return None
    return value


class GraphMonitor:
    def __init__(self, validate, profile, invalid_content, *, fetch=download,
                 max_files=MAX_FILES, max_depth=MAX_DEPTH, max_total=MAX_TOTAL_BYTES, max_seconds=MAX_SECONDS):
        self.validate = validate
        self.profile = profile
        self.invalid_content = invalid_content
        self.fetch = fetch
        self.max_files = max_files
        self.max_depth = max_depth
        self.max_total = max_total
        self.deadline = monotonic() + max_seconds
        self.checked = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.total_bytes = 0
        self.cache = {}
        self.observed_hashes = {}

    def load(self, url, kind, source):
        key = (url, kind)
        if key in self.cache:
            return self.cache[key]
        if len(self.cache) >= self.max_files:
            return "本次下载文件数达到上限"
        if self.total_bytes >= self.max_total:
            return "本次下载总字节达到上限"
        if monotonic() >= self.deadline:
            return "本次检查达到总时限"
        try:
            size_limit = min(MAX_BYTES, self.max_total - self.total_bytes)
            response = self.fetch(url, source, self.deadline, size_limit)
            self.total_bytes += len(response.data)
            if len(response.data) > size_limit:
                raise DownloadError("文件超出下载预算")
            digest = sha(response.data)
            self.observed_hashes[key] = digest
            content = self.validate(response.data, response.media_type, kind)
            scan = (rewrite_scan if kind == "rewrite" else javascript_scan)(content)
            result = Resource(response.data, response.final_url, response.media_type, response.redirects,
                              digest, scan, self.profile(content, kind) if source else {})
        except self.invalid_content as exc:
            result = "内容无效（" + str(exc) + "）"
        except DownloadError as exc:
            self.total_bytes += exc.bytes_read
            result = str(exc)
        except OSError:
            result = "下载失败或超时"
        self.cache[key] = result
        return result

    def walk(self, name, source, root):
        nodes, relations, issues, expanded = {}, [], [], {}
        failed = False
        cutoff = False

        def visit(url, kind, resource, depth, trail):
            nonlocal failed, cutoff
            if url in trail:
                issues.append((url, 0, "循环依赖"))
                return
            if url in expanded and expanded[url] <= depth:
                return
            expanded[url] = depth
            nodes[url] = {
                "sha256": resource.sha256, "final_url": resource.final, "media_type": resource.media,
                "kind": kind, "findings": [astuple(finding) for finding in resource.scan.findings],
                "redirects": list(resource.redirects),
            }
            if resource.scan.limited:
                issues.append((url, 0, "依赖或证据达到文件扫描上限"))
                failed = True
            for ref in resource.scan.references:
                if len(relations) >= MAX_EDGES:
                    cutoff = True
                    break
                target = reference_url(ref, resource.final, kind)
                edge = (url, target, ref.line, ref.mechanism)
                if edge not in relations:
                    relations.append(edge)
                if target is None:
                    issues.append((url, ref.line, "动态、局部或不符合 URL 策略的依赖"))
                    continue
                if target in (*trail, url):
                    issues.append((url, ref.line, "循环依赖"))
                    continue
                if depth >= self.max_depth or target not in nodes and len(nodes) >= MAX_ENTRY_FILES:
                    cutoff = True
                    continue
                child = self.load(target, "javascript", {})
                if isinstance(child, str):
                    issues.append((target, 0, child))
                    failed = True
                else:
                    visit(target, "javascript", child, depth + 1, (*trail, url))

        visit(source["url"], source["kind"], root, 0, ())
        if cutoff:
            issues.append((source["url"], 0, "依赖深度、文件数或边数达到上限"))
            failed = True
        relations = sorted(set(relations), key=packed)
        issues = sorted(set(issues), key=packed)
        mitm = root.profile.get("mitm", [])
        if "mitm" in root.profile.get("truncated", []):
            issues.append((source["url"], 0, "MITM 范围列表达到上限"))
        # Include incomplete edges and checked content in the identity, but exclude timestamps.
        identity = {
            "root": source["url"],
            "files": {url: [node["sha256"], node["final_url"], node["media_type"]] for url, node in nodes.items()},
            "relations": relations,
            "issues": issues,
        }
        return {
            "entry": name, "version": sha(packed(identity)), "checked_at": self.checked,
            "root": source["url"], "files": nodes, "dependencies": relations, "issues": issues,
            "mitm": mitm, "graph_complete": not issues, "fetch_failed": failed,
            "review_status": "candidate", "frozen": True, "approval_eligible": not issues,
        }

    def export(self, directory, snapshot):
        # Same content/version is immutable. Publish the local directory atomically.
        parent = directory / snapshot["entry"]
        parent.mkdir(parents=True, exist_ok=True)
        target = parent / snapshot["version"]
        if target.exists():
            return
        with tempfile.TemporaryDirectory(prefix=".writing-", dir=parent) as working:
            temporary = Path(working) / "version"
            assets = temporary / "objects"
            assets.mkdir(parents=True)
            for url, node in snapshot["files"].items():
                resource = self.cache[url, node["kind"]]
                (assets / (node["sha256"] + ".blob")).write_bytes(resource.data)
            manifest = {
                **snapshot,
                "files": {url: {**node, "original_url": url, "checked_at": snapshot["checked_at"],
                                 "review_status": "candidate"} for url, node in snapshot["files"].items()},
                "dependencies": [
                    {"from": origin, "to": destination, "line": line, "mechanism": mechanism}
                    for origin, destination, line, mechanism in snapshot["dependencies"]
                ],
            }
            (temporary / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            try:
                os.rename(temporary, target)
            except OSError:
                if not target.is_dir():
                    raise


def approved_versions(path):
    if path is None:
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or any(
        not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or not isinstance(version, str) or not SHA.fullmatch(version)
        for name, version in value.items()
    ):
        raise ValueError("审核锁必须是来源名称到版本 SHA-256 的 JSON 映射")
    return value


def read_graph(body):
    if STATE_BEGIN not in body and STATE_END not in body:
        return {}
    if body.count(STATE_BEGIN) != 1 or body.count(STATE_END) != 1:
        raise ValueError("依赖状态标记损坏")
    _, _, tail = body.partition(STATE_BEGIN)
    encoded, separator, _ = tail.partition(STATE_END)
    if not separator or len(encoded) > 65536:
        raise ValueError("依赖状态标记或长度无效")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(encoded.strip(), validate=True), STATE_LIMIT + 1)
    if not decoder.eof or decoder.unused_data or len(raw) > STATE_LIMIT:
        raise ValueError("依赖状态编码无效或超过长度限制")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("依赖状态结构无效")
    return {name: baseline_record(record) for name, record in value.items()}


def complete_snapshot(snapshot):
    return (
        isinstance(snapshot, dict) and snapshot.get("graph_complete") is True
        and not snapshot.get("issues") and not snapshot.get("fetch_failed")
        and isinstance(snapshot.get("files"), dict)
        and SHA.fullmatch(str(snapshot.get("version", ""))) is not None
    )


def baseline_record(record):
    if not isinstance(record, dict):
        raise ValueError("依赖状态结构无效")
    if "last_observed" in record:
        observed = record["last_observed"]
        complete = record["last_complete"]
        if (not isinstance(observed, dict) or not SHA.fullmatch(str(observed.get("version", "")))
                or type(observed.get("graph_complete")) is not bool
                or complete is not None and not complete_snapshot(complete)):
            raise ValueError("依赖状态结构无效")
        if observed["graph_complete"] and (complete is None or complete["version"] != observed["version"]):
            raise ValueError("完整依赖状态与最近观察不一致")
        return record
    if not isinstance(record.get("files"), dict) or not SHA.fullmatch(str(record.get("version", ""))):
        raise ValueError("依赖状态结构无效")
    older = record.get("last_complete")
    complete = record if complete_snapshot(record) else older if complete_snapshot(older) else None
    return {
        "last_observed": {"version": record["version"], "graph_complete": complete_snapshot(record)},
        "last_complete": complete,
    }


def serialize_graph(state):
    raw = packed(state)
    if len(raw) > STATE_LIMIT:
        raise ValueError("依赖状态超出存储上限，旧基线已保留")
    encoded = base64.b64encode(zlib.compress(raw, level=9)).decode()
    return f"{STATE_BEGIN}\n{encoded}\n{STATE_END}"


def safe(value, limit=125):
    return re.sub(r"[^\w ./:*?+\-=，、（）]", "?", str(value)[:limit])


def file_label(url):
    # Avoid markdown links and disclosure of query values or arbitrary URL paths.
    try:
        parts = urlsplit(url)
        name = parts.path.rsplit("/", 1)[-1]
        return f"{safe(parts.hostname or '?', 80)}/{safe(name, 52)} [{sha(url.encode())[:8]}]"
    except ValueError:
        return "URL 无效"


LABELS = {
    "network": "网络请求或可能的目的地", "sensitive": "敏感信息线索",
    "storage": "持久化操作", "execution": "动态执行或混淆线索", "mutation": "请求或响应修改线索", "mitm": "MITM 匹配项",
}


def evidence_delta(before, after):
    old = {tuple(item) for item in before}
    new = {tuple(item) for item in after}
    old_behaviors = {(kind, evidence) for kind, _, evidence in old}
    new_behaviors = {(kind, evidence) for kind, _, evidence in new}
    for label, values in (("新增", new - old), ("删除", old - new)):
        for kind, line, evidence in sorted(values)[:12]:
            if (kind, evidence) in old_behaviors & new_behaviors:
                yield f"位置或出现次数变化（{label}）", kind, line, evidence
            else:
                yield label, kind, line, evidence
        if len(values) > 12:
            yield label, "limit", 0, f"另有 {len(values) - 12} 项证据"


def changes(name, before, after, legacy, approved):
    old_files, new_files = before.get("files", {}), after["files"]
    initial = not before
    details = []
    reasons = set()
    for url in sorted(old_files.keys() | new_files.keys()):
        old, new = old_files.get(url, {}), new_files.get(url, {})
        if old == new or not new and not after["graph_complete"]:
            continue
        location = file_label(url)
        old_hash = old.get("sha256", legacy.get("sha256") if url == after["root"] and initial else None)
        old_hash = old_hash if SHA.fullmatch(str(old_hash)) else "无"
        new_hash = new.get("sha256", "无")
        label = "入口" if url == after["root"] else "依赖"
        if new_hash == "无":
            change = "移除"
        elif old_hash == "无":
            change = "首次观察" if initial else "新增"
        else:
            change = "变化" if old_hash != new_hash else "哈希相同，首次收集或元数据变化"
        details.append(f"- {label}{change} `{location}` · `{old_hash}` → `{new_hash}`")
        if new.get("final_url") != old.get("final_url") and new:
            details.append(f"  - 最终位置 `{file_label(new['final_url'])}`")
        if any(origin != target for origin, target in new.get("redirects", [])):
            reasons.add("依赖经明确允许的跨域跳转")
        new_kinds = {kind for kind, _, _ in new.get("findings", [])}
        old_network = {evidence for kind, _, evidence in old.get("findings", []) if kind == "network"}
        new_network = {evidence for kind, _, evidence in new.get("findings", []) if kind == "network"}
        if new_network - old_network:
            reasons.add("出现新的网络目的地或无法确定目的地的调用")
        if "execution" in new_kinds:
            reasons.add("发现动态执行或混淆线索，需核对输入来源")
        if "network" in new_kinds and new_kinds & {"sensitive", "storage"}:
            reasons.add("同一文件存在敏感数据或存储与网络调用，数据流未证实")
        elif "sensitive" in new_kinds:
            reasons.add("存在敏感信息处理线索，需核对读写与转发")
        for action, kind, line, evidence in evidence_delta(old.get("findings", ()), new.get("findings", ())):
            if initial and action == "新增":
                action = "观察到"
            details.append(f"  - {action} {LABELS.get(kind, '证据')} · 第 {safe(line, 8)} 行 · `{safe(evidence)}`")
    old_mitm = set(before.get("mitm", legacy.get("profile", {}).get("mitm", [])))
    new_mitm = set(after["mitm"])
    for prefix, difference in (("新增", new_mitm - old_mitm), ("删除", old_mitm - new_mitm)):
        if difference:
            details.append(f"- MITM hostname {prefix} " + "、".join(f"`{safe(host)}`" for host in sorted(difference)))
    if (before or "profile" in legacy) and (
        any(not host.startswith("-") for host in new_mitm - old_mitm)
        or any(host.startswith("-") for host in old_mitm - new_mitm)
    ):
        reasons.add("MITM 可能扩大（新增匹配或移除排除项）")
    if before:
        root_old = old_files.get(before.get("root"), {})
        root_new = new_files[after["root"]]
        old_matches = {evidence for kind, _, evidence in root_old.get("findings", ()) if kind == "mitm"}
        new_matches = {evidence for kind, _, evidence in root_new.get("findings", ()) if kind == "mitm"}
        if (any(not host.startswith("-") for host in new_matches - old_matches)
                or any(host.startswith("-") for host in old_matches - new_matches)):
            reasons.add("MITM 可能扩大（新增匹配或移除排除项）")
    before_edges = {(origin, target, mechanism): line for origin, target, line, mechanism in before.get("dependencies", [])}
    after_edges = {(origin, target, mechanism): line for origin, target, line, mechanism in after["dependencies"]}
    added = after_edges.keys() - before_edges.keys()
    removed = before_edges.keys() - after_edges.keys()
    if not after["graph_complete"]:
        details.append("- 本轮依赖图不完整，候选不可进入批准流程，保留上次完整图用于比较。")
    for prefix, edge_keys, edges in (
        ("首次观察" if initial else "新增", added, after_edges),
        ("移除", removed if after["graph_complete"] else set(), before_edges),
    ):
        for origin, target, mechanism in sorted(edge_keys, key=packed)[:12]:
            destination = file_label(target) if target else "目标未知"
            line = safe(edges[origin, target, mechanism], 8)
            details.append(
                f"- {prefix}依赖引用 · `{file_label(origin)}` 第 {line} 行 · "
                f"`{safe(mechanism)}` → `{destination}`"
            )
        if len(edge_keys) > 12:
            details.append(f"- 另有 {len(edge_keys) - 12} 条{prefix}的引用。")
    for url, line, issue in after["issues"][:12]:
        details.append(f"- `{file_label(url)}`" + (f" 第 {line} 行" if line else "") + f" · {safe(issue)}")
    if after["issues"]:
        reasons.add("存在未解析、不可下载或循环依赖")
    if len(after["issues"]) > 12:
        details.append(f"- 另有 {len(after['issues']) - 12} 项依赖异常")
    if initial:
        details.insert(0, "- 首次建立依赖基线，历史依赖行为无法比较。")
    high = any(reason.startswith(("MITM", "发现动态", "同一文件")) for reason in reasons)
    risk = "高" if high else "中" if reasons or before_edges != after_edges else "低（仅限已识别线索）"
    return [
        f"#### {safe(name)}",
        f"- Upstream / Candidate `{after['version']}` · Approved `{approved or '未指定'}`",
        f"- 风险 **{risk}**。依据：{'；'.join(sorted(reasons)) or '哈希或依赖记录变化，未发现上述高风险组合'}。",
        "- 建议冻结更新并人工审核。候选快照不改变批准版本。",
        *details,
    ]


def report_blocks(sources, snapshots, before, legacy, approved):
    current = before.copy()
    blocks = []
    for name in sources:
        after = snapshots.get(name)
        if after is None:
            continue
        old = baseline_record(before[name]) if name in before else {}
        prior = old.get("last_complete")
        observed = {"version": after["version"], "graph_complete": after["graph_complete"]}
        if old.get("last_observed") != observed:
            block = changes(name, prior or {}, after, legacy.get(name, {}), approved.get(name))
            if prior and prior["version"] == after["version"]:
                block.insert(3, "- 依赖图已恢复，候选与上一次完整版本一致。")
            blocks.append(block)
        current[name] = {
            "last_observed": observed,
            "last_complete": after if after["graph_complete"] else prior,
        }
    return current, blocks
