"""Review or publish an explicitly approved, dependency-free ReleaseCheck snapshot."""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
from time import monotonic

if __package__:
    from .upstream_graph import packed, sha, snapshot_version
    from .upstream_transport import MAX_BYTES, download, endpoint
else:
    from upstream_graph import packed, sha, snapshot_version
    from upstream_transport import MAX_BYTES, download, endpoint

ENTRY = "ReleaseCheck"
HEX = re.compile(r"[a-f0-9]{64}")
PILOT = "pilot/ReleaseCheck.conf"
SOURCE_BASE = "https://raw.githubusercontent.com/JachinGuan/QuantumultX-Personal/"
SOURCE_PATTERN = re.compile(re.escape(SOURCE_BASE) + r"[a-f0-9]{40}/" + re.escape(PILOT))
MITM_HOST = "example.com"
RULE = r"^https:\/\/example\.com/qx-release-check(?:[/?#]|$) url 302 https://example.org/"
FILE = "ReleaseCheck.conf"
METADATA_LIMIT = 128 * 1024


@dataclass(frozen=True)
class Snapshot:
    data: bytes
    review: dict


@contextmanager
def directory(name, parent=None):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def read_file(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("输入必须为普通文件")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("输入文件超过大小限制")
    return value


def unique_keys(items):
    result = dict(items)
    if len(result) != len(items):
        raise ValueError("JSON 含重复的键")
    return result


def parse_json(data):
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_keys)
    if not isinstance(value, dict):
        raise ValueError("清单必须是 JSON 对象")
    return value


def validate_rule(data):
    text = data.decode("utf-8").replace("\r\n", "\n")
    if any((ord(char) < 32 and char not in "\n\t") or ord(char) > 126 for char in text):
        raise ValueError("试点仅接受 ASCII 规则与注释")
    lines = [line for line in text.split("\n") if line.strip() and not line.startswith("#")]
    if lines != [f"hostname = {MITM_HOST}", RULE]:
        raise ValueError("仅支持明确限制 example.com 诊断路径的单条 HTTPS 目标 302 规则")


def valid_version(version):
    if not isinstance(version, str) or not HEX.fullmatch(version):
        raise ValueError("版本必须为完整小写 SHA-256")
    return version


def load_snapshot(input_dir, version):
    valid_version(version)
    with directory(input_dir) as base, directory(ENTRY, base) as entry, directory(version, entry) as snapshot:
        if set(os.listdir(snapshot)) != {"manifest.json", "objects"}:
            raise ValueError("快照存在缺失或意外文件")
        raw = read_file(snapshot, "manifest.json", METADATA_LIMIT)
        manifest = parse_json(raw)
        source = manifest.get("root")
        if (not isinstance(source, str) or not SOURCE_PATTERN.fullmatch(source)
                or manifest.get("entry") != ENTRY
                or manifest.get("version") != version or manifest.get("review_status") != "candidate"
                or manifest.get("graph_complete") is not True or manifest.get("fetch_failed") is not False
                or manifest.get("frozen") is not True or manifest.get("approval_eligible") is not True
                or manifest.get("dependencies") != [] or manifest.get("issues") != []
                or manifest.get("mitm") != [MITM_HOST]):
            raise ValueError("仅接受通过完整性检查且没有依赖的 ReleaseCheck 候选")
        files = manifest.get("files")
        if not isinstance(files, dict) or set(files) != {source} or not isinstance(files[source], dict):
            raise ValueError("依赖闭包必须恰好包含 ReleaseCheck 入口")
        node = files[source]
        digest = valid_version(node.get("sha256"))
        endpoint(source)
        if (node.get("original_url") != source or node.get("final_url") != source
                or node.get("redirects") != [] or node.get("kind") != "rewrite"
                or node.get("review_status") != "candidate"
                or node.get("media_type") not in ("text/plain", "text/x-conf", "application/octet-stream",
                                                  "binary/octet-stream")):
            raise ValueError("快照源、跳转、资源类型或文件状态不符合发布策略")
        if snapshot_version(source, files, [], []) != version:
            raise ValueError("版本 ID 与快照闭包不符")
        filename = digest + ".blob"
        with directory("objects", snapshot) as objects:
            if os.listdir(objects) != [filename]:
                raise ValueError("对象目录必须恰好包含唯一入口文件")
            data = read_file(objects, filename, MAX_BYTES)
    if sha(data) != digest:
        raise ValueError("入口文件 SHA-256 不匹配")
    validate_rule(data)
    # Only immutable bytes leave this function. Publication never opens the source again.
    return Snapshot(data, {"schema": 1, "entry": ENTRY, "version": version,
                           "manifest_sha256": sha(raw), "files": {source: digest}})


def approval_binding(reviewed):
    return {key: reviewed.review[key] for key in ("version", "manifest_sha256")}


def check_approval(manifests, reviewed, *, require_active):
    version = reviewed.review["version"]
    with directory(manifests) as root:
        if require_active:
            active = parse_json(read_file(root, "approved.json", METADATA_LIMIT))
            if active.get(ENTRY) != approval_binding(reviewed):
                raise ValueError("人工批准锁未绑定当前版本与清单 SHA-256")
        with directory("approvals", root) as approvals, directory(ENTRY, approvals) as entry:
            record = parse_json(read_file(entry, version + ".json", METADATA_LIMIT))
    if packed(record) != packed(reviewed.review):
        raise ValueError("受审记录与快照清单或入口字节不一致")


def verify_origin(reviewed, fetch=download):
    source, = reviewed.review["files"]
    response = fetch(source, {"url": source, "kind": "rewrite"}, monotonic() + 15, MAX_BYTES)
    if response.final_url != source or response.redirects or response.data != reviewed.data:
        raise ValueError("固定提交的来源字节或最终 URL 与受审快照不一致")


def write_new(parent, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def publish(reviewed, manifests, output):
    check_approval(manifests, reviewed, require_active=True)
    version = reviewed.review["version"]
    with directory(output) as root:
        try:
            os.mkdir(ENTRY, dir_fd=root)
        except FileExistsError:
            pass
        with directory(ENTRY, root) as entry:
            # Exclusive directory creation rejects duplicates, including partial prior output.
            os.mkdir(version, dir_fd=entry)
            names = []
            try:
                with directory(version, entry) as release:
                    for name, data in ((FILE, reviewed.data), ("receipt.json", packed(reviewed.review) + b"\n")):
                        names.append(name)
                        write_new(release, name, data)
            except OSError:
                with directory(version, entry) as release:
                    for name in names:
                        try:
                            os.unlink(name, dir_fd=release)
                        except FileNotFoundError:
                            pass
                os.rmdir(version, dir_fd=entry)
                raise


def verify_rollback(reviewed, manifests, output):
    check_approval(manifests, reviewed, require_active=False)
    version = reviewed.review["version"]
    with directory(output) as root, directory(ENTRY, root) as entry, directory(version, entry) as release:
        if set(os.listdir(release)) != {FILE, "receipt.json"}:
            raise ValueError("旧发布目录不完整")
        if packed(parse_json(read_file(release, "receipt.json", METADATA_LIMIT))) != packed(reviewed.review):
            raise ValueError("旧发布凭据与受审快照不一致")
        if read_file(release, FILE, MAX_BYTES) != reviewed.data:
            raise ValueError("旧发布文件与受审快照不一致")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("review", "publish", "verify-origin", "verify-rollback"))
    parser.add_argument("version")
    parser.add_argument("--input-dir", type=Path, default=Path("release-inputs"))
    parser.add_argument("--manifests", type=Path, default=Path("manifests"))
    parser.add_argument("--output", type=Path, default=Path("published"))
    args = parser.parse_args()
    try:
        result = load_snapshot(args.input_dir, args.version)
        if args.action == "review":
            print(json.dumps(result.review, indent=2))
        elif args.action == "publish":
            publish(result, args.manifests, args.output)
        elif args.action == "verify-origin":
            check_approval(args.manifests, result, require_active=True)
            verify_origin(result)
        else:
            verify_rollback(result, args.manifests, args.output)
    except (OSError, ValueError, RecursionError) as exc:
        parser.exit(1, f"校验或发布失败 · {exc.strerror if isinstance(exc, OSError) else '输入不符合发布策略'}\n")


if __name__ == "__main__":
    main()
