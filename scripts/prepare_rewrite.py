"""Prepare ReleaseCheck review material without changing the active approval lock."""

import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile

if __package__:
    from . import check_upstream as monitor, publish_rewrite as release, upstream_graph as graph
else:
    import check_upstream as monitor
    import publish_rewrite as release
    import upstream_graph as graph


def prepare(root, revision, fetch=graph.download):
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("来源必须为完整 Git 提交 SHA")
    url = f"{release.SOURCE_BASE}{revision}/{release.PILOT}"
    # Never stage bytes that fail the exact same validation used by the publisher.
    with tempfile.TemporaryDirectory() as scratch:
        candidates = Path(scratch)
        runner = graph.GraphMonitor(monitor.validate, monitor.profile, monitor.InvalidContent, fetch=fetch)
        source = {"url": url, "kind": "rewrite"}
        resource = runner.load(url, "rewrite", source)
        if isinstance(resource, str):
            raise ValueError("上游下载或内容校验失败，未生成审核材料")
        snapshot = runner.walk(release.ENTRY, source, resource)
        version = snapshot["version"]
        runner.export(candidates, snapshot)
        reviewed = release.load_snapshot(candidates, version)
        destination = root / "release-inputs" / release.ENTRY / version
        record = root / "manifests" / "approvals" / release.ENTRY / (version + ".json")
        if destination.exists() or record.exists():
            raise ValueError("审核材料已存在")
        destination.parent.mkdir(parents=True, exist_ok=True)
        record.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(candidates / release.ENTRY / version, destination)
        with record.open("x", encoding="utf-8") as handle:
            json.dump(reviewed.review, handle, indent=2)
            handle.write("\n")
        return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("--output", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        print(prepare(args.output, args.revision))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"准备审核材料失败 · {exc}\n")


if __name__ == "__main__":
    main()
