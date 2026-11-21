"""Inspect effective GitHub release rules and the current run's owner identity."""

import argparse
import json
import os
import subprocess


def api(path):
    return json.loads(subprocess.check_output(
        ["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}" + (f"/{path}" if path else "")], text=True
    ))


def check_rules(main, publication):
    main_rules = {rule["type"] for rule in main}
    if not {"pull_request", "non_fast_forward", "deletion"} <= main_rules:
        raise ValueError("main 需要生效的 PR、禁止强推和禁止删除规则集")
    if not {"non_fast_forward", "deletion"} <= {rule["type"] for rule in publication}:
        raise ValueError("发布分支需要生效的禁止强推和删除规则集")


def check_dispatcher(owner, actor, triggering_actor):
    if not owner or {actor.lower(), triggering_actor.lower()} != {owner.lower()}:
        raise ValueError("只有仓库所有者可以派发或重跑发布")


def check_policy(policy, read):
    if policy == "personal-owner":
        repo = read("")
        if repo.get("private") is not False or repo.get("owner", {}).get("type") != "User":
            raise ValueError("单人兼容模式仅适用于个人拥有的公开仓库")
        return "已显式启用单人兼容模式；发布仍由所有者及精确批准锁控制"
    if policy not in ("", "rulesets"):
        raise ValueError("未知发布策略")
    check_rules(read("rules/branches/main"), read("rules/branches/rewrite-publications"))
    return "发布规则集检查通过"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("admin", "run"))
    args = parser.parse_args()
    if args.mode == "run":
        check_dispatcher(*(os.environ.get(key, "") for key in (
            "GITHUB_REPOSITORY_OWNER", "GITHUB_ACTOR", "GITHUB_TRIGGERING_ACTOR"
        )))
    print(check_policy(os.environ.get("QX_RELEASE_POLICY", ""), api))


if __name__ == "__main__":
    main()
