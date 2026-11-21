"""Inspect effective GitHub release rules and the current run's owner identity."""

import argparse
import json
import os
import subprocess


def api(path):
    return json.loads(subprocess.check_output(
        ["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/{path}"], text=True
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("admin", "run"))
    args = parser.parse_args()
    if args.mode == "run":
        check_dispatcher(*(os.environ.get(key, "") for key in (
            "GITHUB_REPOSITORY_OWNER", "GITHUB_ACTOR", "GITHUB_TRIGGERING_ACTOR"
        )))
    check_rules(api("rules/branches/main"), api("rules/branches/rewrite-publications"))
    print("发布前置条件检查通过")


if __name__ == "__main__":
    main()
