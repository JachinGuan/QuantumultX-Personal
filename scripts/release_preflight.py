"""Inspect effective GitHub release rules and the current run's human approval."""

import argparse
import json
import os
import subprocess


def api(path):
    return json.loads(subprocess.check_output(
        ["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/{path}"], text=True
    ))


def check_rules(main, publication):
    if not any(rule["type"] == "pull_request"
               and rule.get("parameters", {}).get("required_approving_review_count", 0) >= 1 for rule in main):
        raise ValueError("main 需要生效的规则集，要求批准 PR 且至少一名审核者")
    if not {"non_fast_forward", "deletion"} <= {rule["type"] for rule in publication}:
        raise ValueError("发布分支需要生效的禁止强推和删除规则集")


def check_approval_history(history, dispatchers):
    if not any(review.get("state") == "approved"
               and review.get("user", {}).get("login", "").lower() not in dispatchers | {""}
               and any(env.get("name") == "rewrite-release" for env in review.get("environments", []))
               for review in history):
        raise ValueError("没有可验证的独立环境批准记录")


def check_environment(environment):
    rules = environment.get("protection_rules", [])
    if not any(rule.get("type") == "required_reviewers" and rule.get("reviewers")
               and rule.get("prevent_self_review") is True for rule in rules):
        raise ValueError("rewrite-release 需要配置必需审核者和禁止自审")
    policy = environment.get("deployment_branch_policy") or {}
    if not policy.get("protected_branches") and not policy.get("custom_branch_policies"):
        raise ValueError("rewrite-release 需要配置部署分支限制")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("admin", "run"))
    args = parser.parse_args()
    check_rules(api("rules/branches/main"), api("rules/branches/rewrite-publications"))
    if args.mode == "admin":
        check_environment(api("environments/rewrite-release"))
    else:
        identities = {os.environ.get(key, "").lower() for key in ("GITHUB_ACTOR", "GITHUB_TRIGGERING_ACTOR")}
        check_approval_history(api(f"actions/runs/{os.environ['GITHUB_RUN_ID']}/approvals"), identities)
    print("释放前置条件检查通过")


if __name__ == "__main__":
    main()
