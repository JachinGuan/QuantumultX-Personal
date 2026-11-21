import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import prepare_rewrite, publish_rewrite as release, release_preflight
from scripts.upstream_transport import Download

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SAFE = f"hostname = www.google.cn\n{release.RULE}\n".encode()


class WorkflowTests(unittest.TestCase):
    def test_review_proposal_to_versioned_remote_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "checkout"
            repo.mkdir()
            bare = root / "remote"

            def git(*args, check=True):
                return subprocess.run(["git", *args], cwd=repo, capture_output=True, check=check)

            def action(*args, check=True):
                return subprocess.run(["bash", "scripts/release_git.sh", *map(str, args)],
                                      cwd=repo, capture_output=True, check=check)

            def prepare(data):
                return prepare_rewrite.prepare(repo, lambda url, *args: Download(data, url, "text/plain"))

            git("init", "--bare", str(bare))
            git("init", "-b", "main")
            git("config", "user.name", "Fixture operator")
            git("config", "user.email", "fixture@example.invalid")
            git("remote", "add", "origin", str(bare))
            shutil.copytree(SCRIPTS, repo / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
            lock = repo / "manifests/approved.json"
            lock.parent.mkdir()
            lock.write_text("{}\n")
            git("add", ".")
            git("commit", "-m", "Initial fixture")
            git("push", "origin", "main")
            published = []
            for i, data in enumerate((SAFE, SAFE + b"# second fixture\n")):
                previous_lock = lock.read_bytes()
                version = prepare(data)
                self.assertEqual(lock.read_bytes(), previous_lock)
                git("add", "release-inputs", "manifests/approvals")
                git("commit", "-m", "Prepared review proposal")
                denied = action("build", version, root / f"denied-{i}", check=False)
                self.assertNotEqual(denied.returncode, 0)
                lock.write_text(json.dumps({release.ENTRY: version}))
                git("add", "manifests/approved.json")
                git("commit", "-m", "Fixture human approval")
                worktree = root / f"release-{i}"
                action("build", version, worktree)
                action("push", version, worktree)
                commit = git("--git-dir", str(bare), "rev-parse", "refs/heads/rewrite-publications").stdout.decode().strip()
                path = f"published/GoogleRedirect/{version}/{release.FILE}"
                published.append((commit, path, data))
                for revision, saved_path, saved_data in published:
                    self.assertEqual(git("--git-dir", str(bare), "show", f"{revision}:{saved_path}").stdout, saved_data)
                duplicate = action("build", version, root / f"duplicate-{i}", check=False)
                self.assertNotEqual(duplicate.returncode, 0)
            first = published[0][1].split("/")[2]
            reviewed = release.load_snapshot(repo / "release-inputs", first)
            release.verify_rollback(reviewed, repo / "manifests", root / "release-1/published")

    def test_preparation_rejects_current_upstream_shape_without_writing_material(self):
        raw = br"""hostname = www.google.cn
^https?:\/\/(www.)?(g|google)\.cn url 302 https://www.google.com
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "主机边界"):
                prepare_rewrite.prepare(root, lambda url, *args: Download(raw, url, "text/plain"))
            self.assertEqual(list(root.iterdir()), [])


class PreflightTests(unittest.TestCase):
    def test_requires_pr_review_no_force_and_no_deletion(self):
        main = [{"type": "pull_request", "parameters": {"required_approving_review_count": 1}}]
        publication = [{"type": "deletion"}, {"type": "non_fast_forward"}]
        release_preflight.check_rules(main, publication)
        for rules in ([], publication[:1], publication[1:]):
            with self.assertRaises(ValueError):
                release_preflight.check_rules(main, rules)
        with self.assertRaises(ValueError):
            release_preflight.check_rules([], publication)

    def test_requires_independent_approval_for_correct_environment(self):
        review = {"user": {"login": "Reviewer"}, "state": "approved", "environments": [{"name": "rewrite-release"}]}
        release_preflight.check_approval_history([review], {"dispatcher"})
        for history, identities in (([], set()), ([review], {"reviewer"}),
                                    ([{**review, "environments": [{"name": "test"}]}], set())):
            with self.assertRaises(ValueError):
                release_preflight.check_approval_history(history, identities)

    def test_admin_environment_requires_reviewers_and_no_self_review(self):
        rule = {"type": "required_reviewers", "reviewers": [{"type": "User"}], "prevent_self_review": True}
        env = {"protection_rules": [rule], "deployment_branch_policy": {"protected_branches": True}}
        release_preflight.check_environment(env)
        rule["prevent_self_review"] = False
        with self.assertRaises(ValueError):
            release_preflight.check_environment(env)
