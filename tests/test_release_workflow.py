import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import prepare_rewrite, publish_rewrite as release, release_preflight
from scripts.upstream_graph import approved_versions
from scripts.upstream_transport import Download

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SAFE = f"hostname = example.com\n{release.RULE}\n".encode()


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
                return prepare_rewrite.prepare(repo, "a" * 40, lambda url, *args: Download(data, url, "text/plain"))

            git("init", "--bare", str(bare))
            git("init", "-b", "main")
            git("config", "user.name", "Fixture operator")
            git("config", "user.email", "fixture@example.invalid")
            git("remote", "add", "origin", str(bare))
            shutil.copytree(SCRIPTS, repo / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
            registry = repo / "upstream/modules.json"
            registry.parent.mkdir()
            shutil.copyfile(SCRIPTS.parent / "upstream/modules.json", registry)
            lock = repo / "manifests/approved.json"
            lock.parent.mkdir()
            lock.write_text("{}\n")
            git("add", ".")
            git("commit", "-m", "Initial fixture")
            git("push", "origin", "main")
            published = []
            for i, data in enumerate((SAFE, SAFE + b"# second fixture\n")):
                previous_lock = lock.read_bytes()
                material = os.environ.get("QX_TEST_MATERIAL") if i == 0 else None
                if material:
                    version = os.environ["QX_TEST_VERSION"]
                    for name in ("release-inputs", "manifests/approvals"):
                        shutil.copytree(Path(material) / name, repo / name)
                    reviewed = release.load_snapshot(repo / "release-inputs", version)
                    data = reviewed.data
                    self.assertEqual(data, (SCRIPTS.parent / release.PILOT).read_bytes())
                    print("Live downloaded ReleaseCheck passed the offline Git publication and rollback simulation input checks.")
                else:
                    version = prepare(data)
                self.assertEqual(lock.read_bytes(), previous_lock)
                git("add", "release-inputs", "manifests/approvals")
                git("commit", "-m", "Prepared review proposal")
                denied = action("build", version, root / f"denied-{i}", check=False)
                self.assertNotEqual(denied.returncode, 0)
                reviewed = release.load_snapshot(repo / "release-inputs", version)
                lock.write_text(json.dumps({release.ENTRY: release.approval_binding(reviewed)}))
                self.assertEqual(approved_versions(lock), {release.ENTRY: version})
                git("add", "manifests/approved.json")
                git("commit", "-m", "Fixture human approval")
                worktree = root / f"release-{i}"
                if i == 0:
                    original_registry = registry.read_text()
                    modules = json.loads(original_registry)
                    modules[release.ENTRY]["update_policy"] = "frozen"
                    registry.write_text(json.dumps(modules))
                    blocked = action("build", version, root / "frozen", release.ENTRY, check=False)
                    self.assertNotEqual(blocked.returncode, 0)
                    unmanaged = action("build", version, root / "unmanaged", "AmapAds", check=False)
                    self.assertNotEqual(unmanaged.returncode, 0)
                    registry.write_text(original_registry)
                action("build", version, worktree, release.ENTRY)
                action("push", version, worktree)
                commit = git("--git-dir", str(bare), "rev-parse", "refs/heads/rewrite-publications").stdout.decode().strip()
                path = f"published/ReleaseCheck/{version}/{release.FILE}"
                published.append((commit, path, data))
                for revision, saved_path, saved_data in published:
                    self.assertEqual(git("--git-dir", str(bare), "show", f"{revision}:{saved_path}").stdout, saved_data)
                duplicate = action("build", version, root / f"duplicate-{i}", check=False)
                self.assertNotEqual(duplicate.returncode, 0)
            first = published[0][1].split("/")[2]
            modules = json.loads(registry.read_text())
            modules[release.ENTRY]["update_policy"] = "frozen"
            registry.write_text(json.dumps(modules))
            subprocess.run(
                ["python3", "scripts/publish_rewrite.py", "verify-rollback", first,
                 "--module", release.ENTRY, "--output", str(root / "release-1/published")],
                cwd=repo, check=True, capture_output=True,
            )

    def test_preparation_rejects_current_upstream_shape_without_writing_material(self):
        raw = br"""hostname = www.google.cn
^https?:\/\/(www.)?(g|google)\.cn url 302 https://www.google.com
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, "ReleaseCheck 候选"):
                prepare_rewrite.prepare(root, "a" * 40, lambda url, *args: Download(raw, url, "text/plain"))
            self.assertEqual(list(root.iterdir()), [])


class PreflightTests(unittest.TestCase):
    def test_requires_rulesets_without_forcing_a_second_reviewer(self):
        publication = [{"type": "deletion"}, {"type": "non_fast_forward"}]
        main = [*publication, {"type": "pull_request", "parameters": {"required_approving_review_count": 0}}]
        release_preflight.check_rules(main, publication)
        for rules in ([], publication[:1], publication[1:]):
            with self.assertRaises(ValueError):
                release_preflight.check_rules(main, rules)
        with self.assertRaises(ValueError):
            release_preflight.check_rules(publication, publication)

    def test_only_owner_can_dispatch_and_rerun(self):
        release_preflight.check_dispatcher("Owner", "owner", "OWNER")
        for values in (("owner", "owner", "collaborator"), ("owner", "collaborator", "owner"),
                       ("owner", "bot[bot]", "owner"), ("", "", "")):
            with self.subTest(values=values), self.assertRaises(ValueError):
                release_preflight.check_dispatcher(*values)

    def test_personal_policy_requires_explicit_opt_in_and_public_user_owned_repo(self):
        def public(_):
            return {"private": False, "owner": {"type": "User"}}

        self.assertIn("已显式启用", release_preflight.check_policy("personal-owner", public))
        for policy, reader in (("", lambda _: []), ("typo", public), ("personal-owner", lambda _: {"private": True})):
            with self.assertRaises(ValueError):
                release_preflight.check_policy(policy, reader)
