import io
import json
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_upstream as monitor
from scripts import publish_rewrite as release
from scripts.upstream_graph import GraphMonitor
from scripts.upstream_transport import Download, DownloadError

SOURCE = release.SOURCE_BASE + "a" * 40 + "/" + release.PILOT
SAFE = ("hostname = example.com\n\n# Fixture\n" + release.RULE + "\n").encode()
UNSAFE = br"""hostname = www.google.cn
^https?:\/\/(www.)?(g|google)\.cn url 302 https://www.google.com
"""


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "release-inputs"
        self.manifests = self.root / "manifests"
        self.approvals = self.manifests / "approvals" / release.ENTRY
        self.approvals.mkdir(parents=True)
        self.active = self.manifests / "approved.json"
        self.active.write_text("{}")
        self.output = self.root / "published"
        self.output.mkdir()
        self.version = self.export(SAFE)
        self.candidate = self.inputs / release.ENTRY / self.version
        self.record = self.approvals / (self.version + ".json")
        self.reviewed = release.load_snapshot(self.inputs, self.version)

    def export(self, rule, error=None):
        def fetch(url, _source, _deadline, _limit):
            if error:
                raise error
            return Download(rule, url, "text/plain")

        graph = GraphMonitor(monitor.validate, monitor.profile, monitor.InvalidContent, fetch=fetch)
        source = {"url": SOURCE, "kind": "rewrite"}
        root = graph.load(SOURCE, "rewrite", source)
        if isinstance(root, str):
            return None
        snapshot = graph.walk(release.ENTRY, source, root)
        graph.export(self.inputs, snapshot)
        return snapshot["version"]

    def approve_fixture(self):
        self.active.write_text(json.dumps({release.ENTRY: release.approval_binding(self.reviewed)}))
        self.record.write_text(json.dumps(self.reviewed.review))

    def edit_manifest(self, update):
        path = self.candidate / "manifest.json"
        manifest = json.loads(path.read_bytes())
        update(manifest)
        path.write_text(json.dumps(manifest))

    def test_publication_requires_active_lock_and_exact_review_record(self):
        with self.assertRaisesRegex(ValueError, "人工批准锁"):
            release.publish(self.reviewed, self.manifests, self.output)
        self.active.write_text(json.dumps({release.ENTRY: self.version}))
        with self.assertRaisesRegex(ValueError, "人工批准锁"):
            release.publish(self.reviewed, self.manifests, self.output)
        self.active.write_text(json.dumps({release.ENTRY: release.approval_binding(self.reviewed)}))
        with self.assertRaises(FileNotFoundError):
            release.publish(self.reviewed, self.manifests, self.output)
        self.approve_fixture()
        self.record.write_text(json.dumps({**self.reviewed.review, "manifest_sha256": "0" * 64}))
        with self.assertRaisesRegex(ValueError, "受审记录"):
            release.publish(self.reviewed, self.manifests, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_publish_cli_rejects_ineligible_modules_and_wrong_versions_without_writing(self):
        self.approve_fixture()
        lock = self.active.read_bytes()
        registry = self.root / "modules.json"
        registered = {"monitor_enabled": False, "client_enabled": None, "managed": True,
                      "update_policy": "review", "risk_status": "watch"}
        cases = (
            (release.ENTRY, self.version, {release.ENTRY: {**registered, "managed": False}}),
            (release.ENTRY, self.version, {release.ENTRY: {**registered, "update_policy": "frozen"}}),
            ("UnknownModule", self.version, {release.ENTRY: registered}),
            (release.ENTRY, "../" + self.version, {release.ENTRY: registered}),
            (release.ENTRY, "0" * 64, {release.ENTRY: registered}),
        )
        for module, version, modules in cases:
            with self.subTest(module=module, version=version, modules=modules):
                registry.write_text(json.dumps(modules))
                args = ["publish_rewrite.py", "publish", version, "--module", module,
                        "--registry", str(registry), "--input-dir", str(self.inputs),
                        "--manifests", str(self.manifests), "--output", str(self.output)]
                with patch("sys.argv", args), patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    with self.assertRaises(SystemExit) as result:
                        release.main()
                self.assertEqual(result.exception.code, 1)
                self.assertIn("校验或发布失败", stderr.getvalue())
                self.assertEqual(list(self.output.iterdir()), [])
                self.assertEqual(self.active.read_bytes(), lock)
                self.assertEqual(release.load_snapshot(self.inputs, self.version), self.reviewed)

    def test_manifest_tampering_after_review_is_rejected(self):
        self.approve_fixture()
        self.edit_manifest(lambda manifest: manifest.update(checked_at="changed"))
        modified = release.load_snapshot(self.inputs, self.version)
        self.record.write_text(json.dumps(modified.review))
        with self.assertRaisesRegex(ValueError, "人工批准锁"):
            release.publish(modified, self.manifests, self.output)

    def test_duplicate_refuses_overwrite_and_publish_uses_verified_bytes(self):
        self.approve_fixture()
        next((self.candidate / "objects").iterdir()).write_bytes(b"changed after read")
        release.publish(self.reviewed, self.manifests, self.output)
        file = self.output / release.ENTRY / self.version / release.FILE
        self.assertEqual(file.read_bytes(), SAFE)
        with self.assertRaises(FileExistsError):
            release.publish(self.reviewed, self.manifests, self.output)
        self.assertEqual(file.read_bytes(), SAFE)

    def test_rollback_requires_previously_published_bytes_and_historical_approval(self):
        self.approve_fixture()
        with self.assertRaises(FileNotFoundError):
            release.verify_rollback(self.reviewed, self.manifests, self.output)
        release.publish(self.reviewed, self.manifests, self.output)
        self.active.write_text(json.dumps({release.ENTRY: "a" * 64}))
        release.verify_rollback(self.reviewed, self.manifests, self.output)
        file = self.output / release.ENTRY / self.version / release.FILE
        file.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "旧发布文件"):
            release.verify_rollback(self.reviewed, self.manifests, self.output)

    def test_missing_object_hash_mismatch_and_symlink(self):
        object_file = next((self.candidate / "objects").iterdir())
        object_file.write_bytes(b"wrong digest")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            release.load_snapshot(self.inputs, self.version)
        object_file.unlink()
        with self.assertRaises(ValueError):
            release.load_snapshot(self.inputs, self.version)
        alternate = self.root / "file"
        alternate.write_bytes(SAFE)
        object_file.symlink_to(alternate)
        with self.assertRaises(OSError):
            release.load_snapshot(self.inputs, self.version)

    def test_rejects_manifest_incomplete_nested_or_non_https(self):
        raw = (self.candidate / "manifest.json").read_bytes()
        for update in (
            lambda m: m.update(graph_complete=False),
            lambda m: m.update(issues=["unknown"]),
            lambda m: m.update(dependencies=[{"from": SOURCE, "to": "https://example.test/x.js"}]),
            lambda m: m["files"][SOURCE].update(final_url="http://example.test/conf"),
            lambda m: m.update(root="../../escape"),
        ):
            with self.subTest(update=update):
                (self.candidate / "manifest.json").write_bytes(raw)
                self.edit_manifest(update)
                with self.assertRaises(ValueError):
                    release.load_snapshot(self.inputs, self.version)

    def test_rejects_ambiguous_regex_and_hidden_rewrite_or_js(self):
        unsafe = (
            UNSAFE,
            SAFE + b"^https://x url script-response-body https://example.test/x.js\n",
            SAFE.replace(b"https://example.org/", b"http://example.org/"),
            SAFE.replace(b"example.org", b"example.org.evil.test"),
            SAFE + b"[rewrite_local]\n",
        )
        for data in unsafe:
            with self.subTest(data=data), self.assertRaises(ValueError):
                release.validate_rule(data)
        version = self.export(UNSAFE)
        with self.assertRaisesRegex(ValueError, "ReleaseCheck 候选"):
            release.load_snapshot(self.inputs, version)

    def test_rejects_unsafe_version_and_symlinked_output(self):
        with self.assertRaises(ValueError):
            release.load_snapshot(self.inputs, "../../escape")
        self.approve_fixture()
        (self.output / release.ENTRY).symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            release.publish(self.reviewed, self.manifests, self.output)
        self.assertFalse((self.root / self.version).exists())

    def test_download_failure_cannot_generate_publishable_snapshot(self):
        before = list(self.inputs.glob("**/manifest.json"))
        self.assertIsNone(self.export(SAFE, DownloadError("timeout")))
        self.assertEqual(list(self.inputs.glob("**/manifest.json")), before)

    def test_origin_must_match_pinned_url_and_exact_bytes(self):
        release.verify_origin(self.reviewed, lambda url, *args: Download(SAFE, url, "text/plain"))
        for data, url in ((SAFE + b"# extra", SOURCE), (SAFE, "https://elsewhere.example/a.conf")):
            with self.assertRaisesRegex(ValueError, "来源字节"):
                release.verify_origin(self.reviewed, lambda *args: Download(data, url, "text/plain"))

    def test_modules_with_same_version_have_separate_approval_and_rollback(self):
        self.approve_fixture()
        other = "OtherFixture"
        candidate = self.inputs / other / self.version
        shutil.copytree(self.candidate, candidate)
        manifest = candidate / "manifest.json"
        metadata = json.loads(manifest.read_bytes())
        manifest.write_text(json.dumps({**metadata, "entry": other}))
        with patch.dict(release.POLICIES, {other: release.POLICIES[release.ENTRY]}):
            reviewed_other = release.load_snapshot(self.inputs, self.version, module=other)
            with self.assertRaisesRegex(ValueError, "人工批准锁"):
                release.publish(reviewed_other, self.manifests, self.output)
            active = json.loads(self.active.read_bytes())
            self.active.write_text(json.dumps({**active, other: release.approval_binding(reviewed_other)}))
            other_records = self.approvals.parent / other
            other_records.mkdir()
            (other_records / self.record.name).write_text(json.dumps(reviewed_other.review))
            release.publish(reviewed_other, self.manifests, self.output)
            with self.assertRaises(FileNotFoundError):
                release.verify_rollback(self.reviewed, self.manifests, self.output)
            release.publish(self.reviewed, self.manifests, self.output)
            for reviewed, name in ((self.reviewed, release.ENTRY), (reviewed_other, other)):
                release.verify_rollback(reviewed, self.manifests, self.output)
                self.assertEqual((self.output / name / self.version / (name + ".conf")).read_bytes(), SAFE)

    def test_failed_staging_leaves_no_release(self):
        self.approve_fixture()
        original = release.write_new
        def write(parent, name, data):
            if name == "receipt.json":
                raise OSError("disk full")
            original(parent, name, data)

        with patch.object(release, "write_new", side_effect=write), self.assertRaises(OSError):
            release.publish(self.reviewed, self.manifests, self.output)
        self.assertFalse((self.output / release.ENTRY / self.version).exists())
