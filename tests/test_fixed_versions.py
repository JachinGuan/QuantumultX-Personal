import unittest
from unittest.mock import Mock, patch

from scripts import fixed_versions as book, upstream_graph as graph
from scripts.upstream_transport import Download, DownloadError

SOURCE = "https://raw.githubusercontent.com/demo/rules/master/a.conf"
PIN = "https://raw.githubusercontent.com/demo/rules/" + "b" * 40 + "/a.conf"
DIGEST = "a" * 64
BASELINE = {"url": SOURCE, "sha256": DIGEST, "profile": {}}
PINNED = {"source": SOURCE, "entry": PIN, "sha256": DIGEST, "dependencies": {},
          "license_confirmed": True, "license_evidence": "https://github.com/demo/rules/blob/main/LICENSE"}
ROOT = {"root": SOURCE, "files": {SOURCE: {"sha256": DIGEST}}, "dependencies": []}
COMPLETE = {"last_complete": ROOT, "last_observed": {"graph_complete": True}}


class FixedVersionsTests(unittest.TestCase):
    def test_dynamic_or_moving_dependency_never_offers_link(self):
        for dep in (None, "https://raw.githubusercontent.com/demo/rules/master/script.js",
                    "https://github.com/demo/rules/releases/download/v1/script.js"):
            with self.subTest(dep=dep):
                files = ROOT["files"].copy()
                if dep:
                    files[dep] = {"sha256": DIGEST}
                item = {**ROOT, "files": files, "dependencies": [(SOURCE, dep, 1, "QX script action")]}
                status, _, pin = book.assess({"url": SOURCE}, BASELINE,
                                             {**COMPLETE, "last_complete": item}, {}, [PINNED], Mock())
                self.assertIn("未完整冻结", status)
                self.assertIsNone(pin)

    def test_stale_source_or_hash_requires_research_before_switching(self):
        for source, baseline, record in (
            ({"url": SOURCE + "x"}, BASELINE, COMPLETE),
            ({"url": SOURCE}, {**BASELINE, "sha256": "c" * 64}, COMPLETE),
            ({"url": SOURCE}, BASELINE, {**COMPLETE, "last_observed": {"graph_complete": False}}),
        ):
            with self.subTest(source=source, baseline=baseline):
                verify = Mock()
                self.assertIsNone(book.assess(source, baseline, record, {}, [PINNED], verify)[2])
                verify.assert_not_called()

    def test_rollback_uses_archived_matching_baseline_and_leaves_source_unchanged(self):
        source = {"url": SOURCE}
        verify = Mock(return_value=True)
        latest = {**BASELINE, "sha256": "d" * 64}
        self.assertIsNone(book.assess(source, latest, COMPLETE, {}, [PINNED], verify)[2])
        self.assertEqual(book.assess(source, BASELINE, COMPLETE, {}, [PINNED], verify)[2], PIN)
        self.assertEqual(source, {"url": SOURCE})

    def test_no_reference_offline_license_and_failed_verification_keep_original(self):
        for references, signals, verify in (
            ([], [], Mock(return_value=True)),
            ([PINNED], [], None),
            ([PINNED], [], Mock(return_value=False)),
            ([PINNED], ["html"], Mock(return_value=True)),
            ([{**PINNED, "license_confirmed": False}], [], Mock(return_value=True)),
        ):
            source = {"url": SOURCE}
            self.assertIsNone(book.assess(source, BASELINE, COMPLETE, {"signals": signals}, references, verify)[2])
            self.assertEqual(source["url"], SOURCE)

    def test_pin_must_keep_publisher_path_and_include_license_evidence(self):
        verify = Mock(return_value=True)
        for record in (
            {**PINNED, "entry": PIN.replace("/demo/", "/someone-else/")},
            {**PINNED, "entry": PIN.replace("/a.conf", "/other.conf")},
            {**PINNED, "license_evidence": None},
        ):
            with self.subTest(record=record):
                candidate = book.assess({"url": SOURCE}, BASELINE, COMPLETE, {}, [record], verify)[2]
                self.assertIsNone(candidate)
        verify.assert_not_called()

    def test_unknown_client_and_frozen_module(self):
        module = {"client_enabled": None, "monitor_enabled": True, "update_policy": "frozen"}
        verify = Mock(return_value=True)
        report = book.render({"Demo": {"url": SOURCE}}, {"Demo": module}, {"Demo": BASELINE},
                             {"Demo": COMPLETE}, {}, {"license": {}, "references": {"Demo": [PINNED]}}, verify)
        self.assertIn("未知", report)
        self.assertIn(SOURCE, report)
        self.assertNotIn(PIN, report)
        verify.assert_not_called()

    def test_live_verifier_requires_exact_bytes_and_no_unknown_references(self):
        data = b"^https://example.test url reject\n"
        for payload, digest, expected in (
            (data, graph.sha(data), True),
            (data, DIGEST, False),
            (DownloadError("offline"), graph.sha(data), False),
        ):
            factory = graph.GraphMonitor

            def fetch(url, *_):
                if isinstance(payload, Exception):
                    raise payload
                return Download(payload, url, "text/plain")

            with patch.object(graph, "GraphMonitor", side_effect=lambda *args: factory(*args, fetch=fetch)):
                self.assertEqual(book.verify_reference({"kind": "rewrite"}, {**PINNED, "sha256": digest}), expected)
