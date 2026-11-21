import json
from pathlib import Path
import socket
import tempfile
from time import monotonic
import unittest
from unittest.mock import MagicMock, patch

from scripts import check_upstream as monitor
from scripts import upstream_graph as graph
from scripts import upstream_scan as scan
from scripts import upstream_transport as transport


ROOT = "https://config.example.test/main.conf"
FIRST = "https://scripts.example.test/first.js"
SECOND = "https://scripts.example.test/second.js"
SOURCE = {"url": ROOT, "kind": "rewrite"}
SOURCES = {"Example": SOURCE}


def rewrite(host="api.example.test", action="script-response-body"):
    return f"^https://api url {action} {FIRST}\nhostname = {host}\n".encode()


def fixture(data, final=ROOT, mime="text/plain"):
    return transport.Download(data, final, mime)


class GraphTests(unittest.TestCase):
    def run_graph(self, files, **limits):
        def fetch(url, source, deadline, limit):
            response = files[url]
            if isinstance(response, Exception):
                raise response
            return response

        run = graph.GraphMonitor(monitor.validate, monitor.profile, monitor.InvalidContent, fetch=fetch, **limits)
        root = run.load(ROOT, "rewrite", SOURCE)
        return run, run.walk("Example", SOURCE, root)

    def test_detects_dependency_only_change_and_sanitized_evidence_diff(self):
        old = {
            ROOT: fixture(rewrite()),
            FIRST: fixture(b'fetch("https://old.example.test");\nconst x = 1;', FIRST),
        }
        new = {
            **old,
            FIRST: fixture(
                b'const c = $request.headers["Authorization"];\n'
                b'fetch("https://new.example.test/path?token=never-copy");\n'
                b'$prefs.setValueForKey(c, "private");', FIRST
            ),
        }
        _, before = self.run_graph(old)
        _, after = self.run_graph(new)
        _, blocks = graph.report_blocks(SOURCES, {"Example": after}, {"Example": before}, {}, {})
        report = "\n".join(blocks[0])
        self.assertEqual(before["files"][ROOT]["sha256"], after["files"][ROOT]["sha256"])
        self.assertNotEqual(before["version"], after["version"])
        for expected in ("first.js", "**高**", "old.example.test", "new.example.test", "第 2 行",
                         "Authorization", "持久化操作", before["files"][FIRST]["sha256"],
                         after["files"][FIRST]["sha256"]):
            self.assertIn(expected, report)
        self.assertNotIn("never-copy", report)
        self.assertNotIn("入口变化", report)

    def test_resolves_multilevel_and_cycles_with_one_fetch_per_url(self):
        files = {
            ROOT: fixture(rewrite()),
            FIRST: fixture(b'import "./second.js";', FIRST),
            SECOND: fixture(b'import("./first.js");', SECOND),
        }
        run, snapshot = self.run_graph(files)
        self.assertEqual(set(snapshot["files"]), set(files))
        self.assertEqual(len(run.cache), 3)
        self.assertTrue(any("循环" in issue[2] for issue in snapshot["issues"]))
        self.assertIn((SECOND, FIRST, 1, "import"), snapshot["dependencies"])
        self.assertFalse(snapshot["graph_complete"])

    def test_dynamic_and_policy_rejected_references_are_unknown(self):
        files = {
            ROOT: fixture(rewrite()),
            FIRST: fixture(b'import(prefix + "/x.js");\nrequire("https://127.0.0.1/x.js");'
                           b'\nimport(`https://x.test/${key}.js`);', FIRST),
        }
        run, snapshot = self.run_graph(files)
        self.assertEqual(len(run.cache), 2)
        self.assertEqual(sum(target is None for _, target, _, _ in snapshot["dependencies"]), 3)
        self.assertTrue(snapshot["frozen"])

    def test_invalid_scripts_or_download_errors_preserve_comparison_baseline(self):
        valid_files = {ROOT: fixture(rewrite()), FIRST: fixture(b"const x = 1;", FIRST)}
        _, before = self.run_graph(valid_files)
        for invalid in (fixture(b"<html>oops</html>", FIRST, "text/html"),
                        fixture(b"Access denied", FIRST), TimeoutError(),
                        transport.DownloadError("跨域重定向未经允许"),
                        fixture(b"x" * (transport.MAX_BYTES + 1), FIRST)):
            with self.subTest(invalid=type(invalid)):
                _, after = self.run_graph({**valid_files, FIRST: invalid})
                state, blocks = graph.report_blocks(SOURCES, {"Example": after}, {"Example": before}, {}, {})
                self.assertTrue(after["fetch_failed"])
                self.assertEqual(state["Example"]["last_complete"], before)
                self.assertNotIn("依赖移除", "\n".join(blocks[0]))
                _, repeated = graph.report_blocks(SOURCES, {"Example": after}, state, {}, {})
                self.assertEqual(repeated, [])

    def test_success_two_different_failures_then_recovery(self):
        good = {ROOT: fixture(rewrite()), FIRST: fixture(b'import "./second.js";', FIRST),
                SECOND: fixture(b"const second = 1;", SECOND)}
        _, complete = self.run_graph(good)
        state, _ = graph.report_blocks(SOURCES, {"Example": complete}, {}, {}, {})
        for url in (FIRST, SECOND):
            _, incomplete = self.run_graph({**good, url: TimeoutError()})
            state, reports = graph.report_blocks(SOURCES, {"Example": incomplete}, state, {}, {})
            self.assertEqual(state["Example"]["last_complete"], complete)
            self.assertEqual(state["Example"]["last_observed"]["version"], incomplete["version"])
            self.assertNotIn("files", state["Example"])
            self.assertIn(graph.file_label(url), "\n".join(reports[0]))
            self.assertNotIn("依赖移除", "\n".join(reports[0]))
        state, reports = graph.report_blocks(SOURCES, {"Example": complete}, state, {}, {})
        self.assertIn("依赖图已恢复", "\n".join(reports[0]))
        self.assertEqual(state["Example"]["last_complete"], complete)

    def test_unresolved_never_replaces_complete_or_becomes_approval_eligible(self):
        good = {ROOT: fixture(rewrite()), FIRST: fixture(b"const value = 1;", FIRST)}
        _, complete = self.run_graph(good)
        _, dynamic = self.run_graph({**good, FIRST: fixture(b'import(dynamicUrl);', FIRST)})
        self.assertFalse(dynamic["fetch_failed"])
        self.assertFalse(dynamic["approval_eligible"])
        state, reports = graph.report_blocks(SOURCES, {"Example": dynamic}, {"Example": complete}, {}, {})
        self.assertEqual(state["Example"]["last_complete"], complete)
        self.assertIn("不可进入批准流程", "\n".join(reports[0]))
        migrated = graph.read_graph(graph.serialize_graph({"Example": {**dynamic, "last_complete": complete}}))
        self.assertEqual(migrated, graph.read_graph(graph.serialize_graph(state)))
        only_dynamic = graph.read_graph(graph.serialize_graph({"Example": dynamic}))
        self.assertIsNone(only_dynamic["Example"]["last_complete"])

    def test_release_dependency_inherits_only_same_project_asset_permissions(self):
        root = "https://github.com/owner/project/releases/latest/download/main.snippet"
        child = "https://github.com/owner/project/releases/download/v1/handler.js"
        asset = "https://release-assets.githubusercontent.com/asset?signature=value"
        source = {"url": root, "kind": "rewrite", "redirect_hosts": ["release-assets.githubusercontent.com"]}
        policy = graph.dependency_policy(source, child)
        self.assertEqual(policy["url"], child)
        transport.allow_redirect(child, asset, policy)
        for different in (child.replace("/owner/project/", "/owner/other/"),
                          child.replace("/releases/download/", "/raw/"),
                          child.replace("github.com", "other.example")):
            self.assertEqual(graph.dependency_policy(source, different), {})
            with self.assertRaises(transport.DownloadError):
                transport.allow_redirect(different, asset, policy if "/raw/" in different else {})

    def test_depth_file_and_total_size_limits(self):
        files = {ROOT: fixture(rewrite()), FIRST: fixture(b'import "./second.js";', FIRST),
                 SECOND: fixture(b"const second = 1;", SECOND)}
        for limits in ({"max_depth": 1}, {"max_files": 2}, {"max_total": len(rewrite()) + 2}):
            with self.subTest(limits=limits):
                _, snapshot = self.run_graph(files, **limits)
                self.assertTrue(snapshot["fetch_failed"])
                self.assertNotIn(SECOND, snapshot["files"])

    def test_mitm_expansion(self):
        _, before = self.run_graph({ROOT: fixture(rewrite("api.example.test,-secret.example.test")),
                                    FIRST: fixture(b"const x = 1;", FIRST)})
        _, after = self.run_graph({ROOT: fixture(rewrite("*.example.test")),
                                   FIRST: fixture(b"const x = 1;", FIRST)})
        result = "\n".join(graph.changes("Example", before, after, {}, None))
        self.assertIn("MITM 可能扩大", result)
        self.assertIn("secret.example.test", result)
        self.assertIn("**高**", result)

    def test_export_is_immutable_and_never_approves(self):
        files = {ROOT: fixture(rewrite()), FIRST: fixture(b"const x = 1;", FIRST)}
        run, snapshot = self.run_graph(files)
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            lock = parent / "approved.json"
            lock.write_text(json.dumps({"Example": "a" * 64}))
            original = lock.read_bytes()
            approved = graph.approved_versions(lock)
            run.export(parent / "candidates", snapshot)
            export = parent / "candidates" / "Example" / snapshot["version"]
            manifest = export / "manifest.json"
            first = manifest.read_bytes()
            run.export(parent / "candidates", {**snapshot, "checked_at": "later"})
            stored = json.loads(first)
            self.assertEqual(stored["review_status"], "candidate")
            self.assertTrue(stored["frozen"])
            self.assertNotEqual(approved["Example"], snapshot["version"])
            self.assertEqual(lock.read_bytes(), original)
            self.assertEqual(manifest.read_bytes(), first)
            for metadata in stored["files"].values():
                digest = metadata["sha256"]
                self.assertEqual(graph.sha((export / "objects" / (digest + ".blob")).read_bytes()), digest)

    def test_app_report_resumes_v2_state_and_does_not_repeat_unchanged_graph(self):
        digest = graph.sha(rewrite())
        legacy = {"Example": {"url": ROOT, "sha256": digest, "legacy_sha256": "a" * 64}}
        old_body = f"{monitor.BEGIN}\n{json.dumps(legacy)}\n{monitor.END}"
        files = {ROOT: fixture(rewrite()), FIRST: fixture(b"const x = 1;", FIRST)}
        factory = graph.GraphMonitor

        def setup(*args):
            return factory(*args, fetch=lambda url, *_: files[url])

        previous, previous_graph = monitor.read_state(old_body), graph.read_graph(old_body)
        with patch.object(graph, "GraphMonitor", side_effect=setup):
            report, body, comments = monitor.graph_report(SOURCES, previous, previous_graph, {})
            self.assertIn("首次建立依赖基线", report)
            self.assertTrue(comments)
            resumed = monitor.read_state(body)
            self.assertEqual(resumed["Example"]["legacy_sha256"], "a" * 64)
            report, _, comments = monitor.graph_report(SOURCES, resumed, graph.read_graph(body), {})
            self.assertIn("无候选变化", report)
            self.assertFalse(comments)

    def test_untrusted_evidence_cannot_inject_markdown_or_workflow_commands(self):
        text = graph.safe('@reviewer\n`</details>\n::warning::bad')
        for unsafe in ("@", "\n", "`", "<", ">"):
            self.assertNotIn(unsafe, text)
        label = graph.file_label("https://test.example/@reviewer%0a<script>.js")
        self.assertNotIn("@reviewer", label)
        self.assertNotIn("<script>", label)


class ScannerTests(unittest.TestCase):
    def test_qx_script_actions_and_parameters(self):
        actions = ("request-body", "response-body", "request-header", "response-header",
                   "analyze-echo-response", "echo-response")
        lines = [f"^https://x url script-{action} {FIRST}" for action in actions]
        lines += [f'^https://x url-and-header script-response-body script-path="{SECOND}", timeout=30',
                  f"# ^https://x url script-response-body {SECOND}"]
        found = scan.rewrite_scan("\n".join(lines))
        self.assertEqual([ref.target for ref in found.references], [FIRST] * len(actions) + [SECOND])

    def test_imports_and_remote_loaders_ignore_comment_and_string_examples(self):
        code = """
        // import('https://bad.example/test.js')
        const comment = "import('https://bad.example/test.js')";
        import {
            named
        } from './first.js';
        export { named } from './second.js';
        importScripts("./a.js", "./b.js");
        require('https://scripts.example.test/first.js');
        fetch("https://scripts.example.test/second.js");
        """
        found = scan.javascript_scan(code)
        self.assertEqual([ref.target for ref in found.references],
                         ["./first.js", "./second.js", "./a.js", "./b.js", FIRST, SECOND])

    def test_dynamic_execution_sensitive_headers_and_mutations(self):
        code = (
            '$request.headers["Cookie"] = value;\n'
            'const account = $persistentStore.read("name");\n'
            '$task.fetch({url: "https://net.example.test", headers: hdrs});\n'
            'eval(value);\nnew Function(value);\n$done({body: rewritten});'
        )
        found = scan.javascript_scan(code)
        for evidence in (
            scan.Finding("sensitive", 1, "Cookie（请求头上下文）"),
            scan.Finding("mutation", 1, "headers 可能写入或转发"),
            scan.Finding("network", 3, "net.example.test"),
            scan.Finding("execution", 4, "eval"),
            scan.Finding("execution", 5, "Function"),
            scan.Finding("mutation", 6, "body 可能写入或转发"),
        ):
            self.assertIn(evidence, found.findings)


class TransportTests(unittest.TestCase):
    def test_rejects_url_tricks_and_ssrf_names_at_entry(self):
        for url in (
            "http://example.test/a.js", "https://a.test@localhost/a.js", "https://localhost/a.js",
            "https://127.1/a.js", "https://2130706433/a.js", "https://169.254.169.254/a.js",
            "https://[::ffff:127.0.0.1]/a.js", "https://metadata.google.internal/a.js",
            "https://host.test:8443/a.js", "https://public.test./a.js", "https://host.test/a.js?secret=x",
            "https://host.test/\n@org", "https://host.test\\@other.test/a.js",
        ):
            with self.subTest(url=url), self.assertRaises(transport.DownloadError):
                transport.endpoint(url)

    def test_dns_checks_all_addresses_and_connects_only_to_pinned_ipv4(self):
        def address(ip, family=socket.AF_INET):
            return (family, socket.SOCK_STREAM, 6, "", (ip, 443))

        for private in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "168.63.129.16"):
            with self.subTest(private=private), patch.object(socket, "getaddrinfo", return_value=[
                address("8.8.8.8"), address(private)
            ]), self.assertRaises(transport.DownloadError):
                transport.public_addresses("rebinding.example", monotonic() + 1)
        connection = MagicMock()
        response = connection.getresponse.return_value.__enter__.return_value
        response.status = 200
        response.getheader.side_effect = lambda key, default=None: {"Content-Type": "text/plain"}.get(key, default)
        response.read1.side_effect = [b"const x = 1;", b""]
        with patch.object(socket, "getaddrinfo", return_value=[address("8.8.8.8")]) as dns, patch.object(
            transport, "PinnedHTTPS", return_value=connection
        ) as pinned:
            transport.download(FIRST, {}, monotonic() + 1)
        self.assertEqual(pinned.call_args.args[:2], ("scripts.example.test", "8.8.8.8"))
        self.assertEqual(dns.call_count, 1)
        connection.request.assert_called_once()
        self.assertNotIn("Authorization", connection.request.call_args.kwargs["headers"])

    def test_redirect_is_rejected_before_second_dns_lookup(self):
        for location in ("https://elsewhere.example/x.js", "http://scripts.example.test/x.js",
                         "https://169.254.169.254/x.js", "https://[invalid/a.js"):
            with self.subTest(location=location):
                connection = MagicMock()
                response = connection.getresponse.return_value.__enter__.return_value
                response.status = 302
                response.getheader.return_value = location
                with patch.object(transport, "public_addresses", return_value=["8.8.8.8"]) as dns, patch.object(
                    transport, "PinnedHTTPS", return_value=connection
                ), self.assertRaises(transport.DownloadError):
                    transport.download(FIRST, {}, monotonic() + 1)
                self.assertEqual(dns.call_count, 1)

    def test_timeout_and_streaming_size_limit(self):
        with self.assertRaises(transport.DownloadError):
            transport.download(FIRST, {}, monotonic() - 1)
        for chunks, expected in (([b"12345"], 5), ([b"12", TimeoutError()], 2)):
            connection = MagicMock()
            response = connection.getresponse.return_value.__enter__.return_value
            response.status = 200
            response.getheader.side_effect = lambda key, default=None: default
            response.read1.side_effect = chunks
            with patch.object(transport, "public_addresses", return_value=["8.8.8.8"]), patch.object(
                transport, "PinnedHTTPS", return_value=connection
            ), self.assertRaises(transport.DownloadError) as error:
                transport.download(FIRST, {}, monotonic() + 1, max_bytes=4)
            self.assertEqual(error.exception.bytes_read, expected)
