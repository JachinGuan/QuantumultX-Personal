import io
import json
import unittest
from unittest.mock import Mock, patch

from scripts import check_upstream as monitor
from scripts import upstream_transport as transport


URL = "https://example.test/a.conf"
SOURCE = {"url": URL, "kind": "rewrite"}
REWRITE = (
    "[rewrite_local]\n"
    "^https://api\\.example\\.test url script-response-body https://cdn.example.test/main.js\n"
    "hostname = api.example.test,-private.example.test\n"
)


class FakeResponse(io.BytesIO):
    def __init__(self, data, *, status=200, content_type="text/plain", **headers):
        super().__init__(data)
        self.status = status
        self.headers = {"Content-Type": content_type, **headers}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


class DownloadTests(unittest.TestCase):
    def observe(self, response):
        connection = Mock()
        if isinstance(response, Exception):
            connection.getresponse.side_effect = response
        else:
            connection.getresponse.return_value = response
        with patch.object(transport, "public_addresses", return_value=["8.8.8.8"]), patch.object(
            transport, "PinnedHTTPS", return_value=connection
        ):
            return monitor.observe(SOURCE)

    def test_valid_rewrite_is_hashed_and_profiled(self):
        body = REWRITE.encode()
        result = self.observe(FakeResponse(body, **{"Content-Length": str(len(body))}))
        self.assertFalse(result.error)
        self.assertEqual(result.sha256, monitor.digest(body))
        self.assertEqual(result.profile["operations"], ["script-response-body"])
        self.assertTrue(result.profile["dependencies"][0].startswith("cdn.example.test/"))

    def test_error_pages_even_when_http_is_200(self):
        for data, content_type, reason in [
            (b"<html><title>Forbidden</title></html>", "text/plain", "HTML or XML"),
            (b"<html><script src='/cdn-cgi/challenge-platform'></script></html>", "text/html", "challenge"),
            (b"<form>Verify you are human</form>", "text/html", "challenge"),
            (b"404: Not Found", "text/plain", "no recognized"),
            (b'{"message":"blocked"}', "application/json", "Content-Type"),
        ]:
            with self.subTest(reason=reason):
                result = self.observe(FakeResponse(data, content_type=content_type))
                self.assertIn(reason, result.error)
                self.assertEqual(monitor.digest(data), result.sha256)
                self.assertIsNone(result.profile)

    def test_download_failures_do_not_leak_exception_details(self):
        result = self.observe(OSError("private query value"))
        self.assertEqual(result.error, "HTTPS 下载失败")
        result = self.observe(FakeResponse(b"", status=403))
        self.assertEqual(result.error, "HTTP 403")
        result = self.observe(FakeResponse(REWRITE.encode(), status=206))
        self.assertIn("206", result.error)

    def test_disallows_unexpected_redirect(self):
        for url, reason in (
            ("http://example.test/a.conf", "URL 被策略拒绝"),
            ("https://other.test/a.conf", "跨域重定向"),
            ("https://example.test/", "站点首页"),
        ):
            with self.subTest(url=url):
                response = FakeResponse(b"", status=302, Location=url)
                self.assertIn(reason, self.observe(response).error)

    def test_weatherkit_asset_redirects_are_scoped(self):
        source = {
            "url": "https://github.com/NSRingo/WeatherKit/releases/latest/download/file.snippet",
            "redirect_hosts": ["release-assets.githubusercontent.com"],
        }
        release = "https://github.com/NSRingo/WeatherKit/releases/download/v1/file.snippet"
        transport.allow_redirect(source["url"], release, source)
        transport.allow_redirect(release, "https://release-assets.githubusercontent.com/asset?signature=value", source)
        with self.assertRaises(transport.DownloadError):
            transport.allow_redirect(source["url"], "https://github.com/other/project/releases/download/v1/file.snippet", source)

    def test_checks_response_bounds_and_representation(self):
        for data, headers, reason in [
            (b"", {}, "empty"),
            (b"a" * (monitor.LIMIT + 1), {}, "超出下载预算"),
            (REWRITE.encode(), {"Content-Length": "999"}, "Content-Length 不符"),
            (REWRITE.encode(), {"Content-Encoding": "gzip"}, "响应编码"),
            (b"\xff\x00", {}, "UTF-8"),
        ]:
            with self.subTest(reason=reason):
                self.assertIn(reason, self.observe(FakeResponse(data, **headers)).error)

    def test_javascript_basic_structure(self):
        content = b"const body = JSON.parse($response.body); $done({body});"
        self.assertIn("$done", monitor.validate(content, "application/javascript", "javascript"))
        for error_page in (b"Access denied", b"// function fake() {}", b"<script>function challenge() {}</script>"):
            with self.subTest(error_page=error_page), self.assertRaises(monitor.InvalidContent):
                monitor.validate(error_page, "text/plain", "javascript")


class ReportTests(unittest.TestCase):
    def entry(self, body):
        return {"url": URL, "sha256": monitor.digest(body.encode()), "profile": monitor.profile(body, "rewrite")}

    def test_change_reports_mitm_dependencies_destinations_and_mutations(self):
        old = self.entry(REWRITE)
        changed = (
            "^https://x url script-request-header https://new.example.test/handler\n"
            "^https://x url 302 https://target.example.test/landing\n"
            "hostname = *.example.test\n"
        )
        new = self.entry(changed)
        result = monitor.Observation(new["sha256"], new["profile"])
        _, body, changed_flag = monitor.render({"Source": SOURCE}, {"Source": old}, {"Source": result})
        for expected in (
            old["sha256"], new["sha256"], "Content passed", "potential MITM scope expansion",
            "High", "Manual review", "new.example.test/", "target.example.test",
            "script-request-header", "script-response-body", "-private.example.test", "api.example.test",
        ):
            self.assertIn(expected, body)
        self.assertTrue(changed_flag)
        self.assertEqual(monitor.read_state(body)["Source"], new)

    def test_sensitive_and_execution_indicators_suppress_raw_values(self):
        code = """
        const token = $request.headers.Authorization;
        const value = $request.headers["Cookie"];
        import("https://scripts.example.test/loader");
        fetch("https://api.example.test/path?token=secret-value");
        eval(atob(value));
        new Function(value)();
        $done({ body: token, headers: {} });
        """
        found = monitor.profile(code, "javascript")
        details, risk, _ = monitor.compare(monitor.profile("const n = 0;", "javascript"), found)
        self.assertEqual(risk, "High")
        report = "\n".join(details)
        for expected in ("eval", "Function constructor", "Dynamic loading", "Obfuscation",
                         "Cookie", "Authorization", "Token/API key", "api.example.test",
                         "scripts.example.test/", "Body", "Headers"):
            self.assertIn(expected, report)
        self.assertNotIn("secret-value", report)

    def test_invalid_results_preserve_all_baselines_and_show_repeated_payload(self):
        shared = "a" * 64
        before = {
            "A": {"url": URL, "sha256": shared},
            "B": {"url": "https://example.test/b.conf", "sha256": shared},
        }
        sources = {name: {**SOURCE, "url": entry["url"]} for name, entry in before.items()}
        error = monitor.Observation("b" * 64, error="HTML or XML page")
        after, changes, failures, repeated, historical = monitor.summarize(
            sources, before, {"A": error, "B": error}
        )
        self.assertEqual(before, after)
        self.assertFalse(changes)
        self.assertEqual(len(failures), 2)
        self.assertIn(error.sha256, repeated[0])
        self.assertIn(shared, historical[0])

    def test_legacy_hash_only_migrates_after_validation_and_remains_visible(self):
        new = self.entry(REWRITE)
        before = {"Source": {"url": URL, "sha256": "a" * 64}}
        result = monitor.Observation(new["sha256"], new["profile"])
        report, body, changed = monitor.render({"Source": SOURCE}, before, {"Source": result})
        self.assertTrue(changed)
        self.assertIn("Previous static profile unavailable", report)
        self.assertNotIn("(+)", report)
        after = monitor.read_state(body)
        self.assertEqual(after["Source"]["legacy_sha256"], "a" * 64)
        _, _, unchanged = monitor.render({"Source": SOURCE}, after, {"Source": result})
        self.assertFalse(unchanged)

    def test_bad_baseline_fails_closed(self):
        for body in ("", None, f"{monitor.BEGIN} {{}} {monitor.END}"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                monitor.read_state(body)
        entry = self.entry(REWRITE)
        entry["profile"]["rule_count"] = "@someone"
        with self.assertRaises(ValueError):
            monitor.read_state(f"{monitor.BEGIN}{json.dumps({'X': entry})}{monitor.END}")

    def test_sanitizes_external_feature_values(self):
        self.assertEqual(monitor.displayed({"@someone <img> \n`"}), "`?someone ?img? ??`")


if __name__ == "__main__":
    unittest.main()
