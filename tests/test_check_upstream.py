import io
import json
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from scripts import check_upstream as monitor


URL = "https://example.test/a.conf"
SOURCE = {"url": URL, "kind": "rewrite"}
REWRITE = (
    "[rewrite_local]\n"
    "^https://api\\.example\\.test url script-response-body https://cdn.example.test/main.js\n"
    "hostname = api.example.test,-private.example.test\n"
)


class FakeResponse(io.BytesIO):
    def __init__(self, data, *, status=200, url=URL, content_type="text/plain", **headers):
        super().__init__(data)
        self.status = status
        self.url = url
        self.headers = {"Content-Type": content_type, **headers}

    def geturl(self):
        return self.url


class DownloadTests(unittest.TestCase):
    def observe(self, response):
        opener = Mock()
        if isinstance(response, Exception):
            opener.open.side_effect = response
        else:
            opener.open.return_value = response
        with patch.object(monitor.urllib.request, "build_opener", return_value=opener):
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
        error = URLError("private query value")
        result = self.observe(error)
        self.assertEqual(result.error, "download failed (URLError)")
        result = self.observe(HTTPError(URL, 403, "forbidden", {}, None))
        self.assertEqual(result.error, "HTTP 403")
        result = self.observe(FakeResponse(REWRITE.encode(), status=206))
        self.assertIn("206", result.error)

    def test_disallows_unexpected_final_url_and_validates_redirect_before_request(self):
        result = self.observe(FakeResponse(REWRITE.encode(), url="https://example.test/"))
        self.assertIn("homepage", result.error)
        redirect = monitor.CheckedRedirect(lambda url: monitor.check_target(SOURCE, url))
        for url in ("http://example.test/a.conf", "https://other.test/a.conf", "https://example.test/"):
            with self.subTest(url=url), self.assertRaises(monitor.InvalidContent):
                redirect.redirect_request(monitor.urllib.request.Request(URL), None, 302, "", {}, url)

    def test_weatherkit_asset_redirects_are_scoped(self):
        source = {
            "url": "https://github.com/NSRingo/WeatherKit/releases/latest/download/file.snippet",
            "redirect_hosts": ["release-assets.githubusercontent.com"],
        }
        monitor.check_target(source, "https://github.com/NSRingo/WeatherKit/releases/download/v1/file.snippet")
        monitor.check_target(source, "https://release-assets.githubusercontent.com/asset?signature=value")
        with self.assertRaises(monitor.InvalidContent):
            monitor.check_target(source, "https://github.com/other/project/releases/download/v1/file.snippet")

    def test_checks_response_bounds_and_representation(self):
        for data, headers, reason in [
            (b"", {}, "empty"),
            (b"a" * (monitor.LIMIT + 1), {}, "2 MiB"),
            (REWRITE.encode(), {"Content-Length": "999"}, "size does not match"),
            (REWRITE.encode(), {"Content-Encoding": "gzip"}, "encoding"),
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
