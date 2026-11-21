import unittest
from unittest.mock import patch

from scripts import check_upstream as monitor, upstream_alerts as alerts, upstream_graph as graph
from scripts.upstream_transport import Download, DownloadError

ROOT = "https://audit.example/module.conf"
SCRIPT = "https://audit.example/module.js"
SOURCE = {"kind": "rewrite", "url": ROOT}
MODULE = {"monitor_enabled": True, "managed": False, "client_enabled": None,
          "update_policy": "review", "risk_status": "normal"}


def rewrite(host="audit.example"):
    return f"^https://audit.example url script-response-body {SCRIPT}\nhostname = {host}\n".encode()


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.root = rewrite()
        self.script = b"const data = 1;"
        self.body = ""
        self.factory = graph.GraphMonitor

    def run_monitor(self, paused=False):
        def fetch(url, *_):
            if paused:
                self.fail("paused source was fetched")
            payload = self.root if url == ROOT else self.script
            if isinstance(payload, Exception):
                raise payload
            return Download(payload, url, "text/plain")

        with patch.object(graph, "GraphMonitor", side_effect=lambda *args: self.factory(*args, fetch=fetch)):
            report, self.body, comments = monitor.graph_report(
                {} if paused else {"Example": SOURCE},
                monitor.read_state(self.body) if self.body else {},
                graph.read_graph(self.body), {}, paused=("Example",) if paused else (),
                modules={"Example": {**MODULE, "monitor_enabled": not paused}},
                prior_alerts=alerts.read_state(self.body),
            )
        return report, "\n".join(comments)

    def test_routine_update_changes_baseline_without_comment_and_client_is_unknown(self):
        report, comments = self.run_monitor()
        self.assertIn("客户端：未知", report)
        self.assertIn("可继续使用", report)
        self.assertEqual(comments, "")
        self.script = b"const data = 2;"
        report, comments = self.run_monitor()
        self.assertEqual(comments, "")
        self.assertIn("正常内容更新", report)
        self.assertIn(graph.sha(self.script), report)
        self.assertTrue(alerts.read_state(self.body)["Example"]["last_success"])

    def test_html_repeat_pause_and_recovery_keep_the_complete_baseline(self):
        self.run_monitor()
        baseline = graph.read_graph(self.body)["Example"]["last_complete"]
        success = alerts.read_state(self.body)["Example"]["last_success"]
        self.root = DownloadError("来源重定向至站点首页")
        report, comments = self.run_monitor()
        self.assertIn("新异常 · HTML", comments)
        self.assertIn("保留基线", report)
        self.assertEqual(graph.read_graph(self.body)["Example"]["last_complete"], baseline)
        self.assertEqual(alerts.read_state(self.body)["Example"]["last_success"], success)
        self.assertEqual(self.run_monitor()[1], "")
        state = alerts.read_state(self.body)
        report, comments = self.run_monitor(paused=True)
        self.assertIn("上游监控已暂停", report)
        self.assertEqual(comments, "")
        self.assertEqual(alerts.read_state(self.body), state)
        self.root = rewrite()
        _, comments = self.run_monitor()
        self.assertIn("恢复 · HTML", comments)
        self.assertEqual(self.run_monitor()[1], "")

    def test_dependency_failure_then_mitm_upgrade_and_risk_recovery(self):
        self.run_monitor()
        self.script = DownloadError("HTTP 404")
        report, comments = self.run_monitor()
        self.assertIn("新异常 · 依赖闭包不完整", comments)
        self.assertIn("HTTP 404", report)
        self.root = rewrite("*.audit.example")
        report, comments = self.run_monitor()
        self.assertIn("严重程度升级 · MITM", comments)
        self.assertIn("建议在 QX 手动停用", report)
        self.assertEqual(self.run_monitor()[1], "")
        self.script = b'const token = $request.headers.Authorization;'
        _, comments = self.run_monitor()
        self.assertIn("恢复 · 依赖闭包不完整", comments)
        self.assertIn("敏感信息访问线索", comments)
        self.script = b'const token = $request.headers.Authorization; eval(token);'
        _, comments = self.run_monitor()
        self.assertIn("动态执行或混淆线索", comments)
        self.assertEqual(self.run_monitor()[1], "")
        self.script = b"const data = 1;"
        self.root = rewrite()
        _, comments = self.run_monitor()
        self.assertIn("恢复 · ", comments)
        self.assertIn("MITM 范围可能扩大", comments)

    def test_changing_failure_kind_does_not_report_availability_recovery(self):
        self.run_monitor()
        self.root = DownloadError("来源重定向至站点首页")
        self.run_monitor()
        self.root = DownloadError("HTTP 503")
        _, comments = self.run_monitor()
        self.assertIn("新异常 · 入口不可用", comments)
        self.assertNotIn("恢复", comments)

    def test_legacy_report_migration_does_not_repeat_known_conditions(self):
        self.run_monitor()
        previous = monitor.read_state(self.body)
        before = graph.read_graph(self.body)
        legacy = "- **Example** · 来源重定向至站点首页 · 保留基线\n"
        state = alerts.migrate(legacy, previous, before)
        self.assertEqual(state["Example"]["signals"], ["html"])
        self.assertEqual(state["Example"]["last_success"], before["Example"]["last_complete"]["checked_at"])

    def test_invalid_alert_state_fails_closed(self):
        with self.assertRaises(ValueError):
            alerts.read_state(f'{alerts.BEGIN}{{"Example":{{"signals":["invalid"]}}}}{alerts.END}')
