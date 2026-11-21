import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import check_upstream as monitor, module_registry, publish_rewrite
from scripts import upstream_graph as graph
from scripts.upstream_transport import Download

ROOT = Path(__file__).resolve().parents[1]


class ModuleRegistryTests(unittest.TestCase):
    def test_amap_is_user_disabled_but_monitoring_is_independent(self):
        modules = module_registry.load_modules(ROOT / "upstream/modules.json")
        amap = modules["AmapAds"]
        self.assertIs(amap["client_enabled"], False)
        self.assertEqual(amap["client_report"]["basis"], "user_report")
        self.assertFalse(amap["managed"])
        self.assertEqual(amap["update_policy"], "frozen")
        sources = json.loads((ROOT / "upstream/sources.json").read_text())
        active, _ = module_registry.select_sources(sources, modules)
        self.assertIn("AmapAds", active)
        self.assertIsNone(modules["RedditAds"]["client_enabled"])

    def test_pause_one_module_never_fetches_it_or_discards_its_baselines(self):
        enabled = "https://example.test/active.conf"
        disabled = "https://example.test/paused.conf"
        sources = {name: {"url": url, "kind": "rewrite"} for name, url in (("On", enabled), ("Off", disabled))}
        active, paused = module_registry.select_sources(
            sources, {"On": {"monitor_enabled": True}, "Off": {"monitor_enabled": False}}
        )
        previous = {"Off": {"url": disabled, "sha256": "a" * 64}}
        prior_graph = {"Off": {"last_observed": {"version": "b" * 64, "graph_complete": False}, "last_complete": None}}
        factory = graph.GraphMonitor
        fetched = []

        def fetch(url, *_):
            fetched.append(url)
            return Download(b"^https://example.test url reject\n", url, "text/plain")

        with patch.object(graph, "GraphMonitor", side_effect=lambda *args: factory(*args, fetch=fetch)):
            report, body, _ = monitor.graph_report(active, previous, prior_graph, {}, paused=paused)
        self.assertEqual(fetched, [enabled])
        self.assertEqual(monitor.read_state(body)["Off"], previous["Off"])
        self.assertEqual(graph.read_graph(body)["Off"], prior_graph["Off"])
        self.assertIn("暂停上游监控（保留基线） · Off", report)

    def test_resume_compares_dependency_changes_to_the_pre_pause_baseline(self):
        url = "https://example.test/resumed.conf"
        dependency = "https://example.test/resumed.js"
        sources = {"Resume": {"url": url, "kind": "rewrite"}}
        registry = {"Resume": {"monitor_enabled": True}}
        original = b"const value = 1;"
        files = {url: f"^https://example.test url script-response-body {dependency}\n".encode(),
                 dependency: original}
        fetched = []
        factory = graph.GraphMonitor

        def fetch(target, *_):
            fetched.append(target)
            return Download(files[target], target, "text/plain")

        def run(previous_body=""):
            active, paused = module_registry.select_sources(sources, registry)
            return monitor.graph_report(
                active, monitor.read_state(previous_body) if previous_body else {},
                graph.read_graph(previous_body), {}, paused=paused,
            )

        with patch.object(graph, "GraphMonitor", side_effect=lambda *args: factory(*args, fetch=fetch)):
            _, initial, _ = run()
            baseline = graph.read_graph(initial)["Resume"]["last_complete"]
            self.assertTrue(baseline["graph_complete"])
            registry["Resume"]["monitor_enabled"] = False
            fetched.clear()
            _, paused, comments = run(initial)
            self.assertEqual(fetched, [])
            self.assertEqual(comments, [])
            self.assertEqual(monitor.read_state(paused), monitor.read_state(initial))
            self.assertEqual(graph.read_graph(paused), graph.read_graph(initial))

            registry["Resume"]["monitor_enabled"] = True
            _, unchanged, comments = run(paused)
            self.assertEqual(fetched, [url, dependency])
            self.assertEqual(comments, [])
            self.assertEqual(graph.read_graph(unchanged)["Resume"]["last_observed"]["version"], baseline["version"])

            files[dependency] = b"const value = 2;"
            report, updated, comments = run(paused)
            self.assertFalse(comments)
            self.assertNotIn("首次建立依赖基线", report)
            self.assertIn(graph.sha(original), report)
            self.assertIn(graph.sha(files[dependency]), report)
            self.assertEqual(monitor.read_state(updated), monitor.read_state(initial))
            self.assertNotEqual(graph.read_graph(updated)["Resume"]["last_complete"]["version"], baseline["version"])

    def test_managed_flag_cannot_add_a_publication_policy(self):
        with self.assertRaisesRegex(ValueError, "专用发布校验策略"):
            publish_rewrite.load_snapshot(ROOT / "release-inputs", "a" * 64, module="AmapAds")
