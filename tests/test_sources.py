import json
from pathlib import Path
import unittest

from scripts.upstream_transport import DownloadError, allow_redirect


class UnresolvedSourceTests(unittest.TestCase):
    def test_preserves_unresolved_source_identity_and_rejects_homepage(self):
        sources = json.loads((Path(__file__).resolve().parents[1] / "upstream/sources.json").read_text())
        originals = {
            "BiliBiliAdsLite": ("rewrite/BiliBiliAdsLite.conf", "rewrite"),
            "StartUpAds": ("rewrite/StartUpAds.conf", "rewrite"),
            "ZhiHu": ("scripts/zhihu.ads.js", "javascript"),
            "XiaoHongShu": ("rewrite/XiaoHongShuAds.conf", "rewrite"),
        }
        homepage = "https://ddgksf2013.top/"
        for name, (path, kind) in originals.items():
            with self.subTest(source=name):
                entry = sources[name]
                self.assertEqual(entry["url"], homepage + path)
                self.assertEqual(entry["kind"], kind)
                self.assertEqual(entry["investigation"]["status"], "homepage_redirect_unresolved")
                self.assertTrue(entry["investigation"]["reason"])
                with self.assertRaisesRegex(DownloadError, "站点首页"):
                    allow_redirect(entry["url"], homepage, entry)
