import json
import re
import unittest
from pathlib import Path

from build import build_data, to_js

ROOT = Path(__file__).resolve().parent.parent

ALERTS = {
    "summary": {
        "first_event": "2025-12-10T06:55:46", "last_event": "2025-12-10T11:04:45",
        "failed_logins": 100, "failed_on_nonexistent_accounts": 10, "unique_attacking_ips": 3,
        "successful_logins": 1,
        "top_attacking_ips": [["1.1.1.1", 60], ["2.2.2.2", 30], ["3.3.3.3", 10]],
        "top_targeted_usernames": [["root", 50], ["<img src=x onerror=alert(1)>", 5]],
        "failed_logins_timeline": [["2025-12-10T06:55:46", 4], ["2025-12-10T07:05:46", 0]],
    },
    "alerts": [
        {"rule": "brute_force", "severity": "high", "ip": "1.1.1.1", "count": 60, "detail": "60 failed"},
        {"rule": "username_spray", "severity": "medium", "ip": "1.1.1.1", "count": 8, "detail": "8 users"},
        {"rule": "brute_force", "severity": "high", "ip": "2.2.2.2", "count": 30, "detail": "30 failed"},
        {"rule": "clean_login", "severity": "info", "ip": "9.9.9.9", "count": 0, "detail": "ok"},
    ],
}
ENRICHED = [
    {"ip": "1.1.1.1", "verdict": "malicious", "abuse_score": 100, "total_reports": 50,
     "last_reported": "2026-10-01T00:00:00+00:00", "country": "CN", "isp": "X"},
    {"ip": "2.2.2.2", "verdict": "no reports", "abuse_score": 0, "total_reports": 0,
     "last_reported": None, "country": "CN", "isp": "Y"},
]


class BuildDataTests(unittest.TestCase):
    def setUp(self):
        self.data = build_data(ALERTS, ENRICHED, {"dataset": "test", "intel": "AbuseIPDB"})

    def test_joins_log_hunter_and_threat_intel(self):
        a = {x["ip"]: x for x in self.data["attackers"]}
        self.assertEqual(a["1.1.1.1"]["rules"], ["brute_force", "username_spray"])
        self.assertEqual(a["1.1.1.1"]["verdict"], "malicious")
        self.assertEqual(a["3.3.3.3"]["verdict"], "not checked")
        self.assertNotIn("9.9.9.9", a, "info-level clean logins are not attackers")

    def test_countries_weighted_by_failed_logins(self):
        self.assertEqual(self.data["countries"], [("CN", 90)])

    def test_kpis(self):
        k = self.data["kpis"]
        self.assertEqual((k["brute_force_ips"], k["username_spray_ips"]), (2, 1))
        self.assertEqual((k["intel_checked"], k["intel_malicious"]), (2, 1))

    def test_verdict_counts_have_no_phantom_zero_entries(self):
        data = build_data(ALERTS, [ENRICHED[1]], {"dataset": "t", "intel": "t"})
        self.assertEqual(data["verdicts"], {"no reports": 1})
        self.assertEqual(data["kpis"]["intel_malicious"], 0)


class SecurityTests(unittest.TestCase):
    def test_attacker_controlled_text_is_escaped_in_data_file(self):
        js = to_js(build_data(ALERTS, ENRICHED, {"dataset": "</script><b>x</b>", "intel": "t"}))
        self.assertNotIn("<", js)
        self.assertNotIn(">", js)
        payload = js[len("window.HOME_SOC_DATA = "):-2]
        self.assertIn("<img src=x onerror=alert(1)>", json.dumps(json.loads(payload)), "value survives round-trip")

    def test_page_script_never_inserts_html(self):
        app = (ROOT / "docs" / "app.js").read_text(encoding="utf-8")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(sink, app, f"{sink} would let attacker-controlled log data run as code")

    def test_page_has_strict_content_security_policy(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        csp = re.search(r'Content-Security-Policy"\s+content="([^"]+)"', html).group(1)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("<script>", html, "no inline scripts")


if __name__ == "__main__":
    unittest.main()
