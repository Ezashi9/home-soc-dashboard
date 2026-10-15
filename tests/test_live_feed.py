import re
import unittest
from pathlib import Path

from build import to_js
from live_feed import build_live_data, fetch, parse_top_ips, parse_top_ports, sample_ssh_attackers

ROOT = Path(__file__).resolve().parent.parent

TOP_IPS = [
    {"rank": 1, "source": "13.94.254.200", "reports": 319739, "targets": 1},
    {"rank": 2, "source": "89.248.163.109", "reports": "96279", "targets": 150},
    {"rank": 3, "source": "10.0.0.1", "reports": 5, "targets": 1},            # private: dropped
    {"rank": 4, "source": "<script>x</script>", "reports": 5, "targets": 1},  # junk: dropped
]
TOP_PORTS = {"0": {"targetport": 22, "records": 582802, "sources": 9410},
             "1": {"targetport": 16767, "records": 76488, "sources": 3477},
             "2": {"targetport": 99999, "records": 1, "sources": 1},           # invalid port: dropped
             "date": "2026-10-15", "limit": 3}
SSH_LIST = "\n".join(["1.1.1.1", "8.8.8.8", "9.9.9.9", "192.168.0.1", "not an ip", "", "8.8.8.8"])


class ParseTests(unittest.TestCase):
    def test_top_ips_keeps_only_valid_public_addresses(self):
        rows = parse_top_ips(TOP_IPS)
        self.assertEqual([r["ip"] for r in rows], ["13.94.254.200", "89.248.163.109"])
        self.assertEqual(rows[1]["reports"], 96279)

    def test_top_ports_names_and_validation(self):
        day, rows = parse_top_ports(TOP_PORTS)
        self.assertEqual(day, "2026-10-15")
        self.assertEqual([(r["port"], r["name"]) for r in rows], [(22, "SSH"), (16767, "")])

    def test_malformed_feeds_parse_to_nothing(self):
        self.assertEqual(parse_top_ips({"error": "oops"}), [])
        self.assertEqual(parse_top_ports([1, 2]), (None, []))

    def test_ssh_sample_is_deduplicated_validated_and_repeatable(self):
        total, first = sample_ssh_attackers(SSH_LIST, 2, "2026-10-15")
        _, again = sample_ssh_attackers(SSH_LIST, 2, "2026-10-15")
        self.assertEqual(total, 3)
        self.assertEqual(first, again)
        self.assertTrue(set(first) <= {"1.1.1.1", "8.8.8.8", "9.9.9.9"})


class FetchTests(unittest.TestCase):
    def test_fetch_combines_feeds(self):
        def get(path):
            return TOP_IPS if path.startswith("topips") else TOP_PORTS
        feed = fetch(get=get, get_text=lambda url: SSH_LIST, n_ssh=2)
        self.assertEqual(len(feed["top_ips"]), 2)
        self.assertEqual(feed["ssh_total"], 3)
        self.assertEqual(len(feed["ssh_sample"]), 2)

    def test_empty_feed_is_refused_rather_than_published(self):
        with self.assertRaises(RuntimeError):
            fetch(get=lambda path: [] if path.startswith("topips") else TOP_PORTS, get_text=lambda url: SSH_LIST)
        with self.assertRaises(RuntimeError):
            fetch(get=lambda path: TOP_IPS if path.startswith("topips") else TOP_PORTS, get_text=lambda url: "")


class BuildTests(unittest.TestCase):
    def setUp(self):
        feed = {"fetched_at": "2026-10-15T13:51:00+00:00", "dshield_date": "2026-10-15",
                "top_ips": parse_top_ips(TOP_IPS), "top_ports": parse_top_ports(TOP_PORTS)[1],
                "ssh_total": 3, "ssh_sample": ["1.1.1.1", "8.8.8.8"]}
        enriched = [
            {"ip": "1.1.1.1", "verdict": "malicious", "abuse_score": 100, "total_reports": 50, "country": "AU"},
            {"ip": "8.8.8.8", "verdict": "suspicious", "abuse_score": 40, "total_reports": 3, "country": "US"},
            {"ip": "13.94.254.200", "verdict": "no reports", "abuse_score": 0, "total_reports": 0, "country": "NL"},
        ]
        self.data = build_live_data(feed, enriched)

    def test_group_stats(self):
        self.assertEqual(self.data["stats"]["ssh"]["malicious"], 1)
        self.assertEqual(self.data["stats"]["ssh"]["checked"], 2)
        self.assertEqual(self.data["stats"]["scanners"]["malicious"], 0)
        self.assertEqual(self.data["stats"]["scanners"]["checked"], 1, "unchecked IPs don't count as checked")

    def test_kpis(self):
        self.assertEqual(self.data["kpis"]["top_port"]["port"], 22)
        self.assertEqual(self.data["kpis"]["broadest"]["ip"], "89.248.163.109")
        self.assertEqual(self.data["ssh"][0]["ip"], "1.1.1.1", "highest score first")

    def test_output_is_escaped(self):
        js = to_js(self.data, "LIVE_FEED_DATA")
        self.assertTrue(js.startswith("window.LIVE_FEED_DATA = "))
        self.assertNotIn("<", js)


class PageTests(unittest.TestCase):
    def test_live_page_security(self):
        html = (ROOT / "docs" / "live.html").read_text(encoding="utf-8")
        csp = re.search(r'Content-Security-Policy"\s+content="([^"]+)"', html).group(1)
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("<script>", html)
        js = (ROOT / "docs" / "live.js").read_text(encoding="utf-8")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(sink, js)

    def test_workflow_pins_actions_to_commits(self):
        wf = (ROOT / ".github" / "workflows" / "live-feed.yml").read_text(encoding="utf-8")
        uses = re.findall(r"uses:\s*(\S+)", wf)
        self.assertTrue(uses)
        for u in uses:
            self.assertRegex(u, r"@[0-9a-f]{40}$", f"{u} must be pinned to a full commit SHA")


if __name__ == "__main__":
    unittest.main()
