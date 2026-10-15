"""Live threat feed: today's attackers from two public feeds, compared side by side.

- SANS DShield: the most active sources hitting its global sensor network (mostly scanners).
- blocklist.de: IPs reported for SSH attacks in the last 48 hours (password guessers).

  python live_feed.py fetch                 -> live/dshield.json + live/ips.txt
  (run IOC Enricher on live/ips.txt)        -> live/enriched.json
  python live_feed.py build                 -> docs/live-data.js
"""
import argparse
import ipaddress
import json
import random
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from build import to_js

ROOT = Path(__file__).resolve().parent
LIVE = ROOT / "live"
API = "https://isc.sans.edu/api/"
BLOCKLIST_SSH = "https://lists.blocklist.de/lists/ssh.txt"
# DShield asks API users to identify themselves with a custom user agent.
USER_AGENT = "home-soc-dashboard (https://github.com/Ezashi9/home-soc-dashboard)"

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "Windows RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MS SQL",
    1723: "PPTP VPN", 2222: "SSH (alt)", 2323: "Telnet (alt)", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5432: "PostgreSQL", 5555: "Android ADB", 5900: "VNC", 6379: "Redis",
    8000: "HTTP (alt)", 8080: "HTTP (alt)", 8443: "HTTPS (alt)", 8888: "HTTP (alt)",
    9200: "Elasticsearch", 27017: "MongoDB", 51413: "BitTorrent",
}


def http_get_json(path: str, timeout: int = 60):
    req = urllib.request.Request(API + path + "?json", headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def http_get_text(url: str, timeout: int = 60) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _public_ip(value) -> str | None:
    # Feed data comes from third parties, so validate it before it reaches the page or the enricher.
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(addr) if addr.is_global else None


def _count(value) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def parse_top_ips(raw) -> list[dict]:
    rows = []
    for r in raw if isinstance(raw, list) else []:
        ip = _public_ip(r.get("source")) if isinstance(r, dict) else None
        if ip:
            rows.append({"ip": ip, "reports": _count(r.get("reports")), "targets": _count(r.get("targets"))})
    return rows


def parse_top_ports(raw) -> tuple[str | None, list[dict]]:
    if not isinstance(raw, dict):
        return None, []
    rows = []
    for key, r in raw.items():
        if key.isdigit() and isinstance(r, dict):
            port = _count(r.get("targetport"))
            if 0 < port < 65536:
                rows.append({"port": port, "name": PORT_NAMES.get(port, ""),
                             "attacks": _count(r.get("records")), "sources": _count(r.get("sources"))})
    rows.sort(key=lambda r: -r["attacks"])
    return raw.get("date"), rows


def sample_ssh_attackers(text: str, n: int, seed: str) -> tuple[int, list[str]]:
    ips = sorted({ip for ip in (_public_ip(line) for line in text.splitlines()) if ip})
    # Seeded by date: the same day always gives the same sample, so a rerun doesn't change the page.
    return len(ips), sorted(random.Random(seed).sample(ips, min(n, len(ips))))


def fetch(get=http_get_json, get_text=http_get_text, n_ips: int = 25, n_ports: int = 10, n_ssh: int = 25) -> dict:
    now = datetime.now(timezone.utc)
    ips = parse_top_ips(get(f"topips/records/{n_ips}"))
    day, ports = parse_top_ports(get(f"topports/records/{n_ports}"))
    ssh_total, ssh = sample_ssh_attackers(get_text(BLOCKLIST_SSH), n_ssh, now.date().isoformat())
    if not ips or not ports or not ssh:
        raise RuntimeError("a feed returned no usable data; refusing to publish an empty page")
    return {"fetched_at": now.isoformat(timespec="seconds"), "dshield_date": day,
            "top_ips": ips, "top_ports": ports, "ssh_total": ssh_total, "ssh_sample": ssh}


def _with_intel(base: dict, intel: dict) -> dict:
    i = intel.get(base["ip"], {})
    return {**base, "verdict": i.get("verdict", "not checked"), "abuse_score": i.get("abuse_score"),
            "total_reports": i.get("total_reports"), "last_reported": i.get("last_reported"),
            "country": i.get("country"), "isp": i.get("isp"), "usage_type": i.get("usage_type")}


def _group_stats(rows: list[dict]) -> dict:
    verdicts = Counter(r["verdict"] for r in rows)
    checked = sorted((r["abuse_score"] or 0) for r in rows if r["verdict"] not in ("not checked", "skipped"))
    return {
        "count": len(rows),
        "checked": len(checked),
        "malicious": verdicts.get("malicious", 0),
        "verdicts": dict(verdicts),
        "median_score": checked[len(checked) // 2] if checked else None,
    }


def build_live_data(feed: dict, enriched_rows: list[dict]) -> dict:
    intel = {row["ip"]: row for row in enriched_rows}
    scanners = [_with_intel({"rank": n, **r}, intel) for n, r in enumerate(feed["top_ips"], 1)]
    ssh = [_with_intel({"ip": ip}, intel) for ip in feed["ssh_sample"]]
    ssh.sort(key=lambda r: (-(r["abuse_score"] or 0), -(r["total_reports"] or 0)))
    countries = Counter(r["country"] for r in scanners + ssh if r["country"])
    broadest = max(scanners, key=lambda a: a["targets"])
    return {
        "fetched_at": feed["fetched_at"],
        "dshield_date": feed["dshield_date"],
        "ports": feed["top_ports"],
        "scanners": scanners,
        "ssh": ssh,
        "ssh_total": feed["ssh_total"],
        "stats": {"scanners": _group_stats(scanners), "ssh": _group_stats(ssh)},
        "countries": countries.most_common(10),
        "kpis": {
            "top_port": feed["top_ports"][0],
            "loudest": {k: scanners[0][k] for k in ("ip", "reports", "targets")},
            "broadest": {k: broadest[k] for k in ("ip", "reports", "targets")},
        },
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Live threat feed from SANS DShield and blocklist.de.")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="download today's attackers and attacked ports")
    f.add_argument("--out", default=str(LIVE))
    b = sub.add_parser("build", help="combine feeds + IOC Enricher output into docs/live-data.js")
    b.add_argument("--feed", default=str(LIVE / "dshield.json"))
    b.add_argument("--enriched", default=str(LIVE / "enriched.json"))
    b.add_argument("--out", default=str(ROOT / "docs" / "live-data.js"))
    args = p.parse_args()

    if args.cmd == "fetch":
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        try:
            feed = fetch()
        except Exception as e:  # network errors, bad JSON, empty feed: keep the last good page instead
            sys.exit(f"Fetch failed, leaving the published feed unchanged: {e}")
        (out / "dshield.json").write_text(json.dumps(feed, indent=2), encoding="utf-8")
        ips = dict.fromkeys([r["ip"] for r in feed["top_ips"]] + feed["ssh_sample"])
        (out / "ips.txt").write_text("\n".join(ips) + "\n", encoding="utf-8")
        print(f"Fetched {len(feed['top_ips'])} DShield sources, {len(feed['top_ports'])} ports, and "
              f"{len(feed['ssh_sample'])} of {feed['ssh_total']:,} blocklist.de SSH attackers")
    else:
        feed = json.loads(Path(args.feed).read_text(encoding="utf-8"))
        enriched = json.loads(Path(args.enriched).read_text(encoding="utf-8"))
        data = build_live_data(feed, enriched)
        Path(args.out).write_text(to_js(data, "LIVE_FEED_DATA"), encoding="utf-8")
        st = data["stats"]
        print(f"Wrote {args.out}: scanners {st['scanners']['malicious']}/{st['scanners']['checked']} malicious, "
              f"SSH attackers {st['ssh']['malicious']}/{st['ssh']['checked']} malicious")


if __name__ == "__main__":
    main()
