"""Combine Log Hunter and IOC Enricher output into the data file the dashboard page reads."""
import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def build_data(alerts_doc: dict, enriched_rows: list[dict], sources: dict) -> dict:
    summary = alerts_doc["summary"]
    intel = {row["ip"]: row for row in enriched_rows}

    attackers: dict[str, dict] = {}

    def attacker(ip: str) -> dict:
        return attackers.setdefault(ip, {"ip": ip, "failed_logins": 0, "rules": []})

    for ip, count in summary.get("top_attacking_ips", []):
        attacker(ip)["failed_logins"] = count
    for alert in alerts_doc["alerts"]:
        if alert["severity"] == "info":
            continue
        a = attacker(alert["ip"])
        if alert["rule"] not in a["rules"]:
            a["rules"].append(alert["rule"])
        if alert["rule"] == "brute_force":
            a["failed_logins"] = max(a["failed_logins"], alert["count"])

    for a in attackers.values():
        row = intel.get(a["ip"])
        if row:
            a.update(verdict=row["verdict"], abuse_score=row["abuse_score"], total_reports=row["total_reports"],
                     last_reported=row["last_reported"], country=row["country"], isp=row["isp"])
        else:
            a.update(verdict="not checked", abuse_score=None, total_reports=None,
                     last_reported=None, country=None, isp=None)

    by_country: dict[str, int] = defaultdict(int)
    for a in attackers.values():
        if a["country"]:
            by_country[a["country"]] += a["failed_logins"]

    alerts = [a for a in alerts_doc["alerts"]]
    rules = defaultdict(int)
    for a in alerts:
        rules[a["rule"]] += 1

    checked = [a for a in attackers.values() if a["verdict"] != "not checked"]
    verdicts = defaultdict(int)
    for a in checked:
        verdicts[a["verdict"]] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": sources,
        "period": {"start": summary["first_event"], "end": summary["last_event"]},
        "kpis": {
            "failed_logins": summary["failed_logins"],
            "failed_on_nonexistent_accounts": summary["failed_on_nonexistent_accounts"],
            "attacking_ips": summary["unique_attacking_ips"],
            "brute_force_ips": rules["brute_force"],
            "username_spray_ips": rules["username_spray"],
            "successful_logins": summary["successful_logins"],
            "suspicious_logins": rules["success_after_failure"],
            "intel_checked": len(checked),
            "intel_malicious": verdicts.get("malicious", 0),
        },
        "verdicts": dict(verdicts),
        "timeline": summary.get("failed_logins_timeline", []),
        "top_usernames": summary["top_targeted_usernames"],
        "countries": sorted(by_country.items(), key=lambda kv: -kv[1]),
        "attackers": sorted(attackers.values(), key=lambda a: -a["failed_logins"]),
        "alerts": alerts,
    }


def to_js(data: dict, var: str = "HOME_SOC_DATA") -> str:
    # The data contains attacker-controlled strings (usernames from SSH logs). Escaping <, > and &
    # means no value can ever close a script tag or form HTML, even if this file is inlined later.
    payload = json.dumps(data, ensure_ascii=True, indent=1)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return f"window.{var} = {payload};\n"


def main() -> None:
    p = argparse.ArgumentParser(description="Build the Home SOC dashboard data file.")
    p.add_argument("--alerts", default=str(ROOT / "sample-data" / "alerts.json"), help="Log Hunter alerts.json")
    p.add_argument("--enriched", default=str(ROOT / "sample-data" / "enriched.json"), help="IOC Enricher enriched.json")
    p.add_argument("--dataset", default="Loghub OpenSSH sample (historical lab-server logs)",
                   help="description of where the logs came from")
    p.add_argument("--out", default=str(ROOT / "docs" / "data.js"))
    args = p.parse_args()

    alerts_doc = json.loads(Path(args.alerts).read_text(encoding="utf-8"))
    enriched = json.loads(Path(args.enriched).read_text(encoding="utf-8"))
    data = build_data(alerts_doc, enriched, {"dataset": args.dataset, "intel": "AbuseIPDB"})
    Path(args.out).write_text(to_js(data), encoding="utf-8")
    print(f"Wrote {args.out}: {len(data['attackers'])} attackers, {len(data['alerts'])} alerts")


if __name__ == "__main__":
    main()
