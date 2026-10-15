"use strict";
// All values come from third-party feeds, so they are only ever inserted with textContent.

(function () {
  const data = window.LIVE_FEED_DATA;
  const fmt = (n) => (n === null || n === undefined ? "–" : Number(n).toLocaleString("en-GB"));
  const STALE_AFTER_HOURS = 48;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  const fetched = new Date(data.fetched_at);
  document.getElementById("updated").textContent =
    `Updated ${fetched.toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" })} UTC. ` +
    "Refreshed automatically every day.";

  const ageHours = (Date.now() - fetched.getTime()) / 36e5;
  if (ageHours > STALE_AFTER_HOURS) {
    const stale = document.getElementById("stale");
    stale.append(el("strong", "", "This data is out of date. "),
      document.createTextNode(`The last successful update was ${Math.floor(ageHours / 24)} days ago, so the daily job may be failing.`));
    stale.hidden = false;
  }

  const top = data.kpis.top_port;
  document.getElementById("hero-value").textContent = top.name ? `${top.port} (${top.name})` : String(top.port);
  document.getElementById("hero-note").textContent =
    `${fmt(top.attacks)} attacks from ${fmt(top.sources)} different sources.`;

  // ---------- comparison ----------

  const st = data.stats;
  const compare = document.getElementById("compare");
  for (const [source, s, detail] of [
    ["SSH password guessers (blocklist.de)", st.ssh, `random sample of ${fmt(data.ssh_total)} reported in the last 48 hours`],
    ["Most active sources (DShield)", st.scanners, "top 25 by attacks reported today"],
  ]) {
    const item = el("div", "compare-item");
    item.append(el("p", "compare-source", source),
      el("p", "compare-value", `${s.malicious} of ${s.checked}`),
      el("p", "compare-detail", `flagged malicious by AbuseIPDB · ${detail}`));
    compare.append(item);
  }
  document.getElementById("compare-note").textContent =
    "Why so different? DShield ranks sources by how often they hit its sensors, and the busiest are mostly " +
    "scanners sweeping the internet for open ports. Most server owners never notice those. AbuseIPDB is " +
    "largely fed by server owners reporting failed logins, which catches password guessers. " +
    "No single threat feed sees everything, which is why analysts cross-check more than one.";

  // ---------- tables ----------

  function table(id, headers, rows) {
    const t = document.getElementById(id);
    const tr = el("tr");
    for (const [label, cls] of headers) {
      const th = el("th", cls || "", label);
      th.scope = "col";
      tr.append(th);
    }
    const thead = el("thead");
    thead.append(tr);
    const tbody = el("tbody");
    for (const cells of rows) {
      const row = el("tr");
      row.append(...cells);
      tbody.append(row);
    }
    t.append(thead, tbody);
  }
  const td = (text, cls) => el("td", cls, text);
  function verdictCell(v) {
    const cell = el("td");
    cell.append(el("span", `status status-${v.replace(/\s+/g, "-")}`, v));
    return cell;
  }
  const score = (s) => (s === null || s === undefined ? "–" : `${s}/100`);

  document.getElementById("ssh-sub").textContent =
    `${data.ssh.length} randomly sampled from ${fmt(data.ssh_total)} IPs reported to blocklist.de for SSH attacks in the last 48 hours.`;

  table("table-ssh",
    [["IP address"], ["Threat intel"], ["Abuse score", "num"], ["Reports (1 yr)", "num"], ["Country"], ["Network owner"], ["Network type"]],
    data.ssh.map((a) => [td(a.ip, "mono"), verdictCell(a.verdict), td(score(a.abuse_score), "num"),
      td(fmt(a.total_reports), "num"), td(a.country || "–"), td(a.isp || "–", "wrap"), td(a.usage_type || "–", "wrap")]));

  table("table-scanners",
    [["#", "num"], ["IP address"], ["Attacks", "num"], ["Sensors hit", "num"], ["Threat intel"], ["Abuse score", "num"],
      ["Country"], ["Network owner"]],
    data.scanners.map((a) => [td(a.rank, "num"), td(a.ip, "mono"), td(fmt(a.reports), "num"), td(fmt(a.targets), "num"),
      verdictCell(a.verdict), td(score(a.abuse_score), "num"), td(a.country || "–"), td(a.isp || "–", "wrap")]));

  // ---------- charts ----------

  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const charts = [];

  function barChart(id, labels, values, unit, description) {
    const canvas = document.getElementById(id);
    canvas.setAttribute("aria-label", description);
    charts.push(new Chart(canvas, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data: values, backgroundColor: css("--series"), hoverBackgroundColor: css("--series-hover"),
          borderRadius: 4, borderSkipped: "start", maxBarThickness: 24, categoryPercentage: 0.8, barPercentage: 0.9,
        }],
      },
      options: {
        indexAxis: "y", maintainAspectRatio: false, animation: false,
        plugins: {
          legend: { display: false },
          tooltip: { displayColors: false, callbacks: { label: (ctx) => `${fmt(ctx.parsed.x)} ${unit}` } },
        },
        scales: {
          x: {
            beginAtZero: true, grid: { color: css("--grid") }, border: { display: false },
            ticks: {
              color: css("--text-muted"), precision: 0,
              callback: (v) => (v >= 1000 ? `${Math.round(v / 1000)}K` : v),
            },
          },
          y: { grid: { display: false }, border: { color: css("--axis") }, ticks: { color: css("--text-secondary"), autoSkip: false } },
        },
      },
    }));
  }

  function draw() {
    charts.splice(0).forEach((c) => c.destroy());
    Chart.defaults.font.family = 'system-ui, -apple-system, "Segoe UI", sans-serif';
    const ports = data.ports;
    barChart("chart-ports", ports.map((p) => (p.name ? `${p.port} ${p.name}` : String(p.port))), ports.map((p) => p.attacks),
      "attacks", "Bar chart of most-attacked ports: " + ports.map((p) => `${p.port} ${fmt(p.attacks)}`).join(", ") + ".");
    const c = data.countries;
    barChart("chart-countries", c.map(([code]) => code), c.map(([, n]) => n),
      "attackers", "Bar chart of attackers by country: " + c.map(([code, n]) => `${code} ${n}`).join(", ") + ".");
  }

  draw();
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", draw);
})();
