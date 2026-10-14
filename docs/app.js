"use strict";
// Every value on this page can contain attacker-controlled text (e.g. usernames typed into SSH),
// so it is only ever inserted with textContent, never as HTML.

(function () {
  const data = window.HOME_SOC_DATA;
  const fmt = (n) => (n === null || n === undefined ? "–" : Number(n).toLocaleString("en-GB"));

  function el(tag, opts = {}, text) {
    const node = document.createElement(tag);
    if (opts.className) node.className = opts.className;
    if (opts.scope) node.scope = opts.scope;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function timeLabel(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  }

  function dateTimeLabel(iso) {
    const d = new Date(iso);
    return d.toLocaleString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  }

  // ---------- text sections ----------

  const k = data.kpis;
  document.getElementById("period").textContent =
    `${data.sources.dataset}, ${dateTimeLabel(data.period.start)} to ${timeLabel(data.period.end)}.`;
  document.getElementById("hero-value").textContent = fmt(k.failed_logins);
  document.getElementById("hero-note").textContent =
    `from ${fmt(k.attacking_ips)} IP addresses. ${fmt(k.failed_on_nonexistent_accounts)} targeted accounts that don't exist.`;

  const tiles = [
    ["Brute-force sources", k.brute_force_ips, "10+ failures inside 5 minutes"],
    ["Username sprayers", k.username_spray_ips, "5+ different usernames tried"],
    ["Successful logins", k.successful_logins,
      k.suspicious_logins ? `${k.suspicious_logins} after repeated failures` : "none after repeated failures"],
    ["Flagged by threat intel", k.intel_malicious, `of ${k.intel_checked} checked in AbuseIPDB`],
  ];
  const tileRoot = document.getElementById("tiles");
  for (const [label, value, detail] of tiles) {
    const t = el("div", { className: "tile" });
    t.append(el("p", { className: "tile-label" }, label), el("p", { className: "tile-value" }, fmt(value)),
      el("p", { className: "tile-detail" }, detail));
    tileRoot.append(t);
  }

  const verdictCounts = Object.entries(data.verdicts).map(([v, n]) => `${n} ${v}`).join(", ");
  document.getElementById("intel-sub").textContent =
    `Every source with at least one failed login in the top 10, plus every IP Log Hunter flagged. ` +
    `Flagged IPs were checked in AbuseIPDB: ${verdictCounts || "none checked"}.`;

  const checked = data.attackers.filter((a) => a.verdict !== "not checked");
  if (checked.length && checked.every((a) => a.verdict === "no reports")) {
    const note = document.getElementById("intel-note");
    const lead = el("strong", {}, "Why threat intel finds nothing here: ");
    const reported = checked.filter((a) => a.last_reported).map((a) => a.last_reported.slice(0, 7));
    const tail = reported.length ? ` ${reported.length} had been reported before (last report: ` +
      `${reported.join(", ")}), but those reports are now too old to count.` : "";
    note.append(lead, document.createTextNode(
      "none of these addresses have abuse reports from the last 365 days." + tail +
      " Older logs often show this: attackers move on and IP addresses get reassigned, so threat " +
      "intelligence goes stale. That's why the last-reported date matters as much as the score."));
    note.hidden = false;
  }

  // ---------- tables ----------

  function table(id, headers, rows) {
    const t = document.getElementById(id);
    const thead = el("thead");
    const hr = el("tr");
    for (const [label, cls] of headers) hr.append(el("th", { className: cls || "", scope: "col" }, label));
    thead.append(hr);
    const tbody = el("tbody");
    for (const cells of rows) {
      const tr = el("tr");
      for (const cell of cells) tr.append(cell);
      tbody.append(tr);
    }
    t.append(thead, tbody);
  }

  function td(text, className) { return el("td", { className: className || "" }, text); }

  function statusCell(value) {
    const cell = el("td");
    cell.append(el("span", { className: `status status-${value.replace(/\s+/g, "-")}` }, value));
    return cell;
  }

  function rulesCell(rules) {
    const cell = el("td");
    if (!rules.length) cell.textContent = "–";
    for (const r of rules) cell.append(el("span", { className: "rule" }, r.replace(/_/g, " ")));
    return cell;
  }

  table("table-attackers",
    [["IP address"], ["Failed logins", "num"], ["Log Hunter rules"], ["Threat intel"], ["Abuse score", "num"],
      ["Last reported"], ["Country"], ["Network owner"]],
    data.attackers.map((a) => [
      td(a.ip, "mono"), td(fmt(a.failed_logins), "num"), rulesCell(a.rules), statusCell(a.verdict),
      td(a.abuse_score === null ? "–" : `${a.abuse_score}/100`, "num"),
      td(a.last_reported ? a.last_reported.slice(0, 10) : "–"), td(a.country || "–"), td(a.isp || "–", "wrap"),
    ]));

  const severityOrder = { high: 0, medium: 1, info: 2 };
  table("table-alerts",
    [["Severity"], ["Rule"], ["IP address"], ["Detail"]],
    [...data.alerts]
      .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || b.count - a.count)
      .map((a) => [statusCell(a.severity), td(a.rule.replace(/_/g, " ")), td(a.ip, "mono"), td(a.detail, "wrap")]));

  // ---------- charts ----------

  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const charts = [];

  function describe(canvasId, text) {
    document.getElementById(canvasId).setAttribute("aria-label", text);
  }

  function barChart(canvasId, labels, values, { horizontal = false, tooltipLabel = (v) => fmt(v) } = {}) {
    const series = css("--series");
    const chart = new Chart(document.getElementById(canvasId), {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: series,
          hoverBackgroundColor: css("--series-hover"),
          borderRadius: 4,
          borderSkipped: "start",
          maxBarThickness: 24,
          categoryPercentage: 0.8,
          barPercentage: 0.9,
        }],
      },
      options: {
        indexAxis: horizontal ? "y" : "x",
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            displayColors: false,
            callbacks: { label: (ctx) => tooltipLabel(ctx.parsed[horizontal ? "x" : "y"]) },
          },
        },
        scales: {
          [horizontal ? "x" : "y"]: {
            beginAtZero: true,
            grid: { color: css("--grid") },
            border: { display: false },
            ticks: { color: css("--text-muted"), precision: 0 },
          },
          [horizontal ? "y" : "x"]: {
            grid: { display: false },
            border: { color: css("--axis") },
            ticks: { color: css("--text-secondary"), autoSkip: !horizontal, maxRotation: 0 },
          },
        },
      },
    });
    charts.push(chart);
    return chart;
  }

  function drawCharts() {
    charts.splice(0).forEach((c) => c.destroy());
    Chart.defaults.font.family = 'system-ui, -apple-system, "Segoe UI", sans-serif';

    const tl = data.timeline;
    barChart("chart-timeline", tl.map(([t]) => timeLabel(t)), tl.map(([, n]) => n),
      { tooltipLabel: (v) => `${fmt(v)} failed logins` });
    const peak = tl.reduce((best, cur) => (cur[1] > best[1] ? cur : best), tl[0] || ["", 0]);
    describe("chart-timeline", `Column chart of failed logins per 10 minutes. Peak: ${peak[1]} at ${timeLabel(peak[0])}.`);

    const ips = data.attackers.slice(0, 10);
    barChart("chart-ips", ips.map((a) => a.ip), ips.map((a) => a.failed_logins),
      { horizontal: true, tooltipLabel: (v) => `${fmt(v)} failed logins` });
    describe("chart-ips", `Bar chart of top attacking IPs. Highest: ${ips[0].ip} with ${ips[0].failed_logins}.`);

    const users = data.top_usernames;
    barChart("chart-users", users.map(([u]) => u), users.map(([, n]) => n),
      { horizontal: true, tooltipLabel: (v) => `${fmt(v)} attempts` });
    describe("chart-users", `Bar chart of most-targeted usernames. Highest: ${users[0][0]} with ${users[0][1]}.`);

    const countries = data.countries;
    barChart("chart-countries", countries.map(([c]) => c), countries.map(([, n]) => n),
      { horizontal: true, tooltipLabel: (v) => `${fmt(v)} failed logins` });
    describe("chart-countries", "Bar chart of failed logins by attacker country: " +
      countries.map(([c, n]) => `${c} ${n}`).join(", ") + ".");
  }

  document.getElementById("footer-sources").textContent =
    `Data: ${data.sources.dataset}. Threat intelligence: ${data.sources.intel}. ` +
    `Page generated ${data.generated_at.slice(0, 10)}.`;

  drawCharts();
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", drawCharts);
})();
