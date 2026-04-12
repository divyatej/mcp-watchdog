"""
Generate a self-contained HTML audit report from a mcp_watchdog.jsonl log.

Usage:
    mcp-watchdog report --log mcp_watchdog.jsonl --out report.html
"""

import html as _html
from collections import Counter, defaultdict
from pathlib import Path

from .logger import load_log


def _e(value) -> str:
    """HTML-escape a value from untrusted log data."""
    return _html.escape(str(value))


def generate_report(log_path: str, out_path: str = "mcp_watchdog_report.html"):
    events = load_log(log_path)
    if not events:
        print(f"No events found in {log_path}")
        return

    # Aggregate stats
    tool_calls: Counter = Counter()
    verdicts: list[dict] = []
    sessions: set = set()
    methods: Counter = Counter()

    for e in events:
        sessions.add(e.get("session", ""))
        if e["type"] == "message":
            methods[e.get("method", "")] += 1
            if e.get("tool"):
                tool_calls[e["tool"]] += 1
        elif e["type"] == "verdict":
            verdicts.append(e)

    blocks = [v for v in verdicts if v["action"] == "block"]
    alerts = [v for v in verdicts if v["action"] == "alert"]

    # Timeline for sparkline (tool calls per minute bucket)
    from collections import OrderedDict
    minute_buckets: defaultdict = defaultdict(int)
    for e in events:
        if e["type"] == "message" and e.get("tool"):
            minute = e["ts"][:16]  # "YYYY-MM-DDTHH:MM"
            minute_buckets[minute] += 1
    timeline = list(OrderedDict(sorted(minute_buckets.items())).items())

    html = _build_html(
        sessions=sessions,
        tool_calls=tool_calls,
        methods=methods,
        blocks=blocks,
        alerts=alerts,
        timeline=timeline,
        events=events,
        log_path=log_path,
    )

    Path(out_path).write_text(html, encoding="utf-8")
    print(f"Report written to {out_path}")


def _build_html(sessions, tool_calls, methods, blocks, alerts, timeline, events, log_path):
    total_calls = sum(tool_calls.values())

    top_tools_rows = "\n".join(
        f"<tr><td>{_e(tool)}</td><td>{count}</td></tr>"
        for tool, count in tool_calls.most_common(15)
    )

    verdict_rows = ""
    for v in sorted(blocks + alerts, key=lambda x: x["ts"], reverse=True)[:100]:
        color = "#c0392b" if v["action"] == "block" else "#e67e22"
        verdict_rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:12px">{_e(v['ts'])}</td>
          <td><span style="color:{color};font-weight:bold">{_e(v['action'].upper())}</span></td>
          <td><code>{_e(v['tool'])}</code></td>
          <td>{_e(v['rule'])}</td>
          <td style="font-size:12px">{_e(v['reason'])}</td>
        </tr>"""

    timeline_labels = [t[0][11:16] for t in timeline]  # HH:MM
    timeline_values = [t[1] for t in timeline]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>mcp-watchdog audit report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: #0f1117; color: #e2e8f0; padding: 24px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .sub {{ color: #64748b; font-size: 13px; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: #1e2330; border-radius: 10px; padding: 20px 24px; min-width: 160px; }}
  .card .num {{ font-size: 36px; font-weight: 700; }}
  .card .label {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
  .red {{ color: #ef4444; }} .orange {{ color: #f97316; }}
  .green {{ color: #22c55e; }} .blue {{ color: #60a5fa; }}
  .section {{ background: #1e2330; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 15px; margin-bottom: 14px; color: #94a3b8; text-transform: uppercase;
                 letter-spacing: 0.08em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 10px; color: #64748b; border-bottom: 1px solid #2d3748; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #1a202c; }}
  tr:hover td {{ background: #252d3d; }}
  code {{ background: #2d3748; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  .chart-wrap {{ height: 180px; }}
</style>
</head>
<body>
<h1>🐕 mcp-watchdog audit report</h1>
<div class="sub">Log: {log_path} &nbsp;·&nbsp; Sessions: {len(sessions)}</div>

<div class="cards">
  <div class="card">
    <div class="num blue">{total_calls}</div><div class="label">Tool calls</div>
  </div>
  <div class="card">
    <div class="num red">{len(blocks)}</div><div class="label">Blocked</div>
  </div>
  <div class="card">
    <div class="num orange">{len(alerts)}</div><div class="label">Alerts</div>
  </div>
  <div class="card">
    <div class="num green">{len(tool_calls)}</div><div class="label">Unique tools</div>
  </div>
</div>

<div class="section">
  <h2>Activity timeline (tool calls / minute)</h2>
  <div class="chart-wrap"><canvas id="timeline"></canvas></div>
</div>

<div class="section">
  <h2>Top tools by call count</h2>
  <table>
    <tr><th>Tool</th><th>Calls</th></tr>
    {top_tools_rows}
  </table>
</div>

<div class="section">
  <h2>Blocked &amp; alerted calls (most recent 100)</h2>
  {'<p style="color:#64748b;font-size:13px">No issues detected.</p>' if not verdict_rows else f'''
  <table>
    <tr><th>Time</th><th>Action</th><th>Tool</th><th>Rule</th><th>Reason</th></tr>
    {verdict_rows}
  </table>'''}
</div>

<script>
(function () {{
  var labels = {timeline_labels};
  var values = {timeline_values};
  if (!labels.length) return;

  var canvas = document.getElementById('timeline');
  canvas.width  = canvas.parentElement.offsetWidth || 800;
  canvas.height = 160;
  var ctx = canvas.getContext('2d');
  var W = canvas.width, H = canvas.height;
  var pad = {{ top: 10, right: 10, bottom: 28, left: 36 }};
  var chartW = W - pad.left - pad.right;
  var chartH = H - pad.top - pad.bottom;

  var maxVal = Math.max.apply(null, values) || 1;
  var barW   = Math.max(2, chartW / labels.length - 2);

  ctx.fillStyle = '#1e2330';
  ctx.fillRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = '#2d3748';
  ctx.lineWidth = 1;
  for (var gi = 0; gi <= 4; gi++) {{
    var gy = pad.top + chartH - (gi / 4) * chartH;
    ctx.beginPath(); ctx.moveTo(pad.left, gy); ctx.lineTo(pad.left + chartW, gy); ctx.stroke();
    ctx.fillStyle = '#64748b';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxVal * gi / 4), pad.left - 4, gy + 3);
  }}

  // Bars
  for (var i = 0; i < values.length; i++) {{
    var x = pad.left + i * (chartW / labels.length);
    var barH = (values[i] / maxVal) * chartH;
    ctx.fillStyle = '#3b82f6';
    ctx.beginPath();
    ctx.roundRect(x + 1, pad.top + chartH - barH, barW, barH, 2);
    ctx.fill();
  }}

  // X-axis labels (show ~6 evenly spaced)
  ctx.fillStyle = '#64748b';
  ctx.font = '10px sans-serif';
  ctx.textAlign = 'center';
  var step = Math.max(1, Math.floor(labels.length / 6));
  for (var j = 0; j < labels.length; j += step) {{
    var lx = pad.left + j * (chartW / labels.length) + barW / 2;
    ctx.fillText(labels[j], lx, H - 6);
  }}
}})();
</script>
</body>
</html>"""