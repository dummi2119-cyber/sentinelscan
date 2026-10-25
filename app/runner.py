"""Background scan execution and report generation."""
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor

from . import config, db, scanners

_executor = ThreadPoolExecutor(max_workers=config.MAX_CONCURRENT_SCANS)


def submit(scan_id):
    try:
        _executor.submit(_run, scan_id)
        return True
    except Exception:
        return False


def running_count():
    return sum(1 for f in _executor._threads if getattr(f, "ident", None) and f.is_alive()) if hasattr(_executor, "_threads") else 0


def _run(scan_id):
    start = time.time()
    scan = db.get_scan(scan_id)
    if not scan:
        return
    user_id = scan["user_id"]
    tool = scan["tool"]
    target = scan["target"]
    params = json.loads(scan["params"] or "{}")

    db.update_scan(scan_id, status="running", started_at=db.now_ts(), error="")
    db.audit("scan_started", f"{scan_id}:{target}", actor=f"user:{user_id}")

    try:
        findings, meta = scanners.run_scan(tool, target, params)
        summary = scanners.summarize(findings)
        report_path = os.path.join(config.REPORT_DIR, f"{scan_id}.json")
        report = {
            "scan_id": scan_id,
            "tool": tool,
            "target": target,
            "params": params,
            "meta": meta,
            "generated_at": db.now_ts(),
            "summary": summary,
            "findings": findings,
        }
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)

        html = render_html_report(report)
        html_path = os.path.join(config.REPORT_DIR, f"{scan_id}.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        # charge credits once, only on success
        _charge(user_id, tool)

        db.update_scan(
            scan_id,
            status="completed",
            finished_at=db.now_ts(),
            summary=json.dumps(summary),
            report_json=report_path,
            report_html=html_path,
            error="",
        )
        db.audit("scan_completed", f"{scan_id}:{target}", actor=f"user:{user_id}")
    except Exception as e:
        db.update_scan(scan_id, status="failed", finished_at=db.now_ts(), error=str(e)[:1000])
        db.audit("scan_failed", f"{scan_id}:{target}", actor=f"user:{user_id}")


def _charge(user_id, tool):
    tool_row = db.get_tool(tool)
    cost = tool_row["credits"] if tool_row else 1
    with db.get_db() as conn:
        conn.execute("UPDATE users SET credits = credits - ? WHERE id=? AND credits >= ?", (cost, user_id, cost))
        row = conn.execute("SELECT credits FROM users WHERE id=?", (user_id,)).fetchone()
        remaining = row["credits"] if row else 0
    return remaining


def cancel(scan_id):
    # We don't forcibly kill threads in this demo; we mark intent so the runner
    # short-circuits if still queued.
    scan = db.get_scan(scan_id)
    if scan and scan["status"] == "queued":
        db.update_scan(scan_id, status="cancelled")
        return True
    return False


# ---------------------------------------------------------------------------
# HTML report rendering (self-contained, no template engine needed)
# ---------------------------------------------------------------------------
_SEV_COLOR = {
    "critical": "#e11d48", "high": "#f97316", "medium": "#eab308",
    "low": "#3b82f6", "info": "#64748b",
}


def render_html_report(report):
    s = report["summary"]
    meta = report["meta"]
    tool_name = (dict(db.get_tool(report["tool"]) or {}) or {}).get("name", report["tool"])
    findings_rows = []
    for f in report["findings"]:
        color = _SEV_COLOR.get(f["severity"], "#64748b")
        findings_rows.append(f"""
      <tr>
        <td><span class="badge" style="background:{color}">{f['severity'].upper()}</span></td>
        <td>{_h(f['title'])}</td>
        <td>{f.get('path','')}</td>
        <td>{f.get('cvss','—')}</td>
      </tr>""")
    findings_html = "\n".join(findings_rows) or "<tr><td colspan=4>No findings.</td></tr>"

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan Report {report['scan_id']}</title>
<style>
  :root{{--bg:#0b1020;--card:#131a2e;--line:#24304d;--txt:#e6ecff;--mut:#8ea0c8}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--txt);font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
  .wrap{{max-width:980px;margin:0 auto;padding:32px 20px 64px}}
  h1{{font-size:24px;margin:0 0 4px}} .mut{{color:var(--mut)}}
  .card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin:18px 0}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}}
  .stat{{background:#0e1526;border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}}
  .stat b{{display:block;font-size:26px}}
  table{{width:100%;border-collapse:collapse;font-size:14px}}
  th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
  th{{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}}
  .badge{{color:#fff;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase}}
  .kv{{display:grid;grid-template-columns:160px 1fr;gap:6px 14px}}
  .kv div:nth-child(odd){{color:var(--mut)}}
  a{{color:#38bdf8}} .rem{{white-space:pre-wrap}}
</style></head><body><div class="wrap">
  <p class="mut">SentinelScan Report</p>
  <h1>{_h(tool_name)} &mdash; {_h(report['target'])}</h1>
  <p class="mut">{report['scan_id']} &middot; generated {_dt(report['generated_at'])}
     &middot; mode: <b>{meta.get('mode','simulated')}</b></p>

  <div class="card">
    <div class="grid">
      <div class="stat"><b style="color:#e11d48">{s.get('critical',0)}</b>Critical</div>
      <div class="stat"><b style="color:#f97316">{s.get('high',0)}</b>High</div>
      <div class="stat"><b style="color:#eab308">{s.get('medium',0)}</b>Medium</div>
      <div class="stat"><b style="color:#3b82f6">{s.get('low',0)}</b>Low</div>
      <div class="stat"><b style="color:#8ea0c8">{s.get('info',0)}</b>Info</div>
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0">Scan details</h2>
    <div class="kv">
      <div>Target</div><div>{_h(report['target'])}</div>
      <div>Tool</div><div>{_h(tool_name)}</div>
      <div>Started</div><div>{_dt(report.get('started_at'))}</div>
      <div>Finished</div><div>{_dt(report.get('finished_at'))}</div>
      <div>Duration</div><div>{report.get('duration_s','—')}s</div>
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0">Findings</h2>
    <table><thead><tr><th>Severity</th><th>Title</th><th>Location</th><th>CVSS</th></tr></thead>
    <tbody>{findings_html}</tbody></table>
  </div>

  <div class="card">
    <h2 style="margin-top:0">Detailed findings</h2>
    {''.join(_finding_block(f) for f in report['findings'])}
  </div>

  <p class="mut" style="text-align:center;font-size:12px">Generated by SentinelScan &middot; Confidential</p>
</div></body></html>"""


def _finding_block(f):
    color = _SEV_COLOR.get(f["severity"], "#64748b")
    return f"""
    <div style="border:1px solid var(--line);border-left:4px solid {color};border-radius:10px;padding:14px;margin:12px 0">
      <div><span class="badge" style="background:{color}">{f['severity'].upper()}</span>
      <b> {_h(f['title'])}</b> <span class="mut">CVSS {f.get('cvss','—')}</span></div>
      <div class="mut" style="margin:6px 0">Location: <code>{_h(f.get('path',''))}</code> &middot; ID {f['id']}</div>
      <p>{_h(f['description'])}</p>
      <p><b style="color:#fca5a5">Impact:</b> {_h(f['impact'])}</p>
      <p><b style="color:#86efac">Remediation:</b> {_h(f['remediation'])}</p>
      <p class="rem"><b>Evidence:</b> {_h(f.get('evidence',''))}</p>
      <p class="mut">Reference: <a href="{_h(f['reference'])}" target="_blank">{_h(f['reference'])}</a></p>
    </div>"""


def _h(s):
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _dt(ts):
    return db.to_dt(ts) or "—"
