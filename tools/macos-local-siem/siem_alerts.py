#!/usr/bin/env python3
"""Local SIEM alerting and dashboard output."""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import sqlite3
import subprocess
from pathlib import Path


def parse_args() -> argparse.Namespace:
    app_home = Path.home() / "Library" / "Application Support" / "CorpusLocalSIEM"
    parser = argparse.ArgumentParser(description="Generate local SIEM alerts and dashboard.")
    parser.add_argument("--db", default=str(app_home / "localsiem.db"))
    parser.add_argument("--dashboard-root", default="/opt/homebrew/var/www/localsiem")
    parser.add_argument("--notify", action="store_true")
    parser.add_argument("--window-minutes", type=int, default=60)
    parser.add_argument("--report-hours", type=int, default=24)
    return parser.parse_args()


def fetch_scalar(conn: sqlite3.Connection, query: str, params: tuple = ()) -> int:
    row = conn.execute(query, params).fetchone()
    return int(row[0] if row and row[0] is not None else 0)


def get_alerts(conn: sqlite3.Connection, window_minutes: int) -> list[dict]:
    alerts: list[dict] = []

    auth_failures = conn.execute(
        """
        SELECT COALESCE(actor_ip, 'unknown') AS actor, COUNT(*) AS c
        FROM events
        WHERE event_type = 'auth_failure'
          AND event_ts >= datetime('now', ?)
        GROUP BY actor
        HAVING c >= 5
        ORDER BY c DESC
        """,
        (f"-{window_minutes} minutes",),
    ).fetchall()
    for actor, count in auth_failures:
        alerts.append(
            {
                "severity": "high",
                "title": "Repeated authentication failures",
                "detail": f"{count} auth failures from {actor} in the last {window_minutes} minutes.",
            }
        )

    apache_5xx = fetch_scalar(
        conn,
        """
        SELECT COUNT(*)
        FROM events
        WHERE source = 'apache_access'
          AND severity = 'high'
          AND event_ts >= datetime('now', ?)
        """,
        (f"-{window_minutes} minutes",),
    )
    if apache_5xx >= 10:
        alerts.append(
            {
                "severity": "high",
                "title": "Elevated Apache 5xx volume",
                "detail": f"{apache_5xx} high-severity Apache access events in the last {window_minutes} minutes.",
            }
        )

    apache_errors = fetch_scalar(
        conn,
        """
        SELECT COUNT(*)
        FROM events
        WHERE source = 'apache_error'
          AND severity IN ('high', 'medium')
          AND event_ts >= datetime('now', ?)
        """,
        (f"-{window_minutes} minutes",),
    )
    if apache_errors >= 5:
        alerts.append(
            {
                "severity": "medium",
                "title": "Apache error spike",
                "detail": f"{apache_errors} Apache error events in the last {window_minutes} minutes.",
            }
        )

    tshark_errors = fetch_scalar(
        conn,
        """
        SELECT COUNT(*)
        FROM events
        WHERE source = 'tshark_summary'
          AND event_type = 'collector_error'
          AND event_ts >= datetime('now', ?)
        """,
        (f"-{window_minutes} minutes",),
    )
    if tshark_errors:
        alerts.append(
            {
                "severity": "medium",
                "title": "Packet telemetry collection issue",
                "detail": f"tshark collector failed {tshark_errors} time(s) in the last {window_minutes} minutes.",
            }
        )

    return alerts


def build_terminal_report(conn: sqlite3.Connection, alerts: list[dict], report_hours: int) -> str:
    since = f"-{report_hours} hours"
    rows = conn.execute(
        """
        SELECT source, COUNT(*) AS c
        FROM events
        WHERE event_ts >= datetime('now', ?)
        GROUP BY source
        ORDER BY c DESC
        """,
        (since,),
    ).fetchall()
    total = sum(row[1] for row in rows)
    lines = [
        "=== Corpus Local SIEM Report ===",
        f"Window: last {report_hours}h",
        f"Total normalized events: {total}",
    ]
    if rows:
        lines.append("By source:")
        for source, count in rows:
            lines.append(f"  - {source}: {count}")
    else:
        lines.append("By source: no events captured yet.")

    lines.append("")
    lines.append("Alerts:")
    if alerts:
        for alert in alerts:
            lines.append(f"  [{alert['severity'].upper()}] {alert['title']} — {alert['detail']}")
    else:
        lines.append("  No active high-signal detections.")
    return "\n".join(lines)


def build_dashboard_html(conn: sqlite3.Connection, alerts: list[dict], report_hours: int) -> str:
    source_rows = conn.execute(
        """
        SELECT source, COUNT(*) AS c
        FROM events
        WHERE event_ts >= datetime('now', ?)
        GROUP BY source
        ORDER BY c DESC
        """,
        (f"-{report_hours} hours",),
    ).fetchall()
    latest_events = conn.execute(
        """
        SELECT event_ts, source, severity, COALESCE(actor_ip, ''), event_type, raw_excerpt
        FROM events
        ORDER BY event_ts DESC
        LIMIT 50
        """
    ).fetchall()
    generated = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%SZ")

    alert_items = "".join(
        f"<li><strong>{html.escape(a['severity'].upper())}</strong> "
        f"{html.escape(a['title'])}: {html.escape(a['detail'])}</li>"
        for a in alerts
    )
    if not alert_items:
        alert_items = "<li>No active high-signal detections.</li>"

    source_rows_html = "".join(
        f"<tr><td>{html.escape(source)}</td><td>{count}</td></tr>" for source, count in source_rows
    )
    event_rows_html = "".join(
        "<tr>"
        f"<td>{html.escape(ts)}</td>"
        f"<td>{html.escape(source)}</td>"
        f"<td>{html.escape(severity)}</td>"
        f"<td>{html.escape(actor)}</td>"
        f"<td>{html.escape(event_type)}</td>"
        f"<td>{html.escape(excerpt[:200])}</td>"
        "</tr>"
        for ts, source, severity, actor, event_type, excerpt in latest_events
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Corpus Local SIEM v1</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 24px; color: #111827; }}
    .card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 6px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    .small {{ color: #6b7280; font-size: 12px; }}
  </style>
</head>
<body>
  <h1>Corpus Local SIEM v1</h1>
  <p class="small">Generated: {generated} UTC</p>

  <div class="card">
    <h2>Active Alerts</h2>
    <ul>{alert_items}</ul>
  </div>

  <div class="card">
    <h2>Event Volume (last {report_hours}h)</h2>
    <table>
      <thead><tr><th>Source</th><th>Count</th></tr></thead>
      <tbody>{source_rows_html}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Latest Normalized Events</h2>
    <table>
      <thead>
        <tr>
          <th>Timestamp (UTC)</th><th>Source</th><th>Severity</th><th>Actor/IP</th><th>Event Type</th><th>Raw Excerpt</th>
        </tr>
      </thead>
      <tbody>{event_rows_html}</tbody>
    </table>
  </div>
</body>
</html>
"""


def maybe_notify(alerts: list[dict]) -> None:
    if not alerts:
        return
    top = alerts[0]
    title = "Corpus Local SIEM Alert"
    body = f"{top['severity'].upper()}: {top['title']}"
    script = f'display notification "{body}" with title "{title}"'
    subprocess.run(["osascript", "-e", script], check=False)


def main() -> int:
    args = parse_args()
    db_path = Path(args.db).expanduser()
    if not db_path.exists():
        print(json.dumps({"error": f"database not found at {db_path}"}))
        return 1

    conn = sqlite3.connect(db_path)
    alerts = get_alerts(conn, args.window_minutes)
    report = build_terminal_report(conn, alerts, args.report_hours)
    print(report)

    dashboard_root = Path(args.dashboard_root).expanduser()
    dashboard_root.mkdir(parents=True, exist_ok=True)
    dashboard = dashboard_root / "index.html"
    dashboard.write_text(build_dashboard_html(conn, alerts, args.report_hours), encoding="utf-8")
    conn.close()

    if args.notify:
        maybe_notify(alerts)

    print(f"\nDashboard written to: {dashboard}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
