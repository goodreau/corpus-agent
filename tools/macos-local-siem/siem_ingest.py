#!/usr/bin/env python3
"""Local macOS SIEM v1 ingestion pipeline."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UTC = dt.timezone.utc

APACHE_ACCESS_CANDIDATES = (
    "/var/log/apache2/access_log",
    "/opt/homebrew/var/log/apache2/access_log",
    "/opt/homebrew/var/log/httpd/access_log",
)
APACHE_ERROR_CANDIDATES = (
    "/var/log/apache2/error_log",
    "/opt/homebrew/var/log/apache2/error_log",
    "/opt/homebrew/var/log/httpd/error_log",
)

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<when>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+'
    r'(?P<path>[^"]+)\s+HTTP/[0-9.]+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
ERROR_RE = re.compile(
    r"^\[(?P<when>[^\]]+)\]\s+\[(?P<module>[^\]]+)\]\s+\[pid\s+(?P<pid>\d+)"
    r"(?::tid\s+\d+)?\](?:\s+\[client\s+(?P<client>[^\]]+)\])?\s*(?P<message>.*)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Event:
    event_ts: str
    source: str
    severity: str
    actor_ip: str | None
    event_type: str
    raw_excerpt: str
    metadata: dict[str, Any]

    def uid(self) -> str:
        canonical = "|".join(
            [
                self.event_ts,
                self.source,
                self.severity,
                self.actor_ip or "",
                self.event_type,
                self.raw_excerpt,
            ]
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_args() -> argparse.Namespace:
    app_home = Path.home() / "Library" / "Application Support" / "CorpusLocalSIEM"
    parser = argparse.ArgumentParser(description="Ingest local SIEM data into SQLite.")
    parser.add_argument("--db", default=str(app_home / "localsiem.db"))
    parser.add_argument("--lookback-minutes", type=int, default=65)
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--access-log", default=first_existing(APACHE_ACCESS_CANDIDATES))
    parser.add_argument("--error-log", default=first_existing(APACHE_ERROR_CANDIDATES))
    parser.add_argument("--tshark-duration-sec", type=int, default=8)
    parser.add_argument("--max-lines-per-log", type=int, default=4000)
    return parser.parse_args()


def first_existing(candidates: tuple[str, ...]) -> str:
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return candidates[0]


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_uid TEXT NOT NULL UNIQUE,
            event_ts TEXT NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            actor_ip TEXT,
            event_type TEXT NOT NULL,
            raw_excerpt TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(event_ts);
        CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_ip);
        """
    )


def coerce_timestamp(value: str | None) -> str:
    if not value:
        return dt.datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
    candidate = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(candidate)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            parsed = dt.datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return dt.datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


def severity_from_http_status(status: int) -> str:
    if status >= 500:
        return "high"
    if status >= 400:
        return "medium"
    return "info"


def detect_macos_event_type(message: str) -> str:
    lower = message.lower()
    if "failed" in lower and ("auth" in lower or "login" in lower or "password" in lower):
        return "auth_failure"
    if "accepted" in lower or "authenticated" in lower:
        return "auth_success"
    if "sudo" in lower:
        return "privilege_use"
    return "system_security_event"


def ingest_events(conn: sqlite3.Connection, events: list[Event]) -> int:
    inserted = 0
    for event in events:
        row = (
            event.uid(),
            event.event_ts,
            event.source,
            event.severity,
            event.actor_ip,
            event.event_type,
            event.raw_excerpt[:500],
            json.dumps(event.metadata, ensure_ascii=False),
        )
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO events (
                event_uid, event_ts, source, severity, actor_ip, event_type, raw_excerpt, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted


def collect_macos_logs(lookback_minutes: int) -> list[Event]:
    cmd = [
        "log",
        "show",
        "--style",
        "json",
        "--last",
        f"{lookback_minutes}m",
        "--predicate",
        '(process == "sudo" OR process == "sshd" OR process == "securityd" OR process == "authorizationhost" OR process == "opendirectoryd" OR process == "loginwindow")',
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return [
            Event(
                event_ts=coerce_timestamp(None),
                source="macos_unified_log",
                severity="medium",
                actor_ip=None,
                event_type="collector_error",
                raw_excerpt=f"log show failed: {proc.stderr.strip() or proc.stdout.strip()}",
                metadata={"command": " ".join(cmd), "returncode": proc.returncode},
            )
        ]

    events: list[Event] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = str(
            item.get("eventMessage")
            or item.get("composedMessage")
            or item.get("message")
            or ""
        )
        if not message:
            continue
        ts = coerce_timestamp(
            str(item.get("timestamp") or item.get("time") or item.get("date") or "")
        )
        message_type = str(item.get("messageType") or "default").lower()
        severity = "info"
        if "error" in message_type:
            severity = "high"
        elif "fault" in message_type or "default" not in message_type:
            severity = "medium"
        actor_match = IP_RE.search(message)
        events.append(
            Event(
                event_ts=ts,
                source="macos_unified_log",
                severity=severity,
                actor_ip=actor_match.group(0) if actor_match else None,
                event_type=detect_macos_event_type(message),
                raw_excerpt=message,
                metadata={
                    "process": item.get("process"),
                    "pid": item.get("pid"),
                    "subsystem": item.get("subsystem"),
                    "category": item.get("category"),
                    "messageType": item.get("messageType"),
                },
            )
        )
    return events


def tail_lines(path: Path, max_lines: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
        return lines[-max_lines:]
    except OSError:
        return []


def collect_apache_access(path: str, max_lines: int) -> list[Event]:
    target = Path(path)
    if not target.exists():
        return []
    events: list[Event] = []
    for line in tail_lines(target, max_lines):
        match = ACCESS_RE.match(line.strip())
        if not match:
            continue
        status = int(match.group("status"))
        events.append(
            Event(
                event_ts=coerce_timestamp(match.group("when")),
                source="apache_access",
                severity=severity_from_http_status(status),
                actor_ip=match.group("ip"),
                event_type=f"http_{status}",
                raw_excerpt=line.strip(),
                metadata={
                    "method": match.group("method"),
                    "path": match.group("path"),
                    "status": status,
                    "size": match.group("size"),
                    "referer": match.group("referer") or "",
                    "user_agent": match.group("ua") or "",
                    "log_path": path,
                },
            )
        )
    return events


def collect_apache_error(path: str, max_lines: int) -> list[Event]:
    target = Path(path)
    if not target.exists():
        return []
    events: list[Event] = []
    for line in tail_lines(target, max_lines):
        stripped = line.strip()
        match = ERROR_RE.match(stripped)
        if not match:
            continue
        module = match.group("module").lower()
        severity = "high" if "error" in module or "crit" in module else "medium"
        client = match.group("client") or ""
        actor = IP_RE.search(client)
        events.append(
            Event(
                event_ts=coerce_timestamp(match.group("when")),
                source="apache_error",
                severity=severity,
                actor_ip=actor.group(0) if actor else None,
                event_type="apache_error",
                raw_excerpt=stripped,
                metadata={
                    "module": module,
                    "pid": match.group("pid"),
                    "client": client,
                    "message": match.group("message"),
                    "log_path": path,
                },
            )
        )
    return events


def parse_tshark_interfaces() -> str | None:
    proc = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line[0].isdigit():
            return line.split(".", 1)[0]
    return None


def collect_tshark(duration_sec: int) -> list[Event]:
    interface = parse_tshark_interfaces()
    if not interface:
        return []
    cmd = [
        "tshark",
        "-n",
        "-Q",
        "-q",
        "-i",
        interface,
        "-a",
        f"duration:{duration_sec}",
        "-z",
        "conv,ip",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return [
            Event(
                event_ts=coerce_timestamp(None),
                source="tshark_summary",
                severity="medium",
                actor_ip=None,
                event_type="collector_error",
                raw_excerpt=f"tshark capture failed: {proc.stderr.strip() or proc.stdout.strip()}",
                metadata={"command": " ".join(cmd), "returncode": proc.returncode},
            )
        ]

    now = coerce_timestamp(None)
    events: list[Event] = []
    for line in proc.stdout.splitlines():
        if "<->" not in line:
            continue
        excerpt = " ".join(line.split())
        if not excerpt:
            continue
        ips = IP_RE.findall(excerpt)
        actor = ips[0] if ips else None
        events.append(
            Event(
                event_ts=now,
                source="tshark_summary",
                severity="info",
                actor_ip=actor,
                event_type="network_conversation",
                raw_excerpt=excerpt,
                metadata={"interface": interface},
            )
        )
    if not events:
        events.append(
            Event(
                event_ts=now,
                source="tshark_summary",
                severity="info",
                actor_ip=None,
                event_type="network_capture_empty",
                raw_excerpt="No conversations observed during tshark sampling window.",
                metadata={"interface": interface, "duration_sec": duration_sec},
            )
        )
    return events


def apply_retention(conn: sqlite3.Connection, retention_days: int) -> int:
    cur = conn.execute(
        "DELETE FROM events WHERE event_ts < datetime('now', ?)",
        (f"-{retention_days} days",),
    )
    conn.commit()
    return cur.rowcount


def main() -> int:
    args = parse_args()
    db_path = Path(args.db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    ensure_schema(conn)

    mac_events = collect_macos_logs(args.lookback_minutes)
    access_events = collect_apache_access(args.access_log, args.max_lines_per_log)
    error_events = collect_apache_error(args.error_log, args.max_lines_per_log)
    tshark_events = collect_tshark(args.tshark_duration_sec)

    inserted = {
        "macos_unified_log": ingest_events(conn, mac_events),
        "apache_access": ingest_events(conn, access_events),
        "apache_error": ingest_events(conn, error_events),
        "tshark_summary": ingest_events(conn, tshark_events),
    }
    purged = apply_retention(conn, args.retention_days)
    conn.close()

    print(
        json.dumps(
            {
                "db": str(db_path),
                "inserted": inserted,
                "retention_days": args.retention_days,
                "purged": purged,
                "lookback_minutes": args.lookback_minutes,
                "access_log": args.access_log,
                "error_log": args.error_log,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
