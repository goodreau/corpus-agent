# macOS Local SIEM v1

Local-first SIEM pipeline for macOS that ingests:

- macOS unified security/auth events (`log show`)
- Apache access/error logs
- Wireshark/tshark packet summaries

into one normalized SQLite store with idempotent inserts and 90-day retention.

## Components

- `siem_ingest.py` — scheduled ingestion + normalization + retention purge.
- `siem_alerts.py` — high-signal detection, terminal report, Apache dashboard output, optional macOS notifications.
- `run_cycle.sh` — one end-to-end cycle (ingest + alerting).
- `install_launch_agent.sh` — installs a user launchd job running every 15 minutes.
- `com.corpus.localsiem.plist.template` — launchd template.

## Data store

Default DB path:

`~/Library/Application Support/CorpusLocalSIEM/localsiem.db`

Normalized schema:

- `event_ts`
- `source`
- `severity`
- `actor_ip`
- `event_type`
- `raw_excerpt`

Idempotency is enforced via unique `event_uid` (SHA-256 of canonical event fields).

## Dashboard

Default Apache dashboard path:

`/opt/homebrew/var/www/localsiem/index.html`

If your Apache docroot differs, run alerts with `--dashboard-root <path>`.

## Install and run

```bash
cd /Volumes/Corpus/corpus-agent/tools/macos-local-siem
chmod +x run_cycle.sh install_launch_agent.sh
./run_cycle.sh
./install_launch_agent.sh
```

## Manual commands

```bash
python3 siem_ingest.py --lookback-minutes 65 --tshark-duration-sec 8
python3 siem_alerts.py --notify
sqlite3 ~/Library/Application\ Support/CorpusLocalSIEM/localsiem.db \
  "SELECT source, COUNT(*) FROM events GROUP BY source;"
```

## Notes

- No cloud dependencies are required.
- No firewall/routing/network reconfiguration is performed.
- Existing services are not replaced.
