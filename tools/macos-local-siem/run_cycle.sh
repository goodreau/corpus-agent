#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_HOME="${HOME}/Library/Application Support/CorpusLocalSIEM"
DB_PATH="${APP_HOME}/localsiem.db"
LOG_PATH="${APP_HOME}/run.log"
DASHBOARD_ROOT="${SIEM_DASHBOARD_ROOT:-/opt/homebrew/var/www/localsiem}"
LOOKBACK_MINUTES="${SIEM_LOOKBACK_MINUTES:-65}"
TSHARK_DURATION="${SIEM_TSHARK_DURATION_SEC:-8}"

mkdir -p "${APP_HOME}"

{
  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Starting SIEM cycle"
  /usr/bin/env python3 "${SCRIPT_DIR}/siem_ingest.py" \
    --db "${DB_PATH}" \
    --lookback-minutes "${LOOKBACK_MINUTES}" \
    --tshark-duration-sec "${TSHARK_DURATION}"

  /usr/bin/env python3 "${SCRIPT_DIR}/siem_alerts.py" \
    --db "${DB_PATH}" \
    --dashboard-root "${DASHBOARD_ROOT}"

  echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Completed SIEM cycle"
} >> "${LOG_PATH}" 2>&1
