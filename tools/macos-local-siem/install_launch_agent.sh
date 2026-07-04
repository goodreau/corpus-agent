#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNNER="${SCRIPT_DIR}/run_cycle.sh"
TEMPLATE="${SCRIPT_DIR}/com.corpus.localsiem.plist.template"
APP_HOME="${HOME}/Library/Application Support/CorpusLocalSIEM"
LAUNCH_AGENTS_DIR="${HOME}/Library/LaunchAgents"
PLIST_PATH="${LAUNCH_AGENTS_DIR}/com.corpus.localsiem.plist"
USER_DOMAIN="gui/$(id -u)"

mkdir -p "${APP_HOME}" "${LAUNCH_AGENTS_DIR}"

if [[ ! -x "${RUNNER}" ]]; then
  chmod +x "${RUNNER}"
fi

sed \
  -e "s#__RUNNER__#${RUNNER//\//\\/}#g" \
  -e "s#__APP_HOME__#${APP_HOME//\//\\/}#g" \
  "${TEMPLATE}" > "${PLIST_PATH}"

launchctl bootout "${USER_DOMAIN}" "${PLIST_PATH}" >/dev/null 2>&1 || true
launchctl bootstrap "${USER_DOMAIN}" "${PLIST_PATH}"
launchctl enable "${USER_DOMAIN}/com.corpus.localsiem"
launchctl kickstart -k "${USER_DOMAIN}/com.corpus.localsiem"

echo "Installed launch agent: ${PLIST_PATH}"
echo "Status:"
launchctl print "${USER_DOMAIN}/com.corpus.localsiem" | sed -n '1,20p'
