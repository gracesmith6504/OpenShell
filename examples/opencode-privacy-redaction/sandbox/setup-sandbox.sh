#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Create an OpenShell sandbox running opencode, wired to inference.local and the
# host-side local-model MCP, then start the opencode web UI and expose it.
#
# Prereqs (on the host):
#   - An OpenShell gateway is registered and selected (openshell gateway list).
#   - The redaction proxy (:8000) and MCP (:8001) are running: see ../proxy.
#   - inference is routed to the proxy (see README "One-time gateway wiring").
set -euo pipefail

SANDBOX_NAME="${SANDBOX_NAME:-opencode}"
WEB_PORT="${WEB_PORT:-9119}"
SERVICE_NAME="${SERVICE_NAME:-web}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY="$HERE/../policies/opencode-policy.yaml"
CONFIG="$HERE/opencode.json"
PROVISION="$HERE/opencode-provision.sh"
SSH_CONFIG="/tmp/${SANDBOX_NAME}-ssh-config"

echo "== creating sandbox '$SANDBOX_NAME' =="
openshell sandbox create --name "$SANDBOX_NAME" --policy "$POLICY" --no-tty -- echo sandbox-ready

echo "== fetching ssh config =="
openshell sandbox ssh-config "$SANDBOX_NAME" > "$SSH_CONFIG"
SSH=(ssh -F "$SSH_CONFIG" "openshell-${SANDBOX_NAME}")

echo "== provisioning opencode config =="
"${SSH[@]}" 'cat > /tmp/opencode-provision.sh' < "$PROVISION"
"${SSH[@]}" 'cat > /tmp/opencode.json' < "$CONFIG"
"${SSH[@]}" 'sh /tmp/opencode-provision.sh < /tmp/opencode.json'

echo "== starting opencode web on 127.0.0.1:${WEB_PORT} (inside sandbox) =="
# setsid+nohup so the server survives the ssh session. Logs to /sandbox/web.log.
# NB: do not pkill by "opencode web" from a one-liner whose text contains that
# string - pkill -f would match its own shell. Kill by port/PID instead.
"${SSH[@]}" "export HOME=/sandbox; cd /sandbox/workspace; rm -f /sandbox/web.log; \
  setsid nohup opencode web --hostname 127.0.0.1 --port ${WEB_PORT} > /sandbox/web.log 2>&1 < /dev/null & echo launched"
sleep 6
"${SSH[@]}" "curl -s -m 6 -o /dev/null -w 'sandbox web / = HTTP %{http_code}\n' http://127.0.0.1:${WEB_PORT}/" || true

echo "== exposing web service via the gateway =="
EXPOSE_OUT="$(openshell service expose "$SANDBOX_NAME" "$WEB_PORT" "$SERVICE_NAME" 2>&1)"
echo "$EXPOSE_OUT"

# Pull the exposed URL out of the command output (grep stops at the ANSI reset).
URL="$(printf '%s\n' "$EXPOSE_OUT" | grep -oE 'https?://[A-Za-z0-9.:/_-]+' | head -1)"

echo
if [ -n "$URL" ]; then
  echo "Opening $URL"
  if command -v open >/dev/null 2>&1; then
    open "$URL"            # macOS
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &   # Linux
  else
    echo "(could not auto-open a browser - open the URL above manually)"
  fi
else
  echo "Done. Open the URL printed above."
fi

echo
echo "Verify the wiring:"
echo "  ${SSH[*]} 'export HOME=/sandbox; cd /sandbox/workspace; opencode run --model inference-local/openai/openai/gpt-5.5 \"say hi\"'"
