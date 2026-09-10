#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required for the secret/log audit." >&2
  exit 2
fi

fail=0

report_matches() {
  local title="$1"
  local matches="$2"
  if [[ -n "$matches" ]]; then
    echo "[$title]" >&2
    echo "$matches" >&2
    fail=1
  fi
}

server_logging_matches="$(
  rg -n '\b(println!|eprintln!|dbg!)\b|\b(info!|debug!|warn!|error!|trace!)\s*!' server/src \
    | grep -v 'server/src/main.rs:.*info!(%addr, "server listening")' \
    || true
)"
report_matches "server raw logging must be reviewed before use" "$server_logging_matches"

android_log_matches="$(
  rg -n '\bLog\.(v|d|i|w|e|wtf)\b|HttpLoggingInterceptor' android/app/src/main/java \
    | grep -v 'android/app/src/main/java/com/enigma/securechat/network/SafeLog.kt:' \
    || true
)"
report_matches "android logging must go through SafeLog and must not use HttpLoggingInterceptor" "$android_log_matches"

safelog_sensitive_matches="$(
  rg -n 'SafeLog\.(info|warn)\([^)]*(Authorization|Bearer|accessToken|access_token|token|fcmToken|fcm_token|secret|downloadSecret|download_secret|ciphertext|presign|url)' android/app/src/main/java \
    | grep -v 'SafeLog.redactedId' \
    || true
)"
report_matches "SafeLog call contains sensitive-looking data without an explicit redaction helper" "$safelog_sensitive_matches"

ws_query_token_matches="$(
  rg -n '(/v1/ws[^[:space:]]*token=|token=[^[:space:]]*/v1/ws|v1/ws[^\n`"]*token)' server android docs scripts \
    --glob '!scripts/audit-secret-logs.sh' \
    || true
)"
report_matches "WebSocket authentication token must not be passed in query strings" "$ws_query_token_matches"

if [[ "$fail" -ne 0 ]]; then
  cat >&2 <<'EOF'
Secret/log audit failed.

Allowed patterns must be intentionally redacted or documented before adding a narrow exception.
EOF
  exit 1
fi

echo "Secret/log audit passed."
