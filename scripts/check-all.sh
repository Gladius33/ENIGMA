#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/scripts/audit-secret-logs.sh"
"$ROOT_DIR/scripts/check-server.sh"
"$ROOT_DIR/scripts/check-android.sh"
