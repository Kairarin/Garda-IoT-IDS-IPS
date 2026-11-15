#!/usr/bin/env bash
# GARDA-IoT · membuat token rahasia pengujian IDS (header X-IDS-Test-Token).
# Jalankan dari root repo:  ./deploy/scripts/create_test_token.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TOKEN_FILE="${GARDA_IDS_TOKEN_PATH:-$DIR/edge-server/.ids_test_token}"
python3 -c "import secrets; print(secrets.token_hex(32))" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
echo "[OK] Token dibuat: $TOKEN_FILE (jangan di-commit)"
