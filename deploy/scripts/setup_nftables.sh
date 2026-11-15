#!/usr/bin/env bash
# GARDA-IoT · memuat table firewall IPS (inet ids_ips_auto).
# Jalankan di Raspberry Pi:  sudo ./deploy/scripts/setup_nftables.sh
set -euo pipefail

ENV_FILE="${GARDA_ENV_FILE:-/etc/garda-iot/garda.env}"
[ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a
: "${GARDA_ESP32_IP:?GARDA_ESP32_IP belum diatur di $ENV_FILE}"

DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$DIR/nftables/ids_ips_auto.nft.template"
OUT="/etc/garda-iot/ids_ips_auto.nft"

if [ "$(id -u)" -ne 0 ]; then echo "Jalankan dengan sudo." >&2; exit 1; fi
mkdir -p /etc/garda-iot

sed -e "s/__ESP32_IP__/${GARDA_ESP32_IP}/" \
    -e "s/__HOST_VETH__/${GARDA_HOST_VETH:-veth-ids-host}/" \
    -e "s/__LAN_IF__/${GARDA_LAN_IF:-wlan0}/" "$TEMPLATE" > "$OUT"

nft list table inet ids_ips_auto >/dev/null 2>&1 && nft delete table inet ids_ips_auto
nft -f "$OUT"
echo "[OK] Table inet ids_ips_auto dimuat dari $OUT"
nft list table inet ids_ips_auto
