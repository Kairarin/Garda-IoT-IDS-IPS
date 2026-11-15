#!/usr/bin/env bash
# GARDA-IoT · membuat lingkungan uji (network namespace penguji + NAT).
# Jalankan di Raspberry Pi:  sudo ./deploy/scripts/setup_namespace.sh
# Aman dijalankan ulang; jalankan setiap Raspberry Pi selesai booting.
set -euo pipefail

ENV_FILE="${GARDA_ENV_FILE:-/etc/garda-iot/garda.env}"
[ -f "$ENV_FILE" ] && set -a && . "$ENV_FILE" && set +a

NS="ids-attacker"
HOST_VETH="veth-ids-host"
NS_VETH="veth-ids-ns"
HOST_IP="${GARDA_IDS_HOST_IP:-10.200.0.1}"
ATTACKER_IP="${GARDA_ATTACKER_IP:-10.200.0.2}"
LAN_IF="${GARDA_LAN_IF:-wlan0}"

if [ "$(id -u)" -ne 0 ]; then echo "Jalankan dengan sudo." >&2; exit 1; fi

ip netns list | grep -qw "$NS" || ip netns add "$NS"
if ! ip link show "$HOST_VETH" >/dev/null 2>&1; then
  ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
  ip link set "$NS_VETH" netns "$NS"
fi

ip addr replace "$HOST_IP/24" dev "$HOST_VETH"
ip link set "$HOST_VETH" up
ip netns exec "$NS" ip addr replace "$ATTACKER_IP/24" dev "$NS_VETH"
ip netns exec "$NS" ip link set "$NS_VETH" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route replace default via "$HOST_IP"

sysctl -qw net.ipv4.ip_forward=1

# NAT keluar lewat antarmuka LAN (postrouting, setelah chain forward milik IPS)
nft list table ip ids_nat >/dev/null 2>&1 || {
  nft add table ip ids_nat
  nft "add chain ip ids_nat postrouting { type nat hook postrouting priority srcnat; }"
  nft add rule ip ids_nat postrouting ip saddr "${ATTACKER_IP%.*}.0/24" oifname "$LAN_IF" masquerade
}

echo "[OK] Namespace $NS siap: penguji $ATTACKER_IP -> host $HOST_IP -> $LAN_IF"
