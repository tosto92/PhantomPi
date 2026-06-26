"""
Pivot status endpoint: returns pivot readiness, spoofed identity from the
spoof-target log, current routes on veth1, and suggested subnets from the
traffic-analyzer pre-computed cache (subnet-suggestions.json).
"""

import json
import os
import re
import subprocess

from flask import jsonify

VETH_IN      = "veth0"
VETH_OUT     = "veth1"
CONFIG_FILE  = "/opt/implant/config.env"
PIVOT_NFT    = "/opt/implant/scripts/pivot-nft.sh"
PIVOT_CONNTRACK = "/opt/implant/scripts/pivot-conntrack.sh"
SPOOF_LOG    = "/opt/implant/logs/spoof-target/spoof-target.log"
SUBNETS_FILE = "/opt/implant/logs/traffic-analyzer/subnet-suggestions.json"


def _run(cmd):
    try:
        return subprocess.check_output(
            cmd, shell=True, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return ""


def _iface_exists(name):
    return _run(f"ip link show {name} 2>/dev/null") != ""


def _config_value(name, default=""):
    if not os.path.isfile(CONFIG_FILE):
        return default
    try:
        with open(CONFIG_FILE) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(f"{name}="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        return default
    return default


def _backend():
    return _config_value("PIVOT_BACKEND", "legacy-spoof")


def _pivot_script():
    return PIVOT_CONNTRACK if _backend() in ("conntrack-bridge", "conntrack-mark") else PIVOT_NFT


def _parse_spoof_log():
    """Return the last successfully applied entry from spoof-target.log."""
    if not os.path.isfile(SPOOF_LOG):
        return {}
    try:
        with open(SPOOF_LOG) as fh:
            content = fh.read()
    except OSError:
        return {}

    # Split on entry headers; take last non-empty block
    blocks = re.split(r"--- Log Entry:[^\n]*---", content)
    last = next((b.strip() for b in reversed(blocks) if b.strip()), "")
    if not last:
        return {}

    # Only return entries where settings were actually applied
    if "Settings applied successfully" not in last:
        return {}

    mapping = {
        "Spoofed IP":       "ip",
        "Spoofed MAC":      "mac",
        "Spoofed Hostname": "hostname",
        "Detected Gateway": "gateway",
        "Detected DNS":     "dns",
    }
    result = {}
    for line in last.splitlines():
        for label, key in mapping.items():
            if line.strip().startswith(f"{label}:"):
                val = line.split(":", 1)[1].strip()
                if val and val != "Not set":
                    result[key] = val
    return result


def _current_routes():
    if _backend() in ("nft-stateful", "conntrack-bridge"):
        out = _run(f"{_pivot_script()} status 2>/dev/null")
        routes = []
        for line in out.splitlines():
            if line and "=" not in line:
                routes.append(line.strip())
        return routes
    out = _run(f"ip route show dev {VETH_OUT} 2>/dev/null")
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def _script_backend_ready():
    out = _run(f"{_pivot_script()} status 2>/dev/null")
    values = {}
    for line in out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return (
        (
            values.get("namespace_ready") == "yes"
            and values.get("bridge_peer_ready") == "yes"
            and values.get("nft_ready") == "yes"
        )
        or (
            values.get("bridge_ip_ready") == "yes"
            and values.get("iptables_ready") == "yes"
            and values.get("ebtables_ready") == "yes"
            and values.get("br_netfilter_ready") == "yes"
            and (_backend() != "conntrack-mark" or values.get("mark_ready") == "yes")
        )
    )


def _suggest_subnets():
    """
    Read pre-computed subnet suggestions written by traffic-analyzer.
    Returns instantly -- no PCAP processing at query time.
    """
    if not os.path.isfile(SUBNETS_FILE):
        return []
    try:
        with open(SUBNETS_FILE) as fh:
            data = json.load(fh)
        return data.get("suggestions", [])
    except (json.JSONDecodeError, OSError):
        return []


def register(app):
    @app.route("/pivot-status", methods=["GET"])
    def pivot_status():
        backend = _backend()
        pivot_ready = _script_backend_ready() if backend in ("nft-stateful", "conntrack-bridge", "conntrack-mark") else (
            _iface_exists(VETH_IN) and _iface_exists(VETH_OUT)
        )
        return jsonify({
            "backend":           backend,
            "pivot_ready":       pivot_ready,
            "spoofed":           _parse_spoof_log(),
            "current_routes":    _current_routes(),
            "suggested_subnets": _suggest_subnets() if pivot_ready else [],
        })
