"""
Pivot route management: add or remove routes through veth1.

POST /pivot-setup  {"subnets": ["192.168.10.0/24", "10.10.5.0/24"]}
POST /pivot-reset  {"subnets": [...]}   # omit or pass [] to reset all
"""

import os
import re
import subprocess

from flask import jsonify, request

VETH_OUT  = "veth1"
CONFIG_FILE = "/opt/implant/config.env"
PIVOT_NFT = "/opt/implant/scripts/pivot-nft.sh"
PIVOT_CONNTRACK = "/opt/implant/scripts/pivot-conntrack.sh"
SPOOF_LOG = "/opt/implant/logs/spoof-target/spoof-target.log"

_CIDR_RE = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
)


def _run(cmd):
    r = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _veth_ready():
    rc, _, _ = _run(f"ip link show {VETH_OUT} 2>/dev/null")
    return rc == 0


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


def _script_backend_ready():
    rc, out, _ = _run(f"{_pivot_script()} status 2>/dev/null")
    if rc != 0:
        return False
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


def _get_gateway():
    """Read gateway from the last applied spoof-target log entry."""
    if not os.path.isfile(SPOOF_LOG):
        return None
    try:
        with open(SPOOF_LOG) as fh:
            content = fh.read()
    except OSError:
        return None
    blocks = re.split(r"--- Log Entry:[^\n]*---", content)
    last = next((b.strip() for b in reversed(blocks) if b.strip()), "")
    for line in last.splitlines():
        if line.strip().startswith("Detected Gateway:"):
            val = line.split(":", 1)[1].strip()
            if val and val != "Not set":
                return val
    return None


def _existing_routes():
    rc, out, _ = _run(f"ip route show dev {VETH_OUT} 2>/dev/null")
    subnets = set()
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if parts:
                subnets.add(parts[0])
    return subnets


def register(app):

    @app.route("/pivot-setup", methods=["POST"])
    def pivot_setup():
        backend = _backend()
        if backend in ("nft-stateful", "conntrack-bridge", "conntrack-mark"):
            if not _script_backend_ready():
                return jsonify({"error": f"pivot not ready: {backend} backend is not applied"}), 409
        elif not _veth_ready():
            return jsonify({"error": "pivot not ready: veth1 does not exist"}), 409

        body = request.get_json(silent=True) or {}
        subnets = [s for s in body.get("subnets", []) if _CIDR_RE.match(s)]
        if not subnets:
            return jsonify({"error": "no valid subnets provided"}), 400

        if backend in ("nft-stateful", "conntrack-bridge", "conntrack-mark"):
            configured, failed = [], []
            for subnet in subnets:
                rc, _, err = _run(f"{_pivot_script()} route-add {subnet}")
                if rc == 0:
                    configured.append(subnet)
                else:
                    failed.append({"subnet": subnet, "error": err})
            return jsonify({
                "backend":    backend,
                "configured": configured,
                "skipped":    [],
                "failed":     failed,
            })

        gateway = _get_gateway()
        if not gateway:
            return jsonify({
                "error": "gateway not found in spoof-target log; run spoof-target.sh with --gateway first"
            }), 409

        existing = _existing_routes()
        configured, skipped, failed = [], [], []

        for subnet in subnets:
            if subnet in existing:
                skipped.append(subnet)
                continue
            rc, _, err = _run(
                f"ip route add {subnet} via {gateway} dev {VETH_OUT}"
            )
            if rc == 0:
                configured.append(subnet)
            else:
                failed.append({"subnet": subnet, "error": err})

        return jsonify({
            "backend":    backend,
            "gateway":    gateway,
            "configured": configured,
            "skipped":    skipped,
            "failed":     failed,
        })

    @app.route("/pivot-reset", methods=["POST"])
    def pivot_reset():
        backend = _backend()
        body = request.get_json(silent=True) or {}
        subnets = [s for s in body.get("subnets", []) if _CIDR_RE.match(s)]

        removed, failed = [], []

        if backend in ("nft-stateful", "conntrack-bridge", "conntrack-mark"):
            if not subnets:
                rc, _, err = _run(f"{_pivot_script()} route-flush")
                if rc == 0:
                    return jsonify({"backend": backend, "removed": "all", "failed": []})
                return jsonify({"backend": backend, "removed": [], "failed": [{"subnet": "all", "error": err}]})
            for subnet in subnets:
                rc, _, err = _run(f"{_pivot_script()} route-del {subnet}")
                if rc == 0:
                    removed.append(subnet)
                else:
                    failed.append({"subnet": subnet, "error": err})
            return jsonify({"backend": backend, "removed": removed, "failed": failed})

        if not subnets:
            # Flush all routes on veth1
            rc, _, err = _run(f"ip route flush dev {VETH_OUT} 2>/dev/null")
            if rc == 0:
                return jsonify({"removed": "all", "failed": []})
            return jsonify({"removed": [], "failed": [{"subnet": "all", "error": err}]})

        for subnet in subnets:
            rc, _, err = _run(f"ip route del {subnet} 2>/dev/null")
            if rc == 0:
                removed.append(subnet)
            else:
                failed.append({"subnet": subnet, "error": err})

        return jsonify({"removed": removed, "failed": failed})
