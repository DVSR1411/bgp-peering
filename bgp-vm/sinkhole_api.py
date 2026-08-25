#!/usr/bin/env python3
"""
BGP Sinkhole Manager
====================
Flask app with UI to manage sinkholed prefixes and view BGP status.

Features:
    - View BGP peering status (Established / Active / Down)
    - Add malicious prefixes (auto-propagates to ISP via eBGP)
    - View all active sinkholed prefixes
    - Remove individual prefixes
    - Flush all prefixes at once

Usage:
    sudo pip3 install flask
    sudo python3 sinkhole_api.py

    Open: http://<BGP_PUBLIC_IP>:5000
"""

import subprocess
import re
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

SINKHOLE_IP = "<SINKHOLE_PRIVATE_IP>"  # Replace with actual sinkhole IP (e.g., 172.31.34.1)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>BGP Sinkhole Manager</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #e6edf3;
            min-height: 100vh;
            padding: 30px 20px;
        }
        .container { max-width: 900px; margin: 0 auto; }
        header { margin-bottom: 30px; }
        header h1 { color: #ff6b6b; font-size: 24px; }
        header p { color: #555; font-size: 12px; margin-top: 4px; }

        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px; }
        @media (max-width: 700px) { .grid { grid-template-columns: 1fr; } }

        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
        }
        .card-full { grid-column: 1 / -1; }
        .card-title {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #888;
            margin-bottom: 12px;
        }

        /* Peering status */
        .peer-status { display: flex; align-items: center; gap: 12px; }
        .peer-dot {
            width: 12px; height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        .peer-dot.up { background: #2ecc71; }
        .peer-dot.down { background: #e74c3c; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
        .peer-info { font-size: 13px; }
        .peer-info .label { color: #888; }
        .peer-detail {
            margin-top: 12px;
            background: #0d1117;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 11px;
            color: #8b949e;
            white-space: pre-wrap;
            max-height: 150px;
            overflow-y: auto;
        }

        /* Add form */
        .form-row { display: flex; gap: 8px; }
        input[type="text"] {
            flex: 1;
            padding: 10px 14px;
            border: 1px solid #30363d;
            border-radius: 6px;
            background: #0d1117;
            color: #e6edf3;
            font-size: 13px;
            font-family: monospace;
        }
        input[type="text"]:focus { outline: none; border-color: #ff6b6b; }
        input::placeholder { color: #3d444d; }

        .btn {
            padding: 10px 18px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.15s;
        }
        .btn-add { background: #238636; color: #fff; }
        .btn-add:hover { background: #2ea043; }
        .btn-rm { background: #21262d; color: #f85149; border: 1px solid #30363d; padding: 5px 10px; font-size: 11px; }
        .btn-rm:hover { background: #f8514922; border-color: #f85149; }
        .btn-flush { background: #da3633; color: #fff; width: 100%; margin-top: 8px; }
        .btn-flush:hover { background: #f85149; }
        .btn-refresh { background: #21262d; color: #8b949e; border: 1px solid #30363d; padding: 6px 12px; font-size: 11px; }
        .btn-refresh:hover { background: #30363d; }

        /* Prefix list */
        .prefix-table { width: 100%; margin-top: 10px; }
        .prefix-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
            font-family: monospace;
            font-size: 13px;
        }
        .prefix-row:last-child { border-bottom: none; }
        .prefix-row .left { display: flex; align-items: center; gap: 10px; }
        .prefix-row .dot { width: 6px; height: 6px; background: #2ecc71; border-radius: 50%; }

        .empty { color: #3d444d; text-align: center; padding: 25px; font-size: 13px; }
        .count { color: #555; font-size: 11px; margin-top: 8px; }

        .alert {
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 12px;
            font-size: 12px;
            display: none;
        }
        .alert-ok { background: #0f291a; border: 1px solid #238636; color: #3fb950; }
        .alert-err { background: #2d1115; border: 1px solid #da3633; color: #f85149; }

        .actions-row { display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>BGP Sinkhole Manager</h1>
            <p>Manage malicious prefixes on bgp-vm (AS 65001). ISP (AS 65002) learns changes via eBGP.</p>
        </header>

        <div id="alert" class="alert"></div>

        <div class="grid">
            <!-- BGP Peering Status -->
            <div class="card">
                <div class="card-title">BGP Peering Status</div>
                <div class="peer-status">
                    <div id="peer-dot" class="peer-dot down"></div>
                    <div class="peer-info">
                        <div id="peer-state">Checking...</div>
                        <div class="label" id="peer-neighbor"></div>
                    </div>
                </div>
                <div>
                    <button class="btn btn-refresh" onclick="loadStatus()" style="margin-top:12px;">Refresh</button>
                </div>
                <div id="peer-detail" class="peer-detail">Loading...</div>
            </div>

            <!-- Add Prefix -->
            <div class="card">
                <div class="card-title">Add Malicious Prefix</div>
                <div class="form-row">
                    <input type="text" id="prefix" placeholder="198.51.100.0/24"
                           onkeydown="if(event.key==='Enter')add()">
                    <button class="btn btn-add" onclick="add()">Add</button>
                </div>
                <p style="color:#3d444d;font-size:11px;margin-top:10px;">
                    Accepts any valid CIDR: /32 for single IP, /24 for a subnet, etc.
                </p>
                <button class="btn btn-flush" onclick="flushAll()">Flush All Prefixes</button>
            </div>
        </div>

        <!-- Prefix List -->
        <div class="card card-full">
            <div class="actions-row">
                <div class="card-title" style="margin-bottom:0;">Active Sinkholed Prefixes</div>
                <button class="btn btn-refresh" onclick="loadPrefixes()">Refresh</button>
            </div>
            <div id="prefix-list" class="prefix-table"><div class="empty">Loading...</div></div>
            <div id="count" class="count"></div>
        </div>
    </div>

    <script>
        function msg(text, type) {
            const el = document.getElementById('alert');
            el.className = 'alert alert-' + type;
            el.textContent = text;
            el.style.display = 'block';
            setTimeout(() => el.style.display = 'none', 4000);
        }

        async function add() {
            const inp = document.getElementById('prefix');
            const prefix = inp.value.trim();
            if (!prefix) return;
            const r = await fetch('/api/prefix', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({prefix})
            });
            const d = await r.json();
            if (d.success) { msg('Added ' + prefix + ' to sinkhole', 'ok'); inp.value = ''; loadPrefixes(); }
            else msg(d.error, 'err');
        }

        async function remove(prefix) {
            const r = await fetch('/api/prefix', {
                method: 'DELETE',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({prefix})
            });
            const d = await r.json();
            if (d.success) { msg('Removed ' + prefix, 'ok'); loadPrefixes(); }
            else msg(d.error, 'err');
        }

        async function flushAll() {
            if (!confirm('Remove ALL sinkholed prefixes? ISP will withdraw all routes.')) return;
            const r = await fetch('/api/flush', {method: 'POST'});
            const d = await r.json();
            if (d.success) { msg('Flushed ' + d.removed + ' prefix(es)', 'ok'); loadPrefixes(); }
            else msg(d.error, 'err');
        }

        async function loadPrefixes() {
            const r = await fetch('/api/prefixes');
            const d = await r.json();
            const el = document.getElementById('prefix-list');
            const cnt = document.getElementById('count');

            if (d.prefixes.length === 0) {
                el.innerHTML = '<div class="empty">No prefixes sinkholed. Add one above.</div>';
                cnt.textContent = '';
                return;
            }
            el.innerHTML = d.prefixes.map(p =>
                '<div class="prefix-row">' +
                '<div class="left"><div class="dot"></div><span>' + p.prefix + '</span></div>' +
                '<button class="btn btn-rm" onclick="remove(\\'' + p.prefix + '\\')">Remove</button>' +
                '</div>'
            ).join('');
            cnt.textContent = d.prefixes.length + ' prefix(es) sinkholed';
        }

        async function loadStatus() {
            const r = await fetch('/api/status');
            const d = await r.json();
            const dot = document.getElementById('peer-dot');
            const state = document.getElementById('peer-state');
            const neighbor = document.getElementById('peer-neighbor');
            const detail = document.getElementById('peer-detail');

            dot.className = 'peer-dot ' + (d.established ? 'up' : 'down');
            state.textContent = d.established ? 'Established' : 'Down / Active';
            neighbor.textContent = d.neighbor ? 'Peer: ' + d.neighbor + ' (AS ' + d.remote_as + ')' : '';
            detail.textContent = d.raw;
        }

        loadPrefixes();
        loadStatus();
        setInterval(loadStatus, 15000);
    </script>
</body>
</html>
"""


def vtysh(commands):
    """Run vtysh commands."""
    args = []
    for c in commands:
        args.extend(["-c", c])
    try:
        r = subprocess.run(["vtysh"] + args, capture_output=True, text=True, timeout=10)
        return r.stdout + r.stderr
    except Exception as e:
        return f"Error: {e}"


def get_prefixes():
    """Get currently sinkholed prefixes."""
    output = vtysh(["show running-config"])
    results = []
    for m in re.finditer(r"ip prefix-list MALICIOUS seq (\d+) permit (.+)", output):
        results.append({"seq": m.group(1), "prefix": m.group(2)})
    return results


def validate(prefix):
    """Validate CIDR notation."""
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", prefix):
        return False
    ip, mask = prefix.split("/")
    if int(mask) > 32:
        return False
    for o in ip.split("."):
        if int(o) > 255:
            return False
    return True


def next_seq():
    """Get next seq number."""
    prefixes = get_prefixes()
    if prefixes:
        return max(int(p["seq"]) for p in prefixes) + 10
    return 10


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/prefixes")
def api_list():
    return jsonify({"prefixes": get_prefixes()})


@app.route("/api/prefix", methods=["POST"])
def api_add():
    prefix = request.get_json().get("prefix", "").strip()
    if not validate(prefix):
        return jsonify({"success": False, "error": "Invalid CIDR format (e.g., 192.168.1.0/24)"})

    for p in get_prefixes():
        if p["prefix"] == prefix:
            return jsonify({"success": False, "error": f"{prefix} already sinkholed"})

    seq = next_seq()
    vtysh([
        "configure terminal",
        f"ip prefix-list MALICIOUS seq {seq} permit {prefix}",
        f"ip route {prefix} {SINKHOLE_IP}",
        "router bgp 65001",
        "address-family ipv4 unicast",
        f"network {prefix}",
        "end",
        "clear bgp * out",
        "write memory"
    ])
    return jsonify({"success": True})


@app.route("/api/prefix", methods=["DELETE"])
def api_remove():
    prefix = request.get_json().get("prefix", "").strip()
    seq = None
    for p in get_prefixes():
        if p["prefix"] == prefix:
            seq = p["seq"]
            break
    if not seq:
        return jsonify({"success": False, "error": "Prefix not found"})

    vtysh([
        "configure terminal",
        f"no ip prefix-list MALICIOUS seq {seq}",
        f"no ip route {prefix} {SINKHOLE_IP}",
        "router bgp 65001",
        "address-family ipv4 unicast",
        f"no network {prefix}",
        "end",
        "clear bgp * out",
        "write memory"
    ])
    return jsonify({"success": True})


@app.route("/api/flush", methods=["POST"])
def api_flush():
    prefixes = get_prefixes()
    if not prefixes:
        return jsonify({"success": True, "removed": 0})

    commands = ["configure terminal"]
    for p in prefixes:
        commands.append(f"no ip prefix-list MALICIOUS seq {p['seq']}")
        commands.append(f"no ip route {p['prefix']} {SINKHOLE_IP}")

    commands.append("router bgp 65001")
    commands.append("address-family ipv4 unicast")
    for p in prefixes:
        commands.append(f"no network {p['prefix']}")
    commands.extend(["end", "clear bgp * out", "write memory"])

    vtysh(commands)
    return jsonify({"success": True, "removed": len(prefixes)})


@app.route("/api/status")
def api_status():
    raw = vtysh(["show bgp summary"])
    established = False
    neighbor = None
    remote_as = None

    for line in raw.split("\n"):
        parts = line.split()
        if len(parts) >= 10 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
            neighbor = parts[0]
            remote_as = parts[2]
            # If State/PfxRcd is a number, session is established
            try:
                int(parts[9])
                established = True
            except (ValueError, IndexError):
                established = False

    return jsonify({
        "established": established,
        "neighbor": neighbor,
        "remote_as": remote_as,
        "raw": raw.strip()
    })


if __name__ == "__main__":
    print()
    print("  BGP Sinkhole Manager")
    print(f"  Sinkhole IP: {SINKHOLE_IP}")
    print(f"  Open http://<BGP_PUBLIC_IP>:5000")
    print()
    app.run(host="0.0.0.0", port=5000)
