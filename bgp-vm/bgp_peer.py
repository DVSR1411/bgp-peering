#!/usr/bin/env python3
"""
BGP Sinkhole Manager
====================
Flask app with UI to add, remove, or flush all malicious prefixes on bgp-vm.
Changes propagate to isp-vm automatically via eBGP.

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
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #e94560; font-size: 26px; margin-bottom: 5px; }
        .subtitle { color: #666; font-size: 13px; margin-bottom: 30px; }

        .card {
            background: #16213e;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid #0f3460;
        }
        .card-title {
            color: #e94560;
            font-size: 15px;
            font-weight: 600;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .form-row { display: flex; gap: 10px; }
        input[type="text"] {
            flex: 1;
            padding: 12px 16px;
            border: 1px solid #0f3460;
            border-radius: 6px;
            background: #1a1a2e;
            color: #eee;
            font-size: 14px;
            font-family: monospace;
        }
        input[type="text"]:focus { outline: none; border-color: #e94560; }
        input[type="text"]::placeholder { color: #444; }

        .btn {
            padding: 12px 22px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .btn-add { background: #e94560; color: white; }
        .btn-add:hover { background: #ff6b81; }
        .btn-del { background: #c0392b; color: white; padding: 6px 14px; font-size: 11px; }
        .btn-del:hover { background: #e74c3c; }
        .btn-flush { background: #e74c3c; color: white; width: 100%; margin-top: 10px; }
        .btn-flush:hover { background: #ff6b6b; }

        .prefix-list { margin-top: 10px; }
        .prefix-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 15px;
            background: #1a1a2e;
            border-radius: 6px;
            margin-bottom: 8px;
            border: 1px solid #0f3460;
            font-family: monospace;
            font-size: 13px;
        }
        .prefix-item .dot {
            width: 8px; height: 8px;
            background: #2ecc71;
            border-radius: 50%;
            margin-right: 12px;
        }
        .prefix-item .info { display: flex; align-items: center; }

        .alert {
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-size: 13px;
            display: none;
        }
        .alert-ok { background: #1e4620; border: 1px solid #2ecc71; color: #2ecc71; }
        .alert-err { background: #4a1c1c; border: 1px solid #e74c3c; color: #e74c3c; }

        .empty { color: #444; text-align: center; padding: 30px; font-size: 13px; }
        .count { color: #666; font-size: 12px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BGP Sinkhole Manager</h1>
        <p class="subtitle">Add or remove malicious prefixes. ISP learns changes automatically via eBGP.</p>

        <div id="alert" class="alert"></div>

        <!-- ADD -->
        <div class="card">
            <div class="card-title">Add Prefix</div>
            <div class="form-row">
                <input type="text" id="prefix" placeholder="e.g. 198.51.100.0/24 or 10.0.0.1/32"
                       onkeydown="if(event.key==='Enter')add()">
                <button class="btn btn-add" onclick="add()">Add</button>
            </div>
        </div>

        <!-- LIST -->
        <div class="card">
            <div class="card-title">Active Prefixes</div>
            <div id="list" class="prefix-list"><div class="empty">Loading...</div></div>
            <div id="count" class="count"></div>
        </div>

        <!-- FLUSH -->
        <div class="card">
            <div class="card-title">Flush All</div>
            <p style="color:#888;font-size:13px;margin-bottom:10px;">Remove ALL sinkholed prefixes at once. ISP will withdraw all routes.</p>
            <button class="btn btn-flush" onclick="flushAll()">Flush All Prefixes</button>
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
            if (d.success) { msg('Added ' + prefix, 'ok'); inp.value = ''; load(); }
            else msg(d.error, 'err');
        }

        async function remove(prefix) {
            const r = await fetch('/api/prefix', {
                method: 'DELETE',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({prefix})
            });
            const d = await r.json();
            if (d.success) { msg('Removed ' + prefix, 'ok'); load(); }
            else msg(d.error, 'err');
        }

        async function flushAll() {
            if (!confirm('Remove ALL sinkholed prefixes?')) return;
            const r = await fetch('/api/flush', {method: 'POST'});
            const d = await r.json();
            if (d.success) { msg('Flushed ' + d.removed + ' prefixes', 'ok'); load(); }
            else msg(d.error, 'err');
        }

        async function load() {
            const r = await fetch('/api/prefixes');
            const d = await r.json();
            const el = document.getElementById('list');
            const cnt = document.getElementById('count');

            if (d.prefixes.length === 0) {
                el.innerHTML = '<div class="empty">No prefixes sinkholed</div>';
                cnt.textContent = '';
                return;
            }
            el.innerHTML = d.prefixes.map(p =>
                '<div class="prefix-item">' +
                '<div class="info"><div class="dot"></div>' + p.prefix + '</div>' +
                '<button class="btn btn-del" onclick="remove(\\'' + p.prefix + '\\')">Remove</button>' +
                '</div>'
            ).join('');
            cnt.textContent = d.prefixes.length + ' prefix(es) active';
        }

        load();
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
        return jsonify({"success": False, "error": "Invalid CIDR (e.g., 192.168.1.0/24)"})

    for p in get_prefixes():
        if p["prefix"] == prefix:
            return jsonify({"success": False, "error": f"{prefix} already exists"})

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


if __name__ == "__main__":
    print()
    print("  BGP Sinkhole Manager")
    print(f"  Sinkhole IP: {SINKHOLE_IP}")
    print(f"  Open http://<BGP_PUBLIC_IP>:5000")
    print()
    app.run(host="0.0.0.0", port=5000)
