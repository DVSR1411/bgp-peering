#!/bin/bash
# Install the BGP-driven SNAT policy on isp-vm as a systemd service + timer,
# and remove the older static iptables MASQUERADE rules from earlier attempts.
set -euo pipefail

# --- Remove earlier iptables NAT rules we experimented with ---
sudo iptables -t nat -D POSTROUTING -o ens5 ! -d 172.31.0.0/16 -j MASQUERADE 2>/dev/null || true
for P in 198.51.100.0/24 203.0.113.0/24 192.0.2.0/24; do
  sudo iptables -t nat -D POSTROUTING -o ens5 -d "$P" -j RETURN 2>/dev/null || true
done
sudo iptables -t nat -D POSTROUTING -o ens5 -d 172.31.0.0/16 -j RETURN 2>/dev/null || true
sudo iptables -t nat -D POSTROUTING -o ens5 -j MASQUERADE 2>/dev/null || true

# --- Install the policy script ---
sudo install -m 0755 /tmp/nat-sinkhole-aware.sh /usr/local/sbin/nat-sinkhole-aware.sh

# --- systemd service (oneshot) ---
sudo tee /etc/systemd/system/nat-sinkhole.service > /dev/null << 'UNIT'
[Unit]
Description=BGP-driven SNAT policy (exclude sinkhole-bound traffic from MASQUERADE)
After=frr.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nat-sinkhole-aware.sh
RemainAfterExit=yes
UNIT

# --- systemd timer: re-sync with BGP routes every 30s ---
sudo tee /etc/systemd/system/nat-sinkhole.timer > /dev/null << 'UNIT'
[Unit]
Description=Periodically re-sync BGP-driven SNAT policy

[Timer]
OnBootSec=15
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now nat-sinkhole.service
sudo systemctl enable --now nat-sinkhole.timer

echo "=== service status ==="
sudo systemctl --no-pager --lines=0 status nat-sinkhole.service | head -5
echo "=== current nft table ==="
sudo nft list table ip ispnat
