#!/bin/bash
# Configure this instance as a NAT instance.
# Backend VMs (in a subnet routed through this instance) will have their
# source IP rewritten to this instance's private IP (MASQUERADE), so the
# sinkhole sees a single fixed source IP for all backend VMs.

set -e

# 1. Enable IP forwarding (persist)
sudo sysctl -w net.ipv4.ip_forward=1
if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
  echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
fi

# 2. MASQUERADE all forwarded traffic out ens5.
#    This rewrites the source of any traffic this box forwards to its own
#    ens5 IP (172.31.33.117), covering every backend VM and every
#    malicious prefix automatically - no per-prefix maintenance.
sudo iptables -t nat -C POSTROUTING -o ens5 -j MASQUERADE 2>/dev/null || \
  sudo iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE

# 3. Allow forwarding through the box
sudo iptables -C FORWARD -i ens5 -o ens5 -j ACCEPT 2>/dev/null || \
  sudo iptables -A FORWARD -i ens5 -o ens5 -j ACCEPT

# 4. Persist iptables rules across reboot
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
sudo netfilter-persistent save

echo "=== ip_forward ==="
sudo sysctl net.ipv4.ip_forward
echo "=== nat POSTROUTING ==="
sudo iptables -t nat -L POSTROUTING -n -v
echo "=== FORWARD ==="
sudo iptables -L FORWARD -n -v
echo "NAT_SETUP_DONE"
