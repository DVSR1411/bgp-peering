#!/bin/bash
# BGP-driven SNAT policy for isp-vm.
#
# Single source of truth = the kernel routing table, which BGP populates.
# Any prefix whose next-hop is the SINKHOLE is "malicious" and must NOT be
# SNAT'd (so the sinkhole sees the real source, i.e. the NAT instance IP).
# Everything else bound for the internet IS SNAT'd to isp-vm's IP so the IGW
# can translate it and normal internet works.
#
# No malicious prefix is hardcoded. This script reads the live routes via the
# sinkhole next-hop and programs an nftables set accordingly. Re-run it (or let
# the systemd path/timer below run it) whenever BGP routes change; adds/removes
# are picked up automatically.

set -euo pipefail

SINKHOLE_NH="172.31.19.2"
VPC_CIDR="172.31.0.0/16"
WAN_IF="ens5"

# Collect all prefixes the kernel currently routes to the sinkhole (BGP-learned).
mapfile -t SINK_PREFIXES < <(ip route show | awk -v nh="$SINKHOLE_NH" '$0 ~ ("via " nh) {print $1}')

# (Re)build the nftables table.
nft delete table ip ispnat 2>/dev/null || true
nft add table ip ispnat

# A named set holding the sinkhole-bound (malicious) prefixes.
nft add set ip ispnat sinkhole_nets '{ type ipv4_addr ; flags interval ; }'

# Populate the set from the live routing table (empty is fine).
if [ "${#SINK_PREFIXES[@]}" -gt 0 ]; then
  elems=$(IFS=,; echo "${SINK_PREFIXES[*]}")
  nft add element ip ispnat sinkhole_nets "{ $elems }"
fi

nft add chain ip ispnat post '{ type nat hook postrouting priority srcnat ; policy accept ; }'

# 1. Never SNAT intra-VPC traffic.
nft add rule ip ispnat post oifname "$WAN_IF" ip daddr "$VPC_CIDR" return
# 2. Never SNAT sinkhole-bound (malicious) traffic -> preserve source for capture.
nft add rule ip ispnat post oifname "$WAN_IF" ip daddr @sinkhole_nets return
# 3. MASQUERADE everything else (genuine internet) to isp-vm's IP.
nft add rule ip ispnat post oifname "$WAN_IF" masquerade

echo "Programmed sinkhole_nets with ${#SINK_PREFIXES[@]} prefix(es): ${SINK_PREFIXES[*]:-<none>}"
