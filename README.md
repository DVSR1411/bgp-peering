# BGP-Based IP Sinkholing Lab

## Overview

This lab demonstrates malicious-prefix redirection using real eBGP peering between two autonomous systems in AWS. When a client attempts to reach a known-malicious IP, the traffic is intercepted and redirected to a sinkhole server where the client's source IP is captured — proving the infection/compromise without the traffic ever reaching the real malicious destination.

## Architecture

```
                    eBGP (AS 65001 <-> AS 65002)
                    ┌─────────────────────────┐
                    │                         │
              ┌─────┴─────┐           ┌───────┴───────┐
              │  bgp-vm   │           │    isp-vm     │
              │ AS 65001  │           │   AS 65002    │
              │ (control  │           │ (data plane)  │
              │  plane)   │           │               │
              └───────────┘           └───────┬───────┘
                                              │
                    ┌─────────────────────────┬┘
                    │                         │
              ┌─────┴─────┐           ┌───────┴───────┐
              │  client   │           │  sinkhole-vm  │
              │           │──traffic──│  captures     │
              │           │           │  packets      │
              └───────────┘           └───────────────┘
```

### Traffic Flow

1. **Client** sends traffic to a malicious IP (e.g., 198.51.100.1)
2. **AWS route table** forwards all client traffic to isp-vm's ENI
3. **isp-vm** looks up the destination in its BGP-learned routing table
4. BGP route (learned from bgp-vm) says: `198.51.100.0/24 → next-hop <SINKHOLE_PRIVATE_IP>`
5. **isp-vm forwards** the packet directly to sinkhole-vm (same subnet, L2 delivery)
6. **Sinkhole captures** the packet with client's real source IP preserved

### Key Design Decision

Sinkhole-vm MUST be in the **same subnet** as isp-vm. This is because isp-vm forwards packets at L3 (IP forwarding), and the next-hop must be reachable at L2 (ARP). If they're in different subnets, the VPC gateway handles the forwarding but doesn't know about the BGP-learned routes.

## Placeholder Reference

Replace these placeholders throughout the guide with your actual values:

| Placeholder | Description | Example Value |
|-------------|-------------|---------------|
| `<BGP_PRIVATE_IP>` | bgp-vm private IP | 172.31.25.0 |
| `<BGP_PUBLIC_IP>` | bgp-vm public IP / EIP | 13.200.6.40 |
| `<ISP_PRIVATE_IP>` | isp-vm private IP | 172.31.32.26 |
| `<ISP_PUBLIC_IP>` | isp-vm public IP / EIP | 13.233.40.215 |
| `<SINKHOLE_PRIVATE_IP>` | sinkhole-vm private IP (same subnet as isp-vm) | 172.31.34.1 |
| `<SINKHOLE_PUBLIC_IP>` | sinkhole-vm public IP / EIP | 13.232.89.13 |
| `<CLIENT_PRIVATE_IP>` | client private IP | 172.31.3.154 |
| `<CLIENT_PUBLIC_IP>` | client public IP / EIP | 65.0.139.96 |
| `<ISP_SUBNET_GW>` | isp-vm subnet's VPC gateway (first IP + 1) | 172.31.32.1 |
| `<BGP_SUBNET_CIDR>` | bgp-vm subnet CIDR | 172.31.16.0/20 |
| `<ISP_SUBNET_CIDR>` | isp-vm subnet CIDR | 172.31.32.0/20 |
| `<CLIENT_SUBNET_CIDR>` | client subnet CIDR | 172.31.0.0/20 |
| `<VPC_CIDR>` | VPC CIDR | 172.31.0.0/16 |
| `<VPC_ID>` | VPC ID | vpc-07cd186540d79acb4 |
| `<ISP_INSTANCE_ID>` | isp-vm instance ID | i-015e76f76077f1694 |
| `<SINKHOLE_INSTANCE_ID>` | sinkhole-vm instance ID | i-0a6dc8a0d497eb93d |
| `<ISP_SG_ID>` | isp-vm security group ID | sg-0ec44438fe8c082ac |
| `<SINKHOLE_SG_ID>` | sinkhole-vm security group ID | sg-09a9c1fd7ba54705a |
| `<CLIENT_RT_ID>` | client subnet route table ID | rtb-01ee11b6c87af37bd |
| `<CLIENT_SUBNET_ID>` | client subnet ID | subnet-0be7e1310c576b594 |
| `<BGP_SUBNET_ID>` | bgp-vm subnet ID | subnet-0a2a68065d26aae04 |
| `<ISP_SUBNET_ID>` | isp-vm + sinkhole subnet ID | subnet-07e66f0d977d65690 |
| `<IGW_ID>` | Internet Gateway ID | igw-xxxxxxxx |
| `<BGP_RT_ID>` | bgp subnet route table ID | rtb-xxxxxxxx |
| `<ISP_RT_ID>` | isp subnet route table ID | rtb-xxxxxxxx |
| `<REGION>` | AWS region | ap-south-1 |

## Malicious Prefixes (RFC 5737 TEST-NET ranges)

| Prefix | Description |
|--------|-------------|
| 198.51.100.0/24 | TEST-NET-2 (safe, non-routable) |
| 203.0.113.0/24 | TEST-NET-3 (safe, non-routable) |
| 192.0.2.0/24 | TEST-NET-1 (safe, non-routable) |

---

## Step-by-Step Setup

### Step 0: VPC and Subnet Configuration

#### 0.1 VPC

Use an existing VPC or create one:
```bash
aws ec2 create-vpc --cidr-block 172.31.0.0/16 --region <REGION>
```

#### 0.2 Subnets

Create 3 subnets. **Critical:** isp-vm and sinkhole-vm MUST be in the **same subnet**.

```bash
# bgp-vm subnet
aws ec2 create-subnet --vpc-id <VPC_ID> --cidr-block <BGP_SUBNET_CIDR> --availability-zone <AZ1> --region <REGION>

# isp-vm + sinkhole-vm subnet (SAME subnet)
aws ec2 create-subnet --vpc-id <VPC_ID> --cidr-block <ISP_SUBNET_CIDR> --availability-zone <AZ2> --region <REGION>

# client subnet
aws ec2 create-subnet --vpc-id <VPC_ID> --cidr-block <CLIENT_SUBNET_CIDR> --availability-zone <AZ3> --region <REGION>
```

#### 0.3 Internet Gateway (for SSH access and isp-vm internet forwarding)

```bash
# Create and attach IGW
aws ec2 create-internet-gateway --region <REGION>
aws ec2 attach-internet-gateway --internet-gateway-id <IGW_ID> --vpc-id <VPC_ID> --region <REGION>
```

#### 0.4 Route Tables

You need **3 route tables**:

**bgp-vm subnet route table** — default internet access:
```bash
aws ec2 create-route-table --vpc-id <VPC_ID> --region <REGION>
# Add default route to IGW
aws ec2 create-route --route-table-id <BGP_RT_ID> --destination-cidr-block 0.0.0.0/0 --gateway-id <IGW_ID> --region <REGION>
# Associate with bgp-vm subnet
aws ec2 associate-route-table --route-table-id <BGP_RT_ID> --subnet-id <BGP_SUBNET_ID> --region <REGION>
```

**isp-vm + sinkhole subnet route table** — default internet access:
```bash
aws ec2 create-route-table --vpc-id <VPC_ID> --region <REGION>
# Add default route to IGW
aws ec2 create-route --route-table-id <ISP_RT_ID> --destination-cidr-block 0.0.0.0/0 --gateway-id <IGW_ID> --region <REGION>
# Associate with isp subnet
aws ec2 associate-route-table --route-table-id <ISP_RT_ID> --subnet-id <ISP_SUBNET_ID> --region <REGION>
```

**client subnet route table** — ALL traffic goes through isp-vm:
```bash
aws ec2 create-route-table --vpc-id <VPC_ID> --region <REGION>
# Route ALL traffic to isp-vm (not IGW!)
aws ec2 create-route --route-table-id <CLIENT_RT_ID> --destination-cidr-block 0.0.0.0/0 --instance-id <ISP_INSTANCE_ID> --region <REGION>
# Associate with client subnet
aws ec2 associate-route-table --route-table-id <CLIENT_RT_ID> --subnet-id <CLIENT_SUBNET_ID> --region <REGION>
```

> **Why client → isp-vm instead of IGW?**
> This makes isp-vm the gateway for all client traffic. isp-vm then decides:
> - Malicious destination (BGP-learned route) → forward to sinkhole
> - Legitimate destination → forward to IGW (internet)
>
> Without this, client traffic bypasses isp-vm entirely and sinkholing doesn't work.

#### 0.5 Launch EC2 Instances

| Instance | Subnet | Notes |
|----------|--------|-------|
| bgp-vm | bgp subnet | Ubuntu 24.04, t2.micro or larger |
| isp-vm | isp subnet | Ubuntu 24.04, **same subnet as sinkhole** |
| sinkhole-vm | isp subnet | Ubuntu 24.04, **same subnet as isp-vm** |
| client | client subnet | Ubuntu 24.04, no direct SSH after route table change |

All instances use the same key pair and security group (or separate SGs configured below).

---

### Step 1: AWS Instance Configuration

#### 1.1 Disable Source/Destination Check

Required on isp-vm and sinkhole-vm (they receive traffic not destined for their own IP):

- EC2 → Instances → select **isp-vm** → Actions → Networking → Change source/destination check → **Stop**
- EC2 → Instances → select **sinkhole-vm** → Actions → Networking → Change source/destination check → **Stop**

Or via CLI:
```bash
aws ec2 modify-instance-attribute --instance-id <ISP_INSTANCE_ID> --no-source-dest-check --region <REGION>
aws ec2 modify-instance-attribute --instance-id <SINKHOLE_INSTANCE_ID> --no-source-dest-check --region <REGION>
```

#### 1.2 Security Groups

**isp-vm's security group** — allow all VPC traffic inbound:
```bash
aws ec2 authorize-security-group-ingress --group-id <ISP_SG_ID> --protocol -1 --cidr <VPC_CIDR> --region <REGION>
```

**sinkhole-vm's security group** — allow all VPC traffic inbound:
```bash
aws ec2 authorize-security-group-ingress --group-id <SINKHOLE_SG_ID> --protocol -1 --cidr <VPC_CIDR> --region <REGION>
```

#### 1.3 Verify Client Route Table

Confirm the client's route table (set up in Step 0.4) is correctly associated:

```bash
aws ec2 describe-route-tables --filters "Name=association.subnet-id,Values=<CLIENT_SUBNET_ID>" --region <REGION> --query "RouteTables[*].Routes"
```

Expected:
| Destination | Target |
|-------------|--------|
| <VPC_CIDR> | local |
| 0.0.0.0/0 | <ISP_INSTANCE_ID> (isp-vm) |

**Note:** This breaks direct SSH to client from the internet. Use a jump host in the VPC (any instance in the isp or bgp subnet) to reach client via its private IP.

---

### Step 2: Install FRR on bgp-vm and isp-vm

SSH into each VM and run:

```bash
# Add FRR repository
curl -s https://deb.frrouting.org/frr/keys.gpg | sudo tee /usr/share/keyrings/frrouting.gpg > /dev/null
echo 'deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr noble frr-stable' | sudo tee /etc/apt/sources.list.d/frr.list

# Install
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y frr frr-pythontools

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

---

### Step 3: Configure FRR on bgp-vm

```bash
sudo tee /etc/frr/daemons << 'EOF'
zebra=yes
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
bgpd_options="   -A 0.0.0.0"
EOF
```

```bash
sudo tee /etc/frr/frr.conf << 'EOF'
frr version 10.7.0
frr defaults traditional
hostname bgp-vm
log syslog informational
service integrated-vtysh-config

ip prefix-list MALICIOUS seq 10 permit 198.51.100.0/24
ip prefix-list MALICIOUS seq 20 permit 203.0.113.0/24
ip prefix-list MALICIOUS seq 30 permit 192.0.2.0/24

route-map SET_SINKHOLE_NH permit 10
 match ip address prefix-list MALICIOUS
 set ip next-hop <SINKHOLE_PRIVATE_IP>
exit

route-map SET_SINKHOLE_NH permit 20
exit

ip route 192.0.2.0/24 <SINKHOLE_PRIVATE_IP>
ip route 198.51.100.0/24 <SINKHOLE_PRIVATE_IP>
ip route 203.0.113.0/24 <SINKHOLE_PRIVATE_IP>

router bgp 65001
 bgp router-id <BGP_PRIVATE_IP>
 bgp log-neighbor-changes
 no bgp ebgp-requires-policy
 neighbor <ISP_PRIVATE_IP> remote-as 65002
 neighbor <ISP_PRIVATE_IP> description ISP-VM
 neighbor <ISP_PRIVATE_IP> ebgp-multihop 2
 neighbor <ISP_PRIVATE_IP> disable-connected-check
 neighbor <ISP_PRIVATE_IP> update-source ens5
 neighbor <ISP_PRIVATE_IP> timers connect 10
 address-family ipv4 unicast
  network <BGP_SUBNET_CIDR>
  network 192.0.2.0/24
  network 198.51.100.0/24
  network 203.0.113.0/24
  neighbor <ISP_PRIVATE_IP> soft-reconfiguration inbound
  neighbor <ISP_PRIVATE_IP> route-map SET_SINKHOLE_NH out
 exit-address-family

line vty
EOF
```

```bash
sudo systemctl restart frr
sudo systemctl enable frr
```

---

### Step 4: Configure FRR on isp-vm

```bash
sudo tee /etc/frr/daemons << 'EOF'
zebra=yes
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
bgpd_options="   -A 0.0.0.0"
EOF
```

```bash
sudo tee /etc/frr/frr.conf << 'EOF'
frr version 10.7.0
frr defaults traditional
hostname isp-vm
log syslog informational
service integrated-vtysh-config

ip route 0.0.0.0/0 <ISP_SUBNET_GW>

router bgp 65002
 bgp router-id <ISP_PRIVATE_IP>
 bgp log-neighbor-changes
 no bgp ebgp-requires-policy
 neighbor <BGP_PRIVATE_IP> remote-as 65001
 neighbor <BGP_PRIVATE_IP> description BGP-VM
 neighbor <BGP_PRIVATE_IP> ebgp-multihop 2
 neighbor <BGP_PRIVATE_IP> disable-connected-check
 address-family ipv4 unicast
  network <ISP_SUBNET_CIDR>
  neighbor <BGP_PRIVATE_IP> soft-reconfiguration inbound
 exit-address-family

line vty
EOF
```

```bash
sudo systemctl restart frr
sudo systemctl enable frr
```

---

### Step 5: Verify eBGP Peering

On either VM:
```bash
sudo vtysh -c "show bgp summary"
```

Expected output (peering established):
```
Neighbor        V   AS   MsgRcvd  MsgSent  Up/Down  State/PfxRcd
<ISP_PRIVATE_IP>  4  65002    X        X      HH:MM:SS      1
```

Check routes on isp-vm:
```bash
sudo vtysh -c "show ip bgp"
```

Expected — isp-vm sees malicious prefixes with next-hop = sinkhole:
```
*>  192.0.2.0/24     <SINKHOLE_PRIVATE_IP>    0             0 65001 i
*>  198.51.100.0/24  <SINKHOLE_PRIVATE_IP>    0             0 65001 i
*>  203.0.113.0/24   <SINKHOLE_PRIVATE_IP>    0             0 65001 i
```

Verify kernel route installed:
```bash
ip route show 198.51.100.0/24
# Expected: 198.51.100.0/24 via <SINKHOLE_PRIVATE_IP> dev ens5 proto bgp metric 20
```

---

### Step 6: Start Sinkhole Capture

SSH into sinkhole-vm:
```bash
ssh -i bgp-key.pem ubuntu@<SINKHOLE_PUBLIC_IP>

sudo tcpdump -i ens5 -nn 'dst net 198.51.100.0/24 or dst net 203.0.113.0/24 or dst net 192.0.2.0/24' -w /tmp/sinkhole_capture.pcap
```

---

### Step 7: Test from Client

SSH into client (via jump host since direct SSH is broken by the route table change):
```bash
# From any VPC instance that can reach client:
ssh -i bgp-key.pem ubuntu@<CLIENT_PRIVATE_IP>
```

Run test traffic:
```bash
# ICMP - ping malicious IPs
ping -c 3 198.51.100.1
ping -c 3 203.0.113.50
ping -c 3 192.0.2.100

# TCP - HTTP connections to malicious IPs
curl -m 5 http://198.51.100.1
curl -m 5 http://203.0.113.1:8080
curl -m 5 http://192.0.2.50

# TCP - HTTPS connections
curl -m 5 https://198.51.100.10
curl -m 5 https://203.0.113.100

# UDP - DNS queries to malicious IPs
dig @198.51.100.1 example.com +timeout=2 +tries=1
dig @203.0.113.1 evil.com +timeout=2 +tries=1

# TCP - Simulated malware beacons
echo 'MALWARE_BEACON' | nc -w 2 192.0.2.1 4444
echo 'C2_CALLBACK' | nc -w 2 198.51.100.99 9999
```

All traffic will timeout (no reply) — this is expected since the sinkhole isn't responding.

---

### Step 8: Verify Capture

On sinkhole-vm, stop tcpdump (Ctrl+C) and read the pcap:
```bash
sudo tcpdump -r /tmp/sinkhole_capture.pcap -nn
```

Expected output:
```
IP <CLIENT_PRIVATE_IP> > 198.51.100.1: ICMP echo request
IP <CLIENT_PRIVATE_IP> > 203.0.113.50: ICMP echo request
IP <CLIENT_PRIVATE_IP> > 192.0.2.100: ICMP echo request
IP <CLIENT_PRIVATE_IP>.XXXXX > 198.51.100.1.80: Flags [S]
IP <CLIENT_PRIVATE_IP>.XXXXX > 203.0.113.1.8080: Flags [S]
IP <CLIENT_PRIVATE_IP>.XXXXX > 192.0.2.50.80: Flags [S]
IP <CLIENT_PRIVATE_IP>.XXXXX > 198.51.100.10.443: Flags [S]
IP <CLIENT_PRIVATE_IP>.XXXXX > 203.0.113.100.443: Flags [S]
IP <CLIENT_PRIVATE_IP>.XXXXX > 198.51.100.1.53: A? example.com
IP <CLIENT_PRIVATE_IP>.XXXXX > 203.0.113.1.53: A? evil.com
IP <CLIENT_PRIVATE_IP>.XXXXX > 192.0.2.1.4444: Flags [S]
IP <CLIENT_PRIVATE_IP>.XXXXX > 198.51.100.99.9999: Flags [S]
```

**Key observation:** Source IP is the client's real IP — preserved end-to-end with no SNAT/MASQUERADE.

---

## Live Demo: Add a New Malicious Prefix End-to-End

This demonstrates the full workflow: add a malicious IP on bgp-vm → isp-vm learns it automatically → client traffic to that IP gets captured at sinkhole. **No AWS changes needed.**

### Step A: Add the prefix on bgp-vm

```bash
# SSH into bgp-vm
ssh -i bgp-key.pem ubuntu@<BGP_PUBLIC_IP>

# Add new malicious prefix (e.g., 10.99.0.0/16)
sudo vtysh -c "configure terminal" \
  -c "ip prefix-list MALICIOUS seq 40 permit 10.99.0.0/16" \
  -c "ip route 10.99.0.0/16 <SINKHOLE_PRIVATE_IP>" \
  -c "router bgp 65001" \
  -c "address-family ipv4 unicast" \
  -c "network 10.99.0.0/16" \
  -c "end" \
  -c "clear bgp * out" \
  -c "write memory"
```

### Step B: Verify isp-vm learned it automatically

```bash
# SSH into isp-vm
ssh -i bgp-key.pem ubuntu@<ISP_PUBLIC_IP>

# Check BGP table — new prefix should appear within seconds
sudo vtysh -c "show ip bgp 10.99.0.0/16"
```

Expected:
```
BGP routing table entry for 10.99.0.0/16
Paths: (1 available, best #1, table default)
  65001
    <SINKHOLE_PRIVATE_IP> from <BGP_PRIVATE_IP> (<BGP_PRIVATE_IP>)
      Origin IGP, metric 0, valid, external, best
```

Verify kernel route installed:
```bash
ip route show 10.99.0.0/16
# Expected: 10.99.0.0/16 via <SINKHOLE_PRIVATE_IP> dev ens5 proto bgp metric 20
```

### Step C: Start capture on sinkhole

```bash
# SSH into sinkhole-vm
ssh -i bgp-key.pem ubuntu@<SINKHOLE_PUBLIC_IP>

# Start tcpdump for the new prefix
sudo tcpdump -i ens5 -nn dst net 10.99.0.0/16 -w /tmp/new_prefix_capture.pcap
```

### Step D: Send traffic from client

```bash
# SSH into client (via jump host)
ssh -i bgp-key.pem ubuntu@<CLIENT_PRIVATE_IP>

# Ping a host in the new malicious range
ping -c 3 10.99.0.1

# Curl an HTTP endpoint in the range
curl -m 5 http://10.99.0.50

# Simulate a C2 beacon
echo "BEACON" | nc -w 2 10.99.0.100 443
```

### Step E: Verify capture at sinkhole

```bash
# On sinkhole-vm, stop tcpdump (Ctrl+C) and read
sudo tcpdump -r /tmp/new_prefix_capture.pcap -nn
```

Expected output:
```
IP <CLIENT_PRIVATE_IP> > 10.99.0.1: ICMP echo request, id XXXX, seq 1
IP <CLIENT_PRIVATE_IP> > 10.99.0.1: ICMP echo request, id XXXX, seq 2
IP <CLIENT_PRIVATE_IP> > 10.99.0.1: ICMP echo request, id XXXX, seq 3
IP <CLIENT_PRIVATE_IP>.XXXXX > 10.99.0.50.80: Flags [S], seq ...
IP <CLIENT_PRIVATE_IP>.XXXXX > 10.99.0.100.443: Flags [S], seq ...
```

Client's source IP captured. Sinkhole proves client tried to reach the malicious IP.

### Quick-add more prefixes (one-liners on bgp-vm)

```bash
# Add a single /24
sudo vtysh -c "conf t" -c "ip prefix-list MALICIOUS seq 50 permit 172.16.66.0/24" -c "ip route 172.16.66.0/24 <SINKHOLE_PRIVATE_IP>" -c "router bgp 65001" -c "address-family ipv4 unicast" -c "network 172.16.66.0/24" -c "end" -c "clear bgp * out" -c "write memory"

# Add a /32 (single IP)
sudo vtysh -c "conf t" -c "ip prefix-list MALICIOUS seq 60 permit 44.55.66.77/32" -c "ip route 44.55.66.77/32 <SINKHOLE_PRIVATE_IP>" -c "router bgp 65001" -c "address-family ipv4 unicast" -c "network 44.55.66.77/32" -c "end" -c "clear bgp * out" -c "write memory"

# Remove a prefix
sudo vtysh -c "conf t" -c "no ip prefix-list MALICIOUS seq 50" -c "no ip route 172.16.66.0/24 <SINKHOLE_PRIVATE_IP>" -c "router bgp 65001" -c "address-family ipv4 unicast" -c "no network 172.16.66.0/24" -c "end" -c "clear bgp * out" -c "write memory"
```

**No AWS route table changes needed for any of the above. isp-vm learns/removes routes automatically via BGP.**

---

## Troubleshooting

### Peering shows "Active" not Established
- Check `sudo vtysh -c "show bgp neighbor <ISP_PRIVATE_IP>"` — look for "Last reset" reason
- If "No path to specified Neighbor": peers are in different subnets, need `disable-connected-check` and `ebgp-multihop 2`
- Ensure `ip nht resolve-via-default` is set if next-hop resolution fails
- Ensure no iptables rules blocking TCP 179: `sudo iptables -L -n`

### Packets reach isp-vm but not sinkhole
- Verify `ip_forward=1` on isp-vm: `sudo sysctl net.ipv4.ip_forward`
- Check kernel route: `ip route show 198.51.100.0/24` — must show `via <SINKHOLE_PRIVATE_IP>`
- Ensure sinkhole has **source/dest check disabled** in AWS
- Ensure sinkhole is in the **same subnet** as isp-vm
- Check sinkhole's security group allows all traffic from VPC CIDR

### BGP routes not installed in kernel
- Check zebra is running: `sudo vtysh -c "show ip route"`
- If "zebra is not running" — restart FRR: `sudo systemctl restart frr`

### Docker interference
- If Docker was previously installed, it leaves iptables rules with FORWARD policy DROP
- Fix: `sudo iptables -P FORWARD ACCEPT; sudo iptables -F`
- Or remove Docker entirely: `sudo apt purge -y docker.io docker-ce`

### Client SSH broken after route table change
- Client's `0.0.0.0/0 → isp-vm` means return SSH traffic goes to isp-vm instead of IGW
- Use a jump host in the same VPC to SSH to client via its private IP

---

## Important Notes

1. **Source IP is private** — AWS public IPs (EIPs) are NAT'd at the IGW. Since traffic stays inside the VPC, the public IP never appears in packets. Use `aws ec2 describe-instances --filters "Name=private-ip-address,Values=<CLIENT_PRIVATE_IP>"` to map private → public.

2. **Sinkhole must be in same subnet as isp-vm** — AWS VPC routing can't deliver packets to a next-hop in a different subnet based on FRR routes alone. Same-subnet enables direct L2 (ARP) delivery.

3. **No SNAT/MASQUERADE** — source IP is preserved end-to-end. This is critical for attribution.

4. **FRR version matters** — Docker images (`frrouting/frr:latest` on DockerHub) are outdated and crash (signal 11). Use native install via `deb.frrouting.org` (gets v10.7.0).

5. **ebgp-multihop + disable-connected-check** — required when bgp-vm and isp-vm are in different subnets. Without these, FRR refuses to initiate the BGP connection ("No path to specified Neighbor").

---

## File Structure

```
test/
├── README.md                    # This file
├── bgp-key.pem                  # SSH key for all instances
├── bgp-vm/
│   ├── daemons                  # FRR daemons config
│   └── frr.conf                 # BGP + route-map + prefix-list config
├── isp-vm/
│   ├── daemons                  # FRR daemons config
│   └── frr.conf                 # BGP peering config
├── sinkhole_capture.pcap        # First capture (ICMP only)
├── sinkhole_all_prefixes.pcap   # Multi-prefix ICMP capture
└── sinkhole_mixed.pcap          # Mixed traffic capture (ICMP+TCP+UDP)
```
