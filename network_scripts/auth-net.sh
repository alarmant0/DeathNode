#!/bin/bash
set -e

IFACE="eth0"
IP_ADDR="10.0.1.20"
NETMASK="255.255.255.0"
HOSTNAME="blind-auth"

hostnamectl set-hostname "$HOSTNAME"
sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 $HOSTNAME" >> /etc/hosts

systemctl stop NetworkManager || true
systemctl disable NetworkManager || true

cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $IFACE
iface $IFACE inet static
    address $IP_ADDR
    netmask $NETMASK
EOF

ifdown "$IFACE" 2>/dev/null || true
ifup "$IFACE"

ip a show "$IFACE"
ip route

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp -s 10.0.1.10 --dport 443 -m conntrack --ctstate NEW -j ACCEPT

iptables -A INPUT -p icmp -j DROP

iptables-save > /etc/iptables/rules.v4 2>/dev/null || echo "Warning: Could not save iptables rules"