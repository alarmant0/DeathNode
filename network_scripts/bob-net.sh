#!/bin/bash
set -e

IFACE="eth0"
IP_ADDR="10.0.2.11"
NETMASK="255.255.255.0"
GATEWAY="10.0.2.10"
HOSTNAME="shadow-bob"

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
    gateway $GATEWAY
EOF

ifdown "$IFACE" 2>/dev/null || true
ifup "$IFACE"

ip a show "$IFACE"
ip route

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -p tcp -d 10.0.2.10 --dport 443 -m conntrack --ctstate NEW -j ACCEPT

iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

iptables -A INPUT -p icmp -j DROP
iptables -A OUTPUT -p icmp -j DROP

iptables-save > /etc/iptables/rules.v4 2>/dev/null || echo "Warning: Could not save iptables rules"