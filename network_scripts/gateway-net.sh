#!/bin/bash
set -e

DMZ_IFACE="eth0"
DMZ_IP="10.0.1.10"
DMZ_NETMASK="255.255.255.0"

INT_IFACE="eth1"
INT_IP="10.0.2.10"
INT_NETMASK="255.255.255.0"

NAT_IFACE="eth2"
HOSTNAME="deathnode-gateway"

hostnamectl set-hostname "$HOSTNAME"
sed -i '/127.0.1.1/d' /etc/hosts
echo "127.0.1.1 $HOSTNAME" >> /etc/hosts

systemctl stop NetworkManager || true
systemctl disable NetworkManager || true

cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $DMZ_IFACE
iface $DMZ_IFACE inet static
    address $DMZ_IP
    netmask $DMZ_NETMASK

auto $INT_IFACE
iface $INT_IFACE inet static
    address $INT_IP
    netmask $INT_NETMASK

auto $NAT_IFACE
iface $NAT_IFACE inet dhcp
EOF

ifdown "$DMZ_IFACE" 2>/dev/null || true
ifdown "$INT_IFACE" 2>/dev/null || true
ifdown "$NAT_IFACE" 2>/dev/null || true

ifup "$DMZ_IFACE"
ifup "$INT_IFACE"
ifup "$NAT_IFACE" || true

ip a show "$DMZ_IFACE"
ip a show "$INT_IFACE"
ip a show "$NAT_IFACE" || true
ip route

sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp -s 10.0.2.0/24 --dport 443 -m conntrack --ctstate NEW -j ACCEPT

iptables -A OUTPUT -p tcp -d 10.0.1.20 --dport 443 -m conntrack --ctstate NEW -j ACCEPT

iptables -A FORWARD -p tcp -s 10.0.2.0/24 -d 10.0.1.20 --dport 443 -m conntrack --ctstate NEW -j ACCEPT

iptables -t nat -A POSTROUTING -o "$NAT_IFACE" -j MASQUERADE

iptables -A FORWARD -i "$INT_IFACE" -o "$NAT_IFACE" -s 10.0.2.0/24 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "$NAT_IFACE" -o "$INT_IFACE" -d 10.0.2.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables-save > /etc/iptables/rules.v4 2>/dev/null || echo "Warning: Could not save iptables rules"