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
