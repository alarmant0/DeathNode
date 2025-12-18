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
