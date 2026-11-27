#!/bin/bash
# setup_veth_lab.sh - Single-Laptop Virtual Attacker Lab (Network Namespace + veth pair)
# Allows running ALL attacks (SQLi, Path Traversal, SSH Brute-Force, Port Scan, Killshot, and 2M PPS Flood)
# from a single laptop without needing a second machine or Wi-Fi!
set -e

IFACE_IN="veth-bench"
IFACE_OUT="veth-gen"
NETNS="attacker"
IP_IN="198.51.100.1"
IP_OUT="198.51.100.2"

case "$1" in
    start)
        echo "[*] Cleaning up any previous lab setup..."
        sudo ip link set dev $IFACE_IN xdp off 2>/dev/null || true
        sudo ip link del $IFACE_IN 2>/dev/null || true
        sudo ip netns del $NETNS 2>/dev/null || true

        echo "[*] Creating virtual Attacker namespace ($NETNS) and veth cable ($IFACE_IN <---> $IFACE_OUT)..."
        sudo ip netns add $NETNS
        sudo ip link add $IFACE_IN type veth peer name $IFACE_OUT
        sudo ip link set $IFACE_OUT netns $NETNS

        # Configure Host side (veth-bench = 198.51.100.1)
        sudo ip addr add $IP_IN/24 dev $IFACE_IN
        sudo ip link set $IFACE_IN up
        sudo ethtool -K $IFACE_IN tx off rx off 2>/dev/null || true

        # Configure Attacker side inside netns (veth-gen = 198.51.100.2)
        sudo ip netns exec $NETNS ip link set lo up
        sudo ip netns exec $NETNS ip addr add $IP_OUT/24 dev $IFACE_OUT
        sudo ip netns exec $NETNS ip link set $IFACE_OUT up
        sudo ip netns exec $NETNS ip route add default via $IP_IN
        sudo ip netns exec $NETNS ethtool -K $IFACE_OUT tx off rx off 2>/dev/null || true

        # Ensure Nginx, SSHD, and Firewall allow traffic from veth-bench
        sudo systemctl start nginx sshd 2>/dev/null || true
        sudo firewall-cmd --add-port=80/tcp --add-port=22/tcp --add-port=5000/tcp >/dev/null 2>&1 || true

        echo "[+] Single-Laptop Virtual Lab is READY!"
        echo "    Host Interface (XDP Target) : $IFACE_IN ($IP_IN)"
        echo "    Virtual Attacker Namespace  : $NETNS ($IP_OUT via $IFACE_OUT)"
        echo ""
        echo "=== HOW TO RUN YOUR SINGLE-LAPTOP SHOWCASE ==="
        echo "  1. Terminal 1 (Dashboard):  cd dashboard && python3 app.py"
        echo "  2. Terminal 2 (Engine):     sudo ./engine $IFACE_IN --enforce"
        echo "  3. Terminal 3 (Attacker):   sudo ip netns exec $NETNS bash"
        echo "     (Inside Terminal 3, target $IP_IN for all attacks!)"
        ;;
    stop)
        echo "[*] Cleaning up virtual lab..."
        sudo ip link set dev $IFACE_IN xdp off 2>/dev/null || true
        sudo ip link del $IFACE_IN 2>/dev/null || true
        sudo ip netns del $NETNS 2>/dev/null || true
        echo "[+] Cleaned up!"
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac
