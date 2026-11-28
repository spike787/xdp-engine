#!/bin/bash
# SPDX-License-Identifier: MIT
# multihost_lab.sh - Multi-Host Lab (ROADMAP.md Phase 4)
#
# Simulates several independent hosts sharing one Local API, using Linux
# network namespaces instead of separate physical/cloud machines. Each
# namespace has its own, fully independent kernel network stack - its own
# routing table, its own nftables state, and (since generic-mode XDP
# attaches to any netdev, not just hardware NICs - see ROADMAP.md) its own
# independent XDP attachment. They are bridged together into one L2
# network, the same way separate machines on a LAN would be.
#
# Topology:
#   br-lab (10.99.0.1/24)            - the "LAN", lives in the default netns
#     |-- client     (10.99.0.2/24)  - generates traffic, like an external host
#     |-- host-xdp   (10.99.0.11/24) - runs bouncer-xdp against its own veth
#     |-- host-nft   (10.99.0.12/24) - runs bouncer-nft against its own netns
#     |-- host-proxy (10.99.0.13/24) - runs bouncer-proxy + a tiny backend
#
# local-api itself runs in the default namespace, bound to the bridge's own
# address (10.99.0.1:8088), so it is reachable from every namespace exactly
# the way a real Local API would be reachable from several real hosts on
# one network - this script only sets up the topology; starting local-api
# and each bouncer inside the right namespace is left to the caller (see
# docs/multihost-lab.md), the same division of responsibility
# setup_veth_lab.sh uses for the single-host benchmark lab.
#
# bouncer-nft and bouncer-proxy run cleanly against this topology: give
# each its own namespace (host-nft, host-proxy) and it enforces
# independently via real, namespace-scoped kernel state (an nftables
# table, or nothing at all). bouncer-xdp needs one extra step: `ip netns
# exec` gives every invocation a brand-new mount namespace (that's how it
# scopes /sys/class/net to just that namespace's interfaces), and bpffs
# mounted at /sys/fs/bpf in the root mount namespace does NOT carry over
# into that fresh one - so bouncer-xdp's map-pinning (ADR-0002) fails with
# ENOENT unless bpffs is (re-)mounted inside that same invocation, every
# time. Use `exec` below instead of raw `ip netns exec` for host-xdp so
# that mount always happens. See docs/multihost-lab.md for the full
# investigation (an initial run without this mount failed in a way that
# briefly looked like a deeper XDP/environment limitation before the
# mount-namespace root cause was found and confirmed fixed on real
# hardware: traffic to host-xdp was actually dropped and restored, not
# just logged).
set -e

BRIDGE="br-lab"
BRIDGE_IP="10.99.0.1"
PREFIX="24"

declare -A NODES=(
    [client]="10.99.0.2"
    [host-xdp]="10.99.0.11"
    [host-nft]="10.99.0.12"
    [host-proxy]="10.99.0.13"
)

# Linux interface names are capped at 15 characters (IFNAMSIZ), so the
# veth pairs use a short abbreviation of the namespace name rather than
# the namespace name itself (e.g. "veth-prx-br" for "host-proxy") - the
# namespace name shown to the user is unaffected by this limit.
declare -A ABBR=(
    [client]="cli"
    [host-xdp]="xdp"
    [host-nft]="nft"
    [host-proxy]="prx"
)

veth_host() { echo "veth-${ABBR[$1]}-br"; }   # bridge-side end, stays in default netns
veth_ns()   { echo "veth-${ABBR[$1]}"; }      # namespace-side end

cleanup() {
    echo "[*] Cleaning up any previous lab setup..."
    for name in "${!NODES[@]}"; do
        sudo ip link set dev "$(veth_host "$name")" xdp off 2>/dev/null || true
        sudo ip netns exec "$name" ip link set dev "$(veth_ns "$name")" xdp off 2>/dev/null || true
        sudo ip link del "$(veth_host "$name")" 2>/dev/null || true
        sudo ip netns del "$name" 2>/dev/null || true
    done
    sudo ip link del "$BRIDGE" 2>/dev/null || true
}

case "$1" in
    start)
        cleanup

        echo "[*] Creating bridge $BRIDGE ($BRIDGE_IP/$PREFIX)..."
        sudo ip link add "$BRIDGE" type bridge
        sudo ip addr add "$BRIDGE_IP/$PREFIX" dev "$BRIDGE"
        sudo ip link set "$BRIDGE" up

        for name in "${!NODES[@]}"; do
            ip_addr="${NODES[$name]}"
            host_end="$(veth_host "$name")"
            ns_end="$(veth_ns "$name")"

            echo "[*] Creating namespace '$name' ($ip_addr) ..."
            sudo ip netns add "$name"
            sudo ip link add "$host_end" type veth peer name "$ns_end"
            sudo ip link set "$ns_end" netns "$name"

            # Bridge side: no IP needed, just join the L2 domain.
            sudo ip link set "$host_end" master "$BRIDGE"
            sudo ip link set "$host_end" up
            sudo ethtool -K "$host_end" tx off rx off 2>/dev/null || true

            # Namespace side: real IP, real routing table.
            sudo ip netns exec "$name" ip link set lo up
            sudo ip netns exec "$name" ip addr add "$ip_addr/$PREFIX" dev "$ns_end"
            sudo ip netns exec "$name" ip link set "$ns_end" up
            sudo ip netns exec "$name" ethtool -K "$ns_end" tx off rx off 2>/dev/null || true
        done

        echo "[+] Multi-host lab is READY."
        echo "    Shared control plane (run here, in the default namespace;"
        echo "    local-api binds 0.0.0.0, so it's reachable via $BRIDGE_IP from"
        echo "    every namespace below):"
        echo "      LOCAL_API_TOKEN=lab-secret ./local-api /tmp/multihost_lab.db 8088"
        echo ""
        echo "    Enforcement nodes, each in its own namespace:"
        for name in "${!NODES[@]}"; do
            [ "$name" = "client" ] && continue
            if [ "$name" = "host-xdp" ]; then
                echo "      sudo $0 exec $name bash   # ${NODES[$name]}, veth: $(veth_ns "$name") (mounts bpffs first - see note below)"
            else
                echo "      sudo ip netns exec $name bash   # ${NODES[$name]}, veth: $(veth_ns "$name")"
            fi
        done
        echo ""
        echo "    Traffic-generating node:"
        echo "      sudo ip netns exec client bash   # ${NODES[client]}"
        echo ""
        echo "    NOTE: use '$0 exec host-xdp <cmd>' (not raw 'ip netns exec')"
        echo "    to run bouncer-xdp - it mounts bpffs fresh first, which bouncer-xdp"
        echo "    needs to pin its maps (ADR-0002) and 'ip netns exec' alone doesn't"
        echo "    carry over from the default namespace. See docs/multihost-lab.md."
        echo ""
        echo "See docs/multihost-lab.md for the full walkthrough."
        ;;
    stop)
        cleanup
        echo "[+] Cleaned up."
        ;;
    exec)
        ns="$2"
        shift 2 2>/dev/null || true
        if [ -z "$ns" ] || [ "$#" -eq 0 ]; then
            echo "Usage: $0 exec <namespace> <command...>"
            echo "  (mounts bpffs inside the namespace's mount namespace before running"
            echo "   <command...> there - needed for bouncer-xdp's map pinning; harmless"
            echo "   for anything else)"
            exit 1
        fi
        # mount is best-effort: it may already be mounted, or the command may
        # not need it at all, so don't let a second mount attempt abort this.
        sudo ip netns exec "$ns" bash -c 'mount -t bpf bpf /sys/fs/bpf 2>/dev/null; exec "$@"' -- "$@"
        ;;
    *)
        echo "Usage: $0 {start|stop|exec}"
        exit 1
        ;;
esac
