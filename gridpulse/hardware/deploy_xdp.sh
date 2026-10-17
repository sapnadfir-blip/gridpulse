#!/bin/bash
# deploy_xdp.sh - Deploy and manage the GOOSE XDP filter
#
# Usage:
#   ./deploy_xdp.sh load [interface]     Load XDP filter on interface
#   ./deploy_xdp.sh unload [interface]   Remove XDP filter
#   ./deploy_xdp.sh add-mac <MAC>        Add MAC to allowlist
#   ./deploy_xdp.sh stats                Show XDP statistics
#   ./deploy_xdp.sh monitor              Live monitoring mode

set -euo pipefail

IFACE="${2:-eth0}"
XDP_OBJ="/app/xdp_goose_filter.o"
XDP_SRC="/app/xdp_goose_filter.c"
XDP_SEC="xdp_goose"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

compile_xdp() {
    echo -e "${CYAN}[XDP] Compiling BPF program...${NC}"
    clang -O2 -g -target bpf \
        -I/usr/include/aarch64-linux-gnu \
        -c "$XDP_SRC" -o "$XDP_OBJ"
    echo -e "${GREEN}[XDP] Compiled successfully: $XDP_OBJ${NC}"
}

load_xdp() {
    if [ ! -f "$XDP_OBJ" ]; then
        compile_xdp
    fi

    echo -e "${CYAN}[XDP] Loading filter on interface $IFACE...${NC}"
    ip link set dev "$IFACE" xdpgeneric obj "$XDP_OBJ" sec "$XDP_SEC"
    echo -e "${GREEN}[XDP] Filter loaded successfully!${NC}"

    # Verify
    echo -e "${CYAN}[XDP] Verifying loaded programs:${NC}"
    bpftool prog list 2>/dev/null || ip link show dev "$IFACE"
}

unload_xdp() {
    echo -e "${YELLOW}[XDP] Removing filter from $IFACE...${NC}"
    ip link set dev "$IFACE" xdpgeneric off
    echo -e "${GREEN}[XDP] Filter removed.${NC}"
}

add_mac() {
    local MAC="$2"
    echo -e "${CYAN}[XDP] Adding MAC $MAC to allowlist...${NC}"

    # Convert MAC string to hex bytes for bpftool
    local HEX=$(echo "$MAC" | tr ':' ' ' | awk '{for(i=1;i<=NF;i++) printf "%s ", $i; print "00 00"}')
    echo -e "${GREEN}[XDP] MAC $MAC added to allowlist.${NC}"
    bpftool map update name allowed_macs \
        key hex $HEX \
        value 01 00 00 00 2>/dev/null && \
        echo -e "${GREEN}[XDP] MAC $MAC added.${NC}" || \
        echo -e "${RED}[XDP] Failed to add MAC (bpftool may not be available).${NC}"
}

show_stats() {
    echo -e "${CYAN}===== XDP GOOSE Filter Statistics =====${NC}"
    bpftool map dump name xdp_stats 2>/dev/null || echo "Stats map not available"
    echo ""
    echo -e "${CYAN}===== Allowed MACs =====${NC}"
    bpftool map dump name allowed_macs 2>/dev/null || echo "MAC map not available"
    echo ""
    echo -e "${CYAN}===== Rate Limiter State =====${NC}"
    bpftool map dump name rate_limiter 2>/dev/null || echo "Rate map not available"
}

monitor_stats() {
    echo -e "${CYAN}[XDP] Live monitoring (Ctrl+C to stop)...${NC}"
    while true; do
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║     GridPulse XDP GOOSE Filter Stats     ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
        echo ""
        show_stats
        echo ""
        echo -e "${YELLOW}Refreshing every 1 second...${NC}"
        sleep 1
    done
}

case "${1:-help}" in
    load)
        compile_xdp
        load_xdp
        ;;
    unload)
        unload_xdp
        ;;
    add-mac)
        add_mac "$@"
        ;;
    stats)
        show_stats
        ;;
    monitor)
        monitor_stats
        ;;
    *)
        echo "GridPulse XDP GOOSE Filter Manager"
        echo ""
        echo "Usage:"
        echo "  $0 load [interface]        Compile and load XDP filter"
        echo "  $0 unload [interface]      Remove XDP filter"
        echo "  $0 add-mac <MAC>           Add MAC to allowlist"
        echo "  $0 stats                   Show current statistics"
        echo "  $0 monitor                 Live monitoring dashboard"
        echo ""
        echo "Default interface: eth0"
        ;;
esac
