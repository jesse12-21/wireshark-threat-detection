#!/bin/bash
# generate_test_traffic.sh - Produce synthetic threat traffic for detection testing
#
# Generates network traffic patterns that the project's detection scripts
# (dns_tunnel_detect.sh, tls_extract.sh, beacon_detect.sh) are designed to
# identify. Run this script while capturing with tcpdump or Wireshark to
# produce a reproducible test PCAP.
#
# Modes:
#   dns       Long-name TXT queries to a reserved .invalid TLD (NXDOMAIN responses)
#   sni       SNI-less TLS handshakes via openssl s_client (no -servername)
#   beacon    Regular-interval HTTPS connections with small jitter
#   baseline  Normal browsing-pattern traffic for contrast
#   all       Run all four modes sequentially (default)
#
# Usage:
#   ./generate_test_traffic.sh [mode]
#
# Environment variables (optional):
#   INTERVAL    Beacon interval in seconds (default: 30)
#   DURATION    Beacon mode runtime in seconds (default: 180)
#   RESOLVER    DNS resolver for tunneling queries (default: 1.1.1.1)
#
# Examples:
#   # Start a capture in one terminal:
#   sudo tcpdump -i any -w test_traffic.pcapng
#
#   # Generate the full pattern in another:
#   ./generate_test_traffic.sh all
#
#   # Then test detections:
#   ./scripts/dns_tunnel_detect.sh test_traffic.pcapng 50
#   ./scripts/tls_extract.sh test_traffic.pcapng
#   ./scripts/beacon_detect.sh test_traffic.pcapng <example.com IP>
#
# Safety:
#   - DNS queries target the IETF-reserved .invalid TLD (RFC 2606) and always
#     return NXDOMAIN. No real exfiltration occurs.
#   - HTTPS targets are public benign services (example.com).
#   - No attack tools, no real C2, no malicious payloads.
#   - Run only on a lab VM you own and control.

set -euo pipefail

MODE="${1:-all}"
RESOLVER="${RESOLVER:-1.1.1.1}"
INTERVAL="${INTERVAL:-30}"
DURATION="${DURATION:-180}"

# Public benign HTTPS target used for beacon and SNI-less tests.
# example.com is reserved per RFC 2606 and stably hosted.
BEACON_TARGET="example.com"

log() {
    echo "[$(date +%H:%M:%S)] $*"
}

# Pre-flight checks ------------------------------------------------------------

require_command() {
    if ! command -v "$1" &>/dev/null; then
        echo "Error: '$1' is required but not installed."
        echo "  Install with: sudo apt install $2"
        exit 1
    fi
}

require_command dig dnsutils
require_command openssl openssl
require_command curl curl

# Resolve the beacon target to an IP for SNI-less testing
resolve_beacon_ip() {
    dig +short "$BEACON_TARGET" A @"$RESOLVER" 2>/dev/null | \
        grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -1
}

# Generators -------------------------------------------------------------------

generate_dns_tunneling() {
    log "--- Generating DNS tunneling pattern ---"
    log "20 TXT queries with high-entropy 60+ character names to .invalid domain"
    log "(All will return NXDOMAIN — no real exfiltration)"

    local count=20
    for i in $(seq 1 $count); do
        local prefix1
        local prefix2
        prefix1=$(openssl rand -hex 16)
        prefix2=$(openssl rand -hex 12)
        local query="${prefix1}.${prefix2}.exfil-test.invalid"

        log "  TXT query #${i}: ${query:0:60}..."
        dig +tries=1 +time=2 @"$RESOLVER" "$query" TXT \
            > /dev/null 2>&1 || true

        sleep 1
    done

    log "DNS tunneling pattern complete (${count} queries issued)"
    echo ""
}

generate_sni_less_https() {
    log "--- Generating SNI-less TLS handshakes ---"

    local beacon_ip
    beacon_ip=$(resolve_beacon_ip)

    if [ -z "$beacon_ip" ]; then
        log "  WARN: could not resolve $BEACON_TARGET; skipping SNI-less generation"
        return 0
    fi

    log "Target IP: $beacon_ip ($BEACON_TARGET resolved at runtime)"
    log "Connecting via openssl s_client WITHOUT -servername to omit SNI"

    local count=10
    for i in $(seq 1 $count); do
        log "  SNI-less handshake #${i} to ${beacon_ip}:443"
        # openssl s_client without -servername omits the SNI extension.
        # 'Q' is sent on stdin to cleanly close the session.
        echo "Q" | timeout 5 openssl s_client \
            -connect "${beacon_ip}:443" \
            -quiet \
            > /dev/null 2>&1 || true
        sleep 2
    done

    log "SNI-less handshake generation complete (${count} handshakes)"
    log "Note the target IP — feed it to beacon_detect.sh and tls_extract.sh"
    echo ""
}

generate_beacon() {
    log "--- Generating HTTPS beacon pattern ---"
    log "Target: https://${BEACON_TARGET}/"
    log "Interval: ${INTERVAL}s (±3s jitter)   Duration: ${DURATION}s"

    local elapsed=0
    local count=0
    local jitter

    while [ "$elapsed" -lt "$DURATION" ]; do
        count=$((count + 1))
        log "  Beacon #${count} → https://${BEACON_TARGET}/"
        curl --silent --output /dev/null --max-time 5 \
            "https://${BEACON_TARGET}/" 2>/dev/null || true

        # Small random jitter (±3 seconds) to mimic real C2 jitter
        jitter=$(( (RANDOM % 7) - 3 ))
        local wait=$((INTERVAL + jitter))
        sleep "$wait"
        elapsed=$((elapsed + wait))
    done

    log "Beacon generation complete (${count} beacons over ${elapsed}s)"
    echo ""
}

generate_baseline() {
    log "--- Generating baseline normal traffic ---"

    local targets=(
        "www.google.com"
        "duckduckgo.com"
        "github.com"
        "ubuntu.com"
        "mozilla.org"
    )

    for site in "${targets[@]}"; do
        log "  Normal request to https://${site}"
        curl --silent --output /dev/null --max-time 5 \
            "https://${site}/" 2>/dev/null || true
        sleep 3
    done

    log "Baseline traffic complete (${#targets[@]} requests)"
    echo ""
}

# Main -------------------------------------------------------------------------

echo "========================================"
echo "  Test Traffic Generator"
echo "========================================"
echo "Mode:      $MODE"
echo "Started:   $(date)"
echo ""
echo "Capture concurrently with, e.g.:"
echo "  sudo tcpdump -i any -w test_traffic.pcapng"
echo "or open Wireshark on your capture interface before running."
echo ""

case "$MODE" in
    all)
        generate_baseline
        generate_dns_tunneling
        generate_sni_less_https
        generate_beacon
        ;;
    dns)
        generate_dns_tunneling
        ;;
    sni)
        generate_sni_less_https
        ;;
    beacon)
        generate_beacon
        ;;
    baseline)
        generate_baseline
        ;;
    -h|--help|help)
        sed -n '2,30p' "$0"
        exit 0
        ;;
    *)
        echo "Error: unknown mode '$MODE'"
        echo "Usage: $0 [all|dns|sni|beacon|baseline]"
        exit 1
        ;;
esac

echo "========================================"
echo "  Generation complete: $(date)"
echo "========================================"
echo ""
echo "Stop your capture, then run the detection scripts against the PCAP:"
echo "  ./scripts/dns_tunnel_detect.sh test_traffic.pcapng 50"
echo "  ./scripts/tls_extract.sh test_traffic.pcapng"
echo "  ./scripts/beacon_detect.sh test_traffic.pcapng <BEACON_TARGET_IP>"
