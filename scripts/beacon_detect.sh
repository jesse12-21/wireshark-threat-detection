#!/bin/bash
# beacon_detect.sh - Identify potential C2 beaconing behavior across one or more
#                    destination IPs.
#
# Analyzes connection timing to a target — which may be a single IP, a list of
# IPs (for DNS round-robin / fast-flux destinations), or a domain that will be
# resolved at runtime — to detect regular intervals that may indicate
# command-and-control beaconing.
#
# Backward compatible with the single-IP form: passing one IP works exactly as
# before, with the same statistical analysis (mean / stddev / jitter).
#
# Usage:
#   ./beacon_detect.sh <capture_file.pcapng> <target>
#
# Where <target> is one of:
#   - A single IPv4 address:        198.51.100.42
#   - Comma-separated IPv4 list:    198.51.100.42,198.51.100.43,198.51.100.44
#   - A domain name (live resolve): c2.example.com
#
# Examples:
#   ./beacon_detect.sh capture.pcapng 198.51.100.42
#   ./beacon_detect.sh capture.pcapng 198.51.100.42,198.51.100.43,198.51.100.44
#   ./beacon_detect.sh capture.pcapng suspicious.example.com
#
# Note on domain resolution: when a domain is passed, the IPs resolved at
# runtime may differ from those present in the capture (DNS round-robin and
# fast-flux change frequently). For historical investigations, pass the IPs
# observed in the capture directly.

set -euo pipefail

CAPTURE_FILE="${1:?Usage: $0 <capture_file> <ip | ip,ip,ip | domain>}"
TARGET_SPEC="${2:?Usage: $0 <capture_file> <ip | ip,ip,ip | domain>}"

if [ ! -f "$CAPTURE_FILE" ]; then
    echo "Error: File '$CAPTURE_FILE' not found."
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Install with: sudo apt install tshark"
    exit 1
fi

# Target resolution ------------------------------------------------------------

is_ipv4() {
    echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

resolve_targets() {
    local spec="$1"

    # Comma-separated list
    if echo "$spec" | grep -q ','; then
        echo "$spec" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        return
    fi

    # Single IPv4
    if is_ipv4 "$spec"; then
        echo "$spec"
        return
    fi

    # Domain — resolve live
    if ! command -v dig &> /dev/null; then
        echo "Error: target '$spec' is not an IP and 'dig' is not installed." >&2
        echo "       Install with: sudo apt install dnsutils" >&2
        exit 1
    fi

    local resolved
    resolved=$(dig +short "$spec" A 2>/dev/null | \
               grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || true)

    if [ -z "$resolved" ]; then
        echo "Error: could not resolve '$spec' to any IPv4 addresses." >&2
        exit 1
    fi

    echo "$resolved"
}

TARGET_IPS=$(resolve_targets "$TARGET_SPEC")
TARGET_COUNT=$(echo "$TARGET_IPS" | wc -l)

# Build the tshark display filter for set membership
# Wireshark syntax: ip.dst in {1.1.1.1 2.2.2.2 3.3.3.3}
build_ip_filter() {
    local ips
    ips=$(echo "$TARGET_IPS" | tr '\n' ' ' | sed 's/ *$//')
    echo "ip.dst in {${ips}}"
}

IP_FILTER=$(build_ip_filter)

# Report header ----------------------------------------------------------------

echo "========================================"
echo "  Multi-IP C2 Beacon Analysis Report"
echo "========================================"
echo "Capture:     $CAPTURE_FILE"
echo "Target spec: $TARGET_SPEC"
echo "Resolved:    $TARGET_COUNT IP(s)"
echo "$TARGET_IPS" | sed 's/^/             - /'
if ! is_ipv4 "$TARGET_SPEC" && ! echo "$TARGET_SPEC" | grep -q ','; then
    echo ""
    echo "NOTE: Domain was resolved live. IPs in the capture may differ from"
    echo "      current DNS — consider passing observed IPs directly for"
    echo "      historical investigations."
fi
echo ""
echo "Scan time:   $(date)"
echo ""

# Total SYNs across all destinations
TOTAL_SYNS=$(tshark -r "$CAPTURE_FILE" \
  -Y "${IP_FILTER} && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | wc -l)

echo "Total SYN packets across all targets: $TOTAL_SYNS"
echo ""

if [ "$TOTAL_SYNS" -lt 3 ]; then
    echo "Not enough connections to perform interval analysis (need at least 3)."
    exit 0
fi

# Capture duration
FIRST_TS=$(tshark -r "$CAPTURE_FILE" \
  -Y "${IP_FILTER} && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | head -1)

LAST_TS=$(tshark -r "$CAPTURE_FILE" \
  -Y "${IP_FILTER} && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | tail -1)

DURATION=$(echo "$LAST_TS - $FIRST_TS" | bc 2>/dev/null || echo "0")
echo "Capture duration for these hosts: ${DURATION}s"
echo ""

# Per-IP breakdown (only shown when multiple IPs are in scope)
if [ "$TARGET_COUNT" -gt 1 ]; then
    echo "--- Per-Destination Breakdown ---"
    echo "(SYN count | Destination IP)"
    tshark -r "$CAPTURE_FILE" \
      -Y "${IP_FILTER} && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
      -T fields -e ip.dst 2>/dev/null | \
    sort | uniq -c | sort -rn
    echo ""
fi

# Combined interval distribution
echo "--- Combined Connection Interval Distribution ---"
echo "(Count | Interval in seconds)"
echo ""

tshark -r "$CAPTURE_FILE" \
  -Y "${IP_FILTER} && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | \
awk 'NR > 1 { printf "%.0f\n", $1 - prev } { prev = $1 }' | \
sort -n | uniq -c | sort -rn | head -15

echo ""

# Statistical analysis on the combined intervals
echo "--- Combined Statistical Summary ---"

tshark -r "$CAPTURE_FILE" \
  -Y "${IP_FILTER} && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | \
awk '
NR > 1 {
    interval = $1 - prev
    intervals[NR-1] = interval
    sum += interval
    count++
}
{ prev = $1 }
END {
    if (count == 0) exit
    mean = sum / count

    for (i = 1; i <= count; i++) {
        diff = intervals[i] - mean
        sq_sum += diff * diff
    }
    stddev = sqrt(sq_sum / count)

    if (mean > 0) jitter = (stddev / mean) * 100

    printf "  Mean interval:     %.2f seconds\n", mean
    printf "  Std deviation:     %.2f seconds\n", stddev
    printf "  Jitter:            %.1f%%\n", jitter
    printf "  Connection count:  %d\n", count + 1

    if (jitter < 5 && count > 10)
        print "\n⚠️  HIGH CONFIDENCE — Very regular intervals with low jitter."
    else if (jitter < 20 && count > 5)
        print "\n⚡ MEDIUM CONFIDENCE — Somewhat regular intervals (possible jittered beacon)."
    else
        print "\n✅ LOW CONFIDENCE — Intervals appear irregular (likely normal traffic)."

    if (jitter < 20 && count > 5) {
        print ""
        print "Recommended next steps:"
        print "  1. Confirm JA4 fingerprints match across all destination IPs"
        print "  2. Investigate IP reputation for each destination (VirusTotal, AbuseIPDB)"
        print "  3. Check passive DNS history — do these IPs share a common domain?"
        print "  4. Review payload sizes for consistency across destinations"
        print "  5. Check whether activity continues outside business hours"
    }
}
'

echo ""

# Destination port distribution across all targets
echo "--- Destination Port Distribution (all targets) ---"
tshark -r "$CAPTURE_FILE" \
  -Y "${IP_FILTER}" \
  -T fields -e tcp.dstport 2>/dev/null | \
sort | uniq -c | sort -rn | head -5

echo ""
echo "========================================"
