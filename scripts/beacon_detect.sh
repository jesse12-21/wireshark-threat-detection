#!/bin/bash
# beacon_detect.sh - Identify potential C2 beaconing behavior
#
# Analyzes connection timing to a target IP to detect regular intervals
# that may indicate command-and-control beaconing.
#
# Usage: ./beacon_detect.sh <capture_file.pcapng> <target_ip>
# Example: ./beacon_detect.sh capture.pcapng 198.51.100.42

set -euo pipefail

CAPTURE_FILE="${1:?Usage: $0 <capture_file> <target_ip>}"
TARGET_IP="${2:?Usage: $0 <capture_file> <target_ip>}"

if [ ! -f "$CAPTURE_FILE" ]; then
    echo "Error: File '$CAPTURE_FILE' not found."
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Install with: sudo apt install tshark"
    exit 1
fi

echo "========================================"
echo "  C2 Beacon Analysis Report"
echo "========================================"
echo "Capture:    $CAPTURE_FILE"
echo "Target IP:  $TARGET_IP"
echo "Scan time:  $(date)"
echo ""

# Count total connections (SYN packets) to the target
TOTAL_SYNS=$(tshark -r "$CAPTURE_FILE" \
  -Y "ip.dst == $TARGET_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | wc -l)

echo "Total SYN packets to $TARGET_IP: $TOTAL_SYNS"
echo ""

if [ "$TOTAL_SYNS" -lt 3 ]; then
    echo "Not enough connections to perform interval analysis (need at least 3)."
    exit 0
fi

# Calculate time span
FIRST_TS=$(tshark -r "$CAPTURE_FILE" \
  -Y "ip.dst == $TARGET_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | head -1)

LAST_TS=$(tshark -r "$CAPTURE_FILE" \
  -Y "ip.dst == $TARGET_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | tail -1)

DURATION=$(echo "$LAST_TS - $FIRST_TS" | bc 2>/dev/null || echo "0")
echo "Capture duration for this host: ${DURATION}s"
echo ""

# Interval analysis
echo "--- Connection Interval Distribution ---"
echo "(Count | Interval in seconds)"
echo ""

tshark -r "$CAPTURE_FILE" \
  -Y "ip.dst == $TARGET_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.time_epoch 2>/dev/null | \
awk 'NR > 1 { printf "%.0f\n", $1 - prev } { prev = $1 }' | \
sort -n | uniq -c | sort -rn | head -15

echo ""

# Statistical analysis
echo "--- Statistical Summary ---"

tshark -r "$CAPTURE_FILE" \
  -Y "ip.dst == $TARGET_IP && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
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

    # Calculate standard deviation
    for (i = 1; i <= count; i++) {
        diff = intervals[i] - mean
        sq_sum += diff * diff
    }
    stddev = sqrt(sq_sum / count)

    # Calculate jitter percentage
    if (mean > 0) jitter = (stddev / mean) * 100

    printf "  Mean interval:     %.2f seconds\n", mean
    printf "  Std deviation:     %.2f seconds\n", stddev
    printf "  Jitter:            %.1f%%\n", jitter
    printf "  Connection count:  %d\n", count + 1

    # Beacon likelihood assessment
    if (jitter < 5 && count > 10)
        print "\n⚠️  HIGH CONFIDENCE — Very regular intervals with low jitter."
    else if (jitter < 20 && count > 5)
        print "\n⚡ MEDIUM CONFIDENCE — Somewhat regular intervals (possible jittered beacon)."
    else
        print "\n✅ LOW CONFIDENCE — Intervals appear irregular (likely normal traffic)."

    if (jitter < 20 && count > 5) {
        print ""
        print "Recommended next steps:"
        print "  1. Check JA4 fingerprint of TLS handshakes to this IP"
        print "  2. Investigate the destination IP reputation (VirusTotal, AbuseIPDB)"
        print "  3. Review payload sizes for consistency"
        print "  4. Check if traffic occurs outside business hours"
    }
}
'

echo ""

# Port analysis
echo "--- Destination Port Distribution ---"
tshark -r "$CAPTURE_FILE" \
  -Y "ip.dst == $TARGET_IP" \
  -T fields -e tcp.dstport 2>/dev/null | \
sort | uniq -c | sort -rn | head -5

echo ""
echo "========================================"
