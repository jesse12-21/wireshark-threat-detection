#!/bin/bash
# dns_tunnel_detect.sh - Flag potential DNS tunneling in packet captures
#
# Usage: ./dns_tunnel_detect.sh <capture_file.pcapng> [threshold]
# Example: ./dns_tunnel_detect.sh capture.pcapng 50

set -euo pipefail

CAPTURE_FILE="${1:?Usage: $0 <capture_file> [threshold]}"
THRESHOLD="${2:-50}"

if [ ! -f "$CAPTURE_FILE" ]; then
    echo "Error: File '$CAPTURE_FILE' not found."
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Install with: sudo apt install tshark"
    exit 1
fi

echo "========================================"
echo "  DNS Tunneling Detection Report"
echo "========================================"
echo "Capture:   $CAPTURE_FILE"
echo "Threshold: domain names longer than $THRESHOLD characters"
echo "Scan time: $(date)"
echo ""

ALERT_COUNT=0

tshark -r "$CAPTURE_FILE" -Y "dns.qry.name.len > $THRESHOLD && dns.flags.response == 0" \
  -T fields -e frame.time_relative -e ip.src -e dns.qry.name -e dns.qry.type \
  -E separator="|" 2>/dev/null | while IFS="|" read -r timestamp src domain qtype; do
    ALERT_COUNT=$((ALERT_COUNT + 1))
    echo "[ALERT] Time: ${timestamp}s into capture"
    echo "  Source:      $src"
    echo "  Query:       $domain"
    echo "  Query Type:  $qtype"
    echo "  Name Length: $(echo -n "$domain" | wc -c) chars"
    echo ""
done

# Summary statistics
TOTAL_SUSPICIOUS=$(tshark -r "$CAPTURE_FILE" \
  -Y "dns.qry.name.len > $THRESHOLD && dns.flags.response == 0" \
  -T fields -e dns.qry.name 2>/dev/null | wc -l)

TOTAL_DNS=$(tshark -r "$CAPTURE_FILE" \
  -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name 2>/dev/null | wc -l)

TOTAL_TXT=$(tshark -r "$CAPTURE_FILE" \
  -Y "dns.qry.type == 16 && dns.flags.response == 0" \
  -T fields -e dns.qry.name 2>/dev/null | wc -l)

echo "========================================"
echo "  Summary"
echo "========================================"
echo "  Total DNS queries:        $TOTAL_DNS"
echo "  Suspicious (long names):  $TOTAL_SUSPICIOUS"
echo "  TXT record queries:       $TOTAL_TXT"

if [ "$TOTAL_DNS" -gt 0 ]; then
    RATIO=$(echo "scale=1; $TOTAL_SUSPICIOUS * 100 / $TOTAL_DNS" | bc 2>/dev/null || echo "N/A")
    echo "  Suspicious ratio:         ${RATIO}%"
fi

echo ""
if [ "$TOTAL_SUSPICIOUS" -gt 10 ]; then
    echo "⚠️  HIGH — Significant DNS tunneling indicators detected. Investigate immediately."
elif [ "$TOTAL_SUSPICIOUS" -gt 0 ]; then
    echo "⚡ MEDIUM — Some suspicious queries found. Review the flagged domains."
else
    echo "✅ LOW — No obvious DNS tunneling indicators in this capture."
fi
echo ""

# List unique suspicious domains
if [ "$TOTAL_SUSPICIOUS" -gt 0 ]; then
    echo "Unique suspicious base domains:"
    tshark -r "$CAPTURE_FILE" \
      -Y "dns.qry.name.len > $THRESHOLD && dns.flags.response == 0" \
      -T fields -e dns.qry.name 2>/dev/null | \
      awk -F'.' '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -10
fi
