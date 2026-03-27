#!/bin/bash
# tls_extract.sh - Extract TLS Client Hello data for fingerprint analysis
#
# Exports TLS handshake metadata to CSV for bulk analysis,
# fingerprint correlation, and unauthorized client detection.
#
# Usage: ./tls_extract.sh <capture_file.pcapng> [output_file.csv]
# Example: ./tls_extract.sh capture.pcapng tls_handshakes.csv

set -euo pipefail

CAPTURE_FILE="${1:?Usage: $0 <capture_file> [output_file.csv]}"
OUTPUT_FILE="${2:-tls_handshakes.csv}"

if [ ! -f "$CAPTURE_FILE" ]; then
    echo "Error: File '$CAPTURE_FILE' not found."
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Install with: sudo apt install tshark"
    exit 1
fi

echo "========================================"
echo "  TLS Handshake Extraction"
echo "========================================"
echo "Capture:  $CAPTURE_FILE"
echo "Output:   $OUTPUT_FILE"
echo ""

# Write CSV header
echo "timestamp,src_ip,dst_ip,dst_port,sni,tls_version,handshake_length" > "$OUTPUT_FILE"

# Extract TLS Client Hello data
tshark -r "$CAPTURE_FILE" -Y "tls.handshake.type == 1" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e ip.dst \
  -e tcp.dstport \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.version \
  -e tls.handshake.length \
  -E separator=, \
  -E quote=d \
  -E header=n 2>/dev/null >> "$OUTPUT_FILE"

TOTAL=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
echo "Extracted $TOTAL TLS Client Hello records."
echo ""

# Summary: unique SNI (Server Name Indication) values
echo "--- Top Destination Domains (by SNI) ---"
tail -n +2 "$OUTPUT_FILE" | cut -d',' -f5 | tr -d '"' | \
  sort | uniq -c | sort -rn | head -15

echo ""

# Unique destination IPs
echo "--- Unique Destination IPs ---"
tail -n +2 "$OUTPUT_FILE" | cut -d',' -f3 | tr -d '"' | \
  sort -u | head -20

echo ""

# Flag connections without SNI (potential evasion)
NO_SNI=$(tail -n +2 "$OUTPUT_FILE" | awk -F',' '$5 == "\"\"" || $5 == ""' | wc -l)
if [ "$NO_SNI" -gt 0 ]; then
    echo "⚠️  Found $NO_SNI TLS handshakes without SNI — possible evasion technique."
    echo "   These connections may be attempting to hide the destination domain."
    echo ""
    echo "   Connections without SNI:"
    tail -n +2 "$OUTPUT_FILE" | awk -F',' '$5 == "\"\"" || $5 == ""' | \
      cut -d',' -f2,3,4 | tr -d '"' | head -10
else
    echo "✅ All TLS handshakes include SNI values."
fi

echo ""
echo "Full results saved to: $OUTPUT_FILE"
echo "========================================"
