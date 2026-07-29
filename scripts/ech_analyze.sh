#!/bin/bash
# ech_analyze.sh - Analyze Encrypted Client Hello (ECH) usage in a capture
#
# ECH encrypts the Server Name Indication, removing the single most-used
# plaintext signal in TLS monitoring. This script inventories ECH adoption in a
# capture and applies the one detection that survives: a conforming ECH client
# must first fetch the server's ECHConfig from a DNS HTTPS resource record
# (type 65). A client completing ECH with no such lookup is running a hardcoded
# or out-of-band config, which no mainstream browser does.
#
# Usage:
#   ./ech_analyze.sh <capture_file.pcapng>
#
# Example:
#   ./ech_analyze.sh capture.pcapng
#
# Known limitations (read these before acting on output):
#   - DNS caching may place the HTTPS-RR lookup outside the capture window.
#     A flagged host is a lead, not a verdict.
#   - Encrypted DNS (DoH/DoQ) hides the lookup entirely. In DoH environments
#     this correlation requires resolver logs instead of passive capture.
#   - GREASE ECH means browsers emit an ECH-shaped extension on nearly every
#     Client Hello. Extension presence alone is not a signal; this script
#     reports it for inventory purposes only.
#   - ECH dissection depth varies by Wireshark version. Extension type 65037
#     (0xFE0D) is matched directly for portability across releases.

set -euo pipefail

CAPTURE_FILE="${1:?Usage: $0 <capture_file.pcapng>}"

if [ ! -f "$CAPTURE_FILE" ]; then
    echo "Error: File '$CAPTURE_FILE' not found."
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Install with: sudo apt install tshark"
    exit 1
fi

ECH_EXT_TYPE=65037          # 0xFE0D, TLS encrypted_client_hello extension
DNS_HTTPS_RR=65             # RFC 9460 HTTPS resource record

echo "========================================"
echo "  Encrypted Client Hello (ECH) Analysis"
echo "========================================"
echo "Capture:  $CAPTURE_FILE"
echo "Scanned:  $(date)"
echo ""

# --- Overall TLS posture ------------------------------------------------------

TOTAL_CH=$(tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1" \
    -T fields -e frame.number 2>/dev/null | wc -l)

ECH_CH=$(tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1 && tls.handshake.extension.type == ${ECH_EXT_TYPE}" \
    -T fields -e frame.number 2>/dev/null | wc -l)

echo "--- TLS Client Hello Inventory ---"
echo "  Total Client Hellos:        $TOTAL_CH"
echo "  Carrying ECH extension:     $ECH_CH"

if [ "$TOTAL_CH" -gt 0 ]; then
    awk -v e="$ECH_CH" -v t="$TOTAL_CH" \
        'BEGIN { printf "  ECH-extension share:        %.1f%%\n", (e/t)*100 }'
fi
echo ""
echo "  Note: includes GREASE ECH. Browsers send an ECH-shaped extension on"
echo "  nearly every handshake regardless of actual use, so this figure"
echo "  measures client capability, not confirmed ECH sessions."
echo ""

if [ "$ECH_CH" -eq 0 ]; then
    echo "No ECH-capable handshakes observed. Nothing further to analyze."
    exit 0
fi

# --- Outer SNI distribution ---------------------------------------------------
# Under ECH the visible SNI is the provider's cover name. A narrow set of
# repeated cover names is expected; anything unusual is worth a look.

echo "--- Outer SNI on ECH Handshakes ---"
echo "(Count | ClientHelloOuter server_name)"
tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1 && tls.handshake.extension.type == ${ECH_EXT_TYPE}" \
    -T fields -e tls.handshake.extensions_server_name 2>/dev/null | \
    grep -v '^$' | sort | uniq -c | sort -rn | head -15
echo ""

# --- DNS HTTPS-RR correlation -------------------------------------------------

echo "--- DNS HTTPS-RR (type 65) Lookups ---"

HTTPS_RR_HOSTS=$(mktemp)
ECH_HOSTS=$(mktemp)
trap 'rm -f "$HTTPS_RR_HOSTS" "$ECH_HOSTS"' EXIT

tshark -r "$CAPTURE_FILE" \
    -Y "dns.qry.type == ${DNS_HTTPS_RR} && dns.flags.response == 0" \
    -T fields -e ip.src 2>/dev/null | \
    grep -v '^$' | sort -u > "$HTTPS_RR_HOSTS"

RR_COUNT=$(tshark -r "$CAPTURE_FILE" \
    -Y "dns.qry.type == ${DNS_HTTPS_RR} && dns.flags.response == 0" \
    -T fields -e frame.number 2>/dev/null | wc -l)

echo "  HTTPS-RR queries observed:  $RR_COUNT"
echo "  Distinct querying hosts:    $(wc -l < "$HTTPS_RR_HOSTS")"
echo ""

tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1 && tls.handshake.extension.type == ${ECH_EXT_TYPE}" \
    -T fields -e ip.src 2>/dev/null | \
    grep -v '^$' | sort -u > "$ECH_HOSTS"

echo "--- Correlation: ECH Without HTTPS-RR Lookup ---"

ORPHANS=$(comm -23 "$ECH_HOSTS" "$HTTPS_RR_HOSTS")

if [ -z "$ORPHANS" ]; then
    echo "  None. Every ECH-capable host also performed HTTPS-RR lookups."
    echo "  This is the expected result for normal browser traffic."
else
    echo "  The following hosts presented ECH handshakes with no HTTPS-RR"
    echo "  query in this capture:"
    echo ""
    echo "$ORPHANS" | sed 's/^/    - /'
    echo ""
    echo "  Interpretation: a conforming client cannot build a ClientHelloInner"
    echo "  without an ECHConfig, and that config is published in the HTTPS RR."
    echo "  A host doing ECH without the lookup holds a hardcoded config."
    echo ""
    echo "  Before escalating, rule out the benign explanations:"
    echo "    1. DNS caching placed the lookup before the capture started"
    echo "    2. The host uses DoH/DoQ, hiding the query from this capture"
    echo "    3. TLS session resumption reused an earlier config"
    echo ""
    echo "  Recommended next steps:"
    echo "    1. Re-capture over a longer window to rule out cache effects"
    echo "    2. Check whether the host has DoH configured"
    echo "    3. Run beacon_detect.sh against the destination — behavioural"
    echo "       analysis is unaffected by ECH and remains fully available"
    echo "    4. Extract the JA4 and compare against known-good browser"
    echo "       fingerprints (see pq_readiness.sh)"
fi

echo ""
echo "========================================"
