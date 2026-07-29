#!/bin/bash
# pq_readiness.sh - Inventory post-quantum TLS key agreement in a capture
#
# Two purposes, one pass:
#
#   1. Posture. Which clients on this network offer hybrid post-quantum key
#      agreement? Harvest-now-decrypt-later means today's classical-only
#      sessions are tomorrow's plaintext, so knowing the gap is an asset.
#
#   2. Detection, inverted. Hybrid ML-KEM is now default in mainstream
#      browsers and widely negotiated by the major CDNs. Malware TLS stacks
#      lag — implants on older static OpenSSL or bespoke TLS cannot offer PQ
#      groups. A client whose JA4 claims a browser identity but which omits
#      X25519MLKEM768 is presenting a capability profile inconsistent with its
#      fingerprint. Unusually, this detection strengthens as PQ adoption rises.
#
# Usage:
#   ./pq_readiness.sh <capture_file.pcapng>
#
# Example:
#   ./pq_readiness.sh capture.pcapng
#
# Note on JA4: the tls.handshake.ja4 field requires Wireshark 4.2 or later.
# On older builds the JA4 column is reported as unavailable and the posture
# inventory still runs.

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

# IANA TLS Supported Groups (draft-ietf-tls-ecdhe-mlkem)
PQ_X25519_MLKEM768=4588     # 0x11EC - the group browsers and CDNs negotiate
PQ_SECP256R1_MLKEM768=4587  # 0x11EB - FIPS-oriented alternative
PQ_SECP384R1_MLKEM1024=4589 # 0x11ED
PQ_LEGACY_KYBER=25497       # 0x6399 - obsolete pre-standard X25519Kyber768Draft00

PQ_FILTER="tls.handshake.extensions_supported_group == ${PQ_X25519_MLKEM768} \
|| tls.handshake.extensions_supported_group == ${PQ_SECP256R1_MLKEM768} \
|| tls.handshake.extensions_supported_group == ${PQ_SECP384R1_MLKEM1024} \
|| tls.handshake.extensions_supported_group == ${PQ_LEGACY_KYBER}"

echo "========================================"
echo "  Post-Quantum TLS Readiness Report"
echo "========================================"
echo "Capture:  $CAPTURE_FILE"
echo "Scanned:  $(date)"
echo ""

TOTAL_CH=$(tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1" \
    -T fields -e frame.number 2>/dev/null | wc -l)

if [ "$TOTAL_CH" -eq 0 ]; then
    echo "No TLS Client Hello messages in this capture."
    exit 0
fi

PQ_CH=$(tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1 && (${PQ_FILTER})" \
    -T fields -e frame.number 2>/dev/null | wc -l)

echo "--- Adoption Summary ---"
echo "  Total Client Hellos:            $TOTAL_CH"
echo "  Offering a hybrid PQ group:     $PQ_CH"
echo "  Classical-only:                 $((TOTAL_CH - PQ_CH))"
awk -v p="$PQ_CH" -v t="$TOTAL_CH" \
    'BEGIN { printf "  PQ-capable share:               %.1f%%\n", (p/t)*100 }'
echo ""

# --- Group breakdown ----------------------------------------------------------

echo "--- Hybrid Group Distribution ---"
for pair in "${PQ_X25519_MLKEM768}:X25519MLKEM768" \
            "${PQ_SECP256R1_MLKEM768}:SecP256r1MLKEM768" \
            "${PQ_SECP384R1_MLKEM1024}:SecP384r1MLKEM1024" \
            "${PQ_LEGACY_KYBER}:X25519Kyber768Draft00 (obsolete)"; do
    code="${pair%%:*}"
    name="${pair#*:}"
    count=$(tshark -r "$CAPTURE_FILE" \
        -Y "tls.handshake.type == 1 && tls.handshake.extensions_supported_group == ${code}" \
        -T fields -e frame.number 2>/dev/null | wc -l)
    printf "  %-40s %s\n" "$name ($code)" "$count"
done
echo ""

# --- Classical-only clients by source -----------------------------------------

echo "--- Classical-Only Clients by Source Host ---"
echo "(Count | Source IP)"
tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1 && !(${PQ_FILTER})" \
    -T fields -e ip.src 2>/dev/null | \
    grep -v '^$' | sort | uniq -c | sort -rn | head -15
echo ""

# --- Fingerprint / capability mismatch ----------------------------------------

echo "--- Fingerprint vs Capability Mismatch ---"

JA4_SAMPLE=$(tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1" \
    -T fields -e tls.handshake.ja4 2>/dev/null | grep -cv '^$' || true)

if [ "$JA4_SAMPLE" -eq 0 ]; then
    echo "  JA4 unavailable in this Wireshark build (requires 4.2+)."
    echo "  Skipping mismatch analysis; posture inventory above is unaffected."
else
    echo "  Clients presenting a browser-shaped JA4 (t13d prefix) while"
    echo "  offering no post-quantum group:"
    echo ""
    echo "  (Count | Source IP | JA4 | Outer SNI)"

    MISMATCHES=$(tshark -r "$CAPTURE_FILE" \
        -Y "tls.handshake.type == 1 && tls.handshake.ja4 matches \"^t13d\" && !(${PQ_FILTER})" \
        -T fields -e ip.src -e tls.handshake.ja4 -e tls.handshake.extensions_server_name \
        -E separator=, 2>/dev/null | grep -v '^,,$' | sort | uniq -c | sort -rn | head -10 || true)

    if [ -z "$MISMATCHES" ]; then
        echo "    None found."
    else
        echo "$MISMATCHES"
        echo ""
        echo "  A t13d-prefixed JA4 indicates a TLS 1.3 client with a"
        echo "  browser-like extension profile. Offering no PQ group is"
        echo "  inconsistent with a current browser build."
        echo ""
        echo "  Rule out first — these cover most real occurrences:"
        echo "    1. TLS-inspection proxy rewriting the Client Hello and"
        echo "       stripping PQ groups (largest expected cause)"
        echo "    2. Genuinely unpatched or EOL endpoint — check asset inventory"
        echo "    3. Browser automation framework with a bundled older stack"
        echo "    4. Embedded browser engine inside a desktop application"
        echo ""
        echo "  If none apply, treat as a candidate JA4-spoofing implant and"
        echo "  pivot to beacon_detect.sh against the destination."
    fi
fi

echo ""
echo "========================================"
