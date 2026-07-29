#!/bin/bash
# ai_egress_inventory.sh - Inventory AI/LLM egress traffic in a capture
#
# Two network-visible surfaces that barely existed when most network-detection
# tooling was designed:
#
#   1. LLM inference APIs. The prompt field is an unmonitored egress channel.
#      A user or implant can submit an entire repository, customer table, or
#      credential store in a request body, and to conventional DLP it looks
#      like an ordinary HTTPS POST. Without content inspection, byte volume in
#      the originator direction is the strongest available signal.
#
#   2. MCP servers. Model Context Protocol connects assistants to external
#      tools. Reaching an untrusted server grants it influence over what the
#      assistant does with the data it can access. Endpoint scanners exist;
#      network-layer visibility into which servers hosts actually reach is
#      largely unmonitored.
#
# Usage:
#   ./ai_egress_inventory.sh <capture_file.pcapng> [upload_threshold_bytes]
#
# Example:
#   ./ai_egress_inventory.sh capture.pcapng 5242880
#
# Default upload threshold: 10 MB. Interactive chat produces tens of kilobytes
# per session; agentic coding assistants legitimately produce far more, which
# is the dominant false positive here.
#
# Limitation: destination identification relies on SNI. As ECH adoption grows,
# SNI-based classification degrades — the same shift documented in
# ech_analyze.sh. Where SNI is unavailable, fall back to destination IP and
# ASN. This is a coverage gap, stated rather than papered over.

set -euo pipefail

CAPTURE_FILE="${1:?Usage: $0 <capture_file.pcapng> [upload_threshold_bytes]}"
UPLOAD_THRESHOLD="${2:-10485760}"

if [ ! -f "$CAPTURE_FILE" ]; then
    echo "Error: File '$CAPTURE_FILE' not found."
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Install with: sudo apt install tshark"
    exit 1
fi

# Extend from your own egress baseline; this list is a starting point, not a
# complete enumeration of inference providers.
LLM_DOMAINS=(
    "api.openai.com"
    "api.anthropic.com"
    "generativelanguage.googleapis.com"
    "api.mistral.ai"
    "api.cohere.ai"
    "api.together.xyz"
    "api.groq.com"
    "api.deepseek.com"
    "api.x.ai"
)

echo "========================================"
echo "  AI / LLM Egress Inventory"
echo "========================================"
echo "Capture:          $CAPTURE_FILE"
echo "Upload threshold: $UPLOAD_THRESHOLD bytes"
echo "Scanned:          $(date)"
echo ""

# --- LLM API sessions by SNI --------------------------------------------------

echo "--- LLM Inference API Sessions ---"

SNI_DUMP=$(mktemp)
trap 'rm -f "$SNI_DUMP"' EXIT

tshark -r "$CAPTURE_FILE" \
    -Y "tls.handshake.type == 1" \
    -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name \
    -E separator=, 2>/dev/null | grep -v ',,$' > "$SNI_DUMP" || true

FOUND_ANY=0
for domain in "${LLM_DOMAINS[@]}"; do
    count=$(grep -c ",${domain}$" "$SNI_DUMP" || true)
    if [ "$count" -gt 0 ]; then
        FOUND_ANY=1
        printf "  %-40s %s session(s)\n" "$domain" "$count"
    fi
done

if [ "$FOUND_ANY" -eq 0 ]; then
    echo "  No sessions to known LLM inference endpoints observed."
fi
echo ""

# --- Source hosts reaching LLM endpoints --------------------------------------

if [ "$FOUND_ANY" -eq 1 ]; then
    echo "--- Source Hosts Reaching LLM Endpoints ---"
    echo "(Count | Source IP)"
    for domain in "${LLM_DOMAINS[@]}"; do
        grep ",${domain}$" "$SNI_DUMP" || true
    done | cut -d',' -f1 | sort | uniq -c | sort -rn
    echo ""
    echo "  Compare against your sanctioned-AI host list. Sessions from"
    echo "  outside it are shadow-AI usage worth a conversation, not"
    echo "  necessarily an incident."
    echo ""
fi

# --- Upload volume analysis ---------------------------------------------------

echo "--- Request-Direction Volume to LLM Endpoints ---"

if [ "$FOUND_ANY" -eq 0 ]; then
    echo "  No LLM sessions to measure."
else
    echo "  (Bytes sent | Source -> Destination IP)"
    echo ""

    LLM_IPS=$(for domain in "${LLM_DOMAINS[@]}"; do
        grep ",${domain}$" "$SNI_DUMP" || true
    done | cut -d',' -f2 | sort -u)

    if [ -n "$LLM_IPS" ]; then
        for dst in $LLM_IPS; do
            bytes=$(tshark -r "$CAPTURE_FILE" \
                -Y "ip.dst == ${dst} && tcp.len > 0" \
                -T fields -e tcp.len 2>/dev/null | \
                awk '{ s += $1 } END { print s+0 }')

            src=$(grep ",${dst}," "$SNI_DUMP" | head -1 | cut -d',' -f1)

            printf "  %-14s %s -> %s\n" "$bytes" "${src:-unknown}" "$dst"

            if [ "$bytes" -ge "$UPLOAD_THRESHOLD" ]; then
                echo "      HIGH VOLUME - exceeds threshold. Possible bulk"
                echo "      submission of documents or source code. Check"
                echo "      whether an agentic coding assistant explains it"
                echo "      before treating as exfiltration."
            fi
        done
    fi
fi
echo ""

# --- MCP server connections ---------------------------------------------------

echo "--- Model Context Protocol (MCP) Indicators ---"

MCP_HITS=$(tshark -r "$CAPTURE_FILE" \
    -Y 'http.request && (http.request.uri contains "/mcp" || http.request.uri contains "/sse" || http.request.uri contains "jsonrpc")' \
    -T fields -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri \
    -E separator=' | ' 2>/dev/null || true)

SSE_HITS=$(tshark -r "$CAPTURE_FILE" \
    -Y 'http.content_type contains "text/event-stream"' \
    -T fields -e ip.src -e ip.dst -e http.host \
    -E separator=' | ' 2>/dev/null || true)

if [ -z "$MCP_HITS" ] && [ -z "$SSE_HITS" ]; then
    echo "  No cleartext MCP indicators observed."
    echo ""
    echo "  Coverage note: this only sees the Streamable HTTP transport in"
    echo "  cleartext. The stdio transport is local-only and produces no"
    echo "  network artifacts. TLS-wrapped MCP requires proxy logs or"
    echo "  decryption. Absence of findings here is not absence of MCP use."
else
    if [ -n "$MCP_HITS" ]; then
        echo "  MCP endpoint requests:"
        echo "$MCP_HITS" | sed 's/^/    /'
        echo ""
    fi
    if [ -n "$SSE_HITS" ]; then
        echo "  Server-Sent Events streams (MCP Streamable HTTP transport):"
        echo "$SSE_HITS" | sed 's/^/    /' | sort -u
        echo ""
    fi
    echo "  Validate each destination against your approved MCP server list."
    echo "  Note that /sse and /messages are generic paths used by non-MCP"
    echo "  applications; confirm with the JSON-RPC indicator or user agent"
    echo "  before escalating."
fi

echo ""
echo "--- Note on Beacon Analysis ---"
echo "  Agentic tool-use traffic is periodic and can resemble C2 beaconing."
echo "  It differs in payload-size variance: agent traffic is bursty and"
echo "  irregular in size, while beacons are uniform. Before treating a"
echo "  periodic AI-endpoint connection as C2, check size distribution with:"
echo "    tshark -r <capture> -Y \"ip.dst == <IP> && tcp.len > 0\" -T fields -e tcp.len | sort -n | uniq -c"
echo ""
echo "========================================"
