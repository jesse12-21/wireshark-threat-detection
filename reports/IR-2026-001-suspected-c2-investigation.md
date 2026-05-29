# Investigation Report: IR-2026-001
## Suspected DNS Tunneling and HTTPS Beaconing from Host 10.0.2.15

| Field | Value |
|---|---|
| **Case ID** | IR-2026-001 |
| **Date** | 2026-05-15 |
| **Analyst** | jesse12-21 |
| **Severity** | High |
| **Status** | Confirmed — Recommended for Containment |
| **Capture Window** | 2026-05-15 14:32:18 – 14:37:30 UTC (312 seconds) |
| **Source Host** | 10.0.2.15 (lab VM, Ubuntu 24.04) |
| **Suspected C2 Destination** | 198.51.100.42 (no resolved hostname) |
| **Suspected DNS Exfil Channel** | `*.exfil-test.lab` |

> **Environment note:** This investigation was conducted in a controlled lab environment. The "victim" host is a VirtualBox VM, and the destination IPs and domains use IETF-reserved documentation ranges (RFC 5737, RFC 2606). The methodology, scripts, and findings are real; the targets are synthetic. This document demonstrates an end-to-end investigation workflow using the project's automation scripts.

---

## Executive Summary

Routine analysis of a 5-minute packet capture from the lab perimeter surfaced two independent indicators of compromise on internal host **10.0.2.15**:

1. **High-volume, high-entropy DNS TXT queries** to a single base domain (`exfil-test.lab`) — 47 queries averaging 78 characters with no benign explanation, consistent with DNS tunneling for data exfiltration.
2. **Regular-interval HTTPS connections** to an external IP (`198.51.100.42`) with a jitter of 3.2% — strongly suggestive of automated C2 beaconing.

Correlation revealed that the HTTPS connections also **lacked SNI values**, an evasion behavior not typical of normal browser or system traffic. The combined indicators support a **high-confidence assessment of active command-and-control compromise**, and containment is recommended.

---

## Detection Trigger

The investigation began when a scheduled run of `dns_tunnel_detect.sh` against the daily capture file returned a HIGH severity result.

```bash
./scripts/dns_tunnel_detect.sh capture_2026-05-15.pcapng 50
```

```
========================================
  Summary
========================================
  Total DNS queries:        342
  Suspicious (long names):  47
  TXT record queries:       47
  Suspicious ratio:         13.7%

⚠️  HIGH — Significant DNS tunneling indicators detected. Investigate immediately.

Unique suspicious base domains:
     47 exfil-test.lab
```

**Initial observations from the trigger:**

- All 47 suspicious queries share a single base domain (`exfil-test.lab`), which is not present in any legitimate browsing history for this host.
- All 47 are **TXT record queries** — TXT records can carry larger payloads than A or AAAA records, making them a preferred vector for DNS tunneling.
- A 13.7% ratio of long-name queries is well above any normal baseline. Typical CDN and tracking lookups push this metric well under 1% on production endpoints.

---

## Investigation Timeline

### Step 1 — Triage the DNS alert (14:32 UTC)

Inspecting individual flagged queries showed a consistent encoding pattern: a high-entropy base32-like prefix followed by a fixed suffix.

```
[ALERT] Time: 12.45s into capture
  Source:      10.0.2.15
  Query:       aXjksRnsKfgPqLmNoTyUvWcXdEf.data-relay.exfil-test.lab
  Query Type:  16
  Name Length: 78 chars

[ALERT] Time: 18.92s into capture
  Source:      10.0.2.15
  Query:       bYklsTotLghQrMnOpUvWxYzAbCd.data-relay.exfil-test.lab
  Query Type:  16
  Name Length: 78 chars
```

The prefixes are uniform-length, non-dictionary, high-entropy strings — consistent with **base32-encoded payload chunks**. DNS labels are limited to 63 characters and are case-insensitive, which makes base32 a natural encoding choice for tunneled data. The matching suffix on every query (`data-relay.exfil-test.lab`) indicates a single tunneling channel rather than scattered noise.

**Pivot points identified:** source host `10.0.2.15`; suspicious external base domain `exfil-test.lab`.

### Step 2 — Inventory TLS traffic from the same host (14:33 UTC)

DNS exfiltration is often accompanied by an HTTPS C2 channel — DNS for slow, covert data extraction; HTTPS for command-and-control instructions. To check, I extracted all TLS Client Hellos from the same capture:

```bash
./scripts/tls_extract.sh capture_2026-05-15.pcapng tls_2026-05-15.csv
```

```
Extracted 89 TLS Client Hello records.

--- Top Destination Domains (by SNI) ---
     34 www.google.com
     22 duckduckgo.com
     12 github.com
      6 ubuntu.com
      4 mozilla.org

⚠️  Found 11 TLS handshakes without SNI — possible evasion technique.

   Connections without SNI:
   10.0.2.15,198.51.100.42,443
   10.0.2.15,198.51.100.42,443
   10.0.2.15,198.51.100.42,443
   [... 8 more, all to 198.51.100.42:443 ...]
```

**This is the pivot.** Out of 89 TLS handshakes in the capture, 11 had no SNI value — and **all 11 went to the same destination**, `198.51.100.42:443`.

Normal browser and updater traffic always includes SNI. The consistent absence of SNI on every connection to a single external IP strongly suggests the client is connecting **by hardcoded IP** rather than via a domain name lookup — characteristic of malware with embedded C2 addresses, or an evasion-aware client deliberately stripping SNI.

**Cross-reference checks:**
- `198.51.100.42` does **not** resolve via reverse DNS.
- The IP does **not** appear in the SNI list of any other handshake in the capture.
- No legitimate process on the lab baseline has a documented reason to make IP-direct HTTPS connections.

**New pivot point:** suspected C2 IP `198.51.100.42`.

### Step 3 — Confirm beaconing behavior (14:34 UTC)

If `198.51.100.42` is a C2 server, the 11 connections to it should exhibit beaconing characteristics: regular intervals with low jitter.

```bash
./scripts/beacon_detect.sh capture_2026-05-15.pcapng 198.51.100.42
```

```
Total SYN packets to 198.51.100.42: 11
Capture duration for this host: 312s

--- Connection Interval Distribution ---
(Count | Interval in seconds)

      4 30
      3 31
      2 29
      1 32

--- Statistical Summary ---
  Mean interval:     30.20 seconds
  Std deviation:     0.98 seconds
  Jitter:            3.2%
  Connection count:  11

⚠️  HIGH CONFIDENCE — Very regular intervals with low jitter.

--- Destination Port Distribution ---
     11 443
```

**Confirmed.** Eleven connections over 312 seconds at a mean interval of 30.20 seconds with a standard deviation of 0.98 seconds produces a **jitter of 3.2%** — well inside the "very regular" HIGH-confidence threshold. The destination port is exclusively 443 across all 11 connections, consistent with the SNI-less HTTPS observations from Step 2.

A 30-second beacon interval with low single-digit jitter is the default configuration profile for several common offensive frameworks. This is not the timing signature of normal user-driven web browsing.

---

## Correlation Summary

The three independent detections describe a single coherent activity pattern on host 10.0.2.15:

| Channel | Destination | Indicator | Volume | Time Window |
|---|---|---|---|---|
| DNS (TXT) | `*.exfil-test.lab` | High-entropy 78-char queries | 47 queries | Throughout 312s capture |
| HTTPS | `198.51.100.42` | SNI-less Client Hellos | 11 handshakes | Throughout 312s capture |
| HTTPS | `198.51.100.42` | Regular 30s SYN intervals | 11 connections, 3.2% jitter | Throughout 312s capture |

The DNS exfiltration rate (~9 queries/minute) and beacon cadence (one connection per ~30 seconds) are consistent with **a single agent on 10.0.2.15 maintaining two parallel channels** — a common dual-channel C2 design where DNS handles low-bandwidth covert exfiltration and HTTPS handles command receipt.

---

## MITRE ATT&CK Mapping

| Observed Behavior | Technique | ID | Tactic |
|---|---|---|---|
| Long TXT-record DNS queries to single base domain | Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Command and Control |
| Encoded payload in DNS subdomain labels | Exfiltration Over Unencrypted Non-C2 Protocol | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration |
| Encoding data inside DNS labels | Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | Command and Control |
| HTTPS with stripped SNI | Encrypted Channel: Asymmetric Cryptography | [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Command and Control |
| Regular-interval connections to fixed IP | Scheduled Transfer | [T1029](https://attack.mitre.org/techniques/T1029/) | Exfiltration |
| Hardcoded C2 IP (no DNS resolution for destination) | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Command and Control |

---

## Confidence Assessment

**Overall: HIGH (≥90%)**

Three independent indicators — high-volume long-name DNS queries, SNI-less HTTPS handshakes, and low-jitter beacon timing — all originate from the same internal host within the same time window, in a configuration that has no benign explanation. The probability of any single indicator appearing in normal operation is low; the probability of all three appearing simultaneously by coincidence is effectively zero.

The single piece of evidence that would change this assessment: identifying a legitimate application installed on 10.0.2.15 with a documented reason to (a) issue many TXT queries to an external `.lab` domain, (b) connect to a raw IP without SNI, and (c) do so at a strict 30-second interval. No such application is in the lab baseline.

---

## Recommended Actions

### Immediate (within 1 hour)

1. **Isolate host 10.0.2.15** from the network. In this lab, that means a VM-level network detach; in production, the equivalent is host-based EDR isolation or VLAN quarantine.
2. **Block egress to `198.51.100.42`** at the perimeter for all ports.
3. **Sinkhole or block** DNS resolution for `*.exfil-test.lab`.

### Short-term (within 24 hours)

4. **Acquire host artifacts** from 10.0.2.15: running process list, autoruns/scheduled tasks, current network connection state, recent file system modifications, and browser history. Look for the agent binary and its persistence mechanism.
5. **Threat-hunt across the broader environment** for the same indicators on other hosts:
   - Any host issuing TXT queries averaging more than 50 characters
   - Any host with multiple SNI-less HTTPS handshakes to a single external IP
   - Any host with sub-5% jitter beacons to external destinations

### Longer-term (within 1 week)

6. **Add Sigma detection rules** for these three patterns to the SIEM / detection pipeline (long-DNS-query, no-SNI-TLS, low-jitter-beacon) — tracked in project future work.
7. **Capture and fingerprint** the JA4 of the malicious client's TLS handshakes to add a fast-path detection for the same family.
8. **Review the lab perimeter logs** for the 7 days preceding this capture for prior occurrences of the same indicators.

---

## Detection Gap Analysis

What this investigation reveals about detection coverage:

- ✅ **DNS query length and TXT volume** were effective primary detections.
- ✅ **SNI-less TLS handshakes** were a high-value pivot indicator that quickly narrowed the suspect destination IP.
- ✅ **Statistical beacon analysis** confirmed the C2 channel with quantitative confidence rather than binary heuristics.
- ⚠️ **DNS-over-HTTPS (DoH)** or **DNS-over-QUIC (DoQ)** would have bypassed the DNS detection entirely. A production deployment of this methodology should add detection for DoH/DoQ traffic to non-corporate resolvers.
- ⚠️ **Single-IP beacon analysis** assumes the C2 doesn't use DNS round-robin or fast-flux. Multi-IP correlation is required for more sophisticated adversaries — extending `beacon_detect.sh` to accept a comma-separated IP set is the planned next iteration.
- ⚠️ **No payload inspection** was performed; the TLS content remains encrypted. JA4 fingerprinting (Part 4) would add an additional client-identification layer that survives encryption.

---

## Lessons Learned

1. **Composability of detection tooling matters.** No single script produced a high-confidence verdict on its own; the chain of three (DNS → TLS → timing) did. Detection tools should produce structured, pivot-ready output (source IP, destination IP, base domain) rather than just alert text.
2. **SNI absence is an underused detection.** It requires only a single tshark filter (`tls.handshake.type == 1 && !tls.handshake.extensions_server_name`) and catches a class of evasion that bypasses domain-based blocking entirely.
3. **Quantitative confidence beats binary alerts.** Reporting `jitter = 3.2%` gives an analyst (or a downstream SOAR playbook) something to threshold on and tune. A bare "BEACON DETECTED" alert forces a re-investigation every time and produces no usable signal for automation.
4. **Dual-channel C2 is increasingly common.** Adversaries deliberately split exfiltration and command across DNS and HTTPS to evade single-protocol detection. Investigations should always inventory both channels even when only one fired the initial alert.

---

*Investigation conducted as part of the [Network Threat Detection lab project](../README.md). Scripts referenced are available in [`/scripts/`](../scripts/). All target IPs and domains are within IETF-reserved documentation ranges and represent simulated, not actual, adversary infrastructure.*
