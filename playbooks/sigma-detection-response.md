# Sigma Detection Response Playbook

Standard analyst response procedures for the four Sigma detection rules in this project. Use this document as a runbook: when an alert fires, navigate to the matching playbook section and follow the phases in order.

| Playbook | Triggering Rule | Severity | Est. Triage |
|---|---|---|---|
| [**PB-01**](#pb-01--dns-tunneling-anomalously-long-query-name) | [`dns_long_query.yml`](../detections/sigma/dns_long_query.yml) | Medium | 10-15 min |
| [**PB-02**](#pb-02--dns-tunneling-high-volume-txt-queries) | [`dns_txt_high_volume.yml`](../detections/sigma/dns_txt_high_volume.yml) | High | 15-20 min |
| [**PB-03**](#pb-03--tls-client-hello-without-sni-superseded) | [`tls_no_sni_external.yml`](../detections/sigma/tls_no_sni_external.yml) | *Superseded* | — |
| [**PB-04**](#pb-04--https-beaconing-pattern) | [`https_beacon_pattern.yml`](../detections/sigma/https_beacon_pattern.yml) | High | 15-20 min |
| [**PB-05**](#pb-05--ech-session-without-dns-https-rr-lookup) | [`tls_ech_without_dns_config.yml`](../detections/sigma/tls_ech_without_dns_config.yml) | High | 15-20 min |
| [**PB-06**](#pb-06--browser-fingerprint-without-post-quantum-key-share) | [`tls_missing_pq_keyshare.yml`](../detections/sigma/tls_missing_pq_keyshare.yml) | Medium | 10-15 min |
| [**PB-07**](#pb-07--llm-api-egress-and-high-volume-upload) | [`llm_api_egress_unsanctioned.yml`](../detections/sigma/llm_api_egress_unsanctioned.yml) | Medium | 10-20 min |
| [**PB-08**](#pb-08--mcp-server-connection-to-external-host) | [`mcp_server_connection.yml`](../detections/sigma/mcp_server_connection.yml) | Medium | 10-15 min |

---

## How to Use This Playbook

Each playbook follows a three-phase structure:

- **Phase 1 — Initial Triage** (≤5 min): Rule out obvious false positives. If the alert clears here, document and close.
- **Phase 2 — Investigation** (5-15 min): Enrich, correlate, pivot. The goal is a confidence verdict.
- **Phase 3 — Containment & Response**: Actions if the verdict is malicious. May require escalation.

A **decision tree** at the end of each playbook maps verdicts to next actions. A **closure checklist** specifies what must be documented before closing the case.

### Severity definitions

| Severity | Meaning | Response window |
|---|---|---|
| **Critical** | Confirmed compromise; active exfiltration likely | Immediate (< 1 hr containment) |
| **High** | Strong indicator with limited benign explanation | Same day (< 4 hr triage) |
| **Medium** | Suspicious pattern with plausible benign causes | Same business day |
| **Low** | Anomaly worth recording, low priority | Within 1 week |

### Roles

These playbooks assume a tiered SOC. Tier 1 handles Phases 1 and 2; Phase 3 actions tagged **(T2/IR)** require Tier 2 or Incident Response escalation. In a lab or solo environment, the same analyst plays both roles — but the phase boundary still defines a useful checkpoint for re-validating findings.

### Common enrichment sources

All playbooks below rely on these data sources. Have them ready before opening a case.

| Source | Purpose | Quick-access |
|---|---|---|
| **VirusTotal** | IP / domain / file reputation | `https://www.virustotal.com/gui/ip-address/<IP>` |
| **AbuseIPDB** | Crowdsourced IP abuse reports | `https://www.abuseipdb.com/check/<IP>` |
| **Shodan / Censys** | Internet-exposed service fingerprinting | `https://www.shodan.io/host/<IP>` |
| **Passive DNS** (Mnemonic, SecurityTrails) | Historical IP↔domain mappings | API key required |
| **MITRE ATT&CK** | Technique reference | `https://attack.mitre.org/techniques/<ID>/` |
| **Internal PCAP store** | Deep-dive against raw packets | Used with `/scripts/` tools |
| **EDR console** | Host process / file / network state | Vendor-specific |
| **SIEM** | Historical query of related events | Vendor-specific |

### General principles

1. **Document as you go.** Investigations are useless if reproducible findings aren't captured. Use the ticket template at the bottom of this document.
2. **Preserve evidence before action.** Save the PCAP, dump the relevant logs, snapshot the host state *before* containment. Containment destroys evidence.
3. **Single source of truth for indicators.** If you confirm a malicious IP, add it to the central indicator list before notifying anyone — peer analysts running parallel investigations will benefit.
4. **Confidence ≠ certainty.** Document confidence levels (Low / Medium / High) with the evidence supporting each level. "It might be a beacon" is unhelpful; "High confidence — 3.2% jitter, no SNI, no DNS history" is actionable.

---

## PB-01 — DNS Tunneling: Anomalously Long Query Name

**Rule:** [`dns_long_query.yml`](../detections/sigma/dns_long_query.yml)
**Severity:** Medium
**MITRE ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004/) (Application Layer Protocol: DNS), [T1048.003](https://attack.mitre.org/techniques/T1048/003/) (Exfiltration Over Unencrypted Non-C2 Protocol)

### Trigger

A DNS query was observed with a fully-qualified name of more than 50 characters, where the query did not end in a recognized internal-domain suffix (`.local`, `.corp`, `.internal`, etc.).

### Phase 1 — Initial Triage

Extract from the alert: **source IP**, **full query name**, **base domain** (last two labels), **query type**.

| Check | If… | Then… |
|---|---|---|
| Is the source a known mail server? | Yes | Likely DKIM/SPF/DMARC lookup. Verify with one example query — proceed to Phase 2 only if more than 5 queries to the same external base domain. |
| Is the base domain on the org's CDN allowlist? | Yes (e.g., AWS, Cloudflare, Akamai) | Close as FP if query structure matches known CDN object-path pattern. |
| Is this a single one-off query, or are there many? | One-off | Note and close as anomaly. |
| Is the query type TXT or NULL? | Yes | Elevate priority — these record types are tunneling-preferred. |

### Phase 2 — Investigation

1. **Establish volume.** Query the SIEM for queries to the same base domain from the same source over the past 24 hours and 7 days:
   ```spl
   index=dns src_ip=<SOURCE_IP> query=*.<BASE_DOMAIN>
   | stats count, dc(query) as unique_queries by date_hour
   ```
   A sustained high volume (10+ per hour) is a strong tunneling indicator.

2. **Check base domain reputation.**
   ```bash
   curl --silent --header "x-apikey: $VT_KEY" \
     "https://www.virustotal.com/api/v3/domains/<BASE_DOMAIN>" \
     | jq '.data.attributes.last_analysis_stats, .data.attributes.creation_date'
   ```
   A domain registered within the past 30 days with no reputation is highly suspicious.

3. **Inspect the entropy and structure of the subdomain labels.** High-entropy base32/base64-like strings are a strong tunneling signal; sequential or dictionary-word patterns are usually legitimate.

4. **Pivot to PCAP** if available. Run the project's bulk analyzer against today's capture:
   ```bash
   ./scripts/dns_tunnel_detect.sh capture_$(date +%F).pcapng 50
   ```
   The script's HIGH/MEDIUM/LOW verdict gives you a quantitative anchor and the **base-domain grouping** in its output shows whether queries cluster on a single channel.

5. **Correlate with other channels.** Run [`tls_extract.sh`](../scripts/tls_extract.sh) and check for SNI-less HTTPS connections from the same source — dual-channel C2 is common. If found, escalate to PB-03 in parallel.

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **False positive** | Confirmed legitimate service (mail, CDN, anti-tracking) | Close ticket; consider tuning the rule to allowlist |
| **Suspicious — needs more data** | Volume below tunneling threshold; reputation neutral | Add source IP and base domain to watchlist; revisit in 24 hr |
| **Confirmed tunneling** | High volume + high entropy + recently-registered or unknown domain | Proceed to Phase 3 |

### Phase 3 — Containment & Response

1. **(T2/IR)** Block DNS resolution for the base domain at the perimeter (DNS firewall / Response Policy Zone).
2. **(T2/IR)** Add the base domain to the org's blocklist feed.
3. **Notify the host owner** of the source IP; gather any business-context that might explain the activity.
4. **(T2/IR)** If endpoint compromise is suspected, **isolate the host** (EDR network-detach or VLAN quarantine) and initiate host forensics:
   - Process list, network connections, autoruns
   - Recent file system changes
   - Browser history and downloads
5. **Preserve the PCAP** containing the full alert window plus 1 hour before for IR analysis.
6. **Threat-hunt** for the same indicators across the environment — other hosts querying the same base domain, similar query patterns to different domains.

### Closure Checklist

- [ ] Source IP and base domain documented
- [ ] Verdict and confidence level recorded
- [ ] Evidence preserved (DNS logs minimum; PCAP if confirmed)
- [ ] Indicators (base domain, name servers) added to blocklists if malicious
- [ ] If verdict was FP: rule-tuning note added (with allowlist rationale)

---

## PB-02 — DNS Tunneling: High Volume TXT Queries

**Rule:** [`dns_txt_high_volume.yml`](../detections/sigma/dns_txt_high_volume.yml)
**Severity:** High
**MITRE ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1048.003](https://attack.mitre.org/techniques/T1048/003/)

### Trigger

A single source IP issued 30 or more DNS TXT-record queries within a 5-minute window. TXT records can carry larger payloads than A/AAAA records and are a preferred carrier for tunneling tools (iodine, dnscat2, custom implants).

### Phase 1 — Initial Triage

| Check | If… | Then… |
|---|---|---|
| Is the source a mail server? | Yes (verify with asset inventory) | DKIM/SPF/DMARC lookups can hit this threshold during bulk-mail processing. Check the queried domains — legitimate mail queries hit `_dmarc.<domain>`, `<selector>._domainkey.<domain>`. |
| Are the queries all to a single base domain? | Yes | Strong tunneling indicator — legitimate TXT queries are usually spread across many domains. |
| Are query names long and high-entropy? | Yes | Strong tunneling indicator — pair with PB-01 logic. |
| Is the source running a security tool that performs RBL/DNSBL lookups? | Yes | Verify the destination is a known reputation service; close as FP if confirmed. |

### Phase 2 — Investigation

1. **Profile the source's normal DNS behavior.** Pull the prior 24 hours of DNS activity:
   ```spl
   index=dns src_ip=<SOURCE_IP>
   | stats count by qtype_name
   | sort -count
   ```
   If TXT queries are normally 0-5% of total queries and this window shows >50%, the deviation alone is a high-confidence indicator.

2. **Calculate the suspicious-query ratio.** From PCAP:
   ```bash
   ./scripts/dns_tunnel_detect.sh capture_$(date +%F).pcapng 50
   ```
   The script reports `Suspicious ratio: X.X%` — anything over 5% is well outside normal baselines.

3. **Look for the second channel.** DNS tunneling is often paired with HTTPS C2 for command receipt. From the same capture:
   ```bash
   ./scripts/tls_extract.sh capture_$(date +%F).pcapng /tmp/tls.csv
   awk -F',' -v src=<SOURCE_IP> '$2 == "\""src"\""' /tmp/tls.csv | head
   ```
   Pay particular attention to any **SNI-less handshakes** from the same source — this is the exact correlation that produced the verdict in [`reports/IR-2026-001`](../reports/IR-2026-001-suspected-c2-investigation.md).

4. **Check for DoH/DoQ activity from the same source.** If the host is doing tunneled DNS, it may also be using DNS-over-HTTPS to avoid this very detection:
   ```spl
   index=conn src_ip=<SOURCE_IP> dest_port IN (443, 853)
   | stats count by dest_ip
   ```
   Lookups against known DoH-provider IPs (1.1.1.1, 8.8.8.8, etc.) on port 443 from a host that isn't configured for DoH is itself suspicious.

5. **Resolve and reputation-check the base domain** as in PB-01 step 2.

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **False positive** | Mail server hitting DKIM/DMARC; security tool hitting RBL | Close; add source to rule's allowlist |
| **Confirmed tunneling** | High TXT ratio + single base domain + unknown reputation | Proceed to Phase 3 |
| **Confirmed + paired HTTPS C2** | Above + SNI-less or low-jitter HTTPS to one IP from same source | Proceed to Phase 3 **and** activate IR escalation |

### Phase 3 — Containment & Response

1. **(T2/IR)** Sinkhole the base domain at the DNS firewall — don't just block; sinkholing collects continuing query data for forensics.
2. **(T2/IR) Isolate the source host.** TXT-volume tunneling is almost never benign at this scale.
3. **Acquire host artifacts:**
   - Memory snapshot (Volatility-compatible)
   - Disk image of `%USERPROFILE%` / `/home/<user>/` and persistence locations (`~/.config/`, `~/.local/`, scheduled tasks, systemd timers)
   - Running process tree
4. **Hunt for the agent.** TXT-tunneling implants are typically small (single-binary) and often Python or Go. Look for recently-created executables, recently-modified cron / scheduled task definitions, and unexpected systemd services.
5. **Add to detection feed:**
   - Base domain → DNS blocklist
   - Any C2 IPs identified during investigation → IP blocklist
   - Process / file hashes → EDR custom IOCs

### Closure Checklist

Same as PB-01, plus:
- [ ] Host forensic artifacts preserved (memory dump, disk image if available)
- [ ] Persistence mechanism identified (or explicitly noted as not found)
- [ ] Sinkhole data collection running for at least 7 days

---

## PB-03 — TLS Client Hello Without SNI (Superseded)

> **Superseded 2026-07-29 by [PB-05](#pb-05--ech-session-without-dns-https-rr-lookup).** The triggering rule was deprecated because Encrypted Client Hello invalidated its premise: missing SNI is no longer anomalous, and ECH-shaped extensions appear on nearly every browser handshake due to GREASE. This playbook is retained for provenance and for environments still running the deprecated rule in alert-only mode during transition. Treat its verdicts as low confidence. Reasoning: [`docs/refreshes/2026-07.md`](../docs/refreshes/2026-07.md).


**Rule:** [`tls_no_sni_external.yml`](../detections/sigma/tls_no_sni_external.yml)
**Severity:** High
**MITRE ATT&CK:** [T1573.002](https://attack.mitre.org/techniques/T1573/002/) (Encrypted Channel: Asymmetric Cryptography)

### Trigger

A TLS Client Hello was sent to an external (non-RFC1918) IP without the SNI extension. Modern legitimate clients (browsers, OS updaters, package managers, mainstream apps) include SNI on virtually every connection.

### Phase 1 — Initial Triage

| Check | If… | Then… |
|---|---|---|
| What is the destination IP? Reverse-DNS lookup? | Resolves to known vendor (Microsoft, Apple update servers, etc.) | Verify with vendor docs — *some* update mechanisms use direct-IP. Close as FP if confirmed. |
| Is the source a legacy IoT or appliance? | Yes (printers, smart-building hardware, old firmware) | Many such devices have minimal TLS stacks without SNI. Document and tune the rule to allowlist that subnet/device type. |
| Is this a one-off or repeating? | One-off | Note and close — could be probe response or transient. |
| Are there other SNI-less connections from this source? | Yes, multiple, same destination | Strong malware-C2 indicator. Escalate. |

### Phase 2 — Investigation

1. **Reverse-resolve the destination IP** and search passive DNS history:
   ```bash
   dig +short -x <DEST_IP>
   # Plus passive DNS lookup via your provider's API
   ```
   No PTR record + no passive DNS history is highly suspicious. Brand-new resolution history (last 30 days) is suspicious.

2. **Reputation-check the destination IP:**
   ```bash
   curl --silent --header "x-apikey: $VT_KEY" \
     "https://www.virustotal.com/api/v3/ip_addresses/<DEST_IP>" \
     | jq '.data.attributes.last_analysis_stats, .data.attributes.country'
   ```
   And AbuseIPDB:
   ```bash
   curl --silent --header "Key: $ABUSEIPDB_KEY" \
     "https://api.abuseipdb.com/api/v2/check?ipAddress=<DEST_IP>"
   ```

3. **Capture the JA4 fingerprint** if PCAP is available:
   ```bash
   tshark -r capture.pcapng -Y "ip.dst == <DEST_IP> && tls.handshake.type == 1" \
     -T fields -e tls.handshake.ja4
   ```
   Known malware families have published JA4 fingerprints — match against:
   - [FoxIO JA4+ database](https://ja4db.com/)
   - Your org's threat intelligence feed
   A match is a confirmed compromise indicator.

4. **Establish scope.** How many hosts in the environment have SNI-less connections to this IP?
   ```spl
   index=ssl server_name="-" dest_ip=<DEST_IP>
   | stats values(src_ip) as sources count by dest_ip
   ```
   Multiple internal hosts hitting the same SNI-less destination strongly suggests a campaign rather than isolated noise.

5. **Run the project's TLS extractor** for the full picture of TLS behavior from the source:
   ```bash
   ./scripts/tls_extract.sh capture_$(date +%F).pcapng /tmp/tls.csv
   ```
   The script's `Found N TLS handshakes without SNI` summary makes scope visible immediately.

6. **Check for beaconing behavior** to the same destination — SNI-less + beaconing is the textbook signature investigated in [`IR-2026-001`](../reports/IR-2026-001-suspected-c2-investigation.md):
   ```bash
   ./scripts/beacon_detect.sh capture_$(date +%F).pcapng <DEST_IP>
   ```

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **False positive — IoT** | Source is known low-TLS-quality appliance | Close; allowlist the source-asset class in the rule |
| **False positive — legacy update channel** | Vendor-documented direct-IP update mechanism | Close; allowlist the destination |
| **Suspicious — needs more data** | Unknown destination, only 1-2 connections, no other indicators | Add IP and JA4 to watchlist; monitor 24 hr |
| **Confirmed C2** | JA4 matches known malware **OR** beacon analysis shows low jitter **OR** multiple internal hosts hit same IP | Proceed to Phase 3 |

### Phase 3 — Containment & Response

1. **(T2/IR) Block the destination IP** at the perimeter — all ports, all protocols.
2. **(T2/IR) Isolate the source host(s).**
3. **Add the JA4 fingerprint** to the detection feed for fast-path identification of related infections.
4. **(T2/IR)** If multiple hosts hit the same IP: treat as **multi-host campaign**, activate IR coordination.
5. **Threat-hunt** for the same JA4 across the environment over the past 30 days — many C2 frameworks have stable client-side JA4 across infections.
6. **Search for paired DNS/HTTPS indicators** from the same source(s) (PB-01, PB-02, PB-04).

### Closure Checklist

Same as PB-01, plus:
- [ ] JA4 fingerprint captured and added to feed
- [ ] Scope of infection (host count) documented
- [ ] All affected hosts identified and tracked individually

---

## PB-04 — HTTPS Beaconing Pattern

**Rule:** [`https_beacon_pattern.yml`](../detections/sigma/https_beacon_pattern.yml)
**Severity:** High
**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Application Layer Protocol: Web Protocols), [T1029](https://attack.mitre.org/techniques/T1029/) (Scheduled Transfer)

### Trigger

A single source made 15 or more HTTPS (TCP/443) connections to a single external destination IP within a 10-minute window. The Sigma rule detects high-frequency repeat connections; this playbook adds the jitter analysis needed to distinguish C2 beaconing from legitimate periodic traffic.

### Phase 1 — Initial Triage

| Check | If… | Then… |
|---|---|---|
| What is the destination? SNI value? Reverse DNS? | Known CDN or major service (Google, Akamai, Cloudflare edges, vendor telemetry) | Likely legitimate. Verify in Phase 2 step 1 before closing. |
| Was a browser actively in use? | Yes, with persistent web app open (Gmail, Slack, etc.) | Websocket reconnect or polling — likely legitimate. Verify with user / EDR process context. |
| Is the source running an EDR/AV cloud-lookup agent? | Yes | Frequent cloud reputation lookups can hit this threshold. Verify the destination matches the vendor. |
| Was the connection count exactly evenly spaced? | Yes (e.g., every 60s ±2s) | Strong beaconing indicator regardless of destination. Escalate. |

### Phase 2 — Investigation

1. **Identify the destination.** Pull SNI from the SIEM (the beacon rule doesn't include SNI in its match):
   ```spl
   index=ssl src_ip=<SOURCE_IP> dest_ip=<DEST_IP>
   | stats values(server_name) as sni count by dest_ip
   ```
   - SNI to a known CDN → check Phase 1 again, likely benign
   - **No SNI** → critical indicator; cross-reference with PB-03
   - SNI to an unknown domain → reputation-check

2. **Run jitter analysis against the PCAP.** This is the key step — the SIEM rule only counts connections, but **jitter percentage** distinguishes beacons from chatty-but-legitimate connections:
   ```bash
   ./scripts/beacon_detect.sh capture_$(date +%F).pcapng <DEST_IP>
   ```
   Map the script's verdict to action:

   | Script verdict | Interpretation |
   |---|---|
   | HIGH CONFIDENCE (jitter <5%, count >10) | Confirmed beacon — go to Phase 3 |
   | MEDIUM CONFIDENCE (jitter <20%, count >5) | Likely jittered beacon — extend investigation, do not close |
   | LOW CONFIDENCE | Likely legitimate periodic traffic (heartbeat, polling) — verify Phase 1 explanations |

3. **Check if the destination is part of a multi-IP set** (DNS round-robin / fast-flux). Resolve any associated domain at multiple time points or use passive DNS:
   ```bash
   # If you have the SNI domain
   ./scripts/beacon_detect.sh capture_$(date +%F).pcapng <DOMAIN>
   ```
   The multi-IP script will resolve the domain and pool connections across all current IPs — this catches beacons that distribute across a 3-5 IP rotation, which the single-IP SIEM rule misses.

4. **Capture and check the JA4 fingerprint** (same as PB-03 step 3). A "Cobalt Strike default" or "Sliver" JA4 match is a confirmed-compromise verdict on its own.

5. **Check time-of-day pattern.** Run the destination IP through 24-hour activity:
   ```spl
   index=conn dest_ip=<DEST_IP>
   | timechart span=1h count by src_ip
   ```
   24/7 activity with no business-hours dip on a workstation source is highly suspicious. User-driven traffic almost always shows a business-hours pattern.

6. **Inspect payload sizes for uniformity.** Real beacons typically use small, uniform payloads:
   ```bash
   tshark -r capture.pcapng -Y "ip.dst == <DEST_IP> && tcp.len > 0" \
     -T fields -e tcp.len | sort -n | uniq -c
   ```
   A tight distribution around a single payload size is another beacon signature.

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **False positive — CDN/vendor** | SNI matches known service; reputation clean; jitter LOW | Close; consider raising rule threshold for that destination |
| **False positive — persistent web app** | EDR confirms browser process with relevant tab; jitter LOW | Close |
| **Suspicious — needs more data** | Unknown destination; jitter MEDIUM | Add to watchlist; pull next 24 hr |
| **Confirmed beacon — single host** | jitter HIGH (or MEDIUM + no benign explanation) | Proceed to Phase 3 |
| **Confirmed beacon — multi-host** | Above, and multiple internal hosts hit same destination | Phase 3 + activate IR coordination |

### Phase 3 — Containment & Response

1. **(T2/IR)** Block the destination IP at the perimeter. If a domain is involved, block the domain and any other IPs it currently resolves to.
2. **(T2/IR) Isolate the source host(s).**
3. **Acquire a memory snapshot** of the source host **before** isolating, if possible. Beacon implants often only exist in memory; isolating without capturing memory loses the artifact.
4. **Identify the beaconing process** via EDR — match the destination IP in `netstat` / `ss` output to a process and parent process. Document the full process tree.
5. **Add to detection feed:**
   - Destination IP → IP blocklist
   - JA4 fingerprint → JA4 detection feed
   - Process hash → EDR custom IOC
   - Any associated domains → DNS blocklist
6. **Threat-hunt** across the environment:
   - Other hosts connecting to the same destination
   - Hosts producing the same JA4 to any destination
   - Hosts running the same process hash

### Closure Checklist

Same as PB-01, plus:
- [ ] Jitter percentage documented (the quantitative verdict, not just "beacon detected")
- [ ] Process responsible identified (or explicitly noted as unidentified)
- [ ] Memory snapshot status documented (captured / failed / not attempted)
- [ ] JA4 fingerprint captured and added to feed

---

## PB-05 — ECH Session Without DNS HTTPS-RR Lookup

**Rule:** [`tls_ech_without_dns_config.yml`](../detections/sigma/tls_ech_without_dns_config.yml)
**Severity:** High
**MITRE ATT&CK:** [T1573.002](https://attack.mitre.org/techniques/T1573/002/) (Encrypted Channel), [T1090.004](https://attack.mitre.org/techniques/T1090/004/) (Domain Fronting)
**Replaces:** [PB-03](#pb-03--tls-client-hello-without-sni-superseded)

### Trigger

A host completed an ECH-protected TLS handshake with no preceding DNS HTTPS resource record (type 65) query in the correlation window. A conforming client cannot build an encrypted ClientHelloInner without the ECHConfig published in that record, so the client is operating from a hardcoded or out-of-band config.

### Phase 1 — Initial Triage

The benign explanations here are numerous and genuinely common. Work through them before escalating — this rule generates leads, not verdicts.

| Check | If… | Then… |
|---|---|---|
| Does the host use DoH or DoQ? | Yes | The HTTPS-RR query exists but is invisible to passive capture. Re-run the correlation against resolver logs. Close as environmental if confirmed. |
| Was the capture window shorter than the DNS TTL? | Yes | The lookup likely predates the capture. Re-capture over a longer window before drawing conclusions. |
| Is this a one-off or repeating from the same host? | One-off | Note and monitor. Cache and resumption effects produce isolated occurrences routinely. |
| Does the host route through a TLS-inspecting proxy? | Yes | The proxy may perform resolution on the client's behalf. Verify proxy behaviour and exclude if confirmed. |
| Repeating, same host, same destination, no DoH configured? | Yes | Strong indicator. Proceed to Phase 2. |

### Phase 2 — Investigation

1. **Confirm the pattern holds over a longer capture.**
   ```bash
   ./scripts/ech_analyze.sh capture_$(date +%F).pcapng
   ```
   The script reports total ECH share, outer-SNI distribution, and the correlation result. A host that appears in the orphan list across multiple independent captures is not a caching artifact.

2. **Check the host's DNS configuration directly.** Confirm whether DoH is enabled in the browser or at the OS resolver. On Linux: `resolvectl status`. This single check resolves the majority of alerts.

3. **Examine the outer SNI.** ECH cover names are drawn from a small set of provider public names. An outer SNI that is unusual, or that does not match the destination IP's expected CDN, is worth pursuing:
   ```bash
   tshark -r capture.pcapng -Y "ip.dst == <DEST_IP> && tls.handshake.type == 1" \
     -T fields -e tls.handshake.extensions_server_name
   ```

4. **Pivot to behavioural analysis — this is the key step.** ECH conceals the destination name; it does not conceal timing. Everything in the beaconing toolkit remains fully available:
   ```bash
   ./scripts/beacon_detect.sh capture_$(date +%F).pcapng <DEST_IP>
   ```
   A low-jitter beacon to a destination reached via hardcoded-config ECH is a high-confidence C2 verdict even with no visibility into the destination name.

5. **Extract and assess the JA4.** JA4 is computed from the outer Client Hello and survives ECH intact:
   ```bash
   ./scripts/pq_readiness.sh capture_$(date +%F).pcapng
   ```
   A browser-shaped JA4 with no post-quantum key share compounds the finding — see [PB-06](#pb-06--browser-fingerprint-without-post-quantum-key-share).

6. **Reputation-check the destination IP** and search passive DNS. No PTR record and no resolution history is consistent with dedicated C2 infrastructure.

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **Environmental** | Host uses DoH/DoQ, or capture window shorter than TTL | Close; document the visibility gap and consider resolver-log ingestion |
| **False positive — proxy** | TLS-inspection proxy resolves on client's behalf | Close; exclude proxy egress from the rule |
| **Suspicious** | Repeats across captures, no DoH, destination unremarkable | Watchlist; extend capture; re-assess in 24 hr |
| **Confirmed C2** | Repeats + beacon analysis shows low jitter, **or** JA4/PQ mismatch, **or** destination has no DNS history | Proceed to Phase 3 |

### Phase 3 — Containment & Response

1. **(T2/IR)** Block the destination IP at the perimeter. Domain-based blocking is not available — this is the operational cost of ECH and should be noted in the ticket.
2. **(T2/IR) Isolate the source host**, capturing memory first where possible.
3. **Extract the hardcoded ECHConfig** from the implant if host forensics recovers the binary. The config is a durable IOC that identifies related infrastructure.
4. **Add to detection feed:** destination IP, JA4 fingerprint, ECHConfig `config_id` if recovered.
5. **Threat-hunt** for other hosts appearing in the ECH orphan list across recent captures.

### Closure Checklist

- [ ] DoH/DoQ status of the source host confirmed and recorded
- [ ] Correlation verified across more than one capture window
- [ ] Beacon analysis result documented (jitter percentage, not just a verdict)
- [ ] JA4 captured and added to feed
- [ ] If FP: cause recorded (caching / DoH / proxy) and rule tuned accordingly

---

## PB-06 — Browser Fingerprint Without Post-Quantum Key Share

**Rule:** [`tls_missing_pq_keyshare.yml`](../detections/sigma/tls_missing_pq_keyshare.yml)
**Severity:** Medium
**MITRE ATT&CK:** [T1573.002](https://attack.mitre.org/techniques/T1573/002/) (Encrypted Channel), [T1036](https://attack.mitre.org/techniques/T1036/) (Masquerading)

### Trigger

A TLS 1.3 client presenting a browser-shaped JA4 fingerprint did not offer `X25519MLKEM768` (IANA 4588) or any other hybrid post-quantum group. Current browsers offer a PQ key share by default, so the fingerprint and the cryptographic capability disagree.

### Phase 1 — Initial Triage

One cause dominates this rule's output. Check it first.

| Check | If… | Then… |
|---|---|---|
| Does the host's egress traverse a TLS-inspection proxy? | Yes | The proxy rewrites the Client Hello and commonly strips PQ groups. **This is the largest single FP source.** Confirm and exclude the proxy egress range. |
| What does asset inventory say about patch level? | Genuinely outdated browser | Legitimate. Route to patch management rather than security escalation. |
| Is the source a CI runner, scraper, or test host? | Yes | Automation frameworks bundle older TLS stacks. Allowlist the host class. |
| Is the source a standard managed endpoint, current patch level, not behind a proxy? | Yes | Genuine anomaly. Proceed to Phase 2. |

### Phase 2 — Investigation

1. **Establish the environment baseline.**
   ```bash
   ./scripts/pq_readiness.sh capture_$(date +%F).pcapng
   ```
   The adoption summary tells you what normal looks like here. If PQ-capable share is near zero across the board, the rule is premature for this environment and should be shelved until adoption rises — that is a legitimate outcome of triage.

2. **Compare the JA4 against the same host's other sessions.** A host producing both PQ-capable and PQ-absent handshakes with similar fingerprints is running two different TLS stacks — one of which is not the browser it claims to be.

3. **Identify the responsible process** via EDR by matching the destination IP to an open connection. This usually resolves the alert immediately.

4. **Check the destination.** Reputation, passive DNS history, and whether other internal hosts reach it.

5. **Pivot to beacon analysis** if the destination is unfamiliar:
   ```bash
   ./scripts/beacon_detect.sh capture_$(date +%F).pcapng <DEST_IP>
   ```

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **False positive — proxy** | TLS inspection strips PQ groups | Close; exclude proxy egress IPs from the rule |
| **Patch gap** | Legitimate but outdated browser confirmed in inventory | Close as security finding; route to patch management |
| **Environment not ready** | Baseline PQ adoption near zero | Shelve the rule; document the revisit threshold |
| **Confirmed masquerading** | JA4 claims browser, no matching process, unfamiliar destination | Escalate; treat as implant with spoofed fingerprint |

### Phase 3 — Containment & Response

1. **(T2/IR) Isolate the host** and identify the responsible binary.
2. **Block the destination** at the perimeter.
3. **Add the JA4 to the detection feed** — a spoofed fingerprint that fails the PQ check is a durable, high-precision indicator for the same malware family.
4. **Threat-hunt** for the same JA4-without-PQ combination across the environment over the past 30 days.

### Closure Checklist

- [ ] Proxy involvement explicitly ruled in or out
- [ ] Asset patch level checked against inventory
- [ ] Environment PQ baseline recorded
- [ ] Responsible process identified, or explicitly noted as unidentified

---

## PB-07 — LLM API Egress and High-Volume Upload

**Rule:** [`llm_api_egress_unsanctioned.yml`](../detections/sigma/llm_api_egress_unsanctioned.yml)
**Severity:** Medium
**MITRE ATT&CK:** [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service), [T1048](https://attack.mitre.org/techniques/T1048/)

### Trigger

Either a host outside the sanctioned-AI allowlist connected to an LLM inference API, or request-direction volume to such an API exceeded the configured threshold (default 10 MB / 30 min).

### Phase 1 — Initial Triage

This playbook is as much a governance workflow as a security one. Most findings are policy questions, not incidents — treat people accordingly.

| Check | If… | Then… |
|---|---|---|
| Is the source a developer workstation? | Yes | Agentic coding assistants routinely submit large repository context. Expected behaviour; verify the tool is approved and close. |
| Is the destination on the approved provider list? | Yes, but source is unsanctioned | Shadow AI. Route to policy/governance, not incident response. |
| Is the destination an *unapproved* provider? | Yes | Higher concern — data is going somewhere without a processing agreement. Proceed to Phase 2. |
| Is volume high *and* the host has no AI tooling installed? | Yes | Treat as potential exfiltration. Proceed to Phase 2 with urgency. |
| Did the upload occur outside working hours from an idle workstation? | Yes | Strong exfiltration indicator. Proceed to Phase 2. |

### Phase 2 — Investigation

1. **Inventory the host's AI egress.**
   ```bash
   ./scripts/ai_egress_inventory.sh capture_$(date +%F).pcapng
   ```
   Reports sessions by provider, source hosts, and request-direction volume per destination.

2. **Correlate with user activity.** An interactive session should show a human at the keyboard. Check EDR for foreground process activity and login state at the time of the upload. Bulk upload from an idle or locked workstation is the strongest single discriminator between use and exfiltration.

3. **Identify the responsible process.** A browser tab, a sanctioned IDE plugin, and an unrecognised binary are three different conclusions.

4. **Establish what data the host could reach.** Scope the potential exposure using the host's file shares, database credentials, and repository access.

5. **Check for a second channel.** Exfiltration rarely uses one path. Run the DNS and beacon checks against the same source:
   ```bash
   ./scripts/dns_tunnel_detect.sh capture_$(date +%F).pcapng 50
   ./scripts/beacon_detect.sh capture_$(date +%F).pcapng <DEST_IP>
   ```

6. **Distinguish agent traffic from beaconing.** Agentic tool use is periodic and will resemble C2 to the beacon rules. The discriminator is payload-size variance — agent traffic is bursty and irregular, beacons are uniform:
   ```bash
   tshark -r capture.pcapng -Y "ip.dst == <DEST_IP> && tcp.len > 0" \
     -T fields -e tcp.len | sort -n | uniq -c
   ```

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **Sanctioned use** | Approved tool, approved provider, user active | Close |
| **Shadow AI — policy** | Unsanctioned host, approved provider, legitimate user activity | Route to governance; no IR action. Handle as a conversation, not an investigation. |
| **Shadow AI — unapproved provider** | Data leaving to a provider with no processing agreement | Route to governance *and* legal/privacy; assess data classification |
| **Suspected exfiltration** | High volume + no user activity + unrecognised process | Proceed to Phase 3 |

### Phase 3 — Containment & Response

1. **(T2/IR) Isolate the host** if exfiltration is suspected.
2. **Identify the responsible process** and preserve the binary.
3. **Scope the data exposure** — what could the host reach, and what did the volume plausibly contain?
4. **(T2/IR)** Engage legal and privacy if regulated data may have left the environment. Submission to a third-party inference API is a disclosure event under several regimes regardless of intent.
5. **Block the provider** at the perimeter if unapproved.

### Closure Checklist

- [ ] Responsible process identified
- [ ] User activity state at time of upload documented
- [ ] Data classification of potential exposure assessed
- [ ] Governance referral made where the finding is policy rather than incident
- [ ] Legal/privacy engaged if regulated data was in scope

---

## PB-08 — MCP Server Connection to External Host

**Rule:** [`mcp_server_connection.yml`](../detections/sigma/mcp_server_connection.yml)
**Severity:** Medium
**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Tools)

### Trigger

HTTP traffic consistent with a Model Context Protocol client session to a host outside the organisation — a POST to an MCP endpoint path, a Server-Sent Events stream, or a JSON-RPC indicator.

### Phase 1 — Initial Triage

| Check | If… | Then… |
|---|---|---|
| Is the destination on the approved MCP server list? | Yes | Close. Maintaining that list is the prerequisite for this rule being useful. |
| Does the request carry a JSON-RPC indicator or a known MCP client user agent? | No | `/sse` and `/messages` are generic paths used by unrelated applications. Likely not MCP; verify before proceeding. |
| Is the destination a development or staging server reached over VPN? | Yes | Expected during development. Confirm with the owning team and allowlist. |
| Unknown external destination with confirmed MCP semantics? | Yes | Proceed to Phase 2. |

### Phase 2 — Investigation

1. **Inventory MCP indicators in the capture.**
   ```bash
   ./scripts/ai_egress_inventory.sh capture_$(date +%F).pcapng
   ```
   Reports endpoint requests and SSE streams with source, destination, and URI.

2. **Identify the MCP server.** Who operates it? Is it a known open-source server, a vendor integration, or an unattributable host? Reputation-check the destination and check registration age of any associated domain.

3. **Determine the client.** Which assistant or IDE on the host initiated this? EDR process attribution matters more than usual here — the security question is what tools that assistant has access to, and that is a host-side property.

4. **Assess the blast radius.** An MCP server can influence what the connected assistant does with everything it can reach. Enumerate the assistant's configured access: file paths, credentials, repositories, internal APIs.

5. **Check session duration and pattern.** MCP sessions are long-lived by design. Persistent connections to an unattributable external host warrant the same scrutiny as any other long-lived outbound channel — see [PB-04](#pb-04--https-beaconing-pattern) if the traffic is also periodic.

### Decision Tree

| Verdict | Evidence | Next |
|---|---|---|
| **Approved integration** | Destination on allowlist | Close |
| **Not MCP** | Generic `/sse` path, no JSON-RPC, unrelated application | Close; refine rule path patterns |
| **Shadow integration** | Legitimate developer using an unapproved but reputable server | Route to governance; assess the server's tool definitions before approving |
| **Untrusted server** | Unattributable destination, recently registered domain, or assistant has broad data access | Proceed to Phase 3 |

### Phase 3 — Containment & Response

1. **Block the MCP server** at the perimeter.
2. **Disconnect the integration** on the host and preserve its configuration for review.
3. **Review the server's tool definitions** if obtainable — prompt-injection payloads and over-scoped tool descriptions are the primary risk, and both are inspectable.
4. **Assess what the assistant could reach** during the connection window and whether any of it warrants a data-exposure review.
5. **Add to detection feed:** destination, associated domain, client user agent.
6. **Establish an approved-MCP-server allowlist** if one does not exist. This rule is far more useful as deviation-detection against a known-good list than as generic MCP detection.

### Closure Checklist

- [ ] MCP semantics confirmed (not a generic SSE endpoint)
- [ ] Server operator identified or explicitly noted as unattributable
- [ ] Client assistant and its configured access scope documented
- [ ] Approved-server allowlist updated either way
- [ ] Coverage gap noted: stdio-transport MCP is invisible to this rule

---

## Cross-Cutting: When Multiple Alerts Fire Together

The four detections are designed to complement each other. Specific co-occurrence patterns dramatically increase confidence and should change the response:

| Co-occurring rules from the same source IP | Likely scenario | Escalation |
|---|---|---|
| PB-01 + PB-02 | Active DNS tunneling | Treat as **High** confidence even if individual rule outputs are MEDIUM |
| PB-01/02 + PB-03 | Dual-channel C2 (DNS exfil + HTTPS command receipt) | Escalate to IR immediately; this is the [`IR-2026-001`](../reports/IR-2026-001-suspected-c2-investigation.md) pattern |
| PB-05 + PB-04 | ECH-concealed C2 with confirmed beaconing | High-confidence C2. The destination name is unavailable, but timing analysis is unaffected by ECH — the behavioural verdict stands on its own. |
| PB-05 + PB-06 | Hardcoded-config ECH client also failing the PQ capability check | Two independent indicators of a non-browser TLS stack masquerading as one. Escalate. |
| PB-07 + PB-01/02 | Bulk LLM upload alongside DNS tunneling from the same host | Multi-channel exfiltration. Treat the LLM channel as the primary volume path and DNS as the covert control path. |
| PB-08 + PB-04 | MCP session to an unattributable host with beacon-like periodicity | Check payload-size variance before escalating — agent traffic is bursty, beacons are uniform. |
| PB-04 across multiple internal hosts to same destination | Multi-host campaign | Activate IR coordination; treat as a single incident |

If any two of the above co-occur from a single source within a 24-hour window, **default the verdict to High confidence and proceed to Phase 3 immediately**, even if individual rules would close as Medium.

---

## Standard Ticket Documentation Template

Every closed case should record at minimum:

```
CASE: <ID>
RULE: <Sigma rule name and file>
SEVERITY: <as documented>   VERDICT: <FP | Suspicious | Confirmed>   CONFIDENCE: <Low | Med | High>

SOURCE:
  - IP:
  - Hostname (if known):
  - Owner / department:

DESTINATION:
  - IP:
  - Domain / SNI (if known):
  - Reputation summary:

TIMELINE:
  - Alert time:
  - Triage start:
  - Verdict reached:
  - Containment time (if applicable):

EVIDENCE PRESERVED:
  - [ ] SIEM logs (start/end timestamps)
  - [ ] PCAP file (path)
  - [ ] EDR snapshot (host, time)
  - [ ] Memory dump (if applicable)

INDICATORS ADDED TO FEEDS:
  - <list of IPs, domains, hashes, JA4s>

ACTIONS TAKEN:
  - <chronological list>

LESSONS / RULE TUNING:
  - <if any rule tuning is recommended as a result>
```

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/) — adversary technique reference
- [MITRE D3FEND](https://d3fend.mitre.org/) — defensive countermeasures (companion to ATT&CK)
- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) — Computer Security Incident Handling Guide
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/) — phased response methodology
- [FoxIO JA4+ Database](https://ja4db.com/) — published JA4 fingerprints
- Project sources:
  - [Detection rules](../detections/sigma/)
  - [PCAP analysis scripts](../scripts/)
  - [Investigation example: IR-2026-001](../reports/IR-2026-001-suspected-c2-investigation.md)

---

*This playbook is a living document. Update it as new detection rules are added, as tuning insights emerge from production deployment, and as adversary tradecraft evolves.*
