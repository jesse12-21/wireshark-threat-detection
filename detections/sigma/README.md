# Sigma Detection Rules

This directory contains [Sigma](https://github.com/SigmaHQ/sigma) rules that codify the detection logic from this project into a portable, SIEM-agnostic format. The rules target network monitoring data (Zeek logs) and cover the four primary detections demonstrated in the lab walkthrough.

## Rules in this directory

| File | Detection | ATT&CK |
|---|---|---|
| [`dns_long_query.yml`](dns_long_query.yml) | DNS queries with abnormally long names — DNS tunneling indicator | T1071.004, T1048.003 |
| [`dns_txt_high_volume.yml`](dns_txt_high_volume.yml) | High-volume TXT-record queries from a single source (correlation rule) | T1071.004, T1048.003 |
| [`tls_no_sni_external.yml`](tls_no_sni_external.yml) | TLS handshakes to external IPs with no SNI — evasion indicator | T1573.002 |
| [`https_beacon_pattern.yml`](https_beacon_pattern.yml) | Repeated HTTPS connections from one source to one destination (correlation rule) | T1071.001, T1029 |

## Log source

All rules target **Zeek** logs (`dns`, `ssl`, and `conn`). Zeek is the de facto open-source network monitor for SOCs that need structured network telemetry. To adapt to a different source — Suricata EVE JSON, Corelight, Arkime — change the `logsource` block and adjust field names accordingly.

## Converting to your SIEM

Sigma rules are converted to backend-specific query languages using [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli):

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch

# Convert all rules to Splunk SPL
sigma convert -t splunk -p zeek detections/sigma/*.yml

# Convert all rules to Elasticsearch (Lucene)
sigma convert -t lucene -p zeek detections/sigma/*.yml

# Convert all rules to Microsoft Sentinel (KQL)
sigma convert -t microsoft365defender detections/sigma/*.yml
```

The `-p zeek` pipeline maps generic Sigma field names to the actual Zeek field names in your environment.

## Compatibility notes

- The DNS long-query rule uses a regex (`query|re: '^.{51,}$'`) rather than the `|length` value modifier, because not all backends have implemented `|length` yet. Once your backend supports it, swap to `query|length|gte: 51` for slightly cleaner conversion.
- The correlation rules use the modern Sigma 2.0 `correlation:` block. Backends that don't yet implement Sigma 2.0 correlation will convert only the atomic base rule; you'll need to express the count threshold in your SIEM's query language directly.
- Internal-network CIDR filters (`10.0.0.0/8`, etc.) assume RFC 1918 ranges only. Add organization-specific CIDRs (DMZ, lab, partner network) to the `internal_destinations` selection as needed.

## Tuning guidance

These rules are starting points, not production-ready as written. Recommended tuning steps before deploying:

1. **Run for 7 days in alert-only / dry-run mode** to baseline false-positive rates.
2. **Build allowlists** for known-noisy assets — mail servers (DNS TXT), DevOps build hosts (frequent CDN HTTPS), monitoring tools (active probing).
3. **Adjust thresholds** — the `gte: 30` for TXT volume and `gte: 15` for HTTPS connection count are conservative defaults; adjust based on your environment's normal traffic profile.
4. **Tier severity by destination** — a SNI-less connection to a brand-new IP (no prior history) is far higher-risk than one to a well-known endpoint; consider an enrichment pipeline that escalates accordingly.

## See also

- The [`/scripts/`](../../scripts/) directory contains the original bash detection scripts these rules are derived from. The scripts work against raw PCAPs; these rules work against network monitoring logs. They complement each other rather than replace each other.
- The [investigation write-up](../../reports/IR-2026-001-suspected-c2-investigation.md) shows the script-based detections in action; the same investigation patterns translate directly to SIEM queries generated from these Sigma rules.
