# Sigma Detection Rules

This directory contains [Sigma](https://github.com/SigmaHQ/sigma) rules that codify the detection logic from this project into a portable, SIEM-agnostic format. Rules target network monitoring data (Zeek logs) and are validated in CI on every push.

**Last reviewed:** 2026-07-29 (refresh `2026-07`) — see [`docs/refreshes/2026-07.md`](../../docs/refreshes/2026-07.md) for the reasoning behind the current rule set, and the [refresh log](../../docs/refreshes/README.md) for review history.

## Active rules

| File | Detection | ATT&CK | Level |
|---|---|---|---|
| [`dns_long_query.yml`](dns_long_query.yml) | DNS queries with abnormally long names | T1071.004, T1048.003 | medium |
| [`dns_txt_high_volume.yml`](dns_txt_high_volume.yml) | High-volume TXT queries from a single source (correlation) | T1071.004, T1048.003 | high |
| [`https_beacon_pattern.yml`](https_beacon_pattern.yml) | Repeated HTTPS connections to one destination (correlation) | T1071.001, T1029 | high |
| [`tls_ech_without_dns_config.yml`](tls_ech_without_dns_config.yml) | ECH session with no preceding DNS HTTPS-RR lookup (correlation) | T1573.002, T1090.004 | high |
| [`tls_missing_pq_keyshare.yml`](tls_missing_pq_keyshare.yml) | Browser-shaped JA4 lacking a post-quantum key share | T1573.002, T1036 | medium |
| [`llm_api_egress_unsanctioned.yml`](llm_api_egress_unsanctioned.yml) | LLM API egress and high-volume upload (correlation) | T1567, T1048 | medium |
| [`mcp_server_connection.yml`](mcp_server_connection.yml) | MCP server connections to external hosts | T1071.001, T1219 | medium |

## Deprecated rules

Deprecated rules are retained rather than deleted so the reasoning stays with the repository.

| File | Deprecated | Superseded by | Reason |
|---|---|---|---|
| [`tls_no_sni_external.yml`](tls_no_sni_external.yml) | 2026-07-29 | `tls_ech_without_dns_config.yml` | Encrypted Client Hello invalidated the premise that missing SNI is anomalous. Full reasoning in the [refresh document](../../docs/refreshes/2026-07.md#1-encrypted-client-hello-broke-a-rule-in-this-repository). |

## Log source

Rules target **Zeek** logs (`dns`, `ssl`, `conn`, `http`). To adapt to another source — Suricata EVE JSON, Corelight, Arkime — change the `logsource` block and adjust field names.

Two rules depend on fields that may need environment-specific work:

- **`ech_config_id`** (`tls_ech_without_dns_config.yml`) is populated by ECH-aware Zeek analyzers. Older Zeek deployments may need a custom script matching TLS extension type **65037** (`0xFE0D`).
- **`supported_groups`** (`tls_missing_pq_keyshare.yml`) requires the Zeek SSL analyzer to log the client's supported groups list. Verify this is enabled before deploying.

## Converting to your SIEM

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch

# Verify the rules compile
sigma convert -t splunk --without-pipeline detections/sigma/dns_long_query.yml
sigma convert -t lucene --without-pipeline detections/sigma/dns_long_query.yml
```

**On field mapping.** There is no published Zeek processing pipeline plugin for pySigma, so `--without-pipeline` emits the rules with Sigma's field names unchanged (`id.orig_h`, `server_name`, `qtype`). Those already match Zeek's own log schema, so for a Zeek-native SIEM index the output is usable directly.

If your SIEM normalises to a different schema — Splunk CIM, ECS, OCSF — write a small custom pipeline mapping the Zeek field names to yours and pass it by filename:

```bash
sigma convert -t splunk -p my-zeek-to-cim.yml detections/sigma/*.yml
```

`sigma list pipelines` shows what is installed; `sigma plugin list --plugin-type pipeline` shows what is available. An `ocsf` pipeline exists if you normalise to OCSF.

### Negated temporal correlation

`tls_ech_without_dns_config.yml` alerts on the *absence* of an expected event pair, which most backends do not yet express natively. Implement as a scheduled search instead:

```spl
index=ssl ech_config_id=*
| eval ech_time=_time
| join type=left id.orig_h
    [ search index=dns qtype=65 earliest=-5m
      | stats max(_time) as dns_time by id.orig_h ]
| where isnull(dns_time) OR dns_time > ech_time
| table _time id.orig_h id.resp_h server_name
```

Widen the `earliest` window in environments with aggressive DNS caching.

## Compatibility notes

- The DNS long-query rule uses a regex (`query|re: '^.{51,}$'`) rather than the `|length` modifier, because backend coverage for `|length` remains uneven. Swap once your backend supports it.
- Correlation rules use the Sigma 2.0 `correlation:` block. Backends without Sigma 2.0 support convert only the atomic base rules; express the thresholds in your SIEM's query language directly.
- Internal-network CIDR filters assume RFC 1918 only. Add DMZ, lab, and partner ranges.
- `llm_api_egress_unsanctioned.yml` and `tls_missing_pq_keyshare.yml` contain placeholder allowlists (`10.20.30.0/24`, JA4 prefixes) that **must** be populated from your own environment before deployment.

## Tuning guidance

These are starting points, not production-ready as written.

1. **Run 7 days in alert-only mode** to baseline false-positive rates.
2. **Build allowlists** for known-noisy assets — mail servers (DNS TXT), developer subnets (LLM upload volume), TLS-inspection proxy egress IPs (PQ key share).
3. **Adjust thresholds** from observed traffic rather than the defaults here.
4. **Tier severity by destination novelty** — a first-seen destination is higher risk than an established one.

## Continuous integration

[`.github/workflows/validate-detections.yml`](../../.github/workflows/validate-detections.yml) runs on every push touching `detections/` or `scripts/`:

- YAML syntax validation
- `sigma check` rule validation
- UUID uniqueness (a duplicate silently breaks correlation references)
- Backend conversion smoke test against the Splunk backend
- ShellCheck and syntax checks on companion scripts
- Placeholder and committed-capture-file scans

## See also

- [`/scripts/`](../../scripts/) — PCAP-level analysis tools these rules derive from
- [`/playbooks/sigma-detection-response.md`](../../playbooks/sigma-detection-response.md) — analyst response procedures per rule
- [`/reports/`](../../reports/) — worked investigation using the script toolkit
- [`/docs/refreshes/2026-07.md`](../../docs/refreshes/2026-07.md) — why the rule set looks the way it does
- [`/docs/known-limitations.md`](../../docs/known-limitations.md) — tested backend findings and coverage gaps
