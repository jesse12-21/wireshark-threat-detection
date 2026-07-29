# Known Limitations

Findings from testing this repository's detections against real tooling. Each entry states what was tested, what was observed, and what was done about it.

The point of this document is that a detection you have not converted and read is a detection you have not verified. Rules that parse are not the same as rules that mean what you intended once a backend has rendered them.

---

## 1. pySigma Splunk backend does not parenthesise OR groups across selections

**Affects:** rule authoring, Splunk backend
**Found:** 2026-07-29
**Status:** worked around; rules restructured

### What was observed

Given a condition that ANDs a selection with an OR group formed from other selections, the pySigma Splunk backend emits the group without parentheses.

Minimal reproduction:

```yaml
title: T1
id: 11111111-1111-4111-8111-111111111111
status: experimental
logsource:
    product: test
detection:
    a:
        fa: '1'
    b:
        fb: '2'
    c:
        fc: '3'
    condition: a and (b or c)
```

```console
$ sigma convert -t splunk --without-pipeline t1.yml
fa="1" fb="2" OR fc="3"
```

SPL treats adjacent terms as an implicit AND, and AND binds tighter than OR. The emitted query therefore evaluates as:

```
(fa="1" AND fb="2") OR fc="3"
```

The rule specified:

```
fa="1" AND (fb="2" OR fc="3")
```

These are different queries. A rule written this way will match traffic it was not intended to match, and miss traffic it was.

### The canonical idiom does not help

Rewriting to Sigma's `1 of selection_*` form produces byte-identical output:

```yaml
    condition: a and 1 of sel_*
```

```console
$ sigma convert -t splunk --without-pipeline t2.yml
fa="1" fb="2" OR fc="3"
```

So this cannot be worked around by writing the rule differently within a single rule. Tested with `sigma-cli` 3.1.0 and `pysigma-backend-splunk`.

### What is *not* affected

Worth being precise, because the initial assessment of this finding was broader than the evidence supported.

**List values inside a single selection convert correctly.** The backend renders them as `IN (...)`:

```console
$ sigma convert -t splunk --without-pipeline detections/sigma/dns_long_query.yml
NOT (query IN ("*.local", "*.corp", "*.internal", "*.in-addr.arpa", "*.ip6.arpa"))
| regex query="^.{51,}$" | table id.orig_h,query,qtype_name
```

**Negated groups are parenthesised correctly.** The CIDR exclusion blocks used throughout this repository render as expected:

```console
NOT (id.resp_h="10.0.0.0/8" OR id.resp_h="172.16.0.0/12" OR ...)
```

So the affected pattern is narrow and specific: **two or more separately-named selections combined with OR, inside a condition that also contains AND.** Rules built from list-valued fields and negated exclusion groups — which is most of this repository — are unaffected.

### Resolution

`mcp_server_connection.yml` originally used the affected pattern. It was split into two AND-only rules:

- **MCP POST request** — `method: POST` plus a list-valued URI match
- **SSE stream** — `resp_mime_types` contains `text/event-stream`

Both now emit correct SPL. The split is also better detection engineering independent of the bug: a POST to an MCP endpoint and a long-lived SSE stream are distinct observables with different false-positive profiles, and they deserve separate verdicts rather than one rule that fires on either.

### Guidance adopted for this repository

- Prefer **AND-only conditions**. Express alternatives as list values within one selection where the fields allow it.
- Where alternatives span **different field names**, write separate rules rather than one rule with an OR group.
- **Convert every rule and read the output** before deploying. Parsing is not verification. This is now a CI step.

---

## 2. No published Zeek processing pipeline for pySigma

**Affects:** conversion instructions, field mapping
**Found:** 2026-07-29
**Status:** documentation corrected

### What was observed

An earlier version of `detections/sigma/README.md` — and the CI workflow — instructed users to convert with `-p zeek`:

```console
$ sigma convert -t splunk -p zeek detections/sigma/dns_long_query.yml
Error: The pipeline 'zeek' was not found.
```

`sigma plugin list --plugin-type pipeline` confirms no Zeek pipeline is published. The available pipelines are `windows`, `sysmon`, `ossem`, `ocsf`, and `rclinuxedr`.

Anyone following those instructions got an error.

### Resolution

Conversion now uses `--without-pipeline`, which emits Sigma's field names unchanged. Because this repository's rules are already written against Zeek's own schema (`id.orig_h`, `server_name`, `qtype`), the output is directly usable against a Zeek-native index.

Environments normalising to a different schema — Splunk CIM, ECS, OCSF — need a custom pipeline file passed by filename. This is documented in [`detections/sigma/README.md`](../detections/sigma/README.md).

---

## 3. `sigma check` requires network access

**Affects:** CI reliability
**Found:** 2026-07-29
**Status:** accepted, with a documented fallback

### What was observed

`sigma check` fetches MITRE D3FEND data at runtime to validate rule tags. In a network-restricted environment it fails:

```
RuntimeError: Failed to load MITRE D3FEND data: HTTP Error 403: Forbidden
```

This is not a rule defect — the rules parse cleanly offline via `SigmaCollection.load_ruleset()` — but it makes the CI step dependent on an external service.

### Resolution

Accepted for now, since GitHub Actions runners have open network access. The offline parse via pySigma is retained in the workflow as an independent check, so a D3FEND outage degrades validation coverage rather than blocking merges entirely.

---

## 4. Detection coverage gaps

These are inherent to the detection approach rather than tooling defects, and are repeated here so they are findable in one place. Each is also stated in the relevant rule or script.

| Gap | Affects | Detail |
|---|---|---|
| **Encrypted DNS** | `dns_long_query.yml`, `dns_txt_high_volume.yml`, `tls_ech_without_dns_config.yml` | DoH and DoQ hide DNS queries from passive capture. These rules require resolver-log ingestion in DoH-heavy environments. |
| **DNS caching** | `tls_ech_without_dns_config.yml` | An HTTPS-RR lookup may fall outside the correlation window, producing a false positive. Widen the window or verify across multiple captures. |
| **MCP stdio transport** | `mcp_server_connection.yml` | The stdio transport is local-only and produces no network artifacts. Absence of findings is not absence of MCP use. |
| **TLS-wrapped MCP** | `mcp_server_connection.yml` | MCP over HTTPS is invisible without decryption. Run against proxy logs where TLS terminates at a proxy. |
| **TLS-inspection proxies** | `tls_missing_pq_keyshare.yml` | Proxies rewrite the Client Hello and commonly strip PQ groups, producing the exact pattern this rule detects. The single largest FP source; exclude proxy egress IPs. |
| **ECH cover names** | `ech_analyze.sh` | Under ECH the visible SNI is the provider's public name. Destination-name-based analysis is unavailable for that traffic by design. |
| **Negated temporal correlation** | `tls_ech_without_dns_config.yml` | Alerting on the absence of an expected event pair is not natively expressible on most backends. A scheduled-search implementation is provided in [`detections/sigma/README.md`](../detections/sigma/README.md). |

---

*Findings recorded during the [July 2026 refresh](refreshes/2026-07.md). Tooling versions: `sigma-cli` 3.1.0, `pysigma-backend-splunk`, ShellCheck at `--severity=warning`.*
