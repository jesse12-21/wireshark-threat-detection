# Detection Refresh History

Detections expire. Not because they were written badly, but because the protocols they observe keep moving — and the failure is silent. A rule keeps firing, the alerts keep looking plausible, and the signal has quietly drained out of them.

This directory holds the record of each scheduled review: what changed in the protocol landscape, which rules were affected, and what was done about them. Each refresh is a dated document. Nothing is deleted — a deprecated rule keeps its reasoning, and so does a superseded assumption.

## Refresh log

| Refresh | Date | Focus | Rules added | Rules deprecated |
|---|---|---|---|---|
| [2026-07](2026-07.md) | 2026-07-29 | Encrypted Client Hello, post-quantum TLS, AI/agent egress, detection-as-code | 8 | 1 |

**Next scheduled review:** 2026-10-29

A review is also triggered early by any of:

- ECH reaching formal IETF ratification, or a material shift in the GREASE ECH pattern
- Post-quantum adoption crossing a threshold that changes the false-positive profile of `tls_missing_pq_keyshare.yml`
- MCP transport patterns changing, or the stdio-transport visibility gap becoming addressable
- A new encrypted-DNS deployment pattern that further reduces DNS-layer visibility
- Any rule in this repository producing an unexplained change in alert volume

## What a refresh covers

Each review walks the full rule set and asks four questions of every detection:

1. **Does the assumption still hold?** Every rule keys on some property of the traffic. If the protocol changed, the property may be gone.
2. **Has the false-positive profile shifted?** A rule can stay technically correct while becoming operationally useless.
3. **Is there a new observable worth detecting?** New protocols and new tooling create new surfaces.
4. **Does the generated query still mean what the rule says?** Rules that parse are not the same as rules that convert correctly — see [`known-limitations.md`](../known-limitations.md).

## Conventions

- **Rules are deprecated, not deleted.** `status: deprecated`, a dated explanation, and the successor's UUID.
- **Every rule states its expiry conditions.** If a detection depends on a protocol assumption, that assumption is written down.
- **Limitations are declared, not discovered.** Coverage gaps live in the rule files and script headers, and are collected in [`known-limitations.md`](../known-limitations.md).
- **Rules are validated in CI.** See [`.github/workflows/validate-detections.yml`](../../.github/workflows/validate-detections.yml).
