# AegisID Threat Model

## Security goal
Make counterfeiting and bypass **economically irrational**: an attacker must
break multiple independent layers while leaving a tamper-evident trail.

## Attack tree and mitigations

| # | Attack | Layer that blocks it | Residual risk |
|---|---|---|---|
| 1 | Photocopy / reprint QR | L3 one-time nonce | Needs online server |
| 2 | Replay same token | L3 first-scan-wins | None (server state) |
| 3 | Forge new token | L1 Ed25519 signature | Needs manufacturer key theft |
| 4 | Replay old token | L2 TTL expiry | 5-minute window |
| 5 | Relabel product ↔ batch | L4 binding check | Requires valid token |
| 6 | Stolen stock scanned abroad | L4 geo-anomaly | False positives possible |
| 7 | Edit/delete scan records | L5 hash-chained log | Log kept off-DB / anchored |
| 8 | Serve fake "GENUINE" page | Signed API response | Client must verify sig |
| 9 | Insider edits DB | L5 + external anchoring (roadmap) | Anchoring makes it visible |
| 10 | Token enumeration | 128-bit random IDs + rate limiting | 2^128 search space |

## Out of scope (documented, not hidden)
- Physical chip transplant (mitigated by tamper-evident seals + Layer 0 NFC)
- Denial of service (use rate limiting + CDN in production)
- Manufacturer key theft (HSM / key rotation roadmap)

## Reporting
See [SECURITY.md](SECURITY.md).
