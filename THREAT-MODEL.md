# AegisID Threat Model

## Security goal

Make large-scale counterfeiting and verification fraud detectable and expensive, and leave a
tamper-evident record of every verification. AegisID is **not** a guarantee that a physical product is
genuine; it authenticates *tokens* and detects when the same token is presented twice.

## Assets and trust assumptions

| Asset | Assumption |
|---|---|
| Manufacturer signing key | Kept secret. Whoever holds it can issue tokens and forge the audit log. |
| Verification server and database | Run by the manufacturer; the database may be read or modified by an insider. |
| Scanning client | Untrusted by default. It chooses the `region` and may be a fake page. |
| Printed or NFC token | Can be photographed, copied and relabelled by an attacker. |

## Attacks, mitigations and residual risk

| # | Attack | Mitigation | Residual risk |
|---|---|---|---|
| 1 | Photocopy a label | L3 one-time use: the second scan fails | **Cannot tell which label is the original.** If the copy is scanned first it is reported GENUINE and the real product is flagged. Needs hardware-bound identity (NFC) to resolve. |
| 2 | Replay the same token | L3, nonce burned atomically in the database; survives restarts and multiple workers | None beyond #1 |
| 3 | Forge or edit a token | L1 strict schema and Ed25519 signature | Signing-key theft |
| 4 | Use an expired token | L2 expiry | Printed labels need long lifetimes, so the window is long for them |
| 5 | Move a genuine label to another product of the same batch | L4 binds the token to its batch | **Not prevented:** the label is genuine, only the product differs. Same root cause as #1. |
| 6 | Scan stolen stock in another region | L4 region comparison (case and whitespace insensitive) | **Only as strong as the region source.** A client-supplied value is trivially spoofable. |
| 7 | Edit a scan record | L5 hash chain | Detected |
| 8 | Rewrite the whole chain and recompute hashes | Every record is signed with the manufacturer key | An insider **with the signing key** can still forge it |
| 9 | Delete the newest records | Compare `head` with an externally anchored copy | Undetectable without an anchor |
| 10 | Serve a fake "GENUINE" page | Signed responses; client verifies with a pinned public key | The client must actually verify and obtain the key over a trusted channel |
| 11 | Replay a captured GENUINE response to another client | The client `challenge` is inside the signed payload | Clients that omit the challenge are exposed |
| 12 | Guess or enumerate tokens | 128-bit random ids, signatures, per-IP rate limiting | The rate limiter is per process and per IP |
| 13 | Abuse the admin API | Shared secret, constant-time comparison, rate limit, disabled when unset | Single shared secret: keep it on a private network |
| 14 | Malformed or oversized input | Strict schemas with length limits; unknown fields rejected | Use a reverse proxy to cap request size |
| 15 | Learn internals from error messages | Clients receive a generic code and message; details stay in the log | Error codes still reveal the category of failure |
| 16 | Run with the wrong key after a restart | The database is bound to its key id and refuses a different key | None |

## Out of scope

- Physical attacks: chip transplant, label peeling, or a genuine package refilled with fake goods
  (mitigate with tamper-evident seals and hardware-bound NFC).
- Theft of the manufacturer signing key (use an HSM or KMS; key rotation is on the roadmap).
- Network denial of service (use a CDN, WAF and rate limiting at the edge).
- Compromise of the host running the server.

## Reporting

See [SECURITY.md](SECURITY.md).
