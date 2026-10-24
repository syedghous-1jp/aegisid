# AegisID — Unclonable Product Identity 🔐

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688) ![Cryptography](https://img.shields.io/badge/Cryptography-Ed25519-purple) ![Docker](https://img.shields.io/badge/Docker-Ready-2496ED) ![Red Team](https://img.shields.io/badge/Red--Team-ALL_ATTACKS_BLOCKED-brightgreen) ![License](https://img.shields.io/badge/License-MIT-green)

**Stop barcode fraud, QR-code copying and product counterfeiting with an open-source, cryptographically unclonable identity system.**

Barcodes and static QR codes can be photocopied, reprinted or swapped in seconds. AegisID replaces them with **short-lived signed tokens** that run through a **5-Layer Verification Gate** — so a copied barcode, a replayed token, or a forged signature is rejected automatically.

## Why barcode / QR-code systems fail

| Attack | How it works | Why classic barcodes lose |
|---|---|---|
| Photocopy | Copy the label to a fake product | Scanner can't tell a copy from the original |
| Price swap | Move a cheap product's barcode to an expensive one | No product-to-label binding |
| Replay | Scan the same genuine code many times | Codes are static |
| Forgery | Print a brand-new barcode | No cryptographic signature |
| Audit tampering | Edit or delete scan records | Plain databases are editable |

## The 5-Layer Verification Gate

Every scan must pass **all five layers**. One failure = rejection.

| Layer | Check | Blocks |
|---|---|---|
| **1. Signature** | Ed25519 signature over the token | Forged / self-made tokens |
| **2. Expiry** | Token TTL (5 min default) | Stolen or stale tokens |
| **3. One-time use** | First-scan-wins nonce tracking | Photocopied / replayed barcodes |
| **4. Binding + Geo** | Product↔batch binding + expected-region check | Relabeling, stolen-stock scans |
| **5. Audit anchor** | Hash-chained, append-only log entry | Record tampering & insider edits |

Responses are **signed by the manufacturer key**, so a man-in-the-middle can't serve a fake "GENUINE" page either.

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/aegisid.git
cd aegisid
python scripts/selftest.py        # 14/14 tests + all attacks blocked
pip install -r requirements.txt
docker compose up                 # API live at http://localhost:8000
```

### Issue & verify a token (Python)

```python
from aegisid.core import AegisVerifier
from aegisid.crypto import generate_keypair

priv, pub = generate_keypair()
v = AegisVerifier(priv, pub)
v.register_batch("BATCH-001", "Karachi")

token = v.issue_token("BATCH-001")          # put this token in the QR/NFC
result = v.verify(token, scan_region="Karachi")
# {'pid': '...', 'status': 'GENUINE', 'batch': 'BATCH-001', 'anchor': '...', 'sig': '...'}
```

### HTTP API

```bash
curl -X POST localhost:8000/scan   -H "Content-Type: application/json"   -d '{"token": {...}, "region": "Karachi"}'
```

## Red-team proof

This repo doesn't just claim security — it proves it. The attack simulator runs five real attacks (forged signature, expired token, copied barcode replay, geo-anomaly, log tampering) and every one is blocked:

```bash
python scripts/attack_simulator.py
```

```
==============================================================
  AEGISID ATTACK SIMULATOR - RED TEAM RESULTS
==============================================================
  ✔ Forged signature           BLOCKED
  ✔ Expired token              BLOCKED
  ✔ Copied barcode (replay)    BLOCKED
  ✔ Geo-anomaly scan           BLOCKED
  ✔ Audit-log tampering        BLOCKED
==============================================================
  VERDICT: ALL ATTACKS BLOCKED ✔
==============================================================
```

## Honest security model

No system is "100% unhackable" — the goal is to make bypassing cost more than the attacker's gain. AegisID raises that cost with defense-in-depth: hardware anchors (NFC NTAG 424 DNA) can be added as Layer 0, verification responses are signed, the audit log is hash-chained, and keys can be rotated per batch. See [THREAT-MODEL.md](THREAT-MODEL.md) for the full attack tree and mitigations.

## Roadmap

- [ ] NFC challenge-response integration (NTAG 424 DNA)
- [ ] Merkle-root anchoring to an external ledger (immutable audit)
- [ ] ML anomaly scoring (scan velocity, device fingerprinting)
- [ ] Manufacturer key-rotation & revocation service
- [ ] GS1 Digital Link compatibility

## Contributing

Security researchers: please read [SECURITY.md](SECURITY.md). Found a bypass? Open an issue — a working proof-of-concept earns you credit in the README.

MIT License — use it, break it, improve it.
