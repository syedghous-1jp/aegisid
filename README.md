# AegisID

**Clone-resistant product authentication: signed, one-time tokens instead of static barcodes.**

AegisID replaces static barcodes and QR codes with cryptographically signed tokens that are
verified by a server. A forged token, an expired token, a second scan of the same token or a
tampered audit record is rejected automatically.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What AegisID is, and what it is not

Please read this section first; it is the most important one.

- **AegisID makes copying detectable. It does not make a printed code physically uncloneable.**
  A QR code can always be photographed. What AegisID adds is that every token works exactly
  once: the second scan of an identical label fails.
- **It cannot tell which of two identical labels is the original.** If a counterfeiter copies
  a label and the copy is scanned *first*, the copy is reported `GENUINE` and the real product
  is flagged as already scanned. Closing this gap requires a hardware-bound identity such as
  NFC challenge-response (see the [roadmap](#roadmap)). Until then, treat a duplicate-scan alert
  as a signal to investigate, not as proof of which product is fake.
- **The region check is only as trustworthy as the region value.** The scanning client supplies
  it. See [Trust boundaries](#trust-boundaries-and-deployment).

See [THREAT-MODEL.md](THREAT-MODEL.md) for the complete list of attacks, mitigations and residual risks.

## The five-layer verification gate

Every scan must pass all five layers. One failure rejects the product.

| Layer | Check | Stops |
|---|---|---|
| **1. Structure and signature** | Strict token schema and Ed25519 signature | Forged, edited or malformed tokens |
| **2. Expiry** | Token lifetime | Stale or leaked tokens (most useful for short-lived tokens) |
| **3. One-time use** | First scan wins; the nonce is burned atomically in the database | Replayed and duplicated labels |
| **4. Binding and region** | Product is bound to its batch; scan region must match the batch | Relabelling across batches, stock scanned in the wrong region |
| **5. Signed audit log** | Hash-chained log, every record signed with the manufacturer key | Editing or rewriting scan history |

Responses are signed with the manufacturer key and echo a client-supplied `challenge`, so a
captured `GENUINE` answer cannot be replayed to another client.

## Quick start

```bash
git clone https://github.com/syedghous-1jp/aegisid.git
cd aegisid
pip install -r requirements-dev.txt
python scripts/selftest.py        # unit tests + attack simulator
```

### Use it as a library

```python
from aegisid.core import AegisVerifier
from aegisid.crypto import generate_keypair

priv, pub = generate_keypair()
verifier = AegisVerifier(priv, pub)           # in-memory store; pass Store("aegis.db") to persist
verifier.register_batch("BATCH-001", "Karachi")

token = verifier.issue_token("BATCH-001", ttl=86400)   # encode this in the QR / NFC tag
result = verifier.verify(token, scan_region="Karachi", challenge="random-client-value")
# {'pid': '...', 'status': 'GENUINE', 'batch': 'BATCH-001', 'anchor': '...', 'ts': ..., 'challenge': '...', 'sig': '...'}
```

### Run the HTTP API with Docker

```bash
cp .env.example .env
# edit .env and set AEGIS_ADMIN_TOKEN (python -c "import secrets; print(secrets.token_urlsafe(32))")
docker compose up -d --build        # API on http://127.0.0.1:8000
```

The signing key and database live in the `aegis-data` volume, so tokens survive restarts.

```bash
H='Content-Type: application/json'; A="X-Admin-Token: $AEGIS_ADMIN_TOKEN"

# 1. register a batch and its expected region
curl -X POST localhost:8000/admin/batches -H "$H" -H "$A" \
     -d '{"batch_id": "BATCH-001", "region": "Karachi"}'

# 2. issue a token for one product (ttl in seconds, 1 .. 63072000)
curl -X POST localhost:8000/admin/issue -H "$H" -H "$A" \
     -d '{"batch_id": "BATCH-001", "ttl": 86400}'            # -> {"v":1,"pid":...,"sig":...}

# 3. scan it (paste the token JSON from step 2)
curl -X POST localhost:8000/scan -H "$H" \
     -d '{"token": {"v":1,"pid":"...","batch":"BATCH-001","nonce":"...","exp":0,"sig":"..."},
          "region": "Karachi", "challenge": "random-client-value"}'
```

## API reference

| Method and path | Auth | Description |
|---|---|---|
| `GET /health` | none | Liveness probe |
| `GET /public-key` | none | Ed25519 public key (PEM) and `key_id`. Clients verify responses with it. |
| `POST /scan` | none, rate limited | Run a token through the gate. `200` genuine, `403` rejected, `422` invalid input, `429` rate limited |
| `POST /admin/batches` | `X-Admin-Token` | Register a batch and its expected region |
| `POST /admin/issue` | `X-Admin-Token` | Issue a signed token for a new product |
| `GET /admin/audit` | `X-Admin-Token` | Log size, integrity check and head hash |

A rejection returns only a generic code and message
(`INVALID_TOKEN`, `EXPIRED`, `ALREADY_USED`, `REGION_MISMATCH`). The failing layer and internal
details such as the expected region are written to the server log, never to the client.

### Verifying a response on the client

1. Fetch `/public-key` **once, over a trusted channel**, and pin the `key_id`.
2. Send a fresh random `challenge` with every scan.
3. Verify the Ed25519 signature over the canonical JSON of the response (all fields except `sig`,
   keys sorted, separators `,` and `:`) and check that `challenge` equals the value you sent.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_DB` | `:memory:` | SQLite path. In-memory means demo mode: state is lost on restart. |
| `AEGIS_KEY_FILE` | unset | PEM file with the Ed25519 signing key; created with mode 0600 if missing. If unset, an ephemeral key is used and every token dies on restart. |
| `AEGIS_ADMIN_TOKEN` | unset | Secret for `/admin/*`. If unset the admin API is disabled. |
| `AEGIS_RATE_LIMIT` | `60` | Max `/scan` requests per client IP per minute (`0` disables). |

A database is bound to the first signing key it sees. Starting it with a different key fails
immediately instead of silently rejecting every issued token.

### Choosing a token lifetime

Layer 2 only helps when tokens are short-lived. A **printed** label must stay valid from the
factory to the shelf, so give printed tokens a long `ttl` (weeks or months). Use the short
default (300 seconds) for tokens generated on demand, for example by an NFC tag or an app.

## Trust boundaries and deployment

- **Region trust.** `region` is supplied by the scanner. Anyone can claim `"Karachi"`. Only rely on
  layer 4 for geography when the value comes from something you trust: an authenticated retailer
  app, a signed GPS fix or server-side IP geolocation. Otherwise treat it as advisory.
- **TLS.** Run the API behind a TLS reverse proxy. The compose file binds to `127.0.0.1` for this reason.
  Behind a proxy, start uvicorn with `--proxy-headers` and restrict `--forwarded-allow-ips`, otherwise the
  per-IP rate limit sees only the proxy address.
- **Admin API.** Keep `/admin/*` on a private network or behind mTLS or a VPN. The token is compared in
  constant time and attempts are rate limited, but it is still a single shared secret.
- **Signing key.** It is the root of trust. Back it up, keep it out of version control (the repository's
  `.gitignore` excludes `*.pem` and `*.db`) and consider an HSM or KMS for production.
- **Anchor the audit log.** `GET /admin/audit` returns `head`. Publish it to a place you do not control
  alone (a ticket, a public repository, a timestamping service) at regular intervals. This is the only way
  to detect deletion of the newest records.
- **Workers.** State lives in SQLite (WAL mode) so several workers can share it safely. The rate limiter is
  per process.

## Limitations

- Detects duplicates; cannot identify the original label (see above).
- Requires an online verification server.
- The region value is client-supplied unless you provide a trusted source.
- The audit chain is tamper-evident, not tamper-proof: an insider who holds the signing key can forge it,
  and tail truncation needs an external anchor.
- SQLite is appropriate for a single node. A multi-node deployment needs a different store.
- No key rotation or revocation yet.

## Roadmap

- [ ] NFC challenge-response (for example NTAG 424 DNA) to bind a token to the physical product
- [ ] Key rotation and revocation
- [ ] Merkle-root anchoring of the audit log to an external ledger
- [ ] Per-batch token lifetimes
- [ ] Anomaly scoring (scan velocity, duplicate-scan clusters)
- [ ] GS1 Digital Link compatibility

## Development

```bash
pip install -r requirements-dev.txt
python -m unittest discover tests -v     # 47 tests: gate, persistence, concurrency, insider attacks, HTTP API
python scripts/attack_simulator.py        # eight attack scenarios
```

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE).
