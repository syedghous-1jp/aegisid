
"""AegisID core: issuing and verifying unclonable product identities.

Every verification runs through FIVE independent checks (the 5-Layer
Verification Gate). A single failure rejects the product.
"""
import hashlib
import json
import threading
import time
from .crypto import (
    Ed25519PublicKey, sign_json, verify_json, new_product_id,
)

TOKEN_TTL_SECONDS = 300          # 5 minutes: tokens are short-lived
MAX_SCANS_PER_TOKEN = 1          # one-time use: first-scan-wins
TOKEN_KEYS = ("v", "pid", "batch", "nonce", "exp")


class TamperEvidentLog:
    """Append-only hash-chained log. Any edit breaks every later hash."""

    def __init__(self):
        self._entries = []
        self._head = "GENESIS"
        self._lock = threading.Lock()

    def append(self, event: dict) -> str:
        with self._lock:
            record = {"event": event, "prev": self._head, "ts": time.time()}
            digest = hashlib.sha256(
                json.dumps(record, sort_keys=True).encode()).hexdigest()
            record["hash"] = digest
            self._entries.append(record)
            self._head = digest
            return digest

    def verify(self) -> bool:
        prev = "GENESIS"
        for rec in self._entries:
            record = {k: rec[k] for k in ("event", "prev", "ts")}
            if rec["prev"] != prev:
                return False
            if hashlib.sha256(
                json.dumps(record, sort_keys=True).encode()).hexdigest() != rec["hash"]:
                return False
            prev = rec["hash"]
        return True

    def __len__(self):
        return len(self._entries)


class VerificationError(Exception):
    def __init__(self, layer: int, reason: str):
        self.layer = layer
        self.reason = reason
        super().__init__(f"LAYER {layer} FAILED: {reason}")


class AegisVerifier:
    """Issue and verify product tokens with 5-layer defense."""

    def __init__(self, manufacturer_priv, manufacturer_pub):
        self._priv = manufacturer_priv
        self._pub = manufacturer_pub
        self._used_tokens = set()
        self._products = {}          # product_id -> batch_id
        self._batches = {}           # batch_id -> expected_region
        self.log = TamperEvidentLog()
        self._lock = threading.Lock()

    # ---------- issuing ----------
    def register_batch(self, batch_id: str, expected_region: str) -> None:
        self._batches[batch_id] = expected_region

    def issue_token(self, batch_id: str, ttl: int = TOKEN_TTL_SECONDS) -> dict:
        """Create a short-lived signed token for one product."""
        if batch_id not in self._batches:
            raise ValueError("unknown batch")
        pid = new_product_id()
        self._products[pid] = batch_id
        payload = {
            "v": 1,
            "pid": pid,
            "batch": batch_id,
            "nonce": new_product_id(),
            "exp": int(time.time()) + ttl,
        }
        token = dict(payload)
        token["sig"] = sign_json(self._priv, payload)
        return token

    # ---------- verification: THE 5-LAYER GATE ----------
    def verify(self, token: dict, scan_region: str) -> dict:
        """Run all 5 layers. Raises VerificationError on first failure."""
        # Layer 0 (structural): token must be well-formed - reject
        # malformed input cleanly instead of crashing with KeyError.
        if not isinstance(token, dict) or any(k not in token for k in TOKEN_KEYS) \
                or "sig" not in token:
            raise VerificationError(1, "malformed token: missing fields")

        # Layer 1 - Cryptographic signature (is this token genuinely ours?)
        payload = {k: token[k] for k in TOKEN_KEYS}
        if not verify_json(self._pub, payload, token["sig"]):
            raise VerificationError(1, "invalid Ed25519 signature")

        # Layer 2 - Expiry (is the token still alive?)
        if time.time() > payload["exp"]:
            raise VerificationError(2, "token expired")

        # Layer 3 - One-time use / replay protection (provisional check;
        # the nonce is only committed AFTER all layers pass, so a failed
        # geo-check cannot burn a legitimate token).
        if payload["nonce"] in self._used_tokens:
            raise VerificationError(3, "token already scanned (replay or copy)")

        # Layer 4 - Product-batch binding and geo-anomaly check
        if self._products.get(payload["pid"]) != payload["batch"]:
            raise VerificationError(4, "product not bound to this batch")
        if self._batches.get(payload["batch"]) != scan_region:
            raise VerificationError(4, f"geo-anomaly: token issued for "
                                       f"'{self._batches.get(payload['batch'])}' "
                                       f"but scanned in '{scan_region}'")

        # All checks passed -> atomically commit the nonce (thread-safe)
        with self._lock:
            if payload["nonce"] in self._used_tokens:
                raise VerificationError(3,
                    "token already scanned (replay or copy)")
            self._used_tokens.add(payload["nonce"])

        # Layer 5 - Audit anchoring (tamper-evident record)
        entry = {"pid": payload["pid"], "batch": payload["batch"],
                 "region": scan_region, "nonce": payload["nonce"]}
        anchor = self.log.append(entry)

        # Signed, client-verifiable response (prevents MITM fake pages)
        response = {"pid": payload["pid"], "status": "GENUINE",
                    "batch": payload["batch"], "anchor": anchor}
        response["sig"] = sign_json(self._priv, response)
        return response
