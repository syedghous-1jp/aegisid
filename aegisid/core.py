"""AegisID core: issuing and verifying clone-resistant product identities.

Every scan runs through a five-layer verification gate; one failure rejects
the product. Layer 3 (first-scan-wins) detects *duplicates*: it cannot tell
which of two identical labels is the original, see THREAT-MODEL.md.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Optional

from .crypto import (canonical_json, new_product_id, public_key_id, sign_json,
                     verify_json)
from .store import GENESIS, Store

TOKEN_TTL_SECONDS = 300            # default lifetime; use a long TTL for printed labels
TOKEN_VERSION = 1
TOKEN_KEYS = ("v", "pid", "batch", "nonce", "exp")
MAX_CHALLENGE_LEN = 64

# Messages that are safe to return to an (untrusted) client. Internal details
# such as the expected region stay in server logs only.
PUBLIC_MESSAGES = {
    "INVALID_TOKEN": "Token is invalid.",
    "EXPIRED": "Token has expired.",
    "ALREADY_USED": "Token was already scanned. This product may be a copy.",
    "REGION_MISMATCH": "Token was scanned outside its expected region.",
}


class VerificationError(Exception):
    """A verification layer rejected the token.

    ``reason`` is internal (logs, tests). Use ``code`` / ``public_message``
    for anything sent to a client.
    """

    def __init__(self, layer: int, reason: str, code: str = "INVALID_TOKEN"):
        self.layer = layer
        self.reason = reason
        self.code = code
        super().__init__(f"LAYER {layer} FAILED: {reason}")

    @property
    def public_message(self) -> str:
        return PUBLIC_MESSAGES[self.code]


def _norm_region(region: object) -> str:
    return " ".join(str(region).split()).casefold()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class TamperEvidentLog:
    """Hash-chained, *signed* audit log stored in the database.

    Each record contains the hash of the previous one and is signed with the
    manufacturer key. Editing a record breaks the hash chain; rewriting the
    whole chain additionally requires the signing key. Truncating the newest
    entries is only detectable by comparing ``head`` with an externally
    anchored copy (see THREAT-MODEL.md).
    """

    def __init__(self, store: Store, priv, pub):
        self._store = store
        self._priv = priv
        self._pub = pub

    def build(self, event: dict, prev: str) -> tuple:
        """Create ``(record_text, hash, signature)``; used inside the DB transaction."""
        text = canonical_json({"event": event, "prev": prev, "ts": time.time()}).decode()
        digest = _sha256(text)
        return text, digest, sign_json(self._priv, {"log_hash": digest})

    def verify(self) -> bool:
        prev, expected_seq = GENESIS, 1
        for row in self._store.log_rows():
            if row["seq"] != expected_seq:          # a record was deleted
                return False
            expected_seq += 1
            try:
                record = json.loads(row["record"])
            except ValueError:
                return False
            if record.get("prev") != prev:
                return False
            if _sha256(row["record"]) != row["hash"]:
                return False
            if not verify_json(self._pub, {"log_hash": row["hash"]}, row["sig"]):
                return False
            prev = row["hash"]
        return True

    @property
    def head(self) -> str:
        """Hash of the newest record. Publish it externally to anchor the log."""
        return self._store.log_head()

    def __len__(self) -> int:
        return self._store.log_count()


class AegisVerifier:
    """Issue and verify product tokens with five-layer defence."""

    def __init__(self, manufacturer_priv, manufacturer_pub, store: Optional[Store] = None):
        self._priv = manufacturer_priv
        self._pub = manufacturer_pub
        self.store = store or Store()
        self.key_id = public_key_id(manufacturer_pub)
        self._bind_key()
        self.log = TamperEvidentLog(self.store, manufacturer_priv, manufacturer_pub)

    @property
    def public_key(self):
        return self._pub

    def _bind_key(self) -> None:
        """Refuse to run a database with a different signing key than it was created with."""
        bound = self.store.get_meta("key_id")
        if bound is None:
            self.store.set_meta("key_id", self.key_id)
        elif bound != self.key_id:
            raise RuntimeError(
                f"database is bound to signing key {bound} but key {self.key_id} was "
                "supplied; every previously issued token would be rejected")

    # ---------- issuing ----------
    def register_batch(self, batch_id: str, expected_region: str) -> None:
        self.store.add_batch(batch_id, expected_region)

    def issue_token(self, batch_id: str, ttl: int = TOKEN_TTL_SECONDS) -> dict:
        """Create a signed token for one new product."""
        if self.store.batch_region(batch_id) is None:
            raise ValueError("unknown batch")
        pid = new_product_id()
        self.store.add_product(pid, batch_id)
        payload = {"v": TOKEN_VERSION, "pid": pid, "batch": batch_id,
                   "nonce": new_product_id(), "exp": int(time.time()) + ttl}
        return {**payload, "sig": sign_json(self._priv, payload)}

    # ---------- verification ----------
    @staticmethod
    def _parse(token: object) -> dict:
        """Structural validation (part of layer 1): shape and types."""
        bad = VerificationError(1, "malformed token", "INVALID_TOKEN")
        if not isinstance(token, dict) or "sig" not in token:
            raise bad
        if any(k not in token for k in TOKEN_KEYS) or not isinstance(token["sig"], str):
            raise bad
        exp = token["exp"]
        if (not all(isinstance(token[k], str) for k in ("pid", "batch", "nonce"))
                or isinstance(token["v"], bool) or not isinstance(token["v"], int)
                or isinstance(exp, bool) or not isinstance(exp, int)):
            raise bad
        return {k: token[k] for k in TOKEN_KEYS}

    def verify(self, token: dict, scan_region: str,
               challenge: Optional[str] = None) -> dict:
        """Run all five layers; raise ``VerificationError`` on the first failure.

        ``challenge`` is an optional random string chosen by the client. It is
        echoed inside the signed response, so a captured "GENUINE" answer cannot
        be replayed to another client.
        """
        if challenge is not None and (not isinstance(challenge, str)
                                      or len(challenge) > MAX_CHALLENGE_LEN):
            raise ValueError(f"challenge must be a string of at most {MAX_CHALLENGE_LEN} characters")

        # Layer 1 - structure and Ed25519 signature
        payload = self._parse(token)
        if not verify_json(self._pub, payload, token["sig"]):
            raise VerificationError(1, "invalid Ed25519 signature")
        if payload["v"] != TOKEN_VERSION:
            raise VerificationError(1, f"unsupported token version {payload['v']}")

        # Layer 2 - expiry
        if time.time() > payload["exp"]:
            raise VerificationError(2, "token expired", "EXPIRED")

        # Layer 3 - one-time use (read-only pre-check; the nonce is committed
        # atomically at the end, so a failed geo-check cannot burn a real token)
        if self.store.nonce_used(payload["nonce"]):
            raise VerificationError(3, "token already scanned (replay or copy)", "ALREADY_USED")

        # Layer 4 - product/batch binding and region check
        if self.store.product_batch(payload["pid"]) != payload["batch"]:
            raise VerificationError(4, "product not bound to this batch")
        expected = self.store.batch_region(payload["batch"])
        if expected is None or not isinstance(scan_region, str) \
                or _norm_region(expected) != _norm_region(scan_region):
            raise VerificationError(
                4, f"region mismatch: expected {expected!r}, scanned in {scan_region!r}",
                "REGION_MISMATCH")

        # Layer 5 - atomically burn the nonce AND append the signed audit record
        event = {"pid": payload["pid"], "batch": payload["batch"],
                 "region": scan_region, "nonce": payload["nonce"]}
        committed = self.store.commit_scan(payload["nonce"],
                                           lambda prev: self.log.build(event, prev))
        if committed is None:                        # lost a race with another scan
            raise VerificationError(3, "token already scanned (concurrent scan)", "ALREADY_USED")

        response = {"pid": payload["pid"], "status": "GENUINE", "batch": payload["batch"],
                    "anchor": committed["hash"], "ts": int(time.time()),
                    "challenge": challenge}
        response["sig"] = sign_json(self._priv, response)
        return response
