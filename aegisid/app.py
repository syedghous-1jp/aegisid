"""FastAPI server exposing the AegisID verification gate.

Public endpoints
    GET  /health        liveness probe
    GET  /public-key    the manufacturer public key (clients verify signatures with it)
    POST /scan          run a token through the 5-layer gate (rate limited)

Admin endpoints (require the ``X-Admin-Token`` header)
    POST /admin/batches register a batch and its expected region
    POST /admin/issue   issue a signed token for a product in a batch
    GET  /admin/audit   audit-log size, integrity and head hash

Configuration (environment variables)
    AEGIS_DB            SQLite path (default ":memory:" = ephemeral, demo only)
    AEGIS_KEY_FILE      PEM file holding the Ed25519 signing key (created if missing)
    AEGIS_ADMIN_TOKEN   secret for the admin endpoints (admin API disabled if unset)
    AEGIS_RATE_LIMIT    max requests per client IP per minute (default 60, 0 = off)
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .core import MAX_CHALLENGE_LEN, AegisVerifier, VerificationError
from .crypto import (export_public, generate_keypair, load_or_create_private_key)
from .store import Store

log = logging.getLogger("aegisid")
MAX_ISSUE_TTL = 2 * 365 * 24 * 3600     # two years


class RateLimiter:
    """Tiny in-memory sliding-window limiter, one window per client key."""

    def __init__(self, max_calls: int, window: float = 60.0):
        self.max_calls, self.window = max_calls, window
        self._hits: dict = defaultdict(deque)

    def allow(self, key: str) -> bool:
        if self.max_calls <= 0:
            return True
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.max_calls:
            return False
        hits.append(now)
        if len(self._hits) > 10_000:                      # keep memory bounded
            for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                del self._hits[k]
        return True


class TokenModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    v: int
    pid: str = Field(min_length=1, max_length=64)
    batch: str = Field(min_length=1, max_length=64)
    nonce: str = Field(min_length=1, max_length=64)
    exp: int
    sig: str = Field(min_length=1, max_length=128)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: TokenModel
    region: str = Field(min_length=1, max_length=64)
    challenge: Optional[str] = Field(default=None, max_length=MAX_CHALLENGE_LEN)


class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str = Field(min_length=1, max_length=64)
    region: str = Field(min_length=1, max_length=64)


class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str = Field(min_length=1, max_length=64)
    ttl: int = Field(default=300, ge=1, le=MAX_ISSUE_TTL)


def build_verifier_from_env() -> AegisVerifier:
    key_file = os.environ.get("AEGIS_KEY_FILE")
    db_path = os.environ.get("AEGIS_DB", ":memory:")
    if key_file:
        priv = load_or_create_private_key(key_file)
        pub = priv.public_key()
    else:
        priv, pub = generate_keypair()
        log.warning("AEGIS_KEY_FILE is not set: using an EPHEMERAL signing key. "
                    "All tokens become invalid when the process restarts.")
    if db_path == ":memory:":
        log.warning("AEGIS_DB is not set: state is kept in memory only (demo mode).")
    return AegisVerifier(priv, pub, Store(db_path))


def create_app(verifier: Optional[AegisVerifier] = None,
               admin_token: Optional[str] = None,
               rate_limit: Optional[int] = None) -> FastAPI:
    verifier = verifier or build_verifier_from_env()
    admin_token = admin_token if admin_token is not None else os.environ.get("AEGIS_ADMIN_TOKEN", "")
    if rate_limit is None:
        rate_limit = int(os.environ.get("AEGIS_RATE_LIMIT", "60"))
    scan_limiter = RateLimiter(rate_limit)
    admin_limiter = RateLimiter(min(rate_limit, 10) if rate_limit else 0)
    if admin_token and len(admin_token) < 16:
        log.warning("AEGIS_ADMIN_TOKEN is shorter than 16 characters; use a long random value.")

    app = FastAPI(title="AegisID", version=__version__,
                  description="Clone-resistant product authentication API")
    app.state.verifier = verifier

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def limit_scan(request: Request) -> None:
        if not scan_limiter.allow(client_ip(request)):
            raise HTTPException(status_code=429, detail="Too many requests")

    def require_admin(request: Request, x_admin_token: str = Header(default="")) -> None:
        if not admin_limiter.allow("admin:" + client_ip(request)):
            raise HTTPException(status_code=429, detail="Too many requests")
        if not admin_token:
            raise HTTPException(status_code=503, detail="Admin API is disabled (AEGIS_ADMIN_TOKEN not set)")
        if not secrets.compare_digest(x_admin_token.encode(), admin_token.encode()):
            raise HTTPException(status_code=401, detail="Invalid admin token")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/public-key")
    def public_key():
        return {"alg": "Ed25519", "key_id": verifier.key_id,
                "public_key_pem": export_public(verifier.public_key)}

    @app.post("/scan", dependencies=[Depends(limit_scan)])
    def scan(req: ScanRequest, request: Request):
        """Verify a product token through the 5-layer gate."""
        try:
            return verifier.verify(req.token.model_dump(), req.region, req.challenge)
        except VerificationError as exc:
            # Full detail (layer, expected region, ...) only in the server log.
            log.info("scan rejected layer=%s code=%s reason=%s ip=%s",
                     exc.layer, exc.code, exc.reason, client_ip(request))
            raise HTTPException(status_code=403, detail={
                "status": "REJECTED", "code": exc.code, "message": exc.public_message})

    @app.post("/admin/batches", dependencies=[Depends(require_admin)])
    def create_batch(req: BatchRequest):
        try:
            verifier.register_batch(req.batch_id, req.region)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return {"batch_id": req.batch_id, "region": req.region}

    @app.post("/admin/issue", dependencies=[Depends(require_admin)])
    def issue(req: IssueRequest):
        try:
            return verifier.issue_token(req.batch_id, req.ttl)
        except ValueError:
            raise HTTPException(status_code=404, detail="Unknown batch")

    @app.get("/admin/audit", dependencies=[Depends(require_admin)])
    def audit():
        return {"entries": len(verifier.log), "intact": verifier.log.verify(),
                "head": verifier.log.head}

    return app


app = create_app()
