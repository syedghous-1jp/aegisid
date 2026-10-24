"""Cryptographic primitives: Ed25519 signing, verification and key handling."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key,
)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def canonical_json(payload: object) -> bytes:
    """Deterministic JSON encoding used for everything that is signed or hashed."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def export_private(priv: Ed25519PrivateKey) -> str:
    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


def export_public(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def public_key_id(pub: Ed25519PublicKey) -> str:
    """Short, stable fingerprint of a public key (first 16 hex chars of SHA-256)."""
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_or_create_private_key(path: str) -> Ed25519PrivateKey:
    """Load a PEM private key from ``path``; create it (mode 0600) if missing."""
    if os.path.exists(path):
        with open(path, "rb") as fh:
            key = load_pem_private_key(fh.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
        return key
    priv = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(export_private(priv))
    return priv


def sign_json(priv: Ed25519PrivateKey, payload: dict) -> str:
    return b64e(priv.sign(canonical_json(payload)))


def verify_json(pub: Ed25519PublicKey, payload: dict, signature: str) -> bool:
    try:
        pub.verify(b64d(signature), canonical_json(payload))
        return True
    except Exception:
        return False


def new_product_id() -> str:
    """128-bit unguessable identifier (also used for nonces)."""
    return secrets.token_hex(16)
