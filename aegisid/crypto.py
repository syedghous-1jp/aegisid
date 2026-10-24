
"""Cryptographic primitives: Ed25519 signing and verification."""
import base64
import json
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def export_private(priv: Ed25519PrivateKey) -> str:
    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


def export_public(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def sign_json(priv: Ed25519PrivateKey, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return b64e(priv.sign(canonical))


def verify_json(pub: Ed25519PublicKey, payload: dict, signature: str) -> bool:
    try:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        pub.verify(b64d(signature), canonical)
        return True
    except Exception:
        return False


def new_product_id() -> str:
    """128-bit unguessable product identifier."""
    return secrets.token_hex(16)
