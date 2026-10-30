"""AES-256-GCM encryption and separate HMAC-SHA256 authentication."""
import hashlib
import hmac
import json
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical_envelope(envelope: dict) -> bytes:
    """Serialize only signed/authenticated fields in a stable representation."""
    fields = {name: envelope[name] for name in ("message_id", "created_at", "sender", "recipient", "nonce", "ciphertext")}
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encrypt_message(plaintext: str, encryption_key: bytes):
    nonce = os.urandom(12)  # Fresh 96-bit nonce for every AES-GCM operation.
    ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext


def decrypt_message(nonce: bytes, ciphertext: bytes, encryption_key: bytes) -> str:
    try:
        return AESGCM(encryption_key).decrypt(nonce, ciphertext, None).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise ValueError("Message decryption/authentication failed") from exc


def calculate_hmac(envelope: dict, hmac_key: bytes) -> bytes:
    return hmac.new(hmac_key, canonical_envelope(envelope), hashlib.sha256).digest()


def verify_hmac(envelope: dict, supplied_mac: bytes, hmac_key: bytes) -> bool:
    return hmac.compare_digest(calculate_hmac(envelope, hmac_key), supplied_mac)
