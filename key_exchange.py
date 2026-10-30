"""X25519 key agreement and HKDF-based key derivation."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"SecureMessage v1 | Alice and Bob | encryption and HMAC keys"


def generate_exchange_key_pair():
    return x25519.X25519PrivateKey.generate()


def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)


def derive_message_keys(shared_secret):
    """Return independent 32-byte AES and HMAC keys from the shared secret."""
    material = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=HKDF_INFO).derive(shared_secret)
    return material[:32], material[32:]


def public_key_bytes(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
