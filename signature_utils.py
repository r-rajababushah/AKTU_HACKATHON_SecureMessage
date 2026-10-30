"""Ed25519 signing helpers."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_signing_key_pair():
    return ed25519.Ed25519PrivateKey.generate()


def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message)


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
