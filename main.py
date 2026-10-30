"""SecureMessage: a local, educational cryptography demonstration.,"""
import base64
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from key_exchange import derive_message_keys, derive_shared_secret, generate_exchange_key_pair
from message_crypto import calculate_hmac, decrypt_message, encrypt_message, verify_hmac
from signature_utils import generate_signing_key_pair, sign_message, verify_signature

ROOT = Path(__file__).resolve().parent
KEY_DIR = ROOT / "keys"
MESSAGE_DIR = ROOT / "data" / "messages"
USERS = ("Alice", "Bob")
exchange_keys = {}
signing_keys = {}
trusted_signing_public = {}
encryption_key = None
hmac_key = None
received_ids = set()
last_package_path = None


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def set_private_file_permissions(path: Path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows permissions are managed differently.


def save_private_key(path: Path, private_key):
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing private key: {path.name}")
    path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    set_private_file_permissions(path)


def generate_keys():
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for user in USERS:
            xpriv = generate_exchange_key_pair()
            spriv = generate_signing_key_pair()
            save_private_key(KEY_DIR / f"{user.lower()}_x25519_private.pem", xpriv)
            created.append(KEY_DIR / f"{user.lower()}_x25519_private.pem")
            save_private_key(KEY_DIR / f"{user.lower()}_ed25519_private.pem", spriv)
            created.append(KEY_DIR / f"{user.lower()}_ed25519_private.pem")
            (KEY_DIR / f"{user.lower()}_x25519_public.pem").write_bytes(xpriv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            (KEY_DIR / f"{user.lower()}_ed25519_public.pem").write_bytes(spriv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            exchange_keys[user] = xpriv
            signing_keys[user] = spriv
            trusted_signing_public[user] = spriv.public_key()
    except Exception:
        # Do not remove keys already created: preserve them and require deliberate user action.
        raise
    print("Alice and Bob key pairs generated and public keys saved separately.")
    print("Private key files are protected locally; no private keys were displayed.")


def exchange_and_derive():
    global encryption_key, hmac_key
    if len(exchange_keys) != 2:
        print("Generate keys first in this run.")
        return
    alice_pub = exchange_keys["Alice"].public_key()
    bob_pub = exchange_keys["Bob"].public_key()
    alice_secret = derive_shared_secret(exchange_keys["Alice"], bob_pub)
    bob_secret = derive_shared_secret(exchange_keys["Bob"], alice_pub)
    if alice_secret != bob_secret:
        print("Key exchange failed: derived secrets do not match.")
        return
    encryption_key, hmac_key = derive_message_keys(alice_secret)
    print("Public keys exchanged locally. Both parties derived matching shared secrets.")
    print("HKDF derived separate AES-256 and HMAC keys. Secret key material is not displayed.")


def create_package(sender: str, recipient: str, text: str):
    if encryption_key is None or hmac_key is None:
        raise RuntimeError("Perform key exchange first.")
    nonce, ciphertext = encrypt_message(text, encryption_key)
    envelope = {
        "message_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sender": sender,
        "recipient": recipient,
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
    }
    canonical = __import__("message_crypto").canonical_envelope(envelope)
    signature = sign_message(signing_keys[sender], canonical)
    mac = calculate_hmac(envelope, hmac_key)
    return {**envelope, "signature": b64(signature), "hmac_sha256": b64(mac)}


def save_package(package: dict):
    global last_package_path
    MESSAGE_DIR.mkdir(parents=True, exist_ok=True)
    path = MESSAGE_DIR / f"{package['message_id']}.json"
    path.write_text(json.dumps(package, indent=2), encoding="utf-8")
    last_package_path = path
    print(f"Encrypted package saved: {path.relative_to(ROOT)}")


def send_message(sender: str, recipient: str):
    if sender not in signing_keys:
        print("Generate keys first in this run.")
        return
    text = input(f"{sender}, enter your message: ")
    try:
        package = create_package(sender, recipient, text)
        save_package(package)
        print("Message encrypted, signed and authenticated. Plaintext was not saved.")
    except Exception as exc:
        print(f"Could not send message: {exc}")


def verify_and_decrypt(package: dict, expected_recipient: str = None, show: bool = True):
    """Check signature, HMAC, replay ID, then decrypt; plaintext comes last."""
    results = {"signature": False, "hmac": False, "replay": False, "plaintext": None}
    try:
        sender, recipient = package["sender"], package["recipient"]
        canonical = __import__("message_crypto").canonical_envelope(package)
        results["signature"] = verify_signature(trusted_signing_public[sender], canonical, unb64(package["signature"]))
    except Exception:
        results["signature"] = False
    try:
        results["hmac"] = verify_hmac(package, unb64(package["hmac_sha256"]), hmac_key) if hmac_key else False
    except Exception:
        results["hmac"] = False
    results["replay"] = package.get("message_id") not in received_ids
    if show:
        print(f"Digital signature verification: {'PASSED' if results['signature'] else 'FAILED'}")
        print(f"Message authentication (HMAC): {'PASSED' if results['hmac'] else 'FAILED'}")
    if not (results["signature"] and results["hmac"] and results["replay"]):
        if show:
            if not results["replay"]:
                print("Replay protection: REJECTED duplicate message ID")
            print("Message decryption: REJECTED")
        return results
    if expected_recipient and recipient != expected_recipient:
        if show:
            print("Message decryption: REJECTED (wrong recipient)")
        return results
    try:
        results["plaintext"] = decrypt_message(unb64(package["nonce"]), unb64(package["ciphertext"]), encryption_key)
    except Exception:
        if show:
            print("Message decryption: REJECTED")
        return results
    received_ids.add(package["message_id"])
    if show:
        print("Message decryption: SUCCESS")
        print(f"Original message: {results['plaintext']}")
    return results


def load_package(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def receive_message():
    if hmac_key is None:
        print("Perform key exchange first in this run.")
        return
    raw_path = input("Package path (Enter for most recently sent): ").strip()
    path = Path(raw_path) if raw_path else last_package_path
    if path is None or not path.exists():
        print("Package file not found.")
        return
    try:
        package = load_package(path)
        verify_and_decrypt(package, expected_recipient=package.get("recipient"))
    except Exception as exc:
        print(f"Could not process package: {exc}")


def display_package():
    path = last_package_path
    if path is None:
        raw_path = input("Package path: ").strip()
        path = Path(raw_path)
    try:
        print(json.dumps(load_package(path), indent=2))
    except Exception as exc:
        print(f"Could not display package: {exc}")


def tampering_demo():
    global encryption_key, hmac_key
    if encryption_key is None:
        print("Generate keys and perform key exchange first.")
        return
    print("\n=== MESSAGE TAMPERING DEMO ===\n")
    original = create_package("Alice", "Bob", "Meeting deadline is Friday.")
    save_package(original)
    print('Alice sends:\n"Meeting deadline is Friday."\n\nEncrypted message created.')
    modified = json.loads(json.dumps(original))
    raw = bytearray(unb64(modified["ciphertext"]))
    raw[0] ^= 1
    modified["ciphertext"] = b64(bytes(raw))
    print("\nSimulating an attacker modifying the ciphertext...\n\nBob receives modified message.")
    result = verify_and_decrypt(modified, expected_recipient="Bob", show=False)
    print(f"Digital signature verification: {'PASSED' if result['signature'] else 'FAILED'}")
    print(f"Message authentication: {'PASSED' if result['hmac'] else 'FAILED'}")
    print(f"Message decryption: {'SUCCESS' if result['plaintext'] is not None else 'REJECTED'}")
    print("\nRESULT: MESSAGE TAMPERING DETECTED!" if result["plaintext"] is None else "\nRESULT: Unexpected acceptance")
    valid = verify_and_decrypt(original, expected_recipient="Bob", show=False)
    print(f"\nOriginal message package: {'VALID' if valid['plaintext'] is not None else 'INVALID'}")


def forgery_demo():
    if encryption_key is None:
        print("Generate keys and perform key exchange first.")
        return
    package = create_package("Alice", "Bob", "The project deadline is Friday.")
    # Change Alice's valid signature to a signature produced by Bob's distinct key.
    forged = dict(package)
    canonical = __import__("message_crypto").canonical_envelope(forged)
    forged["signature"] = b64(sign_message(signing_keys["Bob"], canonical))
    print("\n=== DIGITAL SIGNATURE FORGERY DEMO ===")
    outcome = verify_and_decrypt(forged, expected_recipient="Bob", show=False)
    print(f"Signature checked against Alice's trusted public key: {'PASSED' if outcome['signature'] else 'FAILED'}")
    print(f"Message rejected before plaintext display: {'YES' if outcome['plaintext'] is None else 'NO'}")


def print_menu():
    print("\n=== SecureMessage | Team 3 – Crusaders ===")
    print("1. Generate Alice and Bob keys")
    print("2. Perform X25519 key exchange")
    print("3. Verify both users derived the same shared secret")
    print("4. Send encrypted message from Alice to Bob")
    print("5. Send encrypted message from Bob to Alice")
    print("6. Display the encrypted message package")
    print("7. Verify and decrypt a received message")
    print("8. Run Message Tampering Demo")
    print("9. Run Digital Signature Forgery Demo")
    print("10. Exit")


def main():
    while True:
        print_menu()
        choice = input("Choose an option: ").strip()
        if choice == "1":
            try:
                generate_keys()
            except FileExistsError as exc:
                print(f"{exc}. Existing keys were left untouched; back them up/remove them deliberately before generating new keys.")
            except Exception as exc:
                print(f"Key generation failed: {exc}")
        elif choice in ("2", "3"):
            exchange_and_derive()
        elif choice == "4":
            send_message("Alice", "Bob")
        elif choice == "5":
            send_message("Bob", "Alice")
        elif choice == "6":
            display_package()
        elif choice == "7":
            receive_message()
        elif choice == "8":
            tampering_demo()
        elif choice == "9":
            forgery_demo()
        elif choice == "10":
            print("Goodbye.")
            break
        else:
            print("Choose a number from 1 to 10.")


if __name__ == "__main__":
    main()
