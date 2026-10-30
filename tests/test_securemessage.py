import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from key_exchange import derive_message_keys, derive_shared_secret, generate_exchange_key_pair
from message_crypto import calculate_hmac, decrypt_message, encrypt_message, verify_hmac
from signature_utils import generate_signing_key_pair, sign_message, verify_signature
from main import verify_and_decrypt


def enc(value):
    return base64.b64encode(value).decode("ascii")


class SecureMessageTests(unittest.TestCase):
    def setUp(self):
        self.alice_x = generate_exchange_key_pair()
        self.bob_x = generate_exchange_key_pair()
        self.alice_sign = generate_signing_key_pair()
        self.bob_sign = generate_signing_key_pair()
        shared_a = derive_shared_secret(self.alice_x, self.bob_x.public_key())
        shared_b = derive_shared_secret(self.bob_x, self.alice_x.public_key())
        self.assertEqual(shared_a, shared_b)
        self.enc_key, self.mac_key = derive_message_keys(shared_a)
        import main
        main.encryption_key = self.enc_key
        main.hmac_key = self.mac_key

    def envelope(self):
        nonce, ciphertext = encrypt_message("hello", self.enc_key)
        return {"message_id": "id-1", "created_at": "2026-01-01T00:00:00Z", "sender": "Alice", "recipient": "Bob", "nonce": enc(nonce), "ciphertext": enc(ciphertext)}

    def sign_envelope(self, envelope, signer=None):
        from message_crypto import canonical_envelope
        envelope["signature"] = enc(sign_message(signer or self.alice_sign, canonical_envelope(envelope)))
        envelope["hmac_sha256"] = enc(calculate_hmac(envelope, self.mac_key))
        return envelope

    def test_x25519_key_pairs_and_matching_secret(self):
        self.assertIsNotNone(self.alice_x.public_key())
        self.assertEqual(derive_shared_secret(self.alice_x, self.bob_x.public_key()), derive_shared_secret(self.bob_x, self.alice_x.public_key()))

    def test_hkdf_consistent_keys(self):
        shared = derive_shared_secret(self.alice_x, self.bob_x.public_key())
        self.assertEqual(derive_message_keys(shared), derive_message_keys(shared))
        self.assertEqual(len(self.enc_key), 32)
        self.assertEqual(len(self.mac_key), 32)
        self.assertNotEqual(self.enc_key, self.mac_key)

    def test_encrypt_decrypt_and_wrong_key(self):
        nonce, ciphertext = encrypt_message("hello", self.enc_key)
        self.assertEqual(decrypt_message(nonce, ciphertext, self.enc_key), "hello")
        with self.assertRaises(ValueError):
            decrypt_message(nonce, ciphertext, b"x" * 32)

    def test_signature_valid_and_forgery_rejected(self):
        message = b"signed"
        signature = sign_message(self.alice_sign, message)
        self.assertTrue(verify_signature(self.alice_sign.public_key(), message, signature))
        self.assertFalse(verify_signature(self.alice_sign.public_key(), message, sign_message(self.bob_sign, message)))

    def test_hmac_valid_and_modified_rejected(self):
        envelope = self.envelope()
        mac = calculate_hmac(envelope, self.mac_key)
        self.assertTrue(verify_hmac(envelope, mac, self.mac_key))
        self.assertFalse(verify_hmac(envelope, bytes([mac[0] ^ 1]) + mac[1:], self.mac_key))

    def test_modified_ciphertext_rejected(self):
        envelope = self.envelope()
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
        ciphertext[0] ^= 1
        envelope["ciphertext"] = enc(ciphertext)
        with self.assertRaises(ValueError):
            decrypt_message(base64.b64decode(envelope["nonce"]), ciphertext, self.enc_key)

    def test_modified_hmac_rejected(self):
        envelope = self.envelope()
        self.assertFalse(verify_hmac(envelope, b"wrong", self.mac_key))

    def test_duplicate_message_id_rejected(self):
        from main import received_ids, trusted_signing_public
        received_ids.clear()
        trusted_signing_public.clear()
        trusted_signing_public["Alice"] = self.alice_sign.public_key()
        envelope = self.sign_envelope(self.envelope())
        first = verify_and_decrypt(envelope, "Bob", show=False)
        second = verify_and_decrypt(envelope, "Bob", show=False)
        self.assertEqual(first["plaintext"], "hello")
        self.assertIsNone(second["plaintext"])
        self.assertFalse(second["replay"])
        received_ids.clear()

    def test_tampered_package_never_reveals_plaintext(self):
        from main import received_ids, trusted_signing_public
        received_ids.clear()
        trusted_signing_public.clear()
        trusted_signing_public["Alice"] = self.alice_sign.public_key()
        envelope = self.sign_envelope(self.envelope())
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
        ciphertext[0] ^= 1
        envelope["ciphertext"] = enc(ciphertext)
        result = verify_and_decrypt(envelope, "Bob", show=False)
        self.assertIsNone(result["plaintext"])
        received_ids.clear()

    def test_wrong_party_keys_cannot_decrypt(self):
        nonce, ciphertext = encrypt_message("secret", self.enc_key)
        wrong_shared = derive_shared_secret(generate_exchange_key_pair(), self.bob_x.public_key())
        wrong_encryption_key, _ = derive_message_keys(wrong_shared)
        with self.assertRaises(ValueError):
            decrypt_message(nonce, ciphertext, wrong_encryption_key)


if __name__ == "__main__":
    unittest.main()
