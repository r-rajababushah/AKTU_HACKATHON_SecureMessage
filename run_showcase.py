"""Launch the local React showcase UI for SecureMessage."""
import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import main as crypto_app
from message_crypto import canonical_envelope
from signature_utils import sign_message

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"


class ShowcaseHandler(BaseHTTPRequestHandler):
    server_version = "SecureMessageShowcase/1.0"

    def log_message(self, _format, *_args):
        return

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_asset(self, path, content_type):
        try:
            body = path.read_bytes()
        except OSError:
            self.send_json(404, {"error": "Showcase asset missing. Run npm install and npm run build."})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 100_000:
            raise ValueError("Request is too large.")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Request must be a JSON object.")
        return value

    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/":
            return self.send_asset(WEB_DIR / "index.html", "text/html; charset=utf-8")
        if route == "/assets/app.js":
            return self.send_asset(WEB_DIR / "assets" / "app.js", "text/javascript; charset=utf-8")
        if route == "/assets/styles.css":
            return self.send_asset(WEB_DIR / "assets" / "styles.css", "text/css; charset=utf-8")
        if route == "/assets/overrides.css":
            return self.send_asset(WEB_DIR / "assets" / "overrides.css", "text/css; charset=utf-8")
        if route == "/api/state":
            return self.send_json(200, {
                "keys_ready": len(crypto_app.exchange_keys) == 2 and len(crypto_app.signing_keys) == 2,
                "session_ready": crypto_app.encryption_key is not None,
                "processed_count": len(crypto_app.received_ids),
                "messages": sorted(path.name for path in crypto_app.MESSAGE_DIR.glob("*.json")),
            })
        if route == "/api/packages":
            packages = []
            for path in sorted(crypto_app.MESSAGE_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
                try:
                    data = crypto_app.load_package(path)
                    packages.append({"file": path.name, "message_id": data.get("message_id"), "sender": data.get("sender"), "recipient": data.get("recipient"), "created_at": data.get("created_at")})
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
            return self.send_json(200, {"packages": packages})
        if route == "/api/package":
            name = Path(parse_qs(urlparse(self.path).query).get("file", [""])[0]).name
            try:
                return self.send_json(200, {"package": crypto_app.load_package(crypto_app.MESSAGE_DIR / name)})
            except (OSError, ValueError, json.JSONDecodeError) as error:
                return self.send_json(404, {"error": str(error)})
        self.send_json(404, {"error": "Page not found."})

    def do_POST(self):
        route = urlparse(self.path).path
        try:
            payload = self.read_json()
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            return self.send_json(400, {"error": f"Invalid request: {error}"})
        try:
            if route == "/api/keys":
                crypto_app.generate_keys()
                return self.send_json(200, {"message": "Alice and Bob's key pairs were generated. Private keys were not displayed."})
            if route == "/api/exchange":
                if len(crypto_app.exchange_keys) != 2:
                    return self.send_json(400, {"error": "Generate Alice and Bob's keys first."})
                crypto_app.exchange_and_derive()
                if crypto_app.encryption_key is None:
                    return self.send_json(400, {"error": "Key exchange did not complete."})
                return self.send_json(200, {"message": "Both participants derived matching secrets; HKDF created separate AES and HMAC keys."})
            if route == "/api/send":
                sender = payload.get("sender")
                recipient = "Bob" if sender == "Alice" else "Alice" if sender == "Bob" else None
                text = payload.get("message")
                if not recipient or not isinstance(text, str) or not text.strip():
                    return self.send_json(400, {"error": "Choose a sender and enter a non-empty message."})
                package = crypto_app.create_package(sender, recipient, text)
                crypto_app.save_package(package)
                return self.send_json(201, {"message": "Encrypted package created and saved. Plaintext was not written to disk.", "package": package, "file": crypto_app.last_package_path.name})
            if route == "/api/receive":
                name = Path(str(payload.get("file", ""))).name
                package = crypto_app.load_package(crypto_app.MESSAGE_DIR / name)
                result = crypto_app.verify_and_decrypt(package, expected_recipient=package.get("recipient"), show=False)
                if result["plaintext"] is None:
                    return self.send_json(400, {"error": "Message rejected; plaintext was not returned.", "signature": result["signature"], "hmac": result["hmac"], "replay": result["replay"], "decrypted": False})
                return self.send_json(200, {"signature": result["signature"], "hmac": result["hmac"], "replay": result["replay"], "decrypted": True, "plaintext": result["plaintext"]})
            if route == "/api/tamper-demo":
                self._require_session()
                original = crypto_app.create_package("Alice", "Bob", "Meeting deadline is Friday.")
                crypto_app.save_package(original)
                modified = dict(original)
                raw = bytearray(crypto_app.unb64(modified["ciphertext"]))
                raw[0] ^= 1
                modified["ciphertext"] = crypto_app.b64(bytes(raw))
                failed = crypto_app.verify_and_decrypt(modified, "Bob", show=False)
                valid_original = crypto_app.verify_and_decrypt(original, "Bob", show=False)
                return self.send_json(200, {"tamper_detected": failed["plaintext"] is None and not failed["signature"] and not failed["hmac"], "signature": failed["signature"], "hmac": failed["hmac"], "modified_rejected": failed["plaintext"] is None, "original_valid": valid_original["plaintext"] == "Meeting deadline is Friday.", "message": "The changed copy was rejected. The original package still verifies."})
            if route == "/api/forgery-demo":
                self._require_session()
                original = crypto_app.create_package("Alice", "Bob", "The project deadline is Friday.")
                forged = dict(original)
                forged["signature"] = crypto_app.b64(sign_message(crypto_app.signing_keys["Bob"], canonical_envelope(forged)))
                result = crypto_app.verify_and_decrypt(forged, "Bob", show=False)
                return self.send_json(200, {"signature": result["signature"], "rejected": result["plaintext"] is None, "plaintext_shown": result["plaintext"] is not None, "message": "Signature made with Bob's key did not verify against Alice's trusted public key."})
        except FileExistsError as error:
            return self.send_json(409, {"error": str(error) + " Existing files were left untouched."})
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            return self.send_json(400, {"error": str(error)})
        self.send_json(404, {"error": "Action not found."})

    def _require_session(self):
        if crypto_app.encryption_key is None or len(crypto_app.signing_keys) != 2:
            raise ValueError("Generate keys and perform key exchange first.")


def main():
    host, port = "127.0.0.1", int(os.environ.get("SECUREMESSAGE_PORT", "8765"))
    server = ThreadingHTTPServer((host, port), ShowcaseHandler)
    url = f"http://{host}:{port}"
    print(f"SecureMessage showcase is running at {url}")
    print("This is a local demo; keep this terminal open. Press Ctrl+C to stop.")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SecureMessage showcase.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
