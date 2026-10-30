# SecureMessage

**Team 3 – Crusaders** · Innovation Hub, Dr. A.P.J. Abdul Kalam Technical University, Lucknow  
**Hackathon:** Build It Secure

SecureMessage is a browser-based React demonstration, backed by a local Python application, of how Alice and Bob can exchange encrypted, authenticated messages. The application simulates the workflow locally on one computer. It does not send messages over a network.

## The three problems this project solves

1. **An eavesdropper reads a message:** AES-256-GCM encrypts message content before it is packaged.
2. **An impostor sends a fake update:** Ed25519 signatures let the receiver check the sender against a trusted public signing key.
3. **A message is changed in transit:** the signature, HMAC-SHA256 and AES-GCM authentication tag detect changes and prevent plaintext from being displayed.

The prototype also demonstrates X25519 key agreement, separate key derivation with HKDF, and duplicate-message rejection during the current process.

## Security claims: what is protected and how to prove it

| Hackathon question | What SecureMessage does | How to show evidence in the demo |
| --- | --- | --- |
| Can an eavesdropper read the message? | AES-256-GCM encrypts the message using a key derived from the X25519 shared secret. The JSON package contains ciphertext, not plaintext. | Send a message, choose **Inspect package**, and show that the sentence is absent while the `ciphertext` field is present. The automated wrong-key test also shows that another key cannot decrypt it. |
| Can an attacker impersonate Alice? | Bob verifies the Ed25519 signature using Alice's trusted public signing key. A signature made with Bob's key does not verify as Alice. | Choose **Run forgery demo**. It signs Alice's fields using Bob's key, checks against Alice's public key, and rejects the message before displaying plaintext. |
| Can an attacker secretly change a message? | The Ed25519 signature and HMAC cover canonical message fields including the ciphertext. AES-GCM also authenticates encrypted content. | Choose **Run tampering demo**. The app flips a real ciphertext bit, reports failed signature and HMAC checks, rejects decryption, then verifies the unchanged original package. |

**Network interception limitation:** SecureMessage does not send Alice-to-Bob messages over a network, so it cannot demonstrate or prove that a live network attacker was blocked. The package inspector shows what an observer who obtained a message envelope could read: metadata and ciphertext, not the plaintext. The UI itself talks to a Python server on this computer's loopback address. This is a local cryptography demonstration, not a deployed network protocol.

### How does it authenticate a sender?

Alice signs the canonical envelope fields (message ID, timestamp, sender, recipient, nonce and ciphertext) with her Ed25519 private key. Bob verifies that signature with the public signing key associated with Alice. Changing any signed field invalidates the signature. The association between a name and public key must be trusted first; this demo creates both participants locally and trusts those generated keys. In a real application, users would verify fingerprints through a trusted independent channel or use a trusted identity service.

### How are keys exchanged and messages kept private?

Alice and Bob exchange only X25519 public keys. Each combines the other person's public key with their own private key and derives the same shared secret locally. HKDF-SHA256 then derives separate 32-byte AES and HMAC keys using a fixed SecureMessage context string. AES-256-GCM encrypts the message with a fresh random 12-byte nonce. The nonce and ciphertext are included in the JSON envelope; the AES key and raw shared secret are not.

### Where are the digital signature and HMAC used?

The sender signs the canonical envelope with Ed25519, which gives the receiver sender-specific verification when the public signing key is trusted. The sender also computes HMAC-SHA256 over the same canonical fields using a separately derived shared key. The receiver checks the signature and HMAC before decryption; Python's `hmac.compare_digest` compares HMAC values. HMAC is a shared-secret integrity check: either Alice or Bob can create a valid tag, so it cannot identify which one sent the message. AES-GCM adds its own ciphertext authentication; HMAC is an extra hackathon demonstration, not a substitute for signatures or GCM.

## Run with one command

Python 3.9 or newer is recommended. The built React interface is included, so Node.js and npm are not needed to run the demo. From the project folder, use the command for your operating system:

### Windows PowerShell

```powershell
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git SecureMessage
cd SecureMessage
py start.py
```

### macOS or Linux

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git SecureMessage
cd SecureMessage
python3 start.py
```

Replace `YOUR-USERNAME/YOUR-REPOSITORY` with the repository address after uploading this project. On first launch, `start.py` creates `.venv` and installs `cryptography`; later launches reuse the environment. It then starts the local server and opens the browser. Keep the terminal open while presenting; press **Ctrl+C** to stop it. The browser assets are bundled in the repository.

The terminal menu remains available after setup with `\.venv\Scripts\python.exe main.py` on Windows or `./.venv/bin/python main.py` on macOS/Linux. The committed browser bundle means users do not need Node.js. If you change the React source, rebuild it from the project folder using `npm ci` followed by `npm run build`, then commit the updated `web/assets/app.js` bundle.

## Try the message workflow

1. Choose **Generate keys**. Public and private keys are written to separate files in `keys/`; private keys are never printed. The program refuses to overwrite existing private keys.
2. Choose **Exchange keys**. The application exchanges public keys locally and confirms the derived secrets match without displaying them.
3. Select Alice or Bob, enter a message, and choose **Encrypt, sign & send**. The app saves an encrypted JSON package in `data/messages/`; plaintext is not saved.
4. Choose **Inspect package** to display the envelope an observer might obtain. The ciphertext is Base64-encoded for JSON; Base64 is only a representation and is not encryption.
5. Choose **Verify & decrypt**. The receiver checks the signature, HMAC and replay ID, then decrypts. The original message appears only if every check succeeds.

Keys and derived session keys are held in memory during the current run. Private keys are persisted, but the app does not automatically load them in a later run. For a fresh classroom run, use a clean project copy if key files already exist; the app will not silently replace them.

In this demo, the same application creates and trusts the participants' signing keys. In a real exchange, users need to authenticate each other's public signing keys in advance, such as by verifying a fingerprint through a separate trusted channel.

## How the cryptography works

### X25519 key exchange

Alice and Bob each generate a private key and a public key. They exchange only the public keys. Each combines their own private key with the other person's public key, independently deriving the same shared secret. The private exchange keys are not sent.

### HKDF-SHA256 key derivation

The shared secret is input key material, not an AES key. HKDF-SHA256 uses a fixed SecureMessage context string to derive two distinct 32-byte keys: one for encryption and one for HMAC. Keeping those purposes separate avoids reusing one derived key for both jobs.

### AES-256-GCM encryption

AES-GCM encrypts the message using a 256-bit key and also authenticates the encrypted bytes. Each encryption uses a fresh random 12-byte nonce, which is stored with the ciphertext. Decryption rejects an incorrect key or modified ciphertext/authentication tag.

### Ed25519 digital signatures

The sender signs the canonical message fields using their private signing key. The receiver checks the signature with that sender's trusted public signing key. A valid signature shows that the signed fields match and that they were signed by the holder of the matching private key. It identifies Alice only if Alice's public key was trusted beforehand; a public key received from an unknown source is not automatically trustworthy.

### HMAC-SHA256

HMAC creates a message authentication tag using the separately derived shared HMAC key. Verification uses Python's `hmac.compare_digest`. Both Alice and Bob know the shared key, so either could generate a valid HMAC. HMAC therefore does not prove which participant sent a message and does not replace Ed25519 signatures.

## What happens when a message is received

1. The receiver checks the Ed25519 signature using the sender's trusted public key.
2. The receiver checks HMAC over the canonical message fields.
3. The receiver rejects a previously processed message ID.
4. Only after those checks pass does the receiver decrypt with AES-GCM.
5. Plaintext is displayed only after decryption and its authentication check succeed.

Each outgoing message has a UUID and a UTC creation timestamp. The app remembers accepted message IDs in memory for the current process. A production system needs durable replay records and a defined timestamp freshness policy.

## Demonstration: evidence for each claim

### 1. Confidentiality and normal delivery

1. Choose **Generate keys**, then **Exchange keys** to create identities and matching session keys.
2. Choose Alice as sender, enter a sample update, and send it. The app saves an encrypted package rather than a plaintext file.
3. Choose **Inspect package** to show the visible envelope fields and ciphertext, with no plaintext field.
4. Choose **Verify & decrypt** to show that the signature, HMAC and AES-GCM checks pass and Bob can recover the original message.

### 2. Message tampering detection

1. Choose **8. Run Message Tampering Demo**.
2. The app creates a real encrypted package for `Meeting deadline is Friday.` and flips one bit in a temporary in-memory copy of the ciphertext.
3. It verifies that the modified copy fails signature and HMAC checks and is rejected before plaintext is shown.
4. It checks the unmodified package afterward and reports whether the original remains valid.

The demo performs actual signature, HMAC and encryption checks; the results are not hardcoded. The changed ciphertext also would fail AES-GCM decryption if the earlier checks were absent.

### 3. Digital signature forgery detection

1. Choose **9. Run Digital Signature Forgery Demo**.
2. The app signs Alice's message fields using Bob's distinct private signing key as the forgery attempt.
3. It verifies using Alice's trusted public key. Verification fails and the message is not decrypted or displayed.

## Run the automated tests

### Windows PowerShell

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### macOS or Linux

```bash
./.venv/bin/python -m unittest discover -s tests -v
```

The tests use newly generated test keys and do not write to the demo `keys/` or `data/messages/` folders.

| Test coverage | Evidence checked |
| --- | --- |
| X25519 and HKDF | Both parties derive matching secrets and consistent, separate keys. |
| AES-GCM | Correct key decrypts; wrong key and modified ciphertext are rejected. |
| Ed25519 | Alice's valid signature passes; a signature from another key fails. |
| HMAC-SHA256 | Valid HMAC passes; an incorrect HMAC fails. |
| Replay protection | A duplicate message ID is rejected. |
| Receiver safety | A tampered package never returns plaintext; wrong party keys cannot decrypt. |

## Project files

```text
SecureMessage/
├── run_showcase.py             # Local web server and API
├── main.py                     # Terminal menu and cryptography workflow
├── key_exchange.py             # X25519 and HKDF-SHA256
├── message_crypto.py           # AES-GCM, canonical envelope and HMAC
├── signature_utils.py          # Ed25519 key generation and verification
├── requirements.txt
├── package.json                # Optional React build command
├── README.md
├── .gitignore
├── web/                        # React source and bundled browser assets
├── data/messages/              # Generated encrypted JSON packages
├── keys/                       # Local keys; ignored by Git
└── tests/test_securemessage.py # unittest security checks
```

## How to explain this project to hackathon judges

**What problem does it solve?** It demonstrates how to keep a message private, verify its sender and detect unauthorized changes.

**How do Alice and Bob agree on a key without sending it?** They exchange X25519 public keys and combine the other person's public key with their own private key locally.

**Why is HKDF used?** It derives purpose-specific keys from the shared secret instead of using that raw secret directly as an encryption key.

**Why AES-GCM?** It encrypts the message and detects changes to the ciphertext or authentication tag.

**Why add HMAC if AES-GCM already authenticates ciphertext?** HMAC is an explicit hackathon requirement and demonstrates shared-key message authentication separately. It is an additional check, not a signature replacement.

**What does a digital signature prove?** It proves that the signed fields match a signature made by the private key corresponding to the trusted public key. Trust in that public key must be established separately.

**Can HMAC prove Alice specifically sent a message?** No. Both Alice and Bob know the HMAC key. Ed25519 provides sender-specific verification when Alice's public key is trusted.

**What happens if an attacker changes the ciphertext?** The signature and HMAC checks fail, so the receiver rejects the message before displaying plaintext. AES-GCM would also reject it during decryption.

**How does the app stop replaying a message?** It remembers accepted UUID message IDs in a set and rejects duplicates during the current run.

**Does this demonstrate security over a live network?** No. It simulates both participants locally. It does not open network connections or test against a live network attacker.

**Where are private keys kept?** In separate local PEM files, with restrictive permissions where supported. The files are excluded by `.gitignore`, but this local storage is not production-grade key management.

**What would be needed for production?** Authenticated key distribution, protected key storage and rotation, durable replay protection, timestamp validation, direction-specific session keys, a network protocol, metadata protections and independent security review.

## Prototype limits

- The application simulates message exchange locally. It does not provide network transport, server authentication or evidence of protection against live interception.
- Private PEM files are unencrypted. File permissions vary by operating system; `.gitignore` reduces accidental commits but is not a secure backup or access-control system.
- Private keys persist on disk, but keys and derived session keys are not automatically loaded into a later application run. Existing private keys are not silently overwritten.
- One derived encryption key and one derived HMAC key are shared in both message directions. Production should derive direction-specific keys and define nonce limits and rekeying.
- Replay tracking is memory-only, and timestamps are recorded but not validated. Production needs durable replay state and freshness rules.
- HMAC and signatures do not hide metadata. The JSON package exposes sender, recipient, timestamp, message ID and ciphertext size.
- The prototype does not implement key revocation, identity enrollment, multi-device support, forward secrecy across sessions, or a secure network transport.
