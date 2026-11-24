
# Zero-Knowledge Encrypted Password Manager

A command-line credential vault built in Python implementing authenticated encryption and zero-knowledge storage principles.

## Security Architecture
* **Key Derivation:** PBKDF2-HMAC-SHA256 with **600,000 iterations** (per OWASP guidelines) and a unique 128-bit cryptographic salt (`os.urandom(16)`) per vault save to defend against rainbow table and brute-force attacks.
* **Authenticated Encryption:** **AES-256-GCM** with a fresh 96-bit nonce per encryption operation, ensuring both confidentiality and integrity (tampering with `vault.enc` invalidates the GCM authentication tag).
* **Zero-Knowledge Design:** The master password is never stored on disk or logged; losing it makes decryption mathematically infeasible.
* **Input Hygiene:** Uses Python's `getpass` module to prevent shoulder-surfing and shell history exposure.

## Threat Model & Mitigations

| Threat | Mitigation Implemented |
| :--- | :--- |
| Offline brute-force of `vault.enc` | High-iteration PBKDF2-SHA256 key stretching + random salt |
| Ciphertext tampering / bit-flipping | AES-GCM authentication tag verification prior to decryption |
| Nonce reuse attacks | Cryptographically random 96-bit nonce generated on every write |
| Shoulder surfing during input | Masked terminal input via `getpass` |

## Setup & Usage
```bash
pip install -r requirements.txt
python vault.py
```
