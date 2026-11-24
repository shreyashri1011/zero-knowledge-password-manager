import os
import json
import base64
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = "vault.enc"
ITERATIONS = 600_000  # OWASP recommended minimum for PBKDF2-SHA256


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a 256-bit cryptographic key from the master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def save_vault(data: dict, master_password: str) -> None:
    """Encrypts and authenticates the vault dictionary using AES-256-GCM."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)

    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    payload = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_vault(master_password: str) -> dict:
    """Decrypts the vault file; raises an exception if password is wrong or tampered."""
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        payload = json.load(f)

    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def main():
    print("=== Zero-Knowledge CLI Password Manager ===")
    master_password = getpass.getpass("Enter Master Password: ")

    try:
        vault = load_vault(master_password)
    except Exception:
        print("[!] Authentication failed: Invalid master password or corrupted vault.")
        return

    while True:
        choice = input("\n[1] Add Credential  [2] Retrieve Credential  [3] List Services  [4] Exit: ").strip()
        if choice == "1":
            service = input("Service (e.g., github.com): ").strip().lower()
            username = input("Username/Email: ").strip()
            secret = getpass.getpass("Password to store: ")
            vault[service] = {"username": username, "password": secret}
            save_vault(vault, master_password)
            print(f"[+] Encrypted and saved credentials for {service}.")
        elif choice == "2":
            service = input("Service name: ").strip().lower()
            if service in vault:
                print(f"Username: {vault[service]['username']}")
                print(f"Password: {vault[service]['password']}")
            else:
                print("[-] Service not found.")
        elif choice == "3":
            print("Stored services:", ", ".join(vault.keys()) or "None")
        elif choice == "4":
            break


if __name__ == "__main__":
    main()
