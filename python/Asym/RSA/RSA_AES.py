"""
RSA + AES Hybrid Encryption
============================

Pure RSA is slow and limited: it can only encrypt data smaller than the key
modulus. Real-world systems use **hybrid encryption**:

    1. Generate a random AES symmetric key (fast, arbitrary-length data).
    2. Encrypt the actual data with AES-CBC.
    3. Encrypt the AES key with RSA-OAEP (secure asymmetric key wrapping).

To decrypt:
    1. Decrypt the wrapped AES key with the RSA private key.
    2. Use the recovered AES key to decrypt the data.

This is how TLS, PGP, and most real cryptographic protocols work.

Libraries used
--------------
    pycryptodome  →  pip install pycryptodome
        Crypto.PublicKey.RSA       — RSA key generation / PEM serialization
        Crypto.Cipher.PKCS1_OAEP  — RSA encryption with OAEP padding (secure)
        Crypto.Cipher.AES          — AES-CBC symmetric encryption
        Crypto.Util.Padding        — PKCS#7 pad / unpad
        Crypto.Random              — Cryptographically secure random bytes
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_rsa_keypair(bits: int = 2048) -> tuple[RSA.RsaKey, RSA.RsaKey]:
    """Generate an RSA key pair.

    Args:
        bits: Key size in bits. Use 2048 minimum; 4096 for long-term security.

    Returns:
        Tuple (private_key, public_key).
    """
    private_key = RSA.generate(bits)
    return private_key, private_key.public_key()


def save_key(key: RSA.RsaKey, path: str, passphrase: str | None = None) -> None:
    """Save an RSA key to a PEM file.

    Args:
        key:        The RSA key to save (private or public).
        path:       Destination file path.
        passphrase: Optional passphrase to encrypt a private key at rest.
                    Ignored for public keys.
    """
    if passphrase and not key.has_private():
        passphrase = None  # Public keys are never encrypted
    pem = key.export_key(passphrase=passphrase) if key.has_private() else key.export_key()
    with open(path, "wb") as f:
        f.write(pem)


def load_key(path: str, passphrase: str | None = None) -> RSA.RsaKey:
    """Load an RSA key from a PEM file.

    Args:
        path:       Path to the PEM file.
        passphrase: Passphrase if the private key was saved encrypted.

    Returns:
        The RSA key object.
    """
    with open(path, "rb") as f:
        return RSA.import_key(f.read(), passphrase=passphrase)


# ---------------------------------------------------------------------------
# Hybrid encryption
# ---------------------------------------------------------------------------

def hybrid_encrypt(plaintext: bytes, public_key: RSA.RsaKey) -> dict:
    """Encrypt *plaintext* using RSA + AES hybrid encryption.

    Steps:
      1. Generate a random 256-bit AES session key.
      2. Encrypt *plaintext* with AES-CBC (random IV).
      3. Wrap (encrypt) the AES key with RSA-OAEP.

    Args:
        plaintext:  The raw bytes to encrypt.
        public_key: Recipient's RSA public key.

    Returns:
        A dict with:
            encrypted_aes_key  – AES key wrapped with RSA-OAEP (bytes)
            iv                 – AES initialisation vector (bytes)
            ciphertext         – AES-CBC encrypted data (bytes)
    """
    # Step 1 — random AES-256 session key
    aes_key = get_random_bytes(32)

    # Step 2 — AES-CBC encryption
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))

    # Step 3 — RSA-OAEP key wrapping
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    return {
        "encrypted_aes_key": encrypted_aes_key,
        "iv":                 aes_cipher.iv,
        "ciphertext":         ciphertext,
    }


def hybrid_decrypt(
    encrypted_aes_key: bytes,
    iv: bytes,
    ciphertext: bytes,
    private_key: RSA.RsaKey,
) -> bytes:
    """Decrypt data produced by :func:`hybrid_encrypt`.

    Steps:
      1. Unwrap the AES key with RSA-OAEP using the private key.
      2. Decrypt *ciphertext* with AES-CBC.

    Args:
        encrypted_aes_key: RSA-OAEP wrapped AES key.
        iv:                AES initialisation vector.
        ciphertext:        AES-CBC encrypted payload.
        private_key:       Recipient's RSA private key.

    Returns:
        The original plaintext bytes.
    """
    # Step 1 — unwrap AES key
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    # Step 2 — AES-CBC decryption
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(aes_cipher.decrypt(ciphertext), AES.block_size)


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print(f"{'RSA + AES Hybrid Encryption':^60}")
    print("=" * 60)

    # --- Key generation ---------------------------------------------------
    print("\n[1] Generating RSA-2048 key pair...")
    private_key, public_key = generate_rsa_keypair(bits=2048)
    print(f"    Key size : {private_key.size_in_bits()} bits")
    print(f"    Public e : {public_key.e}")

    # --- Save / load round-trip -------------------------------------------
    priv_path = "private.pem"
    pub_path  = "public.pem"
    save_key(private_key, priv_path)
    save_key(public_key,  pub_path)
    loaded_priv = load_key(priv_path)
    loaded_pub  = load_key(pub_path)
    print(f"    Saved and reloaded keys from {priv_path} / {pub_path}  ✓")

    # --- Hybrid encrypt / decrypt -----------------------------------------
    print("\n[2] Hybrid Encryption (RSA-OAEP wraps AES-256-CBC)")
    print("-" * 60)

    messages = [
        b"Hello, hybrid encryption!",
        b"RSA alone cannot encrypt large data efficiently. "
        b"Hybrid encryption combines the best of both worlds: "
        b"AES speed + RSA secure key exchange.",
        b"\x00\x01\x02binary\xffdata\xfe works too",
    ]

    for msg in messages:
        bundle = hybrid_encrypt(msg, loaded_pub)
        recovered = hybrid_decrypt(
            bundle["encrypted_aes_key"],
            bundle["iv"],
            bundle["ciphertext"],
            loaded_priv,
        )
        ok = "✓" if recovered == msg else "✗"
        preview = msg[:40].decode(errors="replace")
        if len(msg) > 40:
            preview += "..."
        print(f"  [{ok}] '{preview}'")
        print(f"       AES key (wrapped) : {bundle['encrypted_aes_key'].hex()[:32]}...")
        print(f"       IV               : {bundle['iv'].hex()}")
        print(f"       Ciphertext       : {bundle['ciphertext'].hex()[:32]}...")

    # --- Tamper detection -------------------------------------------------
    print("\n[3] Tamper detection")
    print("-" * 60)
    bundle = hybrid_encrypt(b"secret payload", loaded_pub)
    tampered = bytearray(bundle["ciphertext"])
    tampered[0] ^= 0xFF                             # flip bits in first byte
    try:
        hybrid_decrypt(bundle["encrypted_aes_key"], bundle["iv"], bytes(tampered), loaded_priv)
        print("  [✗] Tampered ciphertext was accepted — unexpected!")
    except (ValueError, KeyError):
        print("  [✓] Tampered ciphertext correctly rejected (padding error)")

    # --- Clean up PEM files -----------------------------------------------
    os.remove(priv_path)
    os.remove(pub_path)
    print(f"\n  Removed temporary key files ({priv_path}, {pub_path})")
