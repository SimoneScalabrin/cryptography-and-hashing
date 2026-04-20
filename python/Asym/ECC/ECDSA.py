"""
ECDSA — Elliptic Curve Digital Signature Algorithm
====================================================
ECDSA is a digital signature scheme based on elliptic-curve cryptography.
It provides the same security guarantees as RSA but with much smaller key sizes,
making it efficient for constrained environments (e.g., TLS, JWT, blockchain).

How it works:
  1. Key generation  — a private key (random scalar) and a public key (point on
                       the curve) are generated from a chosen elliptic curve.
  2. Signing         — the message is hashed; the hash and the private key are
                       combined with a random nonce to produce a signature (r, s).
  3. Verification    — given the public key, message hash, and signature, anyone
                       can verify that the signature was produced by the holder of
                       the corresponding private key without ever seeing that key.

Security notes:
  - Never reuse the signing nonce; nonce reuse leaks the private key (the Sony PS3
    hack is a famous real-world example).
  - The PyCryptodome DSS implementation handles nonce generation securely.
  - FIPS 186-3 mode (used here) is deterministic-friendly and widely supported.

Dependencies:
    pip install pycryptodome
"""

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def generate_keypair(curve: str = "P-256") -> ECC.EccKey:
    """Generate a new ECC key pair on the specified curve.

    Args:
        curve: Name of the elliptic curve to use.
               Common choices: "P-256" (default), "P-384", "P-521", "Ed25519".

    Returns:
        An EccKey object that contains both the private and public key.
    """
    return ECC.generate(curve=curve)


def sign_message(private_key: ECC.EccKey, message: str) -> bytes:
    """Sign a message with an ECC private key using ECDSA (FIPS 186-3).

    The message is first hashed with SHA-256 before signing so that the
    signature covers a fixed-size digest rather than the raw message.

    Args:
        private_key: The signer's ECC private key.
        message:     The plaintext message to sign.

    Returns:
        The DER-encoded ECDSA signature as bytes.
    """
    digest = SHA256.new(message.encode())
    signer = DSS.new(private_key, "fips-186-3")
    return signer.sign(digest)


def verify_signature(public_key: ECC.EccKey, message: str, signature: bytes) -> bool:
    """Verify an ECDSA signature against a message and public key.

    Args:
        public_key: The signer's ECC public key.
        message:    The original plaintext message.
        signature:  The DER-encoded signature produced by :func:`sign_message`.

    Returns:
        True if the signature is valid, False otherwise.
    """
    digest = SHA256.new(message.encode())
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(digest, signature)
        return True
    except ValueError:
        return False


def export_keys(key: ECC.EccKey) -> tuple[str, str]:
    """Export the private and public key as PEM-encoded strings.

    PEM export is the standard way to persist or transmit keys.

    Args:
        key: The ECC key pair to export.

    Returns:
        A tuple of (private_pem, public_pem) strings.
    """
    private_pem = key.export_key(format="PEM")
    public_pem = key.public_key().export_key(format="PEM")
    return private_pem, public_pem


def import_private_key(pem: str) -> ECC.EccKey:
    """Import an ECC private key from a PEM string.

    Args:
        pem: PEM-encoded private key string.

    Returns:
        The reconstructed EccKey object (contains both private and public key).
    """
    return ECC.import_key(pem)


def import_public_key(pem: str) -> ECC.EccKey:
    """Import an ECC public key from a PEM string.

    Args:
        pem: PEM-encoded public key string.

    Returns:
        The reconstructed EccKey object (public key only).
    """
    return ECC.import_key(pem)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("ECDSA — Elliptic Curve Digital Signature Algorithm Demo")
    print("=" * 60)

    # --- 1. Key generation ---------------------------------------------------
    print("\n[1] Generating ECC key pair (curve P-256) ...")
    key = generate_keypair(curve="P-256")
    private_pem, public_pem = export_keys(key)
    print("    Private key (PEM):")
    print("   ", "\n    ".join(private_pem.splitlines()))
    print("    Public key (PEM):")
    print("   ", "\n    ".join(public_pem.splitlines()))

    # --- 2. Sign a message ---------------------------------------------------
    message = "Transfer $1,000 from Alice to Bob on 2026-04-20."
    print(f"\n[2] Signing message:\n    \"{message}\"")
    signature = sign_message(key, message)
    print(f"    Signature (hex): {signature.hex()}")

    # --- 3. Verify with the correct public key -------------------------------
    print("\n[3] Verifying signature with the correct public key ...")
    restored_public_key = import_public_key(public_pem)
    result = verify_signature(restored_public_key, message, signature)
    print(f"    Valid: {result}")  # Expected: True

    # --- 4. Tampered message — signature must be rejected --------------------
    tampered = "Transfer $9,999 from Alice to Bob on 2026-04-20."
    print(f"\n[4] Verifying against a tampered message:\n    \"{tampered}\"")
    result = verify_signature(restored_public_key, tampered, signature)
    print(f"    Valid: {result}")  # Expected: False

    # --- 5. Wrong key — signature must be rejected ---------------------------
    print("\n[5] Verifying with a different (wrong) public key ...")
    wrong_key = generate_keypair(curve="P-256")
    result = verify_signature(wrong_key.public_key(), message, signature)
    print(f"    Valid: {result}")  # Expected: False

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print("  Correct key + original message  → Valid: True")
    print("  Correct key + tampered message  → Valid: False")
    print("  Wrong key   + original message  → Valid: False")


if __name__ == "__main__":
    main()
