"""
RSA — Rivest–Shamir–Adleman Asymmetric Encryption
==================================================

RSA is one of the first public-key cryptosystems (1977) and is still widely
used for secure data transmission, digital signatures, and key exchange.

How it works
------------
1. Key generation
   a. Choose two distinct large primes  p  and  q.
   b. Compute  n = p * q            (public modulus).
   c. Compute  φ(n) = (p-1)(q-1)   (Euler's totient).
   d. Choose   e  : 1 < e < φ(n),  gcd(e, φ(n)) = 1   (public exponent).
   e. Compute  d ≡ e⁻¹ (mod φ(n))  (private exponent, via ext. Euclid).

2. Encryption  (public key):   c = m^e  mod n
3. Decryption  (private key):  m = c^d  mod n

Correctness follows from Euler's theorem: m^(φ(n)) ≡ 1 (mod n) when
gcd(m, n) = 1, so (m^e)^d = m^(ed) = m^(1 + k·φ(n)) ≡ m (mod n).

Security relies on the difficulty of factoring large n back into p and q
(the Integer Factorization Problem).

⚠️  This implementation is EDUCATIONAL.
    - Prime sizes (~10³–10⁵) are cryptographically tiny; real RSA uses 2048+
      bit primes.
    - Messages are encrypted character-by-character (textbook RSA), which is
      deterministic and malleable. Production RSA uses OAEP padding.

Dependencies (same repo)
------------------------
    prime_numbers.fermat_prime_test  →  is_prime
    GCD.euclidean                    →  gcd, modular_inverse
"""

import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from prime_numbers.fermat_prime_test import is_prime
from GCD.euclidean import gcd, modular_inverse

# ---------------------------------------------------------------------------
# Prime-generation bounds (increase for stronger — but slower — demos)
# ---------------------------------------------------------------------------
PRIME_MIN = 1_000
PRIME_MAX = 100_000


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_large_prime(lo: int = PRIME_MIN, hi: int = PRIME_MAX) -> int:
    """Return a random prime in the closed interval [lo, hi].

    Uses rejection sampling: draw uniformly at random until a prime is found.
    The Fermat primality test (10 rounds) is used as the primality filter.

    Args:
        lo: Lower bound (inclusive). Default: PRIME_MIN.
        hi: Upper bound (inclusive). Default: PRIME_MAX.

    Returns:
        A prime integer in [lo, hi].

    Raises:
        ValueError: If lo > hi or the range contains no primes.
    """
    if lo > hi:
        raise ValueError(f"Empty range: lo={lo} > hi={hi}")
    while True:
        num = random.randint(lo, hi)
        if is_prime(num):
            return num


def generate_rsa_keys(
    prime_lo: int = PRIME_MIN,
    prime_hi: int = PRIME_MAX,
) -> dict:
    """Generate an RSA key pair.

    Follows the textbook RSA key-generation algorithm:
      1. Sample two distinct primes p and q.
      2. n     = p * q
      3. φ(n)  = (p-1) * (q-1)
      4. Pick  e  in (1, φ(n)) with gcd(e, φ(n)) == 1.
         Common real-world choice: e = 65537 (skipped here for variety).
      5. d     = modular_inverse(e, φ(n))   →   e*d ≡ 1 (mod φ(n))

    Args:
        prime_lo: Minimum value for the generated primes.
        prime_hi: Maximum value for the generated primes.

    Returns:
        A dict with keys:
            public_key  – (e, n)
            private_key – (d, n)
            p, q        – the two prime factors  *(never share these!)*
            phi_n       – Euler's totient         *(never share this!)*

    Raises:
        ValueError: If modular inverse cannot be found (should not happen with
                    a correctly chosen e).
    """
    # Step 1 — two distinct primes
    p = generate_large_prime(prime_lo, prime_hi)
    q = generate_large_prime(prime_lo, prime_hi)
    while q == p:
        q = generate_large_prime(prime_lo, prime_hi)

    # Step 2 — modulus
    n = p * q

    # Step 3 — totient
    phi_n = (p - 1) * (q - 1)

    # Step 4 — public exponent: start from 65537 and fall back to random
    e = 65537 if gcd(65537, phi_n) == 1 else None
    if e is None:
        e = random.randint(2, phi_n - 1)
        while gcd(e, phi_n) != 1:
            e = random.randint(2, phi_n - 1)

    # Step 5 — private exponent
    d = modular_inverse(e, phi_n)

    return {
        "public_key":  (e, n),
        "private_key": (d, n),
        "p":    p,
        "q":    q,
        "phi_n": phi_n,
    }


# ---------------------------------------------------------------------------
# Encryption / Decryption
# ---------------------------------------------------------------------------

def encrypt(plaintext: str, public_key: tuple[int, int]) -> list[int]:
    """Encrypt *plaintext* with RSA using *public_key*.

    Each character is encrypted independently:
        c_i = ord(char_i) ^ e  mod  n   (textbook RSA, no padding)

    Args:
        plaintext:  The message to encrypt. Every character must satisfy
                    ord(char) < n; raises ValueError otherwise.
        public_key: Tuple (e, n).

    Returns:
        A list of integers (one per character).

    Raises:
        ValueError: If any character code >= n (message too large for the key).
    """
    e, n = public_key
    result = []
    for char in plaintext:
        m = ord(char)
        if m >= n:
            raise ValueError(
                f"Character {char!r} (ord={m}) >= n={n}. "
                "Use larger primes or a shorter/ASCII-only message."
            )
        result.append(pow(m, e, n))
    return result


def decrypt(ciphertext: list[int], private_key: tuple[int, int]) -> str:
    """Decrypt *ciphertext* with RSA using *private_key*.

    Each integer is decrypted independently:
        m_i = c_i ^ d  mod  n

    Args:
        ciphertext:  List of integers produced by :func:`encrypt`.
        private_key: Tuple (d, n).

    Returns:
        The original plaintext string.
    """
    d, n = private_key
    return "".join(chr(pow(c, d, n)) for c in ciphertext)


def sign(message: str, private_key: tuple[int, int]) -> list[int]:
    """Sign *message* with the RSA private key (textbook RSA signature).

    In real RSA signatures the hash of the message is signed, not the raw
    bytes. Here we sign each character's ordinal directly for simplicity.

        sig_i = ord(char_i) ^ d  mod  n

    Args:
        message:     The message to sign.
        private_key: Tuple (d, n).

    Returns:
        A list of integers representing the signature.
    """
    d, n = private_key
    return [pow(ord(c), d, n) for c in message]


def verify(message: str, signature: list[int], public_key: tuple[int, int]) -> bool:
    """Verify a signature produced by :func:`sign`.

    Applies the public key to each signature element and checks that the
    recovered value matches the original character ordinal.

        recovered_i = sig_i ^ e  mod  n  ==  ord(char_i)

    Args:
        message:    The original plaintext.
        signature:  The signature returned by :func:`sign`.
        public_key: Tuple (e, n).

    Returns:
        True if the signature is valid, False otherwise.
    """
    e, n = public_key
    if len(message) != len(signature):
        return False
    return all(pow(s, e, n) == ord(c) for s, c in zip(signature, message))


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print(f"{'RSA — Key Generation':^60}")
    print("=" * 60)

    keys = generate_rsa_keys()
    pub  = keys["public_key"]
    priv = keys["private_key"]

    print(f"  p            = {keys['p']}")
    print(f"  q            = {keys['q']}")
    print(f"  n  = p*q     = {pub[1]}")
    print(f"  φ(n)         = {keys['phi_n']}")
    print(f"  e (pub exp)  = {pub[0]}")
    print(f"  d (priv exp) = {priv[0]}")
    print(f"  Check e*d mod φ(n) = {(pub[0] * priv[0]) % keys['phi_n']}  (must be 1)")

    # --- Encryption / Decryption -------------------------------------------
    print()
    print("=" * 60)
    print(f"{'Encryption & Decryption':^60}")
    print("=" * 60)

    messages = ["HELLO RSA", "Hi!", "RSA 2025"]
    for msg in messages:
        try:
            cipher    = encrypt(msg, pub)
            recovered = decrypt(cipher, priv)
            ok = "✓" if recovered == msg else "✗"
            print(f"  [{ok}] '{msg}'  →  {cipher[:3]}{'...' if len(cipher)>3 else ''}  →  '{recovered}'")
        except ValueError as exc:
            print(f"  [!] '{msg}' — {exc}")

    # --- Digital Signature -------------------------------------------------
    print()
    print("=" * 60)
    print(f"{'Digital Signature':^60}")
    print("=" * 60)

    msg_to_sign = "authentic"
    sig = sign(msg_to_sign, priv)
    valid = verify(msg_to_sign, sig, pub)
    print(f"  Message   : '{msg_to_sign}'")
    print(f"  Signature : {sig[:4]}{'...' if len(sig)>4 else ''}")
    print(f"  Valid     : {valid}  (original message)")

    tampered = "tampered!"
    print(f"  Valid     : {verify(tampered, sig, pub)}  (tampered message '{tampered}')")

    # --- Key-size sensitivity demo ----------------------------------------
    print()
    print("=" * 60)
    print(f"{'Key-size sensitivity':^60}")
    print("=" * 60)
    print("  Generating keys with small primes (100–500) — faster but weaker:")
    small_keys = generate_rsa_keys(prime_lo=100, prime_hi=500)
    sp, sq, sn = small_keys["p"], small_keys["q"], small_keys["public_key"][1]
    print(f"  p={sp}, q={sq}, n={sn}")
    sc = encrypt("HI", small_keys["public_key"])
    sd = decrypt(sc, small_keys["private_key"])
    print(f"  Encrypt/decrypt 'HI' → cipher={sc} → '{sd}'")
