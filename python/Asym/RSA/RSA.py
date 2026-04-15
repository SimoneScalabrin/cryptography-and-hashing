import random
import sys
import os
from math import floor, sqrt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from prime_numbers.fermat_prime_test import is_prime
from GCD.euclidean import gcd, modular_inverse

RANDOM_START = 1e3
RANDOM_END = 1e5


def generate_large_prime(start=RANDOM_START, end=RANDOM_END) -> int:
    """Generate a random prime number in the range [RANDOM_START, RANDOM_END]."""
    while True:
        num = random.randint(int(RANDOM_START), int(RANDOM_END))
        if is_prime(num):
            return num

def generate_rsa_keys() -> dict:
    """Generate a pair of RSA keys (public and private).

    Returns:
        dict: A dictionary containing the public key (e, n) and private key (d, n).
    """
    # Step 1: Generate two distinct large primes p and q
    p = generate_large_prime()
    q = generate_large_prime()
    while q == p:
        q = generate_large_prime()

    # Step 2: Compute n = p * q
    n = p * q

    # Step 3: Compute φ(n) = (p - 1) * (q - 1)
    phi_n = (p - 1) * (q - 1)

    # Step 4: Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = random.randint(2, phi_n - 1)
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Step 5: Compute d such that d ≡ e^(-1) mod φ(n)
    d = modular_inverse(e, phi_n)

    return {
        "public_key": (e, n),
        "private_key": (d, n),
        "p": p,
        "q": q,
        "phi_n": phi_n,
    }


def encrypt(plain_text: str, public_key: tuple) -> str:
    """Encrypt a message using the RSA public key.

    Args:
        plain_text (str): The plaintext message to encrypt (must be < n).
        public_key (tuple): The RSA public key (e, n).

    Returns:
        str: The encrypted ciphertext.
    """
    e, n = public_key
    cipher_text = []
    for char in plain_text:
        a = ord(char)
        cipher_text.append(pow(a, e, n))
    
    return cipher_text

def decrypt(cipher_text: list, private_key: tuple) -> str:
    """Decrypt a message using the RSA private key.

    Args:
        cipher_text (list): The encrypted message (must be < n).
        private_key (tuple): The RSA private key (d, n).

    Returns:
        str: The decrypted plaintext.
    """
    d, n = private_key
    plain_text = []
    for num in cipher_text:
        a = pow(num, d, n)
        plain_text.append(chr(a))
    
    return ''.join(plain_text)

if __name__ == "__main__":
    keys = generate_rsa_keys()
    print("Public Key (e, n):", keys["public_key"])
    print("Private Key (d, n):", keys["private_key"])
    print("p:", keys["p"])
    print("q:", keys["q"])
    print("φ(n):", keys["phi_n"])

    message = "HELLO RSA"
    print("\nOriginal Message:", message)

    cipher = encrypt(message, keys["public_key"])
    print("Encrypted Message:", cipher)

    decrypted = decrypt(cipher, keys["private_key"])
    print("Decrypted Message:", decrypted)