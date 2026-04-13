"""
Diffie-Hellman Key Exchange
===========================

Protocol overview
-----------------
Alice and Bob want to share a secret key over a public channel without ever
transmitting the secret itself. Eve can intercept everything but cannot
recover the key (assuming the Discrete Logarithm Problem is hard).

Public parameters (posted openly):
    p  — large prime modulus
    g  — primitive root / generator (typically 2 or 5)

Steps:
    1. Alice picks private key  a  (random, kept secret)
       Computes public key  A = g^a mod p  → sends A to Bob
    2. Bob picks private key  b  (random, kept secret)
       Computes public key  B = g^b mod p  → sends B to Alice
    3. Alice computes  shared = B^a mod p = g^(ab) mod p
       Bob   computes  shared = A^b mod p = g^(ab) mod p
       → Both get the same shared secret!

Eve sees (p, g, A, B) but recovering a, b, or the shared secret requires
solving the Discrete Logarithm Problem — infeasible for large p.
"""

import random


def generate_keypair(p: int, g: int) -> tuple[int, int]:
    """
    Generate a (private_key, public_key) pair for one party.

    Args:
        p (int): Public prime modulus.
        g (int): Public generator (primitive root modulo p).

    Returns:
        tuple[int, int]: (private_key, public_key) where
            private_key  is a random integer in [2, p-2]  — kept secret
            public_key   = g^private_key mod p             — shared openly

    Examples:
        >>> private, public = generate_keypair(23, 5)
        >>> 2 <= private <= 21
        True
        >>> public == pow(5, private, 23)
        True
    """
    private_key = random.randint(2, p - 2)
    public_key  = pow(g, private_key, p)   # g^private mod p  — O(log private)
    return private_key, public_key


def compute_shared_secret(their_public: int, my_private: int, p: int) -> int:
    """
    Compute the shared secret from the other party's public key and own private key.

    Both Alice and Bob call this function symmetrically, and both obtain
    the same value  g^(ab) mod p  without ever transmitting it.

    Args:
        their_public (int): The other party's public key (g^x mod p).
        my_private   (int): Own private key.
        p            (int): Public prime modulus.

    Returns:
        int: Shared secret  their_public^my_private mod p = g^(xy) mod p.

    Examples:
        >>> # Alice owns a=6, Bob owns b=15, p=23, g=5
        >>> A = pow(5, 6,  23)   # Alice's public key → 8
        >>> B = pow(5, 15, 23)   # Bob's   public key → 19
        >>> compute_shared_secret(B, 6,  23)   # Alice's view
        2
        >>> compute_shared_secret(A, 15, 23)   # Bob's view
        2
    """
    return pow(their_public, my_private, p)


def diffie_hellman_exchange(p: int, g: int,
                             alice_private: int | None = None,
                             bob_private:   int | None = None) -> dict:
    """
    Simulate a complete Diffie-Hellman key exchange between Alice and Bob.

    If private keys are not supplied, they are generated randomly.

    Args:
        p             (int):      Public prime modulus.
        g             (int):      Public generator.
        alice_private (int|None): Alice's private key (auto-generated if None).
        bob_private   (int|None): Bob's private key (auto-generated if None).

    Returns:
        dict with keys:
            alice_private  — Alice's secret exponent
            bob_private    — Bob's   secret exponent
            alice_public   — g^alice_private mod p  (transmitted openly)
            bob_public     — g^bob_private   mod p  (transmitted openly)
            shared_secret  — g^(alice_private*bob_private) mod p

    Raises:
        AssertionError: if Alice and Bob derive different shared secrets.
    """
    if alice_private is None:
        alice_private = random.randint(2, p - 2)
    if bob_private is None:
        bob_private = random.randint(2, p - 2)

    alice_public = pow(g, alice_private, p)   # Alice → Bob
    bob_public   = pow(g, bob_private,   p)   # Bob → Alice

    shared_alice = compute_shared_secret(bob_public,   alice_private, p)
    shared_bob   = compute_shared_secret(alice_public, bob_private,   p)

    assert shared_alice == shared_bob, "BUG: shared secrets do not match!"

    return {
        "alice_private": alice_private,
        "bob_private":   bob_private,
        "alice_public":  alice_public,
        "bob_public":    bob_public,
        "shared_secret": shared_alice,
    }


# ---------------------------------------------------------------------------
# Well-known safe primes (RFC 3526 / IETF)
# ---------------------------------------------------------------------------

# 512-bit safe prime  (demo / educational — too small for production)
PRIME_512 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)

# 1536-bit MODP group (RFC 3526, Group 5) — minimum acceptable in practice
PRIME_1536 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16
)

# 2048-bit MODP group (RFC 3526, Group 14) — current production standard
PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)


if __name__ == "__main__":
    import time

    sep = "=" * 60

    # -----------------------------------------------------------------------
    # 1. Toy example (p=23) — easy to verify by hand
    # -----------------------------------------------------------------------
    print(sep)
    print("EXAMPLE 1 — Toy prime (p=23, g=5)")
    print(sep)
    dh = diffie_hellman_exchange(p=23, g=5, alice_private=6, bob_private=15)
    print(f"  Public  p = 23,  g = 5")
    print(f"  Alice private key  (a) = {dh['alice_private']}")
    print(f"  Bob   private key  (b) = {dh['bob_private']}")
    print(f"  Alice public  key  (A = g^a mod p) = {dh['alice_public']}")
    print(f"  Bob   public  key  (B = g^b mod p) = {dh['bob_public']}")
    print(f"  Shared secret (g^ab mod p)         = {dh['shared_secret']}")
    print(f"  Verify: 5^(6*15) mod 23 = 5^90 mod 23 = {pow(5, 90, 23)}")

    # -----------------------------------------------------------------------
    # 2. Random exchange with a small prime — multiple runs to see variation
    # -----------------------------------------------------------------------
    print(f"\n{sep}")
    print("EXAMPLE 2 — Random private keys, p=1009, g=7  (5 runs)")
    print(sep)
    for i in range(5):
        dh = diffie_hellman_exchange(p=1009, g=7)
        print(f"  Run {i+1}: a={dh['alice_private']:>4}, b={dh['bob_private']:>4} "
              f"→ A={dh['alice_public']:>4}, B={dh['bob_public']:>4} "
              f"→ shared={dh['shared_secret']:>4}")

    # -----------------------------------------------------------------------
    # 3. Production-grade primes — timing comparison
    # -----------------------------------------------------------------------
    print(f"\n{sep}")
    print("EXAMPLE 3 — RFC 3526 safe primes (production-grade)")
    print(sep)

    groups = [
        ("512-bit  (demo only)",      PRIME_512,  2),
        ("1536-bit (RFC 3526 Grp 5)", PRIME_1536, 2),
        ("2048-bit (RFC 3526 Grp 14)", PRIME_2048, 2),
    ]

    for label, prime, gen in groups:
        t0 = time.perf_counter()
        dh = diffie_hellman_exchange(prime, gen)
        elapsed = (time.perf_counter() - t0) * 1000

        shared_str = str(dh['shared_secret'])
        print(f"\n  [{label}]")
        print(f"  Prime  ({prime.bit_length()} bits): {str(prime)[:24]}...")
        print(f"  Generator g = {gen}")
        print(f"  Alice private (a): {str(dh['alice_private'])[:16]}...")
        print(f"  Bob   private (b): {str(dh['bob_private'])[:16]}...")
        print(f"  Alice public  (A): {str(dh['alice_public'])[:24]}...")
        print(f"  Bob   public  (B): {str(dh['bob_public'])[:24]}...")
        print(f"  Shared secret    : {shared_str[:24]}...  ({len(shared_str)} decimal digits)")
        print(f"  Key exchange time: {elapsed:.2f} ms")

    # -----------------------------------------------------------------------
    # 4. Security note — what Eve sees vs what she needs
    # -----------------------------------------------------------------------
    print(f"\n{sep}")
    print("SECURITY NOTE — What Eve can and cannot do")
    print(sep)
    dh = diffie_hellman_exchange(PRIME_2048, 2)
    print(f"  Eve intercepts (all public):")
    print(f"    p = {str(PRIME_2048)[:24]}...  ({PRIME_2048.bit_length()} bits)")
    print(f"    g = 2")
    print(f"    A = {str(dh['alice_public'])[:24]}...")
    print(f"    B = {str(dh['bob_public'])[:24]}...")
    print()
    print("  To recover the shared secret Eve must find 'a' such that:")
    print("    g^a ≡ A  (mod p)   ← Discrete Logarithm Problem")
    print()
    print("  Best known algorithm (Number Field Sieve) for a 2048-bit prime")
    print("  requires ~2^112 operations — with all computers on Earth it would")
    print("  take longer than the age of the universe.")
    print("  → The shared secret is safe even though A, B, p, g are all public.")
