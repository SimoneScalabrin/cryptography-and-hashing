
import time


# =============================================================================
# TRAPDOOR FUNCTION — The Discrete Logarithm Problem
# =============================================================================
#
# A *trapdoor function* is easy to compute in one direction but computationally
# infeasible to reverse without secret information.
#
# The discrete logarithm is the trapdoor at the heart of Diffie-Hellman (DH):
#
#   EASY  →  given (base, exponent, modulus), compute:  result = base^exponent mod modulus
#   HARD  ←  given (base, result,   modulus), find:     exponent  such that base^exponent ≡ result (mod modulus)
#
# With a large prime modulus (e.g. 2048 bits) no efficient general algorithm
# is known, making reversal computationally infeasible.
# =============================================================================


def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """
    Compute  base^exponent mod modulus  using fast modular exponentiation.

    Python's built-in pow(b, e, m) uses the *square-and-multiply* algorithm
    which runs in O(log exponent) multiplications — efficient even for
    cryptographically large numbers (thousands of bits).

    This is the EASY direction of the trapdoor: given the exponent, the result
    can be computed in microseconds regardless of the size of the modulus.

    Args:
        base     (int): The base g (generator / primitive root).
        exponent (int): The secret exponent x.
        modulus  (int): A large prime p.

    Returns:
        int: base^exponent mod modulus.

    Examples:
        >>> modular_exponentiation(5, 3, 23)
        10                          # 5^3 = 125, 125 mod 23 = 10

        >>> modular_exponentiation(2, 10, 1024)
        0                           # 2^10 = 1024, 1024 mod 1024 = 0

        # Large numbers — still instantaneous (O(log e))
        >>> modular_exponentiation(2, 10**15, 10**9 + 7)
        # returns in microseconds
    """
    # Use Python's 3-argument pow: pow(b, e, m) is O(log e) via square-and-multiply
    return pow(base, exponent, modulus)


def discrete_logarithm(base: int, result: int, modulus: int) -> int:
    """
    Solve the discrete logarithm problem by brute-force search.

    Find the smallest positive integer  x  such that:
        base^x ≡ result  (mod modulus)

    This is the HARD direction of the trapdoor. The brute-force approach
    tries every exponent from 1 upward — O(modulus) in the worst case.
    For a large prime p (e.g. 2048-bit), this is completely infeasible.

    Args:
        base    (int): The generator g (same value used in modular_exponentiation).
        result  (int): The public value  g^x mod p  that was observed.
        modulus (int): The prime modulus p.

    Returns:
        int: The exponent x such that base^x ≡ result (mod modulus).

    Note:
        This brute-force implementation is for educational purposes only.
        It is practical only for small moduli (p < ~10^6).
        Real-world attacks (e.g. Baby-step Giant-step, Index calculus) are
        faster but still infeasible for large primes.

    Examples:
        >>> discrete_logarithm(5, 10, 23)
        3                           # because 5^3 mod 23 = 10

        >>> discrete_logarithm(2, 9, 11)
        6                           # because 2^6 mod 11 = 64 mod 11 = 9
    """
    exponent = 1
    while pow(base, exponent, modulus) != result:
        exponent += 1
    return exponent


# =============================================================================
# Diffie-Hellman Key Exchange — demonstration
# =============================================================================
#
# Two parties (Alice and Bob) agree on a shared secret without ever
# transmitting it, exploiting the trapdoor asymmetry above.
#
# Public parameters (known to everyone, including Eve):
#   p  = large prime modulus
#   g  = primitive root / generator
#
# Protocol:
#   1. Alice picks secret  a,  computes  A = g^a mod p  → sends A to Bob
#   2. Bob   picks secret  b,  computes  B = g^b mod p  → sends B to Alice
#   3. Alice computes  shared = B^a mod p  =  g^(ab) mod p
#      Bob   computes  shared = A^b mod p  =  g^(ab) mod p
#   → Both arrive at the same shared secret!
#
# Eve sees (p, g, A, B) but cannot recover  a, b, or the shared secret
# without solving the discrete logarithm — computationally infeasible for
# large p.
# =============================================================================

def diffie_hellman(p: int, g: int, a: int, b: int) -> dict:
    """
    Simulate a full Diffie-Hellman key exchange between Alice and Bob.

    Args:
        p (int): Public prime modulus.
        g (int): Public generator (primitive root modulo p).
        a (int): Alice's private secret exponent.
        b (int): Bob's private secret exponent.

    Returns:
        dict with keys:
            public_A  – Alice's public value  g^a mod p
            public_B  – Bob's public   value  g^b mod p
            shared_A  – shared secret computed by Alice  (B^a mod p)
            shared_B  – shared secret computed by Bob    (A^b mod p)
    """
    public_A = modular_exponentiation(g, a, p)   # Alice → Bob  (public)
    public_B = modular_exponentiation(g, b, p)   # Bob → Alice  (public)

    shared_A = modular_exponentiation(public_B, a, p)  # Alice computes shared key
    shared_B = modular_exponentiation(public_A, b, p)  # Bob   computes shared key

    assert shared_A == shared_B, "Key exchange failed — shared secrets differ!"
    return {
        "public_A": public_A,
        "public_B": public_B,
        "shared_A": shared_A,
        "shared_B": shared_B,
    }


if __name__ == "__main__":

    # -------------------------------------------------------------------------
    # 1. Basic examples
    # -------------------------------------------------------------------------
    print("=== modular_exponentiation ===")
    cases = [(5, 3, 23), (2, 10, 1024), (3, 6, 7)]
    for b, e, m in cases:
        print(f"  {b}^{e} mod {m} = {modular_exponentiation(b, e, m)}")

    # -------------------------------------------------------------------------
    # 2. Trapdoor asymmetry — timing comparison across growing prime sizes
    #
    # For each prime p we run N_SAMPLES random secrets and average the timings.
    # The EASY direction (modular exponentiation) stays O(log exponent) and
    # barely changes. The HARD direction (brute-force DL) is O(p) on average,
    # so the gap grows linearly with p — and would grow exponentially for
    # cryptographic-sized primes where even smarter algorithms fail.
    # -------------------------------------------------------------------------
    import random
    import statistics

    # (prime p, generator g, human label)
    # Primes chosen so that g is a primitive root and brute-force stays feasible
    test_primes = [
        (23,    5,  "p=23    (~5 bits)"),
        (97,    5,  "p=97    (~7 bits)"),
        (509,   2,  "p=509   (~9 bits)"),
        (1009,  7,  "p=1009  (~10 bits)"),
        (2039,  7,  "p=2039  (~11 bits)"),
        (4093,  2,  "p=4093  (~12 bits)"),
        (8191,  7,  "p=8191  (~13 bits, Mersenne prime)"),
        (16381, 7,  "p=16381 (~14 bits)"),
        (32749, 6,  "p=32749 (~15 bits)"),
    ]

    N_SAMPLES = 10   # averages over this many random secrets per prime

    print("\n=== Trapdoor asymmetry — how the gap grows with prime size ===")
    print(f"  (averaged over {N_SAMPLES} random secrets each)\n")
    print(f"  {'Prime':<30}  {'Easy (µs)':>10}  {'Hard (µs)':>12}  {'Ratio':>8}")
    print(f"  {'-'*30}  {'-'*10}  {'-'*12}  {'-'*8}")

    for p, g, label in test_primes:
        easy_times, hard_times = [], []

        for _ in range(N_SAMPLES):
            secret = random.randint(2, p - 2)

            # EASY: modular exponentiation — O(log secret)
            t0 = time.perf_counter()
            public = modular_exponentiation(g, secret, p)
            easy_times.append((time.perf_counter() - t0) * 1e6)

            # HARD: brute-force discrete log — O(p) worst case
            t0 = time.perf_counter()
            discrete_logarithm(g, public, p)
            hard_times.append((time.perf_counter() - t0) * 1e6)

        avg_easy = statistics.mean(easy_times)
        avg_hard = statistics.mean(hard_times)
        ratio    = avg_hard / avg_easy if avg_easy > 0 else float("inf")

        print(f"  {label:<30}  {avg_easy:>10.2f}  {avg_hard:>12.2f}  {ratio:>7.0f}x")

    print()
    print("  Observation: Easy stays roughly constant (O(log e) is fast).")
    print("  Hard grows ~linearly with p — the ratio widens steadily.")
    print("  For a 2048-bit prime (~10^617) brute-force would take longer")
    print("  than the age of the universe, even on all computers on Earth.")

    # -------------------------------------------------------------------------
    # 3. Diffie-Hellman key exchange
    # -------------------------------------------------------------------------
    print("\n=== Diffie-Hellman Key Exchange ===")

    # RFC 3526 — 1536-bit MODP group prime (truncated to first 10 digits for demo)
    # For a real demo we use a well-known safe prime
    p_dh = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378422751787149945677905618002180919007787879422408694574327793

    g_dh = 2          # generator for this group

    alice_secret = 123456789_987654321   # Alice's private key (large in practice)
    bob_secret   = 987654321_123456789   # Bob's private key

    t0 = time.perf_counter()
    dh = diffie_hellman(p_dh, g_dh, alice_secret, bob_secret)
    elapsed = (time.perf_counter() - t0) * 1000

    print(f"  Prime p  : {str(p_dh)[:30]}...  ({p_dh.bit_length()} bits)")
    print(f"  Generator: {g_dh}")
    print(f"  Alice private (a): {alice_secret}")
    print(f"  Bob   private (b): {bob_secret}")
    print(f"  Alice public  (g^a mod p): {str(dh['public_A'])[:30]}...")
    print(f"  Bob   public  (g^b mod p): {str(dh['public_B'])[:30]}...")
    print(f"  Shared secret (Alice)    : {str(dh['shared_A'])[:30]}...")
    print(f"  Shared secret (Bob)      : {str(dh['shared_B'])[:30]}...")
    print(f"  Match: {dh['shared_A'] == dh['shared_B']}  — computed in {elapsed:.2f} ms")
    print()
    print("  Eve sees p, g, public_A, public_B — to recover the shared secret")
    print("  she must solve the discrete log, which is computationally infeasible")
    print(f"  for a {p_dh.bit_length()}-bit prime.")
