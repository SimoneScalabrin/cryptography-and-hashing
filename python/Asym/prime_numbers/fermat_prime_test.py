"""
Fermat Primality Test
=====================
A probabilistic primality test based on Fermat's Little Theorem:

    If p is prime, then for any integer a (1 < a < p):
        a^(p-1) ≡ 1 (mod p)

The test picks k random bases `a` and verifies the congruence. If the
congruence fails for any base, the number is definitely composite. If it
holds for all k bases, the number is *probably* prime (but not certain).

False positives (Carmichael numbers):
    Some composite numbers (e.g. 561, 1105, 1729) pass the test for *every*
    base coprime to them — these are called Carmichael numbers. For stronger
    guarantees use the Miller-Rabin test instead.

Time complexity: O(k * log²n) due to modular exponentiation.

Typical usage in cryptography:
    RSA key generation requires large primes (~2048 bits). Probabilistic tests
    like this one are used as fast filters before applying deterministic checks.
"""

import random


def is_prime(num: int, k: int = 10) -> bool:
    """
    Probabilistically test whether `num` is prime using Fermat's Little Theorem.

    The test repeats `k` rounds; each round picks a fresh random witness `a`
    and checks whether a^(num-1) ≡ 1 (mod num). A single failure proves the
    number is composite. Passing all rounds means the number is *probably*
    prime, with the probability of a false positive ≤ (1/2)^k for non-
    Carmichael numbers.

    Args:
        num (int): The integer to test. Must be a positive integer ≥ 2.
        k   (int): Number of random witness rounds. Higher values reduce the
                   probability of a false positive. Default is 10, giving a
                   false-positive probability ≤ 1/1024 for non-Carmichael numbers.

    Returns:
        bool: True  — num is *probably* prime.
              False — num is *definitely* composite.

    Examples:
        >>> is_prime(17)
        True
        >>> is_prime(15)
        False
        >>> is_prime(561)   # Carmichael number — may return True (false positive)
        True
    """
    if k <= 0:
        raise ValueError(f"k must be a positive integer, got {k}")
    # Numbers ≤ 1 are not prime by definition
    if num <= 1:
        return False

    # 2 and 3 are prime; handle them explicitly because randint below
    # requires num-2 ≥ 2, which fails for num < 4
    if num <= 3:
        return True

    # Even numbers greater than 2 are always composite
    if num % 2 == 0:
        return False

    for _ in range(k):
        # Choose a random base a in [2, num-2]
        a = random.randint(2, num - 2)

        # Fermat's congruence: a^(num-1) mod num must equal 1 for primes
        x = pow(a, num - 1, num)   # Python's built-in 3-arg pow is O(log² num)

        if x != 1:
            # Fermat witness found — num is definitely composite
            return False

    # Passed all k rounds → probably prime
    return True


# ---------------------------------------------------------------------------
# Demo / usage examples
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Edge Cases ===")
    for n in [0, 1, 2, 3, 4]:
        print(f"is_prime({n:>4}) -> {is_prime(n)}")

    print("\n=== Small Numbers ===")
    samples = [5, 10, 11, 13, 15, 17, 18, 19, 20, 23, 25]
    for n in samples:
        print(f"is_prime({n:>4}) -> {is_prime(n)}")

    print("\n=== Primes in range [2, 50] ===")
    primes_in_range = [n for n in range(2, 51) if is_prime(n)]
    print(primes_in_range)

    print("\n=== Larger Numbers (relevant to RSA key generation) ===")
    large_samples = [97, 100, 7919, 7920, 104729, 104730]
    for n in large_samples:
        print(f"is_prime({n:>7}) -> {is_prime(n)}")

    print("\n=== Carmichael Numbers (known false positives for Fermat test) ===")
    carmichael = [561, 1105, 1729, 2465, 8911]
    for n in carmichael:
        result = is_prime(n)
        print(f"is_prime({n:>5}) -> {result}  (composite, but Fermat says prime!)")

    print("\n=== Effect of increasing k (witness rounds) ===")
    # For a non-Carmichael composite, more rounds reduce false-positive risk
    composite = 341  # 341 = 11 × 31, a base-2 pseudoprime
    for rounds in [1, 5, 10, 20]:
        results = [is_prime(composite, k=rounds) for _ in range(100)]
        false_positives = sum(results)
        print(f"  k={rounds:>2}, false positives in 100 trials: {false_positives}")