

"""
Euclidean Algorithm — Greatest Common Divisor (GCD)
=====================================================

The Euclidean algorithm is one of the oldest known algorithms (c. 300 BC).
It computes the greatest common divisor (GCD) of two non-negative integers,
i.e. the largest integer that divides both without a remainder.

Mathematical basis:
    gcd(a, 0) = a
    gcd(a, b) = gcd(b, a mod b)   for b > 0

Time complexity:  O(log(min(a, b)))
Space complexity: O(log(min(a, b))) recursive / O(1) iterative

Relevance in cryptography:
    - RSA key generation (checking that e and φ(n) are coprime)
    - Extended Euclidean Algorithm (modular inverse, used in RSA decryption)
    - Diffie-Hellman and other number-theory-based protocols
"""


def gcd(a: int, b: int) -> int:
    """Return the GCD of *a* and *b* using the recursive Euclidean algorithm.

    Args:
        a: A non-negative integer.
        b: A non-negative integer.

    Returns:
        The greatest common divisor of a and b.

    Raises:
        ValueError: If both a and b are zero (GCD is undefined).

    Examples:
        >>> gcd(48, 18)
        6
        >>> gcd(0, 7)
        7
        >>> gcd(100, 75)
        25
    """
    if a < 0 or b < 0:
        return gcd(abs(a), abs(b))
    if a == 0 and b == 0:
        raise ValueError("gcd(0, 0) is undefined")
    if b == 0:
        return a
    return gcd(b, a % b)


def gcd_iterative(a: int, b: int) -> int:
    """Return the GCD of *a* and *b* using the iterative Euclidean algorithm.

    Preferred over the recursive version for large inputs (no stack overhead).

    Args:
        a: A non-negative integer.
        b: A non-negative integer.

    Returns:
        The greatest common divisor of a and b.

    Raises:
        ValueError: If both a and b are zero (GCD is undefined).

    Examples:
        >>> gcd_iterative(48, 18)
        6
        >>> gcd_iterative(0, 7)
        7
        >>> gcd_iterative(100, 75)
        25
    """
    a, b = abs(a), abs(b)
    if a == 0 and b == 0:
        raise ValueError("gcd(0, 0) is undefined")
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (gcd, x, y) such that a*x + b*y == gcd (Bézout's identity).

    The extended Euclidean algorithm not only finds the GCD but also the
    Bézout coefficients x and y, which are used to compute modular inverses
    (a fundamental operation in RSA and other public-key cryptosystems).

    Args:
        a: An integer.
        b: An integer.

    Returns:
        A tuple (gcd, x, y) where gcd = gcd(a, b) and a*x + b*y == gcd.

    Examples:
        >>> extended_gcd(35, 15)
        (5, 1, -2)
        >>> extended_gcd(3, 11)   # modular inverse of 3 mod 11 is x=4
        (1, 4, -1)
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def are_coprime(a: int, b: int) -> bool:
    """Return True if *a* and *b* are coprime (gcd == 1).

    Two numbers are coprime when they share no common factor other than 1.
    This check is used in RSA to verify that the public exponent e is valid
    with respect to φ(n).

    Examples:
        >>> are_coprime(14, 15)
        True
        >>> are_coprime(14, 21)
        False
    """
    return gcd_iterative(a, b) == 1


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    examples = [
        (48, 18),
        (100, 75),
        (0, 7),
        (561, 0),
        (1071, 462),   # classic textbook example
        (-56, 98),     # negative numbers
        (14, 15),      # consecutive integers → always coprime
        (3, 11),       # two distinct primes → always coprime
        (35, 64),      # no common factors → coprime
    ]

    print("=" * 55)
    print(f"{'Euclidean Algorithm — GCD examples':^55}")
    print("=" * 55)

    for a, b in examples:
        result_rec = gcd(a, b)
        result_it  = gcd_iterative(a, b)
        coprime    = are_coprime(a, b) if not (a == 0 and b == 0) else "N/A"
        print(f"  gcd({a:>5}, {b:>5})  →  recursive={result_rec}  "
              f"iterative={result_it}  coprime={coprime}")

    print()
    print("Extended Euclidean Algorithm — Bézout coefficients:")
    print("-" * 55)
    ext_examples = [(35, 15), (3, 11), (1071, 462)]
    for a, b in ext_examples:
        g, x, y = extended_gcd(a, b)
        print(f"  extended_gcd({a}, {b})  →  gcd={g},  "
              f"{a}*({x}) + {b}*({y}) = {a*x + b*y}")

    print()
    print("Modular inverse via extended GCD (used in RSA):")
    print("-" * 55)
    # Modular inverse of e mod φ(n): find x such that e*x ≡ 1 (mod φ)
    e, phi = 3, 40          # toy RSA example: p=5, q=11 → φ=40
    g, x, _ = extended_gcd(e, phi)
    if g == 1:
        mod_inv = x % phi
        print(f"  Modular inverse of {e} mod {phi}  →  d = {mod_inv}  "
              f"(check: {e}*{mod_inv} mod {phi} = {(e * mod_inv) % phi})")
