

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


def modular_inverse(a: int, m: int) -> int:
    """Return the modular inverse of *a* modulo *m*, i.e. x such that a*x ≡ 1 (mod m).

    Uses the Extended Euclidean Algorithm. The inverse exists if and only if
    gcd(a, m) == 1 (a and m are coprime).

    Typical use in RSA: given public exponent e and φ(n), compute the private
    exponent d = modular_inverse(e, φ(n)) so that e*d ≡ 1 (mod φ(n)).

    Args:
        a: The integer to invert.
        m: The modulus (must be > 1).

    Returns:
        The modular inverse of a mod m, in the range [0, m).

    Raises:
        ValueError: If m <= 1.
        ValueError: If the inverse does not exist (gcd(a, m) != 1).

    Examples:
        >>> modular_inverse(3, 40)   # RSA: e=3, φ(n)=40 → d=27
        27
        >>> modular_inverse(3, 11)   # 3*4 ≡ 1 (mod 11)
        4
        >>> modular_inverse(7, 26)   # 7*15 ≡ 1 (mod 26)
        15
    """
    if m <= 1:
        raise ValueError(f"Modulus must be > 1, got {m}")
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no modular inverse mod {m} (gcd={g})")
    return x % m


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
    print("Modular inverse (modular_inverse):")
    print("-" * 55)
    inv_examples = [
        (3,  40,   "RSA toy: e=3, φ(n)=40"),
        (3,  11,   "3*4 ≡ 1 (mod 11)"),
        (7,  26,   "7*15 ≡ 1 (mod 26)"),
        (17, 3120, "RSA: e=17, φ(n)=3120"),  # p=61, q=53
    ]
    for a, m, note in inv_examples:
        d = modular_inverse(a, m)
        print(f"  modular_inverse({a}, {m})  →  {d}  "
              f"(check: {a}*{d} mod {m} = {(a * d) % m})  # {note}")
