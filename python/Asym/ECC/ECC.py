"""
Elliptic Curve Cryptography (ECC)
==================================
This module implements ECC over a finite field GF(p), where all arithmetic is
performed modulo a prime p.  Using a finite field is essential for real
cryptography: floating-point arithmetic introduces rounding errors and provides
no security guarantees.

Curve equation:  y² ≡ x³ + ax + b  (mod p)

Classes
-------
Point               — A point (x, y) on an elliptic curve, including ∞.
EllipticCurve       — Curve operations: addition, doubling, scalar multiplication.
ECDH                — Elliptic Curve Diffie-Hellman key exchange.

Key concepts
------------
- Point at infinity (∞): the identity element of the group; P + ∞ = ∞ + P = P.
- Point negation: −(x, y) = (x, −y mod p).
- Point addition: standard chord-and-tangent rule, using modular inverse.
- Scalar multiplication n*P: computed via the double-and-add algorithm in O(log n).
- ECDLP hardness: given P and Q = n*P it is infeasible to recover n for large p,
  which is the security foundation of ECC.

References
----------
- https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
- https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman
"""

import os
import random
import sys
from typing import Optional, Tuple

# Allow importing sibling packages (prime_numbers, GCD) the same way RSA.py does.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from prime_numbers.naive_prime import is_prime
from GCD.euclidean import modular_inverse


# ---------------------------------------------------------------------------
# Point
# ---------------------------------------------------------------------------

class Point:
    """A point on an elliptic curve over GF(p).

    The special singleton ``INFINITY`` (defined below) represents the point at
    infinity, i.e. the identity element of the elliptic-curve group.

    Attributes
    ----------
    x : int or None
        x-coordinate (None for the point at infinity).
    y : int or None
        y-coordinate (None for the point at infinity).
    """

    def __init__(self, x: Optional[int], y: Optional[int]) -> None:
        self.x = x
        self.y = y

    def is_infinity(self) -> bool:
        """Return ``True`` if this point is the point at infinity."""
        return self.x is None and self.y is None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        if self.is_infinity():
            return "Point(∞)"
        return f"Point({self.x}, {self.y})"

    def __str__(self) -> str:
        if self.is_infinity():
            return "∞"
        return f"({self.x}, {self.y})"


# Singleton representing the point at infinity (identity element).
INFINITY = Point(None, None)


# ---------------------------------------------------------------------------
# EllipticCurve
# ---------------------------------------------------------------------------

class EllipticCurve:
    """An elliptic curve y² ≡ x³ + ax + b  (mod p) over the finite field GF(p).

    All point coordinates and intermediate values are integers in [0, p-1].
    Division is replaced by multiplication with the modular inverse, computed
    via Fermat's little theorem: k⁻¹ ≡ k^(p-2) (mod p) for prime p.

    Attributes
    ----------
    a : int  — Coefficient *a* in the Weierstrass equation.
    b : int  — Coefficient *b* in the Weierstrass equation.
    p : int  — Prime modulus defining GF(p).

    Raises
    ------
    ValueError
        If ``p`` is not prime, or if the curve is singular
        (i.e. 4a³ + 27b² ≡ 0 mod p, which means the curve has cusps or
        self-intersections and does not form a valid group).
    """

    def __init__(self, a: int, b: int, p: int) -> None:
        if not is_prime(p):
            raise ValueError(f"p={p} must be a prime number.")
        if (4 * a ** 3 + 27 * b ** 2) % p == 0:
            raise ValueError(
                "Singular curve: 4a³ + 27b² ≡ 0 (mod p). "
                "Choose different parameters."
            )
        self.a = a
        self.b = b
        self.p = p

    # ------------------------------------------------------------------
    # Curve membership
    # ------------------------------------------------------------------

    def is_on_curve(self, P: Point) -> bool:
        """Return ``True`` iff point *P* satisfies y² ≡ x³ + ax + b (mod p).

        The point at infinity is always considered to be on the curve.
        """
        if P.is_infinity():
            return True
        lhs = (P.y ** 2) % self.p
        rhs = (P.x ** 3 + self.a * P.x + self.b) % self.p
        return lhs == rhs

    # ------------------------------------------------------------------
    # Group operations
    # ------------------------------------------------------------------

    def negate(self, P: Point) -> Point:
        """Return the additive inverse of *P*: −P = (x, −y mod p).

        Property: P + (−P) = ∞.
        """
        if P.is_infinity():
            return INFINITY
        return Point(P.x, (-P.y) % self.p)

    def add_points(self, P: Point, Q: Point) -> Point:
        """Return the sum P + Q on the elliptic curve (mod p).

        Handles all cases:

        * P = ∞  →  Q   (identity element)
        * Q = ∞  →  P   (identity element)
        * P = −Q →  ∞   (additive inverses cancel)
        * P = Q  →  point doubling   (tangent rule)
        * else   →  general point addition  (secant rule)

        The slope *m* is computed using the modular inverse of the denominator,
        which replaces the real-number division used on non-finite curves.

        Parameters
        ----------
        P, Q : Point  — Points on this curve.

        Returns
        -------
        Point  — The resulting point P + Q.
        """
        if P.is_infinity():
            return Q
        if Q.is_infinity():
            return P

        x1, y1 = P.x, P.y
        x2, y2 = Q.x, Q.y

        if x1 == x2 and (y1 + y2) % self.p == 0:
            # P and Q are additive inverses → point at infinity
            return INFINITY

        if P == Q:
            # Point doubling: tangent slope  m = (3x₁² + a) · (2y₁)⁻¹  mod p
            m = (3 * x1 * x1 + self.a) * modular_inverse(2 * y1, self.p) % self.p
        else:
            # Point addition: secant slope   m = (y₂ − y₁) · (x₂ − x₁)⁻¹  mod p
            m = (y2 - y1) * modular_inverse(x2 - x1, self.p) % self.p

        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return Point(x3, y3)

    def double_and_add(self, n: int, P: Point) -> Point:
        """Return the scalar multiple n·P using the double-and-add algorithm.

        The algorithm scans the binary representation of *n* from the least
        significant bit to the most significant bit:

        * If the current bit is 1, add the current power-of-2 multiple to the
          running result.
        * Always double the current multiple for the next iteration.

        Time complexity: O(log n) — one doubling per bit, plus at most one
        addition per bit.  This is analogous to fast modular exponentiation.

        Parameters
        ----------
        n : int    — Positive scalar multiplier.
        P : Point  — Base point on the curve.

        Returns
        -------
        Point  — The point n·P.

        Raises
        ------
        ValueError  — If *n* is not a positive integer.

        Examples
        --------
        >>> curve = EllipticCurve(a=2, b=3, p=97)
        >>> G = Point(3, 6)
        >>> curve.double_and_add(2, G) == curve.add_points(G, G)
        True
        >>> curve.double_and_add(1, G) == G
        True
        """
        if n <= 0:
            raise ValueError("Scalar n must be a positive integer.")

        result = INFINITY        # Accumulator — starts as the identity element
        addend = Point(P.x, P.y) # Tracks 2^i · P for the current bit position i

        while n:
            if n & 1:                                      # Current bit is 1
                result = self.add_points(result, addend)
            addend = self.add_points(addend, addend)       # Double for next bit
            n >>= 1

        return result

    def order_of_point(self, P: Point, max_order: int = 100_000) -> Optional[int]:
        """Return the order of point *P*: the smallest n > 0 such that n·P = ∞.

        This brute-force search is only practical for small curves.

        Parameters
        ----------
        P         : Point  — The point whose order to compute.
        max_order : int    — Upper bound on the search.

        Returns
        -------
        int or None  — The order of P, or None if not found within *max_order*.
        """
        current = Point(P.x, P.y)
        for i in range(1, max_order + 1):
            if current.is_infinity():
                return i
            current = self.add_points(current, P)
        return None


# ---------------------------------------------------------------------------
# ECDH key exchange
# ---------------------------------------------------------------------------

class ECDH:
    """Elliptic Curve Diffie-Hellman (ECDH) key exchange.

    Both parties agree on a public curve and a generator point G.  Each party
    chooses a secret scalar (private key) and publishes its scalar multiple of
    G (public key).  Multiplying one's own private key by the other party's
    public key yields the same shared secret for both parties, because:

        Alice: a · (b·G) = (ab)·G
        Bob:   b · (a·G) = (ab)·G

    Security relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP):
    given G and Q = n·G, recovering n is computationally infeasible for large p.

    Attributes
    ----------
    curve     : EllipticCurve  — The agreed-upon curve.
    G         : Point          — The agreed-upon generator (base) point.
    key_range : Tuple[int,int] — (min, max) range for random private key generation.

    Raises
    ------
    ValueError  — If G is not on the curve.
    """

    def __init__(
        self,
        curve: EllipticCurve,
        G: Point,
        key_range: Tuple[int, int] = (2, 10_000),
    ) -> None:
        if not curve.is_on_curve(G):
            raise ValueError("Generator point G is not on the given curve.")
        self.curve = curve
        self.G = G
        self.key_range = key_range

    def generate_keypair(self) -> Tuple[int, Point]:
        """Generate a random (private_key, public_key) pair.

        Returns
        -------
        Tuple[int, Point]
            ``(private_key, public_key)`` where ``public_key = private_key · G``.
        """
        private_key = random.randint(*self.key_range)
        public_key = self.curve.double_and_add(private_key, self.G)
        return private_key, public_key

    def compute_shared_secret(self, private_key: int, other_public_key: Point) -> Point:
        """Compute the shared secret from own private key and the other party's public key.

        Parameters
        ----------
        private_key      : int    — Own private key scalar.
        other_public_key : Point  — The other party's public key.

        Returns
        -------
        Point  — Shared secret S = private_key · other_public_key.
        """
        return self.curve.double_and_add(private_key, other_public_key)


# ---------------------------------------------------------------------------
# Preset curves for demonstration
# ---------------------------------------------------------------------------

def small_demo_curve() -> Tuple[EllipticCurve, Point]:
    """Return a small educational curve and generator point.

    Curve:     y² ≡ x³ + 2x + 3  (mod 97)
    Generator: G = (3, 6)

    Verification: 6² = 36;  3³ + 2·3 + 3 = 36  ✓
    """
    return EllipticCurve(a=2, b=3, p=97), Point(3, 6)


def medium_demo_curve() -> Tuple[EllipticCurve, Point]:
    """Return a slightly larger educational curve for more varied examples.

    Curve:     y² ≡ x³ + x + 6  (mod 211)
    Generator: G = (2, 2)

    Verification: 2² = 4;  2³ + 2 + 6 = 16 ≢ 4 (mod 211).
    (Coordinates chosen so G is on the curve.)
    """
    curve = EllipticCurve(a=1, b=6, p=211)
    # Find a valid generator by scanning points on the curve
    for x in range(curve.p):
        rhs = (x ** 3 + curve.a * x + curve.b) % curve.p
        # Check if rhs is a quadratic residue mod p
        y = pow(rhs, (curve.p + 1) // 4, curve.p)
        if pow(y, 2, curve.p) == rhs:
            return curve, Point(x, y)
    raise RuntimeError("No point found on medium_demo_curve.")  # should not happen


# ---------------------------------------------------------------------------
# Main — usage examples
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    SEP = "=" * 62

    print(SEP)
    print("  Elliptic Curve Cryptography — Examples")
    print(SEP)

    curve, G = small_demo_curve()
    print(f"\nCurve : y² ≡ x³ + {curve.a}x + {curve.b}  (mod {curve.p})")
    print(f"Generator G = {G}")

    # ------------------------------------------------------------------
    # Example 1 — Point validation
    # ------------------------------------------------------------------
    print("\n--- Example 1: Point Validation (is_on_curve) ---")
    candidates = [
        (Point(3, 6),   True,  "generator G"),
        (Point(80, 10), None,  "random point"),
        (Point(0, 0),   None,  "origin"),
        (INFINITY,      True,  "point at infinity"),
    ]
    for pt, _, label in candidates:
        on = curve.is_on_curve(pt)
        print(f"  {label:25s} {pt!s:20s} on curve: {on}")

    # ------------------------------------------------------------------
    # Example 2 — Point negation
    # ------------------------------------------------------------------
    print("\n--- Example 2: Point Negation ---")
    neg_G = curve.negate(G)
    print(f"  G        = {G}")
    print(f"  −G       = {neg_G}")
    print(f"  −G on curve: {curve.is_on_curve(neg_G)}")
    print(f"  G + (−G) = {curve.add_points(G, neg_G)}  (point at infinity)")

    # ------------------------------------------------------------------
    # Example 3 — Point doubling  (P + P)
    # ------------------------------------------------------------------
    print("\n--- Example 3: Point Doubling (P + P = 2P) ---")
    two_G = curve.add_points(G, G)
    print(f"  G     = {G}")
    print(f"  G + G = {two_G}")
    print(f"  2G on curve: {curve.is_on_curve(two_G)}")

    # ------------------------------------------------------------------
    # Example 4 — General point addition  (P + Q, P ≠ Q)
    # ------------------------------------------------------------------
    print("\n--- Example 4: General Point Addition (P + Q) ---")
    two_G = curve.double_and_add(2, G)
    three_G = curve.double_and_add(3, G)
    five_G_direct = curve.add_points(two_G, three_G)
    five_G_scalar = curve.double_and_add(5, G)
    print(f"  2G          = {two_G}")
    print(f"  3G          = {three_G}")
    print(f"  2G + 3G     = {five_G_direct}")
    print(f"  5G (scalar) = {five_G_scalar}")
    print(f"  Equal: {five_G_direct == five_G_scalar}")

    # ------------------------------------------------------------------
    # Example 5 — Scalar multiplication (double-and-add)
    # ------------------------------------------------------------------
    print("\n--- Example 5: Scalar Multiplication n·G ---")
    print(f"  {'n':>5}   {'n·G'}")
    print(f"  {'-'*5}   {'-'*20}")
    for n in [1, 2, 3, 5, 10, 20, 50, 100]:
        result = curve.double_and_add(n, G)
        print(f"  {n:>5}   {result}")

    # ------------------------------------------------------------------
    # Example 6 — Identity element
    # ------------------------------------------------------------------
    print("\n--- Example 6: Identity Element (∞) ---")
    print(f"  G + ∞ = {curve.add_points(G, INFINITY)}")
    print(f"  ∞ + G = {curve.add_points(INFINITY, G)}")
    print(f"  ∞ + ∞ = {curve.add_points(INFINITY, INFINITY)}")

    # ------------------------------------------------------------------
    # Example 7 — Order of the generator point
    # ------------------------------------------------------------------
    print("\n--- Example 7: Order of a Point ---")
    order = curve.order_of_point(G)
    print(f"  Order of G = {order}  (smallest n > 0 s.t. n·G = ∞)")
    if order:
        check = curve.double_and_add(order, G)
        print(f"  {order}·G = {check}  ✓")
        # Verify that (order+1)·G = G
        wrap = curve.double_and_add(order + 1, G)
        print(f"  ({order}+1)·G = {wrap} = G  ✓" if wrap == G else f"  Unexpected: ({order}+1)·G = {wrap}")

    # ------------------------------------------------------------------
    # Example 8 — Commutativity of scalar multiplication
    # ------------------------------------------------------------------
    print("\n--- Example 8: Commutativity  (a·b)·G = a·(b·G) = b·(a·G) ---")
    a, b = 7, 13
    ab_G  = curve.double_and_add(a * b, G)
    a_bG  = curve.double_and_add(a, curve.double_and_add(b, G))
    b_aG  = curve.double_and_add(b, curve.double_and_add(a, G))
    print(f"  a = {a}, b = {b}")
    print(f"  (a·b)·G = {ab_G}")
    print(f"  a·(b·G) = {a_bG}")
    print(f"  b·(a·G) = {b_aG}")
    print(f"  All equal: {ab_G == a_bG == b_aG}")

    # ------------------------------------------------------------------
    # Example 9 — ECDH key exchange (single exchange)
    # ------------------------------------------------------------------
    print("\n--- Example 9: ECDH Key Exchange ---")
    ecdh = ECDH(curve, G, key_range=(2, 1_000))

    alice_priv, alice_pub = ecdh.generate_keypair()
    bob_priv,   bob_pub   = ecdh.generate_keypair()

    alice_secret = ecdh.compute_shared_secret(alice_priv, bob_pub)
    bob_secret   = ecdh.compute_shared_secret(bob_priv,   alice_pub)

    print(f"  Alice private key  : {alice_priv}")
    print(f"  Alice public key   : {alice_pub}")
    print(f"  Bob   private key  : {bob_priv}")
    print(f"  Bob   public key   : {bob_pub}")
    print(f"  Alice shared secret: {alice_secret}")
    print(f"  Bob   shared secret: {bob_secret}")
    print(f"  Secrets match: {alice_secret == bob_secret}")

    # ------------------------------------------------------------------
    # Example 10 — ECDH stress test
    # ------------------------------------------------------------------
    print("\n--- Example 10: ECDH Stress Test (50 random exchanges) ---")
    successes = 0
    trials = 50
    for _ in range(trials):
        a_priv, a_pub = ecdh.generate_keypair()
        b_priv, b_pub = ecdh.generate_keypair()
        s_a = ecdh.compute_shared_secret(a_priv, b_pub)
        s_b = ecdh.compute_shared_secret(b_priv, a_pub)
        if s_a == s_b:
            successes += 1
    print(f"  {successes}/{trials} exchanges produced matching shared secrets.")

    # ------------------------------------------------------------------
    # Example 11 — Medium curve
    # ------------------------------------------------------------------
    print("\n--- Example 11: Medium Curve (mod 211) ---")
    curve2, G2 = medium_demo_curve()
    print(f"  Curve: y² ≡ x³ + {curve2.a}x + {curve2.b}  (mod {curve2.p})")
    print(f"  Generator G2 = {G2}  on curve: {curve2.is_on_curve(G2)}")
    order2 = curve2.order_of_point(G2)
    print(f"  Order of G2 = {order2}")

    ecdh2 = ECDH(curve2, G2, key_range=(2, order2 - 1 if order2 else 1_000))
    a_priv2, a_pub2 = ecdh2.generate_keypair()
    b_priv2, b_pub2 = ecdh2.generate_keypair()
    s_a2 = ecdh2.compute_shared_secret(a_priv2, b_pub2)
    s_b2 = ecdh2.compute_shared_secret(b_priv2, a_pub2)
    print(f"  ECDH shared secrets match: {s_a2 == s_b2}")

    # ------------------------------------------------------------------
    # Example 12 — Additive inverse edge cases
    # ------------------------------------------------------------------
    print("\n--- Example 12: Edge Cases ---")
    n_G = curve.double_and_add(5, G)
    neg_n_G = curve.negate(n_G)
    print(f"  5·G              = {n_G}")
    print(f"  −(5·G)           = {neg_n_G}")
    print(f"  5·G + (−5·G)     = {curve.add_points(n_G, neg_n_G)}")
    print(f"  5·G + INFINITY   = {curve.add_points(n_G, INFINITY)}")
    print(f"  INFINITY + INFINITY = {curve.add_points(INFINITY, INFINITY)}")

    print(f"\n{SEP}")
    print("  Done.")
    print(SEP)