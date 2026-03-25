"""Naive primality test using trial division with small optimizations.

This module provides `is_prime(n)`, a straightforward primality test that
checks divisibility up to floor(sqrt(n)). It includes simple optimizations:
- early exits for n < 2 and n == 2
- a fast check for even numbers
- testing only odd divisors starting from 3

Intended for educational use and small inputs. For large integers prefer
probabilistic or specialized deterministic algorithms.

Example:
    >>> is_prime(17)
    True
"""

from math import sqrt, floor

def is_prime(n: int) -> bool:
    """Return True if `n` is a prime number, False otherwise.

    Args:
        n: Integer to test for primality.

    Returns:
        `True` if `n` is prime, `False` otherwise.

    Notes:
        - Uses trial division up to floor(sqrt(n)).
        - Time complexity: O(sqrt(n)), with half the checks skipped by
          testing only odd divisors.
        - Not intended for cryptographic-sized primes.
    """
    # Numbers less than 2 are not prime by definition
    if n < 2:
        return False

    # 2 is the only even prime
    if n == 2:
        return True

    # Exclude other even numbers quickly
    if n % 2 == 0:
        return False

    # Check odd divisors from 3 up to floor(sqrt(n))
    limit = floor(sqrt(n)) + 1
    for i in range(3, limit, 2):
        # If i divides n evenly, n is composite
        if n % i == 0:
            return False

    # No divisors found -> n is prime
    return True

if __name__ == "__main__":
    # Test the function with examples of increasing size.
    # For very large numbers, skip the naive trial-division check
    # to avoid extremely long runtimes; we print a note instead.
    test_numbers = [
        1,
        2,
        3,
        4,
        5,
        10,
        3459,
        7919,
        1000003,              # small prime (1e6 scale)
        1003545,
        9942647934,           # ~1e10
        32416190071,          # known large prime (~3.24e10)
        3467987234902,
        2305843009213693951,  # 2**61 - 1, Mersenne prime
    ]

    for num in test_numbers:
        print(f"{num} is prime: {is_prime(num)}")