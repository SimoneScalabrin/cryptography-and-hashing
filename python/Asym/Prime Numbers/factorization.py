from math import sqrt, floor


def get_factors(num):
    """
    Returns all factors (divisors) of a given positive integer.

    The algorithm iterates only up to sqrt(num), since factors come in pairs:
    if i divides num, then num // i is also a factor. This gives O(sqrt(n)) time complexity.

    Args:
        num (int): A positive integer to factorize.

    Returns:
        list[int]: An unsorted list of all divisors of num, including 1 and num itself.
    """
    factors = []

    # Only iterate up to floor(sqrt(num)) to find factor pairs efficiently
    limit = floor(sqrt(num))

    for i in range(1, limit + 1):
        if num % i == 0:          # i is a divisor
            factors.append(i)
            # Avoid adding the square root twice (e.g. 6 for num=36)
            if i != num // i:
                factors.append(num // i)

    return factors


if __name__ == "__main__":
    import time

    # --- Small numbers ---
    small_cases = [1, 7, 12, 36, 100]
    print("=== Small numbers ===")
    for n in small_cases:
        print(f"Factors of {n:>4}: {sorted(get_factors(n))}")

    # --- Large numbers ---
    large_cases = [
        (1_000_000,     "1 million (perfect square)"),
        (720_720,       "720 720 (highly composite, 240 divisors)"),
        (8_589_934_592, "2^33"),
        (999_999_937,   "large prime"),
        (123_456_789,   "semi-prime: 3 x 41 152 263"),
    ]
    print("\n=== Large numbers ===")
    for n, desc in large_cases:
        t0 = time.perf_counter()
        result = sorted(get_factors(n))
        elapsed = time.perf_counter() - t0
        print(f"{desc} ({n})"
              f"  ->  {len(result)} divisors  [{elapsed*1000:.2f} ms]")